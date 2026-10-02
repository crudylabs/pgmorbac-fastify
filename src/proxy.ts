import type { FastifyRequest, FastifyReply } from 'fastify';
import type { Pool } from 'pg';
import { hasPermission, hasPermissionAny } from './permissions.js';

export interface DataPermission {
    activity: string;
    view: string;
}

/** Rows returned by a GET that does not ask for a page size. */
export const DEFAULT_PAGE_LIMIT = 100;

/**
 * Largest page a caller may ask for. Deliberately well above the table's
 * page-size options; bulk reads belong on the export routes, which stream
 * from a cursor instead of buffering a PostgREST response.
 *
 * Not configurable: an env override would be an escape hatch around the cap.
 */
export const MAX_PAGE_LIMIT = 1000;

/**
 * Rejects rather than clamps. A clamp answers 200 with a short Content-Range
 * that the caller reads as authoritative, so a truncated read looks like a
 * complete one and surfaces later as wrong numbers. A 400 surfaces at the
 * call site immediately.
 */
function checkLimit(rawQs: string): { ok: true } | { ok: false } {
    for (const value of new URLSearchParams(rawQs).getAll('limit')) {
        const n = Number(value);
        if (!Number.isInteger(n) || n < 0 || n > MAX_PAGE_LIMIT) return { ok: false };
    }
    return { ok: true };
}

export type ProxyDataRouteFn = (
    app: import('fastify').FastifyInstance,
    method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE',
    publicPath: string,
    upstreamResource: string,
    permission: DataPermission | null,
) => void;

type RegistryEntry = { upstreamResource: string; publicPath: string; permission: DataPermission | null };

export interface ProxyRegistry {
    proxy: (
        app: import('fastify').FastifyInstance,
        method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE',
        publicPath: string,
        upstreamResource: string,
        permission: DataPermission | null,
    ) => void;
    allDataPermissions: () => DataPermission[];
    getPermissionByUpstream: (resource: string, method: string) => DataPermission | null | undefined;
    getPublicPath: (resource: string, method: string) => string | undefined;
}

export function createProxyRegistry(db: Pool, postgrestUrl: string): ProxyRegistry {
    const registry = new Map<string, RegistryEntry>();

    function proxy(
        app: import('fastify').FastifyInstance,
        method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE',
        publicPath: string,
        upstreamResource: string,
        permission: DataPermission | null,
    ): void {
        registry.set(`${method}:${upstreamResource}`, { upstreamResource, publicPath, permission });
        app.route({
            method,
            url: publicPath,
            schema: { hide: true } as Record<string, unknown>,
            config: { permission },
            handler: makeHandler(upstreamResource, permission),
        });
    }

    function makeHandler(upstreamResource: string, permission: DataPermission | null) {
        return async function handler(req: FastifyRequest, reply: FastifyReply) {
            const user = ((req as unknown) as Record<string, unknown>).user as { id: string } | null;
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            if (permission !== null) {
                const orgId = req.headers['x-org-id'];
                const orgIdVal = Array.isArray(orgId) ? orgId[0] : orgId;
                const orgIds = req.headers['x-org-ids'];
                const orgIdsVal = Array.isArray(orgIds) ? orgIds[0] : orgIds;

                // Goes through hasPermission rather than is_allowed directly: it is
                // the only place an API key's permission_scope is applied, so an
                // inline check would let a narrowly scoped key act as its full user.
                if (orgIdVal) {
                    if (!await hasPermission(db, req, reply, orgIdVal, permission.activity, permission.view)) {
                        return reply;
                    }
                } else if (orgIdsVal && orgIdsVal.trim()) {
                    // A multi-org list read (e.g. "all organizations"): scoped to the
                    // set via X-Org-Ids. RLS filters each row, so the gate only needs
                    // permission in one of them.
                    const ids = orgIdsVal.split(',').map(s => s.trim()).filter(Boolean);
                    if (!await hasPermissionAny(db, req, reply, ids, permission.activity, permission.view)) {
                        return reply;
                    }
                } else {
                    return reply.code(400).send({ error: 'X-Org-Id header is required' });
                }
            }

            const qsIndex = req.url.indexOf('?');
            const rawQs = qsIndex === -1 ? '' : req.url.slice(qsIndex + 1);

            if (!checkLimit(rawQs).ok) return reply.code(400).send({ error: 'limit_exceeded' });

            // Only reads get a default page. On PATCH and DELETE, PostgREST reads
            // limit as a bound on the affected rows, so injecting one would
            // silently truncate a bulk mutation.
            let qs = rawQs ? `?${rawQs}` : '';
            if (req.method === 'GET' && !new URLSearchParams(rawQs).has('limit')) {
                qs = rawQs ? `?${rawQs}&limit=${DEFAULT_PAGE_LIMIT}` : `?limit=${DEFAULT_PAGE_LIMIT}`;
            }

            const url = `${postgrestUrl}/${upstreamResource}${qs}`;

            const headers: Record<string, string> = {};
            const pick = (src: string, dst: string = src) => {
                const v = req.headers[src.toLowerCase()];
                if (v) headers[dst] = Array.isArray(v) ? v[0] : v;
            };
            pick('authorization', 'Authorization');
            pick('x-org-id',     'X-Org-Id');
            pick('x-org-ids',    'X-Org-Ids');
            pick('content-type', 'Content-Type');
            pick('prefer',       'Prefer');
            pick('accept',       'Accept');

            if (req.method === 'POST' || req.method === 'PATCH') {
                const existing = headers['Prefer'];
                if (!existing || !existing.includes('return=')) {
                    headers['Prefer'] = existing
                        ? `${existing}, return=representation`
                        : 'return=representation';
                }
            }

            const hasBody = req.method !== 'GET' && req.method !== 'HEAD' && req.body != null;
            const body    = hasBody ? JSON.stringify(req.body) : undefined;

            let upstream: Response;
            try {
                upstream = await fetch(url, { method: req.method, headers, body });
            } catch {
                return reply.code(503).send({ error: 'Data service unavailable' });
            }

            reply.code(upstream.status);
            const fwd = (name: string) => {
                const v = upstream.headers.get(name);
                if (v !== null) reply.header(name, v);
            };
            fwd('content-type');
            fwd('content-range');
            fwd('x-total-count');

            return reply.send(await upstream.text());
        };
    }

    function allDataPermissions(): DataPermission[] {
        const seen = new Set<string>();
        const result: DataPermission[] = [];
        for (const { permission } of registry.values()) {
            if (permission != null) {
                const key = `${permission.activity}:${permission.view}`;
                if (!seen.has(key)) { seen.add(key); result.push(permission); }
            }
        }
        return result;
    }

    function getPermissionByUpstream(resource: string, method: string): DataPermission | null | undefined {
        return registry.get(`${method.toUpperCase()}:${resource}`)?.permission;
    }

    function getPublicPath(resource: string, method: string): string | undefined {
        return registry.get(`${method.toUpperCase()}:${resource}`)?.publicPath;
    }

    return { proxy, allDataPermissions, getPermissionByUpstream, getPublicPath };
}
