import type { FastifyRequest, FastifyReply } from 'fastify';
import type { Pool } from 'pg';

export interface DataPermission {
    activity: string;
    view: string;
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
                if (!orgIdVal) return reply.code(400).send({ error: 'X-Org-Id header is required' });

                const { rows } = await db.query<{ allowed: boolean }>(
                    'SELECT morbac.is_allowed($1::UUID, $2::UUID, $3, $4) AS allowed',
                    [user.id, orgIdVal, permission.activity, permission.view],
                );
                if (!rows[0]?.allowed) return reply.code(403).send({ error: 'Forbidden' });
            }

            const qs = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
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
