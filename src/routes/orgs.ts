import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import type { CheckLimitFn, OrgEventSink } from '../plugin.js';
import {
    getUser, getOrgScope, orgScopeExpr, hasPermission, SYSTEM_ORG_ID,
} from '../permissions.js';
import { orgResponse, notFound, forbidden, unauthorized, badRequest } from '../schemas.js';

interface OrgRow { id: string; name: string; parent_id: string | null; metadata?: Record<string, unknown> }

export function createOrgRoutes(db: Pool, checkLimit?: CheckLimitFn, emitOrgEvent?: OrgEventSink) {
    return async function orgRoutes(app: FastifyInstance) {
        app.get('/orgs', {
            schema: {
                tags: ['Management'],
                summary: 'List organisations',
                description: 'Returns all accessible organisations, or only those within the scoped org subtree when X-Org-Id is provided.',
                security: [{ oauth2: [] }],
                response: {
                    200: { type: 'array', items: orgResponse },
                    401: unauthorized, 403: forbidden,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const orgIds = getOrgScope(req, reply, false);
            if (orgIds === null) return reply;

            if (orgIds.length === 0) {
                const { rows: adminCheck } = await db.query<{ allowed: boolean }>(
                    'SELECT morbac.is_allowed($1::UUID, NULL::UUID, $2, $3) AS allowed',
                    [user.id, 'read', 'orgs'],
                );
                if (adminCheck[0]?.allowed) {
                    const { rows } = await db.query(
                        'SELECT id, name, parent_id, metadata FROM morbac.orgs ORDER BY name',
                    );
                    return rows;
                }
                const { rows } = await db.query(
                    `SELECT DISTINCT o.id, o.name, o.parent_id, o.metadata
                     FROM morbac.orgs o
                     INNER JOIN morbac.user_roles ur ON ur.org_id = o.id AND ur.user_id = $1
                     ORDER BY o.name`,
                    [user.id],
                );
                return rows;
            }

            if (!await hasPermission(db, req, reply, orgIds[0], 'read', 'orgs')) return reply;

            const isSystemScope = orgIds.includes(SYSTEM_ORG_ID);
            const { expr, params } = isSystemScope ? { expr: '', params: [] } : orgScopeExpr(orgIds, 'id');
            const { rows } = await db.query(
                `SELECT id, name, parent_id, metadata FROM morbac.orgs ${expr ? `WHERE ${expr}` : ''} ORDER BY name`,
                params,
            );
            return rows;
        });

        app.post('/orgs', {
            schema: {
                tags: ['Management'],
                summary: 'Create an organisation',
                description: [
                    'Creates a sub-organisation under `parent_id`. Requires `create`/`orgs` permission in the parent org.',
                    'Creating a root organisation (no `parent_id`) requires `create`/`root_orgs` permission in the scoped org.',
                ].join('\n'),
                security: [{ oauth2: [] }],
                body: {
                    type: 'object',
                    required: ['name'],
                    properties: {
                        name:      { type: 'string', minLength: 1, maxLength: 255 },
                        parent_id: { type: 'string', format: 'uuid', nullable: true },
                    },
                },
                response: {
                    201: orgResponse,
                    400: badRequest, 401: unauthorized, 403: forbidden,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const { name, parent_id } = req.body as { name: string; parent_id?: string | null };
            const orgIds = getOrgScope(req, reply, false);
            if (orgIds === null) return reply;
            const orgId = orgIds[0] ?? null;

            const permOrgId = parent_id ?? orgId;
            const permTarget = parent_id ? 'orgs' : 'root_orgs';
            if (!await hasPermission(db, req, reply, permOrgId ?? null, 'create', permTarget)) return reply;

            if (checkLimit) {
                const ok = await checkLimit(
                    reply, 'max_orgs',
                    'SELECT count(*)::TEXT AS c FROM morbac.orgs WHERE id <> $1::UUID',
                    [SYSTEM_ORG_ID],
                );
                if (!ok) return reply;
            }

            const { rows } = await db.query<OrgRow>(
                'INSERT INTO morbac.orgs (name, parent_id) VALUES ($1, $2) RETURNING id, name, parent_id, metadata',
                [name, parent_id ?? null],
            );
            emitOrgEvent?.({ action: 'created', org: rows[0], actorId: user.id });
            return reply.code(201).send(rows[0]);
        });

        app.patch('/orgs/:id', {
            schema: {
                tags: ['Management'],
                summary: 'Update an organisation',
                description: 'Updates an organisation name or parent. Requires `update`/`orgs` permission in the target org.',
                security: [{ oauth2: [] }],
                params: { type: 'object', properties: { id: { type: 'string', format: 'uuid' } } },
                body: {
                    type: 'object',
                    properties: {
                        name:      { type: 'string', minLength: 1, maxLength: 255 },
                        parent_id: { type: 'string', format: 'uuid', nullable: true },
                    },
                },
                response: {
                    200: orgResponse,
                    400: badRequest, 401: unauthorized, 403: forbidden, 404: notFound,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const { id } = req.params as { id: string };
            if (id === SYSTEM_ORG_ID) return reply.code(403).send({ error: 'System entities are immutable' });
            if (!await hasPermission(db, req, reply, id, 'update', 'orgs')) return reply;

            const body = req.body as { name?: string; parent_id?: string | null };
            const { rows } = await db.query<OrgRow & { reparented: boolean }>(
                `WITH prev AS (SELECT parent_id AS old_parent FROM morbac.orgs WHERE id = $4)
                 UPDATE morbac.orgs o
                 SET name      = CASE WHEN $1::text IS NOT NULL THEN $1 ELSE name END,
                     parent_id = CASE WHEN $2 THEN NULL WHEN $3::text IS NOT NULL THEN $3::uuid ELSE parent_id END
                 FROM prev
                 WHERE o.id = $4
                 RETURNING o.id, o.name, o.parent_id, o.metadata,
                           (o.parent_id IS DISTINCT FROM prev.old_parent) AS reparented`,
                [body.name ?? null, body.parent_id === null, body.parent_id ?? null, id],
            );
            if (!rows[0]) return reply.code(404).send({ error: 'Not found' });
            const { reparented, ...org } = rows[0];
            emitOrgEvent?.({ action: 'updated', org: { ...org, reparented }, actorId: user.id });
            return org;
        });

        app.delete('/orgs/:id', {
            schema: {
                tags: ['Management'],
                summary: 'Delete an organisation',
                description: 'Deletes an organisation and all its children (cascade). Requires `delete`/`orgs` permission.',
                security: [{ oauth2: [] }],
                params: { type: 'object', properties: { id: { type: 'string', format: 'uuid' } } },
                response: {
                    204: { type: 'null', description: 'Organisation deleted.' },
                    400: badRequest, 401: unauthorized, 403: forbidden,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const { id } = req.params as { id: string };
            if (id === SYSTEM_ORG_ID) return reply.code(403).send({ error: 'System entities are immutable' });
            if (!await hasPermission(db, req, reply, id, 'delete', 'orgs')) return reply;

            const { rows } = await db.query<OrgRow>(
                'DELETE FROM morbac.orgs WHERE id = $1 RETURNING id, name, parent_id, metadata',
                [id],
            );
            if (rows[0]) emitOrgEvent?.({ action: 'deleted', org: rows[0], actorId: user.id });
            return reply.code(204).send();
        });
    };
}
