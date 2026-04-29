import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import type { CheckLimitFn } from '../plugin.js';
import {
    getUser, getOrgScope, orgScopeExpr, hasPermission, SYSTEM_ORG_ID,
} from '../permissions.js';
import { roleResponse, notFound, forbidden, unauthorized, badRequest } from '../schemas.js';

export function createRoleRoutes(db: Pool, checkLimit?: CheckLimitFn) {
    return async function roleRoutes(app: FastifyInstance) {
        app.get('/roles', {
            schema: {
                tags: ['Management'],
                summary: 'List roles',
                description: 'Returns roles within the scoped org subtree.',
                security: [{ oauth2: [] }],
                response: {
                    200: { type: 'array', items: roleResponse },
                    400: badRequest, 401: unauthorized, 403: forbidden,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const orgIds = getOrgScope(req, reply, false);
            if (orgIds === null) return reply;

            if (!await hasPermission(db, req, reply, orgIds[0] ?? null, 'read', 'roles')) return reply;

            const { expr, params } = orgScopeExpr(orgIds, 'r.org_id');
            const { rows } = await db.query(
                `SELECT r.id, r.org_id, r.name, r.description, o.name AS org_name
                 FROM morbac.roles r
                 JOIN morbac.orgs o ON o.id = r.org_id
                 ${expr ? `WHERE ${expr}` : ''}
                 ORDER BY o.name, r.name`,
                params,
            );
            return rows;
        });

        app.post('/roles', {
            schema: {
                tags: ['Management'],
                summary: 'Create a role',
                description: 'Creates a role scoped to the given org. Requires `create`/`roles` permission.',
                security: [{ oauth2: [] }],
                body: {
                    type: 'object',
                    required: ['org_id', 'name'],
                    properties: {
                        org_id:      { type: 'string', format: 'uuid' },
                        name:        { type: 'string', minLength: 1 },
                        description: { type: 'string' },
                    },
                },
                response: {
                    201: roleResponse,
                    400: badRequest, 401: unauthorized, 403: forbidden,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const { org_id, name, description } = req.body as {
                org_id: string; name: string; description?: string;
            };
            if (!await hasPermission(db, req, reply, org_id, 'create', 'roles')) return reply;

            if (checkLimit) {
                const ok = await checkLimit(reply, 'max_roles', 'SELECT count(*)::TEXT AS c FROM morbac.roles');
                if (!ok) return reply;
            }

            const { rows } = await db.query(
                `INSERT INTO morbac.roles (org_id, name, description) VALUES ($1, $2, $3)
                 RETURNING id, org_id, name, description`,
                [org_id, name, description ?? null],
            );
            const org = await db.query('SELECT name FROM morbac.orgs WHERE id = $1', [org_id]);
            return reply.code(201).send({ ...rows[0], org_name: org.rows[0]?.name });
        });

        app.patch('/roles/:id', {
            schema: {
                tags: ['Management'],
                summary: 'Update a role',
                description: "Updates a role name or description. Requires `update`/`roles` permission in the role's org.",
                security: [{ oauth2: [] }],
                params: { type: 'object', properties: { id: { type: 'string', format: 'uuid' } } },
                body: {
                    type: 'object',
                    properties: {
                        name:        { type: 'string', minLength: 1 },
                        description: { type: 'string', nullable: true },
                    },
                },
                response: {
                    200: roleResponse,
                    400: badRequest, 401: unauthorized, 403: forbidden, 404: notFound,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const { id } = req.params as { id: string };
            const roleOrg = await db.query<{ org_id: string }>(
                'SELECT org_id FROM morbac.roles WHERE id = $1', [id],
            );
            if (!roleOrg.rows[0]) return reply.code(404).send({ error: 'Not found' });
            if (roleOrg.rows[0].org_id === SYSTEM_ORG_ID) return reply.code(403).send({ error: 'System entities are immutable' });
            if (!await hasPermission(db, req, reply, roleOrg.rows[0].org_id, 'update', 'roles')) return reply;

            const { name, description } = req.body as { name?: string; description?: string };
            const { rows } = await db.query(
                `UPDATE morbac.roles
                 SET name        = COALESCE($1, name),
                     description = COALESCE($2, description)
                 WHERE id = $3
                 RETURNING id, org_id, name, description,
                           (SELECT name FROM morbac.orgs WHERE id = org_id) AS org_name`,
                [name ?? null, description ?? null, id],
            );
            if (!rows[0]) return reply.code(404).send({ error: 'Not found' });
            return rows[0];
        });

        app.delete('/roles/:id', {
            schema: {
                tags: ['Management'],
                summary: 'Delete a role',
                description: "Deletes a role. Requires `delete`/`roles` permission in the role's org.",
                security: [{ oauth2: [] }],
                params: { type: 'object', properties: { id: { type: 'string', format: 'uuid' } } },
                response: {
                    204: { type: 'null', description: 'Role deleted.' },
                    400: badRequest, 401: unauthorized, 403: forbidden, 404: notFound,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const { id } = req.params as { id: string };
            const roleOrg = await db.query<{ org_id: string }>(
                'SELECT org_id FROM morbac.roles WHERE id = $1', [id],
            );
            if (!roleOrg.rows[0]) return reply.code(404).send({ error: 'Not found' });
            if (roleOrg.rows[0].org_id === SYSTEM_ORG_ID) return reply.code(403).send({ error: 'System entities are immutable' });
            if (!await hasPermission(db, req, reply, roleOrg.rows[0].org_id, 'delete', 'roles')) return reply;

            await db.query('DELETE FROM morbac.roles WHERE id = $1', [id]);
            return reply.code(204).send();
        });

        app.get('/role-hierarchy', {
            schema: {
                tags: ['Management'],
                summary: 'List role hierarchy edges',
                description: 'Returns senior->junior role relationships within the scoped org subtree.',
                security: [{ oauth2: [] }],
                response: {
                    200: {
                        type: 'array',
                        items: {
                            type: 'object',
                            properties: {
                                senior_role_id: { type: 'string', format: 'uuid' },
                                senior_name:    { type: 'string' },
                                junior_role_id: { type: 'string', format: 'uuid' },
                                junior_name:    { type: 'string' },
                                org_id:         { type: 'string', format: 'uuid' },
                                org_name:       { type: 'string' },
                            },
                        },
                    },
                    400: badRequest, 401: unauthorized, 403: forbidden,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const orgIds = getOrgScope(req, reply, false);
            if (orgIds === null) return reply;

            if (!await hasPermission(db, req, reply, orgIds[0] ?? null, 'read', 'roles')) return reply;

            const { expr, params } = orgScopeExpr(orgIds, 'rs.org_id');
            const { rows } = await db.query(
                `SELECT rh.senior_role_id, rs.name AS senior_name,
                        rh.junior_role_id, rj.name AS junior_name,
                        rs.org_id, o.name AS org_name
                 FROM morbac.role_hierarchy rh
                 JOIN morbac.roles rs ON rs.id = rh.senior_role_id
                 JOIN morbac.roles rj ON rj.id = rh.junior_role_id
                 JOIN morbac.orgs  o  ON o.id  = rs.org_id
                 ${expr ? `WHERE ${expr}` : ''}`,
                params,
            );
            return rows;
        });

        app.post('/role-hierarchy', {
            schema: {
                tags: ['Management'],
                summary: 'Add a hierarchy edge',
                description: '`senior_role` inherits all permissions of `junior_role`. Requires `update`/`roles` in the senior role\'s org.',
                security: [{ oauth2: [] }],
                body: {
                    type: 'object',
                    required: ['senior_role_id', 'junior_role_id'],
                    properties: {
                        senior_role_id: { type: 'string', format: 'uuid' },
                        junior_role_id: { type: 'string', format: 'uuid' },
                    },
                },
                response: {
                    201: {
                        type: 'object',
                        properties: {
                            senior_role_id: { type: 'string', format: 'uuid' },
                            junior_role_id: { type: 'string', format: 'uuid' },
                        },
                    },
                    400: badRequest, 401: unauthorized, 403: forbidden, 404: notFound,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const { senior_role_id, junior_role_id } = req.body as {
                senior_role_id: string; junior_role_id: string;
            };
            const roleOrg = await db.query<{ org_id: string }>(
                'SELECT org_id FROM morbac.roles WHERE id = $1', [senior_role_id],
            );
            if (!roleOrg.rows[0]) return reply.code(404).send({ error: 'Senior role not found' });
            if (roleOrg.rows[0].org_id === SYSTEM_ORG_ID) return reply.code(403).send({ error: 'System entities are immutable' });
            if (!await hasPermission(db, req, reply, roleOrg.rows[0].org_id, 'update', 'roles')) return reply;

            await db.query(
                'INSERT INTO morbac.role_hierarchy (senior_role_id, junior_role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                [senior_role_id, junior_role_id],
            );
            return reply.code(201).send({ senior_role_id, junior_role_id });
        });

        app.delete('/role-hierarchy', {
            schema: {
                tags: ['Management'],
                summary: 'Remove a hierarchy edge',
                description: "Removes the senior->junior inheritance link. Requires `update`/`roles` in the senior role's org.",
                security: [{ oauth2: [] }],
                body: {
                    type: 'object',
                    required: ['senior_role_id', 'junior_role_id'],
                    properties: {
                        senior_role_id: { type: 'string', format: 'uuid' },
                        junior_role_id: { type: 'string', format: 'uuid' },
                    },
                },
                response: {
                    204: { type: 'null', description: 'Edge removed.' },
                    400: badRequest, 401: unauthorized, 403: forbidden, 404: notFound,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const { senior_role_id, junior_role_id } = req.body as {
                senior_role_id: string; junior_role_id: string;
            };
            const roleOrg = await db.query<{ org_id: string }>(
                'SELECT org_id FROM morbac.roles WHERE id = $1', [senior_role_id],
            );
            if (!roleOrg.rows[0]) return reply.code(404).send({ error: 'Senior role not found' });
            if (roleOrg.rows[0].org_id === SYSTEM_ORG_ID) return reply.code(403).send({ error: 'System entities are immutable' });
            if (!await hasPermission(db, req, reply, roleOrg.rows[0].org_id, 'update', 'roles')) return reply;

            await db.query(
                'DELETE FROM morbac.role_hierarchy WHERE senior_role_id = $1 AND junior_role_id = $2',
                [senior_role_id, junior_role_id],
            );
            return reply.code(204).send();
        });
    };
}
