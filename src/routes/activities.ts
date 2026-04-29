import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import { getUser, getOrgScope, hasPermission } from '../permissions.js';
import { unauthorized, badRequest, forbidden } from '../schemas.js';

export function createActivityRoutes(db: Pool) {
    return async function activityRoutes(app: FastifyInstance) {
        app.get('/activities', {
            schema: {
                tags: ['Management'],
                summary: 'List activities',
                description: 'Read-only list of permission verbs (read, create, update, delete). Managed at the database level.',
                security: [{ oauth2: [] }],
                response: {
                    200: {
                        type: 'array',
                        items: {
                            type: 'object',
                            properties: {
                                name:        { type: 'string' },
                                description: { type: 'string', nullable: true },
                            },
                        },
                    },
                    401: unauthorized,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });
            const { rows } = await db.query('SELECT name, description FROM morbac.activities ORDER BY name');
            return rows;
        });

        app.get('/activities/:name/users', {
            schema: {
                tags: ['Management'],
                summary: 'List users with a given activity',
                description: 'Returns users who have permissions via roles or direct user rules for the given activity.',
                security: [{ oauth2: [] }],
                params: { type: 'object', properties: { name: { type: 'string' } } },
                response: {
                    200: {
                        type: 'array',
                        items: {
                            type: 'object',
                            properties: {
                                id:           { type: 'string', format: 'uuid' },
                                user_name:    { type: 'string' },
                                email:        { type: 'string', nullable: true },
                                account_type: { type: 'string' },
                                org_id:       { type: 'string', format: 'uuid' },
                                org_name:     { type: 'string' },
                                role_id:      { type: 'string', format: 'uuid', nullable: true },
                                role_name:    { type: 'string', nullable: true },
                                source:       { type: 'string' },
                            },
                        },
                    },
                    400: badRequest, 401: unauthorized, 403: forbidden,
                },
            },
        }, async (req, reply) => {
            const caller = getUser(req);
            if (!caller) return reply.code(401).send({ error: 'Authentication required' });

            const orgIds = getOrgScope(req, reply, false);
            if (orgIds === null) return reply;
            if (!await hasPermission(db, req, reply, orgIds[0] ?? null, 'read', 'users')) return reply;

            const { name } = req.params as { name: string };
            const { rows } = await db.query(
                `SELECT DISTINCT
                     u.id, u.name AS user_name, u.email, u.account_type,
                     o.id AS org_id, o.name AS org_name,
                     ur.role_id, ro.name AS role_name,
                     'role' AS source
                 FROM morbac.user_roles ur
                 JOIN morbac.mv_role_closure rc ON rc.senior_role_id = ur.role_id
                 JOIN morbac.rules r ON r.role_id = rc.junior_role_id AND r.activity = $1
                 JOIN app.users u ON u.id = ur.user_id
                 JOIN morbac.orgs o ON o.id = ur.org_id
                 JOIN morbac.roles ro ON ro.id = ur.role_id
                 WHERE morbac.org_in_scope(ur.org_id, r.org_id, r.scope)

                 UNION

                 SELECT DISTINCT
                     u.id, u.name AS user_name, u.email, u.account_type,
                     o.id AS org_id, o.name AS org_name,
                     NULL::UUID AS role_id, NULL::TEXT AS role_name,
                     'direct' AS source
                 FROM morbac.user_rules urr
                 JOIN app.users u ON u.id = urr.user_id
                 JOIN morbac.orgs o ON o.id = urr.org_id
                 WHERE urr.activity = $1

                 ORDER BY user_name, org_name`,
                [name],
            );
            return rows;
        });

        app.get('/views', {
            schema: {
                tags: ['Management'],
                summary: 'List views',
                description: 'Read-only list of permission subjects (the resources activities apply to). Managed at the database level.',
                security: [{ oauth2: [] }],
                response: {
                    200: {
                        type: 'array',
                        items: {
                            type: 'object',
                            properties: {
                                name:        { type: 'string' },
                                description: { type: 'string', nullable: true },
                            },
                        },
                    },
                    401: unauthorized,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });
            const { rows } = await db.query('SELECT name, description FROM morbac.views ORDER BY name');
            return rows;
        });

        app.get('/views/:name/users', {
            schema: {
                tags: ['Management'],
                summary: 'List users with a given view',
                description: 'Returns users who have permissions via roles or direct user rules for the given view.',
                security: [{ oauth2: [] }],
                params: { type: 'object', properties: { name: { type: 'string' } } },
                response: {
                    200: {
                        type: 'array',
                        items: {
                            type: 'object',
                            properties: {
                                id:           { type: 'string', format: 'uuid' },
                                user_name:    { type: 'string' },
                                email:        { type: 'string', nullable: true },
                                account_type: { type: 'string' },
                                org_id:       { type: 'string', format: 'uuid' },
                                org_name:     { type: 'string' },
                                role_id:      { type: 'string', format: 'uuid', nullable: true },
                                role_name:    { type: 'string', nullable: true },
                                source:       { type: 'string' },
                            },
                        },
                    },
                    400: badRequest, 401: unauthorized, 403: forbidden,
                },
            },
        }, async (req, reply) => {
            const caller = getUser(req);
            if (!caller) return reply.code(401).send({ error: 'Authentication required' });

            const orgIds = getOrgScope(req, reply, false);
            if (orgIds === null) return reply;
            if (!await hasPermission(db, req, reply, orgIds[0] ?? null, 'read', 'users')) return reply;

            const { name } = req.params as { name: string };
            const { rows } = await db.query(
                `SELECT DISTINCT
                     u.id, u.name AS user_name, u.email, u.account_type,
                     o.id AS org_id, o.name AS org_name,
                     ur.role_id, ro.name AS role_name,
                     'role' AS source
                 FROM morbac.user_roles ur
                 JOIN morbac.mv_role_closure rc ON rc.senior_role_id = ur.role_id
                 JOIN morbac.rules r ON r.role_id = rc.junior_role_id AND r.view = $1
                 JOIN app.users u ON u.id = ur.user_id
                 JOIN morbac.orgs o ON o.id = ur.org_id
                 JOIN morbac.roles ro ON ro.id = ur.role_id
                 WHERE morbac.org_in_scope(ur.org_id, r.org_id, r.scope)

                 UNION

                 SELECT DISTINCT
                     u.id, u.name AS user_name, u.email, u.account_type,
                     o.id AS org_id, o.name AS org_name,
                     NULL::UUID AS role_id, NULL::TEXT AS role_name,
                     'direct' AS source
                 FROM morbac.user_rules urr
                 JOIN app.users u ON u.id = urr.user_id
                 JOIN morbac.orgs o ON o.id = urr.org_id
                 WHERE urr.view = $1

                 ORDER BY user_name, org_name`,
                [name],
            );
            return rows;
        });

        app.get('/activity-view-bindings', {
            schema: {
                tags: ['Management'],
                summary: 'List activity-view bindings',
                description: 'Valid (activity, view) pairs that can be used when creating rules. Activities with no bindings accept any view.',
                security: [{ oauth2: [] }],
                response: {
                    200: {
                        type: 'array',
                        items: {
                            type: 'object',
                            properties: {
                                activity: { type: 'string' },
                                view:     { type: 'string' },
                            },
                        },
                    },
                    401: unauthorized,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });
            const { rows } = await db.query(
                'SELECT activity, view FROM morbac.activity_view_bindings ORDER BY activity, view',
            );
            return rows;
        });
    };
}
