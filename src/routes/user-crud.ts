import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import type { CheckLimitFn } from '../plugin.js';
import {
    getUser, getOrgScope, orgScopeExpr, hasPermission, getAccountType, viewForType, SYSTEM_ORG_ID,
} from '../permissions.js';
import { userResponse, notFound, forbidden, unauthorized, badRequest } from '../schemas.js';

export function createUserCrudRoutes(db: Pool, checkLimit?: CheckLimitFn) {
    return async function userCrudRoutes(app: FastifyInstance) {
        app.get('/users', {
            schema: {
                tags: ['Management'],
                summary: 'List users',
                description: 'Returns users who have at least one role within the scoped org subtree. System and service accounts are filtered based on `read`/`system_users` and `read`/`service_users` permissions.',
                security: [{ oauth2: [] }],
                response: {
                    200: { type: 'array', items: userResponse },
                    400: badRequest, 401: unauthorized, 403: forbidden,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const orgIds = getOrgScope(req, reply, false);
            if (orgIds === null) return reply;

            if (!await hasPermission(db, req, reply, orgIds[0] ?? null, 'read', 'users')) return reply;

            const checkOrg = orgIds[0] ?? null;
            const [sysRes, svcRes, globalRes] = await Promise.all([
                db.query<{ allowed: boolean }>('SELECT morbac.is_allowed($1::UUID, $2::UUID, $3, $4) AS allowed',
                    [user.id, checkOrg, 'read', 'system_users']),
                db.query<{ allowed: boolean }>('SELECT morbac.is_allowed($1::UUID, $2::UUID, $3, $4) AS allowed',
                    [user.id, checkOrg, 'read', 'service_users']),
                db.query<{ allowed: boolean }>('SELECT morbac.is_allowed($1::UUID, NULL, $2, $3) AS allowed',
                    [user.id, 'read', 'users']),
            ]);
            const canSeeSystem    = sysRes.rows[0]?.allowed    ?? false;
            const canSeeService   = svcRes.rows[0]?.allowed   ?? false;
            const canReadGlobally = globalRes.rows[0]?.allowed ?? false;

            const { expr, params } = orgScopeExpr(orgIds, 'ur2.org_id');
            const isSystemScope = orgIds.includes(SYSTEM_ORG_ID);
            const placement = canReadGlobally ? ' OR u.needs_placement' : '';
            const whereClause = expr && !isSystemScope
                ? `WHERE (u.id IN (SELECT ur2.user_id FROM morbac.user_roles ur2 WHERE ${expr})${placement})`
                : '';
            const { rows } = await db.query(
                `SELECT
                     u.id, u.email, u.name, u.account_type, u.is_active, u.needs_placement, u.created_at,
                     COALESCE(
                         json_agg(json_build_object(
                             'role_id',   ur.role_id,
                             'role_name', r.name,
                             'org_id',    ur.org_id,
                             'org_name',  o.name
                         )) FILTER (WHERE ur.role_id IS NOT NULL),
                         '[]'::json
                     ) AS roles
                 FROM app.users u
                 LEFT JOIN morbac.user_roles ur ON ur.user_id = u.id
                 LEFT JOIN morbac.roles      r  ON r.id = ur.role_id
                 LEFT JOIN morbac.orgs       o  ON o.id = ur.org_id
                 ${whereClause}
                 GROUP BY u.id ORDER BY u.name`,
                whereClause ? params : [],
            );
            return (rows as { account_type: string }[]).filter((u) => {
                if (u.account_type === 'system'  && !canSeeSystem)  return false;
                if (u.account_type === 'service' && !canSeeService) return false;
                return true;
            });
        });

        app.post('/users', {
            schema: {
                tags: ['Management'],
                summary: 'Create a user',
                description: 'Creates a user account. Requires `create`/`users` (or `create`/`service_users`) permission in the scoped org.',
                security: [{ oauth2: [] }],
                body: {
                    type: 'object',
                    required: ['email', 'name'],
                    properties: {
                        email:        { type: 'string', format: 'email', maxLength: 320 },
                        name:         { type: 'string', minLength: 1, maxLength: 255 },
                        password:     { type: 'string', minLength: 8, maxLength: 1024 },
                        account_type: { type: 'string', enum: ['user', 'service'], default: 'user' },
                        is_active:    { type: 'boolean', default: true },
                    },
                },
                response: {
                    201: userResponse,
                    400: badRequest, 401: unauthorized, 403: forbidden,
                    409: { description: 'Email already in use.' },
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const orgIds = getOrgScope(req, reply, false);
            if (orgIds === null) return reply;
            const orgId = orgIds[0] ?? null;

            const { email: rawEmail, name, password, account_type = 'user', is_active = true } = req.body as {
                email: string; name: string; password?: string;
                account_type?: 'user' | 'service'; is_active?: boolean;
            };
            const email = rawEmail.trim().toLowerCase();
            const view = viewForType(account_type);
            if (!await hasPermission(db, req, reply, orgId, 'create', view)) return reply;

            if (checkLimit) {
                const limitName = account_type === 'service' ? 'max_service_users' : 'max_users';
                const ok = await checkLimit(
                    reply, limitName,
                    `SELECT count(*)::TEXT AS c FROM app.users WHERE account_type = $1`,
                    [account_type],
                );
                if (!ok) return reply;
            }

            const hash = password ? await bcrypt.hash(password, 12) : null;
            try {
                const { rows } = await db.query(
                    `INSERT INTO app.users (email, name, password_hash, account_type, is_active)
                     VALUES ($1, $2, $3, $4, $5)
                     RETURNING id, email, name, account_type, is_active, needs_placement, created_at`,
                    [email, name, hash, account_type, is_active],
                );
                return reply.code(201).send({ ...rows[0], roles: [] });
            } catch (e: unknown) {
                if ((e as { code?: string }).code === '23505') return reply.code(409).send({ error: 'Email already in use' });
                throw e;
            }
        });

        app.patch('/users/:id', {
            schema: {
                tags: ['Management'],
                summary: 'Update a user',
                description: "Updates a user's name, email, password, or active status. Requires `update`/`users` (or `update`/`service_users`) permission.",
                security: [{ oauth2: [] }],
                params: { type: 'object', properties: { id: { type: 'string', format: 'uuid' } } },
                body: {
                    type: 'object',
                    properties: {
                        name:      { type: 'string', minLength: 1, maxLength: 255 },
                        email:     { type: 'string', format: 'email', maxLength: 320 },
                        password:  { type: 'string', minLength: 8, maxLength: 1024 },
                        is_active: { type: 'boolean' },
                    },
                },
                response: {
                    200: userResponse,
                    400: badRequest, 401: unauthorized, 403: forbidden, 404: notFound,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const orgIds = getOrgScope(req, reply, false);
            if (orgIds === null) return reply;
            const orgId = orgIds[0] ?? null;

            const { id } = req.params as { id: string };
            const type = await getAccountType(db, id);
            if (!type) return reply.code(404).send({ error: 'Not found' });
            if (type === 'system') return reply.code(403).send({ error: 'System entities are immutable' });
            if (!await hasPermission(db, req, reply, orgId, 'update', viewForType(type))) return reply;

            const { name, email, password, is_active } = req.body as {
                name?: string; email?: string; password?: string; is_active?: boolean;
            };
            const hash = password ? await bcrypt.hash(password, 12) : null;
            const { rows } = await db.query(
                `UPDATE app.users
                 SET name          = COALESCE($1, name),
                     email         = COALESCE($2, email),
                     is_active     = COALESCE($3, is_active),
                     password_hash = COALESCE($4, password_hash)
                 WHERE id = $5
                 RETURNING id, email, name, account_type, is_active, needs_placement, created_at`,
                [name ?? null, email ?? null, is_active ?? null, hash, id],
            );
            if (!rows[0]) return reply.code(404).send({ error: 'Not found' });
            return rows[0];
        });

        app.delete('/users/:id', {
            schema: {
                tags: ['Management'],
                summary: 'Delete a user',
                description: 'Permanently deletes a user account. Requires `delete`/`users` (or `delete`/`service_users`) permission.',
                security: [{ oauth2: [] }],
                params: { type: 'object', properties: { id: { type: 'string', format: 'uuid' } } },
                response: {
                    204: { type: 'null', description: 'User deleted.' },
                    400: badRequest, 401: unauthorized, 403: forbidden, 404: notFound,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const orgIds = getOrgScope(req, reply, false);
            if (orgIds === null) return reply;
            const orgId = orgIds[0] ?? null;

            const { id } = req.params as { id: string };
            const type = await getAccountType(db, id);
            if (!type) return reply.code(404).send({ error: 'Not found' });
            if (type === 'system') return reply.code(403).send({ error: 'System entities are immutable' });
            if (!await hasPermission(db, req, reply, orgId, 'delete', viewForType(type))) return reply;

            await db.query('DELETE FROM app.users WHERE id = $1', [id]);
            return reply.code(204).send();
        });
    };
}
