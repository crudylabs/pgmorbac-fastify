import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import type { CheckLimitFn } from '../plugin.js';
import {
    getUser, getOrgScope, orgScopeExpr, hasPermission, canActOnUser, checkApiKeyScope,
    getAccountType, viewForType, SYSTEM_ORG_ID,
} from '../permissions.js';
import { userResponse, notFound, forbidden, unauthorized, badRequest } from '../schemas.js';
import { generatePassword } from '../password.js';
import { callerControlsRoleOrg } from './role-authority.js';

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
            // A user awaiting placement belongs to no org, so seeing one is the
            // no-org perimeter (a NULL org), not a claim about every org. Any
            // grant that reaches it answers: a role rule scoped unattributed or
            // all, a user rule with no org, or a global rule.
            const [sysRes, svcRes, noOrgRes] = await Promise.all([
                db.query<{ allowed: boolean }>('SELECT morbac.is_allowed($1::UUID, $2::UUID, $3, $4) AS allowed',
                    [user.id, checkOrg, 'read', 'system_users']),
                db.query<{ allowed: boolean }>('SELECT morbac.is_allowed($1::UUID, $2::UUID, $3, $4) AS allowed',
                    [user.id, checkOrg, 'read', 'service_users']),
                db.query<{ allowed: boolean }>('SELECT morbac.is_allowed($1::UUID, NULL, $2, $3) AS allowed',
                    [user.id, 'read', 'users']),
            ]);
            const canSeeSystem      = sysRes.rows[0]?.allowed   ?? false;
            const canSeeService     = svcRes.rows[0]?.allowed   ?? false;
            const canReadUnattached = noOrgRes.rows[0]?.allowed ?? false;

            const { expr, params } = orgScopeExpr(orgIds, 'ur2.org_id');
            const isSystemScope = orgIds.includes(SYSTEM_ORG_ID);
            const placement = canReadUnattached ? ' OR u.needs_placement' : '';
            const whereClause = expr && !isSystemScope
                ? `WHERE (u.id IN (SELECT ur2.user_id FROM morbac.user_roles ur2 WHERE ${expr})${placement} OR u.account_type IN ('system', 'service'))`
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
                description: 'Creates a user account. For `user` accounts a strong password is auto-generated and returned once as `generated_password`; the account must change it on first login. `service` accounts have no password (API-only). Requires `create`/`users` (or `create`/`service_users`) permission. Pass `placement` to give the account a role in one go: an account created without one is unplaced, and only a holder of unattributed `read`/`users` can see it afterwards, so a manager who creates a user without placing it loses sight of it.',
                security: [{ oauth2: [] }],
                body: {
                    type: 'object',
                    required: ['email', 'name'],
                    properties: {
                        email:        { type: 'string', format: 'email', maxLength: 320 },
                        name:         { type: 'string', minLength: 1, maxLength: 255 },
                        account_type: { type: 'string', enum: ['user', 'service'], default: 'user' },
                        is_active:    { type: 'boolean', default: true },
                        placement:    {
                            type: 'object',
                            required: ['role_id', 'org_id'],
                            additionalProperties: false,
                            properties: {
                                role_id: { type: 'string', format: 'uuid' },
                                org_id:  { type: 'string', format: 'uuid' },
                            },
                        },
                    },
                },
                response: {
                    201: { ...userResponse, properties: { ...userResponse.properties, generated_password: { type: 'string' } } },
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

            const { email: rawEmail, name, account_type = 'user', is_active = true, placement } = req.body as {
                email: string; name: string;
                account_type?: 'user' | 'service'; is_active?: boolean;
                placement?: { role_id: string; org_id: string };
            };
            const email = rawEmail.trim().toLowerCase();
            const view = viewForType(account_type);
            if (!await hasPermission(db, req, reply, orgId, 'create', view)) return reply;

            // Placing the account is a second act of authority, checked before
            // anything is written so a refused placement creates no account.
            if (placement) {
                const assignView = account_type === 'service' ? 'service_users' : 'user_roles';
                if (!await hasPermission(db, req, reply, placement.org_id, 'create', assignView)) return reply;
                if (!await callerControlsRoleOrg(db, user.id, placement.role_id, 'create')) {
                    return reply.code(403).send({ error: 'Cannot assign a role outside your authority' });
                }
            }

            if (checkLimit) {
                const limitName = account_type === 'service' ? 'max_service_users' : 'max_users';
                const ok = await checkLimit(
                    reply, limitName,
                    `SELECT count(*)::TEXT AS c FROM app.users WHERE account_type = $1`,
                    [account_type],
                );
                if (!ok) return reply;
            }

            // Passwords are never admin-supplied. User accounts get a strong generated
            // password (returned once) and must change it on first login. Service
            // accounts are API-only and have no password.
            const generated = account_type === 'user' ? generatePassword() : null;
            const hash = generated ? await bcrypt.hash(generated, 12) : null;
            const tx = await db.connect();
            try {
                await tx.query('BEGIN');
                const { rows } = await tx.query(
                    `INSERT INTO app.users (email, name, password_hash, account_type, is_active, must_change_password)
                     VALUES ($1, $2, $3, $4, $5, $6)
                     RETURNING id, email, name, account_type, is_active, needs_placement, created_at`,
                    [email, name, hash, account_type, is_active, generated !== null],
                );
                const created = rows[0] as { id: string; needs_placement: boolean };
                const roles: { role_id: string; org_id: string }[] = [];
                if (placement) {
                    await tx.query('SELECT morbac.assign_role($1::UUID, $2::UUID, $3::UUID)',
                        [created.id, placement.role_id, placement.org_id]);
                    await tx.query('UPDATE app.users SET needs_placement = FALSE WHERE id = $1', [created.id]);
                    created.needs_placement = false;
                    roles.push(placement);
                }
                await tx.query('COMMIT');
                return reply.code(201).send({ ...created, roles, ...(generated && { generated_password: generated }) });
            } catch (e: unknown) {
                await tx.query('ROLLBACK').catch(() => undefined);
                if ((e as { code?: string }).code === '23505') return reply.code(409).send({ error: 'Email already in use' });
                if ((e as { message?: string }).message?.includes('Separation of Duty')) {
                    return reply.code(409).send({ error: 'Role assignment would violate Separation of Duty constraints' });
                }
                throw e;
            } finally {
                tx.release();
            }
        });

        app.patch('/users/:id', {
            schema: {
                tags: ['Management'],
                summary: 'Update a user',
                description: "Updates a user's name, email, or active status. Passwords are never admin-supplied: set `reset_password: true` to generate a new strong password (returned once as `generated_password`) which the user must change on next login. Requires `update`/`users` (or `update`/`service_users`) permission.",
                security: [{ oauth2: [] }],
                params: { type: 'object', properties: { id: { type: 'string', format: 'uuid' } } },
                body: {
                    type: 'object',
                    properties: {
                        name:           { type: 'string', minLength: 1, maxLength: 255 },
                        email:          { type: 'string', format: 'email', maxLength: 320 },
                        is_active:      { type: 'boolean' },
                        reset_password: { type: 'boolean' },
                    },
                },
                response: {
                    200: { ...userResponse, properties: { ...userResponse.properties, generated_password: { type: 'string' } } },
                    400: badRequest, 401: unauthorized, 403: forbidden, 404: notFound,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const { id } = req.params as { id: string };
            const type = await getAccountType(db, id);
            if (!type) return reply.code(404).send({ error: 'Not found' });
            if (type === 'system') return reply.code(403).send({ error: 'System entities are immutable' });
            const view = viewForType(type);
            if (!checkApiKeyScope(req, reply, 'update', view)) return reply;
            if (!await canActOnUser(db, user.id, id, 'update', view)) {
                return reply.code(404).send({ error: 'Not found' });
            }

            const { name, email, is_active, reset_password } = req.body as {
                name?: string; email?: string; is_active?: boolean; reset_password?: boolean;
            };
            // Only 'user' accounts have passwords. Service accounts authenticate via API keys.
            const generated = reset_password && type === 'user' ? generatePassword() : null;
            const hash = generated ? await bcrypt.hash(generated, 12) : null;
            const { rows } = await db.query(
                `UPDATE app.users
                 SET name          = COALESCE($1, name),
                     email         = COALESCE($2, email),
                     is_active     = COALESCE($3, is_active),
                     password_hash = COALESCE($4, password_hash),
                     must_change_password = CASE WHEN $4 IS NOT NULL THEN TRUE ELSE must_change_password END
                 WHERE id = $5
                 RETURNING id, email, name, account_type, is_active, needs_placement, created_at`,
                [name ?? null, email ?? null, is_active ?? null, hash, id],
            );
            if (!rows[0]) return reply.code(404).send({ error: 'Not found' });
            return reply.send({ ...rows[0], ...(generated && { generated_password: generated }) });
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

            const { id } = req.params as { id: string };
            const type = await getAccountType(db, id);
            if (!type) return reply.code(404).send({ error: 'Not found' });
            if (type === 'system') return reply.code(403).send({ error: 'System entities are immutable' });
            const view = viewForType(type);
            if (!checkApiKeyScope(req, reply, 'delete', view)) return reply;
            if (!await canActOnUser(db, user.id, id, 'delete', view)) {
                return reply.code(404).send({ error: 'Not found' });
            }

            await db.query('DELETE FROM app.users WHERE id = $1', [id]);
            return reply.code(204).send();
        });
    };
}
