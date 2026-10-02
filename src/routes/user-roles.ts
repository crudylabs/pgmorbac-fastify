import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import { getUser, getOrgScope, hasPermission, getAccountType } from '../permissions.js';

import { notFound, forbidden, unauthorized, badRequest } from '../schemas.js';
import { callerControlsRoleOrg } from './role-authority.js';

export function createUserRoleRoutes(db: Pool) {
    return async function userRoleRoutes(app: FastifyInstance) {
        app.post('/users/:id/roles', {
            schema: {
                tags: ['Management'],
                summary: 'Assign a role to a user',
                description: 'Assigns a role to a user in the given org. Requires `create`/`user_roles` permission (or `create`/`service_users` for service accounts).',
                security: [{ oauth2: [] }],
                params: { type: 'object', properties: { id: { type: 'string', format: 'uuid' } } },
                body: {
                    type: 'object',
                    required: ['role_id', 'org_id'],
                    properties: {
                        role_id: { type: 'string', format: 'uuid' },
                        org_id:  { type: 'string', format: 'uuid' },
                    },
                },
                response: {
                    201: {
                        type: 'object',
                        properties: {
                            user_id: { type: 'string', format: 'uuid' },
                            role_id: { type: 'string', format: 'uuid' },
                            org_id:  { type: 'string', format: 'uuid' },
                        },
                    },
                    400: badRequest, 401: unauthorized, 403: forbidden,
                    409: { description: 'Would violate a Separation of Duty constraint.' },
                },
            },
        }, async (req, reply) => {
            const caller = getUser(req);
            if (!caller) return reply.code(401).send({ error: 'Authentication required' });

            const { id: user_id } = req.params as { id: string };
            const { role_id, org_id } = req.body as { role_id: string; org_id: string };

            const assignType = await getAccountType(db, user_id);
            if (assignType === 'system') return reply.code(403).send({ error: 'System account roles are immutable' });
            const assignView = assignType === 'service' ? 'service_users' : 'user_roles';
            if (!await hasPermission(db, req, reply, org_id, 'create', assignView)) return reply;
            if (!await callerControlsRoleOrg(db, caller.id, role_id, 'create')) {
                return reply.code(403).send({ error: 'Cannot assign a role outside your authority' });
            }

            try {
                await db.query(
                    'SELECT morbac.assign_role($1::UUID, $2::UUID, $3::UUID)',
                    [user_id, role_id, org_id],
                );
            } catch (e: unknown) {
                if ((e as { message?: string }).message?.includes('Separation of Duty')) {
                    return reply.code(409).send({ error: 'Role assignment would violate Separation of Duty constraints' });
                }
                throw e;
            }
            await db.query('UPDATE app.users SET needs_placement = FALSE WHERE id = $1 AND needs_placement', [user_id]);
            return reply.code(201).send({ user_id, role_id, org_id });
        });

        app.get('/users/:id/effective-permissions', {
            schema: {
                tags: ['Management'],
                summary: 'Get effective permissions for a user',
                description: 'Returns the flattened list of all rules applying to a user: role-based rules (including role hierarchy), direct user rules, and global rules.',
                security: [{ oauth2: [] }],
                params: { type: 'object', properties: { id: { type: 'string', format: 'uuid' } } },
                response: {
                    200: {
                        type: 'array',
                        items: {
                            type: 'object',
                            properties: {
                                activity:  { type: 'string', nullable: true },
                                view:      { type: 'string', nullable: true },
                                modality:  { type: 'string', enum: ['permission', 'prohibition'] },
                                scope:     { type: 'string', nullable: true },
                                org_id:    { type: 'string', format: 'uuid', nullable: true },
                                org_name:  { type: 'string', nullable: true },
                                role_id:   { type: 'string', format: 'uuid', nullable: true },
                                role_name: { type: 'string', nullable: true },
                                source:    { type: 'string' },
                            },
                        },
                    },
                    400: badRequest, 401: unauthorized, 403: forbidden, 404: notFound,
                },
            },
        }, async (req, reply) => {
            const caller = getUser(req);
            if (!caller) return reply.code(401).send({ error: 'Authentication required' });

            const orgIds = getOrgScope(req, reply, false);
            if (orgIds === null) return reply;
            if (!await hasPermission(db, req, reply, orgIds[0] ?? null, 'read', 'users')) return reply;

            const { id } = req.params as { id: string };
            const exists = await db.query('SELECT 1 FROM app.users WHERE id = $1', [id]);
            if (!exists.rows[0]) return reply.code(404).send({ error: 'Not found' });

            const { rows } = await db.query(
                `SELECT DISTINCT
                     r.activity, r.view, r.modality, r.scope,
                     o.id AS org_id, o.name AS org_name,
                     ro.id AS role_id, ro.name AS role_name,
                     'role' AS source
                 FROM morbac.user_roles ur
                 JOIN morbac.mv_role_closure rc ON rc.senior_role_id = ur.role_id
                 JOIN morbac.rules r ON r.role_id = rc.junior_role_id
                 JOIN morbac.orgs o ON o.id = r.org_id
                 JOIN morbac.roles ro ON ro.id = r.role_id
                 WHERE ur.user_id = $1
                   AND morbac.org_in_scope(ur.org_id, r.org_id, r.scope)

                 UNION ALL

                 SELECT DISTINCT
                     urr.activity, urr.view, urr.modality, NULL AS scope,
                     o.id AS org_id, o.name AS org_name,
                     NULL::UUID AS role_id, NULL::TEXT AS role_name,
                     'direct' AS source
                 FROM morbac.user_rules urr
                 JOIN morbac.orgs o ON o.id = urr.org_id
                 WHERE urr.user_id = $1

                 UNION ALL

                 SELECT DISTINCT
                     gr.activity, gr.view, gr.modality, NULL AS scope,
                     NULL::UUID AS org_id, NULL::TEXT AS org_name,
                     NULL::UUID AS role_id, NULL::TEXT AS role_name,
                     'global' AS source
                 FROM morbac.global_rules gr
                 WHERE gr.user_id = $1

                 ORDER BY source, org_name NULLS LAST, activity, view`,
                [id],
            );
            return rows;
        });

        app.delete('/users/:id/roles', {
            schema: {
                tags: ['Management'],
                summary: 'Remove a role from a user',
                description: 'Revokes a role from a user in the given org. Requires `delete`/`user_roles` permission (or `delete`/`service_users` for service accounts).',
                security: [{ oauth2: [] }],
                params: { type: 'object', properties: { id: { type: 'string', format: 'uuid' } } },
                body: {
                    type: 'object',
                    required: ['role_id', 'org_id'],
                    properties: {
                        role_id: { type: 'string', format: 'uuid' },
                        org_id:  { type: 'string', format: 'uuid' },
                    },
                },
                response: {
                    204: { type: 'null', description: 'Role assignment removed.' },
                    400: badRequest, 401: unauthorized, 403: forbidden,
                },
            },
        }, async (req, reply) => {
            const caller = getUser(req);
            if (!caller) return reply.code(401).send({ error: 'Authentication required' });

            const { id: user_id } = req.params as { id: string };
            const { role_id, org_id } = req.body as { role_id: string; org_id: string };

            const revokeType = await getAccountType(db, user_id);
            if (revokeType === 'system') return reply.code(403).send({ error: 'System account roles are immutable' });
            const revokeView = revokeType === 'service' ? 'service_users' : 'user_roles';
            if (!await hasPermission(db, req, reply, org_id, 'delete', revokeView)) return reply;
            if (!await callerControlsRoleOrg(db, caller.id, role_id, 'delete')) {
                return reply.code(403).send({ error: 'Cannot revoke a role outside your authority' });
            }

            await db.query(
                'SELECT morbac.revoke_role($1::UUID, $2::UUID, $3::UUID)',
                [user_id, role_id, org_id],
            );
            return reply.code(204).send();
        });
    };
}
