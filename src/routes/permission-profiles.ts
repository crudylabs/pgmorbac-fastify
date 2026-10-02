import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import type { CheckLimitFn, RoleEventSink } from '../plugin.js';
import { getUser, getOrgScope, hasPermission, SYSTEM_ORG_ID } from '../permissions.js';
import { roleResponse, notFound, forbidden, unauthorized, badRequest } from '../schemas.js';
import { loadProfile, validateGrantable, applyProfileRules } from './profile-apply.js';

const profileResponse = {
    type: 'object',
    properties: {
        module_id:    { type: 'string' },
        key:          { type: 'string' },
        content_hash: { type: 'string' },
        rules: {
            type: 'array',
            items: {
                type: 'object',
                properties: {
                    activity: { type: 'string' },
                    view:     { type: 'string' },
                    modality: { type: 'string' },
                    scope:    { type: 'string' },
                },
            },
        },
    },
};

const profileRef = {
    type: 'object',
    required: ['module_id', 'key'],
    properties: {
        module_id: { type: 'string', maxLength: 128 },
        key:       { type: 'string', maxLength: 128 },
    },
};

export function createPermissionProfileRoutes(db: Pool, checkLimit?: CheckLimitFn, emitRoleEvent?: RoleEventSink) {
    return async function permissionProfileRoutes(app: FastifyInstance) {
        app.get('/permission-profiles', {
            schema: {
                tags: ['Management'],
                summary: 'List permission profiles',
                description: 'Returns role presets declared by modules. Requires `read`/`roles`.',
                security: [{ oauth2: [] }],
                querystring: {
                    type: 'object',
                    properties: { module_id: { type: 'string', maxLength: 128 } },
                },
                response: {
                    200: { type: 'array', items: profileResponse },
                    400: badRequest, 401: unauthorized, 403: forbidden,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const orgIds = getOrgScope(req, reply, false);
            if (orgIds === null) return reply;
            if (!await hasPermission(db, req, reply, orgIds[0] ?? null, 'read', 'roles')) return reply;

            const { module_id } = req.query as { module_id?: string };
            const { rows } = await db.query(
                `SELECT module_id, key, content_hash, rules
                 FROM app.permission_profiles
                 ${module_id ? 'WHERE module_id = $1' : ''}
                 ORDER BY module_id, key`,
                module_id ? [module_id] : [],
            );
            return rows;
        });

        app.post('/roles/from-profile', {
            schema: {
                tags: ['Management'],
                summary: 'Create a role from a profile',
                description:
                    'Creates a role in the target org and seeds its rules from a module profile. '
                    + 'Requires `create`/`roles`, and the caller must already hold every granted permission. '
                    + 'When `sync` is true the role tracks future profile changes.',
                security: [{ oauth2: [] }],
                body: {
                    type: 'object',
                    required: ['org_id', 'name', 'profile'],
                    properties: {
                        org_id:      { type: 'string', format: 'uuid' },
                        name:        { type: 'string', minLength: 1, maxLength: 200 },
                        description: { type: 'string', maxLength: 500 },
                        sync:        { type: 'boolean', default: false },
                        profile:     profileRef,
                    },
                },
                response: {
                    201: roleResponse,
                    400: badRequest, 401: unauthorized, 403: forbidden, 404: notFound,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const { org_id, name, description, sync, profile } = req.body as {
                org_id: string; name: string; description?: string; sync?: boolean;
                profile: { module_id: string; key: string };
            };

            if (org_id === SYSTEM_ORG_ID) return reply.code(403).send({ error: 'System entities are immutable' });
            if (!await hasPermission(db, req, reply, org_id, 'create', 'roles')) return reply;

            const prof = await loadProfile(db, profile.module_id, profile.key);
            if (!prof) return reply.code(404).send({ error: 'Not found' });

            if (checkLimit) {
                const ok = await checkLimit(reply, 'max_roles', 'SELECT count(*)::TEXT AS c FROM morbac.roles');
                if (!ok) return reply;
            }
            if (!await validateGrantable(db, reply, user.id, org_id, prof.rules)) return reply;

            const client = await db.connect();
            try {
                await client.query('BEGIN');
                const { rows: [role] } = await client.query(
                    `INSERT INTO morbac.roles (org_id, name, description) VALUES ($1, $2, $3)
                     RETURNING id, org_id, name, description`,
                    [org_id, name, description ?? null],
                );
                const nonSelf = await applyProfileRules(client, org_id, role.id, profile.module_id, profile.key, prof.rules);
                if (sync) {
                    await client.query(
                        `INSERT INTO app.role_profile_links (role_id, module_id, profile_key, synced, applied_hash)
                         VALUES ($1, $2, $3, TRUE, $4)`,
                        [role.id, profile.module_id, profile.key, prof.content_hash],
                    );
                }
                await client.query('COMMIT');
                if (nonSelf) await db.query('SELECT morbac.invalidate_cache()');

                const org = await db.query('SELECT name FROM morbac.orgs WHERE id = $1', [org_id]);
                emitRoleEvent?.({ action: 'created', role, actorId: user.id });
                return reply.code(201).send({ ...role, org_name: org.rows[0]?.name });
            } catch (e) {
                await client.query('ROLLBACK');
                throw e;
            } finally {
                client.release();
            }
        });

        app.post('/roles/:id/profile-sync', {
            schema: {
                tags: ['Management'],
                summary: 'Attach a profile to an existing role',
                description:
                    'Applies a module profile to an existing role and records the link. Requires '
                    + '`update`/`roles`, and the caller must already hold every granted permission. '
                    + 'When `sync` is true the role tracks future profile changes.',
                security: [{ oauth2: [] }],
                params: { type: 'object', properties: { id: { type: 'string', format: 'uuid' } } },
                body: {
                    type: 'object',
                    required: ['profile'],
                    properties: {
                        profile: profileRef,
                        sync:    { type: 'boolean', default: true },
                    },
                },
                response: {
                    200: {
                        type: 'object',
                        properties: {
                            role_id:      { type: 'string', format: 'uuid' },
                            module_id:    { type: 'string' },
                            profile_key:  { type: 'string' },
                            synced:       { type: 'boolean' },
                            applied_hash: { type: 'string' },
                        },
                    },
                    400: badRequest, 401: unauthorized, 403: forbidden, 404: notFound,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const { id } = req.params as { id: string };
            const { profile, sync } = req.body as { profile: { module_id: string; key: string }; sync?: boolean };
            const synced = sync !== false;

            const { rows: [roleRow] } = await db.query<{ org_id: string }>(
                'SELECT org_id FROM morbac.roles WHERE id = $1', [id],
            );
            if (!roleRow) return reply.code(404).send({ error: 'Not found' });
            if (roleRow.org_id === SYSTEM_ORG_ID) return reply.code(403).send({ error: 'System entities are immutable' });
            if (!await hasPermission(db, req, reply, roleRow.org_id, 'update', 'roles')) return reply;

            const prof = await loadProfile(db, profile.module_id, profile.key);
            if (!prof) return reply.code(404).send({ error: 'Not found' });
            if (!await validateGrantable(db, reply, user.id, roleRow.org_id, prof.rules)) return reply;

            const client = await db.connect();
            try {
                await client.query('BEGIN');
                const nonSelf = await applyProfileRules(client, roleRow.org_id, id, profile.module_id, profile.key, prof.rules);
                await client.query(
                    `INSERT INTO app.role_profile_links (role_id, module_id, profile_key, synced, applied_hash, applied_at)
                     VALUES ($1, $2, $3, $4, $5, now())
                     ON CONFLICT (role_id)
                     DO UPDATE SET module_id = EXCLUDED.module_id, profile_key = EXCLUDED.profile_key,
                                   synced = EXCLUDED.synced, applied_hash = EXCLUDED.applied_hash, applied_at = now()`,
                    [id, profile.module_id, profile.key, synced, prof.content_hash],
                );
                await client.query('COMMIT');
                if (nonSelf) await db.query('SELECT morbac.invalidate_cache()');
                return reply.send({ role_id: id, module_id: profile.module_id, profile_key: profile.key, synced, applied_hash: prof.content_hash });
            } catch (e) {
                await client.query('ROLLBACK');
                throw e;
            } finally {
                client.release();
            }
        });

        app.delete('/roles/:id/profile-sync', {
            schema: {
                tags: ['Management'],
                summary: 'Detach a role from its profile',
                description:
                    "Removes the profile link so the role stops tracking the profile. Requires "
                    + "`update`/`roles`. Already-applied rules are left in place.",
                security: [{ oauth2: [] }],
                params: { type: 'object', properties: { id: { type: 'string', format: 'uuid' } } },
                response: {
                    204: { type: 'null', description: 'Link removed.' },
                    400: badRequest, 401: unauthorized, 403: forbidden, 404: notFound,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const { id } = req.params as { id: string };
            const { rows: [roleRow] } = await db.query<{ org_id: string }>(
                'SELECT org_id FROM morbac.roles WHERE id = $1', [id],
            );
            if (!roleRow) return reply.code(404).send({ error: 'Not found' });
            if (roleRow.org_id === SYSTEM_ORG_ID) return reply.code(403).send({ error: 'System entities are immutable' });
            if (!await hasPermission(db, req, reply, roleRow.org_id, 'update', 'roles')) return reply;

            await db.query('DELETE FROM app.role_profile_links WHERE role_id = $1', [id]);
            return reply.code(204).send();
        });
    };
}
