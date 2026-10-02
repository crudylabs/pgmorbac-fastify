import { randomBytes, createHash } from 'node:crypto';
import type { FastifyInstance, FastifyReply } from 'fastify';
import type { Pool } from 'pg';
import { getUser, canActOnUser, checkApiKeyScope, getAccountType } from '../permissions.js';
import { notFound, forbidden, unauthorized, badRequest } from '../schemas.js';

function generateKey(): { raw: string; hash: string; prefix: string } {
    const raw    = 'pgm_' + randomBytes(16).toString('hex');
    const hash   = createHash('sha256').update(raw).digest('hex');
    const prefix = raw.slice(0, 12);
    return { raw, hash, prefix };
}

const keyResponse = {
    type: 'object',
    properties: {
        id:               { type: 'string', format: 'uuid' },
        name:             { type: 'string' },
        description:      { type: 'string', nullable: true },
        key_prefix:       { type: 'string' },
        readonly:         { type: 'boolean' },
        permission_scope: {},
        expires_at:       { type: 'string', format: 'date-time', nullable: true },
        last_used_at:     { type: 'string', format: 'date-time', nullable: true },
        created_at:       { type: 'string', format: 'date-time' },
    },
};

type Scope = 'inherit' | Array<{ activity: string; view: string }>;

// Distinct (activity, view) pairs a user/service account currently holds. Used
// both to populate the scope picker and to cap a key's scope server-side, so the
// two can never diverge. Mirrors GET /me/permissions for the target account.
const HELD_PERMS_SQL = `
    SELECT DISTINCT activity, view FROM (
        SELECT activity, view FROM morbac.user_rules
          WHERE user_id = $1 AND modality = 'permission' AND activity IS NOT NULL AND view IS NOT NULL
        UNION
        SELECT activity, view FROM morbac.global_rules
          WHERE (user_id = $1 OR user_id IS NULL) AND modality = 'permission' AND activity IS NOT NULL AND view IS NOT NULL
        UNION
        SELECT r.activity, r.view FROM morbac.rules r
          JOIN morbac.user_roles ur ON ur.role_id = r.role_id
          WHERE ur.user_id = $1 AND r.modality = 'permission' AND r.is_active = TRUE
        UNION
        SELECT a.name, v.name FROM morbac.activities a CROSS JOIN morbac.views v
          WHERE EXISTS (
              SELECT 1 FROM morbac.global_rules gr
              WHERE gr.user_id = $1 AND gr.modality = 'permission' AND gr.activity IS NULL AND gr.view IS NULL
          )
    ) t`;

async function heldPerms(db: Pool, userId: string): Promise<Array<{ activity: string; view: string }>> {
    const { rows } = await db.query<{ activity: string; view: string }>(HELD_PERMS_SQL, [userId]);
    return rows;
}

// API keys are only manageable for service accounts. Minting a key for a human
// ('user') or 'system' account would be impersonation, so those are treated as
// non-existent here (404). Keys inherit the service account's own permissions.
export function createUserKeyRoutes(db: Pool) {
    return async function userKeyRoutes(app: FastifyInstance) {
        async function ensureService(id: string, reply: FastifyReply): Promise<boolean> {
            const type = await getAccountType(db, id);
            if (type !== 'service') { await reply.code(404).send({ error: 'Not found' }); return false; }
            return true;
        }

        app.get('/users/:id/keys', {
            schema: {
                tags: ['Management'],
                summary: 'List a service account API keys',
                description: 'Lists API keys belonging to a service account. Requires `read`/`service_users`.',
                security: [{ oauth2: [] }],
                params: { type: 'object', properties: { id: { type: 'string', format: 'uuid' } } },
                response: { 200: { type: 'array', items: keyResponse }, 401: unauthorized, 403: forbidden, 404: notFound },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });
            const { id } = req.params as { id: string };
            if (!await ensureService(id, reply)) return reply;
            if (!checkApiKeyScope(req, reply, 'read', 'service_users')) return reply;
            if (!await canActOnUser(db, user.id, id, 'read', 'service_users')) return reply.code(404).send({ error: 'Not found' });

            const { rows } = await db.query(
                `SELECT id, name, description, key_prefix, readonly, permission_scope, expires_at, last_used_at, created_at
                 FROM app.api_keys WHERE user_id = $1 ORDER BY created_at DESC`,
                [id],
            );
            return rows;
        });

        app.get('/users/:id/permission-options', {
            schema: {
                tags: ['Management'],
                summary: 'List a service account delegatable permissions',
                description: 'Distinct (activity, view) pairs the service account holds, for restricting an API key scope. Requires `read`/`service_users`.',
                security: [{ oauth2: [] }],
                params: { type: 'object', properties: { id: { type: 'string', format: 'uuid' } } },
                response: {
                    200: { type: 'array', items: { type: 'object', properties: { activity: { type: 'string' }, view: { type: 'string' } } } },
                    401: unauthorized, 403: forbidden, 404: notFound,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });
            const { id } = req.params as { id: string };
            if (!await ensureService(id, reply)) return reply;
            if (!checkApiKeyScope(req, reply, 'read', 'service_users')) return reply;
            if (!await canActOnUser(db, user.id, id, 'read', 'service_users')) return reply.code(404).send({ error: 'Not found' });

            return heldPerms(db, id);
        });

        app.post('/users/:id/keys', {
            schema: {
                tags: ['Management'],
                summary: 'Create an API key for a service account',
                description: 'Mints an API key for a service account. The full key is returned once. Requires `create`/`service_users`.',
                security: [{ oauth2: [] }],
                params: { type: 'object', properties: { id: { type: 'string', format: 'uuid' } } },
                body: {
                    type: 'object',
                    required: ['name'],
                    properties: {
                        name:        { type: 'string', minLength: 1, maxLength: 255 },
                        description: { type: 'string', maxLength: 1000 },
                        readonly:    { type: 'boolean', default: false },
                        expires_at:  { type: 'string', format: 'date-time', nullable: true },
                        permission_scope: {},
                    },
                },
                response: {
                    201: { ...keyResponse, properties: { ...keyResponse.properties, key: { type: 'string' } } },
                    400: badRequest, 401: unauthorized, 403: forbidden, 404: notFound, 409: { description: 'A key with this name already exists.' },
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });
            const { id } = req.params as { id: string };
            if (!await ensureService(id, reply)) return reply;
            if (!checkApiKeyScope(req, reply, 'create', 'service_users')) return reply;
            if (!await canActOnUser(db, user.id, id, 'create', 'service_users')) return reply.code(404).send({ error: 'Not found' });

            const { name, description, readonly = false, expires_at, permission_scope } = req.body as {
                name: string; description?: string; readonly?: boolean; expires_at?: string | null; permission_scope?: Scope;
            };

            const scope: Scope = permission_scope ?? 'inherit';
            if (scope !== 'inherit' && !Array.isArray(scope)) {
                return reply.code(400).send({ error: 'permission_scope must be "inherit" or an array of {activity, view}' });
            }
            if (Array.isArray(scope)) {
                if (scope.length > 200) return reply.code(400).send({ error: 'permission_scope has too many entries' });
                for (const pair of scope) {
                    if (!pair || typeof pair.activity !== 'string' || typeof pair.view !== 'string'
                        || pair.activity.length < 1 || pair.activity.length > 64
                        || pair.view.length < 1 || pair.view.length > 64) {
                        return reply.code(400).send({ error: 'permission_scope entries must be {activity, view} strings' });
                    }
                }
                const held = await heldPerms(db, id);
                const heldSet = new Set(held.map((p) => `${p.activity} ${p.view}`));
                for (const pair of scope) {
                    if (!heldSet.has(`${pair.activity} ${pair.view}`)) {
                        return reply.code(400).send({ error: 'Scope includes a permission the service account does not hold' });
                    }
                }
            }

            const { raw, hash, prefix } = generateKey();
            try {
                const { rows } = await db.query(
                    `INSERT INTO app.api_keys (user_id, name, description, key_hash, key_prefix, readonly, expires_at, permission_scope)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
                     RETURNING id, name, description, key_prefix, readonly, permission_scope, expires_at, last_used_at, created_at`,
                    [id, name, description ?? null, hash, prefix, readonly, expires_at ?? null, JSON.stringify(scope)],
                );
                return reply.code(201).send({ ...rows[0], key: raw });
            } catch (e: unknown) {
                if ((e as { code?: string }).code === '23505') return reply.code(409).send({ error: 'A key with this name already exists' });
                throw e;
            }
        });

        app.delete('/users/:id/keys/:keyId', {
            schema: {
                tags: ['Management'],
                summary: 'Revoke a service account API key',
                description: 'Revokes an API key belonging to a service account. Requires `delete`/`service_users`.',
                security: [{ oauth2: [] }],
                params: { type: 'object', properties: { id: { type: 'string', format: 'uuid' }, keyId: { type: 'string', format: 'uuid' } } },
                response: { 204: { type: 'null', description: 'Key revoked.' }, 401: unauthorized, 403: forbidden, 404: notFound },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });
            const { id, keyId } = req.params as { id: string; keyId: string };
            if (!await ensureService(id, reply)) return reply;
            if (!checkApiKeyScope(req, reply, 'delete', 'service_users')) return reply;
            if (!await canActOnUser(db, user.id, id, 'delete', 'service_users')) return reply.code(404).send({ error: 'Not found' });

            await db.query('DELETE FROM app.api_keys WHERE id = $1 AND user_id = $2', [keyId, id]);
            return reply.code(204).send();
        });
    };
}
