import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import { getUser, hasPermission, SYSTEM_ORG_ID } from '../permissions.js';
import { globalRuleResponse, notFound, forbidden, unauthorized } from '../schemas.js';

export function createGlobalRoutes(db: Pool) {
    return async function globalRoutes(app: FastifyInstance) {
        app.get('/global-rules', {
            schema: {
                tags: ['Management'],
                summary: 'List global rules',
                description: 'System-wide permission rules not bound to any organisation or role. Requires `read`/`rules` in the system org.',
                security: [{ oauth2: [] }],
                response: {
                    200: { type: 'array', items: globalRuleResponse },
                    401: unauthorized, 403: forbidden,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            if (!await hasPermission(db, req, reply, SYSTEM_ORG_ID, 'read', 'rules')) return reply;

            const { rows } = await db.query(
                `SELECT gr.id,
                        gr.user_id,
                        COALESCE(u.name, gr.user_id::TEXT) AS user_name,
                        u.email AS user_email,
                        gr.activity, gr.view, gr.modality, gr.priority,
                        (sp.user_id IS NOT NULL) AS is_system_principal,
                        (gr.user_id IS NULL AND gr.view = 'system_users' AND gr.modality = 'prohibition') AS is_system_managed
                 FROM morbac.global_rules gr
                 LEFT JOIN app.users u ON u.id = gr.user_id
                 LEFT JOIN morbac.system_principals sp ON sp.user_id = gr.user_id
                 ORDER BY u.name NULLS LAST, gr.activity, gr.view`,
            );
            return rows;
        });

        app.post('/global-rules', {
            schema: {
                tags: ['Management'],
                summary: 'Create a global rule',
                description: 'Grants or prohibits access system-wide for a user (or all users when `user_id` is null). `activity`/`view` null = any activity/view. Requires `create`/`rules` in the system org.',
                security: [{ oauth2: [] }],
                body: {
                    type: 'object',
                    required: ['modality'],
                    properties: {
                        user_id:  { type: 'string', format: 'uuid', nullable: true },
                        activity: { type: 'string', nullable: true },
                        view:     { type: 'string', nullable: true },
                        modality: { type: 'string', enum: ['permission', 'prohibition'] },
                        priority: { type: 'integer' },
                    },
                },
                response: {
                    201: globalRuleResponse,
                    401: unauthorized, 403: forbidden,
                    409: { description: 'Rule already exists.' },
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const { user_id, activity, view, modality, priority } = req.body as {
                user_id?: string | null; activity?: string | null; view?: string | null;
                modality: 'permission' | 'prohibition'; priority?: number;
            };

            if (user_id) {
                const { rows: [sp] } = await db.query(
                    'SELECT 1 FROM morbac.system_principals WHERE user_id = $1', [user_id],
                );
                if (sp) return reply.code(403).send({ error: 'System principal rules are immutable' });
            }

            if (!await hasPermission(db, req, reply, SYSTEM_ORG_ID, 'create', 'rules')) return reply;

            try {
                const { rows } = await db.query(
                    `INSERT INTO morbac.global_rules (user_id, activity, view, context_id, modality, priority)
                     VALUES ($1, $2, $3, (SELECT id FROM morbac.contexts WHERE name = 'always'), $4::morbac.modality, $5)
                     RETURNING id, user_id,
                         (SELECT name  FROM app.users WHERE id = $1) AS user_name,
                         (SELECT email FROM app.users WHERE id = $1) AS user_email,
                         activity, view, modality, priority,
                         FALSE AS is_system_principal,
                         (user_id IS NULL AND view = 'system_users' AND modality = 'prohibition') AS is_system_managed`,
                    [user_id ?? null, activity ?? null, view ?? null, modality, priority ?? null],
                );
                return reply.code(201).send(rows[0]);
            } catch (e: unknown) {
                if ((e as { code?: string }).code === '23505') return reply.code(409).send({ error: 'Rule already exists' });
                throw e;
            }
        });

        app.delete('/global-rules/:id', {
            schema: {
                tags: ['Management'],
                summary: 'Delete a global rule',
                description: 'Removes a global rule. Requires `delete`/`rules` in the system org. System principal rules cannot be deleted.',
                security: [{ oauth2: [] }],
                params: { type: 'object', properties: { id: { type: 'string', format: 'uuid' } } },
                response: {
                    204: { type: 'null', description: 'Rule deleted.' },
                    401: unauthorized, 403: forbidden, 404: notFound,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const { id } = req.params as { id: string };
            const { rows: [gr] } = await db.query<{ user_id: string | null; is_system_managed: boolean }>(
                `SELECT user_id,
                        (user_id IS NULL AND view = 'system_users' AND modality = 'prohibition') AS is_system_managed
                 FROM morbac.global_rules WHERE id = $1`, [id],
            );
            if (!gr) return reply.code(404).send({ error: 'Not found' });

            if (gr.is_system_managed) return reply.code(403).send({ error: 'System-managed rules are immutable' });

            if (gr.user_id) {
                const { rows: [sp] } = await db.query(
                    'SELECT 1 FROM morbac.system_principals WHERE user_id = $1', [gr.user_id],
                );
                if (sp) return reply.code(403).send({ error: 'System principal rules are immutable' });
            }

            if (!await hasPermission(db, req, reply, SYSTEM_ORG_ID, 'delete', 'rules')) return reply;

            await db.query('DELETE FROM morbac.global_rules WHERE id = $1', [id]);
            return reply.code(204).send();
        });
    };
}
