import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import { getUser, getOrgScope, orgScopeExpr, hasPermission } from '../permissions.js';
import { userRuleResponse, notFound, forbidden, unauthorized, badRequest } from '../schemas.js';

export function createUserRuleRoutes(db: Pool) {
    return async function userRuleRoutes(app: FastifyInstance) {
        app.get('/user-rules', {
            schema: {
                tags: ['Management'],
                summary: 'List user rules',
                description: 'Direct per-user authorization rules that bypass the role system.',
                security: [{ oauth2: [] }],
                response: {
                    200: { type: 'array', items: userRuleResponse },
                    400: badRequest, 401: unauthorized, 403: forbidden,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const orgIds = getOrgScope(req, reply, false);
            if (orgIds === null) return reply;

            if (!await hasPermission(db, req, reply, orgIds[0] ?? null, 'read', 'user_rules')) return reply;

            const { expr, params } = orgScopeExpr(orgIds, 'ur.org_id');
            const { rows } = await db.query(
                `SELECT ur.id, ur.user_id, ur.org_id,
                        COALESCE(u.name, ur.user_id::TEXT) AS user_name,
                        u.email AS user_email,
                        o.name  AS org_name,
                        ur.activity, ur.view, ur.modality, ur.priority
                 FROM morbac.user_rules ur
                 JOIN morbac.orgs  o ON o.id = ur.org_id
                 LEFT JOIN app.users u ON u.id = ur.user_id
                 ${expr ? `WHERE ${expr}` : ''}
                 ORDER BY o.name, ur.activity, ur.view`,
                params,
            );
            return rows;
        });

        app.post('/user-rules', {
            schema: {
                tags: ['Management'],
                summary: 'Create a user rule',
                description: 'Grants or prohibits access for a specific user, bypassing the role system. Requires `create`/`user_rules`.',
                security: [{ oauth2: [] }],
                body: {
                    type: 'object',
                    required: ['user_id', 'org_id', 'activity', 'view', 'modality'],
                    properties: {
                        user_id:  { type: 'string', format: 'uuid' },
                        org_id:   { type: 'string', format: 'uuid' },
                        activity: { type: 'string' },
                        view:     { type: 'string' },
                        modality: { type: 'string', enum: ['permission', 'prohibition'] },
                        priority: { type: 'integer' },
                    },
                },
                response: {
                    201: userRuleResponse,
                    400: badRequest, 401: unauthorized, 403: forbidden,
                    409: { description: 'Rule already exists.' },
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const { user_id, org_id, activity, view, modality, priority } = req.body as {
                user_id: string; org_id: string; activity: string;
                view: string; modality: 'permission' | 'prohibition'; priority?: number;
            };

            if (!await hasPermission(db, req, reply, org_id, 'create', 'user_rules')) return reply;

            try {
                const { rows } = await db.query(
                    `INSERT INTO morbac.user_rules
                         (user_id, org_id, activity, view, context_id, modality, priority)
                     VALUES (
                         $1, $2, $3, $4,
                         (SELECT id FROM morbac.contexts WHERE name = 'always'),
                         $5::morbac.modality, $6
                     )
                     RETURNING id, user_id, $2::UUID AS org_id,
                         COALESCE((SELECT name  FROM app.users WHERE id = $1), $1::TEXT) AS user_name,
                         (SELECT email FROM app.users WHERE id = $1) AS user_email,
                         (SELECT name  FROM morbac.orgs WHERE id = $2) AS org_name,
                         activity, view, modality, priority`,
                    [user_id, org_id, activity, view, modality, priority ?? null],
                );
                return reply.code(201).send(rows[0]);
            } catch (e: unknown) {
                if ((e as { code?: string }).code === '23505') return reply.code(409).send({ error: 'Rule already exists' });
                throw e;
            }
        });

        app.delete('/user-rules/:id', {
            schema: {
                tags: ['Management'],
                summary: 'Delete a user rule',
                description: "Removes a per-user rule. Requires `delete`/`user_rules` in the rule's org.",
                security: [{ oauth2: [] }],
                params: { type: 'object', properties: { id: { type: 'string', format: 'uuid' } } },
                response: {
                    204: { type: 'null', description: 'Rule deleted.' },
                    400: badRequest, 401: unauthorized, 403: forbidden, 404: notFound,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const { id } = req.params as { id: string };
            const { rows: [ur] } = await db.query<{ org_id: string }>(
                'SELECT org_id FROM morbac.user_rules WHERE id = $1', [id],
            );
            if (!ur) return reply.code(404).send({ error: 'Not found' });
            if (!await hasPermission(db, req, reply, ur.org_id, 'delete', 'user_rules')) return reply;

            await db.query('DELETE FROM morbac.user_rules WHERE id = $1', [id]);
            return reply.code(204).send();
        });
    };
}
