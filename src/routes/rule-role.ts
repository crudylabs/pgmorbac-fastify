import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import { getUser, getOrgScope, orgScopeExpr, hasPermission, SYSTEM_ORG_ID } from '../permissions.js';
import { ruleResponse, notFound, forbidden, unauthorized, badRequest } from '../schemas.js';

export function createRoleRuleRoutes(db: Pool) {
    return async function roleRuleRoutes(app: FastifyInstance) {
        app.get('/rules', {
            schema: {
                tags: ['Management'],
                summary: 'List role rules',
                description: 'Returns role-based permission rules within the scoped org subtree.',
                security: [{ oauth2: [] }],
                response: {
                    200: { type: 'array', items: ruleResponse },
                    400: badRequest, 401: unauthorized, 403: forbidden,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const orgIds = getOrgScope(req, reply, false);
            if (orgIds === null) return reply;

            if (!await hasPermission(db, req, reply, orgIds[0] ?? null, 'read', 'rules')) return reply;

            const { expr, params } = orgScopeExpr(orgIds, 'r.org_id');
            const { rows } = await db.query(
                `SELECT r.id, r.role_id, r.org_id, o.name AS org_name, ro.name AS role_name,
                        r.activity, r.view, r.modality, r.priority, r.scope
                 FROM morbac.rules r
                 JOIN morbac.orgs  o  ON o.id  = r.org_id
                 JOIN morbac.roles ro ON ro.id = r.role_id
                 ${expr ? `WHERE ${expr}` : ''}
                 ORDER BY o.name, ro.name, r.activity, r.view`,
                params,
            );
            return rows;
        });

        app.post('/rules', {
            schema: {
                tags: ['Management'],
                summary: 'Create a role rule',
                description: 'Adds a role-based permission rule. Scope is stored natively and evaluated at query time.',
                security: [{ oauth2: [] }],
                body: {
                    type: 'object',
                    required: ['org_id', 'role_id', 'activity', 'view', 'modality'],
                    properties: {
                        org_id:   { type: 'string', format: 'uuid' },
                        role_id:  { type: 'string', format: 'uuid' },
                        activity: { type: 'string' },
                        view:     { type: 'string' },
                        modality: { type: 'string', enum: ['permission', 'prohibition'] },
                        priority: { type: 'integer' },
                        scope: {
                            type: 'string',
                            enum: ['self', 'children', 'descendants', 'subtree', 'parent', 'ancestors', 'lineage', 'root'],
                            default: 'self',
                        },
                    },
                },
                response: {
                    201: ruleResponse,
                    400: badRequest, 401: unauthorized, 403: forbidden, 404: notFound,
                    409: { description: 'Rule already exists.' },
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const { org_id, role_id, activity, view, modality, priority, scope = 'self' } = req.body as {
                org_id: string; role_id: string; activity: string;
                view: string; modality: 'permission' | 'prohibition'; priority?: number; scope?: string;
            };

            if (!await hasPermission(db, req, reply, org_id, 'create', 'rules')) return reply;

            try {
                const { rows } = await db.query(
                    `INSERT INTO morbac.rules
                         (org_id, role_id, activity, view, context_id, modality, scope, priority, is_active)
                     VALUES (
                         $1, $2, $3, $4,
                         (SELECT id FROM morbac.contexts WHERE name = 'always'),
                         $5::morbac.modality, $6, $7, TRUE
                     )
                     RETURNING id, $2::UUID AS role_id, $1::UUID AS org_id,
                         (SELECT name FROM morbac.orgs  WHERE id = $1) AS org_name,
                         (SELECT name FROM morbac.roles WHERE id = $2) AS role_name,
                         activity, view, modality, priority, scope`,
                    [org_id, role_id, activity, view, modality, scope, priority ?? null],
                );
                return reply.code(201).send(rows[0]);
            } catch (e: unknown) {
                if ((e as { code?: string }).code === '23505') return reply.code(409).send({ error: 'Rule already exists' });
                throw e;
            }
        });

        app.delete('/rules/:id', {
            schema: {
                tags: ['Management'],
                summary: 'Delete a role rule',
                description: "Removes a role-based permission rule. Requires `delete`/`rules` in the rule's org.",
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
            const { rows: [rule] } = await db.query<{ org_id: string }>(
                'SELECT org_id FROM morbac.rules WHERE id = $1', [id],
            );
            if (!rule) return reply.code(404).send({ error: 'Not found' });
            if (rule.org_id === SYSTEM_ORG_ID) return reply.code(403).send({ error: 'System entities are immutable' });
            if (!await hasPermission(db, req, reply, rule.org_id, 'delete', 'rules')) return reply;

            await db.query('DELETE FROM morbac.rules WHERE id = $1', [id]);
            return reply.code(204).send();
        });
    };
}
