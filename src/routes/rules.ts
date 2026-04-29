import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import { getUser, getOrgScope, orgScopeExpr, hasPermission, SYSTEM_ORG_ID } from '../permissions.js';
import { ruleResponse, crossOrgRuleResponse, userRuleResponse, notFound, forbidden, unauthorized, badRequest } from '../schemas.js';

export function createRuleRoutes(db: Pool) {
    return async function ruleRoutes(app: FastifyInstance) {
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

        app.get('/cross-org-rules', {
            schema: {
                tags: ['Management'],
                summary: 'List cross-org rules',
                description: "Rules that grant a role from a source org access to a target org's resources.",
                security: [{ oauth2: [] }],
                response: {
                    200: { type: 'array', items: crossOrgRuleResponse },
                    400: badRequest, 401: unauthorized, 403: forbidden,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const orgIds = getOrgScope(req, reply, false);
            if (orgIds === null) return reply;

            if (!await hasPermission(db, req, reply, orgIds[0] ?? null, 'read', 'cross_org_rules')) return reply;

            const { expr: srcExpr, params: srcParams } = orgScopeExpr(orgIds, 'cor.source_org_id');
            const { expr: tgtExpr, params: tgtParams } = orgScopeExpr(orgIds, 'cor.target_org_id', srcParams.length);
            const where = srcExpr && tgtExpr ? `WHERE (${srcExpr} OR ${tgtExpr})`
                        : srcExpr ? `WHERE ${srcExpr}`
                        : tgtExpr ? `WHERE ${tgtExpr}`
                        : '';

            const { rows } = await db.query(
                `SELECT cor.id,
                        cor.source_org_id, cor.role_id AS source_role_id, cor.target_org_id,
                        so.name  AS source_org_name,
                        sr.name  AS source_role_name,
                        "to".name AS target_org_name,
                        cor.activity, cor.view, cor.modality, cor.priority
                 FROM morbac.cross_org_rules cor
                 JOIN morbac.orgs  so  ON so.id  = cor.source_org_id
                 JOIN morbac.roles sr  ON sr.id  = cor.role_id
                 JOIN morbac.orgs  "to" ON "to".id = cor.target_org_id
                 ${where}
                 ORDER BY so.name, sr.name, "to".name, cor.activity, cor.view`,
                [...srcParams, ...tgtParams],
            );
            return rows;
        });

        app.post('/cross-org-rules', {
            schema: {
                tags: ['Management'],
                summary: 'Create a cross-org rule',
                description: 'Grants a role from source_org access to target_org resources. Requires `create`/`cross_org_rules` in the source org.',
                security: [{ oauth2: [] }],
                body: {
                    type: 'object',
                    required: ['source_org_id', 'source_role_id', 'target_org_id', 'activity', 'view', 'modality'],
                    properties: {
                        source_org_id:  { type: 'string', format: 'uuid' },
                        source_role_id: { type: 'string', format: 'uuid' },
                        target_org_id:  { type: 'string', format: 'uuid' },
                        activity:       { type: 'string' },
                        view:           { type: 'string' },
                        modality:       { type: 'string', enum: ['permission', 'prohibition'] },
                        priority:       { type: 'integer' },
                    },
                },
                response: {
                    201: crossOrgRuleResponse,
                    400: badRequest, 401: unauthorized, 403: forbidden,
                    409: { description: 'Rule already exists.' },
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const { source_org_id, source_role_id, target_org_id, activity, view, modality, priority } = req.body as {
                source_org_id: string; source_role_id: string; target_org_id: string;
                activity: string; view: string; modality: 'permission' | 'prohibition'; priority?: number;
            };

            if (source_org_id === SYSTEM_ORG_ID) return reply.code(403).send({ error: 'System entities are immutable' });
            if (!await hasPermission(db, req, reply, source_org_id, 'create', 'cross_org_rules')) return reply;

            try {
                const { rows } = await db.query(
                    `INSERT INTO morbac.cross_org_rules
                         (source_org_id, target_org_id, role_id, activity, view, context_id, modality, priority)
                     VALUES (
                         $1, $2, $3, $4, $5,
                         (SELECT id FROM morbac.contexts WHERE name = 'always'),
                         $6::morbac.modality, $7
                     )
                     RETURNING id,
                         $1::UUID AS source_org_id, $3::UUID AS source_role_id, $2::UUID AS target_org_id,
                         (SELECT name FROM morbac.orgs  WHERE id = $1) AS source_org_name,
                         (SELECT name FROM morbac.roles WHERE id = $3) AS source_role_name,
                         (SELECT name FROM morbac.orgs  WHERE id = $2) AS target_org_name,
                         activity, view, modality, priority`,
                    [source_org_id, target_org_id, source_role_id, activity, view, modality, priority ?? null],
                );
                return reply.code(201).send(rows[0]);
            } catch (e: unknown) {
                if ((e as { code?: string }).code === '23505') return reply.code(409).send({ error: 'Rule already exists' });
                throw e;
            }
        });

        app.delete('/cross-org-rules/:id', {
            schema: {
                tags: ['Management'],
                summary: 'Delete a cross-org rule',
                description: 'Removes a cross-org rule. Requires `delete`/`cross_org_rules` in the source org.',
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
            const { rows: [cor] } = await db.query<{ source_org_id: string }>(
                'SELECT source_org_id FROM morbac.cross_org_rules WHERE id = $1', [id],
            );
            if (!cor) return reply.code(404).send({ error: 'Not found' });
            if (cor.source_org_id === SYSTEM_ORG_ID) return reply.code(403).send({ error: 'System entities are immutable' });
            if (!await hasPermission(db, req, reply, cor.source_org_id, 'delete', 'cross_org_rules')) return reply;

            await db.query('DELETE FROM morbac.cross_org_rules WHERE id = $1', [id]);
            return reply.code(204).send();
        });

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
