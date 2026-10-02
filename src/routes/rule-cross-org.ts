import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import { getUser, getOrgScope, orgScopeExpr, hasPermission, isActivityViewBound, SYSTEM_ORG_ID } from '../permissions.js';
import { crossOrgRuleResponse, notFound, forbidden, unauthorized, badRequest } from '../schemas.js';

export function createCrossOrgRuleRoutes(db: Pool) {
    return async function crossOrgRuleRoutes(app: FastifyInstance) {
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

            if (!await isActivityViewBound(db, activity, view)) {
                return reply.code(400).send({ error: `Activity "${activity}" is not valid for view "${view}"` });
            }

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
                const code = (e as { code?: string }).code;
                if (code === '23505') return reply.code(409).send({ error: 'Rule already exists' });
                if (code === '23503') return reply.code(400).send({ error: 'Unknown activity or view' });
                if (code === 'P0001') return reply.code(400).send({ error: `Activity "${activity}" is not valid for view "${view}"` });
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
    };
}
