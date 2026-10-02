import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import { getUser, getOrgScope, orgScopeExpr, hasPermission, canActOnUser, SYSTEM_ORG_ID } from '../permissions.js';
import { delegationResponse, notFound, forbidden, unauthorized, badRequest } from '../schemas.js';

const SELECT_COLUMNS = `
    d.id, d.delegator_id, d.delegatee_id, d.role_id, d.org_id,
    dor.name  AS delegator_name, dor.email AS delegator_email,
    dee.name  AS delegatee_name, dee.email AS delegatee_email,
    ro.name   AS role_name, o.name AS org_name,
    d.valid_from, d.valid_until, d.revoked, d.created_at`;

export function createDelegationRoutes(db: Pool) {
    return async function delegationRoutes(app: FastifyInstance) {
        app.get('/delegations', {
            schema: {
                tags: ['Management'],
                summary: 'List role delegations',
                description: 'Time-bounded role delegations within the scoped org subtree. A delegatee gains the delegated role only while the delegator still holds it, within the validity window, and until revoked.',
                security: [{ oauth2: [] }],
                response: {
                    200: { type: 'array', items: delegationResponse },
                    400: badRequest, 401: unauthorized, 403: forbidden,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const orgIds = getOrgScope(req, reply, false);
            if (orgIds === null) return reply;

            if (!await hasPermission(db, req, reply, orgIds[0] ?? null, 'read', 'delegations')) return reply;

            const { expr, params } = orgScopeExpr(orgIds, 'd.org_id');
            const { rows } = await db.query(
                `SELECT ${SELECT_COLUMNS}
                 FROM morbac.delegations d
                 JOIN morbac.orgs  o  ON o.id  = d.org_id
                 JOIN morbac.roles ro ON ro.id = d.role_id
                 LEFT JOIN app.users dor ON dor.id = d.delegator_id
                 LEFT JOIN app.users dee ON dee.id = d.delegatee_id
                 ${expr ? `WHERE ${expr}` : ''}
                 ORDER BY d.created_at DESC`,
                params,
            );
            return rows;
        });

        app.post('/delegations', {
            schema: {
                tags: ['Management'],
                summary: 'Create a role delegation',
                description: 'Delegates a role the delegator holds to another user, time-bounded. Requires `create`/`delegations` in the org. The delegator must currently hold the role in that org.',
                security: [{ oauth2: [] }],
                body: {
                    type: 'object',
                    required: ['delegator_id', 'delegatee_id', 'role_id', 'org_id', 'valid_until'],
                    properties: {
                        delegator_id: { type: 'string', format: 'uuid' },
                        delegatee_id: { type: 'string', format: 'uuid' },
                        role_id:      { type: 'string', format: 'uuid' },
                        org_id:       { type: 'string', format: 'uuid' },
                        valid_from:   { type: 'string', format: 'date-time' },
                        valid_until:  { type: 'string', format: 'date-time' },
                    },
                },
                response: {
                    201: delegationResponse,
                    400: badRequest, 401: unauthorized, 403: forbidden, 404: notFound,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const { delegator_id, delegatee_id, role_id, org_id, valid_from, valid_until } = req.body as {
                delegator_id: string; delegatee_id: string; role_id: string;
                org_id: string; valid_from?: string; valid_until: string;
            };

            if (org_id === SYSTEM_ORG_ID) return reply.code(403).send({ error: 'System entities are immutable' });
            if (delegator_id === delegatee_id) return reply.code(400).send({ error: 'delegator_and_delegatee_must_differ' });

            if (!await hasPermission(db, req, reply, org_id, 'create', 'delegations')) return reply;

            // The caller must be the delegator, or hold authority over them. Otherwise
            // any create/delegations holder could self-grant a powerful role held by
            // another principal by naming them as delegator.
            if (delegator_id !== user.id
                && !await canActOnUser(db, user.id, delegator_id, 'create', 'user_roles')) {
                return reply.code(403).send({ error: 'Cannot delegate on behalf of this user' });
            }

            const from = valid_from ? new Date(valid_from) : new Date();
            const until = new Date(valid_until);
            if (Number.isNaN(until.getTime()) || until <= from) {
                return reply.code(400).send({ error: 'invalid_validity_window' });
            }

            const { rows: [delegatee] } = await db.query<{ ok: number }>(
                'SELECT 1 AS ok FROM app.users WHERE id = $1', [delegatee_id],
            );
            if (!delegatee) return reply.code(400).send({ error: 'invalid_delegatee' });

            const { rows: [held] } = await db.query<{ ok: number }>(
                'SELECT 1 AS ok FROM morbac.user_roles WHERE user_id = $1 AND role_id = $2 AND org_id = $3',
                [delegator_id, role_id, org_id],
            );
            if (!held) return reply.code(400).send({ error: 'delegator_lacks_role' });

            try {
                const { rows } = await db.query(
                    `INSERT INTO morbac.delegations (delegator_id, delegatee_id, role_id, org_id, valid_from, valid_until)
                     VALUES ($1, $2, $3, $4, $5, $6)
                     RETURNING id, delegator_id, delegatee_id, role_id, org_id, valid_from, valid_until, revoked, created_at,
                         (SELECT name  FROM app.users   WHERE id = delegator_id) AS delegator_name,
                         (SELECT email FROM app.users   WHERE id = delegator_id) AS delegator_email,
                         (SELECT name  FROM app.users   WHERE id = delegatee_id) AS delegatee_name,
                         (SELECT email FROM app.users   WHERE id = delegatee_id) AS delegatee_email,
                         (SELECT name  FROM morbac.roles WHERE id = role_id)     AS role_name,
                         (SELECT name  FROM morbac.orgs  WHERE id = org_id)      AS org_name`,
                    [delegator_id, delegatee_id, role_id, org_id, from.toISOString(), until.toISOString()],
                );
                return reply.code(201).send(rows[0]);
            } catch (e: unknown) {
                const code = (e as { code?: string }).code;
                if (code === '23514') return reply.code(400).send({ error: 'invalid_validity_window' });
                if (code === '23503') return reply.code(400).send({ error: 'invalid_role_or_org' });
                throw e;
            }
        });

        app.delete('/delegations/:id', {
            schema: {
                tags: ['Management'],
                summary: 'Revoke a role delegation',
                description: 'Revokes a delegation (sets revoked = true), immediately removing the delegated role. The delegator may revoke their own delegation; otherwise `delete`/`delegations` is required in the org.',
                security: [{ oauth2: [] }],
                params: { type: 'object', properties: { id: { type: 'string', format: 'uuid' } } },
                response: {
                    204: { type: 'null', description: 'Delegation revoked.' },
                    400: badRequest, 401: unauthorized, 403: forbidden, 404: notFound,
                },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });

            const { id } = req.params as { id: string };
            const { rows: [del] } = await db.query<{ org_id: string; delegator_id: string }>(
                'SELECT org_id, delegator_id FROM morbac.delegations WHERE id = $1', [id],
            );
            if (!del) return reply.code(404).send({ error: 'Not found' });

            if (del.delegator_id !== user.id) {
                if (!await hasPermission(db, req, reply, del.org_id, 'delete', 'delegations')) return reply;
            }

            await db.query('UPDATE morbac.delegations SET revoked = TRUE WHERE id = $1', [id]);
            return reply.code(204).send();
        });
    };
}
