import type { FastifyInstance, FastifyReply } from 'fastify';
import type { Pool } from 'pg';
import { getUser, canActOnUser, checkApiKeyScope, getAccountType, viewForType } from '../permissions.js';
import { notFound, forbidden, unauthorized, badRequest } from '../schemas.js';

const MAX_ORG_FILTER = 100;

const orgFilterArray = {
    type: 'array',
    maxItems: MAX_ORG_FILTER,
    items: { type: 'string', format: 'uuid' },
} as const;

const orgFilterResponse = {
    type: 'object',
    properties: { org_filter: orgFilterArray },
} as const;

/** Subset of `ids` that `userId` is allowed to read as orgs. Used both to filter
 *  what a caller may see and to validate what a caller may write, so neither
 *  direction can be used to probe orgs outside the caller's reach. */
async function visibleOrgIds(db: Pool, userId: string, ids: string[]): Promise<string[]> {
    if (ids.length === 0) return [];
    const { rows } = await db.query<{ id: string }>(
        `SELECT o.id FROM morbac.orgs o
         WHERE o.id = ANY($2::UUID[]) AND morbac.is_allowed($1::UUID, o.id, 'read', 'orgs')`,
        [userId, ids],
    );
    return rows.map((r) => r.id);
}

async function storedOrgFilter(db: Pool, userId: string): Promise<string[]> {
    const { rows } = await db.query<{ org_filter: unknown }>(
        `SELECT ui_preferences->'orgFilter' AS org_filter FROM app.users WHERE id = $1`,
        [userId],
    );
    const value = rows[0]?.org_filter;
    if (!Array.isArray(value)) return [];
    return value.filter((id): id is string => typeof id === 'string');
}

/** The org filter is a display preference, never an authorization input: every
 *  route still authorizes the org ids it receives on the wire. */
export function createUserOrgFilterRoutes(db: Pool) {
    return async function userOrgFilterRoutes(app: FastifyInstance) {
        async function resolveView(id: string, reply: FastifyReply): Promise<string | null> {
            const type = await getAccountType(db, id);
            if (type === null || type === 'system') {
                await reply.code(404).send({ error: 'Not found' });
                return null;
            }
            return viewForType(type);
        }

        app.get('/users/:id/org-filter', {
            schema: {
                tags: ['Management'],
                summary: 'Read a user organization filter',
                description: 'Organization filter stored in the user preferences, restricted to the orgs the caller can read. Requires `read`/`users` (or `service_users`).',
                security: [{ oauth2: [] }],
                params: { type: 'object', properties: { id: { type: 'string', format: 'uuid' } } },
                response: { 200: orgFilterResponse, 401: unauthorized, 403: forbidden, 404: notFound },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });
            const { id } = req.params as { id: string };

            const view = await resolveView(id, reply);
            if (!view) return reply;
            if (!checkApiKeyScope(req, reply, 'read', view)) return reply;
            if (!await canActOnUser(db, user.id, id, 'read', view)) return reply.code(404).send({ error: 'Not found' });

            const stored = await storedOrgFilter(db, id);
            return { org_filter: await visibleOrgIds(db, user.id, stored) };
        });

        app.patch('/users/:id/org-filter', {
            schema: {
                tags: ['Management'],
                summary: 'Replace a user organization filter',
                description: 'Replaces the slice of the organization filter the caller can see. Ids outside the caller reach are preserved untouched. Requires `update`/`users` (or `service_users`).',
                security: [{ oauth2: [] }],
                params: { type: 'object', properties: { id: { type: 'string', format: 'uuid' } } },
                body: {
                    type: 'object',
                    required: ['org_filter'],
                    additionalProperties: false,
                    properties: { org_filter: orgFilterArray },
                },
                response: { 200: orgFilterResponse, 400: badRequest, 401: unauthorized, 403: forbidden, 404: notFound },
            },
        }, async (req, reply) => {
            const user = getUser(req);
            if (!user) return reply.code(401).send({ error: 'Authentication required' });
            const { id } = req.params as { id: string };

            const type = await getAccountType(db, id);
            if (type === null) return reply.code(404).send({ error: 'Not found' });
            if (type === 'system') return reply.code(403).send({ error: 'System entities are immutable' });
            const view = viewForType(type);

            if (!checkApiKeyScope(req, reply, 'update', view)) return reply;
            if (!await canActOnUser(db, user.id, id, 'update', view)) return reply.code(404).send({ error: 'Not found' });

            const submitted = [...new Set((req.body as { org_filter: string[] }).org_filter)];

            // Only the caller's own reach is validated. The target's is deliberately
            // not: the filter is intersected with what the target can see at render
            // time, so an id they cannot see shows nothing and grants nothing, and
            // forbidding it would forbid preserving the very ids below.
            const visibleToCaller = await visibleOrgIds(db, user.id, submitted);
            if (visibleToCaller.length !== submitted.length) {
                return reply.code(400).send({ error: 'Invalid organization' });
            }

            const stored = await storedOrgFilter(db, id);
            const callerVisibleStored = new Set(await visibleOrgIds(db, user.id, stored));
            const preserved = stored.filter((orgId) => !callerVisibleStored.has(orgId));
            const next = [...new Set([...submitted, ...preserved])];

            await db.query(
                `UPDATE app.users
                 SET ui_preferences = COALESCE(ui_preferences, '{}'::jsonb) || jsonb_build_object('orgFilter', $1::jsonb)
                 WHERE id = $2`,
                [JSON.stringify(next), id],
            );

            return { org_filter: submitted };
        });
    };
}
