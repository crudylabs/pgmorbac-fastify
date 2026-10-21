import type { FastifyRequest, FastifyReply } from 'fastify';
import type { Pool } from 'pg';
import { runPostHooks, runPreHooks } from './permission-hooks.js';

export { addPermissionHook, type PermissionCheck, type PrePermissionHook, type PostPermissionHook } from './permission-hooks.js';

export const SYSTEM_ORG_ID = '00000000-0000-0000-0000-000000000000';

/** The no-org bucket. An object whose org is UNATTRIBUTED belongs to no
 *  organisation (typically awaiting attribution). Mirrors the SQL model where a
 *  NULL org means unattributed -- it never means "any org" or "all orgs". */
export const UNATTRIBUTED = null;

/** A single org target: an organisation id, or UNATTRIBUTED. */
export type OrgTarget = string | typeof UNATTRIBUTED;

/** Which records a listing should return. Either 'all' -- every organisation,
 *  unattributed included -- or an explicit list of targets, where an
 *  UNATTRIBUTED entry selects objects that have no org. */
export type OrgSelection = 'all' | OrgTarget[];

/** Serialises an OrgSelection for the morbac.org_ids session variable.
 *  'all' returns null: no restriction, which the extension reads as every
 *  authorized record including unattributed ones. */
export function orgSelectionToSetting(selection: OrgSelection): string | null {
    return selection === 'all' ? null : JSON.stringify(selection);
}

/** The X-Org-Ids token naming the no-org bucket on a data request. An org id is
 *  always a UUID, so the token cannot collide with one. The pre-request hook
 *  turns it into the JSON null element of morbac.org_ids. */
export const UNATTRIBUTED_ORG_TOKEN = 'unattributed';

/** Builds an X-Org-Ids value from org targets, naming the no-org bucket with
 *  UNATTRIBUTED_ORG_TOKEN. Data requests only: the management routes below are
 *  org-scoped listings and reject the token. */
export function orgTargetsToHeader(targets: OrgTarget[]): string {
    return targets.map((t) => t ?? UNATTRIBUTED_ORG_TOKEN).join(',');
}

export function getUser(req: FastifyRequest): { id: string } | null {
    return ((req as unknown) as Record<string, unknown>).user as { id: string } | null ?? null;
}

export function getOrgScope(req: FastifyRequest, reply: FastifyReply, required = true): string[] | null {
    const single = req.headers['x-org-id'];
    const singleVal = Array.isArray(single) ? single[0] : (single ?? null);
    if (singleVal) return [singleVal];

    const multi = req.headers['x-org-ids'];
    const multiVal = Array.isArray(multi) ? multi[0] : (multi ?? null);
    if (multiVal) {
        const ids = multiVal.split(',').map((s) => s.trim()).filter(Boolean);
        // These routes enumerate orgs via get_org_scope, which the no-org bucket
        // is not part of. Rejecting beats letting the token reach a UUID cast.
        if (ids.some((id) => id.toLowerCase() === UNATTRIBUTED_ORG_TOKEN)) {
            reply.code(400).send({ error: `${UNATTRIBUTED_ORG_TOKEN} is only valid on data requests, not management routes` });
            return null;
        }
        if (ids.length > 0) return ids;
    }

    if (required) {
        reply.code(400).send({ error: 'X-Org-Id header is required' });
        return null;
    }
    return [];
}

export function orgScopeExpr(orgIds: string[], column: string, paramOffset = 0): { expr: string; params: string[] } {
    if (orgIds.length === 0) return { expr: '', params: [] };
    const parts = orgIds.map((_, i) =>
        `SELECT org_id FROM morbac.get_org_scope($${paramOffset + i + 1}::UUID, 'subtree')`,
    );
    return { expr: `${column} IN (${parts.join(' UNION ')})`, params: orgIds };
}

export function viewForType(type: 'user' | 'service'): string {
    return type === 'service' ? 'service_users' : 'users';
}

export async function getAccountType(
    db: Pool,
    id: string,
): Promise<'user' | 'system' | 'service' | null> {
    const { rows } = await db.query<{ account_type: 'user' | 'system' | 'service' }>(
        'SELECT account_type FROM app.users WHERE id = $1',
        [id],
    );
    return rows[0]?.account_type ?? null;
}

export type ApiKeyScope = 'inherit' | Array<{ activity: string; view: string }>;

function scopeAllows(scope: ApiKeyScope | undefined, activity: string, target: string): boolean {
    if (!scope || scope === 'inherit') return true;
    return scope.some((p) => p.activity === activity && p.view === target);
}

/** True if the caller may exercise (activity, view) over the target user.
 *  Authorizes against the target's ACTUAL membership orgs (or a global rule),
 *  never a caller-supplied header. A target with no membership can only be
 *  managed by a global admin. Prevents cross-org account takeover. */
/** Enforces an API key's permission_scope for management routes that no longer
 *  route through hasPermission (they authorize against target ownership instead).
 *  Sends 403 and returns false when the key's scope excludes (activity, view). */
export function checkApiKeyScope(
    req: FastifyRequest,
    reply: FastifyReply,
    activity: string,
    view: string,
): boolean {
    const apiKeyScope = ((req as unknown) as Record<string, unknown>).apiKeyScope as ApiKeyScope | undefined;
    if (!scopeAllows(apiKeyScope, activity, view)) {
        reply.code(403).send({ error: 'Insufficient permissions' });
        return false;
    }
    return true;
}

export async function canActOnUser(
    db: Pool,
    callerId: string,
    targetUserId: string,
    activity: string,
    view: string,
): Promise<boolean> {
    if (await isAllowed(db, callerId, null, activity, view)) return true;
    const { rows } = await db.query<{ org_id: string }>(
        'SELECT DISTINCT org_id FROM morbac.user_roles WHERE user_id = $1::UUID',
        [targetUserId],
    );
    return (await permittedOrgs(db, callerId, rows.map((r) => r.org_id), activity, view)).length > 0;
}

/** True if the caller may reach org (activity, view) at every org that a rule
 *  with (ruleOrgId, scope) would cover. Enforces that a rule can never grant a
 *  permission the caller does not already hold on the affected orgs, killing
 *  scope-based vertical privilege escalation.
 *
 *  The 'unattributed' and 'all' scopes reach objects with no org, which
 *  get_org_scope does not enumerate (unattributed is not an organisation).
 *  Those scopes additionally require the caller to hold the permission on
 *  unattributed objects, otherwise 'unattributed' would pass vacuously. */
export async function canGrantRule(
    db: Pool,
    callerId: string,
    ruleOrgId: string,
    scope: string,
    activity: string,
    view: string,
): Promise<boolean> {
    const { rows } = await db.query<{ org_id: string }>(
        'SELECT org_id FROM morbac.get_org_scope($1::UUID, $2) AS s(org_id)',
        [ruleOrgId, scope],
    );
    const covered = rows.map((r) => r.org_id);
    if ((await permittedOrgs(db, callerId, covered, activity, view)).length !== covered.length) return false;
    if (scope !== 'unattributed' && scope !== 'all') return true;
    return isAllowed(db, callerId, null, activity, view);
}

/** True iff (activity, view) has an explicit row in morbac.activity_view_bindings.
 *  The DB trigger only restricts an activity once it has at least one binding
 *  (empty = unconstrained); this closes that gap at the application layer so an
 *  activity/view pair with no binding is rejected rather than silently allowed. */
export async function isActivityViewBound(db: Pool, activity: string, view: string): Promise<boolean> {
    const { rows } = await db.query<{ ok: boolean }>(
        `SELECT EXISTS(SELECT 1 FROM morbac.activity_view_bindings WHERE activity = $1 AND view = $2) AS ok`,
        [activity, view],
    );
    return rows[0]?.ok ?? false;
}

/** True iff the caller holds the global wildcard rule (activity IS NULL, view IS NULL).
 *  Used by framework-level surfaces (audit, monitoring) that are not org-scoped. */
export async function isGlobalAdmin(db: Pool, userId: string): Promise<boolean> {
    const { rows } = await db.query<{ is_admin: boolean }>(
        `SELECT EXISTS(
             SELECT 1 FROM morbac.global_rules
             WHERE user_id = $1::UUID AND activity IS NULL AND view IS NULL AND modality = 'permission'
         ) AS is_admin`,
        [userId],
    );
    return rows[0]?.is_admin === true;
}

/** Sends 401/403 and returns false unless the caller is authenticated and holds
 *  the global wildcard rule. Use for routes with no org concept (e.g. monitoring). */
export async function requireGlobalAdmin(db: Pool, req: FastifyRequest, reply: FastifyReply): Promise<boolean> {
    const user = getUser(req);
    if (!user) {
        reply.code(401).send({ error: 'Authentication required' });
        return false;
    }
    if (!(await isGlobalAdmin(db, user.id))) {
        reply.code(403).send({ error: 'Insufficient permissions' });
        return false;
    }
    return true;
}

/** True if the user may perform (activity, view) in ANY context: any org they
 *  belong to, unattributed objects, or via a global rule. For deciding whether
 *  to expose a feature at all -- never a substitute for the per-object check.
 *  Names no org, so permission hooks do not run. */
export async function hasAnyPermission(
    db: Pool,
    userId: string,
    activity: string,
    view: string,
): Promise<boolean> {
    const { rows } = await db.query<{ allowed: boolean }>(
        'SELECT morbac.has_permission($1::UUID, $2, $3) AS allowed',
        [userId, activity, view],
    );
    return rows[0]?.allowed === true;
}

/**
 * The same decision `hasPermission` makes, without touching the reply.
 *
 * For callers that must ask about many permissions and decide what to do with
 * the answers: a report fan-out drops the metrics the runner cannot read
 * rather than failing, so it needs the boolean, not a 403 on the wire. Honours
 * an API key's scope exactly as `hasPermission` does, so a restricted key never
 * reads more through this door than through that one.
 */
export async function canPerform(
    db: Pool,
    req: FastifyRequest,
    orgId: string | null,
    activity: string,
    target: string,
): Promise<boolean> {
    const user = getUser(req);
    if (!user) return false;
    const apiKeyScope = ((req as unknown) as Record<string, unknown>).apiKeyScope as ApiKeyScope | undefined;
    if (!scopeAllows(apiKeyScope, activity, target)) return false;
    return isAllowed(db, user.id, orgId, activity, target, req);
}

/** Reads an API key's scope off a request, for callers that must reason about it. */
export function apiKeyScopeOf(req: FastifyRequest): ApiKeyScope | undefined {
    return ((req as unknown) as Record<string, unknown>).apiKeyScope as ApiKeyScope | undefined;
}

/** Authorization for a single object. Pass the object's org, or UNATTRIBUTED
 *  when the object has no org. */
export async function hasPermission(
    db: Pool,
    req: FastifyRequest,
    reply: FastifyReply,
    orgId: string | null,
    activity: string,
    target: string,
): Promise<boolean> {
    const user = getUser(req);
    if (!user) {
        reply.code(401).send({ error: 'Authentication required' });
        return false;
    }
    const apiKeyScope = ((req as unknown) as Record<string, unknown>).apiKeyScope as ApiKeyScope | undefined;
    if (!scopeAllows(apiKeyScope, activity, target)) {
        reply.code(403).send({ error: 'Insufficient permissions' });
        return false;
    }
    if (!await isAllowed(db, user.id, orgId, activity, target, req)) {
        reply.code(403).send({ error: 'Insufficient permissions' });
        return false;
    }
    return true;
}

/**
 * A coarse gate for a multi-org list read (e.g. the "all organizations" filter):
 * the caller may proceed if allowed in at least one of the requested orgs. RLS
 * still filters each row by its own org, so a row the caller cannot see in one
 * of the listed orgs is dropped regardless.
 */
export async function hasPermissionAny(
    db: Pool,
    req: FastifyRequest,
    reply: FastifyReply,
    orgIds: string[],
    activity: string,
    target: string,
): Promise<boolean> {
    const user = getUser(req);
    if (!user) {
        reply.code(401).send({ error: 'Authentication required' });
        return false;
    }
    const apiKeyScope = ((req as unknown) as Record<string, unknown>).apiKeyScope as ApiKeyScope | undefined;
    if (!scopeAllows(apiKeyScope, activity, target)) {
        reply.code(403).send({ error: 'Insufficient permissions' });
        return false;
    }
    const real = orgIds.filter((v) => v && v.toLowerCase() !== UNATTRIBUTED_ORG_TOKEN);
    if ((await permittedOrgs(db, user.id, real, activity, target, req)).length === 0) {
        reply.code(403).send({ error: 'Insufficient permissions' });
        return false;
    }
    return true;
}

/**
 * The one permission decision every helper makes: morbac's answer, narrowed by
 * the application's permission hooks (`addPermissionHook`). Use it instead of
 * querying `morbac.is_allowed` directly, which would skip those hooks.
 */
export async function isAllowed(
    db: Pool,
    userId: string,
    orgId: string | null,
    activity: string,
    view: string,
    req?: FastifyRequest,
): Promise<boolean> {
    const check = { userId, orgId, activity, view, req };
    if (!await runPreHooks(check, db)) return false;
    const { rows } = await db.query<{ allowed: boolean }>(
        'SELECT morbac.is_allowed($1::UUID, $2::UUID, $3, $4) AS allowed',
        [userId, orgId, activity, view],
    );
    return runPostHooks(check, rows[0]?.allowed === true, db);
}

/** The orgs among `orgIds` where `isAllowed` would answer yes, in their given order, asked of morbac in one query. */
export async function permittedOrgs(
    db: Pool,
    userId: string,
    orgIds: string[],
    activity: string,
    view: string,
    req?: FastifyRequest,
): Promise<string[]> {
    const candidates: string[] = [];
    for (const orgId of new Set(orgIds)) {
        if (await runPreHooks({ userId, orgId, activity, view, req }, db)) candidates.push(orgId);
    }
    if (candidates.length === 0) return [];
    const { rows } = await db.query<{ o: string }>(
        'SELECT o FROM unnest($2::UUID[]) o WHERE morbac.is_allowed($1::UUID, o, $3, $4)',
        [userId, candidates, activity, view],
    );
    const allowed = new Set(rows.map((r) => r.o.toLowerCase()));
    const out: string[] = [];
    for (const orgId of candidates) {
        if (await runPostHooks({ userId, orgId, activity, view, req }, allowed.has(orgId.toLowerCase()), db)) out.push(orgId);
    }
    return out;
}
