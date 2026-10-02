import type { Pool, PoolClient } from 'pg';
import type { FastifyReply } from 'fastify';
import { canGrantRule, isActivityViewBound } from '../permissions.js';

export interface ProfileRule {
    activity: string;
    view: string;
    modality: 'permission' | 'prohibition';
    scope: string;
}

export async function loadProfile(
    db: Pool, moduleId: string, key: string,
): Promise<{ rules: ProfileRule[]; content_hash: string } | null> {
    const { rows: [row] } = await db.query<{ rules: ProfileRule[]; content_hash: string }>(
        'SELECT rules, content_hash FROM app.permission_profiles WHERE module_id = $1 AND key = $2',
        [moduleId, key],
    );
    return row ?? null;
}

/** Anti-escalation gate for the caller-driven apply: every rule must be a valid
 *  binding, and the caller must already hold every permission it would grant.
 *  Sends the reply and returns false on the first failure. */
export async function validateGrantable(
    db: Pool, reply: FastifyReply, userId: string, orgId: string, rules: ProfileRule[],
): Promise<boolean> {
    for (const r of rules) {
        if (!await isActivityViewBound(db, r.activity, r.view)) {
            reply.code(400).send({ error: `Activity "${r.activity}" is not valid for view "${r.view}"` });
            return false;
        }
        if (r.modality === 'permission'
            && !await canGrantRule(db, userId, orgId, r.scope, r.activity, r.view)) {
            reply.code(403).send({ error: 'Cannot grant a permission you do not hold on the target orgs' });
            return false;
        }
    }
    return true;
}

/** Insert/adopt every profile rule (tagged) and revoke this profile's tagged rules
 *  no longer in the set. Manual (untagged) rules are never touched. Returns whether
 *  any touched rule was non-self, so the caller can flush the morbac cache. */
export async function applyProfileRules(
    client: PoolClient, orgId: string, roleId: string, moduleId: string, key: string, rules: ProfileRule[],
): Promise<boolean> {
    const tag = JSON.stringify({ profile: { module_id: moduleId, key } });
    let touchedNonSelf = false;
    for (const r of rules) {
        await client.query(
            `INSERT INTO morbac.rules
                 (org_id, role_id, activity, view, context_id, modality, scope, is_active, metadata)
             VALUES ($1, $2, $3, $4,
                 (SELECT id FROM morbac.contexts WHERE name = 'always'),
                 $5::morbac.modality, $6, TRUE, $7::jsonb)
             ON CONFLICT (org_id, role_id, activity, view, context_id, modality, scope)
             DO UPDATE SET metadata = EXCLUDED.metadata, is_active = TRUE`,
            [orgId, roleId, r.activity, r.view, r.modality, r.scope, tag],
        );
        if (r.scope !== 'self') touchedNonSelf = true;
    }
    const keep = rules.map(r => `${r.activity}|${r.view}|${r.modality}|${r.scope}`);
    const { rows: removed } = await client.query<{ scope: string }>(
        `DELETE FROM morbac.rules
         WHERE role_id = $1
           AND metadata->'profile'->>'module_id' = $2
           AND metadata->'profile'->>'key' = $3
           AND (activity || '|' || view || '|' || modality::text || '|' || scope) <> ALL($4::text[])
         RETURNING scope`,
        [roleId, moduleId, key, keep],
    );
    if (removed.some(row => row.scope !== 'self')) touchedNonSelf = true;
    return touchedNonSelf;
}
