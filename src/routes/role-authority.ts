import type { Pool } from 'pg';

/**
 * Whether the caller may hand out this role at all: assigning it is exercising
 * authority over the organization the role lives in, not over the user.
 */
export async function callerControlsRoleOrg(
    db: Pool, callerId: string, roleId: string, activity: string,
): Promise<boolean> {
    const { rows } = await db.query<{ ok: boolean }>(
        `SELECT EXISTS (
             SELECT 1 FROM morbac.roles r
             WHERE r.id = $2::UUID AND morbac.is_allowed($1::UUID, r.org_id, $3, 'user_roles')
         ) AS ok`,
        [callerId, roleId, activity],
    );
    return rows[0]?.ok ?? false;
}
