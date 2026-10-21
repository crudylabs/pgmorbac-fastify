import type { Pool } from 'pg';
import { isAllowed } from '../permissions.js';

/**
 * Whether the caller may hand out this role at all: assigning it is exercising
 * authority over the organization the role lives in, not over the user.
 */
export async function callerControlsRoleOrg(
    db: Pool, callerId: string, roleId: string, activity: string,
): Promise<boolean> {
    const { rows } = await db.query<{ org_id: string | null }>('SELECT org_id FROM morbac.roles WHERE id = $1::UUID', [roleId]);
    return rows.length > 0 && isAllowed(db, callerId, rows[0].org_id, activity, 'user_roles');
}
