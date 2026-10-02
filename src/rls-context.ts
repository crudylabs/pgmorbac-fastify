import type { Pool, PoolClient } from 'pg';
import { orgSelectionToSetting, type OrgSelection } from './permissions.js';

export interface MorbacContext {
    userId: string;
    /** Pin to a single organisation. Unattributed records are excluded by a
     *  pin; use `orgs` to select them. */
    orgId?: string | null;
    /** Which records to return: 'all' (every org, unattributed included), or a
     *  list of targets where an UNATTRIBUTED (null) entry selects records that
     *  have no org. Ignored when `orgId` is set. */
    orgs?: OrgSelection;
}

/**
 * Runs fn on a dedicated client inside a transaction with the morbac session
 * GUCs set, so morbac RLS policies see the acting user.
 *
 * Whether that is load bearing depends on which pool it is given. Under
 * app_runtime, the role without BYPASSRLS that the metrics read path uses, it
 * turns RLS into a second authorization gate behind hasPermission. Under
 * app_backend, which every other caller still uses, the role attribute exempts
 * it and the GUCs only feed the audit triggers.
 *
 * Routes not yet converted fail closed under app_runtime: with no GUC set,
 * morbac.current_user_id() is NULL and the policies return no rows.
 */
export async function withMorbacContext<T>(
    pool: Pool,
    ctx: MorbacContext,
    fn: (client: PoolClient) => Promise<T>,
): Promise<T> {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query(
            `SELECT set_config('morbac.user_id', $1, true),
                    set_config('morbac.org_id',  $2, true),
                    set_config('morbac.org_ids', $3, true)`,
            [
                ctx.userId,
                ctx.orgId ?? '',
                (ctx.orgs === undefined ? null : orgSelectionToSetting(ctx.orgs)) ?? '',
            ],
        );
        const result = await fn(client);
        await client.query('COMMIT');
        return result;
    } catch (err) {
        await client.query('ROLLBACK').catch(() => undefined);
        throw err;
    } finally {
        client.release();
    }
}
