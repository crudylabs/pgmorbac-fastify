import type { Pool } from 'pg';

/**
 * Wraps a query selecting the visible orgs (id, name, parent_id, metadata) and
 * computes each org's path as the names from the nearest visible ancestor down
 * to it. Recursion is seeded from orgs whose parent is absent from the visible
 * set, so a path can never name an ancestor the caller cannot read. Rows come
 * back parent-first (ORDER BY path).
 */
export function withOrgPaths(visSql: string): string {
    return `WITH RECURSIVE vis AS (${visSql}),
    tree AS (
        SELECT v.id, v.name, v.parent_id, v.metadata, ARRAY[v.name]::text[] AS path
        FROM vis v
        WHERE v.parent_id IS NULL OR NOT EXISTS (SELECT 1 FROM vis p WHERE p.id = v.parent_id)
        UNION ALL
        SELECT v.id, v.name, v.parent_id, v.metadata, t.path || v.name
        FROM vis v JOIN tree t ON v.parent_id = t.id
    )
    SELECT id, name, parent_id, metadata, path FROM tree ORDER BY path`;
}

/**
 * Ancestor-path names, keyed by org id, for every org the user may read under
 * `view`. The truncation is the point: a caller who cannot read a parent sees
 * the path start at the topmost org they can read, never above it.
 */
export async function readableOrgPaths(db: Pool, userId: string, view: string): Promise<Map<string, string[]>> {
    const { rows } = await db.query<{ id: string; path: string[] }>(
        withOrgPaths(
            `SELECT id, name, parent_id, NULL::jsonb AS metadata
               FROM morbac.orgs WHERE morbac.is_allowed($1::UUID, id, 'read', $2)`),
        [userId, view]);
    return new Map(rows.map((r) => [r.id, r.path]));
}
