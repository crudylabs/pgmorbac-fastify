import { extensionSql, upgradeScripts, version } from '@crudy/pgmorbac';

export interface MorbacMigration {
    filename: string;
    sql: string;
}

// The pgmorbac install and upgrade scripts (from @crudy/pgmorbac) as plain
// migrations for a migration runner. Without CREATE EXTENSION the morbac schema is
// created up front, and the installed version is recorded. The base keeps the
// historical filename 0001_morbac.sql so schema_migrations rows on existing
// databases stay valid; its bytes must not change for an unchanged extension
// version, or boot re-runs it. Upgrades follow as 0001_morbac--<old>--<new>.sql.
export function morbacMigrations(): MorbacMigration[] {
    const lines = extensionSql().split('\n');
    lines.splice(lines.indexOf('') + 1, 0, 'CREATE SCHEMA IF NOT EXISTS morbac;');
    const sql = lines.join('\n') + `
-- Record the installed schema version (readable via
-- morbac.get_config('schema_version'); upgrade scripts bump it).
INSERT INTO morbac.config (key, value, description)
VALUES ('schema_version', '${version}', 'Installed pgmorbac schema version')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = CURRENT_TIMESTAMP;
`;
    return [
        { filename: '0001_morbac.sql', sql },
        ...upgradeScripts().map(u => ({ filename: `0001_morbac--${u.from}--${u.to}.sql`, sql: u.sql })),
    ];
}
