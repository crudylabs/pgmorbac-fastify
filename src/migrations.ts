import { readFileSync, readdirSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const sqlDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'sql');

export interface MorbacMigration {
    filename: string;
    sql: string;
}

// The morbac schema ships with this package as a PGXN-style extension script
// (sql/pgmorbac--<version>.sql) plus upgrade scripts (sql/upgrades/). For the
// crudy migration runner they are exposed as plain migrations: the base script
// keeps the historical filename 0001_morbac.sql so schema_migrations rows on
// existing databases stay valid, and upgrade scripts follow in version order
// as 0001_morbac--<old>--<new>.sql.
export function morbacMigrations(): MorbacMigration[] {
    const base = readdirSync(sqlDir)
        .filter(f => /^pgmorbac--\d+\.\d+\.\d+\.sql$/.test(f))
        .sort();
    if (base.length !== 1) {
        throw new Error(`[pgmorbac] Expected exactly one base script in ${sqlDir}, found ${base.length}`);
    }
    const migrations: MorbacMigration[] = [{
        filename: '0001_morbac.sql',
        sql: readFileSync(join(sqlDir, base[0]), 'utf8'),
    }];

    const upgradesDir = join(sqlDir, 'upgrades');
    if (existsSync(upgradesDir)) {
        for (const f of readdirSync(upgradesDir).filter(n => n.endsWith('.sql')).sort()) {
            migrations.push({
                filename: `0001_morbac${f.replace(/^pgmorbac/, '').replace(/\.sql$/, '')}.sql`,
                sql: readFileSync(join(upgradesDir, f), 'utf8'),
            });
        }
    }
    return migrations;
}
