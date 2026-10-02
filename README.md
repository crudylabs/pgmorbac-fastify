# @crudy/pgmorbac

**Multi-OrBAC permission helpers for Fastify and PostgreSQL.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Node](https://img.shields.io/badge/Node-%3E%3D18-brightgreen.svg)](https://nodejs.org/)

This is the Node.js companion to the [`pgmorbac` PostgreSQL extension](https://github.com/crudylabs/pgmorbac). The extension implements the Multi-OrBAC access control model in the database (`morbac` schema); this package wires it into a Fastify backend: permission checks, RLS session context, management routes, a PostgREST data proxy, and the migration loader that ships the extension SQL.

> The SQL extension is a separate project under the MIT license. This helper package is Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Install

```bash
npm install @crudy/pgmorbac
```

Peer dependencies (both optional, install the ones you use): `fastify >=5`, `pg >=8`.

## Exports

The package is split into focused entry points so you only pull in what you need.

| Import | Purpose |
|--------|---------|
| `@crudy/pgmorbac` | RLS session context and shared domain types |
| `@crudy/pgmorbac/permissions` | `hasPermission`, org-scope resolution, admin checks |
| `@crudy/pgmorbac/proxy` | PostgREST data proxy with per-route permissions |
| `@crudy/pgmorbac/plugin` | Fastify management routes (orgs, roles, rules, users, delegations) |
| `@crudy/pgmorbac/list-query` | PostgREST-style sort/filter/pagination parsing |
| `@crudy/pgmorbac/schemas` | JSON schema response fragments |
| `@crudy/pgmorbac/migrations` | Loads the bundled `morbac` extension SQL as migrations |
| `@crudy/pgmorbac/api` | Domain type definitions (`Org`, `Role`, `Rule`, ...) |

## Usage

### Permission checks

Every org-scoped route authorizes with `hasPermission`. Authentication is necessary but not sufficient; the check calls `morbac.is_allowed` and requires an `X-Org-Id` header.

```ts
import { hasPermission } from '@crudy/pgmorbac/permissions';

app.get('/documents', async (req, reply) => {
  const orgId = req.headers['x-org-id'] as string;
  if (!(await hasPermission(pool, req, reply, orgId, 'read', 'documents'))) return;
  // ... authorized: read and return rows
});
```

### RLS session context

Run queries under the acting user so `morbac` row-level security policies apply as a second gate behind `hasPermission`. Required for non-`BYPASSRLS` runtime roles.

```ts
import { withMorbacContext } from '@crudy/pgmorbac';

const rows = await withMorbacContext(pool, { userId, orgId }, async (client) => {
  const { rows } = await client.query('SELECT * FROM app.orgs');
  return rows;
});
```

### Data proxy

Expose an `app`-schema table through the backend with an explicit permission. A path that is never registered does not exist (fail closed).

```ts
import { createProxyRegistry } from '@crudy/pgmorbac/proxy';

const proxy = createProxyRegistry(pool, process.env.POSTGREST_URL!);
proxy.proxyDataRoute(app, 'GET', '/data/documents', 'documents', { activity: 'read', view: 'documents' });
```

Pass `null` as the permission for any-authenticated-user access with no org check. Page size is capped at `MAX_PAGE_LIMIT` (1000); over-large `limit` values are rejected, never silently clamped.

### Migrations

The extension SQL ships inside this package (`sql/pgmorbac--<version>.sql`, plus `sql/upgrades/`). Feed it to your migration runner before your own DDL.

```ts
import { morbacMigrations } from '@crudy/pgmorbac/migrations';

for (const { filename, sql } of morbacMigrations()) {
  await runMigration(filename, sql);
}
```

The base script keeps the historical filename `0001_morbac.sql` so `schema_migrations` rows on existing databases stay valid; upgrade scripts follow in version order.

### Management routes

Register CRUD routes for orgs, roles, rules, users, global rules, activities, and delegations. Supply optional hooks for license-limit enforcement and event emission.

```ts
import { createMgmtRoutes } from '@crudy/pgmorbac/plugin';

createMgmtRoutes({
  db: pool,
  checkLimit: async (reply, name, sql, params) => { /* enforce quotas */ return true; },
  emitOrgEvent: (event) => { /* audit / notify */ },
});
```

## Security model

- **Deny by default.** Unregistered routes do not exist; unauthorized reads return `404` over `403` to avoid enumeration.
- **Reads are checked too.** List and detail routes require the same permission checks as writes.
- **Two gates stacked.** `hasPermission` (application) plus `morbac` RLS (database) when running under a non-`BYPASSRLS` role.
- **Allowlisted queries.** `list-query` parameterizes values and allowlists sortable/filterable columns; user input is never interpolated.

## Related

- [pgmorbac](https://github.com/crudylabs/pgmorbac) — the PostgreSQL extension (MIT)
- [Documentation](https://pgmorbac.crudy.fr) — model, architecture, integration guides

## License

Apache-2.0 (c) 2025-2026 Marc Villain. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
