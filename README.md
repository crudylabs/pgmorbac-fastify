# @crudy/pgmorbac-fastify

**Multi-OrBAC permission helpers for Fastify and PostgreSQL.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node](https://img.shields.io/badge/Node-%3E%3D18-brightgreen.svg)](https://nodejs.org/)

This is the Node.js companion to the [`pgmorbac` PostgreSQL extension](https://github.com/crudylabs/pgmorbac). The extension implements the Multi-OrBAC access control model in the database (`morbac` schema); this package wires it into a Fastify backend: permission checks, RLS session context, management routes, a PostgREST data proxy, and the migration loader for the extension SQL from [`@crudy/pgmorbac`](https://www.npmjs.com/package/@crudy/pgmorbac).

> MIT, like the pgmorbac SQL extension it builds on. See [LICENSE](LICENSE).

## Install

```bash
npm install @crudy/pgmorbac-fastify
```

Peer dependencies (both optional, install the ones you use): `fastify >=5`, `pg >=8`.

## Exports

The package is split into focused entry points so you only pull in what you need.

| Import | Purpose |
|--------|---------|
| `@crudy/pgmorbac-fastify` | RLS session context and shared domain types |
| `@crudy/pgmorbac-fastify/permissions` | `hasPermission`, `isAllowed`, `permittedOrgs`, permission hooks, org-scope resolution, admin checks |
| `@crudy/pgmorbac-fastify/proxy` | PostgREST data proxy with per-route permissions |
| `@crudy/pgmorbac-fastify/plugin` | Fastify management routes (orgs, roles, rules, users, delegations) |
| `@crudy/pgmorbac-fastify/list-query` | PostgREST-style sort/filter/pagination parsing |
| `@crudy/pgmorbac-fastify/schemas` | JSON schema response fragments |
| `@crudy/pgmorbac-fastify/migrations` | Loads the bundled `morbac` extension SQL as migrations |
| `@crudy/pgmorbac-fastify/api` | Domain type definitions (`Org`, `Role`, `Rule`, ...) |

## Usage

### Permission checks

Every org-scoped route authorizes with `hasPermission`. Authentication is necessary but not sufficient; the check calls `morbac.is_allowed` and requires an `X-Org-Id` header.

```ts
import { hasPermission } from '@crudy/pgmorbac-fastify/permissions';

app.get('/documents', async (req, reply) => {
  const orgId = req.headers['x-org-id'] as string;
  if (!(await hasPermission(pool, req, reply, orgId, 'read', 'documents'))) return;
  // ... authorized: read and return rows
});
```

For a decision without a reply, use `isAllowed(pool, userId, orgId, activity, view)`; for several orgs at once, `permittedOrgs`. Never query `morbac.is_allowed` directly: it skips the hooks below.

### Permission hooks

An application adds its own rules to every decision with `addPermissionHook`. A `pre` hook runs before morbac is asked and a `post` hook receives morbac's answer. Either can only refuse: a decision is allowed when morbac allows it and every hook returns `true`. A hook that throws fails the decision with its error.

```ts
import { addPermissionHook } from '@crudy/pgmorbac-fastify/permissions';

// No action in an org whose subscription lapsed.
addPermissionHook('pre', async ({ orgId }) => orgId === null || await subscriptionActive(orgId));
```

The hooks run in `hasPermission`, `hasPermissionAny`, `canPerform`, `canActOnUser`, `canGrantRule`, `isAllowed`, `permittedOrgs` and the data proxy, which forwards only the `X-Org-Ids` the caller is allowed in. `hasAnyPermission` names no org and runs none. Row-level security evaluates morbac alone, so a rule that must also hide rows belongs in the database.

### RLS session context

Run queries under the acting user so `morbac` row-level security policies apply as a second gate behind `hasPermission`. Required for non-`BYPASSRLS` runtime roles.

```ts
import { withMorbacContext } from '@crudy/pgmorbac-fastify';

const rows = await withMorbacContext(pool, { userId, orgId }, async (client) => {
  const { rows } = await client.query('SELECT * FROM app.orgs');
  return rows;
});
```

### Data proxy

Expose an `app`-schema table through the backend with an explicit permission. A path that is never registered does not exist (fail closed).

```ts
import { createProxyRegistry } from '@crudy/pgmorbac-fastify/proxy';

const proxy = createProxyRegistry(pool, process.env.POSTGREST_URL!);
proxy.proxyDataRoute(app, 'GET', '/data/documents', 'documents', { activity: 'read', view: 'documents' });
```

Pass `null` as the permission for any-authenticated-user access with no org check. Page size is capped at `MAX_PAGE_LIMIT` (1000); over-large `limit` values are rejected, never silently clamped.

### Migrations

`morbacMigrations()` returns the extension SQL from `@crudy/pgmorbac` (install script plus upgrade scripts) ready for your migration runner. Feed it before your own DDL.

```ts
import { morbacMigrations } from '@crudy/pgmorbac-fastify/migrations';

for (const { filename, sql } of morbacMigrations()) {
  await runMigration(filename, sql);
}
```

The base script keeps the historical filename `0001_morbac.sql` so `schema_migrations` rows on existing databases stay valid; upgrade scripts follow in version order.

### Management routes

Register CRUD routes for orgs, roles, rules, users, global rules, activities, and delegations. Supply optional hooks for license-limit enforcement and event emission.

```ts
import { createMgmtRoutes } from '@crudy/pgmorbac-fastify/plugin';

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
- **Hooks only narrow.** An application rule added with `addPermissionHook` can refuse a decision morbac allowed, never allow one it refused.
- **Allowlisted queries.** `list-query` parameterizes values and allowlists sortable/filterable columns; user input is never interpolated.

## Related

- [pgmorbac](https://github.com/crudylabs/pgmorbac) — the PostgreSQL extension (MIT)
- [Documentation](https://pgmorbac.crudy.fr) — model, architecture, integration guides

## License

MIT (c) 2025-2026 Marc Villain. See [LICENSE](LICENSE).
