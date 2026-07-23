# @crudy/pgmorbac

**Multi-OrBAC permission helpers for Fastify and PostgreSQL.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Node](https://img.shields.io/badge/Node-%3E%3D18-brightgreen.svg)](https://nodejs.org/)

This is the Node.js companion to the [`pgmorbac` PostgreSQL extension](https://git.villains.fr/crudy/pgmorbac). The extension implements the Multi-OrBAC access control model in the database (`morbac` schema); this package wires it into a Fastify backend: permission checks, a PostgREST data proxy, management routes, and the JSON schemas and domain types that go with them.

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
| `@crudy/pgmorbac` | Shared domain types (`DataPermission`, `Org`, `Role`, `Rule`, ...) |
| `@crudy/pgmorbac/permissions` | `hasPermission`, org-scope resolution, admin checks |
| `@crudy/pgmorbac/proxy` | PostgREST data proxy with per-route permissions |
| `@crudy/pgmorbac/plugin` | Fastify management routes (orgs, roles, rules, users, delegations) |
| `@crudy/pgmorbac/schemas` | JSON schema response fragments |
| `@crudy/pgmorbac/api` | Domain type definitions |

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

### Data proxy

Expose an `app`-schema table through the backend with an explicit permission. A path that is never registered does not exist (fail closed).

```ts
import { createProxyRegistry } from '@crudy/pgmorbac/proxy';

const proxy = createProxyRegistry(pool, process.env.POSTGREST_URL!);
proxy.proxyDataRoute(app, 'GET', '/data/documents', 'documents', { activity: 'read', view: 'documents' });
```

Pass `null` as the permission for any-authenticated-user access with no org check. Page size is capped at `MAX_PAGE_LIMIT` (1000); over-large `limit` values are rejected, never silently clamped.

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
- **Allowlisted queries.** Values are parameterized and columns allowlisted; user input is never interpolated.

## Related

- [pgmorbac](https://git.villains.fr/crudy/pgmorbac) — the PostgreSQL extension (MIT)
- [Documentation](https://pgmorbac.villains.fr) — model, architecture, integration guides

## License

Apache-2.0 (c) 2025-2026 Marc Villain. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
