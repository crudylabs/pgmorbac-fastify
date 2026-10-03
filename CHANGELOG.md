# Changelog

All notable changes to this package will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-07-25

### Added
- First stable release of the Node.js companion to the `pgmorbac` PostgreSQL extension.
- `hasPermission` and org-scope helpers backed by `morbac.is_allowed`.
- `withMorbacContext` for running queries under the acting user so RLS applies.
- PostgREST data proxy with per-route permissions and a hard page-size cap.
- `morbacMigrations()` loader that ships the bundled extension SQL.
- Fastify management routes for orgs, roles, rules, users, global rules, activities, and delegations.
- PostgREST-style list-query parsing with allowlisted sort/filter columns.
- JSON schema response fragments and shared domain types.
- Unattributed org target: `UNATTRIBUTED`, `OrgTarget` and `OrgSelection` express
  a specific organisation, records with no org, or every org at once.
- `hasAnyPermission` wraps the `morbac.has_permission` capability probe for UI gating.
- `withMorbacContext` accepts an org selection, serialised to `morbac.org_ids`
  where a JSON null element names the unattributed bucket.

[1.0.0]: https://github.com/crudylabs/pgmorbac-fastify/releases/tag/v1.0.0
