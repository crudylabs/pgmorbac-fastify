# Changelog

All notable changes to this package will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-22

### Added
- Initial release of the Node.js companion to the `pgmorbac` PostgreSQL extension.
- `hasPermission` and org-scope helpers backed by `morbac.is_allowed`.
- PostgREST data proxy with per-route permissions and a hard page-size cap.
- Fastify management routes for orgs, roles, rules, users, global rules, activities, and delegations.
- JSON schema response fragments and shared domain types.

[0.1.0]: https://git.villains.fr/crudy/pgmorbac-node/releases/tag/v0.1.0
