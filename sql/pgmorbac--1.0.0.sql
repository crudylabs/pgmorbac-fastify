-- pgmorbac: Multi-OrBAC for PostgreSQL
-- Organization-Based Access Control with multi-organization support,
-- role/activity/view hierarchies, deontic modalities, and temporal constraints.
-- Based on the CNRS Multi-OrBAC research model.

CREATE SCHEMA IF NOT EXISTS morbac;

CREATE TYPE morbac.modality AS ENUM (
    'permission',
    'prohibition',
    'obligation',
    'recommendation'
);

COMMENT ON TYPE morbac.modality IS 'Deontic modalities: permission, prohibition, obligation, recommendation';

CREATE TABLE morbac.config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE morbac.config IS 'Extension configuration - edit values to customize behavior';

INSERT INTO morbac.config (key, value, description) VALUES
    ('cache_ttl_seconds',       '300',             'Authorization cache time-to-live in seconds (default: 5 minutes)'),
    ('hierarchy_max_depth',     '10',              'Maximum depth for hierarchy traversal to prevent infinite loops'),
    ('enable_audit_by_default', 'false',           'Whether to enable audit logging by default on installation'),
    -- System view names used in RLS policies on morbac tables.
    -- Override with morbac.set_config() to use your own naming conventions.
    -- The configured name must exist in morbac.views and your rules must reference it.
    ('system_view.orgs',            'orgs',            'View name for morbac.orgs table access control'),
    ('system_view.roles',           'roles',           'View name for morbac.roles table access control'),
    ('system_view.rules',           'rules',           'View name for morbac.rules table access control'),
    ('system_view.user_roles',      'user_roles',      'View name for morbac.user_roles table access control'),
    ('system_view.contexts',        'contexts',        'View name for morbac.contexts table access control'),
    ('system_view.activities',      'activities',      'View name for morbac.activities table access control'),
    ('system_view.views',           'views',           'View name for morbac.views table access control'),
    ('system_view.delegations',     'delegations',     'View name for morbac.delegations table access control'),
    ('system_view.cross_org_rules', 'cross_org_rules', 'View name for morbac.cross_org_rules table access control'),
    ('system_view.user_rules',      'user_rules',      'View name for morbac.user_rules table access control'),
    ('system_view.global_rules',       'global_rules',       'View name for morbac.global_rules table access control'),
    ('system_view.system_principals',  'system_principals',  'View name for morbac.system_principals table access control');

CREATE OR REPLACE FUNCTION morbac.get_config(p_key TEXT)
RETURNS TEXT
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
DECLARE
    v_value TEXT;
BEGIN
    SELECT value INTO v_value FROM morbac.config WHERE key = p_key;
    RETURN v_value;
EXCEPTION
    WHEN OTHERS THEN
        RETURN NULL;
END;
$$;

COMMENT ON FUNCTION morbac.get_config(TEXT) IS
'Get configuration value by key';

CREATE OR REPLACE FUNCTION morbac.set_config(p_key TEXT, p_value TEXT)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE morbac.config
    SET value = p_value, updated_at = CURRENT_TIMESTAMP
    WHERE key = p_key;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Configuration key % does not exist', p_key;
    END IF;
END;
$$;

COMMENT ON FUNCTION morbac.set_config(TEXT, TEXT) IS
'Set configuration value by key';

CREATE TABLE morbac.orgs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    parent_id UUID REFERENCES morbac.orgs(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_orgs_name ON morbac.orgs(name);
CREATE INDEX idx_orgs_parent ON morbac.orgs(parent_id);

COMMENT ON TABLE morbac.orgs IS 'Organizations - first-class entities in Multi-OrBAC with hierarchy support';

-- Activities are global abstract actions (not org-scoped)

CREATE TABLE morbac.activities (
    name TEXT PRIMARY KEY,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE morbac.activities IS 'Activities - abstract actions in OrBAC model (global)';

-- Senior activities imply junior activities (e.g., write implies read)
CREATE TABLE morbac.activity_hierarchy (
    senior_activity TEXT NOT NULL REFERENCES morbac.activities(name) ON DELETE CASCADE,
    junior_activity TEXT NOT NULL REFERENCES morbac.activities(name) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (senior_activity, junior_activity),
    CHECK (senior_activity != junior_activity)
);

CREATE INDEX idx_activity_hierarchy_senior ON morbac.activity_hierarchy(senior_activity);
CREATE INDEX idx_activity_hierarchy_junior ON morbac.activity_hierarchy(junior_activity);

COMMENT ON TABLE morbac.activity_hierarchy IS 'Activity hierarchy - senior activities imply junior activities';
COMMENT ON COLUMN morbac.activity_hierarchy.senior_activity IS 'Senior activity (implies junior)';
COMMENT ON COLUMN morbac.activity_hierarchy.junior_activity IS 'Junior activity (implied by senior)';

INSERT INTO morbac.activities (name, description) VALUES
    ('create', 'Create new entities'),
    ('read',   'Read or list entities'),
    ('update', 'Modify existing entities'),
    ('delete', 'Remove entities')
ON CONFLICT (name) DO NOTHING;

-- Views are global abstract object categories (not org-scoped)

CREATE TABLE morbac.views (
    name TEXT PRIMARY KEY,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE morbac.views IS 'Views - abstract object categories in OrBAC model (global)';

-- Senior views inherit from junior views (e.g., confidential_documents is a documents)
CREATE TABLE morbac.view_hierarchy (
    senior_view TEXT NOT NULL REFERENCES morbac.views(name) ON DELETE CASCADE,
    junior_view TEXT NOT NULL REFERENCES morbac.views(name) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (senior_view, junior_view),
    CHECK (senior_view != junior_view)
);

CREATE INDEX idx_view_hierarchy_senior ON morbac.view_hierarchy(senior_view);
CREATE INDEX idx_view_hierarchy_junior ON morbac.view_hierarchy(junior_view);

COMMENT ON TABLE morbac.view_hierarchy IS 'View hierarchy - senior views inherit from junior views';
COMMENT ON COLUMN morbac.view_hierarchy.senior_view IS 'Senior view (more specific)';
COMMENT ON COLUMN morbac.view_hierarchy.junior_view IS 'Junior view (more general)';

-- Default system view names - match system_view.* config keys.
-- Override config values to rename; the new name must be seeded here too.
INSERT INTO morbac.views (name, description) VALUES
    ('orgs',              'Organizations table'),
    ('roles',             'Roles table'),
    ('rules',             'Authorization rules table'),
    ('user_roles',        'User-role assignments table'),
    ('user_rules',        'User-level authorization rules table'),
    ('global_rules',      'System-wide authorization rules table'),
    ('system_principals', 'System principals table'),
    ('delegations',       'Role delegations table'),
    ('cross_org_rules',   'Cross-organization rules table')
ON CONFLICT (name) DO NOTHING;

-- Roles are scoped to organizations and abstract sets of subjects

CREATE TABLE morbac.roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES morbac.orgs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, name)
);

CREATE INDEX idx_roles_org_id ON morbac.roles(org_id);
CREATE INDEX idx_roles_org_name ON morbac.roles(org_id, name);

COMMENT ON TABLE morbac.roles IS 'Roles scoped to organizations - abstract sets of subjects';

-- Senior roles inherit permissions from junior roles

CREATE TABLE morbac.role_hierarchy (
    senior_role_id UUID NOT NULL REFERENCES morbac.roles(id) ON DELETE CASCADE,
    junior_role_id UUID NOT NULL REFERENCES morbac.roles(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (senior_role_id, junior_role_id),
    CHECK (senior_role_id != junior_role_id)
);

CREATE INDEX idx_role_hierarchy_senior ON morbac.role_hierarchy(senior_role_id);
CREATE INDEX idx_role_hierarchy_junior ON morbac.role_hierarchy(junior_role_id);

COMMENT ON TABLE morbac.role_hierarchy IS 'Role hierarchy - senior roles inherit from junior roles';
COMMENT ON COLUMN morbac.role_hierarchy.senior_role_id IS 'Senior role (inherits permissions)';
COMMENT ON COLUMN morbac.role_hierarchy.junior_role_id IS 'Junior role (provides permissions)';

-- Maps users to roles within organizations; user_id is external (e.g., from auth system)

CREATE TABLE morbac.user_roles (
    user_id UUID NOT NULL,
    role_id UUID NOT NULL REFERENCES morbac.roles(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES morbac.orgs(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id, org_id)
);

CREATE INDEX idx_user_roles_user_org ON morbac.user_roles(user_id, org_id);
CREATE INDEX idx_user_roles_role ON morbac.user_roles(role_id);
CREATE INDEX idx_user_roles_fast ON morbac.user_roles(user_id, org_id) INCLUDE (role_id);

COMMENT ON TABLE morbac.user_roles IS 'Maps users to roles within organizations';
COMMENT ON COLUMN morbac.user_roles.user_id IS 'External user identifier';

-- Temporary delegation of a role from one user to another, time-bounded

CREATE TABLE morbac.delegations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    delegator_id UUID NOT NULL,
    delegatee_id UUID NOT NULL,
    role_id UUID NOT NULL REFERENCES morbac.roles(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES morbac.orgs(id) ON DELETE CASCADE,
    valid_from TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_until TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (delegator_id != delegatee_id),
    CHECK (valid_until > valid_from)
);

CREATE INDEX idx_delegations_delegatee ON morbac.delegations(delegatee_id, org_id);
CREATE INDEX idx_delegations_validity ON morbac.delegations(valid_from, valid_until) WHERE NOT revoked;

COMMENT ON TABLE morbac.delegations IS 'Temporary delegation of roles from one user to another';
COMMENT ON COLUMN morbac.delegations.valid_from IS 'Delegation start time';
COMMENT ON COLUMN morbac.delegations.valid_until IS 'Delegation end time';
COMMENT ON COLUMN morbac.delegations.revoked IS 'Whether delegation has been revoked';

-- Explicitly prevent users from ever getting certain roles; takes precedence over positive assignments

CREATE TABLE morbac.negative_role_assignments (
    user_id UUID NOT NULL,
    role_id UUID NOT NULL REFERENCES morbac.roles(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES morbac.orgs(id) ON DELETE CASCADE,
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id, org_id)
);

CREATE INDEX idx_negative_assignments ON morbac.negative_role_assignments(user_id, org_id);

COMMENT ON TABLE morbac.negative_role_assignments IS 'Explicit prohibition of role assignments';
COMMENT ON COLUMN morbac.negative_role_assignments.reason IS 'Reason for prohibition';

-- Mutually exclusive roles that cannot be held simultaneously

CREATE TABLE morbac.sod_conflicts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_a_id UUID NOT NULL REFERENCES morbac.roles(id) ON DELETE CASCADE,
    role_b_id UUID NOT NULL REFERENCES morbac.roles(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES morbac.orgs(id) ON DELETE CASCADE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (role_a_id != role_b_id),
    UNIQUE (role_a_id, role_b_id, org_id)
);

CREATE INDEX idx_sod_conflicts_org ON morbac.sod_conflicts(org_id);
CREATE INDEX idx_sod_conflicts_roles ON morbac.sod_conflicts(role_a_id, role_b_id);

COMMENT ON TABLE morbac.sod_conflicts IS 'Separation of Duty: mutually exclusive roles';

-- Min/max user count constraints per role

CREATE TABLE morbac.role_cardinality (
    role_id UUID PRIMARY KEY REFERENCES morbac.roles(id) ON DELETE CASCADE,
    min_users INTEGER,
    max_users INTEGER,
    description TEXT,
    CHECK (min_users IS NULL OR min_users >= 0),
    CHECK (max_users IS NULL OR max_users >= 1),
    CHECK (min_users IS NULL OR max_users IS NULL OR max_users >= min_users)
);

COMMENT ON TABLE morbac.role_cardinality IS 'Cardinality constraints for roles (min/max number of users)';
COMMENT ON COLUMN morbac.role_cardinality.min_users IS 'Minimum number of users required for this role';
COMMENT ON COLUMN morbac.role_cardinality.max_users IS 'Maximum number of users allowed for this role';

-- Roles computed dynamically based on conditions rather than explicit assignment

CREATE TABLE morbac.derived_roles (
    role_id UUID PRIMARY KEY REFERENCES morbac.roles(id) ON DELETE CASCADE,
    condition_evaluator REGPROC NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE morbac.derived_roles IS 'Roles computed dynamically based on conditions';
COMMENT ON COLUMN morbac.derived_roles.condition_evaluator IS 'Function(user_id, org_id) returning boolean';

-- Transitive closure and effective role/activity/view lookup functions
--
-- All functions that query morbac tables are SECURITY DEFINER so they run
-- as the extension owner and bypass RLS on morbac tables. This prevents
-- infinite recursion when RLS policies call is_allowed(), which in turn
-- calls these functions.

CREATE OR REPLACE FUNCTION morbac.get_org_ancestors(p_org_id UUID)
RETURNS TABLE(org_id UUID, depth INTEGER)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE org_ancestors AS (
        SELECT p_org_id AS org_id, 0 AS depth
        UNION
        SELECT o.parent_id, oa.depth + 1
        FROM org_ancestors oa
        INNER JOIN morbac.orgs o ON o.id = oa.org_id
        WHERE o.parent_id IS NOT NULL
    )
    SELECT * FROM org_ancestors;
END;
$$;

COMMENT ON FUNCTION morbac.get_org_ancestors(UUID) IS
'Returns all ancestor organizations (including self) with depth in hierarchy';

CREATE OR REPLACE FUNCTION morbac.get_org_descendants(p_org_id UUID)
RETURNS TABLE(org_id UUID, depth INTEGER)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE org_descendants AS (
        SELECT p_org_id AS org_id, 0 AS depth
        UNION
        SELECT o.id, od.depth + 1
        FROM org_descendants od
        INNER JOIN morbac.orgs o ON o.parent_id = od.org_id
    )
    SELECT * FROM org_descendants;
END;
$$;

COMMENT ON FUNCTION morbac.get_org_descendants(UUID) IS
'Returns all descendant organizations (including self) with depth in hierarchy';

-- Get a named scope of organizations relative to a given org.
--
-- Supported scopes:
--   'self'         - the org itself only (depth = 0)
--   'children'     - direct children only (descendants at depth = 1)
--   'descendants'  - all descendants, excluding self (depth > 0)
--   'subtree'      - self + all descendants (equivalent to get_org_descendants)
--   'parent'       - direct parent only (ancestor at depth = 1)
--   'ancestors'    - all ancestors, excluding self (depth > 0)
--   'lineage'      - self + all ancestors (equivalent to get_org_ancestors)
--   'root'         - topmost ancestor only (max depth ancestor)
--   'unattributed' - the no-org bucket; resolves to no real orgs (empty set)
--   'all'          - every organization (unattributed is not an org, so it is
--                    not listed here; org_in_scope('all') does cover it)
--
-- Optional p_max_depth limits how many levels are traversed (NULL = unlimited).
CREATE OR REPLACE FUNCTION morbac.get_org_scope(
    p_org_id    UUID,
    p_scope     TEXT,
    p_max_depth INTEGER DEFAULT NULL
)
RETURNS TABLE(org_id UUID, depth INTEGER)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
BEGIN
    CASE p_scope
        WHEN 'self' THEN
            RETURN QUERY
            SELECT p_org_id, 0;

        WHEN 'children' THEN
            RETURN QUERY
            SELECT d.org_id, d.depth
            FROM morbac.get_org_descendants(p_org_id) d
            WHERE d.depth = 1
              AND (p_max_depth IS NULL OR d.depth <= p_max_depth);

        WHEN 'descendants' THEN
            RETURN QUERY
            SELECT d.org_id, d.depth
            FROM morbac.get_org_descendants(p_org_id) d
            WHERE d.depth > 0
              AND (p_max_depth IS NULL OR d.depth <= p_max_depth);

        WHEN 'subtree' THEN
            RETURN QUERY
            SELECT d.org_id, d.depth
            FROM morbac.get_org_descendants(p_org_id) d
            WHERE (p_max_depth IS NULL OR d.depth <= p_max_depth);

        WHEN 'parent' THEN
            RETURN QUERY
            SELECT a.org_id, a.depth
            FROM morbac.get_org_ancestors(p_org_id) a
            WHERE a.depth = 1
              AND (p_max_depth IS NULL OR a.depth <= p_max_depth);

        WHEN 'ancestors' THEN
            RETURN QUERY
            SELECT a.org_id, a.depth
            FROM morbac.get_org_ancestors(p_org_id) a
            WHERE a.depth > 0
              AND (p_max_depth IS NULL OR a.depth <= p_max_depth);

        WHEN 'lineage' THEN
            RETURN QUERY
            SELECT a.org_id, a.depth
            FROM morbac.get_org_ancestors(p_org_id) a
            WHERE (p_max_depth IS NULL OR a.depth <= p_max_depth);

        WHEN 'root' THEN
            RETURN QUERY
            SELECT a.org_id, a.depth
            FROM morbac.get_org_ancestors(p_org_id) a
            ORDER BY a.depth DESC
            LIMIT 1;

        WHEN 'unattributed' THEN
            RETURN QUERY
            SELECT NULL::UUID, 0 WHERE FALSE;

        WHEN 'all' THEN
            RETURN QUERY
            SELECT o.id, 0 FROM morbac.orgs o;

        ELSE
            RAISE EXCEPTION 'get_org_scope: unknown scope "%". Valid scopes: self, children, descendants, subtree, parent, ancestors, lineage, root, unattributed, all', p_scope;
    END CASE;
END;
$$;

COMMENT ON FUNCTION morbac.get_org_scope(UUID, TEXT, INTEGER) IS
'Returns a named set of organizations relative to p_org_id. Scopes: self, children, descendants, subtree, parent, ancestors, lineage, root, unattributed, all. Optional p_max_depth limits traversal depth.';

CREATE OR REPLACE FUNCTION morbac.get_effective_roles(p_user_id UUID, p_org_id UUID)
RETURNS TABLE(role_id UUID, depth INTEGER)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE effective_roles AS (
        SELECT ur.role_id, 0 AS depth
        FROM morbac.user_roles ur
        WHERE ur.user_id = p_user_id
          AND ur.org_id = p_org_id
        UNION
        SELECT rh.junior_role_id, er.depth + 1
        FROM effective_roles er
        INNER JOIN morbac.role_hierarchy rh ON rh.senior_role_id = er.role_id
    )
    SELECT DISTINCT ON (effective_roles.role_id) effective_roles.role_id, effective_roles.depth
    FROM effective_roles
    ORDER BY effective_roles.role_id, effective_roles.depth;
END;
$$;

COMMENT ON FUNCTION morbac.get_effective_roles(UUID, UUID) IS
'Returns all effective roles for a user in an organization (direct + inherited via role hierarchy)';

CREATE OR REPLACE FUNCTION morbac.get_inherited_roles(p_role_id UUID)
RETURNS TABLE(role_id UUID, depth INTEGER)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE inherited_roles AS (
        SELECT p_role_id AS role_id, 0 AS depth
        UNION
        SELECT rh.junior_role_id, ir.depth + 1
        FROM inherited_roles ir
        INNER JOIN morbac.role_hierarchy rh ON rh.senior_role_id = ir.role_id
    )
    SELECT DISTINCT ON (inherited_roles.role_id) inherited_roles.role_id, inherited_roles.depth
    FROM inherited_roles
    ORDER BY inherited_roles.role_id, inherited_roles.depth;
END;
$$;

COMMENT ON FUNCTION morbac.get_inherited_roles(UUID) IS
'Returns all roles inherited by a role (transitive closure via role hierarchy)';

CREATE OR REPLACE FUNCTION morbac.get_effective_activities(p_activity TEXT)
RETURNS TABLE(activity TEXT, depth INTEGER)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE effective_activities AS (
        SELECT p_activity AS activity, 0 AS depth
        UNION
        SELECT ah.junior_activity, ea.depth + 1
        FROM effective_activities ea
        INNER JOIN morbac.activity_hierarchy ah ON ah.senior_activity = ea.activity
    )
    SELECT DISTINCT ON (effective_activities.activity) effective_activities.activity, effective_activities.depth
    FROM effective_activities
    ORDER BY effective_activities.activity, effective_activities.depth;
END;
$$;

COMMENT ON FUNCTION morbac.get_effective_activities(TEXT) IS
'Returns all activities including those implied via activity hierarchy (e.g., write implies read)';

CREATE OR REPLACE FUNCTION morbac.get_effective_views(p_view TEXT)
RETURNS TABLE(view TEXT, depth INTEGER)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE effective_views AS (
        SELECT p_view AS view, 0 AS depth
        UNION
        SELECT vh.junior_view, ev.depth + 1
        FROM effective_views ev
        INNER JOIN morbac.view_hierarchy vh ON vh.senior_view = ev.view
    )
    SELECT DISTINCT ON (effective_views.view) effective_views.view, effective_views.depth
    FROM effective_views
    ORDER BY effective_views.view, effective_views.depth;
END;
$$;

COMMENT ON FUNCTION morbac.get_effective_views(TEXT) IS
'Returns all views including parent categories via view hierarchy';

CREATE OR REPLACE FUNCTION morbac.get_comprehensive_roles(p_user_id UUID, p_org_id UUID)
RETURNS TABLE(role_id UUID, source TEXT, depth INTEGER)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE effective_roles AS (
        -- Direct role assignments
        SELECT ur.role_id, 'direct'::TEXT as source, 0 AS depth
        FROM morbac.user_roles ur
        WHERE ur.user_id = p_user_id
          AND ur.org_id = p_org_id
          AND NOT EXISTS (
              SELECT 1 FROM morbac.negative_role_assignments nra
              WHERE nra.user_id = p_user_id
                AND nra.role_id = ur.role_id
                AND nra.org_id = p_org_id
          )

        UNION

        -- Delegated roles (active and not revoked)
        SELECT d.role_id, 'delegation'::TEXT, 0 AS depth
        FROM morbac.delegations d
        WHERE d.delegatee_id = p_user_id
            AND d.org_id = p_org_id
            AND NOT d.revoked
            AND now() BETWEEN d.valid_from AND d.valid_until
            AND EXISTS (
                    SELECT 1 FROM morbac.user_roles ur
                    WHERE ur.user_id = d.delegator_id
                        AND ur.role_id = d.role_id
                        AND ur.org_id = d.org_id
            )
            AND NOT EXISTS (
                    SELECT 1 FROM morbac.negative_role_assignments nra
                    WHERE nra.user_id = p_user_id
                        AND nra.role_id = d.role_id
                        AND nra.org_id = p_org_id
            )

        UNION

        -- Role hierarchy (junior roles inherited by user's roles)
        SELECT rh.junior_role_id, er.source || '_inherited', er.depth + 1
        FROM effective_roles er
        INNER JOIN morbac.role_hierarchy rh ON rh.senior_role_id = er.role_id
    )
    SELECT DISTINCT ON (effective_roles.role_id) effective_roles.role_id, effective_roles.source, effective_roles.depth
    FROM effective_roles
    WHERE effective_roles.role_id IS NOT NULL
    ORDER BY effective_roles.role_id, effective_roles.depth;

    -- Add derived roles separately
    RETURN QUERY
    SELECT dr.role_id, 'derived'::TEXT, 0
    FROM morbac.derived_roles dr
    INNER JOIN morbac.roles r ON r.id = dr.role_id
    WHERE r.org_id = p_org_id
      AND morbac.eval_derived_role(dr.condition_evaluator, p_user_id, p_org_id)
      AND NOT EXISTS (
          SELECT 1 FROM morbac.negative_role_assignments nra
          WHERE nra.user_id = p_user_id
            AND nra.role_id = dr.role_id
            AND nra.org_id = p_org_id
      );
END;
$$;

COMMENT ON FUNCTION morbac.get_comprehensive_roles(UUID, UUID) IS
'Returns all effective roles including direct, delegated, derived, and inherited via hierarchy';

CREATE OR REPLACE FUNCTION morbac.eval_derived_role(
    p_evaluator REGPROC,
    p_user_id UUID,
    p_org_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
DECLARE
    v_result BOOLEAN;
BEGIN
    EXECUTE format('SELECT %s(%L, %L)', p_evaluator::text, p_user_id, p_org_id) INTO v_result;
    RETURN COALESCE(v_result, FALSE);
EXCEPTION
    WHEN OTHERS THEN
        RETURN FALSE;
END;
$$;

COMMENT ON FUNCTION morbac.eval_derived_role(REGPROC, UUID, UUID) IS
'Evaluates a derived role condition function';

-- Check if p_target_org_id falls within the scope of p_rule_org_id.
-- Used by the authorization engine to evaluate scoped rules at query time.
CREATE OR REPLACE FUNCTION morbac.org_in_scope(
    p_target_org_id UUID,
    p_rule_org_id   UUID,
    p_scope         TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
BEGIN
    -- Org target vocabulary: all (every org, unattributed included),
    -- unattributed (no-org objects only), or a specific org via the tree scopes.
    -- Tree scopes never match an unattributed object.
    IF p_scope = 'all' THEN
        RETURN TRUE;
    END IF;
    IF p_scope = 'unattributed' THEN
        RETURN p_target_org_id IS NULL;
    END IF;
    IF p_target_org_id IS NULL THEN
        RETURN FALSE;
    END IF;

    IF p_scope = 'self' THEN
        RETURN p_target_org_id = p_rule_org_id;
    END IF;
    RETURN EXISTS(
        SELECT 1 FROM morbac.get_org_scope(p_rule_org_id, p_scope)
        WHERE org_id = p_target_org_id
    );
END;
$$;

COMMENT ON FUNCTION morbac.org_in_scope(UUID, UUID, TEXT) IS
'Returns TRUE if p_target_org_id is within get_org_scope(p_rule_org_id, p_scope). Scope unattributed matches only a NULL target; other scopes never match NULL. SECURITY DEFINER to bypass RLS on morbac.orgs.';

-- Precomputed transitive closures for all hierarchies to avoid recursive CTEs on each request

CREATE MATERIALIZED VIEW morbac.mv_role_closure AS
WITH RECURSIVE role_closure AS (
    SELECT id as senior_role_id, id as junior_role_id, 0 as depth
    FROM morbac.roles
    UNION
    SELECT rh.senior_role_id, rh.junior_role_id, 1 as depth
    FROM morbac.role_hierarchy rh
    UNION
    SELECT rc.senior_role_id, rh.junior_role_id, rc.depth + 1
    FROM role_closure rc
    INNER JOIN morbac.role_hierarchy rh ON rh.senior_role_id = rc.junior_role_id
    WHERE rc.depth < (SELECT value::integer FROM morbac.config WHERE key = 'hierarchy_max_depth')
)
SELECT DISTINCT senior_role_id, junior_role_id, MIN(depth) as depth
FROM role_closure
GROUP BY senior_role_id, junior_role_id;

CREATE UNIQUE INDEX idx_mv_role_closure ON morbac.mv_role_closure(senior_role_id, junior_role_id);
CREATE INDEX idx_mv_role_closure_junior ON morbac.mv_role_closure(junior_role_id);

COMMENT ON MATERIALIZED VIEW morbac.mv_role_closure IS
'Precomputed role hierarchy transitive closure - refresh after role hierarchy changes';

CREATE MATERIALIZED VIEW morbac.mv_org_closure AS
WITH RECURSIVE org_closure AS (
    SELECT id as descendant_id, id as ancestor_id, 0 as depth
    FROM morbac.orgs
    UNION
    SELECT o.id, oc.ancestor_id, oc.depth + 1
    FROM morbac.orgs o
    INNER JOIN org_closure oc ON o.parent_id = oc.descendant_id
    WHERE oc.depth < (SELECT value::integer FROM morbac.config WHERE key = 'hierarchy_max_depth')
)
SELECT DISTINCT descendant_id, ancestor_id, MIN(depth) as depth
FROM org_closure
GROUP BY descendant_id, ancestor_id;

CREATE UNIQUE INDEX idx_mv_org_closure ON morbac.mv_org_closure(descendant_id, ancestor_id);
CREATE INDEX idx_mv_org_closure_ancestor ON morbac.mv_org_closure(ancestor_id);

COMMENT ON MATERIALIZED VIEW morbac.mv_org_closure IS
'Precomputed organization hierarchy transitive closure - refresh after org hierarchy changes';

CREATE MATERIALIZED VIEW morbac.mv_activity_closure AS
WITH RECURSIVE activity_closure AS (
    SELECT name as senior_activity, name as junior_activity, 0 as depth
    FROM morbac.activities
    UNION
    SELECT ah.senior_activity, ah.junior_activity, 1 as depth
    FROM morbac.activity_hierarchy ah
    UNION
    SELECT ac.senior_activity, ah.junior_activity, ac.depth + 1
    FROM activity_closure ac
    INNER JOIN morbac.activity_hierarchy ah ON ah.senior_activity = ac.junior_activity
    WHERE ac.depth < (SELECT value::integer FROM morbac.config WHERE key = 'hierarchy_max_depth')
)
SELECT DISTINCT senior_activity, junior_activity, MIN(depth) as depth
FROM activity_closure
GROUP BY senior_activity, junior_activity;

CREATE UNIQUE INDEX idx_mv_activity_closure ON morbac.mv_activity_closure(senior_activity, junior_activity);
CREATE INDEX idx_mv_activity_closure_junior ON morbac.mv_activity_closure(junior_activity);

COMMENT ON MATERIALIZED VIEW morbac.mv_activity_closure IS
'Precomputed activity hierarchy transitive closure - refresh after activity hierarchy changes';

CREATE MATERIALIZED VIEW morbac.mv_view_closure AS
WITH RECURSIVE view_closure AS (
    SELECT name as senior_view, name as junior_view, 0 as depth
    FROM morbac.views
    UNION
    SELECT vh.senior_view, vh.junior_view, 1 as depth
    FROM morbac.view_hierarchy vh
    UNION
    SELECT vc.senior_view, vh.junior_view, vc.depth + 1
    FROM view_closure vc
    INNER JOIN morbac.view_hierarchy vh ON vh.senior_view = vc.junior_view
    WHERE vc.depth < (SELECT value::integer FROM morbac.config WHERE key = 'hierarchy_max_depth')
)
SELECT DISTINCT senior_view, junior_view, MIN(depth) as depth
FROM view_closure
GROUP BY senior_view, junior_view;

CREATE UNIQUE INDEX idx_mv_view_closure ON morbac.mv_view_closure(senior_view, junior_view);
CREATE INDEX idx_mv_view_closure_junior ON morbac.mv_view_closure(junior_view);

COMMENT ON MATERIALIZED VIEW morbac.mv_view_closure IS
'Precomputed view hierarchy transitive closure - refresh after view hierarchy changes';

CREATE OR REPLACE FUNCTION morbac.refresh_hierarchy_cache()
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY morbac.mv_role_closure;
    REFRESH MATERIALIZED VIEW CONCURRENTLY morbac.mv_org_closure;
    REFRESH MATERIALIZED VIEW CONCURRENTLY morbac.mv_activity_closure;
    REFRESH MATERIALIZED VIEW CONCURRENTLY morbac.mv_view_closure;
END;
$$;

COMMENT ON FUNCTION morbac.refresh_hierarchy_cache() IS
'Refresh all materialized hierarchy views - call after modifying hierarchies';

-- Contexts represent conditions under which rules apply, implemented as callable predicates

CREATE TABLE morbac.contexts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    evaluator REGPROC NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_contexts_name ON morbac.contexts(name);

COMMENT ON TABLE morbac.contexts IS 'Contexts - conditions under which rules apply (callable predicates)';
COMMENT ON COLUMN morbac.contexts.evaluator IS 'Function that evaluates this context (returns boolean)';

-- Default context that always evaluates to true

CREATE OR REPLACE FUNCTION morbac.context_always()
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN TRUE;
END;
$$;

COMMENT ON FUNCTION morbac.context_always() IS 'Default context evaluator - always returns true';

INSERT INTO morbac.contexts (name, description, evaluator)
VALUES (
    'always',
    'Default context - always evaluates to true',
    'morbac.context_always'::regproc
);

CREATE OR REPLACE FUNCTION morbac.eval_context(p_context_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
DECLARE
    v_evaluator REGPROC;
    v_result BOOLEAN;
BEGIN
    SELECT evaluator INTO v_evaluator
    FROM morbac.contexts
    WHERE id = p_context_id;

    IF v_evaluator IS NULL THEN
        RAISE EXCEPTION 'Context % not found', p_context_id;
    END IF;

    EXECUTE format('SELECT %s()', v_evaluator::text) INTO v_result;

    RETURN COALESCE(v_result, FALSE);
END;
$$;

COMMENT ON FUNCTION morbac.eval_context(UUID) IS 'Evaluates a context by calling its evaluator function';

-- Core OrBAC rule relation: Rule(org, role, activity, view, context, modality)
--
-- scope controls which orgs this rule covers relative to org_id:
--   'self'         - exact org only (default, current behavior)
--   'subtree'      - org + all descendants
--   'descendants'  - all descendants, excluding self
--   'children'     - direct children only
--   'parent'       - direct parent only
--   'ancestors'    - all ancestors, excluding self
--   'lineage'      - self + all ancestors
--   'root'         - topmost ancestor only
--   'unattributed' - no-org objects only (org_id column above is the declaring authority)
--   'all'          - every org, unattributed included
-- Evaluated at query time via org_in_scope() - new orgs are picked up automatically.
--
-- Org target vocabulary: a specific org (the tree scopes), 'unattributed', or 'all'.

CREATE TABLE morbac.rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES morbac.orgs(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES morbac.roles(id) ON DELETE CASCADE,
    activity TEXT NOT NULL REFERENCES morbac.activities(name) ON DELETE CASCADE,
    view TEXT NOT NULL REFERENCES morbac.views(name) ON DELETE CASCADE,
    context_id UUID NOT NULL REFERENCES morbac.contexts(id) ON DELETE CASCADE,
    modality morbac.modality NOT NULL,
    scope TEXT NOT NULL DEFAULT 'self',
    priority INTEGER,
    valid_from TIMESTAMPTZ,
    valid_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_active BOOLEAN NOT NULL DEFAULT FALSE,
    metadata JSONB DEFAULT '{}'::jsonb,
    UNIQUE(org_id, role_id, activity, view, context_id, modality, scope),
    CHECK (valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from),
    CHECK (scope IN ('self', 'children', 'descendants', 'subtree', 'parent', 'ancestors', 'lineage', 'root', 'unattributed', 'all'))
);

CREATE INDEX idx_rules_org_role ON morbac.rules(org_id, role_id);
CREATE INDEX idx_rules_activity_view ON morbac.rules(activity, view);
CREATE INDEX idx_rules_modality ON morbac.rules(modality);
CREATE INDEX idx_rules_lookup ON morbac.rules(org_id, role_id, activity, view, modality);
CREATE INDEX idx_rules_fast_lookup ON morbac.rules(org_id, activity, modality, view)
INCLUDE (role_id, context_id)
WHERE is_active = true;

COMMENT ON TABLE morbac.rules IS 'Core OrBAC rules - Permission, Prohibition, Obligation, Recommendation';
COMMENT ON COLUMN morbac.rules.scope IS 'Object scope: self (default), subtree, descendants, children, parent, ancestors, lineage, root, unattributed, all. Selects which objects (by org) the rule reaches: a specific org via the tree scopes, unattributed for no-org objects only, or all for every org including unattributed. Evaluated at query time - new orgs are covered automatically.';
COMMENT ON COLUMN morbac.rules.modality IS 'Deontic modality: permission, prohibition, obligation, recommendation';
COMMENT ON COLUMN morbac.rules.priority IS 'Optional rule priority (higher wins). NULL = 0. A permission with higher priority than a prohibition overrides it.';

-- Trigger to maintain is_active based on temporal validity

CREATE OR REPLACE FUNCTION morbac.rules_set_is_active()
RETURNS TRIGGER AS $$
BEGIN
    NEW.is_active := (
        (NEW.valid_from IS NULL OR NEW.valid_from <= CURRENT_TIMESTAMP)
        AND (NEW.valid_until IS NULL OR NEW.valid_until > CURRENT_TIMESTAMP)
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_rules_set_is_active ON morbac.rules;
CREATE TRIGGER trg_rules_set_is_active
BEFORE INSERT OR UPDATE ON morbac.rules
FOR EACH ROW EXECUTE FUNCTION morbac.rules_set_is_active();

-- Check if a rule is currently valid based on temporal constraints

CREATE OR REPLACE FUNCTION morbac.is_rule_valid(
    p_valid_from TIMESTAMPTZ,
    p_valid_until TIMESTAMPTZ
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_now TIMESTAMPTZ := CURRENT_TIMESTAMP;
BEGIN
    IF p_valid_from IS NOT NULL AND v_now < p_valid_from THEN
        RETURN FALSE;
    END IF;

    IF p_valid_until IS NOT NULL AND v_now >= p_valid_until THEN
        RETURN FALSE;
    END IF;

    RETURN TRUE;
END;
$$;

COMMENT ON FUNCTION morbac.is_rule_valid(TIMESTAMPTZ, TIMESTAMPTZ) IS
'Check if a rule is currently valid based on temporal constraints';

-- Rules that grant access across organization boundaries.
--
-- source_org_id: the org where the user must hold role_id.
-- target_org_id: the org where the resource resides.

CREATE TABLE morbac.cross_org_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_org_id UUID NOT NULL REFERENCES morbac.orgs(id) ON DELETE CASCADE,
    target_org_id UUID NOT NULL REFERENCES morbac.orgs(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES morbac.roles(id) ON DELETE CASCADE,
    activity TEXT NOT NULL REFERENCES morbac.activities(name) ON DELETE CASCADE,
    view TEXT NOT NULL REFERENCES morbac.views(name) ON DELETE CASCADE,
    context_id UUID NOT NULL REFERENCES morbac.contexts(id) ON DELETE CASCADE,
    modality morbac.modality NOT NULL,
    priority INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_from TIMESTAMPTZ,
    valid_until TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}'::jsonb,
    CHECK (source_org_id != target_org_id),
    CHECK (valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from),
    UNIQUE(source_org_id, target_org_id, role_id, activity, view, context_id, modality)
);

CREATE INDEX idx_cross_org_rules_source ON morbac.cross_org_rules(source_org_id, role_id);
CREATE INDEX idx_cross_org_rules_target ON morbac.cross_org_rules(target_org_id);
CREATE INDEX idx_cross_org_rules_temporal ON morbac.cross_org_rules(valid_from, valid_until);

COMMENT ON TABLE morbac.cross_org_rules IS 'Inter-organizational rules for cross-org access';
COMMENT ON COLUMN morbac.cross_org_rules.source_org_id IS 'Org where user holds the role';
COMMENT ON COLUMN morbac.cross_org_rules.target_org_id IS 'Org where the resource resides';

-- Direct user-level rules: Rule(user, org, activity, view, context, modality)
--
-- Grants or prohibits access for a specific user in an org, bypassing the role system.
-- Evaluated alongside regular rules and cross_org_rules in is_allowed_nocache().
-- Priority resolution follows the same semantics: higher priority wins, ties go to prohibition.
--
-- Org target: a specific org, or NULL for unattributed (no-org) objects.
-- For the same user across every org, use morbac.global_rules.

CREATE TABLE morbac.user_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    org_id UUID REFERENCES morbac.orgs(id) ON DELETE CASCADE,
    activity TEXT NOT NULL REFERENCES morbac.activities(name) ON DELETE CASCADE,
    view TEXT NOT NULL REFERENCES morbac.views(name) ON DELETE CASCADE,
    context_id UUID NOT NULL REFERENCES morbac.contexts(id) ON DELETE CASCADE,
    modality morbac.modality NOT NULL,
    priority INTEGER,
    valid_from TIMESTAMPTZ,
    valid_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata JSONB DEFAULT '{}'::jsonb,
    CHECK (valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from),
    UNIQUE(user_id, org_id, activity, view, context_id, modality)
);

-- NULLs are distinct in UNIQUE, so the unattributed target needs its own index
CREATE UNIQUE INDEX idx_user_rules_unattributed_unique
    ON morbac.user_rules(user_id, activity, view, context_id, modality)
    WHERE org_id IS NULL;

CREATE INDEX idx_user_rules_user_org ON morbac.user_rules(user_id, org_id);
CREATE INDEX idx_user_rules_activity_view ON morbac.user_rules(activity, view);
CREATE INDEX idx_user_rules_modality ON morbac.user_rules(modality);
CREATE INDEX idx_user_rules_lookup ON morbac.user_rules(user_id, org_id, activity, modality, view);

COMMENT ON TABLE morbac.user_rules IS 'Direct user-level rules - grant or prohibit access for a specific user, bypassing the role system';
COMMENT ON COLUMN morbac.user_rules.user_id IS 'User this rule applies to directly';
COMMENT ON COLUMN morbac.user_rules.org_id IS 'Org where the resource resides; NULL targets unattributed (no-org) objects';
COMMENT ON COLUMN morbac.user_rules.modality IS 'Deontic modality: permission, prohibition, obligation, recommendation';
COMMENT ON COLUMN morbac.user_rules.priority IS 'Optional priority (higher wins). NULL = 0. Follows same resolution as morbac.rules.';

-- Global rules: Rule(user_id, activity, view, context, modality)
--
-- No org_id or role_id - applies system-wide regardless of org membership or roles.
-- user_id NULL = every user; non-NULL = specific user only.
-- activity NULL = any activity; view NULL = any view.
--
-- Evaluated at steps 3.5 (prohibitions) and 6.5 (permissions) in is_allowed_nocache().
-- When activity/view are set, hierarchy resolution applies normally.

CREATE TABLE morbac.global_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID,
    activity TEXT REFERENCES morbac.activities(name) ON DELETE CASCADE,
    view TEXT REFERENCES morbac.views(name) ON DELETE CASCADE,
    context_id UUID NOT NULL REFERENCES morbac.contexts(id) ON DELETE CASCADE,
    modality morbac.modality NOT NULL,
    priority INTEGER,
    valid_from TIMESTAMPTZ,
    valid_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_active BOOLEAN NOT NULL DEFAULT FALSE,
    metadata JSONB DEFAULT '{}'::jsonb,
    CHECK (valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from),
    UNIQUE(user_id, activity, view, context_id, modality)
);

CREATE INDEX idx_global_rules_user_id ON morbac.global_rules(user_id);
CREATE INDEX idx_global_rules_activity_view ON morbac.global_rules(activity, view);
CREATE INDEX idx_global_rules_modality ON morbac.global_rules(modality);
CREATE INDEX idx_global_rules_fast_lookup ON morbac.global_rules(modality)
    INCLUDE (user_id, activity, view, context_id)
    WHERE is_active = true;

COMMENT ON TABLE morbac.global_rules IS
'System-wide rules with no org or role binding. user_id NULL = all users; activity/view NULL = any activity/view.';
COMMENT ON COLUMN morbac.global_rules.user_id IS
'NULL = all users; non-NULL = this specific user only';
COMMENT ON COLUMN morbac.global_rules.activity IS
'NULL = any activity; non-NULL = specific activity (hierarchy applies)';
COMMENT ON COLUMN morbac.global_rules.view IS
'NULL = any view; non-NULL = specific view (hierarchy applies)';

CREATE OR REPLACE FUNCTION morbac.global_rules_set_is_active()
RETURNS TRIGGER AS $$
BEGIN
    NEW.is_active := (
        (NEW.valid_from IS NULL OR NEW.valid_from <= CURRENT_TIMESTAMP)
        AND (NEW.valid_until IS NULL OR NEW.valid_until > CURRENT_TIMESTAMP)
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_global_rules_set_is_active ON morbac.global_rules;
CREATE TRIGGER trg_global_rules_set_is_active
BEFORE INSERT OR UPDATE ON morbac.global_rules
FOR EACH ROW EXECUTE FUNCTION morbac.global_rules_set_is_active();

-- System principals: backend service accounts defined at deploy time.
--
-- Registered user_ids are fully protected at the trigger level:
--   - No role assignments, revocations, or negative assignments
--   - No user_rules (permissions or prohibitions)
--   - No delegations involving them
--   - No targeted global_rules prohibitions
--   - All prohibitions are skipped in is_allowed_nocache() (see authorization.sql)
--
-- This table has no INSERT/UPDATE/DELETE RLS policies - only the database owner
-- can register or remove system principals (done in SQL at deploy time).
-- SELECT is gated by is_allowed() like all other system tables.

CREATE TABLE morbac.system_principals (
    user_id UUID PRIMARY KEY,
    description TEXT
);

COMMENT ON TABLE morbac.system_principals IS
'Registry of backend service accounts. Immutable at the trigger level - no policy can touch them.';
COMMENT ON COLUMN morbac.system_principals.user_id IS
'External user UUID of the service account';

-- Shared guard for tables with a single user_id column

CREATE OR REPLACE FUNCTION morbac.raise_if_system_principal()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_user_id UUID;
BEGIN
    v_user_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.user_id ELSE NEW.user_id END;
    IF EXISTS (SELECT 1 FROM morbac.system_principals WHERE user_id = v_user_id) THEN
        RAISE EXCEPTION 'operation blocked: % is a system principal', v_user_id;
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER trg_system_principal_user_roles
BEFORE INSERT OR UPDATE OR DELETE ON morbac.user_roles
FOR EACH ROW EXECUTE FUNCTION morbac.raise_if_system_principal();

CREATE TRIGGER trg_system_principal_user_rules
BEFORE INSERT OR UPDATE OR DELETE ON morbac.user_rules
FOR EACH ROW EXECUTE FUNCTION morbac.raise_if_system_principal();

CREATE TRIGGER trg_system_principal_negative_roles
BEFORE INSERT OR UPDATE OR DELETE ON morbac.negative_role_assignments
FOR EACH ROW EXECUTE FUNCTION morbac.raise_if_system_principal();

-- Delegations have two user_id columns

CREATE OR REPLACE FUNCTION morbac.raise_if_system_principal_delegation()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM morbac.system_principals
        WHERE user_id IN (NEW.delegator_id, NEW.delegatee_id)
    ) THEN
        RAISE EXCEPTION 'operation blocked: delegations cannot involve system principals';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_system_principal_delegations
BEFORE INSERT OR UPDATE ON morbac.delegations
FOR EACH ROW EXECUTE FUNCTION morbac.raise_if_system_principal_delegation();

-- Global rules: all operations on rows belonging to a system principal are blocked.
-- This protects both the permission rules defined for them and prevents prohibitions
-- from being added against them. Define their rules at deploy time as the DB owner.

CREATE OR REPLACE FUNCTION morbac.raise_if_system_principal_global_rule()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_user_id UUID;
BEGIN
    v_user_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.user_id ELSE NEW.user_id END;
    IF v_user_id IS NOT NULL
       AND EXISTS (SELECT 1 FROM morbac.system_principals WHERE user_id = v_user_id)
    THEN
        -- allow initial deploy-time insert when no rules exist yet for this principal
        IF TG_OP = 'INSERT'
           AND NOT EXISTS (SELECT 1 FROM morbac.global_rules WHERE user_id = v_user_id)
        THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'operation blocked: global rules for system principal % are immutable', v_user_id;
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER trg_system_principal_global_rules
BEFORE INSERT OR UPDATE OR DELETE ON morbac.global_rules
FOR EACH ROW EXECUTE FUNCTION morbac.raise_if_system_principal_global_rule();

-- Optional whitelist of valid (activity, view) pairs.
-- If any binding exists for an activity, rules may only use listed views.
-- Activities with no bindings are unconstrained.

CREATE TABLE morbac.activity_view_bindings (
    activity TEXT NOT NULL REFERENCES morbac.activities(name) ON DELETE CASCADE,
    view     TEXT NOT NULL REFERENCES morbac.views(name) ON DELETE CASCADE,
    PRIMARY KEY (activity, view)
);

COMMENT ON TABLE morbac.activity_view_bindings IS
'Optional whitelist of valid (activity, view) pairs. Constrains rule creation on a per-activity basis.';

CREATE OR REPLACE FUNCTION morbac.trg_check_activity_view_binding()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM morbac.activity_view_bindings WHERE activity = NEW.activity)
       AND NOT EXISTS (SELECT 1 FROM morbac.activity_view_bindings WHERE activity = NEW.activity AND view = NEW.view)
    THEN
        RAISE EXCEPTION 'Activity "%" is not allowed on view "%" - add a binding to morbac.activity_view_bindings to permit it',
            NEW.activity, NEW.view;
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION morbac.trg_check_activity_view_binding() IS
'Blocks rule creation when an activity has bindings but the target view is not among them.';

DROP TRIGGER IF EXISTS trg_activity_view_binding_check ON morbac.rules;
CREATE TRIGGER trg_activity_view_binding_check
BEFORE INSERT OR UPDATE ON morbac.rules
FOR EACH ROW EXECUTE FUNCTION morbac.trg_check_activity_view_binding();

DROP TRIGGER IF EXISTS trg_activity_view_binding_check ON morbac.cross_org_rules;
CREATE TRIGGER trg_activity_view_binding_check
BEFORE INSERT OR UPDATE ON morbac.cross_org_rules
FOR EACH ROW EXECUTE FUNCTION morbac.trg_check_activity_view_binding();

-- Obligations and recommendations do NOT affect authorization decisions.
-- They are queryable for informational purposes (task lists, compliance prompts, etc.).
--
-- Conflict resolution (from Multi-OrBAC paper):
-- - A prohibition voids any applicable obligation for the same (activity, view)
-- - A prohibition or obligation voids any applicable recommendation for the same (activity, view)

-- Returns pending obligations not voided by an applicable prohibition
CREATE OR REPLACE FUNCTION morbac.pending_obligations(
    p_user_id UUID,
    p_org_id UUID
)
RETURNS TABLE(
    rule_id UUID,
    role_name TEXT,
    activity TEXT,
    view TEXT,
    context_name TEXT,
    created_at TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT
        r.id,
        ro.name,
        r.activity,
        r.view,
        c.name,
        r.created_at
    FROM morbac.rules r
    INNER JOIN morbac.roles ro ON ro.id = r.role_id
    INNER JOIN morbac.contexts c ON c.id = r.context_id
    WHERE r.org_id = p_org_id
      AND r.modality = 'obligation'
      AND r.role_id IN (
          SELECT role_id FROM morbac.get_comprehensive_roles(p_user_id, p_org_id)
      )
      AND morbac.is_rule_valid(r.valid_from, r.valid_until)
      AND morbac.eval_context(r.context_id)
      -- Prohibition voids obligation unless the obligation has strictly higher priority
      AND NOT EXISTS (
          SELECT 1
          FROM morbac.rules p
          WHERE p.org_id = p_org_id
            AND p.modality = 'prohibition'
            AND p.activity IN (SELECT ea.activity FROM morbac.get_effective_activities(r.activity) ea)
            AND p.view IN (SELECT ev.view FROM morbac.get_effective_views(r.view) ev)
            AND p.role_id IN (
                SELECT role_id FROM morbac.get_comprehensive_roles(p_user_id, p_org_id)
            )
            AND morbac.is_rule_valid(p.valid_from, p.valid_until)
            AND morbac.eval_context(p.context_id)
            AND COALESCE(p.priority, 0) >= COALESCE(r.priority, 0)
      )
    ORDER BY r.created_at;
END;
$$;

COMMENT ON FUNCTION morbac.pending_obligations(UUID, UUID) IS
'Returns pending obligations for a user in an organization (informational only). Prohibitions void applicable obligations per Multi-OrBAC conflict resolution.';

-- Returns recommendations not voided by an applicable prohibition or obligation
CREATE OR REPLACE FUNCTION morbac.pending_recommendations(
    p_user_id UUID,
    p_org_id UUID
)
RETURNS TABLE(
    rule_id UUID,
    role_name TEXT,
    activity TEXT,
    view TEXT,
    context_name TEXT,
    created_at TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT
        r.id,
        ro.name,
        r.activity,
        r.view,
        c.name,
        r.created_at
    FROM morbac.rules r
    INNER JOIN morbac.roles ro ON ro.id = r.role_id
    INNER JOIN morbac.contexts c ON c.id = r.context_id
    WHERE r.org_id = p_org_id
      AND r.modality = 'recommendation'
      AND r.role_id IN (
          SELECT role_id FROM morbac.get_comprehensive_roles(p_user_id, p_org_id)
      )
      AND morbac.is_rule_valid(r.valid_from, r.valid_until)
      AND morbac.eval_context(r.context_id)
      -- Prohibition or obligation voids recommendation unless recommendation has strictly higher priority
      AND NOT EXISTS (
          SELECT 1
          FROM morbac.rules p
          WHERE p.org_id = p_org_id
            AND p.modality IN ('prohibition', 'obligation')
            AND p.activity IN (SELECT ea.activity FROM morbac.get_effective_activities(r.activity) ea)
            AND p.view IN (SELECT ev.view FROM morbac.get_effective_views(r.view) ev)
            AND p.role_id IN (
                SELECT role_id FROM morbac.get_comprehensive_roles(p_user_id, p_org_id)
            )
            AND morbac.is_rule_valid(p.valid_from, p.valid_until)
            AND morbac.eval_context(p.context_id)
            AND COALESCE(p.priority, 0) >= COALESCE(r.priority, 0)
      )
    ORDER BY r.created_at;
END;
$$;

COMMENT ON FUNCTION morbac.pending_recommendations(UUID, UUID) IS
'Returns recommendations for a user in an organization (informational only). Prohibitions and obligations void applicable recommendations per Multi-OrBAC conflict resolution.';

CREATE OR REPLACE FUNCTION morbac.user_roles_in_org(
    p_user_id UUID,
    p_org_id UUID
)
RETURNS TABLE(
    role_id UUID,
    role_name TEXT
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT r.id, r.name
    FROM morbac.roles r
    INNER JOIN morbac.user_roles ur ON ur.role_id = r.id
    WHERE ur.user_id = p_user_id
      AND ur.org_id = p_org_id
      AND r.org_id = p_org_id;
END;
$$;

COMMENT ON FUNCTION morbac.user_roles_in_org(UUID, UUID) IS
'Returns all roles for a user in an organization';

CREATE OR REPLACE FUNCTION morbac.user_has_role(
    p_user_id UUID,
    p_org_id UUID,
    p_role_name TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_count
    FROM morbac.roles r
    INNER JOIN morbac.user_roles ur ON ur.role_id = r.id
    WHERE ur.user_id = p_user_id
      AND ur.org_id = p_org_id
      AND r.org_id = p_org_id
      AND r.name = p_role_name;

    RETURN v_count > 0;
END;
$$;

COMMENT ON FUNCTION morbac.user_has_role(UUID, UUID, TEXT) IS
'Returns true if user has specific role in organization';

-- Optional audit logging for tracking changes to security-critical tables.
-- Enable/disable per table with morbac.enable_audit() / morbac.disable_audit().

CREATE TABLE morbac.audit_log (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id UUID,
    org_id UUID,
    table_name TEXT NOT NULL,
    operation TEXT NOT NULL,
    record_id UUID,
    old_data JSONB,
    new_data JSONB,
    changed_fields TEXT[],
    session_username TEXT DEFAULT SESSION_USER,
    client_addr INET DEFAULT INET_CLIENT_ADDR(),
    application_name TEXT DEFAULT CURRENT_SETTING('application_name', true),
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_audit_log_timestamp ON morbac.audit_log(timestamp DESC);
CREATE INDEX idx_audit_log_user_id ON morbac.audit_log(user_id);
CREATE INDEX idx_audit_log_org_id ON morbac.audit_log(org_id);
CREATE INDEX idx_audit_log_table_operation ON morbac.audit_log(table_name, operation);
CREATE INDEX idx_audit_log_record_id ON morbac.audit_log(record_id);

COMMENT ON TABLE morbac.audit_log IS 'Audit trail for security-critical operations';
COMMENT ON COLUMN morbac.audit_log.user_id IS 'Application user (from morbac.current_user_id() if available)';
COMMENT ON COLUMN morbac.audit_log.org_id IS 'Organization context (from morbac.current_org_id() if available)';
COMMENT ON COLUMN morbac.audit_log.operation IS 'INSERT, UPDATE, DELETE, or custom operation name';
COMMENT ON COLUMN morbac.audit_log.changed_fields IS 'Array of field names that changed (for UPDATE operations)';
COMMENT ON COLUMN morbac.audit_log.session_username IS 'Database session user';
COMMENT ON COLUMN morbac.audit_log.client_addr IS 'Client IP address';

CREATE OR REPLACE FUNCTION morbac.audit_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_old_data JSONB;
    v_new_data JSONB;
    v_changed_fields TEXT[];
    v_user_id UUID;
    v_org_id UUID;
    v_record_id UUID;
BEGIN
    BEGIN
        v_user_id := morbac.current_user_id();
    EXCEPTION WHEN OTHERS THEN
        v_user_id := NULL;
    END;

    BEGIN
        v_org_id := morbac.current_org_id();
    EXCEPTION WHEN OTHERS THEN
        v_org_id := NULL;
    END;

    IF TG_OP = 'DELETE' THEN
        v_old_data := row_to_json(OLD)::jsonb;
        v_new_data := NULL;
        v_record_id := (v_old_data->>'id')::uuid;
    ELSIF TG_OP = 'INSERT' THEN
        v_old_data := NULL;
        v_new_data := row_to_json(NEW)::jsonb;
        v_record_id := (v_new_data->>'id')::uuid;
    ELSIF TG_OP = 'UPDATE' THEN
        v_old_data := row_to_json(OLD)::jsonb;
        v_new_data := row_to_json(NEW)::jsonb;
        v_record_id := (v_new_data->>'id')::uuid;

        SELECT array_agg(key)
        INTO v_changed_fields
        FROM jsonb_each(v_old_data)
        WHERE v_old_data->key IS DISTINCT FROM v_new_data->key;
    END IF;

    IF v_org_id IS NULL THEN
        IF v_new_data ? 'org_id' THEN
            v_org_id := (v_new_data->>'org_id')::uuid;
        ELSIF v_old_data ? 'org_id' THEN
            v_org_id := (v_old_data->>'org_id')::uuid;
        END IF;
    END IF;

    INSERT INTO morbac.audit_log (
        user_id,
        org_id,
        table_name,
        operation,
        record_id,
        old_data,
        new_data,
        changed_fields
    ) VALUES (
        v_user_id,
        v_org_id,
        TG_TABLE_NAME,
        TG_OP,
        v_record_id,
        v_old_data,
        v_new_data,
        v_changed_fields
    );

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$;

COMMENT ON FUNCTION morbac.audit_trigger() IS
'Generic audit trigger function - captures INSERT/UPDATE/DELETE operations';

CREATE OR REPLACE FUNCTION morbac.enable_audit(p_table_name TEXT)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_trigger_name TEXT;
BEGIN
    v_trigger_name := 'audit_' || p_table_name;

    EXECUTE format(
        'CREATE TRIGGER %I AFTER INSERT OR UPDATE OR DELETE ON morbac.%I ' ||
        'FOR EACH ROW EXECUTE FUNCTION morbac.audit_trigger()',
        v_trigger_name,
        p_table_name
    );

    RAISE NOTICE 'Audit logging enabled for morbac.%', p_table_name;
END;
$$;

COMMENT ON FUNCTION morbac.enable_audit(TEXT) IS
'Enable audit logging on a morbac table - creates audit trigger';

CREATE OR REPLACE FUNCTION morbac.disable_audit(p_table_name TEXT)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_trigger_name TEXT;
BEGIN
    v_trigger_name := 'audit_' || p_table_name;

    EXECUTE format(
        'DROP TRIGGER IF EXISTS %I ON morbac.%I',
        v_trigger_name,
        p_table_name
    );

    RAISE NOTICE 'Audit logging disabled for morbac.%', p_table_name;
END;
$$;

COMMENT ON FUNCTION morbac.disable_audit(TEXT) IS
'Disable audit logging on a morbac table - removes audit trigger';

-- Row-Level Security helpers, compatible with PostgREST

CREATE OR REPLACE FUNCTION morbac.current_user_id()
RETURNS UUID
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_user_id TEXT;
BEGIN
    v_user_id := current_setting('morbac.user_id', TRUE);

    IF v_user_id IS NULL OR v_user_id = '' THEN
        RETURN NULL;
    END IF;

    RETURN v_user_id::UUID;
EXCEPTION
    WHEN OTHERS THEN
        RETURN NULL;
END;
$$;

COMMENT ON FUNCTION morbac.current_user_id() IS
'Returns current user ID from morbac.user_id session variable';

CREATE OR REPLACE FUNCTION morbac.current_org_id()
RETURNS UUID
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_org_id TEXT;
BEGIN
    v_org_id := current_setting('morbac.org_id', TRUE);

    IF v_org_id IS NULL OR v_org_id = '' THEN
        RETURN NULL;
    END IF;

    RETURN v_org_id::UUID;
EXCEPTION
    WHEN OTHERS THEN
        RETURN NULL;
END;
$$;

COMMENT ON FUNCTION morbac.current_org_id() IS
'Returns current organization ID from morbac.org_id session variable';

CREATE OR REPLACE FUNCTION morbac.current_target_user_id()
RETURNS UUID
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_user_id TEXT;
BEGIN
    v_user_id := current_setting('morbac.target_user_id', TRUE);

    IF v_user_id IS NULL OR v_user_id = '' THEN
        RETURN NULL;
    END IF;

    RETURN v_user_id::UUID;
EXCEPTION
    WHEN OTHERS THEN
        RETURN NULL;
END;
$$;

COMMENT ON FUNCTION morbac.current_target_user_id() IS
'Returns target user ID filter from morbac.target_user_id session variable';

-- Set via: SET morbac.org_ids = '["uuid1","uuid2"]' or '["uuid1", null]' or '[null]'.
-- A JSON null element names the no-org (unattributed) bucket, distinct from
-- the real org UUIDs which populate org_ids.
CREATE OR REPLACE FUNCTION morbac.current_org_filter(
    OUT org_ids              UUID[],
    OUT include_unattributed BOOLEAN
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_raw  TEXT := current_setting('morbac.org_ids', TRUE);
    v_json JSONB;
BEGIN
    org_ids := NULL;
    include_unattributed := FALSE;

    IF v_raw IS NULL OR v_raw = '' THEN
        RETURN;
    END IF;

    v_json := v_raw::jsonb;
    org_ids := ARRAY(
        SELECT x::UUID
        FROM jsonb_array_elements_text(v_json) x
        WHERE x IS NOT NULL
    );
    include_unattributed := EXISTS (
        SELECT 1 FROM jsonb_array_elements(v_json) e WHERE e = 'null'::jsonb
    );
EXCEPTION
    WHEN OTHERS THEN
        org_ids := NULL;
        include_unattributed := FALSE;
END;
$$;

COMMENT ON FUNCTION morbac.current_org_filter() IS
'Parses morbac.org_ids (JSON array) once into real org UUIDs plus a flag for whether the no-org bucket (JSON null element) was requested.';

CREATE OR REPLACE FUNCTION morbac.current_org_ids()
RETURNS UUID[]
LANGUAGE sql
STABLE
AS $$
    SELECT org_ids FROM morbac.current_org_filter();
$$;

COMMENT ON FUNCTION morbac.current_org_ids() IS
'Returns the real org UUIDs from morbac.org_ids (JSON null elements excluded). See current_org_filter() for the no-org bucket flag.';

CREATE OR REPLACE FUNCTION morbac.get_user_orgs(p_user_id UUID)
RETURNS TABLE(org_id UUID)
LANGUAGE sql
STABLE
SECURITY DEFINER
AS $$
    SELECT DISTINCT ur.org_id
    FROM morbac.user_roles ur
    WHERE ur.user_id = p_user_id
    UNION
    SELECT DISTINCT d.org_id
    FROM morbac.delegations d
    WHERE d.delegatee_id = p_user_id
      AND NOT d.revoked
      AND now() BETWEEN d.valid_from AND d.valid_until;
$$;

COMMENT ON FUNCTION morbac.get_user_orgs(UUID) IS
'Returns all org IDs the user has any direct role or active delegation in';

-- rls_check has two forms, distinguished by arity so a NULL never carries two
-- meanings:
--
--   rls_check(activity, view)                       -- table has no org column
--   rls_check(activity, view, row_org_id[, row_user_id]) -- row-scoped by org
--
-- In the 3/4-arg form row_org_id is the record's org, and a NULL value means the
-- record is unattributed (no org) -- never "no org dimension". The 2-arg form
-- carries no org dimension and evaluates against the session org context.

DROP FUNCTION IF EXISTS morbac.rls_check(TEXT, TEXT, UUID, UUID);

CREATE OR REPLACE FUNCTION morbac.rls_check(
    p_activity TEXT,
    p_view     TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_user_id UUID;
    v_org_id  UUID;
BEGIN
    v_user_id := morbac.current_user_id();
    IF v_user_id IS NULL THEN
        RETURN FALSE;
    END IF;

    v_org_id := morbac.current_org_id();
    IF v_org_id IS NOT NULL THEN
        RETURN morbac.is_allowed(v_user_id, v_org_id, p_activity, p_view);
    END IF;

    RETURN morbac.is_allowed(v_user_id, NULL, p_activity, p_view);
END;
$$;

COMMENT ON FUNCTION morbac.rls_check(TEXT, TEXT) IS
'RLS helper for tables without an org column. Uses the session org context (morbac.org_id), else org-independent rules. For row-scoped tables use the 3/4-arg form.';

-- Org scoping: morbac.org_id (single) > morbac.org_ids (list) > all orgs.
-- User scoping: morbac.target_user_id filters rows to a specific user.
CREATE OR REPLACE FUNCTION morbac.rls_check(
    p_activity    TEXT,
    p_view        TEXT,
    p_row_org_id  UUID,
    p_row_user_id UUID DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_user_id         UUID;
    v_org_id          UUID;
    v_org_ids         UUID[];
    v_include_unattr  BOOLEAN;
    v_target_user_id  UUID;
BEGIN
    v_user_id := morbac.current_user_id();

    IF v_user_id IS NULL THEN
        RETURN FALSE;
    END IF;

    -- User filter: if morbac.target_user_id is set, only rows matching that user pass
    IF p_row_user_id IS NOT NULL THEN
        v_target_user_id := morbac.current_target_user_id();
        IF v_target_user_id IS NOT NULL AND p_row_user_id <> v_target_user_id THEN
            RETURN FALSE;
        END IF;
    END IF;

    -- Single org selection: exact bucket only. An unattributed row (NULL org) is
    -- DISTINCT from the pin and is filtered out (use the org_ids list for both).
    v_org_id := morbac.current_org_id();

    IF v_org_id IS NOT NULL THEN
        IF p_row_org_id IS DISTINCT FROM v_org_id THEN
            RETURN FALSE;
        END IF;
        RETURN morbac.is_allowed(v_user_id, v_org_id, p_activity, p_view);
    END IF;

    -- Org list selection: real orgs and/or the unattributed bucket (JSON null element).
    SELECT f.org_ids, f.include_unattributed
    INTO v_org_ids, v_include_unattr
    FROM morbac.current_org_filter() f;

    IF v_org_ids IS NOT NULL OR v_include_unattr THEN
        IF p_row_org_id IS NULL THEN
            IF NOT v_include_unattr THEN
                RETURN FALSE;
            END IF;
            RETURN morbac.is_allowed(v_user_id, NULL, p_activity, p_view);
        END IF;
        IF v_org_ids IS NULL OR NOT (p_row_org_id = ANY(v_org_ids)) THEN
            RETURN FALSE;
        END IF;
        RETURN morbac.is_allowed(v_user_id, p_row_org_id, p_activity, p_view);
    END IF;

    -- No selection set: all authorized rows. The row's own org drives the decision
    -- (unattributed row -> unattributed + org-independent rules).
    RETURN morbac.is_allowed(v_user_id, p_row_org_id, p_activity, p_view);
END;
$$;

COMMENT ON FUNCTION morbac.rls_check(TEXT, TEXT, UUID, UUID) IS
'RLS helper for row-scoped tables. p_row_org_id is the record org; NULL means unattributed. Select records via morbac.org_id (single org, unattributed excluded) or morbac.org_ids (JSON array; a null element adds the unattributed bucket). No selection = all authorized rows including unattributed. Pass row user_id to filter by morbac.target_user_id.';

-- assign_role / revoke_role: convenience wrappers that enforce SoD and
-- cardinality constraints. Access control is handled by RLS on morbac.user_roles.

CREATE OR REPLACE FUNCTION morbac.assign_role(
    p_target_user_id UUID,
    p_role_id UUID,
    p_org_id UUID
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    IF morbac.check_sod_violation(p_target_user_id, p_role_id, p_org_id) THEN
        RAISE EXCEPTION 'Role assignment would violate Separation of Duty constraints';
    END IF;

    -- INSERT triggers RLS policy on morbac.user_roles (create on user_roles view)
    INSERT INTO morbac.user_roles (user_id, role_id, org_id)
    VALUES (p_target_user_id, p_role_id, p_org_id)
    ON CONFLICT (user_id, role_id, org_id) DO NOTHING;

    DECLARE
        v_error TEXT;
    BEGIN
        v_error := morbac.check_cardinality_violation(p_role_id);
        IF v_error IS NOT NULL THEN
            RAISE EXCEPTION 'Role assignment violates cardinality constraint: %', v_error;
        END IF;
    END;
END;
$$;

COMMENT ON FUNCTION morbac.assign_role(UUID, UUID, UUID) IS
'Assign role with SoD and cardinality validation. RLS on morbac.user_roles enforces authorization.';

CREATE OR REPLACE FUNCTION morbac.revoke_role(
    p_target_user_id UUID,
    p_role_id UUID,
    p_org_id UUID
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    -- DELETE triggers RLS policy on morbac.user_roles (delete on user_roles view)
    DELETE FROM morbac.user_roles
    WHERE user_id = p_target_user_id
      AND role_id = p_role_id
      AND org_id = p_org_id;

    DECLARE
        v_error TEXT;
    BEGIN
        v_error := morbac.check_cardinality_violation(p_role_id, FALSE);
        IF v_error IS NOT NULL THEN
            RAISE WARNING 'Role revocation may violate cardinality constraint: %', v_error;
        END IF;
    END;
END;
$$;

COMMENT ON FUNCTION morbac.revoke_role(UUID, UUID, UUID) IS
'Revoke role with cardinality validation. RLS on morbac.user_roles enforces authorization.';

-- Authorization decision cache to avoid repeated expensive computations.
-- TTL is configurable via morbac.config (cache_ttl_seconds).

CREATE TABLE morbac.auth_cache (
    user_id UUID NOT NULL,
    org_id UUID NOT NULL,
    activity TEXT NOT NULL,
    view TEXT NOT NULL,
    allowed BOOLEAN NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (CURRENT_TIMESTAMP + INTERVAL '5 minutes'),
    PRIMARY KEY (user_id, org_id, activity, view)
);

CREATE INDEX idx_auth_cache_expires ON morbac.auth_cache(expires_at);
CREATE INDEX idx_auth_cache_user_org ON morbac.auth_cache(user_id, org_id);

COMMENT ON TABLE morbac.auth_cache IS
'Authorization decision cache - expires after 5 minutes or when policies change';

CREATE OR REPLACE FUNCTION morbac.invalidate_cache(p_user_id UUID DEFAULT NULL, p_org_id UUID DEFAULT NULL)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    IF p_user_id IS NOT NULL AND p_org_id IS NOT NULL THEN
        DELETE FROM morbac.auth_cache WHERE user_id = p_user_id AND org_id = p_org_id;
    ELSIF p_org_id IS NOT NULL THEN
        DELETE FROM morbac.auth_cache WHERE org_id = p_org_id;
    ELSIF p_user_id IS NOT NULL THEN
        DELETE FROM morbac.auth_cache WHERE user_id = p_user_id;
    ELSE
        DELETE FROM morbac.auth_cache;
    END IF;
END;
$$;

COMMENT ON FUNCTION morbac.invalidate_cache(UUID, UUID) IS
'Invalidate auth cache for specific user/org or all entries';

CREATE OR REPLACE FUNCTION morbac.cleanup_auth_cache()
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_deleted INTEGER;
BEGIN
    DELETE FROM morbac.auth_cache WHERE expires_at < CURRENT_TIMESTAMP;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$;

COMMENT ON FUNCTION morbac.cleanup_auth_cache() IS
'Remove expired cache entries - call periodically via cron';

-- Invalidate cache on rule or role changes

CREATE OR REPLACE FUNCTION morbac.invalidate_cache_on_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_org_id UUID;
BEGIN
    IF TG_OP = 'DELETE' THEN
        BEGIN
            v_org_id := OLD.org_id;
        EXCEPTION WHEN undefined_column THEN
            v_org_id := NULL;
        END;
    ELSE
        BEGIN
            v_org_id := NEW.org_id;
        EXCEPTION WHEN undefined_column THEN
            v_org_id := NULL;
        END;
    END IF;
    IF v_org_id IS NOT NULL THEN
        DELETE FROM morbac.auth_cache WHERE org_id = v_org_id;
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER trg_invalidate_cache_rules
AFTER INSERT OR UPDATE OR DELETE ON morbac.rules
FOR EACH ROW EXECUTE FUNCTION morbac.invalidate_cache_on_change();

CREATE TRIGGER trg_invalidate_cache_user_roles
AFTER INSERT OR UPDATE OR DELETE ON morbac.user_roles
FOR EACH ROW EXECUTE FUNCTION morbac.invalidate_cache_on_change();

CREATE TRIGGER trg_invalidate_cache_delegations
AFTER INSERT OR UPDATE OR DELETE ON morbac.delegations
FOR EACH ROW EXECUTE FUNCTION morbac.invalidate_cache_on_change();

CREATE TRIGGER trg_invalidate_cache_cross_org
AFTER INSERT OR UPDATE OR DELETE ON morbac.cross_org_rules
FOR EACH ROW EXECUTE FUNCTION morbac.invalidate_cache_on_change();

CREATE OR REPLACE FUNCTION morbac.invalidate_cache_on_user_rule_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_user_id UUID;
    v_org_id  UUID;
BEGIN
    IF TG_OP = 'DELETE' THEN
        v_user_id := OLD.user_id;
        v_org_id  := OLD.org_id;
    ELSE
        v_user_id := NEW.user_id;
        v_org_id  := NEW.org_id;
    END IF;
    DELETE FROM morbac.auth_cache WHERE user_id = v_user_id AND org_id = v_org_id;
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER trg_invalidate_cache_user_rules
AFTER INSERT OR UPDATE OR DELETE ON morbac.user_rules
FOR EACH ROW EXECUTE FUNCTION morbac.invalidate_cache_on_user_rule_change();

-- Global rules have no org scope - any change invalidates the entire cache
CREATE OR REPLACE FUNCTION morbac.invalidate_cache_on_global_rule_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    DELETE FROM morbac.auth_cache;
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER trg_invalidate_cache_global_rules
AFTER INSERT OR UPDATE OR DELETE ON morbac.global_rules
FOR EACH ROW EXECUTE FUNCTION morbac.invalidate_cache_on_global_rule_change();

-- system_principals changes affect prohibition bypass - invalidate per user
CREATE OR REPLACE FUNCTION morbac.invalidate_cache_on_system_principal_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_user_id UUID;
BEGIN
    v_user_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.user_id ELSE NEW.user_id END;
    DELETE FROM morbac.auth_cache WHERE user_id = v_user_id;
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER trg_invalidate_cache_system_principals
AFTER INSERT OR UPDATE OR DELETE ON morbac.system_principals
FOR EACH ROW EXECUTE FUNCTION morbac.invalidate_cache_on_system_principal_change();

-- Refresh materialized hierarchy views when hierarchies change

CREATE OR REPLACE FUNCTION morbac.refresh_on_hierarchy_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    PERFORM morbac.refresh_hierarchy_cache();
    DELETE FROM morbac.auth_cache;
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER trg_refresh_role_hierarchy
AFTER INSERT OR UPDATE OR DELETE ON morbac.role_hierarchy
FOR EACH STATEMENT EXECUTE FUNCTION morbac.refresh_on_hierarchy_change();

CREATE TRIGGER trg_refresh_activity_hierarchy
AFTER INSERT OR UPDATE OR DELETE ON morbac.activity_hierarchy
FOR EACH STATEMENT EXECUTE FUNCTION morbac.refresh_on_hierarchy_change();

CREATE TRIGGER trg_refresh_view_hierarchy
AFTER INSERT OR UPDATE OR DELETE ON morbac.view_hierarchy
FOR EACH STATEMENT EXECUTE FUNCTION morbac.refresh_on_hierarchy_change();

-- Invalidate entire cache when org hierarchy changes.
-- Scoped rules (scope != 'self') depend on the org tree, so any org change
-- may affect which orgs a rule covers.

CREATE OR REPLACE FUNCTION morbac.invalidate_all_cache()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    DELETE FROM morbac.auth_cache;
    RETURN NULL;
END;
$$;

CREATE TRIGGER trg_invalidate_cache_orgs
AFTER INSERT OR UPDATE OR DELETE ON morbac.orgs
FOR EACH STATEMENT EXECUTE FUNCTION morbac.invalidate_all_cache();

-- Validation functions for SoD, cardinality, and rule conflict detection.
--
-- Rule conflict detection (from Multi-OrBAC paper):
-- Conflicts exist when two rules share the same (org, role, activity, view, context)
-- but their modalities create a situation where one permanently overrides the other:
--   - prohibition + permission    -> permission is dead (always overridden)
--   - prohibition + obligation    -> obligation is always voided
--   - prohibition + recommendation -> recommendation is always voided
--   - obligation  + recommendation -> recommendation is always voided
--
-- Note: hierarchy-based overlaps are intentional design, not flagged here.

CREATE OR REPLACE FUNCTION morbac.check_sod_violation(
    p_user_id UUID,
    p_role_id UUID,
    p_org_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_conflict_exists BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM morbac.user_roles ur
        INNER JOIN morbac.sod_conflicts sod ON (
            (sod.role_a_id = ur.role_id AND sod.role_b_id = p_role_id)
            OR (sod.role_b_id = ur.role_id AND sod.role_a_id = p_role_id)
        )
        WHERE ur.user_id = p_user_id
          AND ur.org_id = p_org_id
          AND sod.org_id = p_org_id
    ) INTO v_conflict_exists;

    RETURN v_conflict_exists;
END;
$$;

COMMENT ON FUNCTION morbac.check_sod_violation(UUID, UUID, UUID) IS
'Returns true if assigning role would violate Separation of Duty constraints';

CREATE OR REPLACE FUNCTION morbac.check_cardinality_violation(
    p_role_id UUID,
    p_adding BOOLEAN DEFAULT TRUE
)
RETURNS TEXT
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_current_count INTEGER;
    v_min_users INTEGER;
    v_max_users INTEGER;
BEGIN
    SELECT
        COUNT(DISTINCT ur.user_id),
        rc.min_users,
        rc.max_users
    INTO v_current_count, v_min_users, v_max_users
    FROM morbac.user_roles ur
    LEFT JOIN morbac.role_cardinality rc ON rc.role_id = ur.role_id
    WHERE ur.role_id = p_role_id
    GROUP BY rc.min_users, rc.max_users;

    IF p_adding AND v_max_users IS NOT NULL THEN
        IF v_current_count >= v_max_users THEN
            RETURN format('Maximum users (%s) reached for role', v_max_users);
        END IF;
    END IF;

    IF NOT p_adding AND v_min_users IS NOT NULL THEN
        IF v_current_count <= v_min_users THEN
            RETURN format('Minimum users (%s) required for role', v_min_users);
        END IF;
    END IF;

    RETURN NULL;
END;
$$;

COMMENT ON FUNCTION morbac.check_cardinality_violation(UUID, BOOLEAN) IS
'Returns error message if cardinality constraint would be violated, NULL otherwise';

CREATE OR REPLACE FUNCTION morbac.detect_rule_conflicts(
    p_org_id     UUID,
    p_role_id    UUID,
    p_activity   TEXT,
    p_view       TEXT,
    p_context_id UUID,
    p_modality   morbac.modality,
    p_exclude_id UUID DEFAULT NULL,
    p_scope      TEXT DEFAULT 'self'
)
RETURNS TABLE(
    conflicting_rule_id  UUID,
    conflicting_modality morbac.modality,
    description          TEXT
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT
        r.id,
        r.modality,
        CASE
            WHEN p_modality = 'prohibition'
                THEN 'prohibition voids existing ' || r.modality::text
            WHEN r.modality = 'prohibition'
                THEN p_modality::text || ' will always be overridden by existing prohibition'
            WHEN p_modality = 'obligation' AND r.modality = 'recommendation'
                THEN 'obligation voids existing recommendation'
            ELSE
                'recommendation will always be overridden by existing obligation'
        END
    FROM morbac.rules r
    WHERE r.org_id     = p_org_id
      AND r.role_id    = p_role_id
      AND r.activity   = p_activity
      AND r.view       = p_view
      AND r.context_id = p_context_id
      AND r.scope      = p_scope
      AND r.modality  != p_modality
      AND (p_exclude_id IS NULL OR r.id != p_exclude_id)
      AND (
          (p_modality = 'prohibition'    AND r.modality IN ('permission', 'obligation', 'recommendation'))
          OR (r.modality = 'prohibition' AND p_modality IN ('permission', 'obligation', 'recommendation'))
          OR (p_modality = 'obligation'     AND r.modality = 'recommendation')
          OR (p_modality = 'recommendation' AND r.modality = 'obligation')
      );
END;
$$;

COMMENT ON FUNCTION morbac.detect_rule_conflicts(UUID, UUID, TEXT, TEXT, UUID, morbac.modality, UUID, TEXT) IS
'Returns rules that directly conflict with the given tuple due to modality precedence (prohibition > obligation > recommendation > permission). Conflicts are scoped: only rules sharing the same scope compete, since different scopes target different object sets.';

-- Trigger: warn (non-blocking) when a new/updated rule conflicts with an existing one

CREATE OR REPLACE FUNCTION morbac.trg_warn_rule_conflicts()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_conflict RECORD;
BEGIN
    FOR v_conflict IN
        SELECT * FROM morbac.detect_rule_conflicts(
            NEW.org_id, NEW.role_id, NEW.activity, NEW.view, NEW.context_id, NEW.modality,
            CASE WHEN TG_OP = 'UPDATE' THEN NEW.id ELSE NULL END,
            NEW.scope
        )
    LOOP
        RAISE WARNING 'Rule conflict: % (conflicts with rule %)',
            v_conflict.description, v_conflict.conflicting_rule_id;
    END LOOP;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_rules_conflict_check ON morbac.rules;
CREATE TRIGGER trg_rules_conflict_check
BEFORE INSERT OR UPDATE ON morbac.rules
FOR EACH ROW EXECUTE FUNCTION morbac.trg_warn_rule_conflicts();

COMMENT ON FUNCTION morbac.trg_warn_rule_conflicts() IS
'Trigger function: emits a WARNING (non-blocking) when a rule conflicts with an existing rule due to modality precedence.';

-- Authorization decision function implementing canonical OrBAC semantics.
--
-- Access is allowed if and only if:
--   1. At least one applicable permission exists
--   2. AND no applicable prohibition exists (or permission has strictly higher priority)
-- Default deny (no permission = deny).
-- Obligations and recommendations do NOT affect authorization.
--
-- Priority resolution:
-- - Each rule has an optional integer priority (NULL = 0, lowest)
-- - When both a prohibition and a permission apply, the higher-priority rule wins
-- - Tie goes to prohibition (modality precedence from the Multi-OrBAC paper)
--
-- Org target (p_org_id): a specific org, or NULL meaning the object is
-- unattributed (has no org). NULL never means "any org".
--
-- Scope:
-- - rules.scope selects which objects a rule covers: a specific org
--   (self/subtree/descendants/...), 'unattributed', or 'all'.
--   Evaluated at query time via org_in_scope() - new orgs are covered automatically.
-- - cross_org_rules.source_org_id is always required: user must hold the role there.
-- - user_rules target a specific user directly (no role required); their org_id
--   is a specific org, or NULL for unattributed objects.
-- - global_rules apply to every org, unattributed included.

CREATE OR REPLACE FUNCTION morbac.is_allowed_nocache(
    p_user_id UUID,
    p_org_id UUID,
    p_activity TEXT,
    p_view TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
DECLARE
    v_rule                     RECORD;
    v_max_prohibition_priority INTEGER := NULL;
    v_max_permission_priority  INTEGER := NULL;
    v_is_system_principal      BOOLEAN;
BEGIN
    v_is_system_principal := EXISTS (
        SELECT 1 FROM morbac.system_principals WHERE user_id = p_user_id
    );

    -- STEPS 1-3.5: Prohibitions - skipped entirely for system principals
    IF NOT v_is_system_principal THEN

        -- STEP 1: Local prohibitions - find the highest-priority applicable one
        FOR v_rule IN
            SELECT r.context_id, COALESCE(r.priority, 0) AS prio
            FROM morbac.rules r
            WHERE morbac.org_in_scope(p_org_id, r.org_id, r.scope)
              AND r.modality = 'prohibition'
              AND r.activity IN (SELECT activity FROM morbac.get_effective_activities(p_activity))
              AND r.view     IN (SELECT view     FROM morbac.get_effective_views(p_view))
              AND r.role_id  IN (SELECT role_id  FROM morbac.get_comprehensive_roles(p_user_id, r.org_id))
              AND morbac.is_rule_valid(r.valid_from, r.valid_until)
            ORDER BY COALESCE(r.priority, 0) DESC
        LOOP
            IF morbac.eval_context(v_rule.context_id) THEN
                v_max_prohibition_priority := v_rule.prio;
                EXIT;
            END IF;
        END LOOP;

        -- STEP 2: Cross-org prohibitions - update max if a higher priority is found
        FOR v_rule IN
            SELECT cr.context_id, COALESCE(cr.priority, 0) AS prio
            FROM morbac.cross_org_rules cr
            WHERE cr.target_org_id = p_org_id
              AND cr.modality = 'prohibition'
              AND cr.activity IN (SELECT activity FROM morbac.get_effective_activities(p_activity))
              AND cr.view     IN (SELECT view     FROM morbac.get_effective_views(p_view))
              AND cr.role_id IN (SELECT role_id FROM morbac.get_comprehensive_roles(p_user_id, cr.source_org_id))
              AND morbac.is_rule_valid(cr.valid_from, cr.valid_until)
            ORDER BY COALESCE(cr.priority, 0) DESC
        LOOP
            IF morbac.eval_context(v_rule.context_id) THEN
                IF v_max_prohibition_priority IS NULL OR v_rule.prio > v_max_prohibition_priority THEN
                    v_max_prohibition_priority := v_rule.prio;
                END IF;
                EXIT;
            END IF;
        END LOOP;

        -- STEP 3: User-level prohibitions - direct user rules, update max if higher
        FOR v_rule IN
            SELECT ur.context_id, COALESCE(ur.priority, 0) AS prio
            FROM morbac.user_rules ur
            WHERE ur.user_id = p_user_id
              AND ur.org_id IS NOT DISTINCT FROM p_org_id
              AND ur.modality = 'prohibition'
              AND ur.activity IN (SELECT activity FROM morbac.get_effective_activities(p_activity))
              AND ur.view     IN (SELECT view     FROM morbac.get_effective_views(p_view))
              AND morbac.is_rule_valid(ur.valid_from, ur.valid_until)
            ORDER BY COALESCE(ur.priority, 0) DESC
        LOOP
            IF morbac.eval_context(v_rule.context_id) THEN
                IF v_max_prohibition_priority IS NULL OR v_rule.prio > v_max_prohibition_priority THEN
                    v_max_prohibition_priority := v_rule.prio;
                END IF;
                EXIT;
            END IF;
        END LOOP;

        -- STEP 3.5: Global prohibitions
        FOR v_rule IN
            SELECT gr.context_id, COALESCE(gr.priority, 0) AS prio
            FROM morbac.global_rules gr
            WHERE (gr.user_id IS NULL OR gr.user_id = p_user_id)
              AND gr.modality = 'prohibition'
              AND (gr.activity IS NULL OR gr.activity IN (SELECT activity FROM morbac.get_effective_activities(p_activity)))
              AND (gr.view     IS NULL OR gr.view     IN (SELECT view     FROM morbac.get_effective_views(p_view)))
              AND morbac.is_rule_valid(gr.valid_from, gr.valid_until)
            ORDER BY COALESCE(gr.priority, 0) DESC
        LOOP
            IF morbac.eval_context(v_rule.context_id) THEN
                IF v_max_prohibition_priority IS NULL OR v_rule.prio > v_max_prohibition_priority THEN
                    v_max_prohibition_priority := v_rule.prio;
                END IF;
                EXIT;
            END IF;
        END LOOP;

    END IF; -- v_is_system_principal

    -- STEP 4: Local permissions - find the highest-priority applicable one
    FOR v_rule IN
        SELECT r.context_id, COALESCE(r.priority, 0) AS prio
        FROM morbac.rules r
        WHERE morbac.org_in_scope(p_org_id, r.org_id, r.scope)
          AND r.modality = 'permission'
          AND r.activity IN (SELECT activity FROM morbac.get_effective_activities(p_activity))
          AND r.view     IN (SELECT view     FROM morbac.get_effective_views(p_view))
          AND r.role_id  IN (SELECT role_id  FROM morbac.get_comprehensive_roles(p_user_id, r.org_id))
          AND morbac.is_rule_valid(r.valid_from, r.valid_until)
        ORDER BY COALESCE(r.priority, 0) DESC
    LOOP
        IF morbac.eval_context(v_rule.context_id) THEN
            v_max_permission_priority := v_rule.prio;
            EXIT;
        END IF;
    END LOOP;

    -- STEP 5: Cross-org permissions - update max if higher found
    FOR v_rule IN
        SELECT cr.context_id, COALESCE(cr.priority, 0) AS prio
        FROM morbac.cross_org_rules cr
        WHERE cr.target_org_id = p_org_id
          AND cr.modality = 'permission'
          AND cr.activity IN (SELECT activity FROM morbac.get_effective_activities(p_activity))
          AND cr.view     IN (SELECT view     FROM morbac.get_effective_views(p_view))
          AND cr.role_id IN (SELECT role_id FROM morbac.get_comprehensive_roles(p_user_id, cr.source_org_id))
          AND morbac.is_rule_valid(cr.valid_from, cr.valid_until)
        ORDER BY COALESCE(cr.priority, 0) DESC
    LOOP
        IF morbac.eval_context(v_rule.context_id) THEN
            IF v_max_permission_priority IS NULL OR v_rule.prio > v_max_permission_priority THEN
                v_max_permission_priority := v_rule.prio;
            END IF;
            EXIT;
        END IF;
    END LOOP;

    -- STEP 6: User-level permissions - direct user rules, update max if higher
    FOR v_rule IN
        SELECT ur.context_id, COALESCE(ur.priority, 0) AS prio
        FROM morbac.user_rules ur
        WHERE ur.user_id = p_user_id
          AND ur.org_id IS NOT DISTINCT FROM p_org_id
          AND ur.modality = 'permission'
          AND ur.activity IN (SELECT activity FROM morbac.get_effective_activities(p_activity))
          AND ur.view     IN (SELECT view     FROM morbac.get_effective_views(p_view))
          AND morbac.is_rule_valid(ur.valid_from, ur.valid_until)
        ORDER BY COALESCE(ur.priority, 0) DESC
    LOOP
        IF morbac.eval_context(v_rule.context_id) THEN
            IF v_max_permission_priority IS NULL OR v_rule.prio > v_max_permission_priority THEN
                v_max_permission_priority := v_rule.prio;
            END IF;
            EXIT;
        END IF;
    END LOOP;

    -- STEP 6.5: Global permissions
    FOR v_rule IN
        SELECT gr.context_id, COALESCE(gr.priority, 0) AS prio
        FROM morbac.global_rules gr
        WHERE (gr.user_id IS NULL OR gr.user_id = p_user_id)
          AND gr.modality = 'permission'
          AND (gr.activity IS NULL OR gr.activity IN (SELECT activity FROM morbac.get_effective_activities(p_activity)))
          AND (gr.view     IS NULL OR gr.view     IN (SELECT view     FROM morbac.get_effective_views(p_view)))
          AND morbac.is_rule_valid(gr.valid_from, gr.valid_until)
        ORDER BY COALESCE(gr.priority, 0) DESC
    LOOP
        IF morbac.eval_context(v_rule.context_id) THEN
            IF v_max_permission_priority IS NULL OR v_rule.prio > v_max_permission_priority THEN
                v_max_permission_priority := v_rule.prio;
            END IF;
            EXIT;
        END IF;
    END LOOP;

    -- STEP 7: Priority resolution
    IF v_max_prohibition_priority IS NULL THEN
        RETURN v_max_permission_priority IS NOT NULL;
    END IF;

    IF v_max_permission_priority IS NOT NULL
       AND v_max_permission_priority > v_max_prohibition_priority THEN
        RETURN TRUE;
    END IF;

    RETURN FALSE;
END;
$$;

COMMENT ON FUNCTION morbac.is_allowed_nocache(UUID, UUID, TEXT, TEXT) IS
'Authorization without cache - use for debugging or when cache must be bypassed';

-- Cached authorization check (default, recommended for production use)
CREATE OR REPLACE FUNCTION morbac.is_allowed(
    p_user_id UUID,
    p_org_id UUID,
    p_activity TEXT,
    p_view TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
AS $$
DECLARE
    v_cached_result BOOLEAN;
    v_computed_result BOOLEAN;
    v_expires_at TIMESTAMPTZ;
BEGIN
    SELECT allowed, expires_at INTO v_cached_result, v_expires_at
    FROM morbac.auth_cache
    WHERE user_id = p_user_id
      AND org_id = p_org_id
      AND activity = p_activity
      AND view = p_view
      AND expires_at > CURRENT_TIMESTAMP;

    IF FOUND THEN
        RETURN v_cached_result;
    END IF;

    v_computed_result := morbac.is_allowed_nocache(p_user_id, p_org_id, p_activity, p_view);

    -- NULL org_id (global-rules-only path) cannot be stored in auth_cache (org_id NOT NULL PK).
    -- Global rule changes flush the entire cache anyway, so skipping is safe.
    IF p_org_id IS NULL THEN
        RETURN v_computed_result;
    END IF;

    BEGIN
        INSERT INTO morbac.auth_cache (user_id, org_id, activity, view, allowed, expires_at)
        VALUES (
            p_user_id,
            p_org_id,
            p_activity,
            p_view,
            v_computed_result,
            CURRENT_TIMESTAMP + make_interval(secs => morbac.get_config('cache_ttl_seconds')::integer)
        )
        ON CONFLICT (user_id, org_id, activity, view) DO UPDATE
        SET allowed = v_computed_result,
            computed_at = CURRENT_TIMESTAMP,
            expires_at = CURRENT_TIMESTAMP + make_interval(secs => morbac.get_config('cache_ttl_seconds')::integer);
    EXCEPTION WHEN read_only_sql_transaction THEN
        NULL;
    END;

    RETURN v_computed_result;
END;
$$;

COMMENT ON FUNCTION morbac.is_allowed(UUID, UUID, TEXT, TEXT) IS
'Complete OrBAC authorization with caching (default) - use is_allowed_nocache() for debugging';

-- Capability probe: does the user hold the permission in ANY context (any org
-- they are a member of, or the no-org bucket, or via global rules)? Intended
-- for UI feature gating, not object-level enforcement. Prohibitions are honored
-- per context: a context counts only if is_allowed() returns true there.
-- Pure cross-org grants into a non-member org are not counted.
CREATE OR REPLACE FUNCTION morbac.has_permission(
    p_user_id UUID,
    p_activity TEXT,
    p_view TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM morbac.get_user_orgs(p_user_id) o
        WHERE morbac.is_allowed(p_user_id, o.org_id, p_activity, p_view)
    ) OR morbac.is_allowed(p_user_id, NULL, p_activity, p_view);
END;
$$;

COMMENT ON FUNCTION morbac.has_permission(UUID, TEXT, TEXT) IS
'Capability probe for UI gating: TRUE if the user is allowed the activity/view in any member org, the no-org bucket, or via global rules. Not a substitute for object-level is_allowed().';

-- RLS policies for morbac system tables.
--
-- is_allowed() and its internal callees are SECURITY DEFINER, so they run as
-- the extension owner and bypass RLS. This prevents infinite recursion when
-- these policies fire.
--
-- View names used in rules are config-driven (system_view.*).
-- Override with morbac.set_config('system_view.orgs', 'my_orgs') etc.
-- The new name must exist in morbac.views and your rules must reference it.
--
-- RLS is disabled for the superuser/extension owner by default (PostgreSQL
-- behavior). Bootstrap the first organization and superuser role as the
-- database owner before enabling this in production.

-- morbac.orgs
-- Row's org context is the org itself.
ALTER TABLE morbac.orgs ENABLE ROW LEVEL SECURITY;

CREATE POLICY orgs_select ON morbac.orgs FOR SELECT
    USING (morbac.is_allowed(morbac.current_user_id(), id, 'read',
        morbac.get_config('system_view.orgs')));

CREATE POLICY orgs_insert ON morbac.orgs FOR INSERT
    WITH CHECK (morbac.is_allowed(morbac.current_user_id(), morbac.current_org_id(), 'create',
        morbac.get_config('system_view.orgs')));

CREATE POLICY orgs_update ON morbac.orgs FOR UPDATE
    USING (morbac.is_allowed(morbac.current_user_id(), id, 'update',
        morbac.get_config('system_view.orgs')));

CREATE POLICY orgs_delete ON morbac.orgs FOR DELETE
    USING (morbac.is_allowed(morbac.current_user_id(), id, 'delete',
        morbac.get_config('system_view.orgs')));

-- morbac.roles
ALTER TABLE morbac.roles ENABLE ROW LEVEL SECURITY;

CREATE POLICY roles_select ON morbac.roles FOR SELECT
    USING (morbac.is_allowed(morbac.current_user_id(), org_id, 'read',
        morbac.get_config('system_view.roles')));

CREATE POLICY roles_insert ON morbac.roles FOR INSERT
    WITH CHECK (morbac.is_allowed(morbac.current_user_id(), org_id, 'create',
        morbac.get_config('system_view.roles')));

CREATE POLICY roles_update ON morbac.roles FOR UPDATE
    USING (morbac.is_allowed(morbac.current_user_id(), org_id, 'update',
        morbac.get_config('system_view.roles')));

CREATE POLICY roles_delete ON morbac.roles FOR DELETE
    USING (morbac.is_allowed(morbac.current_user_id(), org_id, 'delete',
        morbac.get_config('system_view.roles')));

-- morbac.rules
ALTER TABLE morbac.rules ENABLE ROW LEVEL SECURITY;

CREATE POLICY rules_select ON morbac.rules FOR SELECT
    USING (morbac.is_allowed(morbac.current_user_id(), org_id, 'read',
        morbac.get_config('system_view.rules')));

CREATE POLICY rules_insert ON morbac.rules FOR INSERT
    WITH CHECK (morbac.is_allowed(morbac.current_user_id(), org_id, 'create',
        morbac.get_config('system_view.rules')));

CREATE POLICY rules_update ON morbac.rules FOR UPDATE
    USING (morbac.is_allowed(morbac.current_user_id(), org_id, 'update',
        morbac.get_config('system_view.rules')));

CREATE POLICY rules_delete ON morbac.rules FOR DELETE
    USING (morbac.is_allowed(morbac.current_user_id(), org_id, 'delete',
        morbac.get_config('system_view.rules')));

-- morbac.user_roles
ALTER TABLE morbac.user_roles ENABLE ROW LEVEL SECURITY;

CREATE POLICY user_roles_select ON morbac.user_roles FOR SELECT
    USING (morbac.is_allowed(morbac.current_user_id(), org_id, 'read',
        morbac.get_config('system_view.user_roles')));

CREATE POLICY user_roles_insert ON morbac.user_roles FOR INSERT
    WITH CHECK (morbac.is_allowed(morbac.current_user_id(), org_id, 'create',
        morbac.get_config('system_view.user_roles')));

CREATE POLICY user_roles_delete ON morbac.user_roles FOR DELETE
    USING (morbac.is_allowed(morbac.current_user_id(), org_id, 'delete',
        morbac.get_config('system_view.user_roles')));

-- morbac.contexts (global - use current session org for writes)
ALTER TABLE morbac.contexts ENABLE ROW LEVEL SECURITY;

CREATE POLICY contexts_select ON morbac.contexts FOR SELECT
    USING (morbac.is_allowed(morbac.current_user_id(), morbac.current_org_id(), 'read',
        morbac.get_config('system_view.contexts')));

CREATE POLICY contexts_insert ON morbac.contexts FOR INSERT
    WITH CHECK (morbac.is_allowed(morbac.current_user_id(), morbac.current_org_id(), 'create',
        morbac.get_config('system_view.contexts')));

CREATE POLICY contexts_update ON morbac.contexts FOR UPDATE
    USING (morbac.is_allowed(morbac.current_user_id(), morbac.current_org_id(), 'update',
        morbac.get_config('system_view.contexts')));

CREATE POLICY contexts_delete ON morbac.contexts FOR DELETE
    USING (morbac.is_allowed(morbac.current_user_id(), morbac.current_org_id(), 'delete',
        morbac.get_config('system_view.contexts')));

-- morbac.activities (global - use current session org for writes)
ALTER TABLE morbac.activities ENABLE ROW LEVEL SECURITY;

CREATE POLICY activities_select ON morbac.activities FOR SELECT
    USING (morbac.is_allowed(morbac.current_user_id(), morbac.current_org_id(), 'read',
        morbac.get_config('system_view.activities')));

CREATE POLICY activities_insert ON morbac.activities FOR INSERT
    WITH CHECK (morbac.is_allowed(morbac.current_user_id(), morbac.current_org_id(), 'create',
        morbac.get_config('system_view.activities')));

CREATE POLICY activities_update ON morbac.activities FOR UPDATE
    USING (morbac.is_allowed(morbac.current_user_id(), morbac.current_org_id(), 'update',
        morbac.get_config('system_view.activities')));

CREATE POLICY activities_delete ON morbac.activities FOR DELETE
    USING (morbac.is_allowed(morbac.current_user_id(), morbac.current_org_id(), 'delete',
        morbac.get_config('system_view.activities')));

-- morbac.views (global - use current session org for writes)
ALTER TABLE morbac.views ENABLE ROW LEVEL SECURITY;

CREATE POLICY views_select ON morbac.views FOR SELECT
    USING (morbac.is_allowed(morbac.current_user_id(), morbac.current_org_id(), 'read',
        morbac.get_config('system_view.views')));

CREATE POLICY views_insert ON morbac.views FOR INSERT
    WITH CHECK (morbac.is_allowed(morbac.current_user_id(), morbac.current_org_id(), 'create',
        morbac.get_config('system_view.views')));

CREATE POLICY views_update ON morbac.views FOR UPDATE
    USING (morbac.is_allowed(morbac.current_user_id(), morbac.current_org_id(), 'update',
        morbac.get_config('system_view.views')));

CREATE POLICY views_delete ON morbac.views FOR DELETE
    USING (morbac.is_allowed(morbac.current_user_id(), morbac.current_org_id(), 'delete',
        morbac.get_config('system_view.views')));

-- morbac.delegations
ALTER TABLE morbac.delegations ENABLE ROW LEVEL SECURITY;

CREATE POLICY delegations_select ON morbac.delegations FOR SELECT
    USING (morbac.is_allowed(morbac.current_user_id(), org_id, 'read',
        morbac.get_config('system_view.delegations')));

CREATE POLICY delegations_insert ON morbac.delegations FOR INSERT
    WITH CHECK (morbac.is_allowed(morbac.current_user_id(), org_id, 'create',
        morbac.get_config('system_view.delegations')));

CREATE POLICY delegations_update ON morbac.delegations FOR UPDATE
    USING (morbac.is_allowed(morbac.current_user_id(), org_id, 'update',
        morbac.get_config('system_view.delegations')));

CREATE POLICY delegations_delete ON morbac.delegations FOR DELETE
    USING (morbac.is_allowed(morbac.current_user_id(), org_id, 'delete',
        morbac.get_config('system_view.delegations')));

-- morbac.user_rules
ALTER TABLE morbac.user_rules ENABLE ROW LEVEL SECURITY;

CREATE POLICY user_rules_select ON morbac.user_rules FOR SELECT
    USING (morbac.is_allowed(morbac.current_user_id(), org_id, 'read',
        morbac.get_config('system_view.user_rules')));

CREATE POLICY user_rules_insert ON morbac.user_rules FOR INSERT
    WITH CHECK (morbac.is_allowed(morbac.current_user_id(), org_id, 'create',
        morbac.get_config('system_view.user_rules')));

CREATE POLICY user_rules_update ON morbac.user_rules FOR UPDATE
    USING (morbac.is_allowed(morbac.current_user_id(), org_id, 'update',
        morbac.get_config('system_view.user_rules')));

CREATE POLICY user_rules_delete ON morbac.user_rules FOR DELETE
    USING (morbac.is_allowed(morbac.current_user_id(), org_id, 'delete',
        morbac.get_config('system_view.user_rules')));

-- morbac.system_principals (no org_id - SELECT only; INSERT/UPDATE/DELETE reserved for DB owner)
ALTER TABLE morbac.system_principals ENABLE ROW LEVEL SECURITY;

CREATE POLICY system_principals_select ON morbac.system_principals FOR SELECT
    USING (morbac.is_allowed(morbac.current_user_id(), morbac.current_org_id(), 'read',
        morbac.get_config('system_view.system_principals')));

-- morbac.global_rules (no org_id - use current session org for write checks)
ALTER TABLE morbac.global_rules ENABLE ROW LEVEL SECURITY;

CREATE POLICY global_rules_select ON morbac.global_rules FOR SELECT
    USING (morbac.is_allowed(morbac.current_user_id(), morbac.current_org_id(), 'read',
        morbac.get_config('system_view.global_rules')));

CREATE POLICY global_rules_insert ON morbac.global_rules FOR INSERT
    WITH CHECK (morbac.is_allowed(morbac.current_user_id(), morbac.current_org_id(), 'create',
        morbac.get_config('system_view.global_rules')));

CREATE POLICY global_rules_update ON morbac.global_rules FOR UPDATE
    USING (morbac.is_allowed(morbac.current_user_id(), morbac.current_org_id(), 'update',
        morbac.get_config('system_view.global_rules')));

CREATE POLICY global_rules_delete ON morbac.global_rules FOR DELETE
    USING (morbac.is_allowed(morbac.current_user_id(), morbac.current_org_id(), 'delete',
        morbac.get_config('system_view.global_rules')));

-- morbac.cross_org_rules
ALTER TABLE morbac.cross_org_rules ENABLE ROW LEVEL SECURITY;

CREATE POLICY cross_org_rules_select ON morbac.cross_org_rules FOR SELECT
    USING (morbac.is_allowed(morbac.current_user_id(), source_org_id, 'read',
        morbac.get_config('system_view.cross_org_rules')));

CREATE POLICY cross_org_rules_insert ON morbac.cross_org_rules FOR INSERT
    WITH CHECK (morbac.is_allowed(morbac.current_user_id(), source_org_id, 'create',
        morbac.get_config('system_view.cross_org_rules')));

CREATE POLICY cross_org_rules_update ON morbac.cross_org_rules FOR UPDATE
    USING (morbac.is_allowed(morbac.current_user_id(), source_org_id, 'update',
        morbac.get_config('system_view.cross_org_rules')));

CREATE POLICY cross_org_rules_delete ON morbac.cross_org_rules FOR DELETE
    USING (morbac.is_allowed(morbac.current_user_id(), source_org_id, 'delete',
        morbac.get_config('system_view.cross_org_rules')));

-- Multi-org resource pattern (guidance):
--
-- For resources that belong to multiple organizations:
--
--   CREATE TABLE app.documents (id UUID PRIMARY KEY, content TEXT, ...);
--
--   CREATE TABLE app.document_orgs (
--       document_id UUID REFERENCES app.documents(id),
--       org_id UUID REFERENCES morbac.orgs(id),
--       PRIMARY KEY (document_id, org_id)
--   );
--
--   ALTER TABLE app.documents ENABLE ROW LEVEL SECURITY;
--
--   CREATE POLICY document_select ON app.documents FOR SELECT
--   USING (
--       EXISTS (
--           SELECT 1 FROM app.document_orgs do
--           WHERE do.document_id = app.documents.id
--             AND do.org_id = morbac.current_org_id()
--       )
--       AND morbac.rls_check('read', 'documents')
--   );
--
-- This allows a resource to be visible in multiple organizations
-- while enforcing OrBAC policy within each organization context.

-- Grant usage on schema to public (adjust based on your security requirements)
-- GRANT USAGE ON SCHEMA morbac TO public;
-- GRANT SELECT ON ALL TABLES IN SCHEMA morbac TO public;
-- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA morbac TO public;


-- Record the installed schema version (readable via
-- morbac.get_config('schema_version'); upgrade scripts bump it).
INSERT INTO morbac.config (key, value, description)
VALUES ('schema_version', '1.0.0', 'Installed pgmorbac schema version')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = CURRENT_TIMESTAMP;
