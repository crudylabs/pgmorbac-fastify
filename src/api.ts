export interface Org {
    id: string;
    name: string;
    parent_id: string | null;
    metadata: Record<string, unknown>;
    /** Names from the nearest visible ancestor down to this org. Server-computed. */
    path?: string[];
}

export interface Role {
    id: string | null;
    name: string;
    description: string | null;
    source: string;
}

export interface RoleDetail {
    id: string;
    org_id: string;
    org_name: string;
    name: string;
    description: string | null;
    profile_module_id?: string | null;
    profile_key?: string | null;
    profile_synced?: boolean | null;
}

export interface PermissionProfileRule {
    activity: string;
    view: string;
    modality: 'permission' | 'prohibition';
    scope: string;
}

export interface PermissionProfile {
    module_id: string;
    key: string;
    content_hash: string;
    rules: PermissionProfileRule[];
}

export interface Activity {
    name: string;
    description: string | null;
}

export interface View {
    name: string;
    description: string | null;
    /** Rows in this view carry no org, so grant it with an unattributed (or all)
     *  scope rule, a user rule with no org, or a global rule. A tree-scoped rule
     *  could never match. */
    no_org?: boolean;
}

export interface Rule {
    id: string;
    role_id: string;
    org_id: string;
    org_name: string;
    role_name: string;
    activity: string;
    view: string;
    modality: 'permission' | 'prohibition';
    priority: number | null;
    scope: string;
    valid_from: string | null;
    valid_until: string | null;
    is_active: boolean;
}

export interface CrossOrgRule {
    id: string;
    source_org_id: string;
    source_role_id: string;
    target_org_id: string;
    source_org_name: string;
    source_role_name: string;
    target_org_name: string;
    activity: string;
    view: string;
    modality: 'permission' | 'prohibition';
    priority: number | null;
}

export interface UserRule {
    id: string;
    user_id: string;
    /** null = unattributed: the rule targets objects with no org. */
    org_id: string | null;
    user_name: string;
    user_email: string | null;
    org_name: string | null;
    activity: string;
    view: string;
    modality: 'permission' | 'prohibition';
    priority: number | null;
}

export interface GlobalRule {
    id: string;
    user_id: string | null;
    user_name: string | null;
    user_email: string | null;
    activity: string | null;
    view: string | null;
    modality: 'permission' | 'prohibition';
    priority: number | null;
    is_system_principal: boolean;
    is_system_managed: boolean;
}

export interface RoleHierarchy {
    senior_role_id: string;
    senior_name: string;
    junior_role_id: string;
    junior_name: string;
    org_id: string;
    org_name: string;
}

export interface UserDetail {
    id: string;
    email: string;
    name: string;
    account_type: 'user' | 'system' | 'service';
    is_active: boolean;
    needs_placement?: boolean;
    created_at: string;
    roles: { role_id: string; role_name: string; org_id: string; org_name: string }[];
    // Present only on the create/reset response for 'user' accounts: the one-time
    // generated password the account must change on first login.
    generated_password?: string;
}

export interface ServiceAccountKey {
    id: string;
    name: string;
    description: string | null;
    key_prefix: string;
    readonly: boolean;
    permission_scope?: 'inherit' | Array<{ activity: string; view: string }>;
    expires_at: string | null;
    last_used_at: string | null;
    created_at: string;
    key?: string;
}

export interface RuleUser {
    id: string;
    user_name: string;
    email: string | null;
    account_type: 'user' | 'system' | 'service';
    org_id: string;
    org_name: string;
    role_id: string | null;
    role_name: string | null;
    source: 'role' | 'direct';
}

export interface EffectivePermission {
    activity: string | null;
    view: string | null;
    modality: 'permission' | 'prohibition';
    scope: string | null;
    org_id: string | null;
    org_name: string | null;
    role_id: string | null;
    role_name: string | null;
    source: 'role' | 'direct' | 'global';
}

export interface Delegation {
    id: string;
    delegator_id: string;
    delegatee_id: string;
    delegator_name: string | null;
    delegator_email: string | null;
    delegatee_name: string | null;
    delegatee_email: string | null;
    role_id: string;
    role_name: string;
    org_id: string;
    org_name: string;
    valid_from: string;
    valid_until: string;
    revoked: boolean;
    created_at: string;
}

export type ActivityViewBinding = { activity: string; view: string };

export interface MorbacApi {
    checkPermission(token: string, orgId: string, activity: string, view: string): Promise<boolean>;
    clearPermissionCache(): void;
    getOrgs(token: string, orgIds: string[]): Promise<Org[]>;
    createOrg(token: string, orgIds: string[], data: { name: string; parent_id?: string }): Promise<Org>;
    updateOrg(token: string, orgIds: string[], id: string, data: { name?: string; parent_id?: string | null }): Promise<Org>;
    deleteOrg(token: string, orgIds: string[], id: string): Promise<null>;
    getRoles(token: string, orgIds: string[]): Promise<RoleDetail[]>;
    createRole(token: string, orgIds: string[], data: { org_id: string; name: string; description?: string }): Promise<RoleDetail>;
    updateRole(token: string, orgIds: string[], id: string, data: { name?: string; description?: string }): Promise<RoleDetail>;
    deleteRole(token: string, orgIds: string[], id: string): Promise<null>;
    getPermissionProfiles(token: string, orgIds: string[], moduleId?: string): Promise<PermissionProfile[]>;
    createRoleFromProfile(token: string, orgIds: string[], data: { org_id: string; name: string; description?: string; sync?: boolean; profile: { module_id: string; key: string } }): Promise<RoleDetail>;
    attachRoleProfile(token: string, orgIds: string[], roleId: string, data: { profile: { module_id: string; key: string }; sync?: boolean }): Promise<{ role_id: string; module_id: string; profile_key: string; synced: boolean; applied_hash: string }>;
    detachRoleProfile(token: string, orgIds: string[], roleId: string): Promise<null>;
    getRoleHierarchy(token: string, orgIds: string[]): Promise<RoleHierarchy[]>;
    addRoleHierarchy(token: string, orgIds: string[], data: { senior_role_id: string; junior_role_id: string }): Promise<unknown>;
    removeRoleHierarchy(token: string, orgIds: string[], data: { senior_role_id: string; junior_role_id: string }): Promise<unknown>;
    getActivities(token: string, orgIds: string[]): Promise<Activity[]>;
    getViews(token: string, orgIds: string[]): Promise<View[]>;
    getActivityViewBindings(token: string, orgIds: string[]): Promise<ActivityViewBinding[]>;
    getRules(token: string, orgIds: string[]): Promise<Rule[]>;
    createRule(token: string, orgIds: string[], data: { org_id: string; role_id: string; activity: string; view: string; modality: 'permission' | 'prohibition'; scope?: string; priority?: number }): Promise<Rule>;
    deleteRule(token: string, orgIds: string[], id: string): Promise<null>;
    getCrossOrgRules(token: string, orgIds: string[]): Promise<CrossOrgRule[]>;
    createCrossOrgRule(token: string, orgIds: string[], data: { source_org_id: string; source_role_id: string; target_org_id: string; activity: string; view: string; modality: 'permission' | 'prohibition'; priority?: number }): Promise<CrossOrgRule>;
    deleteCrossOrgRule(token: string, orgIds: string[], id: string): Promise<null>;
    getUserRules(token: string, orgIds: string[]): Promise<UserRule[]>;
    createUserRule(token: string, orgIds: string[], data: { user_id: string; org_id: string | null; activity: string; view: string; modality: 'permission' | 'prohibition'; priority?: number }): Promise<UserRule>;
    deleteUserRule(token: string, orgIds: string[], id: string): Promise<null>;
    getGlobalRules(token: string, orgIds: string[]): Promise<GlobalRule[]>;
    createGlobalRule(token: string, orgIds: string[], data: { user_id?: string | null; activity?: string | null; view?: string | null; modality: 'permission' | 'prohibition'; priority?: number }): Promise<GlobalRule>;
    deleteGlobalRule(token: string, orgIds: string[], id: string): Promise<null>;
    getUsers(token: string, orgIds: string[]): Promise<UserDetail[]>;
    createUser(token: string, orgIds: string[], data: { email: string; name: string; account_type?: 'user' | 'service'; placement?: { role_id: string; org_id: string } }): Promise<UserDetail>;
    updateUser(token: string, orgIds: string[], id: string, data: { name?: string; email?: string; is_active?: boolean; reset_password?: boolean }): Promise<UserDetail>;
    deleteUser(token: string, orgIds: string[], id: string): Promise<null>;
    getUserKeys(token: string, orgIds: string[], userId: string): Promise<ServiceAccountKey[]>;
    getUserPermissionOptions(token: string, orgIds: string[], userId: string): Promise<Array<{ activity: string; view: string }>>;
    createUserKey(token: string, orgIds: string[], userId: string, data: { name: string; description?: string; readonly?: boolean; expires_at?: string | null; permission_scope?: 'inherit' | Array<{ activity: string; view: string }> }): Promise<ServiceAccountKey>;
    deleteUserKey(token: string, orgIds: string[], userId: string, keyId: string): Promise<null>;
    getUserOrgFilter(token: string, orgIds: string[], userId: string): Promise<{ org_filter: string[] }>;
    updateUserOrgFilter(token: string, orgIds: string[], userId: string, orgFilter: string[]): Promise<{ org_filter: string[] }>;
    assignRole(token: string, orgIds: string[], data: { user_id: string; role_id: string; org_id: string }): Promise<unknown>;
    removeRole(token: string, orgIds: string[], data: { user_id: string; role_id: string; org_id: string }): Promise<unknown>;
    getActivityUsers(token: string, orgIds: string[], name: string): Promise<RuleUser[]>;
    getViewUsers(token: string, orgIds: string[], name: string): Promise<RuleUser[]>;
    getEffectivePermissions(token: string, orgIds: string[], userId: string): Promise<EffectivePermission[]>;
    getDelegations(token: string, orgIds: string[]): Promise<Delegation[]>;
    createDelegation(token: string, orgIds: string[], data: { delegator_id: string; delegatee_id: string; role_id: string; org_id: string; valid_from?: string; valid_until: string }): Promise<Delegation>;
    revokeDelegation(token: string, orgIds: string[], id: string): Promise<null>;
}

// apiUrl may be a function so a browser caller resolves the origin per request
// rather than when its module loads.
export function createMorbacApi(apiUrl: string | (() => string)): MorbacApi {
    const base = typeof apiUrl === 'function' ? apiUrl : () => apiUrl;
    async function api(method: string, path: string, token: string, orgIds: string[], body?: unknown): Promise<unknown> {
        const headers: Record<string, string> = {
            Authorization: `Bearer ${token}`,
        };
        if (orgIds.length === 1) {
            headers['X-Org-Id'] = orgIds[0];
        } else if (orgIds.length > 1) {
            headers['X-Org-Ids'] = orgIds.join(',');
        }
        if (body !== undefined) headers['Content-Type'] = 'application/json';
        const res = await fetch(`${base()}${path}`, {
            method,
            headers,
            credentials: 'include',
            body: body !== undefined ? JSON.stringify(body) : undefined,
        });
        if (res.status === 204) return null;
        const data = await res.json();
        if (!res.ok) {
            const d = data as { error?: string; message?: string; errorId?: string };
            const err = new Error(d.message || d.error || `Request failed (HTTP ${res.status})`) as
                Error & { status: number; code?: string; errorId?: string };
            err.status = res.status;
            err.code = d.error;
            err.errorId = d.errorId;
            throw err;
        }
        return data;
    }

    const permCache = new Map<string, { value: boolean; expires: number }>();
    const permInflight = new Map<string, Promise<boolean>>();
    const PERM_TTL_MS = 30_000;

    async function fetchPermission(token: string, orgId: string, activity: string, view: string): Promise<boolean> {
        const res = await fetch(`${base()}/me/permissions/check`, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json',
                'X-Org-Id': orgId,
            },
            credentials: 'include',
            body: JSON.stringify({ p_activity: activity, p_view: view }),
        });
        if (!res.ok) {
            const d = await res.json().catch(() => ({})) as { error?: string; message?: string; errorId?: string };
            const err = new Error(d.message || d.error || `Permission check failed (HTTP ${res.status})`) as
                Error & { status: number; code?: string; errorId?: string };
            err.status = res.status;
            err.code = d.error;
            err.errorId = d.errorId;
            throw err;
        }
        return res.json() as Promise<boolean>;
    }

    return {
        checkPermission: (token, orgId, activity, view) => {
            const key = `${token}\x00${orgId}\x00${activity}\x00${view}`;
            const cached = permCache.get(key);
            if (cached && cached.expires > Date.now()) return Promise.resolve(cached.value);
            const existing = permInflight.get(key);
            if (existing) return existing;
            const p = fetchPermission(token, orgId, activity, view).then((value) => {
                permCache.set(key, { value, expires: Date.now() + PERM_TTL_MS });
                return value;
            });
            permInflight.set(key, p);
            void p.finally(() => permInflight.delete(key)).catch(() => {});
            return p;
        },

        clearPermissionCache: () => {
            permCache.clear();
            permInflight.clear();
        },

        getOrgs:   (t, orgIds) => api('GET', '/orgs', t, orgIds) as Promise<Org[]>,
        createOrg: (t, orgIds, d) => api('POST', '/orgs', t, orgIds, d) as Promise<Org>,
        updateOrg: (t, orgIds, id, d) => api('PATCH', `/orgs/${id}`, t, orgIds, d) as Promise<Org>,
        deleteOrg: (t, orgIds, id) => api('DELETE', `/orgs/${id}`, t, orgIds) as Promise<null>,

        getRoles:   (t, orgIds) => api('GET', '/roles', t, orgIds) as Promise<RoleDetail[]>,
        createRole: (t, orgIds, d) => api('POST', '/roles', t, orgIds, d) as Promise<RoleDetail>,
        updateRole: (t, orgIds, id, d) => api('PATCH', `/roles/${id}`, t, orgIds, d) as Promise<RoleDetail>,
        deleteRole: (t, orgIds, id) => api('DELETE', `/roles/${id}`, t, orgIds) as Promise<null>,

        getPermissionProfiles: (t, orgIds, moduleId) =>
            api('GET', moduleId ? `/permission-profiles?module_id=${encodeURIComponent(moduleId)}` : '/permission-profiles', t, orgIds) as Promise<PermissionProfile[]>,
        createRoleFromProfile: (t, orgIds, d) => api('POST', '/roles/from-profile', t, orgIds, d) as Promise<RoleDetail>,
        attachRoleProfile: (t, orgIds, roleId, d) =>
            api('POST', `/roles/${roleId}/profile-sync`, t, orgIds, d) as Promise<{ role_id: string; module_id: string; profile_key: string; synced: boolean; applied_hash: string }>,
        detachRoleProfile: (t, orgIds, roleId) => api('DELETE', `/roles/${roleId}/profile-sync`, t, orgIds) as Promise<null>,

        getRoleHierarchy:    (t, orgIds) => api('GET', '/role-hierarchy', t, orgIds) as Promise<RoleHierarchy[]>,
        addRoleHierarchy:    (t, orgIds, d) => api('POST', '/role-hierarchy', t, orgIds, d),
        removeRoleHierarchy: (t, orgIds, d) => api('DELETE', '/role-hierarchy', t, orgIds, d),

        getActivities:           (t, orgIds) => api('GET', '/activities', t, orgIds) as Promise<Activity[]>,
        getViews:                (t, orgIds) => api('GET', '/views', t, orgIds) as Promise<View[]>,
        getActivityViewBindings: (t, orgIds) => api('GET', '/activity-view-bindings', t, orgIds) as Promise<ActivityViewBinding[]>,

        getRules:   (t, orgIds) => api('GET', '/rules', t, orgIds) as Promise<Rule[]>,
        createRule: (t, orgIds, d) => api('POST', '/rules', t, orgIds, d) as Promise<Rule>,
        deleteRule: (t, orgIds, id) => api('DELETE', `/rules/${id}`, t, orgIds) as Promise<null>,

        getCrossOrgRules:    (t, orgIds) => api('GET', '/cross-org-rules', t, orgIds) as Promise<CrossOrgRule[]>,
        createCrossOrgRule:  (t, orgIds, d) => api('POST', '/cross-org-rules', t, orgIds, d) as Promise<CrossOrgRule>,
        deleteCrossOrgRule:  (t, orgIds, id) => api('DELETE', `/cross-org-rules/${id}`, t, orgIds) as Promise<null>,

        getUserRules:    (t, orgIds) => api('GET', '/user-rules', t, orgIds) as Promise<UserRule[]>,
        createUserRule:  (t, orgIds, d) => api('POST', '/user-rules', t, orgIds, d) as Promise<UserRule>,
        deleteUserRule:  (t, orgIds, id) => api('DELETE', `/user-rules/${id}`, t, orgIds) as Promise<null>,

        getGlobalRules:    (t, orgIds) => api('GET', '/global-rules', t, orgIds) as Promise<GlobalRule[]>,
        createGlobalRule:  (t, orgIds, d) => api('POST', '/global-rules', t, orgIds, d) as Promise<GlobalRule>,
        deleteGlobalRule:  (t, orgIds, id) => api('DELETE', `/global-rules/${id}`, t, orgIds) as Promise<null>,

        getUsers:   (t, orgIds) => api('GET', '/users', t, orgIds) as Promise<UserDetail[]>,
        createUser: (t, orgIds, d) => api('POST', '/users', t, orgIds, d) as Promise<UserDetail>,
        updateUser: (t, orgIds, id, d) => api('PATCH', `/users/${id}`, t, orgIds, d) as Promise<UserDetail>,
        deleteUser: (t, orgIds, id) => api('DELETE', `/users/${id}`, t, orgIds) as Promise<null>,

        getUserKeys:   (t, orgIds, userId) => api('GET', `/users/${userId}/keys`, t, orgIds) as Promise<ServiceAccountKey[]>,
        getUserPermissionOptions: (t, orgIds, userId) => api('GET', `/users/${userId}/permission-options`, t, orgIds) as Promise<Array<{ activity: string; view: string }>>,
        createUserKey: (t, orgIds, userId, d) => api('POST', `/users/${userId}/keys`, t, orgIds, d) as Promise<ServiceAccountKey>,
        deleteUserKey: (t, orgIds, userId, keyId) => api('DELETE', `/users/${userId}/keys/${keyId}`, t, orgIds) as Promise<null>,

        getUserOrgFilter:    (t, orgIds, userId) => api('GET', `/users/${encodeURIComponent(userId)}/org-filter`, t, orgIds) as Promise<{ org_filter: string[] }>,
        updateUserOrgFilter: (t, orgIds, userId, orgFilter) => api('PATCH', `/users/${encodeURIComponent(userId)}/org-filter`, t, orgIds, { org_filter: orgFilter }) as Promise<{ org_filter: string[] }>,

        assignRole: (t, orgIds, d) => api('POST', `/users/${d.user_id}/roles`, t, orgIds, { role_id: d.role_id, org_id: d.org_id }),
        removeRole: (t, orgIds, d) => api('DELETE', `/users/${d.user_id}/roles`, t, orgIds, { role_id: d.role_id, org_id: d.org_id }),

        getActivityUsers:      (t, orgIds, name) => api('GET', `/activities/${encodeURIComponent(name)}/users`, t, orgIds) as Promise<RuleUser[]>,
        getViewUsers:          (t, orgIds, name) => api('GET', `/views/${encodeURIComponent(name)}/users`, t, orgIds) as Promise<RuleUser[]>,
        getEffectivePermissions: (t, orgIds, userId) => api('GET', `/users/${userId}/effective-permissions`, t, orgIds) as Promise<EffectivePermission[]>,

        getDelegations:   (t, orgIds) => api('GET', '/delegations', t, orgIds) as Promise<Delegation[]>,
        createDelegation: (t, orgIds, d) => api('POST', '/delegations', t, orgIds, d) as Promise<Delegation>,
        revokeDelegation: (t, orgIds, id) => api('DELETE', `/delegations/${id}`, t, orgIds) as Promise<null>,
    };
}
