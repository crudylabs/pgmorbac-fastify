import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { addPermissionHook, isAllowed, permittedOrgs } from '../dist/index.js';
import { hasPermission, canActOnUser, canGrantRule } from '../dist/permissions.js';

const A = '00000000-0000-4000-8000-00000000000a';
const B = '00000000-0000-4000-8000-00000000000b';

// morbac allows everything in `allowed` (null = the no-org perimeter).
function fakeDb(allowed, extra = {}) {
    return {
        async query(sql, params) {
            if (sql.includes('unnest')) return { rows: params[1].filter((o) => allowed.has(o)).map((o) => ({ o })) };
            if (sql.includes('morbac.is_allowed')) return { rows: [{ allowed: allowed.has(params[1]) }] };
            if (sql.includes('user_roles')) return { rows: (extra.memberships ?? []).map((org_id) => ({ org_id })) };
            if (sql.includes('get_org_scope')) return { rows: (extra.scope ?? []).map((org_id) => ({ org_id })) };
            throw new Error(`unexpected query ${sql}`);
        },
    };
}

let removers = [];
beforeEach(() => { removers.forEach((r) => r()); removers = []; });
const hook = (phase, fn) => removers.push(addPermissionHook(phase, fn));

test('without hooks the answer is morbac\'s', async () => {
    assert.equal(await isAllowed(fakeDb(new Set([A])), 'u', A, 'read', 'x'), true);
    assert.equal(await isAllowed(fakeDb(new Set()), 'u', A, 'read', 'x'), false);
});

test('a pre hook refuses without asking morbac', async () => {
    const db = fakeDb(new Set([A]));
    let asked = false;
    const query = db.query.bind(db);
    db.query = async (...a) => { asked = true; return query(...a); };
    hook('pre', (c) => c.orgId !== A);
    assert.equal(await isAllowed(db, 'u', A, 'read', 'x'), false);
    assert.equal(asked, false);
});

test('no hook can grant what morbac refused', async () => {
    hook('pre', () => true);
    hook('post', () => true);
    assert.equal(await isAllowed(fakeDb(new Set()), 'u', A, 'read', 'x'), false);
});

test('a post hook sees the answer and can refuse it', async () => {
    const seen = [];
    hook('post', (c, allowed) => { seen.push(allowed); return c.activity !== 'delete'; });
    assert.equal(await isAllowed(fakeDb(new Set([A])), 'u', A, 'delete', 'x'), false);
    assert.equal(await isAllowed(fakeDb(new Set([A])), 'u', A, 'read', 'x'), true);
    assert.deepEqual(seen, [true, true]);
});

test('a hook that is not exactly true refuses', async () => {
    hook('pre', () => undefined);
    assert.equal(await isAllowed(fakeDb(new Set([A])), 'u', A, 'read', 'x'), false);
});

test('a throwing hook fails the decision rather than allowing it', async () => {
    hook('pre', () => { throw new Error('boom'); });
    await assert.rejects(isAllowed(fakeDb(new Set([A])), 'u', A, 'read', 'x'), /boom/);
});

test('permittedOrgs drops the orgs a hook refuses', async () => {
    hook('pre', (c) => c.orgId !== B);
    assert.deepEqual(await permittedOrgs(fakeDb(new Set([A, B])), 'u', [A, B], 'read', 'x'), [A]);
});

test('hasPermission answers 403 when a hook refuses', async () => {
    hook('pre', () => false);
    let code;
    const reply = { code(c) { code = c; return this; }, send() { return this; } };
    assert.equal(await hasPermission(fakeDb(new Set([A])), { user: { id: 'u' } }, reply, A, 'read', 'x'), false);
    assert.equal(code, 403);
});

test('canActOnUser and canGrantRule go through the hooks', async () => {
    hook('pre', (c) => c.orgId !== B);
    assert.equal(await canActOnUser(fakeDb(new Set([B]), { memberships: [B] }), 'u', 't', 'update', 'users'), false);
    assert.equal(await canGrantRule(fakeDb(new Set([A, B]), { scope: [A, B] }), 'u', A, 'subtree', 'read', 'x'), false);
    assert.equal(await canGrantRule(fakeDb(new Set([A])), 'u', A, 'self', 'read', 'x'), true);
});
