import type { FastifyInstance, FastifyReply } from 'fastify';
import type { Pool } from 'pg';
import { createOrgRoutes }      from './routes/orgs.js';
import { createRoleRoutes }     from './routes/roles.js';
import { createRuleRoutes }     from './routes/rules.js';
import { createUserRoutes }     from './routes/users.js';
import { createGlobalRoutes }   from './routes/globals.js';
import { createActivityRoutes } from './routes/activities.js';
import { createDelegationRoutes } from './routes/delegations.js';
import { createPermissionProfileRoutes } from './routes/permission-profiles.js';

export type CheckLimitFn = (
    reply: FastifyReply,
    limitName: string,
    countSql: string,
    params?: unknown[],
) => Promise<boolean>;

export interface OrgEvent {
    action: 'created' | 'updated' | 'deleted';
    org: { id: string; name?: string; parent_id?: string | null; metadata?: Record<string, unknown>; reparented?: boolean };
    actorId: string | null;
}

export type OrgEventSink = (event: OrgEvent) => void;

export interface RoleEvent {
    action: 'created' | 'updated' | 'deleted';
    role: { id: string; org_id?: string; name?: string; description?: string | null };
    actorId: string | null;
}

export type RoleEventSink = (event: RoleEvent) => void;

export interface MgmtPluginOptions {
    db: Pool;
    checkLimit?: CheckLimitFn;
    emitOrgEvent?: OrgEventSink;
    emitRoleEvent?: RoleEventSink;
}

export function createMgmtRoutes(opts: MgmtPluginOptions) {
    const { db, checkLimit, emitOrgEvent, emitRoleEvent } = opts;
    return async function mgmtRoutes(app: FastifyInstance) {
        await app.register(createOrgRoutes(db, checkLimit, emitOrgEvent));
        await app.register(createRoleRoutes(db, checkLimit, emitRoleEvent));
        await app.register(createPermissionProfileRoutes(db, checkLimit, emitRoleEvent));
        await app.register(createRuleRoutes(db));
        await app.register(createUserRoutes(db, checkLimit));
        await app.register(createGlobalRoutes(db));
        await app.register(createActivityRoutes(db));
        await app.register(createDelegationRoutes(db));
    };
}
