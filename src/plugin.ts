import type { FastifyInstance, FastifyReply } from 'fastify';
import type { Pool } from 'pg';
import { createOrgRoutes }      from './routes/orgs.js';
import { createRoleRoutes }     from './routes/roles.js';
import { createRuleRoutes }     from './routes/rules.js';
import { createUserRoutes }     from './routes/users.js';
import { createGlobalRoutes }   from './routes/globals.js';
import { createActivityRoutes } from './routes/activities.js';

export type CheckLimitFn = (
    reply: FastifyReply,
    limitName: string,
    countSql: string,
    params?: unknown[],
) => Promise<boolean>;

export interface MgmtPluginOptions {
    db: Pool;
    checkLimit?: CheckLimitFn;
}

export function createMgmtRoutes(opts: MgmtPluginOptions) {
    const { db, checkLimit } = opts;
    return async function mgmtRoutes(app: FastifyInstance) {
        await app.register(createOrgRoutes(db, checkLimit));
        await app.register(createRoleRoutes(db, checkLimit));
        await app.register(createRuleRoutes(db));
        await app.register(createUserRoutes(db, checkLimit));
        await app.register(createGlobalRoutes(db));
        await app.register(createActivityRoutes(db));
    };
}
