import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import type { CheckLimitFn } from '../plugin.js';
import { createUserCrudRoutes } from './user-crud.js';
import { createUserRoleRoutes } from './user-roles.js';
import { createUserKeyRoutes } from './user-keys.js';
import { createUserOrgFilterRoutes } from './user-org-filter.js';

export function createUserRoutes(db: Pool, checkLimit?: CheckLimitFn) {
    return async function userRoutes(app: FastifyInstance) {
        await app.register(createUserCrudRoutes(db, checkLimit));
        await app.register(createUserRoleRoutes(db));
        await app.register(createUserKeyRoutes(db));
        await app.register(createUserOrgFilterRoutes(db));
    };
}
