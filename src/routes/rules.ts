import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import { createRoleRuleRoutes } from './rule-role.js';
import { createCrossOrgRuleRoutes } from './rule-cross-org.js';
import { createUserRuleRoutes } from './rule-user.js';

export function createRuleRoutes(db: Pool) {
    return async function ruleRoutes(app: FastifyInstance) {
        await app.register(createRoleRuleRoutes(db));
        await app.register(createCrossOrgRuleRoutes(db));
        await app.register(createUserRuleRoutes(db));
    };
}
