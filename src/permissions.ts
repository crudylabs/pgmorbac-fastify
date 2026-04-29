import type { FastifyRequest, FastifyReply } from 'fastify';
import type { Pool } from 'pg';

export const SYSTEM_ORG_ID = '00000000-0000-0000-0000-000000000000';

export function getUser(req: FastifyRequest): { id: string } | null {
    return ((req as unknown) as Record<string, unknown>).user as { id: string } | null ?? null;
}

export function getOrgScope(req: FastifyRequest, reply: FastifyReply, required = true): string[] | null {
    const single = req.headers['x-org-id'];
    const singleVal = Array.isArray(single) ? single[0] : (single ?? null);
    if (singleVal) return [singleVal];

    const multi = req.headers['x-org-ids'];
    const multiVal = Array.isArray(multi) ? multi[0] : (multi ?? null);
    if (multiVal) {
        const ids = multiVal.split(',').map((s) => s.trim()).filter(Boolean);
        if (ids.length > 0) return ids;
    }

    if (required) {
        reply.code(400).send({ error: 'X-Org-Id header is required' });
        return null;
    }
    return [];
}

export function orgScopeExpr(orgIds: string[], column: string, paramOffset = 0): { expr: string; params: string[] } {
    if (orgIds.length === 0) return { expr: '', params: [] };
    const parts = orgIds.map((_, i) =>
        `SELECT org_id FROM morbac.get_org_scope($${paramOffset + i + 1}::UUID, 'subtree')`,
    );
    return { expr: `${column} IN (${parts.join(' UNION ')})`, params: orgIds };
}

export function viewForType(type: 'user' | 'service'): string {
    return type === 'service' ? 'service_users' : 'users';
}

export async function getAccountType(
    db: Pool,
    id: string,
): Promise<'user' | 'system' | 'service' | null> {
    const { rows } = await db.query<{ account_type: 'user' | 'system' | 'service' }>(
        'SELECT account_type FROM app.users WHERE id = $1',
        [id],
    );
    return rows[0]?.account_type ?? null;
}

export async function hasPermission(
    db: Pool,
    req: FastifyRequest,
    reply: FastifyReply,
    orgId: string | null,
    activity: string,
    target: string,
): Promise<boolean> {
    const user = getUser(req);
    if (!user) {
        reply.code(401).send({ error: 'Authentication required' });
        return false;
    }
    const { rows } = await db.query<{ allowed: boolean }>(
        'SELECT morbac.is_allowed($1::UUID, $2::UUID, $3, $4) AS allowed',
        [user.id, orgId, activity, target],
    );
    if (!rows[0]?.allowed) {
        reply.code(403).send({ error: 'Insufficient permissions' });
        return false;
    }
    return true;
}
