import type { FastifyRequest } from 'fastify';
import type { Pool } from 'pg';

/** One permission decision: may this user perform (activity, view) in this org. */
export interface PermissionCheck {
    userId: string;
    /** The org acted in, or null for the no-org perimeter. */
    orgId: string | null;
    activity: string;
    view: string;
    /** The request behind the decision, when there is one. */
    req?: FastifyRequest;
}

/** Runs before morbac is asked. Returning false refuses without asking it. */
export type PrePermissionHook = (check: PermissionCheck, db: Pool) => boolean | Promise<boolean>;

/** Runs after morbac answered, with that answer. Returning false refuses. */
export type PostPermissionHook = (check: PermissionCheck, allowed: boolean, db: Pool) => boolean | Promise<boolean>;

const pre: PrePermissionHook[] = [];
const post: PostPermissionHook[] = [];

/**
 * Adds an application rule to every permission decision the helpers make. A
 * hook can only narrow: a decision is allowed when morbac allows it and every
 * hook agrees, so no hook can grant what morbac refused. A hook that throws
 * fails the decision with its error; nothing is swallowed into an allow.
 * Returns a function that removes the hook.
 */
export function addPermissionHook(phase: 'pre', hook: PrePermissionHook): () => void;
export function addPermissionHook(phase: 'post', hook: PostPermissionHook): () => void;
export function addPermissionHook(phase: 'pre' | 'post', hook: PrePermissionHook | PostPermissionHook): () => void {
    const list = (phase === 'pre' ? pre : post) as unknown[];
    list.push(hook);
    return () => {
        const i = list.indexOf(hook);
        if (i !== -1) list.splice(i, 1);
    };
}

export async function runPreHooks(check: PermissionCheck, db: Pool): Promise<boolean> {
    for (const hook of pre) {
        if (await hook(check, db) !== true) return false;
    }
    return true;
}

export async function runPostHooks(check: PermissionCheck, allowed: boolean, db: Pool): Promise<boolean> {
    let result = allowed;
    for (const hook of post) {
        if (await hook(check, allowed, db) !== true) result = false;
    }
    return result;
}
