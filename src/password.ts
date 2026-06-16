import { randomBytes } from 'node:crypto';

// Unambiguous alphabet (no 0/O/1/l/I) so generated passwords are easy to read
// and copy. 20 chars over 54 symbols is ~115 bits of entropy.
const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';

export function generatePassword(length = 20): string {
    return Array.from(randomBytes(length)).map((b) => ALPHA[b % ALPHA.length]).join('');
}
