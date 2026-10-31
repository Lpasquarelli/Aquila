import { createHash, randomBytes } from 'node:crypto';

export const digest = (value: string) =>
  createHash('sha256').update(value).digest('hex');
export const newRefreshId = () => randomBytes(32).toString('base64url');
