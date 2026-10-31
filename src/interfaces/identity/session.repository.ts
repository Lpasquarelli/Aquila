import type { Session } from '../../models/identity.models.js';

export type RefreshRotationResult =
  'rotated' | 'replayed' | 'invalid' | 'missing';

/** Live session state is authoritative here. A miss must never be rehydrated from SQL. */
export interface ISessionRepository {
  create(session: Session): Promise<void>;
  byId(id: string): Promise<Session | null>;
  userIdById(id: string): Promise<string | null>;
  rotate(input: {
    id: string;
    userId: string;
    generation: number;
    oldHash: string;
    newHash: string;
    expiry: Date;
  }): Promise<RefreshRotationResult>;
  revoke(id: string): Promise<void>;
}
