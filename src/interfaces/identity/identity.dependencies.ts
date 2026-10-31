import type { SessionRevokerService } from '../../services/identity/session-revoker.service.js';
import type { IPasswordHasher } from './password-hasher.service.js';
import type { ISessionEventPublisher } from './session-event.publisher.js';
import type { ISessionRepository } from './session.repository.js';
import type { ITokenService } from './token.service.js';
import type { IUserRepository } from './user.repository.js';

export type IdentityDependencies = {
  users: IUserRepository;
  sessions: ISessionRepository;
  tokens: ITokenService;
  passwords: IPasswordHasher;
  refreshTtl: number;
  sessionMaxTtl: number;
  dummyPasswordHash: string;
  revoker: SessionRevokerService;
  sessionEvents: ISessionEventPublisher;
  allowedAccessAudiences: string[];
};
