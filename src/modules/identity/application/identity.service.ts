import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { ISessionRepository } from './session.repository.js';
import type { ITokenService } from './token.service.js';
import type { IUserRepository } from './user.repository.js';
import type { IPasswordHasher } from './password.hasher.js';
import { CommandError } from '../../../shared/application/command-error.js';

type Options = {
  users: IUserRepository;
  sessions: ISessionRepository;
  tokens: ITokenService;
  passwords: IPasswordHasher;
  refreshTtl: number;
  sessionMaxTtl: number;
  dummyPasswordHash: string;
};

const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const newRefreshId = () => randomBytes(32).toString('base64url');
const invalidRefresh = () => new CommandError(401, 'invalid_refresh_token');

export class LoginCommand {
  constructor(private readonly options: Options) {}

  async execute(emailInput: string, password: string) {
    const user = await this.options.users.byEmail(emailInput.trim().toLowerCase());
    const valid = await this.options.passwords.verify(user?.passwordHash ?? this.options.dummyPasswordHash, password);
    if (!user || !user.active || !valid) throw new CommandError(401, 'invalid_credentials');

    const now = Date.now();
    const id = randomUUID();
    const jti = newRefreshId();
    const absoluteExpiresAt = new Date(now + this.options.sessionMaxTtl * 1000);
    const expiresAt = new Date(Math.min(now + this.options.refreshTtl * 1000, absoluteExpiresAt.getTime()));
    const [accessToken, refreshToken] = await Promise.all([
      this.options.tokens.issueAccessToken({ sub: user.id, sid: id, roles: user.roles }),
      this.options.tokens.issueRefreshToken({ sub: user.id, sid: id, generation: 0, jti, absoluteExpiresAt: Math.floor(absoluteExpiresAt.getTime() / 1000), expiresAt }),
    ]);

    await this.options.sessions.create({
      id, userId: user.id, refreshHash: digest(jti), createdAt: new Date(now), expiresAt, absoluteExpiresAt, generation: 0,
    });
    return { accessToken, refreshToken };
  }
}

export class RefreshSessionCommand {
  constructor(private readonly options: Options) {}

  async execute(raw: string) {
    let claims;
    try { claims = await this.options.tokens.verifyRefreshToken(raw); }
    catch { throw invalidRefresh(); }

    const session = await this.options.sessions.byId(claims.sid);
    if (
      !session || session.userId !== claims.sub || session.expiresAt <= new Date() ||
      session.absoluteExpiresAt <= new Date() || Math.floor(session.absoluteExpiresAt.getTime() / 1000) !== claims.absoluteExpiresAt
    ) throw invalidRefresh();

    const user = await this.options.users.byId(session.userId);
    if (!user?.active) {
      await this.options.sessions.revoke(session.id);
      throw invalidRefresh();
    }

    const nextJti = newRefreshId();
    const nextExpiry = new Date(Math.min(Date.now() + this.options.refreshTtl * 1000, session.absoluteExpiresAt.getTime()));
    const nextGeneration = claims.generation + 1;
    // Finish all fallible signing and SQL work before consuming the current credential.
    const [accessToken, refreshToken] = await Promise.all([
      this.options.tokens.issueAccessToken({ sub: user.id, sid: session.id, roles: user.roles }),
      this.options.tokens.issueRefreshToken({
        sub: user.id, sid: session.id, generation: nextGeneration, jti: nextJti,
        absoluteExpiresAt: claims.absoluteExpiresAt, expiresAt: nextExpiry,
      }),
    ]);

    const result = await this.options.sessions.rotate({
      id: session.id, userId: session.userId, generation: claims.generation,
      oldHash: digest(claims.jti), newHash: digest(nextJti), expiry: nextExpiry,
    });
    if (result === 'replayed') throw new CommandError(401, 'refresh_reuse_detected');
    if (result !== 'rotated') throw invalidRefresh();
    return { accessToken, refreshToken };
  }
}

export class LogoutSessionCommand {
  constructor(private readonly options: Pick<Options, 'sessions' | 'tokens'>) {}

  async execute(sessionId?: string, refreshToken?: string) {
    if (!sessionId && refreshToken) {
      try { sessionId = (await this.options.tokens.verifyRefreshToken(refreshToken)).sid; }
      catch { return; }
    }
    if (sessionId) await this.options.sessions.revoke(sessionId);
  }
}

export function createIdentityService(options: Options) {
  return {
    login: new LoginCommand(options),
    refresh: new RefreshSessionCommand(options),
    logout: new LogoutSessionCommand(options),
  };
}
