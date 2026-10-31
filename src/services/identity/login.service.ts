import { randomUUID } from 'node:crypto';
import type { IdentityDependencies } from '../../interfaces/identity/identity.dependencies.js';
import { CommandError } from '../../utils/errors/command.error.js';
import { digest, newRefreshId } from './refresh-credential.js';

export class LoginCommand {
  constructor(private readonly options: IdentityDependencies) {}

  async execute(emailInput: string, password: string, audience: string) {
    if (!this.options.allowedAccessAudiences.includes(audience))
      throw new CommandError(400, 'invalid_audience');
    const user = await this.options.users.byEmail(
      emailInput.trim().toLowerCase()
    );
    const valid = await this.options.passwords.verify(
      user?.passwordHash ?? this.options.dummyPasswordHash,
      password
    );
    if (!user || !user.active || !valid)
      throw new CommandError(401, 'invalid_credentials');

    const now = Date.now();
    const id = randomUUID();
    const jti = newRefreshId();
    const absoluteExpiresAt = new Date(now + this.options.sessionMaxTtl * 1000);
    const expiresAt = new Date(
      Math.min(
        now + this.options.refreshTtl * 1000,
        absoluteExpiresAt.getTime()
      )
    );
    const [access, refreshToken] = await Promise.all([
      this.options.tokens.issueAccessToken({
        sub: user.id,
        sid: id,
        roles: user.roles,
        audience,
        sessionExpiresAt: expiresAt,
      }),
      this.options.tokens.issueRefreshToken({
        sub: user.id,
        sid: id,
        generation: 0,
        jti,
        absoluteExpiresAt: Math.floor(absoluteExpiresAt.getTime() / 1000),
        expiresAt,
      }),
    ]);

    await this.options.sessions.create({
      id,
      userId: user.id,
      refreshHash: digest(jti),
      createdAt: new Date(now),
      expiresAt,
      absoluteExpiresAt,
      generation: 0,
    });
    await this.options.sessionEvents.activate({
      sid: id,
      sub: user.id,
      roles: user.roles,
      sessionExpiresAt: expiresAt.getTime(),
      tokenDigest: access.digest,
      tokenExpiresAt: access.expiresAt,
    });
    return { accessToken: access.token, refreshToken };
  }
}
