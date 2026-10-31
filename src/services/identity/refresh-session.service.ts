import type { IdentityDependencies } from '../../interfaces/identity/identity.dependencies.js';
import { CommandError } from '../../utils/errors/command.error.js';
import { digest, newRefreshId } from './refresh-credential.js';

const invalidRefresh = () => new CommandError(401, 'invalid_refresh_token');

export class RefreshSessionCommand {
  constructor(private readonly options: IdentityDependencies) {}

  async execute(raw: string, audience: string) {
    if (!this.options.allowedAccessAudiences.includes(audience))
      throw new CommandError(400, 'invalid_audience');
    let claims;
    try {
      claims = await this.options.tokens.verifyRefreshToken(raw);
    } catch {
      throw invalidRefresh();
    }

    const session = await this.options.sessions.byId(claims.sid);
    if (
      !session ||
      session.userId !== claims.sub ||
      session.expiresAt <= new Date() ||
      session.absoluteExpiresAt <= new Date() ||
      Math.floor(session.absoluteExpiresAt.getTime() / 1000) !==
        claims.absoluteExpiresAt
    )
      throw invalidRefresh();

    const user = await this.options.users.byId(session.userId);
    if (!user?.active) {
      await this.options.revoker.revoke(session.id);
      throw invalidRefresh();
    }

    const nextJti = newRefreshId();
    const nextExpiry = new Date(
      Math.min(
        Date.now() + this.options.refreshTtl * 1000,
        session.absoluteExpiresAt.getTime()
      )
    );
    const nextGeneration = claims.generation + 1;
    // Finish all fallible signing and SQL work before consuming the current credential.
    const [access, refreshToken] = await Promise.all([
      this.options.tokens.issueAccessToken({
        sub: user.id,
        sid: session.id,
        roles: user.roles,
        audience,
        sessionExpiresAt: nextExpiry,
      }),
      this.options.tokens.issueRefreshToken({
        sub: user.id,
        sid: session.id,
        generation: nextGeneration,
        jti: nextJti,
        absoluteExpiresAt: claims.absoluteExpiresAt,
        expiresAt: nextExpiry,
      }),
    ]);

    const result = await this.options.sessions.rotate({
      id: session.id,
      userId: session.userId,
      generation: claims.generation,
      oldHash: digest(claims.jti),
      newHash: digest(nextJti),
      expiry: nextExpiry,
    });
    if (result === 'replayed') {
      await this.options.revoker.revoke(session.id);
      throw new CommandError(401, 'refresh_reuse_detected');
    }
    if (result !== 'rotated') throw invalidRefresh();
    await this.options.sessionEvents.activate({
      sid: session.id,
      sub: user.id,
      roles: user.roles,
      sessionExpiresAt: nextExpiry.getTime(),
      tokenDigest: access.digest,
      tokenExpiresAt: access.expiresAt,
    });
    return { accessToken: access.token, refreshToken };
  }
}
