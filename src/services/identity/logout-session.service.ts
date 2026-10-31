import type { IdentityDependencies } from '../../interfaces/identity/identity.dependencies.js';

export class LogoutSessionCommand {
  constructor(
    private readonly options: Pick<IdentityDependencies, 'revoker' | 'tokens'>
  ) {}

  async execute(sessionId?: string, refreshToken?: string) {
    if (!sessionId && refreshToken) {
      try {
        sessionId = (await this.options.tokens.verifyRefreshToken(refreshToken))
          .sid;
      } catch {
        return;
      }
    }
    if (sessionId) await this.options.revoker.revoke(sessionId);
  }
}
