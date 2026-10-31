import type { IAssertionReplayRepository } from '../../interfaces/m2m/assertion-replay.repository.js';
import type { IM2mTokenService } from '../../interfaces/m2m/m2m-token.service.js';
import { CommandError } from '../../utils/errors/command.error.js';

type Options = {
  clientId?: string;
  clientPublicKeyConfigured: boolean;
  assertionReplays: IAssertionReplayRepository;
  tokens: IM2mTokenService;
  accessTtl: number;
  allowedScopes: string[];
};

export class IssueServiceTokenCommand {
  constructor(private readonly options: Options) {}

  async execute(assertion: string, scope: string) {
    const clientId = this.options.clientId;
    if (!clientId || !this.options.clientPublicKeyConfigured)
      throw new CommandError(503, 'm2m_not_configured');
    let payload;
    try {
      payload = await this.options.tokens.verifyClientAssertion(assertion);
    } catch {
      throw new CommandError(401, 'invalid_client_assertion');
    }
    const now = Math.floor(Date.now() / 1000);
    if (
      payload.sub !== clientId ||
      payload.jti.length > 128 ||
      payload.iat > now + 60 ||
      payload.exp - payload.iat > 300 ||
      payload.exp > now + 300
    ) {
      throw new CommandError(401, 'invalid_client_assertion');
    }
    if (!(await this.options.assertionReplays.consume(payload.jti, 300)))
      throw new CommandError(401, 'invalid_client_assertion');
    const scopes = scope.split(' ').filter(Boolean);
    if (
      !scopes.length ||
      scopes.some((item) => !this.options.allowedScopes.includes(item))
    )
      throw new CommandError(403, 'invalid_scope');
    const accessToken = await this.options.tokens.issueServiceToken(
      clientId,
      scopes
    );
    return {
      accessToken,
      expiresIn: this.options.accessTtl,
      tokenType: 'Bearer',
    };
  }
}

export function createM2mService(options: Options) {
  return { issueToken: new IssueServiceTokenCommand(options) };
}
