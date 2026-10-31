import { randomUUID } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import { CommandError } from '../../../shared/application/command-error.js';
import type { IAssertionReplayRepository } from './assertion-replay.repository.js';

type Options = {
  clientId?: string;
  clientPublicKey: Awaited<ReturnType<typeof import('jose').importSPKI>> | null;
  signingKey: Awaited<ReturnType<typeof import('jose').importPKCS8>>;
  assertionReplays: IAssertionReplayRepository;
  activeKeyId: string;
  issuer: string;
  audience: string;
  accessTtl: number;
  allowedScopes: string[];
};

export class IssueServiceTokenCommand {
  constructor(private options: Options) {}
  async execute(assertion: string, scope: string) {
    const clientId = this.options.clientId, clientKey = this.options.clientPublicKey;
    if (!clientId || !clientKey) throw new CommandError(503, 'm2m_not_configured');
    let payload;
    try {
      ({ payload } = await jwtVerify(assertion, clientKey, { issuer: clientId, audience: this.options.issuer, algorithms: ['EdDSA'], requiredClaims: ['sub', 'jti', 'iat', 'exp'] }));
    } catch { throw new CommandError(401, 'invalid_client_assertion'); }
    const now = Math.floor(Date.now() / 1000);
    if (payload.sub !== clientId || typeof payload.jti !== 'string' || payload.jti.length > 128 || typeof payload.iat !== 'number' || typeof payload.exp !== 'number' || payload.iat > now + 60 || payload.exp - payload.iat > 300 || payload.exp > now + 300) {
      throw new CommandError(401, 'invalid_client_assertion');
    }
    if (!(await this.options.assertionReplays.consume(payload.jti, 300))) throw new CommandError(401, 'invalid_client_assertion');
    const scopes = scope.split(' ').filter(Boolean);
    if (!scopes.length || scopes.some((item) => !this.options.allowedScopes.includes(item))) throw new CommandError(403, 'invalid_scope');
    const accessToken = await new SignJWT({ client_id: clientId, scope: scopes.join(' '), token_use: 'service' })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: this.options.activeKeyId })
      .setIssuer(this.options.issuer).setAudience(this.options.audience).setSubject(clientId)
      .setJti(randomUUID()).setIssuedAt().setExpirationTime(`${this.options.accessTtl}s`).sign(this.options.signingKey);
    return { accessToken, expiresIn: this.options.accessTtl, tokenType: 'Bearer' };
  }
}

export function createM2mService(options: Options) {
  return { issueToken: new IssueServiceTokenCommand(options) };
}
