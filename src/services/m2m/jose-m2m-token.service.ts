import type { JWTVerifyGetKey } from 'jose';
import { SignJWT, jwtVerify } from 'jose';
import { randomUUID } from 'node:crypto';
import type {
  ClientAssertionClaims,
  IM2mTokenService,
  ServicePrincipal,
} from '../../interfaces/m2m/m2m-token.service.js';
import { InvalidTokenError } from '../../utils/errors/dependency-unavailable.error.js';

type SigningKey = Awaited<ReturnType<typeof import('jose').importPKCS8>>;
type VerificationKey = Awaited<ReturnType<typeof import('jose').importSPKI>>;

export class JoseM2mTokenService implements IM2mTokenService {
  constructor(
    private readonly options: {
      clientId?: string;
      clientPublicKey: VerificationKey | null;
      signingKey: SigningKey | null;
      resolvePublicKey: JWTVerifyGetKey;
      activeKeyId: string;
      issuer: string;
      audience: string;
      accessTtl: number;
    }
  ) {}

  async verifyClientAssertion(raw: string): Promise<ClientAssertionClaims> {
    if (!this.options.clientId || !this.options.clientPublicKey)
      throw new InvalidTokenError();
    try {
      const { payload } = await jwtVerify(raw, this.options.clientPublicKey, {
        issuer: this.options.clientId,
        audience: this.options.issuer,
        algorithms: ['EdDSA'],
        requiredClaims: ['sub', 'jti', 'iat', 'exp'],
      });
      if (
        typeof payload.sub !== 'string' ||
        typeof payload.jti !== 'string' ||
        typeof payload.iat !== 'number' ||
        typeof payload.exp !== 'number'
      )
        throw new Error('Invalid assertion claims');
      return {
        sub: payload.sub,
        jti: payload.jti,
        iat: payload.iat,
        exp: payload.exp,
      };
    } catch {
      throw new InvalidTokenError();
    }
  }

  async issueServiceToken(clientId: string, scopes: string[]): Promise<string> {
    if (!this.options.signingKey)
      throw new Error('This API role cannot sign service tokens');
    return new SignJWT({
      client_id: clientId,
      scope: scopes.join(' '),
      token_use: 'service',
    })
      .setProtectedHeader({
        alg: 'EdDSA',
        typ: 'JWT',
        kid: this.options.activeKeyId,
      })
      .setIssuer(this.options.issuer)
      .setAudience(this.options.audience)
      .setSubject(clientId)
      .setJti(randomUUID())
      .setIssuedAt()
      .setExpirationTime(`${this.options.accessTtl}s`)
      .sign(this.options.signingKey);
  }

  async verifyServiceToken(raw: string): Promise<ServicePrincipal> {
    try {
      const { payload, protectedHeader } = await jwtVerify(
        raw,
        this.options.resolvePublicKey,
        {
          issuer: this.options.issuer,
          audience: this.options.audience,
          algorithms: ['EdDSA'],
          requiredClaims: ['sub', 'jti', 'exp'],
        }
      );
      if (
        protectedHeader.typ !== 'JWT' ||
        payload.token_use !== 'service' ||
        typeof payload.client_id !== 'string' ||
        payload.sub !== payload.client_id ||
        typeof payload.scope !== 'string'
      )
        throw new Error('Invalid service token claims');
      return {
        clientId: payload.client_id,
        scopes: payload.scope.split(' ').filter(Boolean),
      };
    } catch {
      throw new InvalidTokenError();
    }
  }
}
