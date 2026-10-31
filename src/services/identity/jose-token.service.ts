import type { JWTVerifyGetKey } from 'jose';
import { SignJWT, jwtVerify } from 'jose';
import { createHash, randomUUID } from 'node:crypto';
import type {
  AccessTokenPrincipal,
  ITokenService,
  RefreshTokenClaims,
} from '../../interfaces/identity/token.service.js';
import { InvalidTokenError } from '../../utils/errors/dependency-unavailable.error.js';

type SigningKey = Awaited<ReturnType<typeof import('jose').importPKCS8>>;

export class JoseTokenService implements ITokenService {
  constructor(
    private readonly options: {
      signingKey: SigningKey | null;
      resolvePublicKey: JWTVerifyGetKey;
      activeKeyId: string;
      issuer: string;
      audience: string;
      accessTtl: number;
      sessionEpoch: string;
    }
  ) {}

  async issueAccessToken(input: AccessTokenPrincipal) {
    const expiresAt = Math.floor(
      Math.min(
        Date.now() + this.options.accessTtl * 1000,
        input.sessionExpiresAt?.getTime() ?? Infinity
      ) / 1000
    );
    const token = await this.sign(
      {
        sid: input.sid,
        roles: input.roles,
        token_use: 'access',
        session_epoch: this.options.sessionEpoch,
      },
      input.sub,
      'JWT',
      input.audience
    )
      .setJti(randomUUID())
      .setExpirationTime(expiresAt)
      .sign(this.requireSigningKey());
    return {
      token,
      digest: createHash('sha256').update(token).digest('hex'),
      expiresAt: expiresAt * 1000,
    };
  }

  async issueRefreshToken(input: RefreshTokenClaims & { expiresAt: Date }) {
    return this.sign(
      {
        sid: input.sid,
        generation: input.generation,
        absolute_exp: input.absoluteExpiresAt,
        token_use: 'refresh',
      },
      input.sub,
      'aquila-refresh+jwt'
    )
      .setJti(input.jti)
      .setExpirationTime(Math.floor(input.expiresAt.getTime() / 1000))
      .sign(this.requireSigningKey());
  }

  async verifyAccessToken(
    raw: string,
    audiences = [this.options.audience]
  ): Promise<AccessTokenPrincipal> {
    try {
      const { payload, protectedHeader } = await jwtVerify(
        raw,
        this.options.resolvePublicKey,
        {
          issuer: this.options.issuer,
          audience: audiences,
          algorithms: ['EdDSA'],
          requiredClaims: ['sub', 'sid', 'jti', 'iat', 'exp'],
        }
      );
      if (
        protectedHeader.typ !== 'JWT' ||
        payload.token_use !== 'access' ||
        payload.session_epoch !== this.options.sessionEpoch ||
        typeof payload.sub !== 'string' ||
        typeof payload.sid !== 'string' ||
        !Array.isArray(payload.roles)
      )
        throw new Error('invalid access claims');
      return {
        sub: payload.sub,
        sid: payload.sid,
        roles: payload.roles.map(String),
      };
    } catch {
      throw new InvalidTokenError();
    }
  }

  async verifyRefreshToken(raw: string): Promise<RefreshTokenClaims> {
    try {
      const { payload, protectedHeader } = await jwtVerify(
        raw,
        this.options.resolvePublicKey,
        {
          issuer: this.options.issuer,
          audience: this.options.audience,
          algorithms: ['EdDSA'],
          requiredClaims: ['sub', 'sid', 'jti', 'iat', 'exp'],
        }
      );
      if (
        protectedHeader.typ !== 'aquila-refresh+jwt' ||
        payload.token_use !== 'refresh' ||
        typeof payload.sub !== 'string' ||
        typeof payload.sid !== 'string' ||
        typeof payload.jti !== 'string' ||
        payload.jti.length < 40 ||
        !Number.isSafeInteger(payload.generation) ||
        Number(payload.generation) < 0 ||
        !Number.isSafeInteger(payload.absolute_exp) ||
        Number(payload.absolute_exp) <= 0
      )
        throw new Error('invalid refresh claims');
      return {
        sub: payload.sub,
        sid: payload.sid,
        jti: payload.jti,
        generation: Number(payload.generation),
        absoluteExpiresAt: Number(payload.absolute_exp),
      };
    } catch {
      throw new InvalidTokenError();
    }
  }

  private sign(
    payload: Record<string, unknown>,
    subject: string,
    type: string,
    audience = this.options.audience
  ) {
    return new SignJWT(payload)
      .setProtectedHeader({
        alg: 'EdDSA',
        typ: type,
        kid: this.options.activeKeyId,
      })
      .setIssuer(this.options.issuer)
      .setAudience(audience)
      .setSubject(subject)
      .setIssuedAt();
  }

  private requireSigningKey() {
    if (!this.options.signingKey)
      throw new Error('This API role cannot sign tokens');
    return this.options.signingKey;
  }
}
