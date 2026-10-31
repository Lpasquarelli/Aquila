export type AccessTokenPrincipal = {
  sub: string;
  sid: string;
  roles: string[];
  audience?: string;
  sessionExpiresAt?: Date;
};
export type IssuedAccessToken = {
  token: string;
  digest: string;
  expiresAt: number;
};
export type RefreshTokenClaims = {
  sub: string;
  sid: string;
  generation: number;
  jti: string;
  absoluteExpiresAt: number;
};

export interface ITokenService {
  issueAccessToken(input: AccessTokenPrincipal): Promise<IssuedAccessToken>;
  issueRefreshToken(
    input: RefreshTokenClaims & { expiresAt: Date }
  ): Promise<string>;
  verifyAccessToken(
    raw: string,
    audiences?: string[]
  ): Promise<AccessTokenPrincipal>;
  verifyRefreshToken(raw: string): Promise<RefreshTokenClaims>;
}
