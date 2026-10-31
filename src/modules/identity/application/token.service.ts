export type AccessTokenPrincipal = { sub: string; sid: string; roles: string[] };
export type RefreshTokenClaims = {
  sub: string;
  sid: string;
  generation: number;
  jti: string;
  absoluteExpiresAt: number;
};

export interface ITokenService {
  issueAccessToken(input: AccessTokenPrincipal): Promise<string>;
  issueRefreshToken(input: RefreshTokenClaims & { expiresAt: Date }): Promise<string>;
  verifyAccessToken(raw: string): Promise<AccessTokenPrincipal>;
  verifyRefreshToken(raw: string): Promise<RefreshTokenClaims>;
}
