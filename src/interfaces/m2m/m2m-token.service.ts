export type ClientAssertionClaims = {
  sub: string;
  jti: string;
  iat: number;
  exp: number;
};
export type ServicePrincipal = { clientId: string; scopes: string[] };

export interface IM2mTokenService {
  verifyClientAssertion(raw: string): Promise<ClientAssertionClaims>;
  issueServiceToken(clientId: string, scopes: string[]): Promise<string>;
  verifyServiceToken(raw: string): Promise<ServicePrincipal>;
}
