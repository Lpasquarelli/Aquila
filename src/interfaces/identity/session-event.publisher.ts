export interface ISessionEventPublisher {
  activate(input: {
    sid: string;
    sub: string;
    roles: string[];
    sessionExpiresAt: number;
    tokenDigest: string;
    tokenExpiresAt: number;
  }): Promise<void>;
  publishAndWait(sessionId: string): Promise<void>;
}
