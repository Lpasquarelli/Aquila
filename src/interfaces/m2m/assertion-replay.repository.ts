export interface IAssertionReplayRepository {
  consume(jti: string, ttlSeconds: number): Promise<boolean>;
}
