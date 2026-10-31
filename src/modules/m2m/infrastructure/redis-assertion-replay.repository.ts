import type { RedisCommandGate } from '../../../shared/infrastructure/redis-command-gate.js';
import type { RedisClient } from '../../../shared/infrastructure/redis-client.js';
import type { IAssertionReplayRepository } from '../application/assertion-replay.repository.js';

export class RedisAssertionReplayRepository implements IAssertionReplayRepository {
  constructor(private readonly redis: RedisClient, private readonly gate: RedisCommandGate) {}

  async consume(jti: string, ttlSeconds: number) {
    const result = await this.gate.execute(() => this.redis.set(`aquila:m2m:assertions:${jti}`, '1', 'EX', ttlSeconds, 'NX'));
    return result === 'OK';
  }
}
