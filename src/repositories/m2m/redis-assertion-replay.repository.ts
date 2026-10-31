import type { RedisClient } from '../../clients/redis-client.js';
import type { IAssertionReplayRepository } from '../../interfaces/m2m/assertion-replay.repository.js';
import type { RedisCommandGate } from '../../utils/redis-command-gate.js';

export class RedisAssertionReplayRepository implements IAssertionReplayRepository {
  constructor(
    private readonly redis: RedisClient,
    private readonly gate: RedisCommandGate
  ) {}

  async consume(jti: string, ttlSeconds: number) {
    const result = await this.gate.execute(() =>
      this.redis.set(
        `aquila:m2m:assertions:${jti}`,
        '1',
        'EX',
        ttlSeconds,
        'NX'
      )
    );
    return result === 'OK';
  }
}
