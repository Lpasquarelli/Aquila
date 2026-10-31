import type {
  FastifyRateLimitStore,
  FastifyRateLimitStoreCtor,
} from '@fastify/rate-limit';
import type { RedisClient } from '../clients/redis-client.js';
import type { RedisCommandGate } from '../utils/redis-command-gate.js';

const incrementScript = `
local current = redis.call('INCR', KEYS[1])
local window = tonumber(ARGV[1])
local max = tonumber(ARGV[2])
local continueExceeding = ARGV[3] == 'true'
local exponentialBackoff = ARGV[4] == 'true'
if current == 1 or (continueExceeding and current > max) then
  redis.call('PEXPIRE', KEYS[1], window)
elseif exponentialBackoff and current > max then
  local exponent = current - max - 1
  window = math.min(window * (2 ^ exponent), 9007199254740991)
  redis.call('PEXPIRE', KEYS[1], window)
else
  window = redis.call('PTTL', KEYS[1])
end
return { current, window }
`;

/** Custom store keeps rate-limit Redis failures distinct from user authentication failures. */
export function createRedisRateLimitStore(
  redis: RedisClient,
  gate: RedisCommandGate
): FastifyRateLimitStoreCtor {
  return class AquilaRateLimitStore implements FastifyRateLimitStore {
    private prefix: string;
    private readonly continueExceeding: boolean;
    private readonly exponentialBackoff: boolean;

    constructor(options: {
      nameSpace?: string;
      continueExceeding?: boolean;
      exponentialBackoff?: boolean;
    }) {
      this.prefix = options.nameSpace ?? 'aquila-rate-limit:';
      this.continueExceeding = Boolean(options.continueExceeding);
      this.exponentialBackoff = Boolean(options.exponentialBackoff);
    }

    incr(
      key: string,
      callback: (
        error: Error | null,
        result?: { current: number; ttl: number }
      ) => void,
      timeWindow = 60_000,
      max = 100
    ) {
      void gate
        .execute(async () => {
          const result = (await redis.eval(
            incrementScript,
            1,
            `${this.prefix}${key}`,
            String(timeWindow),
            String(max),
            String(this.continueExceeding),
            String(this.exponentialBackoff)
          )) as [number | string, number | string];
          return { current: Number(result[0]), ttl: Number(result[1]) };
        })
        .then(
          (result) => callback(null, result),
          (error: Error) => callback(error)
        );
    }

    child(routeOptions: Parameters<FastifyRateLimitStore['child']>[0]) {
      const child = Object.create(this) as AquilaRateLimitStore;
      // The plugin supplies routeInfo at runtime, though its store type omits it.
      const routeInfo = (
        routeOptions as { routeInfo?: { method?: string; url?: string } }
      ).routeInfo;
      child.prefix = `${this.prefix}${routeInfo?.method}${routeInfo?.url}-`;
      return child;
    }
  };
}
