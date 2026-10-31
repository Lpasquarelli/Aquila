import type { RedisClient } from '../../clients/redis-client.js';
import type {
  ISessionRepository,
  RefreshRotationResult,
} from '../../interfaces/identity/session.repository.js';
import type { Session } from '../../models/identity.models.js';
import { DependencyUnavailableError } from '../../utils/errors/dependency-unavailable.error.js';
import type { RedisCommandGate } from '../../utils/redis-command-gate.js';

const createScript = `
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local expires = tonumber(ARGV[5])
local absolute = tonumber(ARGV[6])
if expires <= now or absolute <= now then return 0 end
redis.call('HSET', KEYS[1], 'userId', ARGV[1], 'refreshHash', ARGV[2], 'generation', ARGV[3], 'createdAt', ARGV[4], 'expiresAt', expires, 'absoluteExpiresAt', absolute)
redis.call('PEXPIREAT', KEYS[1], math.min(expires, absolute))
return 1
`;

const rotateScript = `
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local values = redis.call('HMGET', KEYS[1], 'userId', 'refreshHash', 'generation', 'expiresAt', 'absoluteExpiresAt', 'createdAt')
if not values[1] then return 0 end
if values[1] ~= ARGV[1] then return -1 end
local currentGeneration = tonumber(values[3])
local expires = tonumber(values[4])
local absolute = tonumber(values[5])
if expires <= now or absolute <= now then return 0 end
local presentedGeneration = tonumber(ARGV[2])
if presentedGeneration < currentGeneration then return 2 end
if presentedGeneration > currentGeneration then return -1 end
if values[2] ~= ARGV[3] then return -1 end
local nextExpiry = math.min(tonumber(ARGV[5]), absolute)
if nextExpiry <= now then return 0 end
redis.call('HSET', KEYS[1], 'refreshHash', ARGV[4], 'generation', currentGeneration + 1, 'expiresAt', nextExpiry)
redis.call('PEXPIREAT', KEYS[1], nextExpiry)
return 1
`;

const findScript = `
local values = redis.call('HMGET', KEYS[1], 'userId', 'refreshHash', 'generation', 'expiresAt', 'absoluteExpiresAt', 'createdAt')
if not values[1] then return {} end
return values
`;

const findUserScript = `return redis.call('HGET', KEYS[1], 'userId') or false`;

export class RedisSessionRepository implements ISessionRepository {
  private readonly prefix: string;

  constructor(
    private readonly redis: RedisClient,
    gate: RedisCommandGate,
    namespace: string
  ) {
    if (!/^[a-zA-Z0-9_-]{1,48}$/.test(namespace))
      throw new Error(
        'SESSION_NAMESPACE must contain 1-48 letters, digits, underscores, or hyphens'
      );
    this.prefix = `aquila:sessions:${namespace}:`;
    this.gate = gate;
  }
  private readonly gate: RedisCommandGate;

  async create(session: Session): Promise<void> {
    const result = Number(
      await this.gate.execute(() =>
        this.redis.eval(
          createScript,
          1,
          this.key(session.id),
          session.userId,
          session.refreshHash,
          String(session.generation),
          String(session.createdAt.getTime()),
          String(session.expiresAt.getTime()),
          String(session.absoluteExpiresAt.getTime())
        )
      )
    );
    if (result !== 1)
      throw new DependencyUnavailableError('Redis session creation');
  }

  async byId(id: string): Promise<Session | null> {
    const values = (await this.gate.execute(() =>
      this.redis.eval(findScript, 1, this.key(id))
    )) as Array<string | null>;
    if (!values?.[0]) return null;
    const [
      userId,
      refreshHash,
      generation,
      expiresAt,
      absoluteExpiresAt,
      createdAt,
    ] = values;
    if (
      !userId ||
      !refreshHash ||
      generation === null ||
      expiresAt === null ||
      absoluteExpiresAt === null ||
      createdAt === null
    )
      return null;
    return {
      id,
      userId,
      refreshHash,
      generation: Number(generation),
      expiresAt: new Date(Number(expiresAt)),
      absoluteExpiresAt: new Date(Number(absoluteExpiresAt)),
      createdAt: new Date(Number(createdAt)),
    };
  }

  async userIdById(id: string): Promise<string | null> {
    const value = await this.gate.execute(() =>
      this.redis.eval(findUserScript, 1, this.key(id))
    );
    return typeof value === 'string' ? value : null;
  }

  async rotate(input: {
    id: string;
    userId: string;
    generation: number;
    oldHash: string;
    newHash: string;
    expiry: Date;
  }): Promise<RefreshRotationResult> {
    const result = Number(
      await this.gate.execute(() =>
        this.redis.eval(
          rotateScript,
          1,
          this.key(input.id),
          input.userId,
          String(input.generation),
          input.oldHash,
          input.newHash,
          String(input.expiry.getTime())
        )
      )
    );
    if (result === 1) return 'rotated';
    if (result === 2) return 'replayed';
    if (result === 0) return 'missing';
    return 'invalid';
  }

  async revoke(id: string): Promise<void> {
    await this.gate.execute(() => this.redis.del(this.key(id)));
  }

  private key(id: string) {
    return `${this.prefix}{${id}}`;
  }
}
