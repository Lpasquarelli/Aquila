import argon2 from 'argon2';
import { randomBytes } from 'node:crypto';
import sql from 'mssql';
import type { JWTVerifyGetKey } from 'jose';
import { SqlUserRepository } from '../modules/identity/infrastructure/sql-user.repository.js';
import { RedisSessionRepository } from '../modules/identity/infrastructure/redis-session.repository.js';
import { Argon2PasswordHasher } from '../modules/identity/infrastructure/argon2-password.hasher.js';
import { JoseTokenService } from '../modules/identity/infrastructure/jose-token.service.js';
import { createIdentityService } from '../modules/identity/application/identity.service.js';
import { RedisAssertionReplayRepository } from '../modules/m2m/infrastructure/redis-assertion-replay.repository.js';
import { createM2mService } from '../modules/m2m/application/m2m.service.js';
import { RedisCommandGate } from '../shared/infrastructure/redis-command-gate.js';
import { createRedisClient, type RedisClusterNode } from '../shared/infrastructure/redis-client.js';

export type ApiRole = 'all' | 'auth' | 'resource';
type SigningKey = Awaited<ReturnType<typeof import('jose').importPKCS8>>;

export type ContainerConfig = {
  role: ApiRole;
  redisUrl: string;
  rateLimitRedisUrl: string;
  redisClusterNodes?: RedisClusterNode[];
  rateLimitRedisClusterNodes?: RedisClusterNode[];
  sessionNamespace: string;
  sqlPoolMax: number;
  redisMaxInflight: number;
  sql?: { server: string; port: number; user: string; password: string; database: string; production: boolean };
  signingKey: SigningKey | null;
  resolvePublicKey: JWTVerifyGetKey;
  activeKeyId: string;
  issuer: string;
  audience: string;
  accessTtl: number;
  refreshTtl: number;
  sessionMaxTtl: number;
  passwordHashConcurrency: number;
  m2mClientId?: string;
  m2mClientPublicKey: Awaited<ReturnType<typeof import('jose').importSPKI>> | null;
  allowedM2mScopes: string[];
};

/** Composition root: resource replicas need Redis and public keys only; auth replicas also open SQL and signing dependencies. */
export async function createContainer(config: ContainerConfig) {
  const redis = createRedisClient(config.redisUrl, config.redisClusterNodes);
  const rateLimitRedis = createRedisClient(config.rateLimitRedisUrl, config.rateLimitRedisClusterNodes);
  let pool: sql.ConnectionPool | undefined;
  try {
    await Promise.all([redis.connect(), rateLimitRedis.connect()]);
    const gate = new RedisCommandGate(3, 1000, config.redisMaxInflight);
    const rateLimitGate = new RedisCommandGate(3, 1000, config.redisMaxInflight);
    const sessions = new RedisSessionRepository(redis, gate, config.sessionNamespace);
    const assertionReplays = new RedisAssertionReplayRepository(redis, gate);
    const tokens = new JoseTokenService({
      signingKey: config.signingKey, resolvePublicKey: config.resolvePublicKey, activeKeyId: config.activeKeyId,
      issuer: config.issuer, audience: config.audience, accessTtl: config.accessTtl,
    });

    const repositories: { users?: SqlUserRepository; sessions: RedisSessionRepository; assertionReplays: RedisAssertionReplayRepository } = {
      sessions, assertionReplays,
    };
    const services: {
      identity?: ReturnType<typeof createIdentityService>;
      m2m?: ReturnType<typeof createM2mService>;
    } = {};

    if (config.role !== 'resource') {
      if (!config.sql || !config.signingKey) throw new Error('Auth role requires SQL settings and a private signing key');
      pool = await sql.connect({
        server: config.sql.server, port: config.sql.port, user: config.sql.user,
        password: config.sql.password, database: config.sql.database,
        connectionTimeout: 1500, requestTimeout: 2000,
        options: { encrypt: true, trustServerCertificate: !config.sql.production },
        pool: { min: 0, max: config.sqlPoolMax, idleTimeoutMillis: 30000, acquireTimeoutMillis: 1000 },
      });
      const users = new SqlUserRepository(pool);
      repositories.users = users;
      services.identity = createIdentityService({
        users, sessions, tokens, passwords: new Argon2PasswordHasher(config.passwordHashConcurrency),
        refreshTtl: config.refreshTtl, sessionMaxTtl: config.sessionMaxTtl,
        dummyPasswordHash: await argon2.hash(randomBytes(32), { type: argon2.argon2id }),
      });
      services.m2m = createM2mService({
        clientId: config.m2mClientId, clientPublicKey: config.m2mClientPublicKey,
        signingKey: config.signingKey, assertionReplays, activeKeyId: config.activeKeyId,
        issuer: config.issuer, audience: config.audience, accessTtl: config.accessTtl, allowedScopes: config.allowedM2mScopes,
      });
    }

    return {
      role: config.role, redis, rateLimitRedis, redisGate: gate, rateLimitGate, pool, repositories, services, tokens,
      close: async () => {
        await Promise.allSettled([redis.quit(), rateLimitRedis.quit()]);
        await pool?.close();
      },
    };
  } catch (error) {
    await Promise.allSettled([redis.quit(), rateLimitRedis.quit()]);
    await pool?.close().catch(() => undefined);
    throw error;
  }
}
