import type { JWTVerifyGetKey } from 'jose';
import {
  createRedisClient,
  type RedisClusterNode,
} from '../clients/redis-client.js';
import { RedisCommandGate } from '../utils/redis-command-gate.js';
import { createIdentityContainer } from './identity.container.js';
import { createM2mContainer } from './m2m.container.js';

export type ApiRole = 'all' | 'auth' | 'resource';
type SigningKey = Awaited<ReturnType<typeof import('jose').importPKCS8>>;
type VerificationKey = Awaited<ReturnType<typeof import('jose').importSPKI>>;

export type ContainerConfig = {
  role: ApiRole;
  redisUrl: string;
  rateLimitRedisUrl: string;
  redisClusterNodes?: RedisClusterNode[];
  rateLimitRedisClusterNodes?: RedisClusterNode[];
  sessionNamespace: string;
  sqlPoolMax: number;
  redisMaxInflight: number;
  sql?: {
    server: string;
    port: number;
    user: string;
    password: string;
    database: string;
    production: boolean;
  };
  signingKey: SigningKey | null;
  resolvePublicKey: JWTVerifyGetKey;
  activeKeyId: string;
  issuer: string;
  audience: string;
  accessTtl: number;
  allowedAccessAudiences: string[];
  natsUrl: string;
  revocationTimeoutMs: number;
  natsUser?: string;
  natsPassword?: string;
  natsTls: boolean;
  natsCaFile?: string;
  refreshTtl: number;
  sessionMaxTtl: number;
  passwordHashConcurrency: number;
  m2mClientId?: string;
  m2mClientPublicKey: VerificationKey | null;
  allowedM2mScopes: string[];
};

/** Process-level composition root. Feature containers own their adapters and services. */
export async function createContainer(config: ContainerConfig) {
  const redis = createRedisClient(config.redisUrl, config.redisClusterNodes);
  const rateLimitRedis = createRedisClient(
    config.rateLimitRedisUrl,
    config.rateLimitRedisClusterNodes
  );
  let identity: Awaited<ReturnType<typeof createIdentityContainer>> | undefined;
  try {
    await Promise.all([redis.connect(), rateLimitRedis.connect()]);
    const redisGate = new RedisCommandGate(3, 1000, config.redisMaxInflight);
    const rateLimitGate = new RedisCommandGate(
      3,
      1000,
      config.redisMaxInflight
    );
    const authEnabled = config.role !== 'resource';
    identity = await createIdentityContainer({
      authEnabled,
      redis,
      gate: redisGate,
      sessionNamespace: config.sessionNamespace,
      signingKey: config.signingKey,
      resolvePublicKey: config.resolvePublicKey,
      activeKeyId: config.activeKeyId,
      issuer: config.issuer,
      audience: config.audience,
      accessTtl: config.accessTtl,
      refreshTtl: config.refreshTtl,
      sessionMaxTtl: config.sessionMaxTtl,
      allowedAccessAudiences: config.allowedAccessAudiences,
      passwordHashConcurrency: config.passwordHashConcurrency,
      sqlPoolMax: config.sqlPoolMax,
      sql: config.sql,
      nats: {
        url: config.natsUrl,
        timeoutMs: config.revocationTimeoutMs,
        user: config.natsUser,
        password: config.natsPassword,
        tls: config.natsTls,
        caFile: config.natsCaFile,
      },
    });
    const m2m = createM2mContainer({
      authEnabled,
      redis,
      gate: redisGate,
      signingKey: config.signingKey,
      resolvePublicKey: config.resolvePublicKey,
      clientId: config.m2mClientId,
      clientPublicKey: config.m2mClientPublicKey,
      activeKeyId: config.activeKeyId,
      issuer: config.issuer,
      audience: config.audience,
      accessTtl: config.accessTtl,
      allowedScopes: config.allowedM2mScopes,
    });
    return {
      role: config.role,
      redis,
      rateLimitRedis,
      redisGate,
      rateLimitGate,
      identity,
      m2m,
      close: async () => {
        await Promise.allSettled([
          redis.quit(),
          rateLimitRedis.quit(),
          identity?.close(),
        ]);
      },
    };
  } catch (error) {
    await Promise.allSettled([
      redis.quit(),
      rateLimitRedis.quit(),
      identity?.close(),
    ]);
    throw error;
  }
}
