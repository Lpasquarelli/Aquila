import argon2 from 'argon2';
import type { JWTVerifyGetKey } from 'jose';
import sql from 'mssql';
import { randomBytes } from 'node:crypto';
import { NatsSessionEventPublisher } from '../clients/nats-session-event.publisher.js';
import type { RedisClient } from '../clients/redis-client.js';
import { RedisSessionRepository } from '../repositories/identity/redis-session.repository.js';
import { SqlUserRepository } from '../repositories/identity/sql-user.repository.js';
import { Argon2PasswordHasher } from '../services/identity/argon2-password-hasher.service.js';
import { createIdentityService } from '../services/identity/identity.service.js';
import { JoseTokenService } from '../services/identity/jose-token.service.js';
import { SessionRevokerService } from '../services/identity/session-revoker.service.js';
import type { RedisCommandGate } from '../utils/redis-command-gate.js';

type SigningKey = Awaited<ReturnType<typeof import('jose').importPKCS8>>;

export type IdentityContainerConfig = {
  authEnabled: boolean;
  redis: RedisClient;
  gate: RedisCommandGate;
  sessionNamespace: string;
  signingKey: SigningKey | null;
  resolvePublicKey: JWTVerifyGetKey;
  activeKeyId: string;
  issuer: string;
  audience: string;
  accessTtl: number;
  refreshTtl: number;
  sessionMaxTtl: number;
  allowedAccessAudiences: string[];
  passwordHashConcurrency: number;
  sqlPoolMax: number;
  sql?: {
    server: string;
    port: number;
    user: string;
    password: string;
    database: string;
    production: boolean;
  };
  nats: {
    url: string;
    timeoutMs: number;
    user?: string;
    password?: string;
    tls: boolean;
    caFile?: string;
  };
};

/** Compose identity services and adapters for the selected API role. */
export async function createIdentityContainer(config: IdentityContainerConfig) {
  const sessions = new RedisSessionRepository(
    config.redis,
    config.gate,
    config.sessionNamespace
  );
  const tokens = new JoseTokenService({
    signingKey: config.signingKey,
    resolvePublicKey: config.resolvePublicKey,
    activeKeyId: config.activeKeyId,
    issuer: config.issuer,
    audience: config.audience,
    accessTtl: config.accessTtl,
    sessionEpoch: config.sessionNamespace,
  });
  let pool: sql.ConnectionPool | undefined;
  let publisher: NatsSessionEventPublisher | undefined;
  try {
    let service: ReturnType<typeof createIdentityService> | undefined;
    if (config.authEnabled) {
      if (!config.sql || !config.signingKey)
        throw new Error(
          'Auth role requires SQL settings and a private signing key'
        );
      publisher = await NatsSessionEventPublisher.connect(
        config.nats.url,
        config.sessionNamespace,
        config.accessTtl,
        config.nats.timeoutMs,
        {
          user: config.nats.user,
          pass: config.nats.password,
          tlsEnabled: config.nats.tls,
          tlsCaFile: config.nats.caFile,
        }
      );
      pool = await sql.connect({
        server: config.sql.server,
        port: config.sql.port,
        user: config.sql.user,
        password: config.sql.password,
        database: config.sql.database,
        connectionTimeout: 1500,
        requestTimeout: 2000,
        options: {
          encrypt: true,
          trustServerCertificate: !config.sql.production,
        },
        pool: {
          min: 0,
          max: config.sqlPoolMax,
          idleTimeoutMillis: 30000,
          acquireTimeoutMillis: 1000,
        },
      });
      const users = new SqlUserRepository(pool);
      service = createIdentityService({
        users,
        sessions,
        tokens,
        passwords: new Argon2PasswordHasher(config.passwordHashConcurrency),
        refreshTtl: config.refreshTtl,
        sessionMaxTtl: config.sessionMaxTtl,
        dummyPasswordHash: await argon2.hash(randomBytes(32), {
          type: argon2.argon2id,
        }),
        revoker: new SessionRevokerService(sessions, publisher),
        sessionEvents: publisher,
        allowedAccessAudiences: config.allowedAccessAudiences,
      });
    }
    return {
      sessions,
      tokens,
      service,
      pool,
      publisher,
      close: async () => {
        await publisher?.close();
        await pool?.close();
      },
    };
  } catch (error) {
    await Promise.allSettled([publisher?.close(), pool?.close()]);
    throw error;
  }
}
