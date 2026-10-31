import type { JWTVerifyGetKey } from 'jose';
import { importPKCS8, importSPKI } from 'jose';
import { readFile, realpath } from 'node:fs/promises';
import { isAbsolute, sep } from 'node:path';
import type { RedisClusterNode } from '../clients/redis-client.js';
import type { ApiRole, ContainerConfig } from './container.js';

export type AppConfig = ContainerConfig & {
  port: number;
  browserCookieAuth: boolean;
  publicOrigin: string;
  trustProxy: boolean;
};

function required(key: string, fallback?: string): string {
  const value = process.env[key] ?? fallback;
  if (!value) throw new Error(`Missing environment variable: ${key}`);
  return value;
}

function positiveNumber(key: string, fallback: string): number {
  const value = Number(required(key, fallback));
  if (!Number.isFinite(value) || value <= 0)
    throw new Error(`${key} must be a positive number`);
  return value;
}

function positiveInteger(key: string, fallback: string): number {
  const value = positiveNumber(key, fallback);
  if (!Number.isSafeInteger(value))
    throw new Error(`${key} must be a positive integer`);
  return value;
}

function clusterNodes(key: string): RedisClusterNode[] | undefined {
  const raw = process.env[key]?.trim();
  if (!raw) return undefined;
  return raw.split(',').map((entry) => {
    const match = /^(\[[^\]]+\]|[^:]+):(\d+)$/.exec(entry.trim());
    if (!match) throw new Error(`${key} entries must use host:port`);
    const host = match[1]!.startsWith('[') ? match[1]!.slice(1, -1) : match[1]!;
    const port = Number(match[2]);
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535)
      throw new Error(`${key} contains an invalid port`);
    return { host, port };
  });
}

async function verificationKeys(activeKeyId: string): Promise<JWTVerifyGetKey> {
  const paths = JSON.parse(
    process.env.JWT_VERIFY_KEYS_JSON ??
      JSON.stringify({
        [activeKeyId]: required('JWT_PUBLIC_KEY_PATH', 'keys/dev-public.pem'),
      })
  ) as unknown;
  if (!paths || typeof paths !== 'object' || Array.isArray(paths))
    throw new Error('JWT_VERIFY_KEYS_JSON must map key IDs to PEM paths');
  const keys = new Map<string, Awaited<ReturnType<typeof importSPKI>>>();
  for (const [keyId, path] of Object.entries(
    paths as Record<string, unknown>
  )) {
    if (
      !/^[A-Za-z0-9_-]{1,64}$/.test(keyId) ||
      typeof path !== 'string' ||
      !path
    ) {
      throw new Error('JWT_VERIFY_KEYS_JSON must map key IDs to PEM paths');
    }
    keys.set(keyId, await importSPKI(await readFile(path, 'utf8'), 'EdDSA'));
  }
  if (!keys.has(activeKeyId))
    throw new Error(
      'Active signing key ID must have a matching public verification key'
    );
  return (protectedHeader) => {
    const key =
      typeof protectedHeader.kid === 'string'
        ? keys.get(protectedHeader.kid)
        : undefined;
    if (!key) throw new Error('Unknown JWT key ID');
    return Promise.resolve(key);
  };
}

export async function loadAppConfig(): Promise<AppConfig> {
  const role = required('API_ROLE', 'all') as ApiRole;
  if (!['all', 'auth', 'resource'].includes(role))
    throw new Error('API_ROLE must be all, auth, or resource');
  const authRole = role !== 'resource';
  const production = process.env.NODE_ENV === 'production';
  const activeKeyId = required('JWT_SIGNING_KEY_ID', 'aquila-ed25519-v1');
  const accessTtl = positiveNumber('ACCESS_TOKEN_TTL_SECONDS', '300');
  if (accessTtl > 3600)
    throw new Error(
      'ACCESS_TOKEN_TTL_SECONDS must be at most 3600 for the session-event retention contract'
    );
  const natsTls = process.env.NATS_TLS === 'true';
  if (production && !natsTls)
    throw new Error('NATS_TLS=true is required in production');
  if (production && authRole) {
    const privateKeyPath = process.env.JWT_PRIVATE_KEY_PATH;
    const projectPath = await realpath(process.cwd());
    if (
      !privateKeyPath ||
      !isAbsolute(privateKeyPath) ||
      (await realpath(privateKeyPath)).startsWith(projectPath + sep)
    ) {
      throw new Error(
        'Production signing key must be mounted outside the project tree'
      );
    }
    if (!process.env.NATS_USER || !process.env.NATS_PASSWORD)
      throw new Error('Production NATS publisher credentials are required');
  }

  const redisUrl = required('REDIS_URL', 'redis://localhost:6379');
  const rateLimitRedisUrl =
    process.env.RATE_LIMIT_REDIS_URL ?? (production ? '' : redisUrl);
  if (!rateLimitRedisUrl)
    throw new Error('RATE_LIMIT_REDIS_URL must be configured in production');

  return {
    role,
    port: positiveInteger('PORT', '3000'),
    trustProxy: process.env.TRUST_PROXY === 'true',
    browserCookieAuth: process.env.BROWSER_COOKIE_AUTH === 'true',
    publicOrigin: required('PUBLIC_ORIGIN', 'http://localhost:3000'),
    redisUrl,
    rateLimitRedisUrl,
    redisClusterNodes: clusterNodes('REDIS_CLUSTER_NODES'),
    rateLimitRedisClusterNodes: clusterNodes('RATE_LIMIT_REDIS_CLUSTER_NODES'),
    sessionNamespace: required('SESSION_NAMESPACE', 'v1'),
    sqlPoolMax: positiveInteger('SQL_POOL_MAX', '10'),
    redisMaxInflight: positiveInteger('REDIS_MAX_INFLIGHT', '10000'),
    sql: authRole
      ? {
          server: required('SQLSERVER_HOST', 'localhost'),
          port: positiveInteger('SQLSERVER_PORT', '1433'),
          user: required('SQLSERVER_USER', 'sa'),
          password: required('SQLSERVER_PASSWORD'),
          database: required('SQLSERVER_DATABASE', 'aquila'),
          production,
        }
      : undefined,
    signingKey: authRole
      ? await importPKCS8(
          await readFile(
            required('JWT_PRIVATE_KEY_PATH', 'keys/dev-private.pem'),
            'utf8'
          ),
          'EdDSA'
        )
      : null,
    resolvePublicKey: await verificationKeys(activeKeyId),
    activeKeyId,
    issuer: required('JWT_ISSUER', 'https://auth.example.com'),
    audience: required('JWT_AUDIENCE', 'aquila-api'),
    accessTtl,
    allowedAccessAudiences: (
      process.env.JWT_ACCESS_AUDIENCES ?? 'aquila-api aquila-consumer'
    )
      .split(' ')
      .filter(Boolean),
    natsUrl: required('NATS_URL', 'nats://localhost:4222'),
    revocationTimeoutMs: positiveInteger('REVOCATION_TIMEOUT_MS', '1500'),
    natsUser: process.env.NATS_USER,
    natsPassword: process.env.NATS_PASSWORD,
    natsTls,
    natsCaFile: process.env.NATS_CA_FILE,
    refreshTtl: positiveNumber('REFRESH_TOKEN_TTL_SECONDS', '1209600'),
    sessionMaxTtl: positiveNumber('REFRESH_SESSION_MAX_SECONDS', '2592000'),
    passwordHashConcurrency: positiveInteger('PASSWORD_HASH_CONCURRENCY', '4'),
    m2mClientId: process.env.M2M_CLIENT_ID,
    m2mClientPublicKey:
      authRole && process.env.M2M_CLIENT_PUBLIC_KEY_PATH
        ? await importSPKI(
            await readFile(process.env.M2M_CLIENT_PUBLIC_KEY_PATH, 'utf8'),
            'EdDSA'
          )
        : null,
    allowedM2mScopes: (process.env.M2M_ALLOWED_SCOPES ?? '')
      .split(' ')
      .filter(Boolean),
  };
}
