import 'dotenv/config';
import { readFile } from 'node:fs/promises';
import { importPKCS8, importSPKI } from 'jose';
import type { JWTVerifyGetKey } from 'jose';
import { createContainer, type ApiRole } from './di/container.js';
import { createAuthenticator } from './http/create-authenticator.js';
import { createApp } from './http/create-app.js';

const get = (key: string, fallback?: string) => {
  const value = process.env[key] ?? fallback;
  if (!value) throw new Error(`Missing environment variable: ${key}`);
  return value;
};
const number = (key: string, fallback: string) => {
  const value = Number(get(key, fallback));
  if (!Number.isFinite(value) || value <= 0) throw new Error(`${key} must be a positive number`);
  return value;
};
const parseClusterNodes = (key: string) => {
  const raw = process.env[key]?.trim();
  if (!raw) return undefined;
  return raw.split(',').map((entry) => {
    const match = /^(\[[^\]]+\]|[^:]+):(\d+)$/.exec(entry.trim());
    if (!match) throw new Error(`${key} entries must use host:port`);
    const host = match[1]!.startsWith('[') ? match[1]!.slice(1, -1) : match[1]!;
    const port = Number(match[2]);
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error(`${key} contains an invalid port`);
    return { host, port };
  });
};
const integer = (key: string, fallback: string) => {
  const value = number(key, fallback);
  if (!Number.isSafeInteger(value)) throw new Error(`${key} must be a positive integer`);
  return value;
};

const role = get('API_ROLE', 'all') as ApiRole;
if (!['all', 'auth', 'resource'].includes(role)) throw new Error('API_ROLE must be all, auth, or resource');
const isAuthRole = role !== 'resource';
const config = {
  role,
  port: integer('PORT', '3000'),
  issuer: get('JWT_ISSUER', 'https://auth.example.com'),
  audience: get('JWT_AUDIENCE', 'aquila-api'),
  activeKeyId: get('JWT_SIGNING_KEY_ID', 'aquila-ed25519-v1'),
  accessTtl: number('ACCESS_TOKEN_TTL_SECONDS', '300'),
  refreshTtl: number('REFRESH_TOKEN_TTL_SECONDS', '1209600'),
  sessionMaxTtl: number('REFRESH_SESSION_MAX_SECONDS', '2592000'),
  sessionNamespace: get('SESSION_NAMESPACE', 'v1'),
  passwordHashConcurrency: integer('PASSWORD_HASH_CONCURRENCY', '4'),
  sqlPoolMax: integer('SQL_POOL_MAX', '10'),
  redisMaxInflight: integer('REDIS_MAX_INFLIGHT', '10000'),
  browserCookieAuth: process.env.BROWSER_COOKIE_AUTH === 'true',
  publicOrigin: get('PUBLIC_ORIGIN', 'http://localhost:3000'),
  allowedM2mScopes: (process.env.M2M_ALLOWED_SCOPES ?? '').split(' ').filter(Boolean),
};

const publicKeyPaths: Record<string, string> = JSON.parse(
  process.env.JWT_VERIFY_KEYS_JSON ?? JSON.stringify({ [config.activeKeyId]: get('JWT_PUBLIC_KEY_PATH', 'keys/dev-public.pem') }),
);
const verificationKeys = new Map<string, Awaited<ReturnType<typeof importSPKI>>>();
for (const [keyId, path] of Object.entries(publicKeyPaths)) {
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(keyId) || typeof path !== 'string' || !path) throw new Error('JWT_VERIFY_KEYS_JSON must map key IDs to PEM paths');
  verificationKeys.set(keyId, await importSPKI(await readFile(path, 'utf8'), 'EdDSA'));
}
if (!verificationKeys.has(config.activeKeyId)) throw new Error('Active signing key ID must have a matching public verification key');
const resolvePublicKey: JWTVerifyGetKey = async (protectedHeader) => {
  const key = typeof protectedHeader.kid === 'string' ? verificationKeys.get(protectedHeader.kid) : undefined;
  if (!key) throw new Error('Unknown JWT key ID');
  return key;
};

const signingKey = isAuthRole
  ? await importPKCS8(await readFile(get('JWT_PRIVATE_KEY_PATH', 'keys/dev-private.pem'), 'utf8'), 'EdDSA')
  : null;
const m2mPublicKey = isAuthRole && process.env.M2M_CLIENT_PUBLIC_KEY_PATH
  ? await importSPKI(await readFile(process.env.M2M_CLIENT_PUBLIC_KEY_PATH, 'utf8'), 'EdDSA')
  : null;
const redisUrl = get('REDIS_URL', 'redis://localhost:6379');
const rateLimitRedisUrl = process.env.RATE_LIMIT_REDIS_URL ?? (process.env.NODE_ENV === 'production' ? '' : redisUrl);
if (!rateLimitRedisUrl) throw new Error('RATE_LIMIT_REDIS_URL must be configured in production');
const redisClusterNodes = parseClusterNodes('REDIS_CLUSTER_NODES');
const rateLimitRedisClusterNodes = parseClusterNodes('RATE_LIMIT_REDIS_CLUSTER_NODES');

const container = await createContainer({
  role,
  redisUrl,
  rateLimitRedisUrl,
  redisClusterNodes,
  rateLimitRedisClusterNodes,
  sessionNamespace: config.sessionNamespace,
  sqlPoolMax: config.sqlPoolMax,
  redisMaxInflight: config.redisMaxInflight,
  sql: isAuthRole ? {
    server: get('SQLSERVER_HOST', 'localhost'), port: number('SQLSERVER_PORT', '1433'), user: get('SQLSERVER_USER', 'sa'),
    password: get('SQLSERVER_PASSWORD'), database: get('SQLSERVER_DATABASE', 'aquila'), production: process.env.NODE_ENV === 'production',
  } : undefined,
  signingKey, resolvePublicKey, activeKeyId: config.activeKeyId,
  issuer: config.issuer, audience: config.audience, accessTtl: config.accessTtl,
  refreshTtl: config.refreshTtl, sessionMaxTtl: config.sessionMaxTtl,
  passwordHashConcurrency: config.passwordHashConcurrency,
  m2mClientId: process.env.M2M_CLIENT_ID, m2mClientPublicKey: m2mPublicKey, allowedM2mScopes: config.allowedM2mScopes,
});
const authenticate = createAuthenticator({ sessions: container.repositories.sessions, tokens: container.tokens });
const app = await createApp({ container, config, authenticate, resolvePublicKey });
container.redis.on('error', (error: Error) => app.log.error({ error }, 'Session Redis connection error'));
container.rateLimitRedis.on('error', (error: Error) => app.log.error({ error }, 'Rate-limit Redis connection error'));

const close = async () => { await app.close(); await container.close(); };
process.once('SIGINT', () => void close());
process.once('SIGTERM', () => void close());
await app.listen({ port: config.port, host: '0.0.0.0' });
