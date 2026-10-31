import Fastify from 'fastify';
import swagger from '@fastify/swagger';
import swaggerUI from '@fastify/swagger-ui';
import cookie from '@fastify/cookie';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import type { JWTVerifyGetKey } from 'jose';
import type { createContainer } from '../di/container.js';
import type { createAuthenticator } from './create-authenticator.js';
import { registerIdentityAuthRoutes, registerIdentityResourceRoutes } from '../modules/identity/http/routes.js';
import { registerM2mAuthRoutes, registerM2mResourceRoutes } from '../modules/m2m/http/routes.js';
import { IdentityController } from '../modules/identity/http/identity.controller.js';
import { IdentityResourceController } from '../modules/identity/http/identity-resource.controller.js';
import { M2mController } from '../modules/m2m/http/m2m.controller.js';
import { createRedisRateLimitStore } from './redis-rate-limit.store.js';

type Options = {
  container: Awaited<ReturnType<typeof createContainer>>;
  config: {
    role: 'all' | 'auth' | 'resource'; port: number; issuer: string; audience: string;
    accessTtl: number; refreshTtl: number; browserCookieAuth: boolean; publicOrigin: string;
  };
  authenticate: ReturnType<typeof createAuthenticator>;
  resolvePublicKey: JWTVerifyGetKey;
};

export async function createApp(options: Options) {
  const app = Fastify({
    logger: true,
    trustProxy: process.env.TRUST_PROXY === 'true',
    bodyLimit: 16384,
    requestTimeout: 15000,
    handlerTimeout: 5000,
  });
  await app.register(helmet);
  await app.register(cookie);
  await app.register(swagger, {
    openapi: {
      info: { title: 'Aquila Secure API', description: 'Authentication, authorization, session, and service-token endpoints.', version: '0.2.0' },
      servers: [{ url: `http://localhost:${options.config.port}` }],
      components: { securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } } },
    },
  });

  app.get('/health/live', { schema: { tags: ['Health'], summary: 'Liveness probe', response: { 200: { type: 'object', properties: { status: { type: 'string' } } } } } }, async () => ({ status: 'ok' }));
  app.get('/health/ready', { schema: { tags: ['Health'], summary: 'Role dependency readiness probe' } }, async (_req, reply) => {
    try {
      await options.container.redisGate.execute(() => options.container.redis.ping());
      await options.container.rateLimitGate.execute(() => options.container.rateLimitRedis.ping());
      if (options.container.pool) await options.container.pool.request().query('SELECT 1');
      return { status: 'ready', role: options.config.role };
    } catch {
      return reply.code(503).send({ error: 'dependencies_unavailable' });
    }
  });

  await app.register(rateLimit, {
    store: createRedisRateLimitStore(options.container.rateLimitRedis, options.container.rateLimitGate),
    skipOnError: false,
    nameSpace: 'aquila-rate-limit:',
    max: 120,
    timeWindow: '1 minute',
    allowList: (request) => request.url === '/health/live' || request.url === '/health/ready',
  });

  const m2mController = new M2mController(options.container.services.m2m, {
    resolvePublicKey: options.resolvePublicKey, issuer: options.config.issuer, audience: options.config.audience,
  });
  if (options.config.role !== 'resource') {
    const service = options.container.services.identity;
    if (!service) throw new Error('Auth role is missing identity service dependencies');
    const identityController = new IdentityController({
      service, tokens: options.container.tokens, accessTtl: options.config.accessTtl,
      refreshTtl: options.config.refreshTtl, browserCookieAuth: options.config.browserCookieAuth,
      publicOrigin: options.config.publicOrigin,
    });
    await registerIdentityAuthRoutes(app, identityController);
    await registerM2mAuthRoutes(app, m2mController);
  }
  if (options.config.role !== 'auth') {
    const resourceController = new IdentityResourceController(options.authenticate);
    await registerIdentityResourceRoutes(app, resourceController);
    await registerM2mResourceRoutes(app, m2mController);
  }

  app.setErrorHandler((error: any, _req, reply) => {
    const status = error.statusCode && error.statusCode >= 400 && error.statusCode < 600 ? error.statusCode : 500;
    if (status >= 500) app.log.error({ statusCode: status, code: error.code, error }, 'Request failed');
    if (status === 429) return reply.code(429).send({ error: 'rate_limit_exceeded' });
    if (status === 400) return reply.code(400).send({ error: 'invalid_request' });
    if (status === 503) {
      reply.header('retry-after', '1');
      return reply.code(503).send({ error: error.code ?? 'service_unavailable' });
    }
    return reply.code(status).send({ error: status >= 500 ? 'internal_error' : error.code ?? 'request_rejected' });
  });
  await app.register(swaggerUI, { routePrefix: '/docs', uiConfig: { docExpansion: 'list', deepLinking: false } });
  return app;
}
