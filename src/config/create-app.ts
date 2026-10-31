import cookie from '@fastify/cookie';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import swagger from '@fastify/swagger';
import swaggerUI from '@fastify/swagger-ui';
import Fastify from 'fastify';
import { registerErrorHandler } from '../middleware/error-handler.middleware.js';
import { createRedisRateLimitStore } from '../middleware/redis-rate-limit.store.js';
import { registerRoutes } from '../routes/routes.js';
import type { AppConfig } from './app.config.js';
import type { createContainer } from './container.js';

type Options = {
  container: Awaited<ReturnType<typeof createContainer>>;
  config: AppConfig;
};

export async function createApp(options: Options) {
  const app = Fastify({
    logger: true,
    trustProxy: options.config.trustProxy,
    bodyLimit: 16384,
    requestTimeout: 15000,
    handlerTimeout: 5000,
  });
  await app.register(helmet);
  await app.register(cookie);
  await app.register(swagger, {
    openapi: {
      info: {
        title: 'Aquila Secure API',
        description:
          'Authentication, authorization, session, and service-token endpoints.',
        version: '0.2.0',
      },
      servers: [{ url: `http://localhost:${options.config.port}` }],
      components: {
        securitySchemes: {
          bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
        },
      },
    },
  });

  await app.register(rateLimit, {
    store: createRedisRateLimitStore(
      options.container.rateLimitRedis,
      options.container.rateLimitGate
    ),
    skipOnError: false,
    nameSpace: 'aquila-rate-limit:',
    max: 120,
    timeWindow: '1 minute',
    allowList: (request) =>
      request.url === '/health/live' || request.url === '/health/ready',
  });

  registerRoutes(app, options.config, options.container);

  registerErrorHandler(app);
  await app.register(swaggerUI, {
    routePrefix: '/docs',
    uiConfig: { docExpansion: 'list', deepLinking: false },
  });
  return app;
}
