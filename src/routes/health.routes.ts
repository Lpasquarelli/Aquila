import type { FastifyInstance } from 'fastify';
import type { ApiRole, createContainer } from '../config/container.js';

export function registerHealthRoutes(
  app: FastifyInstance,
  container: Awaited<ReturnType<typeof createContainer>>,
  role: ApiRole
) {
  app.get(
    '/health/live',
    {
      schema: {
        tags: ['Health'],
        summary: 'Liveness probe',
        response: {
          200: { type: 'object', properties: { status: { type: 'string' } } },
        },
      },
    },
    () => ({ status: 'ok' })
  );

  app.get(
    '/health/ready',
    {
      schema: { tags: ['Health'], summary: 'Role dependency readiness probe' },
    },
    async (_request, reply) => {
      try {
        await container.redisGate.execute(() => container.redis.ping());
        await container.rateLimitGate.execute(() =>
          container.rateLimitRedis.ping()
        );
        if (container.identity.pool)
          await container.identity.pool.request().query('SELECT 1');
        await container.identity.publisher?.ready();
        return { status: 'ready', role };
      } catch {
        return reply.code(503).send({ error: 'dependencies_unavailable' });
      }
    }
  );
}
