import type { FastifyInstance } from 'fastify';

export function registerErrorHandler(app: FastifyInstance) {
  app.setErrorHandler((error, _request, reply) => {
    const failure = (
      error instanceof Error ? error : new Error('Unknown error')
    ) as Error & {
      statusCode?: number;
      code?: string;
    };
    const status =
      failure.statusCode &&
      failure.statusCode >= 400 &&
      failure.statusCode < 600
        ? failure.statusCode
        : 500;
    if (status >= 500)
      app.log.error(
        { statusCode: status, code: failure.code, error: failure },
        'Request failed'
      );
    if (status === 429)
      return reply.code(429).send({ error: 'rate_limit_exceeded' });
    if (status === 400)
      return reply.code(400).send({ error: 'invalid_request' });
    if (status === 503) {
      reply.header('retry-after', '1');
      return reply
        .code(503)
        .send({ error: failure.code ?? 'service_unavailable' });
    }
    return reply.code(status).send({
      error:
        status >= 500 ? 'internal_error' : (failure.code ?? 'request_rejected'),
    });
  });
}
