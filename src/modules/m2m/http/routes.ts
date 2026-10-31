import type { FastifyInstance } from 'fastify';
import type { M2mController } from './m2m.controller.js';

export async function registerM2mAuthRoutes(app: FastifyInstance, controller: M2mController) {
  app.post('/v1/m2m/token', {
    schema: {
      tags: ['Service auth'], summary: 'Exchange signed client assertion for scoped token',
      body: { type: 'object', required: ['clientAssertion', 'scope'], properties: { clientAssertion: { type: 'string' }, scope: { type: 'string' } } },
      response: {
        200: { type: 'object', properties: { accessToken: { type: 'string' }, expiresIn: { type: 'number' }, tokenType: { type: 'string' } } },
        400: { type: 'object', properties: { error: { type: 'string' } } }, 401: { type: 'object', properties: { error: { type: 'string' } } },
        403: { type: 'object', properties: { error: { type: 'string' } } }, 503: { type: 'object', properties: { error: { type: 'string' } } },
      },
    },
  }, controller.issueToken);
}

export async function registerM2mResourceRoutes(app: FastifyInstance, controller: M2mController) {
  app.get('/v1/service/ping', { schema: { tags: ['Service auth'], summary: 'Example service-only resource', security: [{ bearerAuth: [] }] } }, controller.servicePing);
}
