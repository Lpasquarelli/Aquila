import type { FastifyInstance } from 'fastify';
import type { IdentityController } from './identity.controller.js';
import type { IdentityResourceController } from './identity-resource.controller.js';

export async function registerIdentityAuthRoutes(app: FastifyInstance, controller: IdentityController) {
  app.post('/v1/auth/login', {
    schema: {
      tags: ['User auth'], summary: 'Authenticate with password',
      body: { type: 'object', required: ['email', 'password'], properties: { email: { type: 'string', format: 'email' }, password: { type: 'string', format: 'password' } } },
      response: {
        200: { type: 'object', properties: { accessToken: { type: 'string' }, refreshToken: { type: 'string' }, expiresIn: { type: 'number' }, tokenType: { type: 'string' } } },
        400: { type: 'object', properties: { error: { type: 'string' } } }, 401: { type: 'object', properties: { error: { type: 'string' } } },
        429: { type: 'object', properties: { error: { type: 'string' } } }, 503: { type: 'object', properties: { error: { type: 'string' } } },
      },
    }, preHandler: controller.verifyOrigin,
    config: { rateLimit: { max: 8, timeWindow: '15 minutes' } },
  }, controller.login);

  app.post('/v1/auth/refresh', {
    schema: {
      tags: ['User auth'], summary: 'Rotate refresh token', body: { type: 'object', properties: { refreshToken: { type: 'string' } } },
      response: {
        200: { type: 'object', properties: { accessToken: { type: 'string' }, refreshToken: { type: 'string' }, expiresIn: { type: 'number' }, tokenType: { type: 'string' } } },
        401: { type: 'object', properties: { error: { type: 'string' } } }, 503: { type: 'object', properties: { error: { type: 'string' } } },
      },
    }, preHandler: controller.verifyOrigin,
  }, controller.refresh);

  app.post('/v1/auth/logout', {
    schema: {
      tags: ['User auth'], summary: 'Revoke current session', security: [{ bearerAuth: [] }],
      response: { 204: { type: 'null' }, 503: { type: 'object', properties: { error: { type: 'string' } } } },
    },
    preHandler: controller.verifyOrigin,
  }, controller.logout);

}

export async function registerIdentityResourceRoutes(app: FastifyInstance, controller: IdentityResourceController) {
  app.get('/v1/me', { schema: { tags: ['User auth'], summary: 'Read authenticated user', security: [{ bearerAuth: [] }] } }, controller.me);
  app.get('/v1/admin', { schema: { tags: ['Authorization'], summary: 'Example admin-only route', security: [{ bearerAuth: [] }] } }, controller.admin);
}
