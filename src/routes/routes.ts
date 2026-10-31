import type { FastifyInstance } from 'fastify';
import type { AppConfig } from '../config/app.config.js';
import type { createContainer } from '../config/container.js';
import { IdentityResourceController } from '../controller/identity/identity-resource.controller.js';
import { IdentityController } from '../controller/identity/identity.controller.js';
import { M2mController } from '../controller/m2m/m2m.controller.js';
import { createAuthenticator } from '../middleware/user-authenticator.service.js';
import { registerHealthRoutes } from './health.routes.js';
import {
  registerIdentityAuthRoutes,
  registerIdentityResourceRoutes,
} from './identity.routes.js';
import {
  registerM2mAuthRoutes,
  registerM2mResourceRoutes,
} from './m2m.routes.js';

export function registerRoutes(
  app: FastifyInstance,
  config: AppConfig,
  container: Awaited<ReturnType<typeof createContainer>>
) {
  registerHealthRoutes(app, container, config.role);

  if (config.role !== 'resource') {
    if (!container.identity.service)
      throw new Error('Auth role is missing identity service dependencies');
    registerIdentityAuthRoutes(
      app,
      new IdentityController({
        service: container.identity.service,
        tokens: container.identity.tokens,
        accessTtl: config.accessTtl,
        refreshTtl: config.refreshTtl,
        browserCookieAuth: config.browserCookieAuth,
        publicOrigin: config.publicOrigin,
        defaultAudience: config.audience,
        allowedAccessAudiences: config.allowedAccessAudiences,
      })
    );
  }

  if (config.role !== 'auth') {
    const authenticate = createAuthenticator({
      sessions: container.identity.sessions,
      tokens: container.identity.tokens,
    });
    registerIdentityResourceRoutes(
      app,
      new IdentityResourceController(authenticate)
    );
  }

  const m2m = new M2mController(container.m2m.service, container.m2m.tokens);
  if (config.role !== 'resource') registerM2mAuthRoutes(app, m2m);
  if (config.role !== 'auth') registerM2mResourceRoutes(app, m2m);
}
