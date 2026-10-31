import type { FastifyReply, FastifyRequest } from 'fastify';
import type { createAuthenticator } from '../../../http/create-authenticator.js';

export class IdentityResourceController {
  constructor(private readonly authenticate: ReturnType<typeof createAuthenticator>) {}

  me = async (request: FastifyRequest, reply: FastifyReply) => {
    const principal = await this.authenticate(request, reply);
    return principal ? { id: principal.sub, roles: principal.roles } : undefined;
  };

  admin = async (request: FastifyRequest, reply: FastifyReply) => {
    const principal = await this.authenticate(request, reply);
    if (!principal) return;
    if (!principal.roles.includes('admin')) return reply.code(403).send({ error: 'forbidden' });
    return { status: 'authorized' };
  };
}
