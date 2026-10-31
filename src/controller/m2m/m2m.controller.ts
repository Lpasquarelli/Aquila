import type { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { IM2mTokenService } from '../../interfaces/m2m/m2m-token.service.js';
import type { createM2mService } from '../../services/m2m/m2m.service.js';

const issueSchema = z.object({
  clientAssertion: z.string().min(1),
  scope: z.string().min(1).max(256),
});

export class M2mController {
  constructor(
    private service: ReturnType<typeof createM2mService> | undefined,
    private tokens: IM2mTokenService
  ) {}

  issueToken = async (request: FastifyRequest, reply: FastifyReply) => {
    const parsed = issueSchema.safeParse(request.body);
    if (!parsed.success)
      return reply.code(400).send({ error: 'invalid_request' });
    if (!this.service)
      return reply.code(503).send({ error: 'service_unavailable' });
    return this.service.issueToken.execute(
      parsed.data.clientAssertion,
      parsed.data.scope
    );
  };

  servicePing = async (request: FastifyRequest, reply: FastifyReply) => {
    const header = request.headers.authorization;
    if (!header?.startsWith('Bearer '))
      return reply.code(401).send({ error: 'unauthorized' });
    try {
      const principal = await this.tokens.verifyServiceToken(header.slice(7));
      if (!principal.scopes.includes('service:ping')) {
        return reply.code(403).send({ error: 'forbidden' });
      }
      return { status: 'authorized', client: principal.clientId };
    } catch {
      return reply.code(401).send({ error: 'unauthorized' });
    }
  };
}
