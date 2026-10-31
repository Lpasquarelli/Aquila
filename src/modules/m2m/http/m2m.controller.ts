import type { FastifyReply, FastifyRequest } from 'fastify';
import { jwtVerify } from 'jose';
import type { JWTVerifyGetKey } from 'jose';
import { z } from 'zod';
import type { createM2mService } from '../application/m2m.service.js';

const issueSchema = z.object({ clientAssertion: z.string().min(1), scope: z.string().min(1).max(256) });

export class M2mController {
  constructor(
    private service: ReturnType<typeof createM2mService> | undefined,
    private config: { resolvePublicKey: JWTVerifyGetKey; issuer: string; audience: string },
  ) {}

  issueToken = async (request: FastifyRequest, reply: FastifyReply) => {
    const parsed = issueSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid_request' });
    if (!this.service) return reply.code(503).send({ error: 'service_unavailable' });
    return this.service.issueToken.execute(parsed.data.clientAssertion, parsed.data.scope);
  };

  servicePing = async (request: FastifyRequest, reply: FastifyReply) => {
    const header = request.headers.authorization;
    if (!header?.startsWith('Bearer ')) return reply.code(401).send({ error: 'unauthorized' });
    try {
      const { payload } = await jwtVerify(header.slice(7), this.config.resolvePublicKey, {
        issuer: this.config.issuer, audience: this.config.audience, algorithms: ['EdDSA'], requiredClaims: ['sub', 'jti', 'exp'],
      });
      if (payload.token_use !== 'service' || typeof payload.client_id !== 'string' || !String(payload.scope ?? '').split(' ').includes('service:ping')) {
        return reply.code(403).send({ error: 'forbidden' });
      }
      return { status: 'authorized', client: payload.client_id };
    } catch { return reply.code(401).send({ error: 'unauthorized' }); }
  };
}
