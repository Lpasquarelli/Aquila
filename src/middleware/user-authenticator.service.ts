import type { FastifyReply, FastifyRequest } from 'fastify';
import type { ISessionRepository } from '../interfaces/identity/session.repository.js';
import type { ITokenService } from '../interfaces/identity/token.service.js';

export type Principal = { sub: string; sid: string; roles: string[] };

export function createAuthenticator(config: {
  sessions: ISessionRepository;
  tokens: ITokenService;
}) {
  return async function authenticate(
    req: FastifyRequest,
    reply: FastifyReply
  ): Promise<Principal | null> {
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) {
      reply.code(401).send({ error: 'unauthorized' });
      return null;
    }

    let principal: Principal;
    try {
      principal = await config.tokens.verifyAccessToken(header.slice(7));
    } catch {
      reply.code(401).send({ error: 'unauthorized' });
      return null;
    }

    // Redis is the session authority. A miss is a denial; there is no SQL fallback.
    const userId = await config.sessions.userIdById(principal.sid);
    if (!userId || userId !== principal.sub) {
      reply.code(401).send({ error: 'token_revoked' });
      return null;
    }
    return principal;
  };
}
