import type { JWTVerifyGetKey } from 'jose';
import type { RedisClient } from '../clients/redis-client.js';
import { RedisAssertionReplayRepository } from '../repositories/m2m/redis-assertion-replay.repository.js';
import { JoseM2mTokenService } from '../services/m2m/jose-m2m-token.service.js';
import { createM2mService } from '../services/m2m/m2m.service.js';
import type { RedisCommandGate } from '../utils/redis-command-gate.js';

type SigningKey = Awaited<ReturnType<typeof import('jose').importPKCS8>>;
type VerificationKey = Awaited<ReturnType<typeof import('jose').importSPKI>>;

export function createM2mContainer(config: {
  authEnabled: boolean;
  redis: RedisClient;
  gate: RedisCommandGate;
  signingKey: SigningKey | null;
  resolvePublicKey: JWTVerifyGetKey;
  clientId?: string;
  clientPublicKey: VerificationKey | null;
  activeKeyId: string;
  issuer: string;
  audience: string;
  accessTtl: number;
  allowedScopes: string[];
}) {
  const assertionReplays = new RedisAssertionReplayRepository(
    config.redis,
    config.gate
  );
  if (config.authEnabled && !config.signingKey)
    throw new Error('Auth role requires a private signing key');
  const tokens = new JoseM2mTokenService(config);
  const service = config.authEnabled
    ? createM2mService({
        clientId: config.clientId,
        clientPublicKeyConfigured: Boolean(config.clientPublicKey),
        assertionReplays,
        tokens,
        accessTtl: config.accessTtl,
        allowedScopes: config.allowedScopes,
      })
    : undefined;
  return { assertionReplays, service, tokens };
}
