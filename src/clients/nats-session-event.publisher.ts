import {
  jetstream,
  jetstreamManager,
  RetentionPolicy,
  StorageType,
} from '@nats-io/jetstream';
import { connect } from '@nats-io/transport-node';
import { randomUUID } from 'node:crypto';
import type { ISessionEventPublisher } from '../interfaces/identity/session-event.publisher.js';
import { DependencyUnavailableError } from '../utils/errors/dependency-unavailable.error.js';

const STREAM = 'AQUILA_SESSION_EVENTS_V2';
const SUBJECT = 'aquila.session.events.v2';
const decoder = new TextDecoder();
const encoder = new TextEncoder();

export class NatsSessionEventPublisher implements ISessionEventPublisher {
  private constructor(
    private readonly nc: Awaited<ReturnType<typeof connect>>,
    private readonly epoch: string,
    private readonly accessTtlSeconds: number,
    private readonly timeoutMs: number
  ) {}

  static async connect(
    url: string,
    epoch: string,
    accessTtlSeconds: number,
    timeoutMs: number,
    security: {
      user?: string;
      pass?: string;
      tlsCaFile?: string;
      tlsEnabled: boolean;
    }
  ) {
    const nc = await connect({
      servers: url,
      timeout: timeoutMs,
      maxReconnectAttempts: -1,
      ...(security.user ? { user: security.user, pass: security.pass } : {}),
      ...(security.tlsEnabled
        ? {
            tls: {
              rejectUnauthorized: true,
              ...(security.tlsCaFile ? { caFile: security.tlsCaFile } : {}),
            },
          }
        : {}),
    });
    try {
      const manager = await jetstreamManager(nc);
      try {
        await manager.streams.info(STREAM);
      } catch {
        await manager.streams.add({
          name: STREAM,
          subjects: [SUBJECT],
          storage: StorageType.File,
          retention: RetentionPolicy.Limits,
          max_age: 24 * 60 * 60 * 1_000_000_000,
        });
      }
      const stream = await manager.streams.info(STREAM);
      if (
        !stream.config.subjects.includes(SUBJECT) ||
        stream.config.storage !== StorageType.File ||
        stream.config.max_age < (accessTtlSeconds + 3600) * 1_000_000_000
      ) {
        throw new Error(
          'Revocation stream retention or storage is below the authorization contract'
        );
      }
      return new NatsSessionEventPublisher(
        nc,
        epoch,
        accessTtlSeconds,
        timeoutMs
      );
    } catch (error) {
      await nc.close();
      throw error;
    }
  }

  async ready(): Promise<void> {
    try {
      await this.nc.flush();
      await jetstreamManager(this.nc);
    } catch (error) {
      throw new DependencyUnavailableError('Revocation stream', {
        cause: error,
      });
    }
  }

  async activate(input: {
    sid: string;
    sub: string;
    roles: string[];
    sessionExpiresAt: number;
    tokenDigest: string;
    tokenExpiresAt: number;
  }): Promise<void> {
    await this.send({
      kind: 'activated',
      sid: input.sid,
      sub: input.sub,
      roles: input.roles,
      sessionExpiresAt: input.sessionExpiresAt,
      tokenDigest: input.tokenDigest,
      tokenExpiresAt: input.tokenExpiresAt,
    });
  }

  async publishAndWait(sessionId: string): Promise<void> {
    await this.send({
      kind: 'revoked',
      sid: sessionId,
      validUntil: Date.now() + this.accessTtlSeconds * 1000 + 5000,
    });
  }

  private async send(input: Record<string, unknown>): Promise<void> {
    const id = randomUUID();
    const replySubject = `aquila.session.applied.${id}`;
    const subscription = this.nc.subscribe(replySubject);
    try {
      await this.bounded(this.nc.flush());
      const event = { version: 2, id, epoch: this.epoch, ...input };
      await this.bounded(
        jetstream(this.nc).publish(
          SUBJECT,
          encoder.encode(JSON.stringify(event))
        )
      );
      const applied = this.bounded(
        (async () => {
          for await (const message of subscription)
            return decoder.decode(message.data);
          throw new Error('Applied acknowledgement subscription closed');
        })()
      );
      if ((await applied) !== id)
        throw new Error('Invalid applied acknowledgement');
    } catch (error) {
      throw new DependencyUnavailableError('Session projection', {
        cause: error,
      });
    } finally {
      subscription.unsubscribe();
    }
  }

  async close(): Promise<void> {
    await this.nc.close();
  }

  private async bounded<T>(operation: Promise<T>): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        operation,
        new Promise<never>((_resolve, reject) => {
          timer = setTimeout(
            () => reject(new Error('Revocation deadline exceeded')),
            this.timeoutMs
          );
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
}
