import type { ISessionEventPublisher } from '../../interfaces/identity/session-event.publisher.js';
import type { ISessionRepository } from '../../interfaces/identity/session.repository.js';

/** All early session invalidations use this barrier before removing Aquila's live session. */
export class SessionRevokerService {
  constructor(
    private readonly sessions: ISessionRepository,
    private readonly publisher: ISessionEventPublisher
  ) {}

  async revoke(sessionId: string): Promise<void> {
    await this.publisher.publishAndWait(sessionId);
    await this.sessions.revoke(sessionId);
  }
}
