import { DependencyUnavailableError } from '../application/dependency-unavailable.error.js';

/** A small per-process circuit breaker around correctness-critical Redis commands. */
export class RedisCommandGate {
  private failures = 0;
  private openUntil = 0;
  private probeInFlight = false;
  private active = 0;

  constructor(private readonly failureThreshold = 3, private readonly resetAfterMs = 1000, private readonly maxConcurrent = 10000) {}

  async execute<T>(operation: () => Promise<T>): Promise<T> {
    const now = Date.now();
    if (this.openUntil > now) throw new DependencyUnavailableError('Redis');
    if (this.active >= this.maxConcurrent) throw new DependencyUnavailableError('Redis concurrency capacity');
    const isProbe = this.openUntil !== 0;
    if (isProbe && this.probeInFlight) throw new DependencyUnavailableError('Redis');
    if (isProbe) this.probeInFlight = true;
    this.active++;
    try {
      const result = await operation();
      this.failures = 0;
      this.openUntil = 0;
      return result;
    } catch (error) {
      this.failures++;
      if (isProbe || this.failures >= this.failureThreshold) this.openUntil = Date.now() + this.resetAfterMs;
      throw new DependencyUnavailableError('Redis', { cause: error });
    } finally {
      this.active--;
      if (isProbe) this.probeInFlight = false;
    }
  }
}
