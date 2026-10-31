import argon2 from 'argon2';
import type { IPasswordHasher } from '../../interfaces/identity/password-hasher.service.js';
import { CommandError } from '../../utils/errors/command.error.js';

/** Refuses excess CPU/memory work immediately; there is no unbounded password-hash queue. */
export class Argon2PasswordHasher implements IPasswordHasher {
  private active = 0;

  constructor(private readonly maxConcurrent: number) {
    if (!Number.isInteger(maxConcurrent) || maxConcurrent < 1)
      throw new Error('PASSWORD_HASH_CONCURRENCY must be a positive integer');
  }

  async verify(hash: string, password: string): Promise<boolean> {
    if (this.active >= this.maxConcurrent)
      throw new CommandError(503, 'authentication_capacity_exceeded');
    this.active++;
    try {
      return await argon2.verify(hash, password);
    } catch {
      return false;
    } finally {
      this.active--;
    }
  }
}
