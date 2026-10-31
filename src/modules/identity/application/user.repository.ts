import type { User } from '../domain/models.js';
export interface IUserRepository {
  byEmail(email: string): Promise<User | null>;
  byId(id: string): Promise<User | null>;
}
