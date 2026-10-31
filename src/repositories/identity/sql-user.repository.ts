import sql from 'mssql';
import type { IUserRepository } from '../../interfaces/identity/user.repository.js';
import type { User } from '../../models/identity.models.js';
import { DependencyUnavailableError } from '../../utils/errors/dependency-unavailable.error.js';

type UserRow = {
  Id: string;
  Email: string;
  PasswordHash: string;
  RolesCsv: string | null;
  IsActive: boolean;
};

function toUser(row: UserRow | undefined): User | null {
  return row
    ? {
        id: String(row.Id),
        email: row.Email,
        passwordHash: row.PasswordHash,
        roles: String(row.RolesCsv ?? '')
          .split(',')
          .filter(Boolean),
        active: Boolean(row.IsActive),
      }
    : null;
}

export class SqlUserRepository implements IUserRepository {
  constructor(private pool: sql.ConnectionPool) {}
  async byEmail(email: string): Promise<User | null> {
    try {
      const r = await this.pool
        .request()
        .input('email', sql.NVarChar(320), email)
        .query<UserRow>(
          'SELECT TOP (1) Id, Email, PasswordHash, RolesCsv, IsActive FROM dbo.Users WHERE Email = @email'
        );
      return toUser(r.recordset[0]);
    } catch (error) {
      throw new DependencyUnavailableError('SQL Server', { cause: error });
    }
  }
  async byId(id: string): Promise<User | null> {
    try {
      const r = await this.pool
        .request()
        .input('id', sql.NVarChar(128), id)
        .query<UserRow>(
          'SELECT TOP (1) Id, Email, PasswordHash, RolesCsv, IsActive FROM dbo.Users WHERE Id = @id'
        );
      return toUser(r.recordset[0]);
    } catch (error) {
      throw new DependencyUnavailableError('SQL Server', { cause: error });
    }
  }
}
