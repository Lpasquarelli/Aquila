import sql from 'mssql';
import type { IUserRepository } from '../application/user.repository.js';
import type { User } from '../domain/models.js';
import { DependencyUnavailableError } from '../../../shared/application/dependency-unavailable.error.js';
export class SqlUserRepository implements IUserRepository {
  constructor(private pool: sql.ConnectionPool) {}
  async byEmail(email: string): Promise<User | null> {
    try {
      const r = await this.pool.request().input('email', sql.NVarChar(320), email).query('SELECT TOP (1) Id, Email, PasswordHash, RolesCsv, IsActive FROM dbo.Users WHERE Email = @email');
      const x = r.recordset[0];
      return x ? { id: String(x.Id), email: x.Email, passwordHash: x.PasswordHash, roles: String(x.RolesCsv ?? '').split(',').filter(Boolean), active: Boolean(x.IsActive) } : null;
    } catch (error) { throw new DependencyUnavailableError('SQL Server', { cause: error }); }
  }
  async byId(id: string): Promise<User | null> {
    try {
      const r = await this.pool.request().input('id', sql.NVarChar(128), id).query('SELECT TOP (1) Id, Email, PasswordHash, RolesCsv, IsActive FROM dbo.Users WHERE Id = @id');
      const x = r.recordset[0];
      return x ? { id: String(x.Id), email: x.Email, passwordHash: x.PasswordHash, roles: String(x.RolesCsv ?? '').split(',').filter(Boolean), active: Boolean(x.IsActive) } : null;
    } catch (error) { throw new DependencyUnavailableError('SQL Server', { cause: error }); }
  }
}
