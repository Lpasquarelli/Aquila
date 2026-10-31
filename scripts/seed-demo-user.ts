import argon2 from 'argon2';
import 'dotenv/config';
import sql from 'mssql';
import { randomUUID } from 'node:crypto';

const email = process.env.DEMO_EMAIL?.trim().toLowerCase();
const password = process.env.DEMO_PASSWORD;
if (!email || !password || password.length < 12)
  throw new Error(
    'Set DEMO_EMAIL and a DEMO_PASSWORD of at least 12 characters.'
  );
const pool = await sql.connect({
  server: process.env.SQLSERVER_HOST ?? 'localhost',
  port: Number(process.env.SQLSERVER_PORT ?? 1433),
  user: process.env.SQLSERVER_USER ?? 'sa',
  password: process.env.SQLSERVER_PASSWORD!,
  database: process.env.SQLSERVER_DATABASE ?? 'aquila',
  options: {
    encrypt: true,
    trustServerCertificate: process.env.NODE_ENV !== 'production',
  },
});
const passwordHash = await argon2.hash(password, { type: argon2.argon2id });
const result = await pool
  .request()
  .input('id', sql.NVarChar(128), randomUUID())
  .input('email', sql.NVarChar(320), email)
  .input('passwordHash', sql.NVarChar(512), passwordHash)
  .query(`IF NOT EXISTS (SELECT 1 FROM dbo.Users WHERE Email = @email)
    INSERT dbo.Users (Id, Email, PasswordHash, RolesCsv, IsActive) VALUES (@id, @email, @passwordHash, N'admin', 1);
    SELECT Id FROM dbo.Users WHERE Email = @email;`);
console.log(
  `Demo account ready: ${result.recordset[0].Id} (${email}). Existing account was left unchanged.`
);
await pool.close();
