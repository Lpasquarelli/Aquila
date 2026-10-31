USE aquila;
GO
BEGIN TRANSACTION;
IF OBJECT_ID(N'dbo.UsedRefreshTokens', N'U') IS NOT NULL DROP TABLE dbo.UsedRefreshTokens;
IF OBJECT_ID(N'dbo.Sessions', N'U') IS NOT NULL DROP TABLE dbo.Sessions;
COMMIT TRANSACTION;
GO
