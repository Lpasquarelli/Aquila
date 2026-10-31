IF DB_ID(N'aquila') IS NULL
  CREATE DATABASE aquila;
GO
USE aquila;
GO
IF OBJECT_ID(N'dbo.Users', N'U') IS NULL
BEGIN
  CREATE TABLE dbo.Users (
    Id nvarchar(128) NOT NULL CONSTRAINT PK_Users PRIMARY KEY,
    Email nvarchar(320) NOT NULL,
    PasswordHash nvarchar(512) NOT NULL,
    RolesCsv nvarchar(512) NOT NULL CONSTRAINT DF_Users_RolesCsv DEFAULT N'',
    IsActive bit NOT NULL CONSTRAINT DF_Users_IsActive DEFAULT 1,
    CONSTRAINT UQ_Users_Email UNIQUE (Email)
  );
END;
GO
