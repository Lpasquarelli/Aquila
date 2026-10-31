export interface IPasswordHasher {
  verify(hash: string, password: string): Promise<boolean>;
}
