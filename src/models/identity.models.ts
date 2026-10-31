export type User = {
  id: string;
  email: string;
  passwordHash: string;
  roles: string[];
  active: boolean;
};
export type Session = {
  id: string;
  userId: string;
  refreshHash: string;
  expiresAt: Date;
  absoluteExpiresAt: Date;
  createdAt: Date;
  generation: number;
};
