import type { IdentityDependencies } from '../../interfaces/identity/identity.dependencies.js';
import { LoginCommand } from './login.service.js';
import { LogoutSessionCommand } from './logout-session.service.js';
import { RefreshSessionCommand } from './refresh-session.service.js';

export function createIdentityService(options: IdentityDependencies) {
  return {
    login: new LoginCommand(options),
    refresh: new RefreshSessionCommand(options),
    logout: new LogoutSessionCommand(options),
  };
}
