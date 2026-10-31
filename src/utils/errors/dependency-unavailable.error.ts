export class DependencyUnavailableError extends Error {
  readonly statusCode = 503;
  readonly code = 'dependency_unavailable';

  constructor(dependency: string, options?: ErrorOptions) {
    super(`${dependency} unavailable`, options);
    this.name = 'DependencyUnavailableError';
  }
}

export class InvalidTokenError extends Error {
  constructor() {
    super('Invalid token');
    this.name = 'InvalidTokenError';
  }
}
