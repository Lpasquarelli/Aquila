import 'dotenv/config';
import { loadAppConfig } from './config/app.config.js';
import { createContainer } from './config/container.js';
import { createApp } from './config/create-app.js';

const config = await loadAppConfig();
const container = await createContainer(config);
const app = await createApp({ container, config });

container.redis.on('error', (error: Error) =>
  app.log.error({ error }, 'Session Redis connection error')
);
container.rateLimitRedis.on('error', (error: Error) =>
  app.log.error({ error }, 'Rate-limit Redis connection error')
);

const close = async () => {
  await app.close();
  await container.close();
};
process.once('SIGINT', () => void close());
process.once('SIGTERM', () => void close());
await app.listen({ port: config.port, host: '0.0.0.0' });
