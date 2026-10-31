import { jetstreamManager } from '@nats-io/jetstream';
import { connect } from '@nats-io/transport-node';
import 'dotenv/config';

const nc = await connect({
  servers: process.env.NATS_URL ?? 'nats://localhost:4222',
  ...(process.env.NATS_USER
    ? { user: process.env.NATS_USER, pass: process.env.NATS_PASSWORD }
    : {}),
  ...(process.env.NATS_TLS === 'true'
    ? {
        tls: {
          rejectUnauthorized: true,
          ...(process.env.NATS_CA_FILE
            ? { caFile: process.env.NATS_CA_FILE }
            : {}),
        },
      }
    : {}),
});
try {
  const stream = await (
    await jetstreamManager(nc)
  ).streams.info('AQUILA_SESSION_EVENTS_V2');
  console.log(`SESSION_STREAM_CREATED=${stream.created}`);
  console.log(
    `retention_seconds=${Math.floor(stream.config.max_age / 1_000_000_000)}`
  );
} finally {
  await nc.close();
}
