import { Cluster, Redis } from 'ioredis';

export type RedisClient = Redis | Cluster;
export type RedisClusterNode = { host: string; port: number };

const standaloneOptions = {
  lazyConnect: true,
  connectTimeout: 1000,
  commandTimeout: 800,
  maxRetriesPerRequest: 1,
  enableOfflineQueue: false,
  autoResendUnfulfilledCommands: false,
};

export function createRedisClient(url: string, clusterNodes?: RedisClusterNode[]): RedisClient {
  if (clusterNodes?.length) {
    const connection = new URL(url);
    const tls = connection.protocol === 'rediss:' ? { tls: {} } : {};
    const credentials = connection.username || connection.password ? {
      ...(connection.username ? { username: decodeURIComponent(connection.username) } : {}),
      ...(connection.password ? { password: decodeURIComponent(connection.password) } : {}),
    } : {};
    return new Cluster(clusterNodes, {
      lazyConnect: true,
      enableOfflineQueue: false,
      scaleReads: 'master',
      maxRedirections: 2,
      retryDelayOnFailover: 25,
      retryDelayOnClusterDown: 25,
      retryDelayOnTryAgain: 25,
      clusterRetryStrategy: (attempt) => Math.min(attempt * 100, 1000),
      redisOptions: {
        connectTimeout: 1000,
        commandTimeout: 800,
        maxRetriesPerRequest: 1,
        autoResendUnfulfilledCommands: false,
        ...tls,
        ...credentials,
      },
    });
  }
  return new Redis(url, standaloneOptions);
}
