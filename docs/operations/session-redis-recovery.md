# Session Redis recovery

Redis is the authoritative live-session store. A missing session requires sign-in again. Redis replication and snapshots can also restore stale state, so an uncertain failover or rollback requires a fresh namespace before traffic resumes.

1. Close auth and resource traffic at the load balancer and drain every replica. Disable automatic restarts that would bring an old `SESSION_NAMESPACE` back into service.
2. Confirm which Redis primary and persistence state will be retained. If acknowledged writes may have been lost or rolled back, do not trust its session keys.
3. Choose a new, unique `SESSION_NAMESPACE` value and set it on every auth and resource replica.
4. Start the new replicas. Their Redis keys use only the new namespace; the old sessions cannot authorize requests there. Check `/health/ready` on every replica.
5. Reopen traffic only after every old replica is stopped and every new replica is ready. Users with sessions in the old namespace sign in again.

Do not rotate the namespace for an ordinary short Redis command timeout unless the failure may have rolled back or restored Redis state. During any uncertain failover, keep traffic closed until the namespace change is complete. This operational barrier is necessary because Redis asynchronous replication alone cannot prove that an acknowledged logout survived failover.
