# Graceful Restart & Recovery

> Part of the [AOS Cache Design](README.md)

## 15.1 Build State Persistence

In-flight builds are persisted to disk so the server can recover after restart:

```
/var/lib/aos/views/{view}/builds/{drv-hash}.json
{
  "drv": "/var/lib/aos/store/xxx-foo.drv",
  "view": "ci",
  "started_at": 1706000000,
  "status": "building",
  "pid": 12345,
  "server_instance_id": "i-abc123",
  "log_path": "/var/log/aos/builds/{drv-hash}.log"
}
```

Updated atomically (write `.tmp`, fsync, rename) at each phase transition:
`queued → building → complete/failed`.

## 15.2 Planned Restart (SIGTERM)

```
1. SIGTERM received → enter drain mode
   ├── Stop accepting new build requests (return 503)
   ├── Notify all SSE clients: event: drain {"message": "server shutting down"}
   └── Wait for in-flight builds to complete (timeout: 75s)

2. Builds complete within timeout → clean exit
   OR timeout exceeded → forced exit (systemd SIGKILL at 90s)
```

**Drain mode**: an `AtomicBool` flag checked by the build endpoint. New build
requests get 503; existing builds continue. SSE clients receive a `drain` event
so they can display a message.

## 15.3 Crash Recovery

```
1. Server restarts after crash
2. Scan /var/lib/aos/views/ for entries with status: "building"
3. For each:
   ├── Check if PID still alive → wait (with 30s timeout)
   └── Query Nix store: nix-store --query --outputs {drv}
       ├── Outputs exist → mark as "complete" (recovered)
       └── Outputs missing → mark as "failed" (build lost)
4. Reconnecting clients:
   ├── If complete: replay final event from recovered log
   └── If failed: send error event
```

The Nix store is the source of truth. If a build completed while the server
was down, the outputs exist in the store and we can recover the result.

## 15.4 Nix Daemon Restart

`nix-store --realise` communicates with the daemon via a Unix socket. If the
daemon restarts during a build:

- Subprocess retries socket connection (~60s timeout)
- Build may appear stuck (no progress for 10-30s)
- After daemon recovers, build resumes normally
- If daemon is down > 60s, subprocess fails; build marked as failed

Server monitors subprocess stderr for `"connection refused"` patterns and
sends SSE events:
```
event: daemon-unavailable
data: {"message": "Nix daemon temporarily unavailable"}

event: daemon-recovered
data: {}
```

## 15.5 systemd Integration

```ini
[Unit]
Description=AOS Remote Build Server
After=nix-daemon.service network-online.target
Requires=nix-daemon.service

[Service]
Type=notify
ExecStart=/usr/bin/aos serve --config /etc/aos/serve.toml
Restart=on-failure
RestartSec=10s

# Graceful shutdown
KillMode=mixed              # SIGTERM to main, SIGKILL to orphaned children
TimeoutStopSec=90s          # 90s drain period before force-kill

# Permissions
User=aos-serve
Group=nix-daemon
SupplementaryGroups=aos-admins
ReadWritePaths=/var/lib/aos /var/log/aos /run/aos
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

## 15.6 Client Reconnection

When a client's SSE connection drops (server restart, network glitch):

1. Client automatically reconnects with `Last-Event-ID: {N}` header
2. Server checks if build exists in `BuildManager` (in-memory) or on disk
3. If build complete: send final `complete`/`error` event from cached state
4. If build still in-flight: replay log from event N+1, then continue live
5. If build unknown (server crashed): query Nix store, report result or failure

This works transparently with the `BuildManager`'s ring buffer ([HTTP API — Build Log Streaming](03-http-api.md#build-log-streaming--deduplication)) —
replay from any checkpoint is always available.
