# Campaign owner and host setup

This page covers starting the single-host campaign owner, attaching
planner runtimes and executors, and the packaged-executor deployment
file and host resources that local QEMU execution requires. It is part
of [Operating lazy campaigns](campaigns.md).

## Start the single-host owner

The campaign endpoint is a managed Unix socket. Its state directory, peer
policy, optional component authority keys, and any initial imports must be fixed
before the socket becomes visible. Without `--campaign-store`, the owner keeps
immutable objects in `STATE/objects/objects.sqlite3` (with SQLite journal files
when present) and refs in `STATE/refs`, where `STATE` is `--campaign-state`.
Startup reopens an existing SQLite state directory. It rejects a directory-leaf
layout under `STATE/objects`, even if that layout contains only inventory
state; it does not convert the layout in place. Starting the built-in profile
after directory-leaf use requires a separate state directory.

This control-only setup creates a policy for the current Unix peer and exercises
creation, inspection, derivation, and lifecycle mutations without planner or
debugger component authority:

```sh
aos-dev build package jq -o result-jq

FLIGHT="$(mktemp -d)"
install -d -m 700 "$FLIGHT/state" "$FLIGHT/socket"
UID_NOW="$(id -u)"
GID_NOW="$(id -g)"
cat >"$FLIGHT/campaign-peers.toml" <<EOF
schema = "crucible.campaign-local-policy"
version = 1

[[bindings]]
user_id = $UID_NOW
group_id = $GID_NOW
principal = "operator"

[[grants]]
principal = "operator"
operation = "create-campaign"
campaign = "*"

[[grants]]
principal = "operator"
operation = "derive-campaign"
campaign = "*"

[[grants]]
principal = "operator"
operation = "get-campaign"
campaign = "*"

[[grants]]
principal = "operator"
operation = "get-campaign-status"
campaign = "*"

[[grants]]
principal = "operator"
operation = "query-campaign-report"
campaign = "*"

[[grants]]
principal = "operator"
operation = "get-campaign-snapshot"
campaign = "*"

[[grants]]
principal = "operator"
operation = "list-campaigns"
campaign = "*"

[[grants]]
principal = "operator"
operation = "apply-campaign-command"
campaign = "*"
EOF
chmod 600 "$FLIGHT/campaign-peers.toml"

./result/bin/crucible campaign fixture worked-network \
  --output "$FLIGHT/fixture" --format json

start_campaign_server() {
  ./result/bin/crucible serve \
    --listen 127.0.0.1:0 \
    --trusted-unauthenticated-bind \
    --campaign-socket "$FLIGHT/socket/campaign.sock" \
    --campaign-state "$FLIGHT/state" \
    --campaign-policy "$FLIGHT/campaign-peers.toml" \
    --campaign-import-manifest "$FLIGHT/fixture/import.toml" \
    >"$FLIGHT/serve.log" 2>&1 &
  SERVER_PID=$!

  READY_ATTEMPTS=100
  while ! ./result/bin/crucible campaign \
    --socket "$FLIGHT/socket/campaign.sock" \
    --principal operator list --limit 1 --pages 1 --format json \
    >/dev/null 2>&1; do
    READY_ATTEMPTS=$((READY_ATTEMPTS - 1))
    if ! kill -0 "$SERVER_PID" 2>/dev/null || [ "$READY_ATTEMPTS" -eq 0 ]; then
      kill "$SERVER_PID" 2>/dev/null || true
      wait "$SERVER_PID" 2>/dev/null || true
      cat "$FLIGHT/serve.log" >&2
      return 1
    fi
    sleep 0.1
  done
}

campaign() {
  ./result/bin/crucible campaign \
    --socket "$FLIGHT/socket/campaign.sock" \
    --principal operator "$@"
}

start_campaign_server
```

The readiness loop probes the service instead of treating socket existence as
readiness. The daemon owns stale-socket recovery; do not remove its socket by
hand. Run the daemon and the client commands from the same login context so
their kernel credentials continue to match the policy's UID/GID binding.

Continue in that shell to create a source campaign, derive an independent head,
and drive the source through start and pause. Each mutation consumes the exact
snapshot returned by the preceding accepted operation. The fixed 64-digit
command values are idempotency keys; use a new value for each new mutation:

```sh
JQ=./result-jq/bin/jq
START_COMMAND=1111111111111111111111111111111111111111111111111111111111111111
STALE_COMMAND=2222222222222222222222222222222222222222222222222222222222222222
PAUSE_COMMAND=3333333333333333333333333333333333333333333333333333333333333333
RESUME_COMMAND=4444444444444444444444444444444444444444444444444444444444444444

campaign create flight-source \
  --lineage "$FLIGHT/fixture/lineage.bin" \
  --policy "$FLIGHT/fixture/policy.bin" \
  --format json >"$FLIGHT/create.json"
SOURCE_CREATED="$($JQ -er '.snapshot' "$FLIGHT/create.json")"

campaign derive flight-source --snapshot "$SOURCE_CREATED" flight-derived \
  --format json >"$FLIGHT/derive.json"
DERIVED_SNAPSHOT="$($JQ -er '.new_snapshot' "$FLIGHT/derive.json")"
campaign snapshot flight-derived --snapshot "$DERIVED_SNAPSHOT" --format json \
  >"$FLIGHT/derived-snapshot.json"

campaign start flight-source \
  --expected "$SOURCE_CREATED" --command "$START_COMMAND" \
  --format json >"$FLIGHT/start.json"
SOURCE_RUNNING="$($JQ -er '.new_snapshot' "$FLIGHT/start.json")"

if campaign pause flight-source \
  --expected "$SOURCE_CREATED" --command "$STALE_COMMAND" \
  --format json >"$FLIGHT/stale.json" 2>"$FLIGHT/stale.err"; then
  echo "stale campaign mutation was unexpectedly accepted" >&2
  exit 1
fi
case "$(cat "$FLIGHT/stale.err")" in
  *"campaign request used stale snapshot"*) ;;
  *)
    echo "campaign mutation failed for a reason other than a stale snapshot" >&2
    cat "$FLIGHT/stale.err" >&2
    exit 1
    ;;
esac

campaign pause flight-source \
  --expected "$SOURCE_RUNNING" --command "$PAUSE_COMMAND" \
  --format json >"$FLIGHT/pause.json"
SOURCE_PAUSED="$($JQ -er '.new_snapshot' "$FLIGHT/pause.json")"
```

Stop the owner cleanly, restart it over the same state directory, and repeat
the pause request to prove idempotent recovery before resuming from the current
paused snapshot:

```sh
kill "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
start_campaign_server

campaign list --limit 32 --pages 1 --format json >"$FLIGHT/list-after-restart.json"
campaign status flight-source --format json >"$FLIGHT/status-after-restart.json"

campaign pause flight-source \
  --expected "$SOURCE_RUNNING" --command "$PAUSE_COMMAND" \
  --format json >"$FLIGHT/pause-replay.json"
REPLAYED_PAUSED="$($JQ -er '.new_snapshot' "$FLIGHT/pause-replay.json")"
test "$REPLAYED_PAUSED" = "$SOURCE_PAUSED"

campaign resume flight-source \
  --expected "$SOURCE_PAUSED" --command "$RESUME_COMMAND" \
  --format json >"$FLIGHT/resume.json"
SOURCE_RESUMED="$($JQ -er '.new_snapshot' "$FLIGHT/resume.json")"
campaign snapshot flight-source --snapshot "$SOURCE_RESUMED" --format json \
  >"$FLIGHT/resumed-snapshot.json"

kill "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
```

`create` reports `.snapshot`; `derive` and lifecycle mutations report
`.new_snapshot`. A request with a fresh command ID and an old `--expected`
snapshot is stale and must fail, while replaying the exact old command after a
restart returns its original accepted head. The readiness loop makes at most
100 service probes and prints the server log instead of waiting forever; each
probe remains subject to the client's own transport deadline.

For a fixed installation, use private state and socket directories and the
default owner-only socket mode:

```sh
./result/bin/crucible serve \
  --listen 127.0.0.1:9443 \
  --trusted-unauthenticated-bind \
  --campaign-socket /run/user/1000/crucible/campaign.sock \
  --campaign-state ./campaign-state \
  --campaign-policy ./campaign-peers.toml \
  --campaign-import-manifest ./worked-network-fixture/import.toml
```

The listener authenticates the kernel peer credentials and then applies the
configured principal policy. A principal string in a request is not
authentication by itself. The optional component-authority file is a
mode-`0600`, exact 72-byte binary record (`CRUCCA01`, one nonzero 32-byte
planner key, then one distinct nonzero 32-byte debugger key); it is not TOML.
Supply it as `--campaign-component-authority ./campaign-authority.bin` only when
attaching planner/runtime or debugger components.

To attach the long-lived canonical planner/runtime, also supply an existing
campaign and authenticated executor socket:

```text
--campaign-runtime CAMPAIGN
--campaign-executor-socket PATH
```

The executor socket must already be owned with the required strict permissions
and must advertise a compatibility profile and resource ceiling that admit the
campaign lineage. Attachment fails before planner-basis publication when those
facts disagree.

Packaged mode may instead select the complete authenticated local catalog with
`--campaign-runtime-all`. Discovery reads one stable page and fails closed when
the catalog is empty or contains more than 256 campaigns; it never silently
truncates the startup set.

Embedded deployments may retain the service's bounded post-bind attachment
handle and supply either an already connected, authenticated executor stream or
the same exact endpoint capability used at startup. The latter authenticates
the secure parent namespace, socket owner/mode and before/after inode, and peer
credentials under a finite absolute connect deadline after reserving the
campaign and one of 256 runtime slots. The handle carries neither repository
nor component-authority access and closes with the service owner. The
authenticated local listener exposes the same bounded capability to an exact
authorized principal. Attach after bind with:

```sh
crucible campaign \
  --socket /run/user/1000/crucible/campaign.sock \
  --principal operator \
  attach CAMPAIGN \
  --executor-socket /run/user/1000/crucible/executor.sock
```

The result reports whether the request installed a runtime or exactly replayed
one, the request digest, and the current attached-runtime count. Exact replay
does not reconnect to the executor. A changed endpoint for an already attached
campaign fails as command reuse rather than replacing the live runtime.

To let the same daemon own that executor, add `--production-qemu` and an
owner-only packaged-executor deployment file:

```sh
./result/bin/crucible serve \
  --listen 127.0.0.1:9443 \
  --trusted-unauthenticated-bind \
  --production-qemu \
  --campaign-socket /run/user/1000/crucible/campaign.sock \
  --campaign-state ./campaign-state \
  --campaign-policy ./campaign-peers.toml \
  --campaign-component-authority ./campaign-authority.bin \
  --campaign-runtime-all \
  --campaign-executor-socket /run/user/1000/crucible/executor.sock \
  --campaign-packaged-executor ./campaign-executor.toml
```

All packaged-mode runtime entries name the same executor socket and share its
fixed workers and aggregate resource ceiling. The daemon sorts and
authenticates the complete campaign set before acquiring QEMU host resources.
Every campaign must have the same exact Crucible/QEMU compatibility profile.
Distinct scenario artifacts are decoded under a 128 MiB aggregate canonical-
body limit before host acquisition, receive separate native baked-genesis
entries, and route exact promotion by World/scenario identity. A later dynamic
attachment through the packaged endpoint must use a scenario already present
in that startup catalog; otherwise restart with the enlarged catalog or use a
separate pool. The durable store locality derives from `--campaign-state`, so
reordering or adding a compatible campaign does not change the pool identity.

Packaged CLI mode defaults to a scheduler rendezvous every 1,000,000 exact
simulation ticks. This caps each RUN without reducing the terminal run ceiling,
allowing condition evaluation, checkpoint requests, and resource checks between
slices. `--qemu-rendezvous-ticks N` explicitly overrides the interval; ordinary
non-packaged sessions retain their existing default. Keep the chosen execution
settings stable when replaying a campaign. A larger interval trades fewer host
handshakes for slower boundary-level control. Existing quantum budgets still
apply; this is a virtual-time bound, not a wall-clock response guarantee.

The version-2 deployment file is strict TOML, must be an exact-owner regular
file with mode `0600`, and is bounded to 64 KiB:

```toml
schema = "crucible.campaign-packaged-executor"
version = 2
cgroup_root = "/sys/fs/cgroup/crucible"
run_root = "/var/lib/crucible/attempts"
attempt_namespace = "campaign-local"
first_project_id = 10000
project_id_count = 4
child_user_id = 2000
child_group_id = 2000
maximum_tasks = 64
maximum_inodes = 4096
finish_timeout_ms = 30000
maximum_slots = 2
maximum_vcpus = 4
maximum_resident_bytes = 1073741824
maximum_disk_bytes = 2147483648
maximum_execution_quanta = 100000
verify_determinism_findings = true
maximum_checkpoint_bytes = 1073741824
worker_count = 2
host_architecture = "x86_64"
qemu_profile = "deterministic-tcg-v1"

[operations]
listener_workers = 4
pending_connections = 16
requests_per_connection = 4096
accept_poll_interval_ms = 10
exchange_read_timeout_ms = 30000
exchange_write_timeout_ms = 30000
runtime_poll_interval_ms = 100
planner_scan_limit = 1024
planner_input_bytes = 16777216
planner_fuel = 1025
executor_scan_limit = 1024
worker_slots_per_campaign = 2
```

The project-ID count must cover every slot, the worker count cannot exceed the
slot ceiling, and the checkpoint ceiling cannot exceed writable-disk capacity.
The required `operations` table defines the complete operational profile for
this pool. It bounds listener workers and backlog, requests per connection,
accept polling, read/write deadlines retained across reconnect, runtime
fallback polling, planner page/byte/fuel work, executor accounting scans, and
each campaign coordinator's worker slots. Missing or partial tables, zero
dimensions, and values outside the protocol ceilings fail before host-resource
acquisition. Set `worker_slots_per_campaign` no higher than `maximum_slots`.
`verify_determinism_findings = true` explicitly enables two private executions
of ordinary candidates. Both executions share and consume the attempt's finite
physical quantum budget; an incomplete pair does not create a finding.
The configured lifecycle run root is partitioned into stable fixed-worker
subdirectories so recovery state is not shared between concurrent workers.

The host must provide a dedicated cgroup-v2 root with the `cpu`, `memory`, and
`pids` controllers enabled for children. CPU accounting alone is insufficient:
the kernel must expose `cpu.max` (`CONFIG_CFS_BANDWIDTH`). The storage root must
be an empty, supervisor-owned mode-`0700` directory on ext4 with active project
quotas, with the configured project-ID range reserved exclusively for this
allocator. ZFS and an ordinary temporary directory do not satisfy this
contract. The AOS kernel builds in CPU bandwidth control and project-quota
support; the operator still provisions the dedicated roots and enables the
mount's project quotas. The supervisor must also be authorized to place
processes in the cgroup and switch to the distinct non-root child credentials.

`checks.crucible.phase4.qemuHostOwnerVm` exercises this boundary in a disposable
VM, including real guarded QEMU/image-helper launch and resource cleanup,
without reconfiguring the build host. It does not certify a complete campaign
or replace the complete automated recovery and release-profile matrices.

`checks.crucible.phase4.packagedCampaignVm` additionally runs public CLI
compilation, import, creation, and production service restart with real native
baked-genesis capture. It also grants budget, starts the initial discovery,
authenticates its immediate modeled terminal-success observation, and verifies
orderly shutdown. It does not certify guest-driven branching, checkpoint-pause
recovery, or hot-fork execution. Private QEMU debugger sockets are relative to each
guarded generation directory; the gateway resolves the actual returned path.

On service shutdown, the executor stops admission, signals cancellation, and
waits up to thirty seconds for semantic-worker cleanup. A `cleanup is pending`
error means unresolved work still owns its capacity, ledger, repository, and
executor endpoint lock; it is not a successful shutdown. Endpoint reuse remains
blocked until those workers finish. Permanent fail-closed retention needs
operator recovery, not deletion of the lock file or reuse of charged resources.
The thirty-second wait bounds worker cleanup, not arbitrary host filesystem I/O.
