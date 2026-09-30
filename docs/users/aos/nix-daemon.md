# Multi-user Nix builds

`nix` provides the executable payload. Select the separate `nix-daemon` APM
package and enable its package-owned interface to run a multi-user daemon:

```nix
{
  aos.apm.desiredPackages = [ "nix-daemon" ];
  nix-daemon = {
    enable = true;
    buildUsers.count = 8;
    buildDirectory = "/var/cache/nix-build";
    settings = {
      max-jobs = 2;
      cores = 1;
      sandbox = true;
      sandbox-fallback = false;
      allowed-users = [ "*" ];
      trusted-users = [ "root" ];
      experimental-features = [ "nix-command" "flakes" ];
    };
    resources = {
      cpuQuotaCores = 2;
      memoryHigh = "50%";
      memoryMax = "70%";
      memorySwapMax = "0";
    };
    scheduling = {
      cpuPolicy = "batch";
      ioClass = "best-effort";
      ioPriority = 5;
      oomScoreAdjust = 500;
    };
    clients.enable = true;
  };
}
```

These values are the defaults except `enable`, which defaults to `false`.
Package admission requires host policy allowing privileged services. The root
daemon intentionally has an unconfined APM classification: Nix itself creates
the build sandboxes and switches to locked non-root build accounts. The service
requires an AOS image providing immutable `packageServicePolicyAbi >= 1`;
older images fail evaluation with an upgrade diagnostic.

## Configuration and clients

The canonical store is `/nix/store`; clients connect through
`/nix/var/nix/daemon-socket/socket`. The service waits for AOS Nix database
initialization and does not replace the store or recursively change ownership.
Native configuration lives in `/etc/aos/packages/nix-daemon/nix.conf`, separately
from the image-owned `/etc/nix/nix.conf`.

With `clients.enable`, new login shells export `NIX_REMOTE=daemon` and
`NIX_CONF_DIR=/etc/aos/packages/nix-daemon`. Existing shells retain their
environment. APM's privileged store management explicitly selects the local
store and baseline configuration, so configuration activation and garbage
collection do not depend on the daemon being available.

`settings` includes typed common options and accepts ordinary upstream settings
as booleans, integers, single-line strings, or lists of tokens. Names must be
lowercase kebab-case; values cannot inject comments or configuration directives.
Nix validates the upstream meaning of additional settings. The package derives
`build-users-group`, `build-dir`, and the mandatory `/bin/sh` sandbox mapping to
its signed AOS Bash dependency; those settings cannot be overridden. Explicit
`extra-sandbox-paths` are supported but cannot replace that mapping or its
ancestors. No development cache mounts, emulation platforms, or KVM capabilities
are advertised by default. Configure those only when the host provides them.

Local `max-jobs` must be between zero and `buildUsers.count`; zero is available
for remote-only builds. Remote builder specifications and experimental features
remain available. Automatic store garbage collection is off by default
(`min-free = 0`, `max-free = 0`); explicit valid thresholds can enable it.

The build directory must have trusted root-owned ancestry without symlinks or
group/other writes. The daemon prepares the final directory as root with mode
0755. Its signed unit has a narrowly validated `RequiresMountsFor` projection.
Declare a mount unit for any intended separate backing filesystem: systemd
cannot infer an undeclared disk from the directory name.

## Resource policy and restarts

The package's slice imposes aggregate CPU, memory, and swap limits on the daemon
and its build workers. CPU quota is a positive number of cores. Memory limits
accept positive byte counts, `K`/`M`/`G`/`T`, percentages from 1% through 100%,
`0`, or `infinity`. Scheduling supports CPU `other`, `batch`, or `idle`, I/O
`best-effort` or `idle`, priorities 0 through 7, and OOM scores 0 through 1000.

Signed runtime metadata binds native configuration and projected policy bytes
to transactional restarts. A policy service reconciles every resource property
on every change, including disabled generations and rollback. This resets old
runtime overrides rather than allowing them to outrank the selected policy.
The validator covers the package's authenticated direct unit drop-ins; it is
not an effective-systemd audit of root-authored overlays or inherited drop-ins.

Daemon restart stops the listener process while allowing existing Nix workers
to finish in the same resource slice. Scheduling changes affect newly started
processes. Memory policy can terminate workers under pressure; preserving
workers across a restart is not a guarantee that every build will succeed.

## Disable, drain, and remove

The signed package authorizes a fixed pool of `nixbld1` through `nixbld64`, with
UIDs 30001 through 30064 and GID 30000 for `nixbld`. The image permanently reserves
these names and numeric identities and rejects collisions or remapping. The
selected package always retains all 64 locked accounts. `buildUsers.count`
(1 through 64) controls explicit eligible group membership; reducing it does
not remove or reuse accounts while older builds continue.

1. Set `nix-daemon.enable = false` and activate the configuration. The socket
   closes and cannot activate the disabled daemon. Accounts, store contents,
   and existing workers remain.
2. Wait for builds to finish. Disable does not implement a drain request or
   cancel workers.
3. Remove `nix-daemon` from desired packages and remove its interface settings.
   Activation refuses account removal while a reserved identity is running,
   the listener/socket is active, or the worker cgroup cannot be verified.
   An empty retired inactive slice is accepted.

After successful removal, generated account entries disappear. Their numeric
identities remain reserved by the image and must not be assigned to other
accounts. Store contents and completed outputs remain; ordinary AOS store
management decides their later retention.
