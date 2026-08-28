# Runtime package-module coverage

This file is the implementation checklist for production packages that need
operator-owned runtime configuration. A package is in scope when it is an
independently installable workload whose enablement, files, credentials,
topology, or integrations must be changed without rebuilding the image.

Boot-critical and global host policy remains owned by the ordinary dendritic
host modules. Libraries, command-line tools, subordinate binaries, and
per-instance processes do not gain singleton services merely because their
upstream distribution includes a daemon.

## Package-owned services

- [x] nginx
- [x] Envoy
- [x] k3s worker, control-plane, and combined roles
- [x] AOS registry server
- [x] containerd standalone role
- [ ] kubelet standalone role
- [x] etcd
- [x] PostgreSQL
- [x] MariaDB
- [x] Garage
- [x] OpenLDAP server role
- [ ] KubeEdge CloudCore
- [ ] KubeEdge EdgeCore
- [ ] Kerberos KDC role
- [ ] conntrackd role
- [x] rsync daemon role

Each checked service must provide typed options, explicit enablement, generated
artifacts, opaque credential references where needed, exact expose policy,
validation, documentation, and focused lifecycle coverage.

## Composable integration packages

- [ ] Shared versioned Kubernetes resource/addon interface
- [ ] Cilium integration package
- [ ] Longhorn integration package spanning manager, engine, and instance
      manager
- [ ] Concrete nginx site/profile contributor acceptance coverage

Integration packages own their package-prefixed roots and may write only to an
owner-advertised contribution surface. They never enable the owning service or
write its global policy.

## Existing system-owned interfaces

These remain configurable through the platform `host.nix` and supplemental
runtime modules. They must not acquire a competing package artifact owner:

- OpenSSH and opkssh
- chrony
- smartd and watchdog policy
- auditd and kernel audit policy
- nftables and the global firewall
- SELinux and eBPF-LSM policy
- DBus, systemd-networkd, and systemd-resolved
- ZFS, root storage, verity, repart, initrd, and boot recovery
- AOS evaluator, activation, attestation, metadata, and recovery services

The AOS registry hub remains system-owned, but its existing module must expose
all required credential and listener inputs rather than relying on fleet-test
unit overrides.

## Intentionally static or subordinate payloads

No singleton package module is added for CLIs, libraries, build helpers,
security helpers, QEMU, Firecracker, swtpm, Crucible, runc, CNI binaries, or the
raw k3s payload. Those are invoked by an owning service, orchestration resource,
or existing system module.

## Acceptance baseline

Every new service or integration must cover:

1. signed system installation and explicit runtime enablement;
2. real config validation and a health/data-path assertion;
3. replacement or reload with an invalid candidate leaving the active
   generation untouched;
4. reboot replay and rollback of the immutable runtime module set;
5. credential absence and rotation without secret bytes entering Nix inputs;
6. exact ownership, contribution ABI, and foreign-authority rejection;
7. state-retention and uninstall behavior.

Distributed products additionally require multi-machine readiness or join
coverage. Repository-wide completion is gated by the runtime configuration
aggregate, package expose/security checks, and all registered package VM tests.
