# Local sandboxes

A sandbox is an isolated Linux environment on one host: a `systemd-nspawn`
container with its own writable layer, resource limits, network namespace,
and a `/nix/store` that shows only the store paths it asked for. Sandboxes
serve development shells, builds, CI jobs, and automation through one CLI.

The design is specified first as a Lean model, which
[Formal model](formal-model.md) describes. The runtime binaries below are not
implemented yet; their behavior must match the model's definitions, and the
store helper must reproduce the model's conformance vectors.

## Scope

- One host. There is no coordinator, placement, or cross-host migration.
- One privileged daemon decides; small helpers act. Each helper does one job,
  keeps no state of its own, and can be rerun after a crash.
- State has two owners: systemd owns runtime state (units, cgroups, the
  freezer), and the sandbox directory owns persistent state (its spec, layers,
  and GC roots). Nothing else keeps a record that must agree with them.

## Components

| Component | Responsibility |
| --- | --- |
| `aos-sandbox` | Unprivileged CLI. Speaks only the daemon socket. |
| `aos-sandboxd` | Socket-activated root daemon. Identifies clients with `SO_PEERCRED`, authorizes, serializes requests per sandbox with `flock`, writes specs, and drives systemd. |
| `aos-sbx-rootfs` | Mounts the EROFS base image under an overlay whose upper layer sits on XFS with a per-sandbox project quota; reflink-copies the upper layer for snapshots and forks. |
| `aos-sbx-net` | Creates the network namespace, veth pair, and default-deny rules. |
| `aos-sbx-store` | Registers GC roots and keeps the sandbox's store mounts equal to the closure of its roots. |
| `aos-sbx-nixproxy` | Filters the sandbox's Nix daemon socket and exposes realized paths before replying. |
| `aos-sbx-exec` | Runs a command inside a sandbox with the client's file descriptors. |
| `aos-sbx-init` | Minimal PID 1 inside a sandbox. |

The model covers `aos-sandboxd`'s authorization and lifecycle,
`aos-sbx-store`, and `aos-sbx-nixproxy`. The other helpers have no
cross-step invariant that warrants a proof.

## The sandbox store

Each sandbox's `/nix/store` is a slave bind of a host staging directory
holding one read-only bind mount per visible store path. The host changes the
staging directory, and mount propagation applies each change inside the
running sandbox. The sandbox records *roots*; its visible store is the
closure of those roots.

Three decisions follow from the model's theorems:

- **Mount order within an update.** Doing every mount before every unmount is
  not enough, because each mount is visible as soon as it is made. Mounts go
  dependency-first and unmounts referrer-first, so no state a process can
  observe exposes a path without its references.
- **Realizing and rooting are one operation.** The helper registers a root
  through the Nix daemon's realization, which holds a temporary root while it
  builds or substitutes. Realizing first and rooting afterwards would let the
  garbage collector delete the path in between.
- **Impossible orders fail closed.** The planner refuses a graph with a
  reference cycle between distinct paths rather than mount a path before its
  dependency. A Nix store cannot contain such a cycle, and the model proves
  the planner always succeeds on any store without one.

In closure mode, builds inside a sandbox go through `aos-sbx-nixproxy`, which
forwards ordinary daemon requests, refuses requests that change daemon-wide
state, and adds each realized path to the sandbox's roots before it replies.
An open mode instead binds the whole host store read-only with the daemon
socket, as on any multi-user Nix host.
