# Phase 8: Multi-Layer Test Suite

**Plan Phase:** 9 (Tests)

## Objective

Build a comprehensive, Nix-native test suite (`tests/`) with four layers: eval checks, build checks, VM integration tests, and fleet integration tests. The test harness uses QEMU with a custom virtio-serial guest agent for structured communication -- inspired by Guix's marionette but simpler (shell-based, not Guile). All tests are Nix derivations built via `nix-build -A checks` or `aos test`.

## Prerequisites

- Phase 1-4 complete: Packages build, systems evaluate, images boot
- Phase 6-7 complete: Modules produce system configs, K8s images are functional
- QEMU available on build machines
- Understanding of virtio-serial guest communication

## Deliverables

### Test Infrastructure

- `tests/default.nix` -- Test entry point (composes all layers)
- `tests/eval.nix` -- Layer 1: all configs evaluate without error
- `tests/build.nix` -- Layer 2: key packages build successfully, closure size bounds
- `tests/vm/lib.nix` -- QEMU test harness with virtio-serial guest agent
- `tests/fleet/lib.nix` -- Multi-VM orchestrator with socket networking

### VM Test Suites (`tests/vm/`)

- `tests/vm/default.nix` -- VM test entry point
- `tests/vm/boot.nix` -- Boot to multi-user, systemd healthy, no failed units
- `tests/vm/immutability.nix` -- Read-only root, ZFS /var writable, overlay /etc, tmpfs
- `tests/vm/security.nix` -- SELinux enforcing, audit rules, nftables, sysctl hardening
- `tests/vm/networking.nix` -- systemd-networkd, DNS, chrony, SSH
- `tests/vm/kubernetes.nix` -- containerd, kubelet, CNI plugins, crictl
- `tests/vm/update.nix` -- Update agent, health check, boot counting, rollback

### Fleet Test Suites (`tests/fleet/`)

- `tests/fleet/default.nix` -- Fleet test entry point
- `tests/fleet/lib.nix` -- Multi-VM orchestrator
- `tests/fleet/k8s-cluster.nix` -- Boot control-plane + worker, kubeadm join, pod scheduling
- `tests/fleet/rolling-update.nix` -- Simulate fleet update with health checks + rollback

## Detailed Task Checklist

### 8.1 Eval Checks (Layer 1)

Pure Nix evaluation, no VM needed. Runs in <1 second.

- [ ] Write `tests/eval.nix`:
  - [ ] All four system variants evaluate without error (base, server, k8s-worker, k8s-control-plane)
  - [ ] All options have valid types and satisfy constraints
  - [ ] No undefined references, no infinite recursion
  - [ ] Option types are correctly checked (bool, int, str, listOf, etc.)
- [ ] Accessible via: `aos test eval` / `nix-build -A checks.eval`

### 8.2 Build Checks (Layer 2)

Verify key packages build. Standard `nix-build` derivations.

- [ ] Write `tests/build.nix`:
  - [ ] Spot-check critical packages: kernel, systemd, kubelet, containerd
  - [ ] Verify store closure sizes are within bounds (catch accidental bloat)
  - [ ] Verify no runtime references to build-only deps (e.g., GCC not in runtime closure of coreutils)
- [ ] Accessible via: `aos test build` / `nix-build -A checks.build`

### 8.3 VM Test Harness (`tests/vm/lib.nix`)

Custom Nix-native test harness -- ~500 lines of Nix + shell + a tiny guest agent.

- [ ] Write `tests/vm/lib.nix` defining `mkVMTest`:
  - [ ] Input: `{ name; image; testScript; timeout; }`
  - [ ] Output: Nix derivation (test passes = derivation succeeds)
  - [ ] Build the AOS image with the guest agent injected
  - [ ] Boot in QEMU with:
    - [ ] `-device virtio-serial -device virtserialport,chardev=agent,name=aos.test.agent`
    - [ ] QEMU monitor socket for VM control
    - [ ] OVMF UEFI firmware
    - [ ] KVM acceleration
  - [ ] Wait for guest agent to send `ready` over virtio-serial
  - [ ] Run test commands via the agent
  - [ ] Agent returns structured JSON: `{"exit_code": 0, "stdout": "...", "stderr": "..."}`
  - [ ] Each assertion: shell command + expected result
  - [ ] Capture serial log + agent transcript as build output for debugging
  - [ ] Timeout kills hung VMs (default 120s)

### 8.4 Guest Agent

The guest agent is a lightweight shell script injected into the test image:

- [ ] Opens `/dev/virtio-ports/aos.test.agent`
- [ ] Reads newline-delimited shell commands from the virtio serial port
- [ ] Executes each command
- [ ] Returns JSON result: `{"exit_code": N, "stdout": "...", "stderr": "..."}`
- [ ] No Guile dependency (unlike Guix marionette) -- pure shell
- [ ] No SSH/network needed -- works before networking is configured
- [ ] Deterministic: no network timing variability

### 8.5 VM Test Suites

- [ ] `tests/vm/boot.nix`:
  - [ ] `systemctl is-system-running` returns `running` (not `degraded`)
  - [ ] No failed systemd units
  - [ ] Correct kernel version via `uname -r`
  - [ ] `/etc/os-release` shows correct ANDYL OS fields
  - [ ] cgroups v2 unified hierarchy is active
- [ ] `tests/vm/immutability.nix`:
  - [ ] `/nix/store` is mounted read-only (write attempt fails)
  - [ ] `/var` is writable (write + read-back succeeds)
  - [ ] `/etc` is an overlay mount
  - [ ] `/tmp` and `/run` are tmpfs
  - [ ] Changes to `/etc` persist across reboot
  - [ ] Changes to `/var/lib` persist across reboot
- [ ] `tests/vm/security.nix`:
  - [ ] SELinux is loaded and in enforcing (or permissive) mode
  - [ ] Audit rules are active
  - [ ] nftables rules are applied (default deny inbound)
  - [ ] sysctl hardening values set (kptr_restrict, dmesg_restrict, etc.)
- [ ] `tests/vm/networking.nix`:
  - [ ] systemd-networkd is up, interfaces have addresses
  - [ ] DNS resolves (`getent hosts`)
  - [ ] chrony is syncing (or attempting to sync)
  - [ ] SSH accepts connections with only allowed ciphers
- [ ] `tests/vm/kubernetes.nix`:
  - [ ] containerd socket present (`/run/containerd/containerd.sock`)
  - [ ] kubelet is running
  - [ ] `crictl info` succeeds
  - [ ] CNI plugins installed at `/opt/cni/bin/`
  - [ ] Kernel modules loaded: overlay, br_netfilter
- [ ] `tests/vm/update.nix`:
  - [ ] update-check timer is active
  - [ ] health-check service runs successfully
  - [ ] Boot counting works (systemd-bless-boot)

### 8.6 Fleet Test Harness (`tests/fleet/lib.nix`)

Multi-VM orchestrator inspired by NixOS VLan abstraction.

- [ ] Write `tests/fleet/lib.nix` defining `mkFleetTest`:
  - [ ] Input: `{ name; machines; testScript; }`
  - [ ] `machines`: attrset of `{ role; image; }` definitions
  - [ ] Boot multiple QEMU VMs connected via QEMU socket networking (`-netdev socket,listen/connect`)
  - [ ] Each machine has its own virtio-serial agent
  - [ ] Machines can communicate over the virtual network
  - [ ] Assertions run against individual machines and the cluster as a whole

### 8.7 Fleet Test Suites

- [ ] `tests/fleet/k8s-cluster.nix`:
  - [ ] Boot 1 control-plane + 1 worker
  - [ ] `kubeadm init` on control plane
  - [ ] `kubeadm join` on worker
  - [ ] Both nodes reach Ready state (after CNI deployment)
  - [ ] Schedule a test pod; verify it reaches Running
- [ ] `tests/fleet/rolling-update.nix`:
  - [ ] Simulate a fleet update: new image, health check pass
  - [ ] Old generation cleaned up
  - [ ] Simulate failure: health check fails -> automatic rollback

### 8.8 Test CLI Integration

```
aos test                       Run all test layers (eval -> build -> vm -> fleet)
aos test eval                  Run eval checks only
aos test build                 Run build checks only
aos test vm [suite]            Run VM tests (all or specific suite)
aos test fleet [suite]         Run fleet tests (all or specific suite)
```

All test layers are accessible as:
- `nix-build -A checks` (all)
- `nix-build -A checks.eval` (eval only)
- `nix-build -A checks.vm.boot` (specific VM test)
- `nix-build -A checks.fleet.k8s-cluster` (specific fleet test)

### 8.9 Verification

- [ ] `aos test eval` passes in <1 second
- [ ] `aos test build` verifies critical packages build and closure sizes
- [ ] `aos test vm` runs all six VM test suites
- [ ] `aos test fleet` runs both fleet test suites
- [ ] `aos test` runs all four layers end-to-end
- [ ] Test failures produce detailed logs (serial output, agent transcript)
- [ ] Tests run with KVM acceleration on Linux

## Acceptance Criteria

1. Eval checks verify all system variants evaluate without error
2. Build checks verify key packages build and closure sizes are within bounds
3. VM tests boot actual AOS images and verify system behavior via virtio-serial agent
4. Fleet tests boot multiple VMs and verify multi-machine scenarios (k8s cluster, rolling update)
5. Guest agent returns structured JSON responses (not raw serial output parsing)
6. Tests complete within 30 minutes total (eval <1s, build <5min, vm <15min, fleet <10min)
7. Test failures produce actionable debug output (serial log, agent transcript)
8. All tests are Nix derivations accessible via `nix-build -A checks`

## Key Design Decisions

### Why Custom, Not Adopting Existing Frameworks

- **NixOS VM tests**: Tightly coupled to nixpkgs module system internals
- **Guix marionette**: Requires Guile in the guest (we use shell)
- **Kola** (CoreOS): Tightly coupled to CoreOS internals (Ignition v3, coreos-assembler)
- All three would be heavy dependencies contradicting the "no nixpkgs" principle

### Virtio-Serial Guest Agent (from Guix Marionette)

The key insight: communicate with the guest via virtio-serial, not SSH:
- Works before networking is configured (during early boot)
- No authentication overhead (no SSH keys, no TLS)
- Deterministic: no network timing variability
- Works even if firewall blocks all ports

Our implementation is simpler than Guix's: a shell script instead of a Guile REPL, returning structured JSON instead of Scheme expressions.

### Tests Are Nix Derivations

Every test is a standard Nix derivation. Test success = derivation builds. This means:
- Tests are cached by Nix (unchanged tests aren't re-run)
- Tests run in the Nix sandbox (reproducible environment)
- CI just runs `nix-build -A checks`

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| VM tests are inherently slow | High | Long feedback loop | Cache test results via Nix; parallel execution |
| Flaky tests due to timing (K8s readiness, NTP sync) | High | False failures | Polling with generous timeouts; structured JSON responses avoid parsing errors |
| Guest agent has bugs | Medium | Tests report wrong results | Keep agent minimal (~50 lines of shell); test the agent itself |
| QEMU + OVMF firmware availability | Medium | Tests can't boot UEFI | Package OVMF as a test dependency |
| Fleet tests are complex (multi-VM networking) | High | Hard to debug | Capture per-machine serial logs; test simple scenarios first |
