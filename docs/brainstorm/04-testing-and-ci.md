# 04 - Testing and Build Infrastructure

## Overview

This document covers the testing architecture for AOS: building packages natively with
Nix (no Docker), a four-layer test suite (eval, build, VM, fleet), a custom VM test
harness using virtio-serial for structured guest communication, and CLI test integration.

---

## Table of Contents

- [1. Four-Layer Test Architecture](#1-four-layer-test-architecture)
- [2. Eval Tests (Layer 1)](#2-eval-tests-layer-1)
- [3. Build Tests (Layer 2)](#3-build-tests-layer-2)
- [4. VM Integration Tests (Layer 3)](#4-vm-integration-tests-layer-3)
- [5. Fleet Tests (Layer 4)](#5-fleet-tests-layer-4)
- [6. VM Test Harness: virtio-serial Guest Agent](#6-vm-test-harness-virtio-serial-guest-agent)
- [7. CLI Test Integration](#7-cli-test-integration)

---

## 1. Four-Layer Test Architecture

AOS uses a layered test architecture where each layer builds on the previous,
providing progressively deeper verification:

```
Layer 1: Eval   — Pure Nix evaluation (no builds, no VMs, < 1 second)
Layer 2: Build  — Package build verification (minutes)
Layer 3: VM     — Single-VM integration tests (boot actual images)
Layer 4: Fleet  — Multi-VM orchestration tests (k8s cluster, rolling update)
```

All layers are Nix derivations, orchestrated by `tests/default.nix`:

```nix
# tests/default.nix — AOS test suite entry point
{ pkgs, lib }:

let
  mkSystem = modules: lib.evalModules {
    modules = modules ++ import ../modules/module-list.nix;
    inherit pkgs lib;
  };

  systems = {
    base = mkSystem [ ../systems/base.nix ];
    server = mkSystem [ ../systems/server.nix ];
    k8s-worker = mkSystem [ ../systems/k8s-worker.nix ];
    k8s-control-plane = mkSystem [ ../systems/k8s-control-plane.nix ];
  };
in {
  eval = import ./eval.nix { inherit pkgs lib systems; };
  build = import ./build.nix { inherit pkgs lib; };
  vm = import ./vm { inherit pkgs lib systems; };
  fleet = import ./fleet { inherit pkgs lib systems; };
}
```

### Running Tests

```
aos test                    # Run all four layers
aos test eval               # Layer 1 only (fast)
aos test build              # Layer 2 only
aos test vm                 # Layer 3 only (all VM suites)
aos test vm boot            # Single VM suite
aos test fleet              # Layer 4 only
aos test fleet k8s-cluster  # Single fleet suite
```

Under the hood, each maps to:
```
nix-build default.nix -A checks           # All layers
nix-build default.nix -A checks.eval      # Layer 1
nix-build default.nix -A checks.vm.boot   # Specific suite
```

---

## 2. Eval Tests (Layer 1)

### Purpose

Verify that all system configurations evaluate without error. This catches:
- Typos in module option names
- Type mismatches (string where int expected)
- Missing required options
- Infinite recursion in module evaluation
- Undefined references

### Implementation

```nix
# tests/eval.nix
{ pkgs, lib, systems }:

let
  # Test that a system evaluates successfully
  evalCheck = name: system:
    pkgs.mkDerivation {
      pname = "aos-eval-check-${name}";
      version = "0";
      src = null;
      phases = [{
        name = "check";
        script = ''
          # If we get here, evaluation succeeded (Nix is lazy,
          # so we must force evaluation of the config)
          echo "System '${name}' evaluated successfully"

          # Verify key config attributes exist
          test -n "${system.config.aos.system.variant}"
          test -n "${system.config.aos.system.version}"

          mkdir -p $out
          echo "PASS" > $out/result
        '';
      }];
    };
in {
  base = evalCheck "base" systems.base;
  server = evalCheck "server" systems.server;
  k8s-worker = evalCheck "k8s-worker" systems.k8s-worker;
  k8s-control-plane = evalCheck "k8s-control-plane" systems.k8s-control-plane;
}
```

### Speed

Eval tests run in under 1 second — they only exercise the Nix evaluator, no builds,
no network, no VMs. This makes them suitable for pre-commit hooks.

---

## 3. Build Tests (Layer 2)

### Purpose

Verify that critical packages build successfully and that system closures are within
acceptable size limits. This catches:
- Build failures in key packages
- Accidental dependency bloat (e.g., pulling in X11 libraries)
- Runtime references to build-only dependencies

### Implementation

```nix
# tests/build.nix
{ pkgs, lib }:

let
  # Verify a package builds
  buildCheck = name: pkg:
    pkgs.mkDerivation {
      pname = "aos-build-check-${name}";
      version = "0";
      src = null;
      phases = [{
        name = "check";
        script = ''
          # Force the package to build by referencing it
          test -d "${pkg}" || test -f "${pkg}"
          echo "Package '${name}' builds successfully"
          mkdir -p $out
          echo "PASS" > $out/result
        '';
      }];
    };

  # Verify no runtime references to build-only deps
  noRuntimeRef = name: pkg: buildDep:
    pkgs.mkDerivation {
      pname = "aos-no-runtime-ref-${name}";
      version = "0";
      src = null;
      phases = [{
        name = "check";
        script = ''
          refs=$(nix-store --query --references "${pkg}")
          if echo "$refs" | grep -q "${buildDep}"; then
            echo "FAIL: ${name} has runtime reference to build-only dep ${buildDep}"
            exit 1
          fi
          echo "PASS: ${name} has no runtime reference to ${buildDep}"
          mkdir -p $out
          echo "PASS" > $out/result
        '';
      }];
    };

in {
  # Critical packages must build
  kernel = buildCheck "linux" pkgs.linux;
  systemd = buildCheck "systemd" pkgs.systemd;
  containerd = buildCheck "containerd" pkgs.containerd;
  kubelet = buildCheck "kubelet" pkgs.kubelet;

  # Closure size checks
  # (prevent accidental bloat)
}
```

---

## 4. VM Integration Tests (Layer 3)

### Purpose

Boot actual AOS images in QEMU and verify system behavior: service health, filesystem
immutability, security policies, networking, Kubernetes readiness, and update mechanics.

### Test Suites

```
tests/vm/
├── lib.nix             # QEMU test harness (virtio-serial guest agent)
├── boot.nix            # Boot to multi-user, systemd healthy, os-release
├── immutability.nix    # Read-only root, writable /var, overlay /etc, tmpfs
├── security.nix        # SELinux enforcing, audit rules, nftables, sysctl
├── networking.nix      # systemd-networkd, resolved, chrony, SSH
├── kubernetes.nix      # containerd, kubelet, CNI, crictl
└── update.nix          # Update agent, health check, boot counting
```

### Example: Boot Test

```nix
# tests/vm/boot.nix
{ pkgs, lib, systems }:

let
  vmLib = import ./lib.nix { inherit pkgs lib; };
in
  vmLib.mkVMTest {
    name = "boot";
    system = systems.server;
    timeout = 120;

    testScript = ''
      # Verify systemd reached multi-user.target
      assert_success "systemctl is-system-running --wait" \
        "systemd reached running state"

      # Verify no failed units
      assert_success "systemctl list-units --failed --no-legend | wc -l | grep '^0$'" \
        "no failed systemd units"

      # Verify os-release
      assert_output_contains "cat /etc/os-release" "AOS" \
        "os-release contains AOS"

      # Verify system version
      assert_output_contains "cat /etc/os-release" "VERSION=" \
        "os-release contains VERSION"

      # Verify PID 1 is systemd
      assert_output_contains "readlink /proc/1/exe" "systemd" \
        "PID 1 is systemd"
    '';
  }
```

### Example: Immutability Test

```nix
# tests/vm/immutability.nix
{ pkgs, lib, systems }:

let
  vmLib = import ./lib.nix { inherit pkgs lib; };
in
  vmLib.mkVMTest {
    name = "immutability";
    system = systems.server;

    testScript = ''
      # Root filesystem is read-only
      RESULT=$(run_in_guest "mount | grep 'on / ' | grep -c 'ro,'")
      EXIT_CODE=$(echo "$RESULT" | jq -r '.exit_code')
      if [ "$EXIT_CODE" != "0" ]; then
        echo "FAIL: root filesystem is not read-only"
        exit 1
      fi
      echo "PASS: root filesystem is read-only"

      # Cannot write to /nix/store
      assert_success "! touch /nix/store/test-write 2>/dev/null" \
        "cannot write to /nix/store"

      # /var is writable (ZFS)
      assert_success "touch /var/tmp/test-write && rm /var/tmp/test-write" \
        "/var is writable"

      # /tmp is tmpfs
      assert_output_contains "mount | grep 'on /tmp '" "tmpfs" \
        "/tmp is tmpfs"

      # /etc is overlay
      assert_output_contains "mount | grep 'on /etc '" "overlay" \
        "/etc is overlay filesystem"
    '';
  }
```

### Example: Security Test

```nix
# tests/vm/security.nix
{ pkgs, lib, systems }:

let
  vmLib = import ./lib.nix { inherit pkgs lib; };
in
  vmLib.mkVMTest {
    name = "security";
    system = systems.server;

    testScript = ''
      # SELinux is loaded and enforcing
      assert_output_contains "getenforce" "Enforcing" \
        "SELinux is enforcing"

      # Audit rules are active
      assert_success "auditctl -l | grep -c ." \
        "audit rules are loaded"

      # nftables rules are applied
      assert_success "nft list ruleset | grep -c 'chain'" \
        "nftables rules are active"

      # Sysctl hardening values
      assert_output_contains "sysctl kernel.kptr_restrict" "= 2" \
        "kptr_restrict is set to 2"
      assert_output_contains "sysctl kernel.dmesg_restrict" "= 1" \
        "dmesg_restrict is set to 1"
    '';
  }
```

---

## 5. Fleet Tests (Layer 4)

### Purpose

Test multi-machine scenarios: Kubernetes cluster formation, rolling updates with
health checks, and automatic rollback.

### Architecture

```
tests/fleet/
├── lib.nix               # Multi-VM orchestrator
├── k8s-cluster.nix       # Boot control-plane + worker, kubeadm join, pod scheduling
└── rolling-update.nix    # Simulate fleet update with health checks + rollback
```

### Multi-VM Orchestrator

```nix
# tests/fleet/lib.nix — Multi-VM orchestrator
{ pkgs, lib }:

let
  mkFleetTest = { name, machines, testScript }:
    pkgs.mkDerivation {
      pname = "aos-fleet-test-${name}";
      version = "0";

      buildPhase = ''
        # Boot multiple QEMU VMs connected via socket networking
        # Each machine has:
        #   - Its own virtio-serial agent for independent control
        #   - A role (control-plane, worker)
        #   - Its own disk image
        #   - Network connectivity to other machines

        # Launch VMs with QEMU socket networking
        # -netdev socket,listen=:PORT for the first machine
        # -netdev socket,connect=:PORT for subsequent machines

        # Each VM gets run_in_guest_N and assert_success_N helpers
        # (where N is the machine index)

        ${testScript}
      '';
    };
in { inherit mkFleetTest; }
```

### K8s Cluster Test

```nix
# tests/fleet/k8s-cluster.nix
{ pkgs, lib, systems }:

let
  fleetLib = import ./lib.nix { inherit pkgs lib; };
in
  fleetLib.mkFleetTest {
    name = "k8s-cluster";
    machines = [
      { name = "control-plane"; system = systems.k8s-control-plane; }
      { name = "worker"; system = systems.k8s-worker; }
    ];

    testScript = ''
      # Wait for both machines to boot
      wait_for_agent 0  # control-plane
      wait_for_agent 1  # worker

      # Initialize control plane
      assert_success_0 "kubeadm init --config /etc/kubernetes/kubeadm-config.yaml" \
        "kubeadm init succeeds"

      # Get join token
      JOIN_CMD=$(run_in_guest_0 "kubeadm token create --print-join-command" | jq -r '.stdout')

      # Worker joins cluster
      assert_success_1 "$JOIN_CMD" "worker joins cluster"

      # Verify nodes are Ready
      assert_output_contains_0 "kubectl get nodes" "Ready" \
        "nodes are in Ready state"

      # Schedule a test pod
      assert_success_0 "kubectl run test --image=busybox --restart=Never -- sleep 30" \
        "test pod scheduled"

      # Wait for pod to be running
      assert_output_contains_0 \
        "kubectl wait --for=condition=Ready pod/test --timeout=60s" \
        "condition met" \
        "test pod reaches Running state"
    '';
  }
```

### Rolling Update Test

```nix
# tests/fleet/rolling-update.nix
{ pkgs, lib, systems }:

let
  fleetLib = import ./lib.nix { inherit pkgs lib; };
in
  fleetLib.mkFleetTest {
    name = "rolling-update";
    machines = [
      { name = "node-1"; system = systems.server; }
      { name = "node-2"; system = systems.server; }
    ];

    testScript = ''
      # Both nodes boot with v1
      wait_for_agent 0
      wait_for_agent 1

      # Apply update to node-1
      # (simulate: copy new store paths, update boot entry)
      assert_success_0 "aos-update apply /tmp/test-bundle.tar" \
        "update applied to node-1"

      # Reboot node-1
      run_in_guest_0 "reboot"
      wait_for_agent 0  # Wait for node-1 to come back

      # Verify node-1 is running new version
      assert_output_contains_0 "cat /etc/os-release" "VERSION=0.2.0" \
        "node-1 running new version"

      # Health check passes
      assert_success_0 "systemctl is-system-running --wait" \
        "node-1 healthy after update"

      # Now update node-2
      assert_success_1 "aos-update apply /tmp/test-bundle.tar" \
        "update applied to node-2"
    '';
  }
```

---

## 6. VM Test Harness: virtio-serial Guest Agent

### Why virtio-serial (Not SSH)

The VM test harness uses QEMU virtio-serial for host-guest communication, inspired
by Guix's marionette approach. This is superior to SSH-based testing because:

- **Works before networking is configured**: Tests can run during early boot
- **No authentication overhead**: No SSH keys, no TLS handshake
- **Deterministic**: No network timing variability or retries
- **Works through firewalls**: No port exposure needed
- **Simpler**: No SSH server required in the guest

### Architecture

```
Host side:
  ┌──────────────────────────────────────────┐
  │ Test Script (Nix derivation build phase)  │
  │                                           │
  │   run_in_guest("command")                 │
  │       │                                   │
  │       ▼                                   │
  │   socat UNIX-CONNECT:agent.sock           │
  │       │                                   │
  │       ▼                                   │
  │   QEMU chardev socket (agent.sock)        │
  └──────────────────────────────────────────┘
          │
          │ virtio-serial channel
          │
  ┌──────────────────────────────────────────┐
  │ Guest side:                               │
  │                                           │
  │   /dev/virtio-ports/aos.test.agent        │
  │       │                                   │
  │       ▼                                   │
  │   aos-test-agent (shell script)           │
  │       - reads commands from port           │
  │       - executes via eval                  │
  │       - returns JSON response              │
  └──────────────────────────────────────────┘
```

### Guest Agent

The guest agent is a shell script injected into test images. It opens the virtio-serial
port and enters a read-eval-respond loop:

```
Protocol:
  Guest -> Host: {"status":"ready"}
  Host  -> Guest: <shell command string>
  Guest -> Host: {"exit_code":<int>,"stdout":"<escaped>","stderr":"<escaped>"}
  Host  -> Guest: SHUTDOWN
  Guest -> Host: {"status":"shutdown"}  (then powers off)
```

The agent runs as a systemd service (`aos-test-agent.service`) that starts after
`multi-user.target` and is conditioned on the existence of the virtio port.

### Host-Side Test Helpers

The `mkVMTest` function in `tests/vm/lib.nix` provides shell functions for test scripts:

```bash
# Send a command to the guest and return the JSON response
run_in_guest "command"
# Returns: {"exit_code":0,"stdout":"...","stderr":"..."}

# Assert that a command exits successfully
assert_success "command" "description"
# Prints PASS or FAIL with details

# Assert that command output contains an expected string
assert_output_contains "command" "expected" "description"
# Prints PASS or FAIL with actual vs expected output
```

### QEMU Configuration

Each VM test launches QEMU with:

```bash
qemu-system-x86_64 \
  -machine q35,accel=kvm \
  -cpu host \
  -m 2048 \
  -smp 2 \
  -nographic \
  -drive file="$IMAGE",format=raw,if=virtio,readonly=on \
  -device virtio-serial \
  -device virtserialport,chardev=agent,name=aos.test.agent \
  -chardev socket,id=agent,path="$AGENT_SOCK",server=on,wait=off \
  -monitor unix:"$MONITOR_SOCK",server,nowait \
  -serial file:"$SERIAL_LOG" \
  -no-reboot
```

Key QEMU flags:
- `-device virtio-serial` + `-device virtserialport`: Creates the virtio serial channel
- `-chardev socket,path=agent.sock`: Exposes the channel as a Unix socket on the host
- `-monitor unix:monitor.sock`: QEMU monitor for VM control (screenshots, power)
- `-serial file:serial.log`: Captures kernel console output for debugging
- `-no-reboot`: VM exits on guest shutdown/crash (useful for test cleanup)
- `accel=kvm`: Hardware acceleration (required)

### Contrast with Previous Approach

| Feature | Old (SSH-based) | New (virtio-serial) |
|---------|----------------|-------------------|
| Communication | SSH over guest network | virtio-serial device |
| Early boot testing | Not possible | Works immediately |
| Authentication | SSH keys required | None needed |
| Network dependency | Guest network must be up | No network needed |
| Response format | Raw text output | Structured JSON |
| Complexity | SSH server + key management | Tiny shell script |
| Framework | Python/pytest | Pure Nix + shell |

---

## 7. CLI Test Integration

### `aos test` Command

The `aos test` command is implemented in `cli/src/commands/test.rs`:

```rust
#[derive(Subcommand)]
enum TestCmd {
    /// Run eval checks (Layer 1)
    Eval,
    /// Run build checks (Layer 2)
    Build,
    /// Run VM integration tests (Layer 3)
    Vm {
        /// Specific test suite (boot, immutability, security, etc.)
        suite: Option<String>,
    },
    /// Run fleet tests (Layer 4)
    Fleet {
        /// Specific test suite (k8s-cluster, rolling-update)
        suite: Option<String>,
    },
}
```

When invoked without arguments, `aos test` runs all four layers sequentially:
1. Eval (fast, catches config errors immediately)
2. Build (medium, catches build failures)
3. VM (slow, requires KVM)
4. Fleet (slowest, multiple VMs)

If any layer fails, subsequent layers are skipped (fail-fast).

### Test Output

The `aos` CLI provides structured test output:

```
$ aos test
==> Layer 1: Eval checks
  PASS  base evaluates
  PASS  server evaluates
  PASS  k8s-worker evaluates
  PASS  k8s-control-plane evaluates
==> Layer 1: 4/4 passed

==> Layer 2: Build checks
  PASS  linux builds
  PASS  systemd builds
  PASS  containerd builds
  PASS  kubelet builds
==> Layer 2: 4/4 passed

==> Layer 3: VM integration tests
  PASS  boot: systemd reached running state
  PASS  boot: no failed systemd units
  PASS  boot: os-release contains AOS
  PASS  immutability: root filesystem is read-only
  PASS  immutability: /var is writable
  PASS  security: SELinux is enforcing
  PASS  security: nftables rules are active
  PASS  networking: systemd-networkd is active
  PASS  kubernetes: containerd socket present
  PASS  kubernetes: kubelet running
==> Layer 3: 10/10 passed

==> Layer 4: Fleet tests
  PASS  k8s-cluster: kubeadm init succeeds
  PASS  k8s-cluster: worker joins cluster
  PASS  k8s-cluster: nodes are Ready
  PASS  k8s-cluster: test pod scheduled
  PASS  rolling-update: update applied
  PASS  rolling-update: node healthy after update
==> Layer 4: 6/6 passed

==> All tests passed (24/24)
```

With `--json` flag, output is machine-readable for CI integration.

### justfile Targets

```makefile
# justfile test targets
test *args:
    aos test {{args}}

test-fast:
    aos test eval

test-vm suite="":
    aos test vm {{suite}}

test-fleet suite="":
    aos test fleet {{suite}}
```

---

## Summary

| Aspect | Implementation |
|--------|---------------|
| Test architecture | 4 layers: eval, build, VM, fleet |
| Test entry point | `tests/default.nix`, run via `aos test` |
| Eval tests | Pure Nix evaluation, < 1 second, `tests/eval.nix` |
| Build tests | Package build verification, `tests/build.nix` |
| VM tests | QEMU + virtio-serial, `tests/vm/lib.nix` |
| Fleet tests | Multi-VM orchestration, `tests/fleet/lib.nix` |
| Guest communication | virtio-serial (not SSH), structured JSON protocol |
| Guest agent | Shell script at `/dev/virtio-ports/aos.test.agent` |
| Test framework | Pure Nix + shell (not pytest, not Go) |
| CLI integration | `aos test [layer] [suite]` with colored output + `--json` |
| Build environment | Native Nix (no Docker) |
| KVM requirement | VM/fleet tests declare `requiredSystemFeatures = [ "kvm" ]` |
