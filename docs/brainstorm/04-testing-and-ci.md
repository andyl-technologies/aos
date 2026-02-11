# 04 - Testing, CI/CD, and Build Infrastructure

## Overview

This document covers the full testing and continuous integration pipeline for
ANDYL OS. The workflow spans: building packages and golden images inside Docker
on macOS, caching build artifacts via a binary cache, booting images in QEMU for
integration testing, and orchestrating all of this through CI/CD pipelines and
a developer-facing `justfile`.

---

## 1. QEMU Integration Testing

### 1.1 Why QEMU

Golden images must be validated before fleet deployment. QEMU provides
hardware-level emulation that exercises the full boot path: firmware, initrd,
kernel, systemd, ZFS import, Ignition config application, and service startup.
Unlike container-based tests, QEMU tests exercise the actual machine image
bit-for-bit.

### 1.2 Acceleration Backends

#### macOS (Developer Workstation)

macOS does not support KVM. Two options:

| Backend | Performance | Notes |
|---------|------------|-------|
| HVF (Hypervisor.framework) | ~70-80% native | Requires Apple Silicon or Intel with HVF support. QEMU flag: `-accel hvf` |
| TCG (Tiny Code Generator) | ~10-20% native | Pure software emulation. Always available. QEMU flag: `-accel tcg` |

HVF is strongly preferred on macOS. Detection logic:

```bash
# Check if HVF is available
if qemu-system-x86_64 -accel help 2>&1 | grep -q hvf; then
    QEMU_ACCEL="-accel hvf"
else
    QEMU_ACCEL="-accel tcg"
fi
```

Note: On Apple Silicon (aarch64 host) testing x86_64 images, HVF is not
available for cross-architecture. TCG is the only option unless we build
aarch64 images. If we target x86_64 servers, developer testing on Apple
Silicon will be slower. Consider providing a remote Linux test runner for
fast iteration.

#### CI (Linux Runners)

Linux CI runners with KVM support provide near-native performance:

```bash
QEMU_ACCEL="-accel kvm"
# Requires /dev/kvm access
# Runner must have nested virt enabled or bare-metal access
```

GitHub Actions self-hosted runners or cloud instances with nested
virtualization (e.g., GCP `n2-standard-*` with `--enable-nested-virtualization`)
provide KVM.

### 1.3 Test VM Configuration

Standard QEMU invocation for integration testing:

```bash
qemu-system-x86_64 \
    ${QEMU_ACCEL} \
    -m 4096 \
    -smp 2 \
    -cpu host \
    -drive file=andyl-os.qcow2,format=qcow2,if=virtio \
    -drive file=zfs-data.qcow2,format=qcow2,if=virtio \
    -netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::6443-:6443 \
    -device virtio-net-pci,netdev=net0 \
    -serial mon:stdio \
    -nographic \
    -fw_cfg name=opt/com.coreos/config,file=ignition.json \
    -pidfile /tmp/qemu-test.pid \
    -monitor unix:/tmp/qemu-monitor.sock,server,nowait
```

#### Resource Allocation

| Resource | Dev (macOS) | CI (Linux) | Notes |
|----------|-------------|------------|-------|
| RAM | 4 GB | 4 GB | Enough for k8s single-node. Increase to 8 GB for heavy workloads. |
| CPU | 2 vCPUs | 4 vCPUs | `-smp` flag. CI can afford more. |
| Root disk | 20 GB qcow2 | 20 GB qcow2 | Thin-provisioned, grows on demand. |
| ZFS disk | 10 GB qcow2 | 10 GB qcow2 | Second virtio disk for ZFS pool testing. |

#### Networking

**User-mode networking** (default, no root required):

```bash
-netdev user,id=net0,hostfwd=tcp::2222-:22
-device virtio-net-pci,netdev=net0
```

- Pros: No host configuration. Works everywhere. Port forwarding for SSH.
- Cons: No inbound connections (except forwarded ports). No VM-to-VM networking.
- Use for: Single-VM integration tests.

**TAP networking** (for multi-VM tests):

```bash
# Create bridge and tap (Linux CI only, requires root or capabilities)
ip link add br-test type bridge
ip link set br-test up
ip tuntap add dev tap0 mode tap
ip link set tap0 master br-test
ip link set tap0 up

# QEMU
-netdev tap,id=net0,ifname=tap0,script=no,downscript=no
-device virtio-net-pci,netdev=net0
```

- Use for: Multi-node Kubernetes tests, network partition simulation.

#### Serial Console

The serial console is the primary interface for automated testing. All kernel
and systemd output goes to serial:

```bash
# In the image's kernel cmdline:
console=ttyS0,115200n8

# QEMU flag to redirect serial to stdio:
-serial mon:stdio
```

Capture all serial output to a log file:

```bash
qemu-system-x86_64 ... -serial mon:stdio 2>&1 | tee serial-console.log
```

Or use a Unix socket for programmatic access:

```bash
-serial unix:/tmp/qemu-serial.sock,server,nowait
```

Then connect from test code via `socat` or native socket libraries.

#### QEMU Monitor

The QEMU monitor provides VM lifecycle control:

```bash
-monitor unix:/tmp/qemu-monitor.sock,server,nowait
```

Commands via the monitor:

```bash
# Send commands via socat
echo "info status" | socat - UNIX-CONNECT:/tmp/qemu-monitor.sock
echo "screendump /tmp/test-failure.ppm" | socat - UNIX-CONNECT:/tmp/qemu-monitor.sock
echo "quit" | socat - UNIX-CONNECT:/tmp/qemu-monitor.sock

# Snapshot for rollback testing
echo "savevm before-update" | socat - UNIX-CONNECT:/tmp/qemu-monitor.sock
echo "loadvm before-update" | socat - UNIX-CONNECT:/tmp/qemu-monitor.sock
```

### 1.4 Test Scenarios

Each test scenario follows a pattern: boot VM, wait for condition, assert,
collect artifacts, shutdown.

#### 1.4.1 Boot Success

The most basic test: does the image boot to a usable state?

```bash
# Boot and wait for login prompt on serial console
timeout 120 expect -c '
    spawn qemu-system-x86_64 ... -serial mon:stdio -nographic
    expect {
        "login:" { exit 0 }
        timeout { exit 1 }
    }
'
```

Alternatively, wait for a specific systemd target:

```bash
# Via SSH (after boot completes)
ssh -p 2222 -o StrictHostKeyChecking=no root@localhost \
    "systemctl is-system-running --wait" &
WAIT_PID=$!

# Timeout after 120 seconds
if ! timeout 120 wait $WAIT_PID; then
    echo "FAIL: system did not reach running state"
    exit 1
fi
```

Expected: `systemctl is-system-running` returns `running` or `degraded`
(degraded is acceptable if only non-critical services failed, but should be
investigated).

#### 1.4.2 systemd Service Health

```bash
# List of critical services to verify
CRITICAL_SERVICES=(
    "sshd.service"
    "guix-daemon.service"
    "networking.service"
    "zfs-mount.service"
    "zfs-import-cache.service"
    "kubelet.service"
    "containerd.service"
)

for svc in "${CRITICAL_SERVICES[@]}"; do
    status=$(ssh -p 2222 root@localhost "systemctl is-active $svc")
    if [ "$status" != "active" ]; then
        echo "FAIL: $svc is $status"
        ssh -p 2222 root@localhost "journalctl -u $svc --no-pager -n 50"
        exit 1
    fi
done
```

#### 1.4.3 Network Connectivity

```bash
# DNS resolution
ssh -p 2222 root@localhost "dig +short google.com" || exit 1

# Outbound HTTPS
ssh -p 2222 root@localhost "curl -sf https://httpbin.org/get > /dev/null" || exit 1

# Internal DNS (if applicable)
ssh -p 2222 root@localhost "dig +short cache.andyl.internal" || exit 1
```

Note: User-mode QEMU networking provides outbound connectivity via SLIRP.
DNS resolution uses the host's DNS by default.

#### 1.4.4 ZFS Pool Verification

```bash
# Pool import
ssh -p 2222 root@localhost "zpool status datapool" || exit 1

# Check pool is healthy (no degraded/faulted vdevs)
ssh -p 2222 root@localhost "zpool status datapool | grep -q ONLINE" || exit 1

# Datasets mounted
ssh -p 2222 root@localhost "zfs list datapool/containers" || exit 1

# Read/write test
ssh -p 2222 root@localhost "
    echo 'test-data' > /datapool/testfile
    sync
    content=\$(cat /datapool/testfile)
    [ \"\$content\" = 'test-data' ] || exit 1
    rm /datapool/testfile
" || exit 1

# Snapshot/rollback test
ssh -p 2222 root@localhost "
    echo 'before' > /datapool/snaptest
    zfs snapshot datapool@test-snap
    echo 'after' > /datapool/snaptest
    zfs rollback datapool@test-snap
    content=\$(cat /datapool/snaptest)
    [ \"\$content\" = 'before' ] || exit 1
    zfs destroy datapool@test-snap
    rm /datapool/snaptest
" || exit 1
```

#### 1.4.5 Kubernetes Readiness (Pluggable Plugin Architecture)

The base image ships standard CNI plugin binaries (bridge, loopback, etc.)
and the directory structure required by CNI and CSI plugins, but does **not**
bake in any specific CNI implementation. The CNI plugin (e.g., Cilium, Calico,
Flannel) is deployed at runtime as a DaemonSet or Helm release. This test
validates the full lifecycle: base-image prerequisites, runtime plugin
deployment, and end-to-end pod networking.

```bash
# --- Pre-deployment checks (base image provides these) ---

# kubelet is running
ssh -p 2222 root@localhost "systemctl is-active kubelet" || exit 1

# Container runtime is responsive
ssh -p 2222 root@localhost "crictl info" || exit 1

# CNI directory structure and standard plugin binaries exist in the base image
ssh -p 2222 root@localhost "
    test -d /opt/cni/bin || { echo 'FAIL: /opt/cni/bin missing'; exit 1; }
    test -d /etc/cni/net.d || { echo 'FAIL: /etc/cni/net.d missing'; exit 1; }
    # Standard CNI plugins (bridge, loopback) are in the base image
    test -x /opt/cni/bin/loopback || { echo 'FAIL: loopback CNI plugin missing'; exit 1; }
    test -x /opt/cni/bin/bridge || { echo 'FAIL: bridge CNI plugin missing'; exit 1; }
    test -x /opt/cni/bin/host-local || { echo 'FAIL: host-local CNI plugin missing'; exit 1; }
    test -x /opt/cni/bin/portmap || { echo 'FAIL: portmap CNI plugin missing'; exit 1; }
" || exit 1

# CSI extension point directories exist (plugin sockets land here)
ssh -p 2222 root@localhost "
    test -d /var/lib/kubelet/plugins || { echo 'FAIL: /var/lib/kubelet/plugins missing'; exit 1; }
    test -d /var/lib/kubelet/plugins_registry || { echo 'FAIL: /var/lib/kubelet/plugins_registry missing'; exit 1; }
" || exit 1

# No CNI config exists yet (proving the CNI is NOT baked in)
ssh -p 2222 root@localhost "
    count=\$(ls /etc/cni/net.d/*.conf /etc/cni/net.d/*.conflist 2>/dev/null | wc -l)
    if [ \"\$count\" -ne 0 ]; then
        echo 'FAIL: CNI config found before plugin deployment -- CNI should not be baked in'
        exit 1
    fi
" || exit 1

# --- Deploy a CNI plugin (Cilium as the recommended default) ---

ssh -p 2222 root@localhost "
    helm repo add cilium https://helm.cilium.io/ 2>/dev/null || true
    helm install cilium cilium/cilium \
        --namespace kube-system \
        --set kubeProxyReplacement=true \
        --set k8sServiceHost=localhost \
        --set k8sServicePort=6443 \
        --set cni.binPath=/opt/cni/bin \
        --set cni.confPath=/etc/cni/net.d \
        --wait --timeout=120s
" || exit 1

# Verify CNI plugin wrote config to the mutable path (not to immutable root)
ssh -p 2222 root@localhost "
    ls /etc/cni/net.d/*.conflist >/dev/null 2>&1 || \
    ls /etc/cni/net.d/*.conf >/dev/null 2>&1 || \
        { echo 'FAIL: no CNI config found in /etc/cni/net.d after deployment'; exit 1; }
" || exit 1

# Node is Ready (may take 30-60 seconds after CNI deployment)
ssh -p 2222 root@localhost "
    for i in \$(seq 1 30); do
        status=\$(kubectl get node \$(hostname) -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' 2>/dev/null)
        if [ \"\$status\" = 'True' ]; then
            echo 'Node is Ready'
            exit 0
        fi
        sleep 2
    done
    echo 'FAIL: node not Ready after 60s'
    kubectl get node \$(hostname) -o yaml
    exit 1
" || exit 1

# Can schedule a pod (validates end-to-end CNI networking)
ssh -p 2222 root@localhost "
    kubectl run test-pod --image=busybox --restart=Never -- sleep 30
    kubectl wait --for=condition=Ready pod/test-pod --timeout=60s
    kubectl delete pod test-pod --wait=false
" || exit 1
```

#### 1.4.5a CNI Plugin Swap Test (Alternative CNI)

Validates that the pluggable CNI architecture allows swapping one CNI
plugin for another at runtime. The base image is CNI-agnostic; any
conformant CNI plugin deployed as a DaemonSet or Helm release must work.

```bash
# Remove Cilium and install Flannel to verify pluggable CNI architecture
ssh -p 2222 root@localhost "
    # Uninstall the previous CNI plugin
    helm uninstall cilium --namespace kube-system --wait 2>/dev/null || true

    # Clean any existing CNI config written by the previous plugin
    rm -f /etc/cni/net.d/*

    # Deploy Flannel as an alternative CNI plugin
    kubectl apply -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml

    # Wait for Flannel DaemonSet to be ready
    kubectl -n kube-flannel rollout status daemonset/kube-flannel-ds --timeout=120s

    # Verify Flannel wrote its own CNI config
    ls /etc/cni/net.d/*.conflist >/dev/null 2>&1 || \
        { echo 'FAIL: Flannel did not write CNI config'; exit 1; }

    # Verify node becomes Ready with the new CNI
    for i in \$(seq 1 30); do
        status=\$(kubectl get node \$(hostname) -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' 2>/dev/null)
        if [ \"\$status\" = 'True' ]; then
            echo 'Node is Ready with Flannel CNI'
            exit 0
        fi
        sleep 2
    done
    echo 'FAIL: node not Ready with Flannel after 60s'
    exit 1
" || exit 1

# Verify pod scheduling works with the swapped CNI
ssh -p 2222 root@localhost "
    kubectl run swap-test --image=busybox --restart=Never -- sleep 10
    kubectl wait --for=condition=Ready pod/swap-test --timeout=60s
    kubectl delete pod swap-test --wait=false
" || exit 1
```

#### 1.4.5b CSI Driver Deployment Test

Validates that the CSI extension point on ANDYL OS supports runtime
deployment of storage drivers. CSI drivers run as DaemonSets and
communicate via Unix sockets in `/var/lib/kubelet/plugins/`.

```bash
# Deploy a lightweight CSI driver (hostpath-csi for testing purposes)
ssh -p 2222 root@localhost "
    # Deploy the CSI hostpath driver (used for CI validation only)
    kubectl apply -f https://raw.githubusercontent.com/kubernetes-csi/csi-driver-host-path/master/deploy/kubernetes-latest/hostpath/csi-hostpath-plugin.yaml

    # Wait for CSI driver DaemonSet/Deployment to be ready
    kubectl -n default rollout status deployment/csi-hostpathplugin --timeout=120s 2>/dev/null || \
    kubectl -n default rollout status statefulset/csi-hostpathplugin --timeout=120s 2>/dev/null || true

    # Verify CSI driver registered its socket in the mutable plugin directory
    ls /var/lib/kubelet/plugins/csi-hostpath/csi.sock 2>/dev/null || \
    ls /var/lib/kubelet/plugins_registry/csi-hostpath* 2>/dev/null || \
        echo 'WARN: CSI socket not found (driver may use a different registration path)'

    # Verify CSINode object was created
    kubectl get csinodes \$(hostname) -o jsonpath='{.spec.drivers[*].name}' | grep -q hostpath || \
        echo 'WARN: CSI driver not yet registered in CSINode'
" || exit 1
```

#### 1.4.6 Ignition Config Application

```bash
# Verify files created by Ignition
ssh -p 2222 root@localhost "
    # Check specific files exist with correct content
    [ -f /etc/hostname ] || exit 1
    [ -f /etc/andyl/node-role ] || exit 1

    # Check users created
    id andyl-admin || exit 1

    # Check SSH authorized keys
    [ -f /home/andyl-admin/.ssh/authorized_keys ] || exit 1

    # Check network config applied
    [ -f /etc/systemd/network/10-eth0.network ] || exit 1

    # Check Ignition first-boot flag consumed
    [ ! -f /boot/ignition/config.ign ] || echo 'WARN: ignition config still present (expected consumed)'
" || exit 1
```

#### 1.4.7 Update and Rollback

This test uses QEMU snapshots for efficiency:

```bash
# Step 1: Boot image, take VM snapshot at known-good state
echo "savevm baseline" | socat - UNIX-CONNECT:/tmp/qemu-monitor.sock

# Step 2: Apply update (switch to new generation)
ssh -p 2222 root@localhost "
    guix system switch-generation +1
    # Or: guix system reconfigure /etc/guix/system.scm
" || exit 1

# Step 3: Reboot and verify new generation
ssh -p 2222 root@localhost "reboot"
# Wait for SSH to come back
wait_for_ssh 2222 120

ssh -p 2222 root@localhost "
    current=\$(guix system list-generations | head -1)
    echo \"Current generation: \$current\"
    systemctl is-system-running --wait
" || exit 1

# Step 4: Simulate failure — restore to baseline
echo "loadvm baseline" | socat - UNIX-CONNECT:/tmp/qemu-monitor.sock
wait_for_ssh 2222 60

# Step 5: Verify rollback state
ssh -p 2222 root@localhost "
    current=\$(guix system list-generations | head -1)
    echo \"Rolled back to generation: \$current\"
    systemctl is-system-running --wait
" || exit 1
```

#### 1.4.8 Garbage Collection

```bash
ssh -p 2222 root@localhost "
    # Record store size before GC
    before=\$(du -sh /gnu/store | cut -f1)

    # Run GC, keeping only current and previous generation
    guix gc --delete-generations=2d

    after=\$(du -sh /gnu/store | cut -f1)
    echo \"Store size: \$before -> \$after\"

    # Verify current system still works
    systemctl is-system-running --wait || exit 1

    # Verify critical binaries still exist
    which bash || exit 1
    which kubelet || exit 1
    which zfs || exit 1
" || exit 1
```

### 1.5 Test Framework Options

#### Option A: Shell Scripts with Expect (Simple, Low Dependency)

Pros:
- No additional language runtime
- Direct `expect`/`timeout` integration
- Easy to debug (just read the script)

Cons:
- Limited assertions and reporting
- Error handling is cumbersome
- Hard to parallelize

Best for: Initial prototype, simple boot tests.

Example structure:

```
tests/
  lib/
    vm.sh          # VM lifecycle: start, stop, wait_for_ssh, snapshot
    assert.sh      # assert_eq, assert_cmd_success, etc.
    cleanup.sh     # Trap-based resource cleanup
  test-boot.sh
  test-services.sh
  test-zfs.sh
  test-k8s.sh
  test-ignition.sh
  test-update.sh
  run-all.sh       # Runner with TAP-like output
```

```bash
#!/usr/bin/env bash
# tests/lib/vm.sh

VM_PID=""
SERIAL_LOG=""

start_vm() {
    local image="$1"
    local ignition="${2:-}"

    SERIAL_LOG=$(mktemp /tmp/serial-XXXXXX.log)

    local fw_cfg=""
    if [ -n "$ignition" ]; then
        fw_cfg="-fw_cfg name=opt/com.coreos/config,file=$ignition"
    fi

    qemu-system-x86_64 \
        ${QEMU_ACCEL:--accel tcg} \
        -m 4096 -smp 2 \
        -drive file="$image",format=qcow2,if=virtio \
        -netdev user,id=net0,hostfwd=tcp::2222-:22 \
        -device virtio-net-pci,netdev=net0 \
        -serial file:"$SERIAL_LOG" \
        -monitor unix:/tmp/qemu-monitor.sock,server,nowait \
        -nographic \
        -pidfile /tmp/qemu-test.pid \
        $fw_cfg &

    VM_PID=$!
}

wait_for_ssh() {
    local port="${1:-2222}"
    local timeout="${2:-120}"
    local start=$(date +%s)

    while true; do
        if ssh -p "$port" -o ConnectTimeout=2 -o StrictHostKeyChecking=no \
               root@localhost true 2>/dev/null; then
            return 0
        fi

        local elapsed=$(( $(date +%s) - start ))
        if [ "$elapsed" -ge "$timeout" ]; then
            echo "FAIL: SSH not available after ${timeout}s"
            return 1
        fi
        sleep 2
    done
}

stop_vm() {
    if [ -n "$VM_PID" ]; then
        echo "quit" | socat - UNIX-CONNECT:/tmp/qemu-monitor.sock 2>/dev/null
        wait "$VM_PID" 2>/dev/null
        VM_PID=""
    fi
}

collect_artifacts() {
    local dest="$1"
    mkdir -p "$dest"

    [ -f "$SERIAL_LOG" ] && cp "$SERIAL_LOG" "$dest/serial.log"

    # Screenshot on failure
    echo "screendump $dest/screenshot.ppm" | \
        socat - UNIX-CONNECT:/tmp/qemu-monitor.sock 2>/dev/null

    # Journal dump
    ssh -p 2222 -o ConnectTimeout=5 root@localhost \
        "journalctl --no-pager -b" > "$dest/journal.log" 2>/dev/null || true
}

cleanup() {
    stop_vm
    [ -f "$SERIAL_LOG" ] && rm -f "$SERIAL_LOG"
    rm -f /tmp/qemu-test.pid /tmp/qemu-monitor.sock
}

trap cleanup EXIT
```

#### Option B: Python with pytest (Recommended for Production)

Pros:
- Rich assertion library, parametrization, fixtures
- `pexpect` for serial console interaction
- `paramiko` for SSH
- Excellent test reporting (JUnit XML, HTML)
- Easy to parallelize with `pytest-xdist`

Cons:
- Requires Python in the test environment
- More setup/boilerplate

Best for: Production CI, complex test matrices.

```python
# tests/conftest.py
import pytest
import subprocess
import time
import paramiko
import os

class QEMUInstance:
    def __init__(self, image_path, ignition_path=None, memory=4096, cpus=2):
        self.image_path = image_path
        self.ignition_path = ignition_path
        self.memory = memory
        self.cpus = cpus
        self.ssh_port = 2222
        self.process = None
        self.serial_log = f"/tmp/serial-{os.getpid()}.log"
        self.monitor_sock = f"/tmp/qemu-monitor-{os.getpid()}.sock"

    def start(self):
        accel = self._detect_accel()
        cmd = [
            "qemu-system-x86_64",
            "-accel", accel,
            "-m", str(self.memory),
            "-smp", str(self.cpus),
            "-drive", f"file={self.image_path},format=qcow2,if=virtio",
            "-netdev", f"user,id=net0,hostfwd=tcp::{self.ssh_port}-:22",
            "-device", "virtio-net-pci,netdev=net0",
            "-serial", f"file:{self.serial_log}",
            "-monitor", f"unix:{self.monitor_sock},server,nowait",
            "-nographic",
        ]

        if self.ignition_path:
            cmd.extend([
                "-fw_cfg",
                f"name=opt/com.coreos/config,file={self.ignition_path}"
            ])

        self.process = subprocess.Popen(cmd)

    def wait_for_ssh(self, timeout=120):
        start = time.time()
        while time.time() - start < timeout:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect("localhost", port=self.ssh_port,
                             username="root", timeout=5)
                client.close()
                return True
            except Exception:
                time.sleep(2)
        raise TimeoutError(f"SSH not available after {timeout}s")

    def ssh_exec(self, command):
        """Execute command via SSH. Returns (stdout, stderr, exit_code)."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect("localhost", port=self.ssh_port, username="root")
        stdin, stdout, stderr = client.exec_command(command)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        client.close()
        return out, err, exit_code

    def monitor_cmd(self, command):
        """Send command to QEMU monitor."""
        import socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.monitor_sock)
        sock.recv(4096)  # Read banner
        sock.sendall(f"{command}\n".encode())
        time.sleep(0.5)
        result = sock.recv(4096).decode()
        sock.close()
        return result

    def stop(self):
        if self.process:
            self.monitor_cmd("quit")
            self.process.wait(timeout=10)

    def _detect_accel(self):
        result = subprocess.run(
            ["qemu-system-x86_64", "-accel", "help"],
            capture_output=True, text=True
        )
        if "kvm" in result.stdout:
            return "kvm"
        if "hvf" in result.stdout:
            return "hvf"
        return "tcg"


@pytest.fixture(scope="session")
def vm(request, tmp_path_factory):
    """Session-scoped QEMU VM fixture."""
    image = os.environ.get("TEST_IMAGE", "build/andyl-os.qcow2")
    ignition = os.environ.get("TEST_IGNITION", None)

    instance = QEMUInstance(image, ignition)
    instance.start()
    instance.wait_for_ssh(timeout=180)

    yield instance

    # Collect artifacts on failure
    artifacts_dir = tmp_path_factory.mktemp("artifacts")
    if request.session.testsfailed > 0:
        instance.monitor_cmd(f"screendump {artifacts_dir}/failure.ppm")
        try:
            out, _, _ = instance.ssh_exec("journalctl --no-pager -b")
            (artifacts_dir / "journal.log").write_text(out)
        except Exception:
            pass

    instance.stop()
```

```python
# tests/test_boot.py

def test_system_running(vm):
    out, _, code = vm.ssh_exec("systemctl is-system-running --wait")
    assert code == 0
    assert out in ("running", "degraded")

def test_no_failed_units(vm):
    out, _, _ = vm.ssh_exec("systemctl --failed --no-legend")
    failed = [line for line in out.splitlines() if line.strip()]
    assert len(failed) == 0, f"Failed units: {failed}"
```

```python
# tests/test_services.py
import pytest

CRITICAL_SERVICES = [
    "sshd.service",
    "guix-daemon.service",
    "networking.service",
    "zfs-mount.service",
    "zfs-import-cache.service",
    "kubelet.service",
    "containerd.service",
]

@pytest.mark.parametrize("service", CRITICAL_SERVICES)
def test_service_active(vm, service):
    out, _, code = vm.ssh_exec(f"systemctl is-active {service}")
    assert out == "active", f"{service} is {out}"

@pytest.mark.parametrize("service", CRITICAL_SERVICES)
def test_service_no_recent_restarts(vm, service):
    """Verify service hasn't been crash-looping."""
    out, _, _ = vm.ssh_exec(
        f"systemctl show {service} --property=NRestarts --value"
    )
    restarts = int(out) if out.isdigit() else 0
    assert restarts == 0, f"{service} restarted {restarts} times"
```

```python
# tests/test_zfs.py

def test_zfs_pool_online(vm):
    out, _, code = vm.ssh_exec("zpool status datapool")
    assert code == 0
    assert "ONLINE" in out

def test_zfs_read_write(vm):
    _, _, code = vm.ssh_exec("""
        echo 'integration-test' > /datapool/.test-write
        sync
        content=$(cat /datapool/.test-write)
        rm /datapool/.test-write
        [ "$content" = "integration-test" ]
    """)
    assert code == 0

def test_zfs_snapshot_rollback(vm):
    _, _, code = vm.ssh_exec("""
        echo 'original' > /datapool/.snap-test
        zfs snapshot datapool@ci-test
        echo 'modified' > /datapool/.snap-test
        zfs rollback datapool@ci-test
        content=$(cat /datapool/.snap-test)
        zfs destroy datapool@ci-test
        rm /datapool/.snap-test
        [ "$content" = "original" ]
    """)
    assert code == 0
```

```python
# tests/test_k8s.py
import time
import pytest

# --- Base image prerequisites (no CNI plugin baked in) ---

def test_kubelet_active(vm):
    out, _, code = vm.ssh_exec("systemctl is-active kubelet")
    assert out == "active"

def test_containerd_responsive(vm):
    _, _, code = vm.ssh_exec("crictl info")
    assert code == 0

def test_cni_directory_structure(vm):
    """Verify the base image provides CNI and CSI extension points."""
    _, _, code = vm.ssh_exec("test -d /opt/cni/bin")
    assert code == 0, "/opt/cni/bin directory missing from base image"
    _, _, code = vm.ssh_exec("test -d /etc/cni/net.d")
    assert code == 0, "/etc/cni/net.d directory missing from base image"

def test_csi_extension_points(vm):
    """Verify CSI plugin directories exist on mutable /var."""
    _, _, code = vm.ssh_exec("test -d /var/lib/kubelet/plugins")
    assert code == 0, "/var/lib/kubelet/plugins directory missing"
    _, _, code = vm.ssh_exec("test -d /var/lib/kubelet/plugins_registry")
    assert code == 0, "/var/lib/kubelet/plugins_registry directory missing"

def test_standard_cni_plugins_present(vm):
    """Verify standard CNI plugins (bridge, loopback) are in the base image."""
    for plugin in ["bridge", "loopback", "host-local", "portmap"]:
        _, _, code = vm.ssh_exec(f"test -x /opt/cni/bin/{plugin}")
        assert code == 0, f"Standard CNI plugin {plugin} missing from /opt/cni/bin"

def test_no_cni_config_before_deployment(vm):
    """Verify no CNI config is baked into the base image."""
    out, _, _ = vm.ssh_exec(
        "ls /etc/cni/net.d/*.conf /etc/cni/net.d/*.conflist 2>/dev/null | wc -l"
    )
    assert out.strip() == "0", "CNI config found before plugin deployment -- CNI should not be baked in"

# --- CNI plugin deployment (Cilium as the recommended default) ---

def test_cni_plugin_deployment(vm):
    """Deploy Cilium via Helm and verify CNI becomes functional."""
    _, _, code = vm.ssh_exec(
        "helm repo add cilium https://helm.cilium.io/ 2>/dev/null; "
        "helm install cilium cilium/cilium "
        "--namespace kube-system "
        "--set kubeProxyReplacement=true "
        "--set k8sServiceHost=localhost "
        "--set k8sServicePort=6443 "
        "--set cni.binPath=/opt/cni/bin "
        "--set cni.confPath=/etc/cni/net.d "
        "--wait --timeout=120s"
    )
    assert code == 0, "CNI plugin (Cilium) deployment via Helm failed"

def test_cni_config_on_mutable_path(vm):
    """Verify the CNI plugin wrote its config to the mutable /etc overlay."""
    out, _, code = vm.ssh_exec(
        "ls /etc/cni/net.d/*.conflist /etc/cni/net.d/*.conf 2>/dev/null"
    )
    assert code == 0, "No CNI config found in /etc/cni/net.d after plugin deployment"

def test_node_ready(vm):
    """Wait for Kubernetes node to become Ready (requires CNI to be deployed)."""
    for _ in range(30):
        out, _, code = vm.ssh_exec(
            "kubectl get node $(hostname) -o jsonpath="
            "'{.status.conditions[?(@.type==\"Ready\")].status}'"
        )
        if out.strip("'") == "True":
            return
        time.sleep(2)

    # Dump debug info
    out, _, _ = vm.ssh_exec("kubectl get node $(hostname) -o yaml")
    pytest.fail(f"Node not Ready after 60s. Status:\n{out}")

def test_pod_scheduling(vm):
    """Validate end-to-end pod scheduling with the deployed CNI plugin."""
    _, _, code = vm.ssh_exec(
        "kubectl run test-pod --image=busybox --restart=Never -- sleep 30 && "
        "kubectl wait --for=condition=Ready pod/test-pod --timeout=60s && "
        "kubectl delete pod test-pod --wait=false"
    )
    assert code == 0

# --- CNI plugin swap (proves architecture is pluggable) ---

@pytest.mark.slow
def test_cni_plugin_swap(vm):
    """Swap Cilium for Flannel to prove the CNI architecture is pluggable."""
    # Uninstall Cilium
    _, _, code = vm.ssh_exec(
        "helm uninstall cilium --namespace kube-system --wait 2>/dev/null; "
        "rm -f /etc/cni/net.d/*"
    )
    # Deploy Flannel
    _, _, code = vm.ssh_exec(
        "kubectl apply -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml && "
        "kubectl -n kube-flannel rollout status daemonset/kube-flannel-ds --timeout=120s"
    )
    assert code == 0, "Flannel deployment failed during CNI swap test"

    # Verify node becomes Ready with the new CNI
    for _ in range(30):
        out, _, _ = vm.ssh_exec(
            "kubectl get node $(hostname) -o jsonpath="
            "'{.status.conditions[?(@.type==\"Ready\")].status}'"
        )
        if out.strip("'") == "True":
            return
        time.sleep(2)
    pytest.fail("Node not Ready after CNI swap to Flannel")

# --- CSI driver deployment ---

@pytest.mark.slow
def test_csi_driver_deployment(vm):
    """Deploy a CSI driver at runtime and verify it registers with kubelet."""
    _, _, code = vm.ssh_exec(
        "kubectl apply -f https://raw.githubusercontent.com/kubernetes-csi/"
        "csi-driver-host-path/master/deploy/kubernetes-latest/hostpath/"
        "csi-hostpath-plugin.yaml"
    )
    assert code == 0, "CSI hostpath driver deployment failed"

    # Verify CSINode object lists the driver
    for _ in range(15):
        out, _, _ = vm.ssh_exec(
            "kubectl get csinodes $(hostname) -o jsonpath='{.spec.drivers[*].name}'"
        )
        if "hostpath" in out:
            return
        time.sleep(4)
    pytest.fail("CSI driver did not register in CSINode within 60s")
```

#### Option C: Go Test Harness

Pros:
- Strong typing, good for complex orchestration
- Compiles to single binary (no runtime dependencies on test runner)
- Terratest patterns well-established

Cons:
- More boilerplate than Python
- Longer development cycle

Best for: Teams already using Go, infrastructure-as-code shops.

```go
// tests/integration_test.go
package integration

import (
    "os/exec"
    "testing"
    "time"
    "golang.org/x/crypto/ssh"
)

type VM struct {
    cmd      *exec.Cmd
    sshPort  int
}

func startVM(t *testing.T, imagePath string) *VM {
    t.Helper()
    vm := &VM{sshPort: 2222}
    vm.cmd = exec.Command("qemu-system-x86_64",
        "-accel", detectAccel(),
        "-m", "4096", "-smp", "2",
        "-drive", "file="+imagePath+",format=qcow2,if=virtio",
        "-netdev", "user,id=net0,hostfwd=tcp::2222-:22",
        "-device", "virtio-net-pci,netdev=net0",
        "-nographic",
    )
    if err := vm.cmd.Start(); err != nil {
        t.Fatalf("failed to start VM: %v", err)
    }
    t.Cleanup(func() { vm.cmd.Process.Kill() })

    waitForSSH(t, vm.sshPort, 120*time.Second)
    return vm
}

func (vm *VM) exec(t *testing.T, command string) string {
    t.Helper()
    config := &ssh.ClientConfig{
        User:            "root",
        HostKeyCallback: ssh.InsecureIgnoreHostKey(),
    }
    // ... SSH execution ...
    return ""
}

func TestBootSuccess(t *testing.T) {
    vm := startVM(t, "build/andyl-os.qcow2")
    out := vm.exec(t, "systemctl is-system-running --wait")
    if out != "running" && out != "degraded" {
        t.Fatalf("unexpected system state: %s", out)
    }
}
```

#### Framework Recommendation

**Use Python/pytest for production.** Rationale:

1. `paramiko` provides robust SSH without shelling out
2. pytest fixtures manage VM lifecycle cleanly
3. Parametrization enables test matrices (roles x scenarios)
4. JUnit XML output integrates with every CI system
5. `pytest-timeout` prevents hung tests
6. `pytest-html` generates human-readable reports
7. Lower barrier to contribution than Go

### 1.6 Test Result Artifacts

Every test run must produce:

| Artifact | Source | Purpose |
|----------|--------|---------|
| Serial console log | QEMU `-serial file:...` | Full boot trace, kernel messages |
| systemd journal | `journalctl -b --no-pager` via SSH | Service logs, errors |
| Screenshot | `screendump` via QEMU monitor | Visual state on failure |
| Test report | pytest JUnit XML | CI integration, dashboards |
| Failed unit logs | `journalctl -u <unit>` | Targeted debugging |
| ZFS status | `zpool status`, `zfs list` | Storage state |
| k8s state | `kubectl get all -A` | Cluster state |
| Ignition log | `journalctl -u ignition-*` | Config application trace |

CI should upload these as build artifacts (GitHub Actions `upload-artifact`,
GitLab CI artifacts, etc.) and retain them for at least 7 days.

---

## 2. Docker-based Build Pipeline on macOS

### 2.1 Dockerfile for Guix Build Environment

```dockerfile
# syntax=docker/dockerfile:1.6
# CI Build Environment for ANDYL OS
#
# This image is based on the project's Guix builder image
# (see docker/Dockerfile). Guix is installed via the standard binary
# tarball from ftp.gnu.org/gnu/guix/.
#
# Pin by digest for reproducibility.
# Update this digest intentionally, not automatically.
FROM andyl-os-builder@sha256:PINNED_DIGEST_HERE AS ci-builder

# Configure channels - our custom channel for ANDYL OS packages
COPY channels.scm /root/.config/guix/channels.scm

# Entry point script handles guix-daemon startup
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["bash"]
```

```bash
#!/usr/bin/env bash
# docker-entrypoint.sh

set -euo pipefail

# Start guix-daemon in the background
# --no-substitutes: build everything from source for reproducibility
# (remove this flag to use our binary cache for faster CI builds)
guix-daemon \
    --build-users-group=guixbuild \
    ${GUIX_DAEMON_OPTS:---no-substitutes} &
DAEMON_PID=$!

# Wait for daemon to be ready
for i in $(seq 1 30); do
    if guix describe >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Pull latest channel definitions
guix pull --channels=/root/.config/guix/channels.scm

exec "$@"
```

```scheme
;; channels.scm
(list
  ;; Official Guix channel
  (channel
    (name 'guix)
    (url "https://git.savannah.gnu.org/git/guix.git")
    ;; Pin to specific commit for reproducibility
    (commit "PINNED_COMMIT_HASH"))
  ;; ANDYL OS custom channel
  (channel
    (name 'andyl-os)
    (url "https://github.com/andyl/andyl-os-channel.git")
    ;; This will be overridden in CI to test the current branch
    (branch "main")))
```

### 2.2 Deterministic Docker Layers

Key practices for reproducible builds:

1. **Pin base image by digest** -- never use `:latest` or even `:bookworm`
   without a digest. Digests are immutable.

   ```dockerfile
   # Good: pinned digest
   FROM debian:bookworm@sha256:abc123...

   # Bad: mutable tag
   FROM debian:bookworm
   ```

2. **Pin apt package versions**:

   ```dockerfile
   RUN apt-get install -y \
       curl=7.88.1-10+deb12u5 \
       git=1:2.39.2-1.1
   ```

3. **Clean caches in the same layer** to avoid non-deterministic cache state:

   ```dockerfile
   RUN apt-get update && \
       apt-get install -y ... && \
       apt-get clean && \
       rm -rf /var/lib/apt/lists/*
   ```

4. **Multi-stage builds** to separate build tools from output:

   ```dockerfile
   FROM guix-builder AS build
   RUN guix system image --image-type=qcow2 system.scm -o /tmp/image.qcow2

   FROM scratch AS output
   COPY --from=build /tmp/image.qcow2 /image.qcow2
   ```

5. **Content-hash verification**:

   ```bash
   # After build, record hash of output
   sha256sum build/andyl-os.qcow2 > build/andyl-os.qcow2.sha256

   # Reproducibility check: rebuild and compare
   sha256sum -c build/andyl-os.qcow2.sha256
   ```

### 2.3 Volume Strategy

```bash
# Named volume for /gnu/store (persistent cache across builds)
docker volume create guix-store

# Run build container
docker run --rm \
    -v guix-store:/gnu/store \
    -v guix-var:/var/guix \
    -v "$(pwd)/src:/andyl-os/src:ro" \
    -v "$(pwd)/build:/andyl-os/build" \
    --privileged \
    andyl-os-builder \
    guix system image --image-type=qcow2 /andyl-os/src/system.scm \
        -o /andyl-os/build/andyl-os.qcow2
```

| Volume | Mount | Type | Purpose |
|--------|-------|------|---------|
| `guix-store` | `/gnu/store` | Named volume | Persistent Guix store. Survives container restarts. Contains all built derivations. This is the most important cache. |
| `guix-var` | `/var/guix` | Named volume | Guix database (SQLite). Must be kept in sync with `/gnu/store`. |
| Source code | `/andyl-os/src` | Bind mount (ro) | Project source. Read-only to prevent accidental modification. |
| Build output | `/andyl-os/build` | Bind mount | Built images extracted here for host access. |

**Important**: `/gnu/store` and `/var/guix` must be on the same named volume
or always used together. The SQLite database in `/var/guix/db` indexes the
store paths in `/gnu/store`. Orphaning one from the other corrupts the state.

### 2.4 Performance on macOS

Docker on macOS runs inside a Linux VM. File I/O between host and VM is a
major bottleneck.

| Runtime | File Sharing | I/O Performance | Notes |
|---------|-------------|-----------------|-------|
| Docker Desktop | VirtioFS | Good (~80% native) | Default on Apple Silicon. Recommended. |
| Docker Desktop | gRPC FUSE | Poor (~20% native) | Legacy default on Intel. Avoid. |
| OrbStack | Custom VirtioFS | Excellent (~90% native) | Fastest option. Drop-in Docker replacement. |
| Colima | VirtioFS (Lima) | Good (~75% native) | Lighter weight, CLI-first. |

**Recommendations**:

1. Use **OrbStack** or **Docker Desktop with VirtioFS** enabled.
2. Keep `/gnu/store` on a **named volume** (lives inside the VM, no
   host-to-VM I/O overhead). Only bind-mount source code and build output.
3. Allocate at least **8 GB RAM** and **4 CPUs** to the Docker VM.
4. Enable **Rosetta** for x86_64 emulation on Apple Silicon (Docker Desktop
   settings > Features > Use Rosetta for x86_64/amd64).

Resource allocation (Docker Desktop / OrbStack settings):

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPUs | 4 | 8 |
| Memory | 8 GB | 16 GB |
| Disk | 64 GB | 128 GB |

The `/gnu/store` can grow very large (50+ GB) for full system builds.

---

## 3. Binary Cache Architecture

### 3.1 Overview

Guix uses content-addressed derivations. Every build output (package, system
image, etc.) has a unique store path derived from all its inputs. A binary
cache (substitution server) stores pre-built outputs so they don't need to be
rebuilt from source.

The workflow:

```
Builder builds package → NAR archive created → Narinfo metadata generated
→ Both signed with private key → Uploaded to cache server

Consumer requests package → Checks cache → Downloads narinfo → Verifies
signature → Downloads NAR → Unpacks to /gnu/store
```

### 3.2 NAR Archive Format

NAR (Nix ARchive) is a deterministic archive format. Unlike tar, NAR
produces identical output for identical directory trees regardless of
filesystem metadata (timestamps, permissions beyond rwx, etc.).

Structure:
```
NAR = "nix-archive-1" + serialize(path)

serialize(path):
  if regular file:
    "(" "type" "regular" ["executable" ""] "contents" <file-contents> ")"
  if directory:
    "(" "type" "directory"
        ("entry" "(" "name" <name> "node" serialize(entry) ")")*
    ")"
  if symlink:
    "(" "type" "symlink" "target" <target> ")"
```

NARs are typically compressed with zstd or lzip:

```bash
# Generate NAR for a store path
guix archive --export /gnu/store/abc123-package-1.0 | zstd > package.nar.zst
```

### 3.3 Narinfo Files

A narinfo file is a small metadata file that describes a cached store path.
It is served at a URL derived from the store path hash.

Example narinfo for `/gnu/store/abc123...-bash-5.2`:

```
StorePath: /gnu/store/abc123def456-bash-5.2
URL: nar/zstd/abc123def456-bash-5.2
Compression: zstd
FileHash: sha256:fedcba987654...
FileSize: 1234567
NarHash: sha256:0123456789ab...
NarSize: 3456789
References: /gnu/store/xyz789-glibc-2.38 /gnu/store/qrs456-readline-8.2
Deriver: /gnu/store/drv123-bash-5.2.drv
Signature: 1;andyl-cache;BASE64_SIGNATURE_HERE
```

Fields:
- **StorePath**: The full store path this narinfo describes.
- **URL**: Relative URL to download the NAR archive.
- **Compression**: Compression algorithm (none, gzip, lzip, zstd).
- **FileHash/FileSize**: Hash and size of the compressed NAR file.
- **NarHash/NarSize**: Hash and size of the uncompressed NAR.
- **References**: Other store paths this package depends on.
- **Deriver**: The derivation that produced this output.
- **Signature**: Cryptographic signature for authenticity.

### 3.4 Signing Keys

```bash
# Generate a signing key pair (do this once, store securely)
guix archive --generate-key

# This creates:
# /etc/guix/signing-key.sec (private key - keep secret!)
# /etc/guix/signing-key.pub (public key - distribute to all consumers)

# The key is an s-expression (sexp) file:
# (private-key (ecc (curve Ed25519) (q ...) (d ...)))
# (public-key (ecc (curve Ed25519) (q ...)))
```

Key management:
- Store the **private key** in a secrets manager (Vault, AWS Secrets Manager,
  GitHub encrypted secrets). Only the build/cache server needs it.
- Distribute the **public key** to all machines that will consume from the
  cache. Install it via:

```bash
# On each consumer/worker
guix archive --authorize < /path/to/andyl-cache-signing-key.pub
```

Or in the Guix system configuration:

```scheme
(operating-system
  ...
  (services
    (append
      (list
        (simple-service 'andyl-substitute-keys
          guix-service-type
          (guix-configuration
            (substitute-urls
              '("https://cache.andyl.internal"
                "https://ci.guix.gnu.org"))
            (authorized-keys
              (cons* (local-file "./keys/andyl-cache.pub")
                     %default-authorized-guix-keys)))))
      %base-services)))
```

### 3.5 Cache Storage Options

#### Option A: S3-Compatible Object Storage

```
+-------------+      +-----+      +--------+
| guix publish | ---> | S3  | <--- | Workers|
+-------------+      +-----+      +--------+
                    (MinIO/AWS)
```

Pros:
- Infinite scalability
- Built-in redundancy
- Can use AWS S3, MinIO (self-hosted), or Cloudflare R2
- CDN-friendly (put CloudFront/Cloudflare in front)

Cons:
- Requires S3-compatible client integration
- `guix publish` doesn't natively write to S3
- Need a sync/upload script

Implementation with MinIO:

```bash
# Run MinIO locally or in CI
docker run -d \
    --name minio \
    -p 9000:9000 -p 9001:9001 \
    -v minio-data:/data \
    -e MINIO_ROOT_USER=andyl \
    -e MINIO_ROOT_PASSWORD=changeme \
    minio/minio server /data --console-address ":9001"

# Create bucket
mc alias set local http://localhost:9000 andyl changeme
mc mb local/guix-cache

# Upload NARs and narinfos after build
guix publish --port=8080 &
# Then mirror to S3:
mc mirror /var/cache/guix/publish local/guix-cache

# Serve via nginx (for guix substitute-urls compatibility)
# or use S3 website hosting directly
```

#### Option B: Local Filesystem with nginx

```
+-------------+      +-------+      +--------+
| guix publish | ---> | nginx | <--- | Workers|
+-------------+      +-------+      +--------+
                   (filesystem)
```

Pros:
- Simplest setup
- `guix publish` serves directly, or write to disk and serve via nginx
- Good for single-site deployments

Cons:
- Single point of failure
- Requires disk management
- Not easily distributed

```nginx
# /etc/nginx/sites-available/guix-cache
server {
    listen 443 ssl;
    server_name cache.andyl.internal;

    ssl_certificate /etc/ssl/certs/cache.pem;
    ssl_certificate_key /etc/ssl/private/cache.key;

    root /var/cache/guix/publish;

    # Narinfo files
    location ~ ^/([a-z0-9]{32})\.narinfo$ {
        try_files $uri =404;
        add_header Cache-Control "public, max-age=3600";
    }

    # NAR archives
    location /nar/ {
        try_files $uri =404;
        add_header Cache-Control "public, max-age=86400";
    }

    # Version/nix-cache-info endpoint
    location = /nix-cache-info {
        return 200 "StoreDir: /gnu/store\nWantMassQuery: 1\nPriority: 30\n";
        add_header Content-Type text/plain;
    }
}
```

#### Option C: Dedicated `guix publish` Server

```bash
# Run guix publish as a systemd service
guix publish \
    --port=8080 \
    --user=guix-publish \
    --compression=zstd:6 \
    --cache=/var/cache/guix/publish \
    --ttl=30d
```

Pros:
- Zero configuration -- `guix publish` handles everything
- Automatic NAR generation and signing
- Built-in caching and compression

Cons:
- Single-threaded Guile process (can be slow under load)
- No built-in TLS (put behind nginx or a reverse proxy)
- Single machine

**Recommendation**: Start with **Option C** (`guix publish` behind nginx) for
simplicity. Migrate to **Option A** (S3) when the cache grows beyond a single
machine or when you need geographic distribution.

### 3.6 Cache Population Workflow

```
CI Build Pipeline:

  1. guix build package-a     →  /gnu/store/xxx-package-a
  2. guix build package-b     →  /gnu/store/yyy-package-b
  3. guix system image ...    →  /gnu/store/zzz-andyl-os.qcow2
                                     │
                                     ▼
  4. guix copy --to=ssh://cache-server /gnu/store/xxx-package-a
     guix copy --to=ssh://cache-server /gnu/store/yyy-package-b
                                     │
                                     ▼
  5. Cache server runs guix publish, serves NARs + narinfos
                                     │
                                     ▼
  6. Next CI run: guix build --substitute-urls=https://cache.andyl.internal
     → hits cache for unchanged packages
     → only builds what changed
```

Alternative: Direct cache push without SSH:

```bash
# On the builder, generate NARs directly
guix archive --export --recursive /gnu/store/xxx-package-a | \
    zstd | \
    aws s3 cp - s3://guix-cache/nar/zstd/xxx-package-a

# Generate and upload narinfo
guix archive --export --recursive /gnu/store/xxx-package-a \
    | guix-narinfo-generate \
    | aws s3 cp - s3://guix-cache/xxx.narinfo
```

### 3.7 Cache Invalidation and Cleanup

Guix caches are content-addressed. When an input changes, the derivation hash
changes, creating a new cache entry. There is no need for explicit
invalidation -- old entries simply become unused.

Periodic cleanup to manage disk space:

```bash
# Delete cache entries older than 90 days
find /var/cache/guix/publish -name "*.narinfo" -mtime +90 -delete
find /var/cache/guix/publish/nar -mtime +90 -delete

# Or for S3:
aws s3api list-objects-v2 --bucket guix-cache \
    --query "Contents[?LastModified<='2025-01-01']" \
    | jq -r '.[] | .Key' \
    | xargs -I{} aws s3 rm s3://guix-cache/{}
```

### 3.8 Security Model

| Concern | Mitigation |
|---------|-----------|
| Cache poisoning (tampered NARs) | All NARs are signed. Consumers verify signature against authorized public keys before unpacking. |
| Man-in-the-middle | HTTPS for cache transport. TLS terminates at nginx or load balancer. |
| Unauthorized cache writes | Cache push requires authentication (SSH key, S3 credentials). Only CI has write access. |
| Key compromise | Rotate signing keys. Re-sign all cached NARs with new key. Distribute new public key. |
| Supply chain (upstream) | Pin Guix channel commits. Build from source (`--no-substitutes`) for critical packages. Verify upstream signatures. |

---

## 4. CI/CD Pipeline Design

### 4.1 Pipeline Stages

```
┌──────┐   ┌───────────────┐   ┌─────────────┐   ┌──────┐   ┌─────────┐   ┌────────┐
│ Lint │──▶│ Build Packages│──▶│ Build Image  │──▶│ Test │──▶│ Publish │──▶│ Deploy │
└──────┘   └───────────────┘   └─────────────┘   └──────┘   └─────────┘   └────────┘
                                                                              │
                                                                    ┌────────┴────────┐
                                                                    │ staging │  prod  │
                                                                    └─────────────────┘
```

### 4.2 Pipeline Triggers

| Trigger | Pipeline | Scope |
|---------|----------|-------|
| Push to `main` | Full: lint → build → image → test → publish | All roles |
| Pull request | Partial: lint → build → image → test | Changed roles only |
| Git tag `v*` | Full + release: lint → build → image → test → publish → release | All roles |
| Manual dispatch | Configurable | Selected roles |
| Scheduled (nightly) | Full + extended tests | All roles, includes slow tests |

### 4.3 GitHub Actions Pipeline

```yaml
# .github/workflows/ci.yml
name: ANDYL OS CI

on:
  push:
    branches: [main]
    tags: ['v*']
  pull_request:
    branches: [main]
  workflow_dispatch:
    inputs:
      roles:
        description: 'Roles to build (comma-separated, or "all")'
        default: 'all'
      skip_tests:
        description: 'Skip QEMU integration tests'
        type: boolean
        default: false
  schedule:
    - cron: '0 2 * * *'  # Nightly at 2 AM UTC

env:
  GUIX_CACHE_URL: https://cache.andyl.internal
  IMAGE_REGISTRY: ghcr.io/andyl/andyl-os

jobs:
  # ── Stage 1: Lint ──────────────────────────────────────
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Validate Guix package definitions
        run: |
          docker run --rm \
            -v "$PWD:/workspace:ro" \
            andyl-os-builder \
            bash -c "
              cd /workspace
              # Check Scheme syntax
              for f in packages/*.scm; do
                guile -c \"(load \\\"$f\\\")\" || exit 1
              done
              # Lint packages
              for pkg in \$(guix package -A 2>/dev/null | grep andyl | cut -f1); do
                guix lint \$pkg || exit 1
              done
            "

      - name: Validate system configurations
        run: |
          docker run --rm \
            -v "$PWD:/workspace:ro" \
            andyl-os-builder \
            bash -c "
              cd /workspace
              for role in roles/*/system.scm; do
                echo \"Checking \$role...\"
                guix system -n build \"\$role\" || exit 1
              done
            "

  # ── Stage 2: Build Packages ────────────────────────────
  build-packages:
    needs: lint
    runs-on: [self-hosted, linux, x64]  # Needs /gnu/store persistence
    steps:
      - uses: actions/checkout@v4

      - name: Restore Guix store cache
        uses: actions/cache@v4
        with:
          path: /gnu/store-cache
          key: guix-store-${{ hashFiles('channels.scm', 'packages/**') }}
          restore-keys: |
            guix-store-

      - name: Build all packages
        run: |
          docker run --rm \
            -v guix-store:/gnu/store \
            -v guix-var:/var/guix \
            -v "$PWD:/workspace:ro" \
            -e GUIX_DAEMON_OPTS="--substitute-urls=$GUIX_CACHE_URL" \
            andyl-os-builder \
            bash -c "
              cd /workspace
              # Build all ANDYL OS packages
              guix build -L packages/ \
                \$(guix package -A -L packages/ 2>/dev/null | cut -f1 | tr '\n' ' ')
            "

      - name: Push to binary cache
        run: |
          # Push newly built paths to cache
          docker run --rm \
            -v guix-store:/gnu/store \
            -v guix-var:/var/guix \
            -v "$PWD/keys:/keys:ro" \
            andyl-os-builder \
            bash -c "
              guix copy --to=ssh://cache@cache.andyl.internal \
                \$(guix build -L /workspace/packages/ --no-grafts -q \
                  \$(guix package -A -L /workspace/packages/ 2>/dev/null | cut -f1))
            "

  # ── Stage 3: Build Images ─────────────────────────────
  build-images:
    needs: build-packages
    runs-on: [self-hosted, linux, x64]
    strategy:
      matrix:
        role: [k8s-worker, k8s-control, storage, gateway]
    steps:
      - uses: actions/checkout@v4

      - name: Build golden image for ${{ matrix.role }}
        run: |
          docker run --rm \
            -v guix-store:/gnu/store \
            -v guix-var:/var/guix \
            -v "$PWD:/workspace:ro" \
            -v "$PWD/build:/output" \
            -e GUIX_DAEMON_OPTS="--substitute-urls=$GUIX_CACHE_URL" \
            --privileged \
            andyl-os-builder \
            bash -c "
              guix system image \
                --image-type=qcow2 \
                -L /workspace/packages/ \
                /workspace/roles/${{ matrix.role }}/system.scm \
                -o /output/${{ matrix.role }}.qcow2
            "

      - name: Record image hash
        run: |
          sha256sum build/${{ matrix.role }}.qcow2 > \
            build/${{ matrix.role }}.qcow2.sha256

      - name: Upload image artifact
        uses: actions/upload-artifact@v4
        with:
          name: image-${{ matrix.role }}
          path: |
            build/${{ matrix.role }}.qcow2
            build/${{ matrix.role }}.qcow2.sha256
          retention-days: 7

  # ── Stage 4: Integration Tests ─────────────────────────
  test:
    needs: build-images
    if: ${{ !inputs.skip_tests }}
    runs-on: [self-hosted, linux, x64, kvm]  # Must have /dev/kvm
    strategy:
      matrix:
        role: [k8s-worker, k8s-control, storage, gateway]
      fail-fast: false  # Run all role tests even if one fails
    steps:
      - uses: actions/checkout@v4

      - name: Download image
        uses: actions/download-artifact@v4
        with:
          name: image-${{ matrix.role }}
          path: build/

      - name: Verify image hash
        run: sha256sum -c build/${{ matrix.role }}.qcow2.sha256

      - name: Install test dependencies
        run: |
          pip install pytest paramiko pexpect pytest-timeout pytest-html

      - name: Run integration tests
        env:
          TEST_IMAGE: build/${{ matrix.role }}.qcow2
          TEST_ROLE: ${{ matrix.role }}
          TEST_IGNITION: tests/fixtures/${{ matrix.role }}-ignition.json
        run: |
          pytest tests/ \
            -v \
            --timeout=300 \
            --junitxml=test-results/${{ matrix.role }}.xml \
            --html=test-results/${{ matrix.role }}.html \
            -k "not slow" \
            2>&1 | tee test-results/${{ matrix.role }}.log

      - name: Upload test artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: test-results-${{ matrix.role }}
          path: test-results/
          retention-days: 14

      - name: Publish test results
        if: always()
        uses: dorny/test-reporter@v1
        with:
          name: Tests (${{ matrix.role }})
          path: test-results/${{ matrix.role }}.xml
          reporter: java-junit

  # ── Stage 5: Publish ───────────────────────────────────
  publish:
    needs: test
    if: github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v')
    runs-on: [self-hosted, linux, x64]
    steps:
      - uses: actions/checkout@v4

      - name: Download all images
        uses: actions/download-artifact@v4
        with:
          pattern: image-*
          merge-multiple: true
          path: build/

      - name: Upload to artifact storage
        run: |
          VERSION="${GITHUB_SHA::8}"
          if [[ "$GITHUB_REF" == refs/tags/v* ]]; then
            VERSION="${GITHUB_REF#refs/tags/}"
          fi

          for img in build/*.qcow2; do
            role=$(basename "$img" .qcow2)
            echo "Publishing $role version $VERSION"

            # Upload to S3/MinIO/artifact store
            aws s3 cp "$img" \
              "s3://andyl-os-images/$role/$VERSION/$role.qcow2"
            aws s3 cp "$img.sha256" \
              "s3://andyl-os-images/$role/$VERSION/$role.qcow2.sha256"

            # Tag as latest for this environment
            aws s3 cp "$img" \
              "s3://andyl-os-images/$role/dev-latest/$role.qcow2"
          done

      - name: Update image manifest
        run: |
          # Create/update manifest file tracking latest versions
          echo "{
            \"version\": \"$VERSION\",
            \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
            \"commit\": \"$GITHUB_SHA\",
            \"images\": {
              $(for img in build/*.qcow2; do
                role=$(basename "$img" .qcow2)
                hash=$(sha256sum "$img" | cut -d' ' -f1)
                echo "\"$role\": {\"sha256\": \"$hash\"}"
              done | paste -sd,)
            }
          }" | jq . > manifest.json

          aws s3 cp manifest.json "s3://andyl-os-images/manifests/$VERSION.json"

  # ── Stage 6: Release (tags only) ───────────────────────
  release:
    needs: publish
    if: startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          generate_release_notes: true
          files: |
            build/*.qcow2.sha256
          body: |
            ## ANDYL OS ${{ github.ref_name }}

            ### Images
            Download images from artifact storage:
            ```
            aws s3 cp s3://andyl-os-images/<role>/${{ github.ref_name }}/ .
            ```
```

### 4.4 Alternative CI Systems

#### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - lint
  - build
  - test
  - publish

variables:
  GUIX_CACHE_URL: https://cache.andyl.internal

lint:
  stage: lint
  image: andyl-os-builder:latest
  script:
    - for f in packages/*.scm; do guile -c "(load \"$f\")"; done
    - guix lint $(guix package -A | grep andyl | cut -f1)

build:
  stage: build
  tags: [guix-builder]  # Self-hosted runner with /gnu/store
  parallel:
    matrix:
      - ROLE: [k8s-worker, k8s-control, storage, gateway]
  script:
    - guix system image --image-type=qcow2 roles/$ROLE/system.scm -o build/$ROLE.qcow2
  artifacts:
    paths:
      - build/*.qcow2
    expire_in: 7 days

test:
  stage: test
  tags: [kvm]  # Runner with KVM access
  parallel:
    matrix:
      - ROLE: [k8s-worker, k8s-control, storage, gateway]
  script:
    - pytest tests/ -v --junitxml=results.xml
  artifacts:
    reports:
      junit: results.xml
    when: always
```

#### Buildkite

```yaml
# .buildkite/pipeline.yml
steps:
  - label: ":lint: Lint"
    command: just lint
    plugins:
      - docker#v5.0.0:
          image: andyl-os-builder:latest

  - wait

  - group: ":package: Build Images"
    steps:
      - label: ":package: Build {{matrix}}"
        command: just build-image {{matrix}}
        matrix:
          - k8s-worker
          - k8s-control
          - storage
          - gateway
        agents:
          queue: guix-builder
        artifact_paths: "build/*.qcow2"

  - wait

  - group: ":test_tube: Integration Tests"
    steps:
      - label: ":test_tube: Test {{matrix}}"
        command: just test {{matrix}}
        matrix:
          - k8s-worker
          - k8s-control
          - storage
          - gateway
        agents:
          queue: kvm
        artifact_paths: "test-results/**/*"
```

### 4.5 Build Matrix

| Role | Architecture | Priority | Notes |
|------|-------------|----------|-------|
| k8s-worker | x86_64 | High | Most common node type |
| k8s-control | x86_64 | High | Control plane |
| storage | x86_64 | Medium | ZFS-focused |
| gateway | x86_64 | Medium | Network edge |
| k8s-worker | aarch64 | Low | Future: ARM servers |
| k8s-control | aarch64 | Low | Future: ARM control plane |

For aarch64 cross-compilation:

```bash
# Cross-build from x86_64
guix system image --target=aarch64-linux-gnu roles/k8s-worker/system.scm

# Or build natively on aarch64 runner
# (separate CI runner pool)
```

### 4.6 Caching Strategy in CI

```
┌─────────────────────────────────────────────────┐
│ CI Caching Layers                               │
│                                                 │
│  Layer 1: Docker layer cache                    │
│    - Builder image rarely changes               │
│    - Cache Dockerfile layers in registry        │
│                                                 │
│  Layer 2: /gnu/store volume                     │
│    - Persistent named volume on self-hosted      │
│      runner                                     │
│    - Contains all previously built derivations  │
│    - Guix automatically reuses existing paths   │
│                                                 │
│  Layer 3: Binary cache server                   │
│    - Shared across all runners                  │
│    - guix build --substitute-urls=...           │
│    - Fetches pre-built NARs instead of building │
│                                                 │
│  Layer 4: GitHub Actions cache (fallback)       │
│    - actions/cache for /gnu/store tarball        │
│    - Slow to restore (large), but works for     │
│      ephemeral runners                          │
│                                                 │
└─────────────────────────────────────────────────┘
```

For self-hosted runners, Layer 2 (persistent volume) is the most effective.
For ephemeral runners (GitHub-hosted), Layer 3 (binary cache) is essential.

### 4.7 Image Promotion Workflow

```
dev (every merge to main)
  │
  ├──── automatic tests pass
  │
  ▼
staging (manual promotion or auto after 3 days soak)
  │
  ├──── staging validation
  ├──── canary deployment (10% of fleet)
  ├──── monitoring (error rates, resource usage)
  │
  ▼
production (manual approval after canary success)
  │
  ├──── rolling deployment
  ├──── automatic rollback on failure
  │
  ▼
fleet-wide
```

Promotion commands:

```bash
# Promote dev to staging
just promote dev staging v0.5.0-abc1234

# Promote staging to production (requires approval)
just promote staging production v0.5.0-abc1234 --canary-percent=10

# Emergency rollback
just rollback production v0.4.9-def5678
```

### 4.8 Notifications

| Event | Channel | Format |
|-------|---------|--------|
| Build started | Slack #builds | "Build #123 started for main@abc1234" |
| Build failed | Slack #builds + page on-call | "Build #123 FAILED at stage: test (k8s-worker)" |
| Tests passed | Slack #builds | "All 47 tests passed for k8s-worker, k8s-control, storage, gateway" |
| Image published | Slack #releases | "andyl-os v0.5.0 published (4 images)" |
| Promotion | Slack #releases | "v0.5.0 promoted to staging" |
| Canary failure | Slack #alerts + PagerDuty | "Canary failed: error rate > 5% on k8s-worker v0.5.0" |

---

## 5. justfile Structure

The `justfile` is the developer-facing interface to the entire build and test
pipeline. Every CI operation should be expressible as a `just` target.

```justfile
# ANDYL OS Build System
# Usage: just <target> [args...]

# ─── Configuration ──────────────────────────────────────
# Can be overridden: just DOCKER_RUNTIME=orbstack build-image k8s-worker

DOCKER_RUNTIME := env("DOCKER_RUNTIME", "docker")
BUILDER_IMAGE := "andyl-os-builder:latest"
GUIX_CACHE_URL := env("GUIX_CACHE_URL", "https://cache.andyl.internal")
BUILD_DIR := justfile_directory() / "build"
QEMU_ACCEL := if os() == "linux" { "kvm" } else { "hvf,fallback=tcg" }

# Roles available for building
ROLES := "k8s-worker k8s-control storage gateway"

# ─── Bootstrap ──────────────────────────────────────────

# Set up Docker build environment from scratch
bootstrap:
    @echo "Building Guix builder image..."
    {{DOCKER_RUNTIME}} build \
        -t {{BUILDER_IMAGE}} \
        -f docker/Dockerfile \
        .
    @echo "Creating persistent volumes..."
    {{DOCKER_RUNTIME}} volume create guix-store || true
    {{DOCKER_RUNTIME}} volume create guix-var || true
    @echo "Pulling Guix channels (this takes a while on first run)..."
    just _guix-shell "guix pull"
    @echo "Bootstrap complete."

# ─── Building ───────────────────────────────────────────

# Build all ANDYL OS packages
build-packages:
    just _guix-shell " \
        guix build -L /workspace/packages/ \
            \$(guix package -A -L /workspace/packages/ 2>/dev/null | cut -f1 | tr '\n' ' ') \
    "

# Build golden image for a specific role
build-image role:
    @mkdir -p {{BUILD_DIR}}
    @echo "Building image for role: {{role}}"
    {{DOCKER_RUNTIME}} run --rm \
        -v guix-store:/gnu/store \
        -v guix-var:/var/guix \
        -v "{{justfile_directory()}}:/workspace:ro" \
        -v "{{BUILD_DIR}}:/output" \
        -e GUIX_DAEMON_OPTS="--substitute-urls={{GUIX_CACHE_URL}}" \
        --privileged \
        {{BUILDER_IMAGE}} \
        bash -c " \
            guix system image \
                --image-type=qcow2 \
                -L /workspace/packages/ \
                /workspace/roles/{{role}}/system.scm \
                -o /output/{{role}}.qcow2 \
        "
    @echo "Image built: {{BUILD_DIR}}/{{role}}.qcow2"
    sha256sum {{BUILD_DIR}}/{{role}}.qcow2 > {{BUILD_DIR}}/{{role}}.qcow2.sha256

# Build images for all roles
build-all:
    #!/usr/bin/env bash
    set -euo pipefail
    for role in {{ROLES}}; do
        echo "=== Building $role ==="
        just build-image "$role"
    done

# ─── Testing ────────────────────────────────────────────

# Run QEMU integration tests for a role
test role:
    @echo "Testing image for role: {{role}}"
    @test -f "{{BUILD_DIR}}/{{role}}.qcow2" || (echo "Image not found. Run: just build-image {{role}}" && exit 1)
    TEST_IMAGE="{{BUILD_DIR}}/{{role}}.qcow2" \
    TEST_ROLE="{{role}}" \
    TEST_IGNITION="tests/fixtures/{{role}}-ignition.json" \
    QEMU_ACCEL="{{QEMU_ACCEL}}" \
    pytest tests/ \
        -v \
        --timeout=300 \
        --junitxml={{BUILD_DIR}}/test-results/{{role}}.xml \
        --html={{BUILD_DIR}}/test-results/{{role}}.html \
        2>&1 | tee {{BUILD_DIR}}/test-results/{{role}}.log

# Run integration tests for all roles
test-all:
    #!/usr/bin/env bash
    set -euo pipefail
    failed=0
    for role in {{ROLES}}; do
        echo "=== Testing $role ==="
        if ! just test "$role"; then
            failed=1
            echo "FAIL: $role"
        fi
    done
    exit $failed

# Quick smoke test (boot only, no full test suite)
test-smoke role:
    @echo "Smoke testing {{role}}..."
    TEST_IMAGE="{{BUILD_DIR}}/{{role}}.qcow2" \
    QEMU_ACCEL="{{QEMU_ACCEL}}" \
    pytest tests/test_boot.py -v --timeout=180

# ─── Binary Cache ───────────────────────────────────────

# Push build artifacts to binary cache
cache-push:
    just _guix-shell " \
        guix copy --to=ssh://cache@cache.andyl.internal \
            \$(guix build -L /workspace/packages/ --no-grafts -q \
                \$(guix package -A -L /workspace/packages/ 2>/dev/null | cut -f1)) \
    "

# Start a local cache server for development
cache-serve port="8080":
    just _guix-shell " \
        guix publish --port={{port}} --compression=zstd:3 \
            --cache=/var/cache/guix/publish \
    "

# ─── Release ────────────────────────────────────────────

# Tag and publish a release
release tag:
    @echo "Creating release {{tag}}"
    git tag -a "{{tag}}" -m "Release {{tag}}"
    git push origin "{{tag}}"
    @echo "CI will build, test, and publish images for {{tag}}"

# Promote an image from one environment to another
promote from to version:
    @echo "Promoting {{version}} from {{from}} to {{to}}"
    #!/usr/bin/env bash
    set -euo pipefail
    for role in {{ROLES}}; do
        aws s3 cp \
            "s3://andyl-os-images/$role/{{from}}/{{version}}/$role.qcow2" \
            "s3://andyl-os-images/$role/{{to}}-latest/$role.qcow2"
    done
    echo "Promoted {{version}} to {{to}}"

# ─── Development ────────────────────────────────────────

# Lint package definitions
lint:
    just _guix-shell " \
        cd /workspace && \
        for f in packages/*.scm; do \
            echo \"Checking \$f...\" && \
            guile -c \"(load \\\"\$f\\\")\" || exit 1; \
        done && \
        echo 'All package definitions valid.' \
    "

# Verify build reproducibility (build twice, compare hashes)
check-reproducibility role="k8s-worker":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Build 1..."
    just build-image {{role}}
    hash1=$(sha256sum {{BUILD_DIR}}/{{role}}.qcow2 | cut -d' ' -f1)
    mv {{BUILD_DIR}}/{{role}}.qcow2 {{BUILD_DIR}}/{{role}}-build1.qcow2

    echo "Build 2..."
    just build-image {{role}}
    hash2=$(sha256sum {{BUILD_DIR}}/{{role}}.qcow2 | cut -d' ' -f1)

    echo "Build 1: $hash1"
    echo "Build 2: $hash2"

    if [ "$hash1" = "$hash2" ]; then
        echo "PASS: Builds are reproducible"
        rm {{BUILD_DIR}}/{{role}}-build1.qcow2
    else
        echo "FAIL: Builds differ!"
        echo "Kept both builds for investigation:"
        echo "  {{BUILD_DIR}}/{{role}}-build1.qcow2"
        echo "  {{BUILD_DIR}}/{{role}}.qcow2"
        exit 1
    fi

# Diff two image generations (list package differences)
diff old new:
    just _guix-shell " \
        guix system describe {{old}} > /tmp/gen-old.txt && \
        guix system describe {{new}} > /tmp/gen-new.txt && \
        diff -u /tmp/gen-old.txt /tmp/gen-new.txt || true \
    "

# Drop into the Guix build environment shell
shell:
    {{DOCKER_RUNTIME}} run --rm -it \
        -v guix-store:/gnu/store \
        -v guix-var:/var/guix \
        -v "{{justfile_directory()}}:/workspace" \
        -e GUIX_DAEMON_OPTS="--substitute-urls={{GUIX_CACHE_URL}}" \
        --privileged \
        {{BUILDER_IMAGE}} \
        bash

# ─── Maintenance ────────────────────────────────────────

# Run garbage collection on build artifacts
gc:
    @echo "Running garbage collection..."
    just _guix-shell " \
        guix gc --delete-generations=30d && \
        echo 'Store size:' && \
        du -sh /gnu/store \
    "
    @echo "Cleaning old build artifacts..."
    find {{BUILD_DIR}} -name "*.qcow2" -mtime +30 -delete 2>/dev/null || true
    @echo "GC complete."

# Clean all build artifacts (keeps /gnu/store volume)
clean:
    rm -rf {{BUILD_DIR}}/*
    @echo "Build artifacts cleaned."

# Full clean including Docker volumes (WARNING: slow rebuild after this)
clean-all: clean
    @echo "WARNING: This will delete the Guix store and require a full rebuild."
    @echo "Press Ctrl+C to cancel, or Enter to continue."
    @read
    {{DOCKER_RUNTIME}} volume rm guix-store guix-var 2>/dev/null || true
    @echo "Full clean complete. Run 'just bootstrap' to set up again."

# Update Guix channels to latest
update-channels:
    just _guix-shell "guix pull"

# Show current Guix version and channel info
info:
    just _guix-shell "guix describe"

# ─── Internal Helpers ───────────────────────────────────

# Run a command inside the Guix builder container
_guix-shell cmd:
    {{DOCKER_RUNTIME}} run --rm \
        -v guix-store:/gnu/store \
        -v guix-var:/var/guix \
        -v "{{justfile_directory()}}:/workspace:ro" \
        -e GUIX_DAEMON_OPTS="--substitute-urls={{GUIX_CACHE_URL}}" \
        --privileged \
        {{BUILDER_IMAGE}} \
        bash -c "{{cmd}}"
```

### 5.1 Target Documentation

| Target | Description | Dependencies | Duration |
|--------|-------------|-------------|----------|
| `bootstrap` | One-time setup. Builds Docker image, creates volumes, pulls channels. | Docker installed | 15-30 min |
| `build-packages` | Builds all custom packages. Incremental -- skips already-built packages via store dedup. | `bootstrap` | 5-60 min (depends on cache) |
| `build-image ROLE` | Builds a qcow2 golden image for the given role. | `build-packages` | 10-30 min |
| `build-all` | Builds images for all roles sequentially. | `build-packages` | 30-120 min |
| `test ROLE` | Boots image in QEMU, runs pytest integration suite. | `build-image` | 5-15 min |
| `test-all` | Tests all role images. | `build-all` | 20-60 min |
| `test-smoke ROLE` | Quick boot-only test. | `build-image` | 2-5 min |
| `cache-push` | Pushes built packages to binary cache server. | Build completed | 2-10 min |
| `cache-serve` | Starts local guix publish for dev use. | `build-packages` | Runs until stopped |
| `release TAG` | Tags repo, pushes tag to trigger release pipeline. | Clean git state | Seconds |
| `promote FROM TO VER` | Copies images between environments in artifact storage. | Images published | 1-5 min |
| `lint` | Validates Scheme syntax and guix lint on all packages. | `bootstrap` | 1-3 min |
| `check-reproducibility` | Builds twice, compares SHA256. Verifies determinism. | `bootstrap` | 2x build time |
| `diff OLD NEW` | Shows package differences between two system generations. | Two generations | Seconds |
| `shell` | Interactive shell in build environment. For debugging and exploration. | `bootstrap` | Instant |
| `gc` | Deletes old generations and build artifacts > 30 days. | None | 1-5 min |
| `clean` | Removes build output directory. Keeps /gnu/store. | None | Instant |
| `clean-all` | Removes everything including Docker volumes. Nuclear option. | None | Instant (rebuild takes 15+ min) |
| `update-channels` | Pulls latest Guix and ANDYL OS channel commits. | `bootstrap` | 5-15 min |
| `info` | Shows Guix version, channel commits. | `bootstrap` | Seconds |

---

## 6. Test Infrastructure

### 6.1 Test Environment Management

#### VM Lifecycle

Tests must manage QEMU VMs deterministically:

```python
# tests/conftest.py (expanded)

@pytest.fixture(scope="session")
def vm_pool():
    """Manage multiple VMs for multi-node tests."""
    vms = {}
    yield vms
    for name, vm in vms.items():
        vm.stop()

@pytest.fixture
def fresh_vm(tmp_path):
    """Per-test VM with a fresh copy of the image (copy-on-write)."""
    # Create COW overlay so each test gets a clean slate
    base_image = os.environ["TEST_IMAGE"]
    overlay = tmp_path / "test-overlay.qcow2"
    subprocess.run([
        "qemu-img", "create",
        "-f", "qcow2",
        "-b", base_image,
        "-F", "qcow2",
        str(overlay)
    ], check=True)

    vm = QEMUInstance(str(overlay))
    vm.start()
    vm.wait_for_ssh()
    yield vm
    vm.stop()
```

Using qcow2 overlays (backing files) enables per-test isolation without
copying the full image. Each test writes to its own overlay; the base image
is read-only.

#### Network Isolation

For multi-VM tests, use isolated network namespaces (Linux CI only):

```bash
# Create isolated network for test VMs
ip netns add test-ns-$TEST_ID
ip link add veth-host-$TEST_ID type veth peer name veth-vm-$TEST_ID
ip link set veth-vm-$TEST_ID netns test-ns-$TEST_ID

# Cleanup after test
ip netns del test-ns-$TEST_ID
```

#### Storage for ZFS Tests

Create ephemeral qcow2 disks for ZFS pool testing:

```bash
# Create a temporary disk for ZFS
qemu-img create -f qcow2 /tmp/zfs-test-$$.qcow2 10G

# Pass to QEMU as second disk
-drive file=/tmp/zfs-test-$$.qcow2,format=qcow2,if=virtio
```

### 6.2 Test Data Management

Test fixtures live in `tests/fixtures/`:

```
tests/
  fixtures/
    k8s-worker-ignition.json     # Ignition config for k8s-worker role
    k8s-control-ignition.json    # Ignition config for control plane
    storage-ignition.json        # Ignition config for storage role
    gateway-ignition.json        # Ignition config for gateway role
    ssh-keys/
      test-key                   # Ephemeral SSH key for test access
      test-key.pub
    certificates/
      test-ca.pem                # Test CA for TLS validation
```

Generate test SSH keys at test setup time (do not commit real keys):

```python
@pytest.fixture(scope="session", autouse=True)
def test_ssh_key(tmp_path_factory):
    key_dir = tmp_path_factory.mktemp("ssh")
    key_path = key_dir / "test-key"
    subprocess.run([
        "ssh-keygen", "-t", "ed25519",
        "-f", str(key_path),
        "-N", "",  # No passphrase
        "-C", "andyl-os-test"
    ], check=True)
    os.environ["TEST_SSH_KEY"] = str(key_path)
    return key_path
```

### 6.3 Parallel Test Execution

Tests within a single role can run in parallel using `pytest-xdist`:

```bash
pytest tests/ -n 4 --dist loadfile
```

However, VM-based tests have constraints:
- Each parallel worker needs its own QEMU instance
- Port conflicts: each VM needs unique SSH port forwarding
- Resource limits: each VM uses 4 GB RAM

Strategy for parallel execution:

```python
# Use pytest-xdist worker ID for port allocation
@pytest.fixture(scope="session")
def vm(worker_id):
    """Worker-aware VM fixture."""
    # worker_id is "gw0", "gw1", etc. or "master" if not parallel
    if worker_id == "master":
        ssh_port = 2222
    else:
        worker_num = int(worker_id.replace("gw", ""))
        ssh_port = 2222 + worker_num

    instance = QEMUInstance(os.environ["TEST_IMAGE"])
    instance.ssh_port = ssh_port
    instance.start()
    instance.wait_for_ssh()
    yield instance
    instance.stop()
```

**Parallelism recommendations**:

| Level | Parallelism | Mechanism |
|-------|------------|-----------|
| Across roles | High (4x) | CI matrix: each role tests on a separate runner |
| Within a role | Limited (2-3x) | pytest-xdist with port isolation |
| Within a test | None | Tests are sequential within a VM |

### 6.4 Test Reporting and Dashboards

#### JUnit XML for CI Integration

```bash
pytest tests/ --junitxml=results.xml
```

Every major CI system (GitHub Actions, GitLab, Buildkite, Jenkins) natively
displays JUnit XML results.

#### HTML Reports for Humans

```bash
pytest tests/ --html=report.html --self-contained-html
```

#### Custom Dashboard (Optional)

For teams tracking test health over time:

```bash
# Export results to a time-series database
# (e.g., Prometheus pushgateway, InfluxDB, or simple SQLite)

python -c "
import xml.etree.ElementTree as ET
import json, time

tree = ET.parse('results.xml')
root = tree.getroot()
suite = root.find('testsuite')

metrics = {
    'timestamp': int(time.time()),
    'tests': int(suite.get('tests', 0)),
    'failures': int(suite.get('failures', 0)),
    'errors': int(suite.get('errors', 0)),
    'time': float(suite.get('time', 0)),
    'role': '$TEST_ROLE',
    'commit': '$GITHUB_SHA',
}
print(json.dumps(metrics))
" >> test-metrics.jsonl
```

### 6.5 Flaky Test Handling

Flaky tests erode confidence in CI. Strategies:

1. **Automatic retry with quarantine**:

   ```bash
   # pytest-rerunfailures: retry failed tests up to 2 times
   pytest tests/ --reruns 2 --reruns-delay 5
   ```

2. **Quarantine known-flaky tests**:

   ```python
   @pytest.mark.flaky(reruns=3, reason="k8s node registration timing")
   def test_node_ready(vm):
       ...
   ```

3. **Track flake rate**: If a test fails intermittently > 5% of runs, it
   must be fixed or quarantined. Never let flaky tests block the pipeline
   permanently.

4. **Root cause categories**:
   - Timing-dependent (use polling with timeout, not `sleep`)
   - Resource contention (increase VM resources or reduce parallelism)
   - Non-deterministic ordering (explicit waits for readiness)
   - External dependencies (mock or retry)

### 6.6 Test Timeout Configuration

Every test level needs timeouts to prevent hung pipelines:

```python
# pytest.ini or pyproject.toml
[tool.pytest.ini_options]
timeout = 300           # Default: 5 minutes per test
timeout_method = "signal"

# Per-test override for slow tests
markers = [
    "slow: marks tests as slow (>5 min)",
]
```

```python
@pytest.mark.timeout(600)  # 10 minutes for update/rollback test
def test_update_rollback(vm):
    ...

@pytest.mark.timeout(60)  # 1 minute for simple checks
def test_hostname(vm):
    ...
```

VM-level timeouts:

| Operation | Timeout | Action on Timeout |
|-----------|---------|-------------------|
| VM boot (SSH available) | 180s | Kill QEMU, fail test, collect serial log |
| systemd reach running | 120s | Dump journal, fail |
| K8s node Ready | 120s | Dump kubectl, fail |
| Individual SSH command | 30s | Fail assertion |
| Full test suite (per role) | 900s (15 min) | Kill all VMs, fail job |

### 6.7 Resource Cleanup

Resources must be cleaned up even on test failure. Use pytest fixtures with
finalizers and trap-based cleanup in shell scripts.

```python
# Fixture-based cleanup (Python/pytest)
@pytest.fixture
def vm():
    instance = QEMUInstance(...)
    instance.start()
    yield instance
    # This runs even if the test fails
    instance.stop()
    instance.cleanup_artifacts()

# Or with explicit finalizer
@pytest.fixture
def vm(request):
    instance = QEMUInstance(...)
    instance.start()

    def cleanup():
        instance.stop()
        # Remove overlay images
        for f in glob.glob("/tmp/test-overlay-*.qcow2"):
            os.unlink(f)
        # Remove QEMU sockets
        for f in glob.glob("/tmp/qemu-*.sock"):
            os.unlink(f)

    request.addfinalizer(cleanup)
    return instance
```

```bash
# Trap-based cleanup (shell scripts)
cleanup() {
    echo "Cleaning up test resources..."

    # Kill any remaining QEMU processes
    for pid_file in /tmp/qemu-test-*.pid; do
        [ -f "$pid_file" ] && kill "$(cat "$pid_file")" 2>/dev/null
        rm -f "$pid_file"
    done

    # Remove temporary disk images
    rm -f /tmp/zfs-test-*.qcow2
    rm -f /tmp/test-overlay-*.qcow2

    # Remove sockets
    rm -f /tmp/qemu-monitor-*.sock /tmp/qemu-serial-*.sock
}

trap cleanup EXIT INT TERM
```

CI-level cleanup (GitHub Actions):

```yaml
- name: Cleanup test resources
  if: always()
  run: |
    # Kill any orphaned QEMU processes
    pkill -f "qemu-system" || true

    # Remove temporary files
    rm -rf /tmp/qemu-* /tmp/test-* /tmp/serial-*

    # Prune Docker resources
    docker system prune -f --volumes --filter "label=andyl-test"
```

---

## Summary

The ANDYL OS build and test pipeline is structured as:

1. **Developer workflow**: `just` targets for building, testing, and releasing
   from macOS using Docker.
2. **Build environment**: Deterministic Dockerfile with Guix, persistent
   `/gnu/store` volume, pinned channels and base images.
3. **Binary cache**: `guix publish` behind nginx, signed NARs, content-addressed
   caching with optional S3 backend.
4. **Integration testing**: QEMU with HVF/KVM acceleration, pytest framework,
   comprehensive test scenarios covering boot, services, ZFS, k8s, Ignition,
   updates, and rollback.
5. **CI/CD**: GitHub Actions with self-hosted runners, build matrix across roles,
   image promotion pipeline (dev to staging to production).
6. **Test infrastructure**: Isolated per-test VMs via qcow2 overlays, parallel
   execution, structured reporting, and deterministic cleanup.

The key design principles are:
- **Reproducibility**: pinned images, channels, and content-addressed caching.
- **Incremental builds**: only rebuild what changed.
- **Test fidelity**: QEMU tests exercise the actual boot path.
- **Developer ergonomics**: `just test k8s-worker` from a laptop.
