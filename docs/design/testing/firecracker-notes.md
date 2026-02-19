# Firecracker Integration Notes for AOS Test Harness

Reference document for implementing the Firecracker-based test harness. Contains
concrete configuration examples, CLI invocations, gotchas, and recommendations.

Sources:
- [Firecracker getting-started](https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md)
- [Firecracker vsock docs](https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md)
- [Firecracker FAQ](https://github.com/firecracker-microvm/firecracker/blob/main/FAQ.md)
- [Firecracker rootfs-and-kernel-setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/rootfs-and-kernel-setup.md)
- [Firecracker kernel-policy](https://github.com/firecracker-microvm/firecracker/blob/main/docs/kernel-policy.md)
- [Firecracker vm_config.json](https://github.com/firecracker-microvm/firecracker/blob/main/tests/framework/vm_config.json)
- [socat AF_VSOCK support](https://stefano-garzarella.github.io/posts/2021-01-22-socat-vsock/)

---

## 1. `--no-api` mode and JSON config

### How `--no-api` works

Firecracker normally exposes a REST API over a Unix domain socket (`--api-sock`).
The `--no-api` flag disables this API socket entirely. When used, a `--config-file`
must be provided instead. Firecracker reads the JSON config, configures the VM,
and starts it immediately -- no HTTP requests needed.

```bash
firecracker --no-api --config-file vm_config.json
```

This is the mode AOS tests should use. Benefits:
- No API socket to create/clean up
- No multi-step HTTP configuration dance
- Single JSON file defines the entire VM
- Firecracker starts the VM immediately on launch

### Complete JSON config example

This is the config format AOS tests will use. All fields shown; optional ones
can be set to `null` or omitted.

```json
{
  "boot-source": {
    "kernel_image_path": "/nix/store/.../vmlinux",
    "boot_args": "console=ttyS0 reboot=k panic=1 root=/dev/vda ro init=/init",
    "initrd_path": null
  },
  "drives": [
    {
      "drive_id": "rootfs",
      "path_on_host": "/tmp/test-rootfs.ext4",
      "is_root_device": true,
      "is_read_only": true,
      "partuuid": null,
      "cache_type": "Unsafe",
      "io_engine": "Sync",
      "rate_limiter": null,
      "socket": null
    }
  ],
  "machine-config": {
    "vcpu_count": 1,
    "mem_size_mib": 256,
    "smt": false,
    "track_dirty_pages": false,
    "huge_pages": "None"
  },
  "vsock": {
    "guest_cid": 3,
    "uds_path": "/tmp/test-vm.vsock"
  },
  "cpu-config": null,
  "balloon": null,
  "network-interfaces": [],
  "logger": null,
  "metrics": null,
  "mmds-config": null,
  "entropy": null
}
```

### Field reference

| Section | Field | Type | Notes |
|---------|-------|------|-------|
| `boot-source` | `kernel_image_path` | string | Path to uncompressed vmlinux ELF |
| `boot-source` | `boot_args` | string | Kernel command line |
| `boot-source` | `initrd_path` | string/null | Optional initrd |
| `drives[]` | `drive_id` | string | Arbitrary identifier |
| `drives[]` | `path_on_host` | string | Path to raw disk image |
| `drives[]` | `is_root_device` | bool | Marks the root drive |
| `drives[]` | `is_read_only` | bool | Read-only mount |
| `drives[]` | `cache_type` | string | `"Unsafe"` or `"Writeback"` |
| `drives[]` | `io_engine` | string | `"Sync"` or `"Async"` |
| `machine-config` | `vcpu_count` | int | Number of vCPUs |
| `machine-config` | `mem_size_mib` | int | RAM in MiB |
| `vsock` | `guest_cid` | int | Guest context ID (3+) |
| `vsock` | `uds_path` | string | Host-side Unix socket path |

---

## 2. Serial console

### How it works

Firecracker emulates an 8250 serial device. The guest sees it as `/dev/ttyS0`.
By default, the serial console is **disabled** for boot performance. To enable
it, add `console=ttyS0` to `boot_args`.

When enabled, serial output goes to **Firecracker's stdout**. Firecracker does
not provide a separate socket or file for serial output -- it is literally the
process's stdout stream.

### Capturing serial output

To capture serial output to a file for grep/analysis:

```bash
firecracker --no-api --config-file vm_config.json > serial.log 2>&1
```

Or to capture stdout and stderr separately:

```bash
firecracker --no-api --config-file vm_config.json > serial.log 2>firecracker.log
```

Serial output on stdout; Firecracker's own log messages go to stderr (or to a
file if the `logger` config section is set).

### Grepping for PASS/FAIL markers

Yes. Since serial output goes to stdout, the test harness can:
1. Redirect stdout to a file
2. Wait for the Firecracker process to exit
3. Grep the file for markers like `TEST_PASS` or `TEST_FAIL`

This is the simplest communication mechanism for per-test integration VMs
(no systemd, no agent). The init script prints a marker and calls `reboot`.

### Performance note

Enabling `console=ttyS0` adds overhead as every `printk` and every line
written to `/dev/ttyS0` goes through the serial emulation path. For
integration tests that only need a pass/fail result, consider disabling the
console in `boot_args` and using vsock or exit-code-based signaling instead.
Keep `console=ttyS0` for system tests where boot logs are useful for debugging.

---

## 3. Kernel format

### Firecracker requires vmlinux (uncompressed ELF)

**Confirmed.** On x86_64, Firecracker requires an uncompressed ELF kernel image
(`vmlinux`), not `bzImage` or `vmlinuz`. On aarch64, it requires a PE-format
`Image`.

The Linux build produces `vmlinux` at the source tree root. The compressed
`bzImage` is at `arch/x86/boot/bzImage`. Firecracker cannot boot `bzImage`
directly.

### AOS kernel impact

The current AOS kernel build produces `vmlinuz-*` (compressed). For Firecracker,
the build must also produce or expose the uncompressed `vmlinux`. Options:

1. **Install both:** Have the kernel package install `vmlinux` alongside
   `vmlinuz-*` (vmlinux is ~30-60MB uncompressed)
2. **Extract from bzImage:** Use `extract-vmlinux` script from the kernel
   source tree, or `binwalk` to decompress bzImage at test time
3. **Separate derivation:** A test-only derivation that extracts vmlinux from
   the kernel build

**Recommendation:** Option 1 -- install `vmlinux` directly from the kernel
build. It is the cleanest approach and avoids runtime extraction.

### boot_args format

Space-separated kernel command line parameters as a single JSON string:

```json
"boot_args": "console=ttyS0 reboot=k panic=1 root=/dev/vda ro init=/init"
```

Common parameters for AOS tests:

| Parameter | Purpose |
|-----------|---------|
| `console=ttyS0` | Enable serial console output |
| `reboot=k` | Use keyboard controller for reboot (Firecracker intercepts this) |
| `panic=1` | Reboot 1 second after kernel panic |
| `root=/dev/vda` | Root filesystem on first virtio-blk drive |
| `ro` | Mount root read-only initially |
| `rw` | Mount root read-write initially |
| `init=/init` | Path to init process (for per-test VMs without systemd) |
| `init=/sbin/init` | Path to systemd (for system test VMs) |
| `quiet` | Suppress kernel boot messages (faster boot) |
| `enforcing=0` | SELinux permissive mode |

### Required kernel CONFIG options

Firecracker's minimal device model requires these kernel configs:

```
# Mandatory for Firecracker boot
CONFIG_KVM_GUEST=y

# Virtio transport (Firecracker uses MMIO by default, PCI with --enable-pci)
CONFIG_VIRTIO_MMIO=y         # or CONFIG_VIRTIO_PCI=y with --enable-pci
CONFIG_VIRTIO_BLK=y          # Block devices (rootfs)

# Filesystem (must be built-in, not module, for root mount)
CONFIG_EXT4_FS=y

# Serial console
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_PRINTK=y

# vsock (for host-guest communication)
CONFIG_VIRTIO_VSOCKETS=y

# Device infrastructure
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y

# Optional but recommended
CONFIG_VIRTIO_NET=y          # Network (fleet tests)
CONFIG_VIRTIO_BALLOON=y      # Memory ballooning
CONFIG_TMPFS=y               # tmpfs for /tmp, /run
CONFIG_PROC_FS=y
CONFIG_SYSFS=y
```

---

## 4. vsock communication

### Architecture overview

Firecracker implements virtio-vsock, which provides socket-based communication
between host and guest without requiring network configuration. The host side
uses Unix domain sockets (UDS); the guest side uses AF_VSOCK sockets.

```
Host                          Firecracker                    Guest
 |                               |                             |
 |-- connect to UDS ----------->|                             |
 |-- send "CONNECT 52\n" ------>|-- vsock connect CID:port -->|
 |<- "OK 1073741824\n" ---------|                             |
 |<========= bidirectional data stream ======================>|
```

### CID (Context ID) assignment

- CID 0: Hypervisor (reserved)
- CID 1: Reserved
- CID 2: Host (used by guest to connect outbound to host)
- CID 3+: Guests (assigned in the config via `guest_cid`)

For AOS tests, each VM gets a unique CID. Since per-test VMs run concurrently,
each derivation must use a distinct CID. A simple scheme: use a hash of the
test name modulo a range, or assign sequentially from 3.

**Gotcha:** If two concurrent Firecracker instances on the same host are
assigned the same CID, vsock will not work correctly. Each VM must have a
unique CID. Since AOS tests may run 32+ VMs concurrently, CID allocation
must be coordinated. A practical approach: use the Nix derivation hash or
the PID of the builder process to generate unique CIDs.

### Host-side UDS

When Firecracker starts with vsock configured, it creates a Unix domain socket
at the `uds_path` specified in the config. This socket is used for
**host-initiated** connections to the guest.

### Host-to-guest connections

1. Host connects to the UDS at `uds_path`
2. Host sends the text `CONNECT <port>\n` (ASCII, newline-terminated)
3. If a guest process is listening on that vsock port, Firecracker responds
   with `OK <host_port>\n`
4. The connection is now a bidirectional byte stream

**socat example (host side):**
```bash
# Connect to guest port 52 via the Firecracker vsock UDS
echo "CONNECT 52" | socat - UNIX-CONNECT:/tmp/test-vm.vsock
```

For a persistent bidirectional connection:
```bash
socat - UNIX-CONNECT:/tmp/test-vm.vsock <<< "CONNECT 52"
```

**Practical host-side helper (bash):**
```bash
# Send a command and read the response
vsock_command() {
    local uds_path="$1"
    local port="$2"
    local command="$3"
    # Open connection, send CONNECT, then send command, read response
    {
        printf 'CONNECT %d\n' "$port"
        sleep 0.1  # Wait for OK response
        printf '%s\n' "$command"
    } | socat - UNIX-CONNECT:"$uds_path" | tail -n +2  # Skip OK line
}
```

### Guest-to-host connections

For guest-initiated outbound connections, Firecracker uses a port-mapped UDS
convention:

1. Host creates a listening UDS at `<uds_path>_<port>` (e.g., `/tmp/test-vm.vsock_52`)
2. Guest connects to CID 2 (the host) on the desired port
3. Firecracker forwards the connection to the corresponding UDS

**Host listener:**
```bash
socat - UNIX-LISTEN:/tmp/test-vm.vsock_52
```

**Guest connector (using socat inside guest):**
```bash
socat - VSOCK-CONNECT:2:52
```

### Guest-side vsock listening

The guest needs `CONFIG_VIRTIO_VSOCKETS=y` in the kernel and `/dev/vsock` must
exist. Inside the guest, a process listens on an AF_VSOCK port using:

**With socat (if available in guest):**
```bash
socat - VSOCK-LISTEN:52,fork
```

**With C/custom binary (for minimal guests without socat):**
```c
#include <sys/socket.h>
#include <linux/vm_sockets.h>

int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
struct sockaddr_vm addr = {
    .svm_family = AF_VSOCK,
    .svm_cid = VMADDR_CID_ANY,  // Listen on any CID
    .svm_port = 52,
};
bind(fd, (struct sockaddr *)&addr, sizeof(addr));
listen(fd, 1);
int client = accept(fd, NULL, NULL);
// read/write on client fd
```

**Bash cannot natively open AF_VSOCK sockets.** There is no `/dev/vsock`
device file that bash can read/write like a regular file for arbitrary port
communication. The guest agent must use socat or a compiled helper binary.

### Recommendation for AOS

**For per-test integration VMs (no systemd):** Use serial console markers
(print `TEST_PASS` / `TEST_FAIL` to stdout, captured via serial). Simpler
than vsock for single-shot tests. The init script IS the test -- no agent
needed.

**For system test VMs (with systemd):** Use vsock for the guest agent
protocol (replacing the current virtio-serial approach). The guest agent
uses AOS-built socat to listen on a vsock port. The host uses socat with the
CONNECT protocol to send commands and receive JSON responses.

---

## 5. Exit code propagation

### Firecracker behavior on guest shutdown

| Guest action | Firecracker behavior | Exit code |
|--------------|---------------------|-----------|
| `reboot` | Firecracker process exits | 0 (normally) |
| `poweroff` / `halt` | Guest shuts down but **Firecracker keeps running** | N/A (process hangs) |
| `poweroff -f` | Guest kernel halts but **Firecracker keeps running** | N/A (process hangs) |
| Kernel panic | Depends on `panic=` boot arg; with `reboot=k panic=1`, reboots and FC exits | 0 or 148 |
| Triple fault | Firecracker exits | Non-zero |

**Critical gotcha:** `poweroff` and `halt` do NOT cause Firecracker to exit.
Firecracker does not implement ACPI or PM devices. Only `reboot` triggers a
clean VMM exit.

### Exit code is NOT reliable for test results

Firecracker exits with 0 on a clean `reboot`, regardless of what happened
inside the guest. A test that fails and then calls `reboot` will still produce
exit code 0 from Firecracker. Occasional spurious exit code 148 has been
observed during reboot (KVM_EXIT_SHUTDOWN race).

### Recommended approaches for AOS test results

**For per-test integration VMs (no systemd):**

The init script IS the test. It runs the check and signals results via serial:

```bash
#!/bin/sh
# /init -- runs as PID 1

# Run the actual test
if /nix/store/.../gcc -o /tmp/test test.c -lssl -lcrypto && /tmp/test; then
    echo "TEST_RESULT:PASS" > /dev/ttyS0
else
    echo "TEST_RESULT:FAIL" > /dev/ttyS0
fi

# Trigger clean Firecracker exit
reboot -f
```

The host captures serial output (Firecracker stdout) and greps for the marker:

```bash
firecracker --no-api --config-file "$config" > "$serial_log" 2>"$fc_log"
fc_exit=$?

if grep -q "TEST_RESULT:PASS" "$serial_log"; then
    echo "PASS"
elif grep -q "TEST_RESULT:FAIL" "$serial_log"; then
    echo "FAIL"
    exit 1
else
    echo "ERROR: No test result marker found"
    cat "$serial_log"
    exit 1
fi
```

**For system test VMs (with systemd + vsock agent):**

The guest agent reports results over vsock as JSON (same protocol as the
current QEMU-based agent). The host sends SHUTDOWN when done, and the agent
calls `reboot -f` (not `poweroff`).

### Why `reboot -f` and not `reboot`

`reboot` goes through systemd's shutdown sequence, which can take seconds.
`reboot -f` bypasses init and immediately triggers a kernel reboot. Since
Firecracker intercepts the reboot, this causes an immediate clean exit. For
integration tests (no systemd), use `reboot -f` directly. For system tests,
the agent should use `reboot -f` after sending the final response.

---

## 6. Read-only rootfs

### Drive config

The `is_read_only` field in the drive config controls whether the guest can
write to the block device:

```json
{
  "drive_id": "rootfs",
  "path_on_host": "/tmp/rootfs.ext4",
  "is_root_device": true,
  "is_read_only": true
}
```

When `is_read_only` is `true`, any write attempt by the guest to the block
device will fail with I/O error.

### Read-only rootfs with tmpfs overlays

For per-test integration VMs, the rootfs can be entirely read-only:
- Mount root as `ro` via `boot_args`
- The test only needs to read binaries and libraries from the Nix store
- Scratch space uses tmpfs (mounted by the init script)

```bash
#!/bin/sh
# /init for integration test VM
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t tmpfs tmpfs /tmp
mount -t tmpfs tmpfs /run
mount -t devtmpfs devtmpfs /dev

# Run test (rootfs is read-only, /tmp is writable tmpfs)
cd /tmp
# ... test commands ...
reboot -f
```

### Benefits of read-only rootfs for AOS tests

1. **Image reuse:** Multiple concurrent VMs can share the same rootfs image
   file. No need to copy the image per-VM -- Firecracker opens it read-only.
   This saves disk I/O and build time.

2. **Determinism:** Tests cannot modify the rootfs, ensuring each run starts
   from the same state.

3. **Nix store compatibility:** The rootfs is built by mkfs.ext4 in a Nix
   derivation. Making it read-only means the derivation output is used
   directly -- no copying, no mutation.

### For system test VMs

System tests need a writable root for systemd (writes to `/run`, `/var`,
`/etc/machine-id`, etc.). Options:

1. **Read-write rootfs:** Set `is_read_only: false` and copy the image per-VM.
   Simple but requires a writable copy per concurrent VM.

2. **Read-only rootfs + overlay:** Mount rootfs read-only, overlay with tmpfs.
   Requires overlayfs support in the kernel. The init script (or an initrd)
   sets up the overlay before starting systemd.

3. **Read-only rootfs + tmpfs bind mounts:** Mount the rootfs read-only, then
   bind-mount tmpfs over `/run`, `/var`, `/tmp`, `/etc/machine-id`. Simpler
   than overlayfs but may miss some paths systemd needs.

**Recommendation:** Start with option 1 (read-write copy per system-test VM)
for simplicity. Optimize to option 2 later if image copy time becomes a
bottleneck.

---

## 7. Recommendations for AOS test harness

### Per-test integration VMs (compile+link, CLI smoke, ABI checks)

```
                    Config generation
                          |
                    +-----v------+
                    | JSON config |
                    +-----+------+
                          |
              firecracker --no-api --config-file
                          |
                    +-----v------+
                    | Boot vmlinux|  ~125ms
                    +-----+------+
                          |
                    +-----v------+
                    | /init script|  Test runs as PID 1
                    +-----+------+  No systemd. No agent.
                          |
                    +-----v------+
                    | Serial out  |  "TEST_RESULT:PASS" or "TEST_RESULT:FAIL"
                    +-----+------+
                          |
                    +-----v------+
                    | reboot -f   |  Firecracker exits with 0
                    +-----+------+
                          |
                    Host greps serial log for result marker
```

- **Kernel:** Uncompressed `vmlinux` with minimal config
- **Rootfs:** Read-only ext4 with Nix store closure, shared across VMs
- **Init:** Custom `/init` shell script that IS the test
- **Communication:** Serial console (stdout capture)
- **Result:** Grep serial log for `TEST_RESULT:PASS` / `TEST_RESULT:FAIL`
- **Timeout:** Host kills Firecracker process after N seconds if no exit
- **Memory:** 128-256 MiB per VM (sufficient for compile+link)
- **vCPUs:** 1 per VM

### System test VMs (service startup, security, full-stack)

- **Kernel:** Same uncompressed `vmlinux`
- **Rootfs:** Read-write copy of ext4 image (per-VM)
- **Init:** systemd (`/sbin/init`)
- **Communication:** vsock guest agent (replaces virtio-serial)
- **Agent:** AOS socat listening on vsock port, same JSON protocol as current
- **Result:** Agent reports pass/fail over vsock; host asserts on JSON responses
- **Shutdown:** Agent calls `reboot -f` on SHUTDOWN command
- **Memory:** 512-2048 MiB per VM
- **vCPUs:** 1-2 per VM

### CLI invocation template

```bash
# Generate unique paths per test
CONFIG="/tmp/fc-test-${TEST_NAME}/config.json"
VSOCK="/tmp/fc-test-${TEST_NAME}/vm.vsock"
SERIAL_LOG="/tmp/fc-test-${TEST_NAME}/serial.log"
FC_LOG="/tmp/fc-test-${TEST_NAME}/firecracker.log"

# For integration tests (no vsock, serial-only):
firecracker \
    --no-api \
    --config-file "$CONFIG" \
    > "$SERIAL_LOG" 2>"$FC_LOG"

# For system tests (with vsock):
firecracker \
    --no-api \
    --config-file "$CONFIG" \
    > "$SERIAL_LOG" 2>"$FC_LOG" &
FC_PID=$!

# Wait for vsock UDS to appear, then run agent protocol
while [ ! -S "$VSOCK" ]; do sleep 0.1; done
# ... send commands via socat + CONNECT protocol ...

# Clean up
kill $FC_PID 2>/dev/null; wait $FC_PID 2>/dev/null
```

### Migration from current QEMU harness

The current harness (`lib/testing/vm.nix`) uses:
- QEMU with `-machine q35,accel=kvm`
- virtio-serial for guest agent communication
- `socat UNIX-CONNECT:$AGENT_SOCK` for host-to-guest messaging
- `vmlinuz-*` compressed kernel image

Changes needed for Firecracker:

| Aspect | Current (QEMU) | New (Firecracker) |
|--------|----------------|-------------------|
| VMM binary | `qemu-system-x86_64` | `firecracker` |
| Kernel format | `vmlinuz-*` (compressed) | `vmlinux` (uncompressed ELF) |
| Guest communication | virtio-serial port | vsock (system tests) or serial (integration tests) |
| Host-side connection | `socat UNIX-CONNECT:$SOCK` | `socat UNIX-CONNECT:$VSOCK` + `CONNECT <port>` |
| Guest-side listening | `head -1 /dev/virtio-ports/...` | `socat VSOCK-LISTEN:<port>` |
| VM config | CLI flags | JSON config file |
| Shutdown | `poweroff -f` | `reboot -f` (critical difference!) |
| Image reuse | Copy per test | Read-only shared (integration) or copy (system) |

### Gotchas summary

1. **Kernel must be uncompressed vmlinux**, not bzImage/vmlinuz
2. **`poweroff` hangs Firecracker** -- always use `reboot -f` for shutdown
3. **Exit code is always 0** on clean reboot -- do not rely on it for test results
4. **Serial console is Firecracker's stdout**, not a separate file/socket
5. **vsock CIDs must be unique** across concurrent VMs on the same host
6. **vsock host-to-guest requires the CONNECT protocol** -- raw socket connect is not enough
7. **Guest vsock needs /dev/vsock** -- kernel must have `CONFIG_VIRTIO_VSOCKETS=y`
8. **Bash cannot open AF_VSOCK sockets** -- guest agent needs socat or a compiled binary
9. **Firecracker does not implement ACPI/PM** -- no `SendCtrlAltDel` without API socket
10. **With `--no-api`, there is no way to control the VM after start** except via vsock/serial or killing the process
