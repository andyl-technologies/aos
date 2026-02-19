# Implementation Plan

This document describes how the AOS integration test framework is implemented,
integrated into the existing `checks` attribute set, wired into the `aos test`
CLI, and executed on the remote builder.

Companion documents define *what* to test. This document defines *how*.

---

## 1. Architecture: Firecracker MicroVMs

**Critical design decision:** All integration tests -- including compile+link
checks, CLI smoke tests, and library ABI verification -- run inside Firecracker
microVMs booting the actual AOS kernel. This ensures every test validates the
complete stack from kernel through userspace, catching failures that would be
missed by running tests on the builder's host kernel.

### 1.1 Why Not Build-Sandbox Tests?

Build-sandbox tests run on the builder's host kernel (NixOS). This misses:

- Kernel syscall differences between builder and AOS target
- `/proc`/`/sys` layout and content differences
- Dynamic linker behavior under the AOS kernel+glibc combination
- Kernel module availability (netfilter, overlayfs, cgroup v2 features)
- Signal handling and seccomp semantics specific to the AOS kernel config

By running everything in Firecracker microVMs booting the AOS kernel, we
validate that packages work on the actual target system, not just the builder.

### 1.2 Why Firecracker Instead of QEMU

QEMU provides a full hardware emulator: PCI bus, ACPI tables, BIOS/UEFI,
dozens of device models. AOS tests need none of this. QEMU's device model
initialization alone takes ~100-200ms, and a systemd boot inside QEMU takes
~5-8 seconds total.

Firecracker is a purpose-built microVM monitor (VMM) created by AWS for
Lambda and Fargate. It strips away everything a test VM doesn't need:

| Aspect | QEMU | Firecracker |
|--------|------|-------------|
| Boot to userspace | ~1-2s | ~125ms |
| Device model | Full (q35, PCI, ACPI) | Minimal (virtio-blk, virtio-net, vsock) |
| Memory overhead per VM | ~50-100MB | ~5-10MB |
| Guest communication | virtio-serial | vsock |
| Concurrent VMs (32GB RAM) | ~50-100 | ~500+ |
| Binary size | ~50MB | ~5MB |
| Security model | Process isolation | jailer + seccomp + cgroup isolation |

The ~125ms boot time is the key enabler. It makes per-test VMs practical:
instead of amortizing boot cost across a shard of tests, each test gets its
own isolated microVM. This eliminates shard load-balancing entirely.

### 1.3 Per-Test MicroVMs Instead of Sharding

The previous design proposed static VM shards (e.g., "toolchain shard,"
"libraries shard") where multiple tests share a single VM. This creates
problems:

- **Load imbalance.** A Go toolchain test takes 30s; a zlib link check takes
  200ms. Static shards waste VM time waiting for the slowest test.
- **Head-of-line blocking.** One slow test in a shard blocks everything in
  that shard.
- **Complex scheduling.** Manual shard assignment, no automatic rebalancing.

With Firecracker's ~150ms boot overhead, each integration test gets its own
microVM. The host Nix daemon's `--max-jobs` handles all scheduling:

```
nix-build -A checks.integration.all
              |
   Nix daemon evaluates ~200 derivations
   Nix daemon schedules via --max-jobs=32
              |
   +------+------+------+------+---...   (32 concurrent)
   |      |      |      |      |
  FC VM  FC VM  FC VM  FC VM  FC VM
  150ms  150ms  150ms  150ms  150ms
  boot   boot   boot   boot   boot
   |      |      |      |      |
  test   test   test   test   test
  ~1s    ~0.5s  ~2s    ~0.2s  ~0.5s
   |      |      |      |      |
  exit   exit   exit   exit   exit
```

**Nix's content-addressed store eliminates most VMs entirely.** On a typical
commit touching one package, only that package's tests + its reverse
dependencies' tests actually build. The other ~180 derivations are instant
cache hits -- no VM boots at all.

### 1.4 No Guest Nix Daemon

The previous design proposed a Nix daemon inside each VM to sandbox
compile+link tests. With per-test VMs, **the VM IS the sandbox**:

- **Before (shared VM shard):**
  `Boot VM -> Start systemd -> Start Nix daemon -> Build N tests -> Report -> Shutdown`

- **After (per-test microVM):**
  `Boot VM -> init=/test.sh -> compile -> link -> run -> exit(0|1)`

No systemd. No guest Nix daemon. No guest agent protocol. The test script
is literally the init process (PID 1). Exit code = test result. This
removes layers of complexity and boot overhead.

### 1.5 Execution Flow

```
1. Host: nix-build evaluates test derivations
2. Host: Nix daemon schedules builds (--max-jobs=32)
3. Integration tests: Each derivation launches a Firecracker microVM
4. Each microVM: Boots AOS kernel (~125ms)
5. Each microVM: init script compiles/links/runs the test
6. Each microVM: Exits with 0 (pass) or 1 (fail)
7. System tests: Full Firecracker VMs with systemd, vsock agent
8. Host: Nix collects results, reports pass/fail
```

### 1.6 Two VM Modes

| Mode | Init | Communication | Boot time | Use case |
|------|------|---------------|-----------|----------|
| Headless microVM | Test script as PID 1 | Exit code | ~150ms | Integration checks (compile+link, tool smoke) |
| System VM | systemd | vsock guest agent | ~3-5s | Service startup, boot, security checks |

Integration tests (compile+link, tool smoke tests) use headless microVMs.
System tests (service startup, security hardening, boot verification) use
system VMs with systemd and communicate over vsock.

---

## 2. Test Primitives

### 2.1 Firecracker Wrapper

The core infrastructure is a `mkVMTest` function that launches a
Firecracker microVM and runs a test script as PID 1:

```nix
# lib/testing/firecracker.nix

{ pkgs, lib, testTools }:

let
  firecracker = pkgs.firecracker;   # Built from source as AOS package
  kernel = (lib.evalModules {
    modules = [ ../../systems/base.nix ];
    inherit pkgs lib;
  }).config.system.build.kernel;
in
{
  # mkVMTest -- launch a Firecracker microVM, run a script as init.
  #
  # The test script runs as PID 1 inside a microVM booting the AOS kernel.
  # No systemd, no guest agent, no Nix daemon. The VM exits when the script
  # exits. Exit code 0 = pass, non-zero = fail.
  mkVMTest =
    {
      pname,            # Test name
      testScript,       # Shell script to run as init (PID 1)
      rootfsDeps ? [],  # Packages whose store paths must be in the rootfs
      memory ? 256,     # VM memory in MB
    }:
    let
      # Build a minimal rootfs with only the test's dependencies
      testRootfs = pkgs.mkDerivation {
        pname = "test-rootfs-${pname}";
        version = "0";
        src = null;
        buildDeps = [ pkgs.e2fsprogs pkgs.coreutils ];

        exportReferencesGraph =
          lib.concatLists (lib.imap0 (i: dep: [
            "closure-${toString i}" dep
          ]) rootfsDeps);

        phases = [{
          name = "build-rootfs";
          script = ''
            mkdir -p rootfs/nix/store rootfs/proc rootfs/sys rootfs/dev
            mkdir -p rootfs/tmp rootfs/bin rootfs/usr/bin

            # Copy store closure
            cat closure-* | grep '^/nix/store/' | sort -u > all-paths
            while IFS= read -r p; do
              if [ -e "$p" ]; then
                cp -a "$p" rootfs/nix/store/
              fi
            done < all-paths

            # Minimal init script
            cat > rootfs/init << 'INITEOF'
            #!/bin/sh
            mount -t proc proc /proc
            mount -t sysfs sys /sys
            mount -t devtmpfs dev /dev

            # Run the actual test
            /test.sh
            rc=$?

            # Write result and power off
            if [ $rc -eq 0 ]; then
              echo "PASS" > /dev/vda
            else
              echo "FAIL" > /dev/vda
            fi
            echo o > /proc/sysrq-trigger
            INITEOF
            chmod +x rootfs/init

            # The test script
            cat > rootfs/test.sh << 'TESTEOF'
            ${testScript}
            TESTEOF
            chmod +x rootfs/test.sh

            # /bin/sh for the scripts
            ln -sfn ${pkgs.bash}/bin/bash rootfs/bin/sh
            # coreutils
            for bin in ${pkgs.coreutils}/bin/*; do
              ln -sfn "$bin" "rootfs/usr/bin/$(basename $bin)" 2>/dev/null || true
            done

            # Build ext4 image
            SIZE_KB=$(du -sk rootfs | cut -f1)
            IMAGE_MB=$(( SIZE_KB / 1024 * 3 + 128 ))
            mkfs.ext4 -d rootfs -L rootfs -m 1 -q $out ''${IMAGE_MB}M
          '';
        }];
      };
    in
    pkgs.mkDerivation {
      pname = "fc-test-${pname}";
      version = "0";
      src = null;

      buildDeps = [ firecracker pkgs.coreutils pkgs.jq ];

      ROOTFS = builtins.toString testRootfs;
      KERNEL = builtins.toString kernel;

      phases = [{
        name = "test";
        script = ''
          set -eu

          VMLINUX=$(ls $KERNEL/boot/vmlinuz-* | head -1)
          RESULT_DISK="$TMPDIR/result.img"
          FC_SOCK="$TMPDIR/fc.sock"

          # Create a small disk to capture the result
          dd if=/dev/zero of="$RESULT_DISK" bs=1M count=1
          mkfs.ext4 -q "$RESULT_DISK"

          # Copy rootfs (Firecracker needs a writable copy)
          cp $ROOTFS rootfs.ext4
          chmod u+w rootfs.ext4

          # Firecracker config
          cat > fc-config.json << FCCFG
          {
            "boot-source": {
              "kernel_image_path": "$VMLINUX",
              "boot_args": "init=/init console=ttyS0 reboot=k panic=1 quiet"
            },
            "drives": [
              {
                "drive_id": "rootfs",
                "path_on_host": "rootfs.ext4",
                "is_root_device": true,
                "is_read_only": false
              }
            ],
            "machine-config": {
              "vcpu_count": 2,
              "mem_size_mib": ${toString memory}
            }
          }
          FCCFG

          # Launch Firecracker
          firecracker --no-api --config-file fc-config.json \
            > "$TMPDIR/fc-stdout.log" 2> "$TMPDIR/fc-stderr.log" || true

          # Check serial output for PASS/FAIL
          if grep -q "^PASS" "$TMPDIR/fc-stdout.log"; then
            echo "PASS: ${pname}"
            mkdir -p $out
            echo "PASS" > $out/result
          else
            echo "FAIL: ${pname}"
            echo "--- Firecracker stdout ---"
            cat "$TMPDIR/fc-stdout.log"
            echo "--- Firecracker stderr ---"
            cat "$TMPDIR/fc-stderr.log"
            exit 1
          fi
        '';
      }];

      requiredSystemFeatures = [ "kvm" ];
    };
}
```

### 2.2 Integration Check Primitives

Built on top of `mkVMTest`, these provide ergonomic wrappers for
common integration test patterns:

```nix
# lib/testing/integration.nix

{ pkgs, lib, testTools }:

let
  fc = import ./firecracker.nix { inherit pkgs lib testTools; };
in
{
  # mkLinkCheck -- compile a C program against a library, link it, run it.
  # Each invocation spawns its own Firecracker microVM (~150ms boot).
  #
  # Failure modes caught:
  #   - Missing headers (compile error)
  #   - Missing or renamed symbols (link error)
  #   - ABI mismatch / struct layout change (runtime crash)
  #   - Kernel-userspace incompatibility (syscall failure)
  mkLinkCheck =
    {
      pname,          # Test name (e.g. "openssl-libssl")
      library,        # AOS library package to test against
      testSource,     # C source code as a string
      includes ? [],  # Extra -I paths
      libs ? [],      # Libraries to link: [ "ssl" "crypto" ] -> -lssl -lcrypto
      extraDeps ? [], # Additional packages needed at build/link time
    }:
    fc.mkVMTest {
      pname = "link-check-${pname}";
      rootfsDeps = [ library pkgs.bootstrapTools ] ++ extraDeps;
      testScript = ''
        #!/bin/sh
        set -eu
        export PATH="${pkgs.bootstrapTools}/bin:${pkgs.coreutils}/bin"
        export C_INCLUDE_PATH="${library}/include''${C_INCLUDE_PATH:+:$C_INCLUDE_PATH}"
        export LIBRARY_PATH="${library}/lib''${LIBRARY_PATH:+:$LIBRARY_PATH}"
        export LD_LIBRARY_PATH="${library}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

        cat > /tmp/test.c << 'TESTSRC'
        ${testSource}
        TESTSRC

        echo "==> Compiling: ${pname}"
        gcc -o /tmp/test /tmp/test.c \
          ${lib.concatMapStringsSep " " (i: "-I${i}") includes} \
          ${lib.concatMapStringsSep " " (l: "-l${l}") libs} \
          -Wl,-rpath,${library}/lib
        echo "==> Running: ${pname}"
        /tmp/test
        echo "PASS: ${pname}"
      '';
    };

  # mkToolCheck -- run a CLI tool and verify its output.
  # Each invocation spawns its own Firecracker microVM.
  mkToolCheck =
    {
      pname,
      tool,
      command,
      expectedOutput ? null,
      extraDeps ? [],
    }:
    fc.mkVMTest {
      pname = "tool-check-${pname}";
      rootfsDeps = [ tool ] ++ extraDeps;
      testScript = ''
        #!/bin/sh
        set -eu
        export PATH="${tool}/bin:${pkgs.coreutils}/bin"
        export LD_LIBRARY_PATH="${tool}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

        echo "==> Running: ${pname}"
        output=$(${command} 2>&1)
        ${if expectedOutput != null then ''
          if ! echo "$output" | grep -q "${expectedOutput}"; then
            echo "FAIL: ${pname}"
            echo "  expected: ${expectedOutput}"
            echo "  actual: $output"
            exit 1
          fi
        '' else ""}
        echo "PASS: ${pname}"
      '';
    };

  # mkCompileCheck -- verify headers and pkg-config metadata work.
  # Compile-only (no link/execute). Runs in its own microVM.
  mkCompileCheck =
    {
      pname,
      deps,
      testSource,
      flags ? "",
    }:
    fc.mkVMTest {
      pname = "compile-check-${pname}";
      rootfsDeps = deps ++ [ pkgs.bootstrapTools ];
      testScript = ''
        #!/bin/sh
        set -eu
        export PATH="${pkgs.bootstrapTools}/bin:${pkgs.coreutils}/bin"
        ${lib.concatMapStringsSep "\n" (d: ''
          export C_INCLUDE_PATH="${d}/include''${C_INCLUDE_PATH:+:$C_INCLUDE_PATH}"
        '') deps}

        cat > /tmp/test.c << 'TESTSRC'
        ${testSource}
        TESTSRC

        echo "==> Compiling: ${pname}"
        gcc -c /tmp/test.c ${flags} -o /dev/null
        echo "PASS: ${pname}"
      '';
    };
}
```

### 2.3 System Checks (vsock guest agent)

System tests need a full init system (systemd) for testing service startup,
security policies, and boot behavior. These use Firecracker's vsock for
host-guest communication instead of QEMU's virtio-serial.

The existing `mkCheck`/`mkCheckGroup` primitives remain unchanged. What
changes is the VM harness that executes them -- `mkVMTest` is updated to
use Firecracker with vsock:

```nix
# Updated lib/testing/vm.nix sketch

# Guest agent changes:
#   - Listens on vsock CID 3, port 52 (instead of /dev/virtio-ports/...)
#   - Uses socat VSOCK-LISTEN instead of reading from a chardev
#   - Same JSON protocol: {"exit_code":N,"stdout":"...","stderr":"..."}

# Host side changes:
#   - Connects via socat VSOCK-CONNECT:3:52 (instead of UNIX-CONNECT)
#   - Same assertion helpers (run_in_guest, assert_success, etc.)
```

The vsock adaptation is straightforward: same protocol, different transport.

### 2.4 Execution Model Summary

| Type | VMM | Init | Communication | Boot | Concurrency |
|------|-----|------|---------------|------|-------------|
| mkLinkCheck | Firecracker | test script (PID 1) | exit code | ~150ms | --max-jobs |
| mkToolCheck | Firecracker | test script (PID 1) | exit code | ~150ms | --max-jobs |
| mkCompileCheck | Firecracker | test script (PID 1) | exit code | ~150ms | --max-jobs |
| mkCheck/mkCheckGroup | Firecracker | systemd | vsock agent | ~3-5s | per-variant parallel |

---

## 3. File Structure

### New files

```
pkgs/tools/firecracker.nix       # Firecracker package (built from source)

lib/testing/
  firecracker.nix                # mkVMTest: core microVM launcher
  integration.nix                # mkLinkCheck, mkToolCheck, mkCompileCheck

tests/
  integration/
    default.nix                  # Entry point: composes all integration test groups
    toolchain.nix                # gcc, g++, Go, Rust, Python, Perl checks
    libraries.nix                # Shared library compile+link+run checks
    tools.nix                    # CLI tool smoke tests
    build-systems.nix            # cmake, meson, autotools, pkg-config checks
    cross-cutting.nix            # Multi-package integration scenarios
```

### Modified files

```
lib/testing/default.nix          # Export integration primitives
lib/testing/vm.nix               # Migrate from QEMU to Firecracker + vsock
tests/default.nix                # Add checks.integration entry
```

---

## 4. Firecracker Package

Firecracker is a ~5MB Rust binary. AOS already has a Rust toolchain
(`pkgs.rust`), so Firecracker is built from source as an AOS package
rather than imported from nixpkgs:

```nix
# pkgs/tools/firecracker.nix

{ mkDerivation, fetchurl, rust, make }:
let version = "1.10.1"; in
mkDerivation {
  pname = "firecracker";
  inherit version;
  src = fetchurl {
    urls = [
      "https://github.com/firecracker-microvm/firecracker/archive/refs/tags/v${version}.tar.gz"
    ];
    hash = "sha256-...";
  };
  buildDeps = [ rust make ];
  runtimeDeps = [];
  phases = [{
    name = "build";
    script = ''
      cd src/firecracker
      cargo build --release --target x86_64-unknown-linux-gnu
      mkdir -p $out/bin
      cp target/x86_64-unknown-linux-gnu/release/firecracker $out/bin/
    '';
  }];
}
```

This keeps the testing infrastructure fully hermetic -- no nixpkgs
dependency beyond QEMU (which is retained only as a fallback for fleet
tests that need features Firecracker doesn't support, like multicast
networking).

### 4.1 Firecracker Kernel Requirements

Firecracker boots an uncompressed kernel image (vmlinux), not a compressed
bzImage/vmlinuz. The AOS kernel build must produce both:

- `vmlinuz-*` -- compressed, used for real boot and QEMU
- `vmlinux` -- uncompressed ELF, used for Firecracker

The kernel config must include:
- `CONFIG_VIRTIO_MMIO=y` (Firecracker uses MMIO, not PCI)
- `CONFIG_VIRTIO_BLK=y`
- `CONFIG_VIRTIO_NET=y` (for fleet tests)
- `CONFIG_VSOCKETS=y` and `CONFIG_VIRTIO_VSOCKETS=y` (for system test agent)
- `CONFIG_EXT4_FS=y`

These are likely already enabled; verify and add if missing.

---

## 5. Rootfs Strategy

### 5.1 Per-Test Rootfs vs Shared Rootfs

Two approaches for providing the Nix store to test VMs:

**Option A: Per-test rootfs.** Each test derivation builds a minimal rootfs
containing only its dependency closure. Small images (~50-200MB) but building
200 rootfs images adds overhead.

**Option B: Shared base rootfs.** One large rootfs with the full Nix store,
reused by all integration tests. Firecracker can mount it read-only. Each
test varies only its init script.

**Recommendation: Shared base rootfs** with per-test init overlay.

The shared rootfs is built once (a single Nix derivation) and contains all
AOS packages. Each integration test derivation depends on this shared rootfs
and generates only a small init script. Since Firecracker supports read-only
root drives, all VMs share the same rootfs image without copying it.

```nix
# Shared integration rootfs (built once, cached)
integrationRootfs = mkIntegrationRootfs {
  packages = builtins.attrValues pkgs;  # All AOS packages
};

# Each test just creates an init script overlay
mkLinkCheck { ... } = mkVMTest {
  rootfs = integrationRootfs;      # Shared, read-only
  initScript = "...";             # Unique per test
  scratchDisk = true;             # Small writable tmpfs for /tmp
};
```

### 5.2 Scratch Space

Integration tests need writable space for `/tmp` (compilation artifacts).
Options:

1. **Writable rootfs copy** -- `cp rootfs.ext4 /tmp/test.ext4` per VM. Works
   but copies ~1GB per test.
2. **Read-only rootfs + tmpfs** -- Mount rootfs read-only, use kernel's built-in
   tmpfs for `/tmp`. Test init script does `mount -t tmpfs tmpfs /tmp`. No copy.
3. **Overlayfs** -- Read-only rootfs as lower, tmpfs as upper. Full writable
   filesystem without copying. Requires `CONFIG_OVERLAY_FS=y`.

**Recommendation: Option 2 (tmpfs for /tmp)** for simplicity. The test only
needs to write to `/tmp` for compilation. The rootfs stays read-only.

---

## 6. Test Entry Point Changes

### 6.1 lib/testing/default.nix

Add the integration module to the testing library export:

```nix
# lib/testing/default.nix (updated)

{
  pkgs,
  lib,
  testTools,
}:

let
  vm = import ./vm.nix { inherit pkgs lib testTools; };
  fleet = import ./fleet.nix { inherit pkgs lib testTools; };
  assertions = import ./assertions.nix;
  checks = import ./checks.nix;
  integration = import ./integration.nix { inherit pkgs lib testTools; };
in
{
  inherit (vm) mkVMTest mkTestRootfs;
  inherit (fleet) mkFleetTest;
  inherit assertions;
  inherit (checks)
    mkCheck
    mkCheckGroup
    composeChecks
    flattenChecks
    validateChecks
    ;
  inherit (integration) mkLinkCheck mkToolCheck mkCompileCheck;
}
```

### 6.2 tests/default.nix

Add the integration layer between build and vm:

```nix
# tests/default.nix (updated)

{
  pkgs,
  lib,
  testTools,
}:

let
  mkSystem =
    modules:
    lib.evalModules {
      modules = modules;
      inherit pkgs lib;
    };

  systems = {
    base = mkSystem [ ../systems/base.nix ];
    server = mkSystem [ ../systems/server.nix ];
    seed = mkSystem [ ../systems/seed.nix ];
    k8s-worker = mkSystem [ ../systems/k8s-worker.nix ];
    k8s-control-plane = mkSystem [ ../systems/k8s-control-plane.nix ];
  };
in
{
  eval = import ./eval.nix { inherit pkgs lib systems; };
  build = import ./build.nix { inherit pkgs lib; };
  integration = import ./integration { inherit pkgs lib testTools; };
  vm = import ./vm {
    inherit
      pkgs
      lib
      systems
      testTools
      ;
  };
  fleet = import ./fleet {
    inherit
      pkgs
      lib
      systems
      testTools
      ;
  };
}
```

### 6.3 tests/integration/default.nix

The integration entry point composes all test groups:

```nix
# tests/integration/default.nix

{ pkgs, lib, testTools }:

let
  harness = import ../../lib/testing/integration.nix { inherit pkgs lib testTools; };

  groups = {
    toolchain = import ./toolchain.nix { inherit pkgs lib harness; };
    libraries = import ./libraries.nix { inherit pkgs lib harness; };
    tools = import ./tools.nix { inherit pkgs lib harness; };
    build-systems = import ./build-systems.nix { inherit pkgs lib harness; };
    cross-cutting = import ./cross-cutting.nix { inherit pkgs lib harness; };
  };

  allChecks = builtins.concatLists (builtins.attrValues groups);
in
groups // {
  all = pkgs.mkDerivation {
    pname = "aos-integration-checks";
    version = "0";
    src = null;
    buildDeps = allChecks;
    phases = [{
      name = "check";
      script = ''
        echo "==> AOS Integration Checks"
        echo "  ${builtins.toString (builtins.length allChecks)} checks passed."
        mkdir -p $out
        echo "PASS" > $out/result
      '';
    }];
  };
}
```

### 6.4 Access Patterns

```sh
# All integration tests (each spawns its own microVM)
nix-build -A checks.integration.all

# Individual group
nix-build -A checks.integration.toolchain
nix-build -A checks.integration.libraries
nix-build -A checks.integration.tools
nix-build -A checks.integration.build-systems
nix-build -A checks.integration.cross-cutting
```

---

## 7. Integration Test Group Structure

Each group file takes `{ pkgs, lib, harness }` and returns a list of
derivations. The `harness` argument provides `mkLinkCheck`, `mkToolCheck`,
and `mkCompileCheck`.

### 7.1 Example: libraries.nix (excerpt)

```nix
# tests/integration/libraries.nix

{ pkgs, lib, harness }:

let
  inherit (harness) mkLinkCheck mkToolCheck;
in
[
  (mkLinkCheck {
    pname = "openssl-libssl";
    library = pkgs.openssl;
    testSource = ''
      #include <openssl/ssl.h>
      #include <openssl/err.h>
      int main() {
        SSL_library_init();
        SSL_CTX *ctx = SSL_CTX_new(TLS_method());
        if (!ctx) { ERR_print_errors_fp(stderr); return 1; }
        SSL_CTX_free(ctx);
        return 0;
      }
    '';
    libs = [ "ssl" "crypto" ];
  })

  (mkLinkCheck {
    pname = "zlib-compress";
    library = pkgs.zlib;
    testSource = ''
      #include <zlib.h>
      #include <string.h>
      int main() {
        char src[] = "Hello, AOS!";
        char dst[256];
        uLongf dstLen = sizeof(dst);
        if (compress((Bytef *)dst, &dstLen, (Bytef *)src, strlen(src) + 1) != Z_OK)
          return 1;
        char result[256];
        uLongf resultLen = sizeof(result);
        if (uncompress((Bytef *)result, &resultLen, (Bytef *)dst, dstLen) != Z_OK)
          return 1;
        return strcmp(result, src);
      }
    '';
    libs = [ "z" ];
  })

  (mkLinkCheck {
    pname = "curl-links-openssl";
    library = pkgs.curl;
    testSource = ''
      #include <curl/curl.h>
      #include <stdio.h>
      int main() {
        curl_global_init(CURL_GLOBAL_SSL);
        curl_version_info_data *info = curl_version_info(CURLVERSION_NOW);
        if (info->ssl_version == NULL) {
          fprintf(stderr, "curl has no SSL support\n");
          return 1;
        }
        printf("curl SSL: %s\n", info->ssl_version);
        curl_global_cleanup();
        return 0;
      }
    '';
    libs = [ "curl" ];
    extraDeps = [ pkgs.openssl pkgs.zlib pkgs.nghttp2 pkgs.libssh2 ];
  })

  # ... additional library checks ...
]
```

### 7.2 Example: tools.nix (excerpt)

```nix
# tests/integration/tools.nix

{ pkgs, lib, harness }:

let
  inherit (harness) mkToolCheck;
in
[
  (mkToolCheck {
    pname = "jq-parse";
    tool = pkgs.jq;
    command = "echo '{\"key\":\"value\"}' | ${pkgs.jq}/bin/jq -r '.key'";
    expectedOutput = "value";
  })

  (mkToolCheck {
    pname = "curl-version";
    tool = pkgs.curl;
    command = "${pkgs.curl}/bin/curl --version";
    expectedOutput = "https";
  })

  (mkToolCheck {
    pname = "rsync-version";
    tool = pkgs.rsync;
    command = "${pkgs.rsync}/bin/rsync --version";
    expectedOutput = "rsync";
  })

  # ... additional tool checks ...
]
```

---

## 8. Dependency-Aware Test Selection

### 8.1 The Problem

When a single package changes (e.g., openssl is upgraded), rebuilding and
retesting all 162 packages is wasteful. The goal is to determine the minimum
set of integration tests that must pass for the change to be accepted.

### 8.2 Approach: Reverse Dependency Walk

The test selector works in three steps:

1. **Identify changed packages.** Compare the current branch against the base
   branch. For each changed `.nix` file under `pkgs/`, determine the affected
   package name.

2. **Compute the affected set.** For each changed package, walk the forward
   dependency graph to find all packages that directly or transitively depend
   on it. This is the "blast radius."

3. **Select tests.** For each package in the affected set, include its
   integration tests. Also include any cross-cutting tests that mention
   packages in the affected set.

### 8.3 Implementation in the CLI

The `aos test integration --changed` flag implements this by:

```
1. git diff --name-only $(git merge-base HEAD main)..HEAD
2. Filter to pkgs/**/*.nix files
3. Extract package names (strip path prefix and .nix suffix)
4. For each package, evaluate reverse dependencies
5. Build only those test derivations
```

### 8.4 Example: openssl Change

```
Changed file: pkgs/tls/openssl.nix
Changed package: openssl

Reverse deps of openssl:
  curl, openssh, nginx, systemd, rsync, nix, libssh2, libgit2, rust

Integration tests to run:
  - link-check-openssl-libssl        (direct)
  - link-check-openssl-libcrypto     (direct)
  - tool-check-openssl-version       (direct)
  - link-check-curl-links-openssl    (consumer)
  - link-check-nginx-links-openssl   (consumer)
  - link-check-openssh-links-openssl (consumer)
  - cross-cutting-tls-stack          (cross-cutting scenario)

Skipped (unaffected, cached):
  - link-check-zlib-compress
  - tool-check-jq-parse
  - All Go package checks
  - All netfilter checks

Microvm boots for this commit: ~8 (only affected tests)
Time: ~8 × (150ms + ~1s) = ~10 seconds
```

---

## 9. `aos test` CLI Integration

### 9.1 New Subcommands

```
aos test integration                        # All integration tests
aos test integration --group libraries      # Single group
aos test integration --group toolchain      # Single group
aos test integration --package openssl      # Tests involving a specific package
aos test integration --changed              # Tests for packages changed in current branch
```

### 9.2 Implementation

| CLI Command | Nix Build Command |
|---|---|
| `aos test integration` | `nix-build -A checks.integration.all` |
| `aos test integration --group libraries` | `nix-build -A checks.integration.libraries` |
| `aos test integration --package openssl` | Evaluates reverse deps, builds matching tests |
| `aos test integration --changed` | `git diff` + reverse dep walk + selective build |

### 9.3 Output Format

```
$ aos test integration --group libraries
==> Building integration checks: libraries (12 tests)
    Each test runs in its own Firecracker microVM (~150ms boot)

  link-check-openssl-libssl ................ PASS  (1.2s)
  link-check-openssl-libcrypto ............ PASS  (0.9s)
  link-check-zlib-compress ................ PASS  (0.6s)
  link-check-curl-links-openssl ........... PASS  (1.4s)
  tool-check-openssl-version .............. PASS  (0.3s)

==> All 12 integration checks passed (4.1s wall-clock, 32 parallel)
```

---

## 10. VM System Test Migration

### 10.1 QEMU to Firecracker

The existing `mkVMTest` in `lib/testing/vm.nix` migrates from QEMU to
Firecracker. Key changes:

| Component | QEMU (current) | Firecracker (new) |
|-----------|----------------|-------------------|
| VMM binary | `qemu-system-x86_64` | `firecracker` |
| Machine model | `-machine q35,accel=kvm` | Minimal MMIO-based |
| Kernel boot | `-kernel vmlinuz` | `kernel_image_path: vmlinux` |
| Root disk | `-drive file=X,if=virtio` | `drives[0].path_on_host` |
| Guest comms | virtio-serial + unix socket | vsock (CID 3, port 52) |
| Serial output | `-serial file:X` | stdout capture |
| Config | CLI flags | JSON config file |

### 10.2 Guest Agent Adaptation

The guest agent script changes its transport from virtio-serial chardev
to vsock:

```sh
# Before (QEMU): reads/writes /dev/virtio-ports/aos.test.agent
# After (Firecracker): listens on vsock port 52

# Agent waits for connection on vsock
socat VSOCK-LISTEN:52,reuseaddr EXEC:"/opt/aos-test/bin/agent-handler"
```

The JSON protocol (commands, responses, PING/PONG) remains identical.

### 10.3 Host-Side Connection

```sh
# Before (QEMU):
# (printf '%s\n' "$cmd"; sleep 300) | socat - UNIX-CONNECT:$AGENT_SOCK

# After (Firecracker):
# (printf '%s\n' "$cmd"; sleep 300) | socat - VSOCK-CONNECT:3:52
```

The assertion helpers (`run_in_guest`, `assert_success`,
`assert_output_contains`) update their transport but keep identical
interfaces.

---

## 11. Worked Example: OpenSSL Upgrade

### 11.1 The Change

A developer updates `pkgs/tls/openssl.nix` to bump from OpenSSL 3.3.x to
3.4.x.

### 11.2 Per-Commit Pipeline

```
Step 1: Eval (~5s)
  nix-build -A checks.eval
  -> Module definitions still parse.

Step 2: Build (~2-5 min, mostly cached)
  nix-build -A checks.build
  -> Rebuilds openssl + all consumers.

Step 3: Integration tests (~10s wall-clock)
  nix-build -A checks.integration.all
  -> ~8 affected tests spawn microVMs (150ms boot each)
  -> ~180 unaffected tests are instant cache hits
  -> All 8 microVMs run concurrently (--max-jobs=32)

  MicroVM 1: link-check-openssl-libssl ......... PASS (1.2s)
  MicroVM 2: link-check-openssl-libcrypto ...... PASS (0.9s)
  MicroVM 3: tool-check-openssl-version ........ PASS (0.4s)
  MicroVM 4: link-check-curl-links-openssl ..... PASS (1.5s)
  MicroVM 5: link-check-nginx-links-openssl .... PASS (1.3s)
  MicroVM 6: link-check-openssh-links-openssl .. PASS (1.1s)
  MicroVM 7: link-check-libssh2-links-openssl .. PASS (0.8s)
  MicroVM 8: cross-cutting-tls-coherence ....... PASS (2.1s)

  Wall-clock: ~2.5s (limited by slowest test, all run in parallel)

Step 4: System tests (~60s wall-clock)
  nix-build -A checks.vm.services
  -> Firecracker VM boots server variant with systemd
  -> nginx starts and serves over TLS
  -> sshd starts with key auth
  -> nix-daemon starts, store operations work

Step 5: Fleet tests (~5 min, advisory)
  nix-build -A checks.fleet.k8s-cluster
  -> Background, non-blocking.

Total blocking wall-clock: ~65 seconds (eval + build + integration + system)
```

### 11.3 What Each Layer Catches

| Failure Mode | Caught By | Example |
|---|---|---|
| Header removed | Build (Layer 2) | `openssl/bio.h` renamed |
| Symbol removed | Integration (microVM) | `SSL_CTX_new` dropped |
| Symbol renamed | Integration (microVM) | `EVP_MD_CTX_new` -> `EVP_MD_CTX_create` |
| Default behavior changed | Integration (microVM) | TLS 1.0 disabled by default |
| Service startup failure | System VM | nginx fails to start with new libssl |
| Certificate verification | System VM | Self-signed certs rejected |
| Cross-node TLS failure | Fleet | CA bundle incompatibility |

---

## 12. Performance Analysis

### 12.1 Timing Breakdown

```
                          Serial        With Firecracker
                          (QEMU shards) (per-test microVMs)
                          ------------- -------------------
Integration tests (200)
  Boot overhead           10s × 8       150ms × 200 = 30s
  (amortized per test)    (1.25s/test)  (150ms/test)
  Test execution          ~200s total   ~200s total
  Shard imbalance loss    ~60s wasted   0 (no shards)
  Parallelism             8-way         32-way
  Wall-clock              ~3.5 min      ~10s
  Cache hit (no change)   ~10s (boot)   0s (no VM)

System tests (5 variants)
  Boot overhead           8s × 5        3s × 5
  Test execution          ~60s each     ~60s each
  Wall-clock              ~70s          ~63s

Total wall-clock          ~4.5 min      ~75s
```

### 12.2 Why Per-Test VMs Are Faster

The counterintuitive result: 200 microVM boots (200 × 150ms = 30s total)
is faster than 8 QEMU shard boots (8 × 8s = 64s total) because:

1. **No shard imbalance.** Every test finishes as fast as it can.
2. **Higher parallelism.** 32 concurrent VMs vs 8 shards.
3. **Zero boot for cached tests.** Most commits touch 1 package -> ~10 VMs.
4. **No systemd boot.** Init = test script. ~150ms vs ~5-8s.
5. **No guest Nix daemon.** Removes 2-3s daemon startup.

### 12.3 Memory Budget

32 concurrent microVMs × 256MB = 8GB. Well within a typical builder's
capacity. System test VMs need more (2GB each), but only 5 run concurrently
(10GB). Total peak: ~18GB, fits comfortably on a 32GB builder.

### 12.4 Caching Characteristics

| Scenario | VMs Spawned | Wall-Clock |
|----------|-------------|------------|
| No changes (rebuild) | 0 | 0s (all cached) |
| 1 leaf package changed | ~5-10 | ~3s |
| 1 hub package (openssl) | ~20-30 | ~5s |
| Full clean build | ~200 | ~10-15s |

---

## 13. Phased Rollout Plan

### Phase 1: Foundation (Immediate)

**Goal:** Establish the Firecracker-based integration test infrastructure
and cover the highest-impact packages.

**Deliverables:**
- `pkgs/tools/firecracker.nix` -- Firecracker built from source
- Kernel config additions (VIRTIO_MMIO, VSOCKETS if missing)
- `lib/testing/firecracker.nix` -- core microVM test launcher
- `lib/testing/integration.nix` -- mkLinkCheck, mkToolCheck, mkCompileCheck
- `tests/integration/default.nix` -- entry point
- Link checks for Tier 1-2 hub packages: openssl, zlib, zstd, pcre2, curl
- Tool checks for critical CLIs: gcc, jq, tar, rsync, curl, openssl
- `checks.integration` wired into `tests/default.nix`

**Estimated scope:** ~400 LOC infrastructure + ~500 LOC tests

### Phase 2: Breadth + System VM Migration (Short-term)

**Goal:** Cover all shared libraries and CLI tools. Migrate system tests
from QEMU to Firecracker.

**Deliverables:**
- Link checks for ALL shared libraries (~50 packages)
- Tool smoke tests for ALL CLI tools (~30 packages)
- `mkVMTest` migrated from QEMU to Firecracker + vsock
- Guest agent adapted for vsock transport
- `aos test integration --changed` flag in the CLI
- Toolchain tests (C, C++, Go, Rust compilation and execution)

**Estimated scope:** ~2000 LOC total

### Phase 3: Depth (Medium-term)

**Goal:** Cross-package integration scenarios and full coverage.

**Deliverables:**
- Cross-cutting integration scenarios (TLS, Go, SELinux, Nix stacks)
- VM integration check modules (tls-stack, nix-stack, selinux-stack)
- Consumer compatibility matrix for hub libraries
- Fleet test migration to Firecracker (where feature-compatible)

**Estimated scope:** ~3500 LOC total

### Phase 4: Hardening (Long-term)

**Goal:** ABI baseline tracking, symbol verification, performance monitoring.

**Deliverables:**
- SONAME baseline files and checks
- Symbol export count baselines per library
- pkg-config consistency validation
- Binary size regression tracking
- `aos test integration --update-baseline`

**Estimated scope:** ~4500 LOC total

---

## 14. ABI Baseline Tracking (Phase 4 Detail)

For long-term ABI stability, the framework maintains baseline files that
record expected properties of shared libraries. These are checked into the
repository and updated explicitly when upgrades are intentional.

### 14.1 Baseline File Format

```json
{
  "openssl": {
    "sonames": ["libssl.so.3", "libcrypto.so.3"],
    "pkg_config": {
      "libssl": { "version": "3.4.0" },
      "libcrypto": { "version": "3.4.0" }
    }
  },
  "zlib": {
    "sonames": ["libz.so.1"],
    "pkg_config": {
      "zlib": { "version": "1.3.1" }
    }
  }
}
```

### 14.2 Baseline Check Derivation

Each baseline check runs in its own Firecracker microVM, verifying SONAMEs
and pkg-config metadata match the committed baseline:

```nix
mkBaselineCheck = { pname, library, baseline }:
  mkVMTest {
    pname = "baseline-${pname}";
    rootfsDeps = [ library ];
    testScript = ''
      #!/bin/sh
      set -eu
      for soname in ${lib.concatStringsSep " " baseline.sonames}; do
        if [ ! -f "${library}/lib/$soname" ]; then
          echo "FAIL: expected SONAME $soname not found"
          ls "${library}/lib/"*.so* 2>/dev/null
          exit 1
        fi
      done
      echo "PASS: ${pname} baseline"
    '';
  };
```

---

## 15. CI Pipeline Architecture

### 15.1 Per-Commit (Every Push)

**Target: <90 seconds total.**

```
Push / PR update
      |
      v
  Layer 1: eval                              ~5s
  (all system variants evaluate)
      |
      +-- parallel -------------------------+
      |                                      |
  Layer 2: build          Layer 3: VM tests  |  Fleet tests
  (changed pkgs +         (integration +     |  (k8s, update)
   dependents)             system, all       |  ~5-10 min
  ~2-5 min (cached)        Firecracker)      |  (background,
      |                        |             |   non-blocking)
      |    Integration:  ~10s  |             |
      |    (200 per-test       |             |
      |     microVMs, 32       |             |
      |     concurrent)        |             |
      |                        |             |
      |    System:       ~60s  |             |
      |    (5 per-variant      |             |
      |     VMs, parallel)     |             |
      |                        |             |
      +--------+---------------+             |
               |                             |
               v                             v
         Wall-clock: ~75s             Advisory results
```

### 15.2 Release Validation

```
  Tag release
      |
      v
  Full regression suite (blocking):         ~2-5 min
    - All eval checks
    - All build checks (every package)
    - All integration tests (200 microVMs)
    - All system tests (5 variants)
    - All fleet tests (blocking for release)
    - ABI baseline verification (Phase 4)
```

### 15.3 Execution

All CI steps run via the existing remote builder:

```sh
nix-build -A checks.eval --store ssh-ng://dylan@builder-hil1-319ea92d
nix-build -A checks.build --store ssh-ng://dylan@builder-hil1-319ea92d
nix-build -A checks.integration.all --store ssh-ng://dylan@builder-hil1-319ea92d
nix-build -A checks.vm.all --store ssh-ng://dylan@builder-hil1-319ea92d
# Integration tests: 200 microVMs scheduled by Nix --max-jobs
# System tests: 5 Firecracker VMs in parallel
```

The `aos test` CLI wraps these with the correct `--store` flag, progress
reporting, and log formatting. `aos test all` runs the full per-commit
pipeline.

---

## 16. Summary of Nix Attribute Paths

After full implementation:

```
checks.eval                              # Layer 1: Nix evaluation
checks.build                             # Layer 2: Package builds + closures
checks.integration.all                   # All integration tests (per-test microVMs)
checks.integration.toolchain             # Compiler/runtime checks
checks.integration.libraries             # Library ABI checks
checks.integration.tools                 # CLI tool smoke tests
checks.integration.build-systems         # Build system checks
checks.integration.cross-cutting         # Multi-package scenarios
checks.vm.boot                           # System test: boot fundamentals
checks.vm.security                       # System test: kernel hardening
checks.vm.services                       # System test: systemd, chrony, SSH, nginx
checks.vm.networking                     # System test: network stack
checks.vm.kubernetes                     # System test: containerd, kubelet, CNI
checks.vm.k8s-control-plane              # System test: etcd, apiserver
checks.vm.seed                           # System test: seed server
checks.vm.validate                       # Pre-flight syntax check (no VM)
checks.fleet.k8s-cluster                 # Fleet: multi-VM k8s cluster
checks.fleet.rolling-update              # Fleet: rolling update
```

Each `checks.integration.*` attribute depends on individual test derivations,
each of which spawns its own Firecracker microVM. Nix's `--max-jobs` controls
concurrency. Cached tests produce no VM boots.

Each `checks.vm.*` attribute is a single Firecracker VM booting the
appropriate system variant with systemd, communicating over vsock.

Each `checks.fleet.*` attribute launches multiple Firecracker VMs with
tap networking for cross-node validation.
