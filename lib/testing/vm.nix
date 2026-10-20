# lib/testing/vm.nix — Single-VM test harness (Firecracker only)
#
# Architecture:
#   1. Build a rootfs ext4 image from the system's Nix store closure
#      (uses mkfs.ext4 -d — no losetup/mount, sandbox-compatible)
#   2. Boot a Firecracker microVM
#   3. Guest agent communicates over vsock
#   4. Host sends commands, asserts on results
#
# Multi-VM tests live in lib/testing/fleet.nix and use QEMU (virtio-serial
# transport, multicast L2 between guests). The two harnesses are deliberately
# segregated by transport — vsock (Firecracker) here, virtio-serial (QEMU)
# there — and don't share driver state.
#
# Requirements:
#   - Kernel with built-in: VIRTIO, VIRTIO_PCI, VIRTIO_BLK, EXT4_FS,
#     VIRTIO_CONSOLE, DEVTMPFS, DEVTMPFS_MOUNT, VIRTIO_VSOCKETS, VIRTIO_MMIO
#   - requiredSystemFeatures = [ "kvm" ] on the builder
{
  pkgs,
  lib,
}: let
  firecracker = pkgs.firecracker;

  # Headless rootfs builder for integration tests without a system manager.
  fcLib = import ./firecracker.nix {inherit pkgs lib;};
  kernel = pkgs.linux;

  # The selected image package owns its test disk shape. The harness only
  # supplies generic builders and the evaluated system inputs.
  mkTestDisk = arguments: let
    platform = arguments.system.config.aos.image.platform;
  in
    if platform == null
    then throw "mkTestDisk requires a selected image-builder ability"
    else
      platform.buildTestDisk {
        closureInfoFor = lib.build.closureInfo {inherit pkgs;};
        inherit (pkgs) mkDerivation;
        testAgent = pkgs.aos-test-agent;
        sshTools = pkgs.openssh;
        inputs = arguments;
      };

  # ---------------------------------------------------------------------------
  # Create a VM test derivation
  # ---------------------------------------------------------------------------
  checksLib = import ./checks.nix;

  # ---------------------------------------------------------------------------
  # Headless test: test script IS init (PID 1), serial PASS/FAIL markers
  # ---------------------------------------------------------------------------
  mkHeadlessTest = {
    name,
    testScript,
    rootfsDeps ? [],
    memory ? 256,
    extraWritableMiB ? 0,
    vcpuCount ? 1,
    hostCpuPin ? false,
    hostCpuPinIndex ? null,
  }: let
    rootfs = fcLib.mkFirecrackerRootfs {
      pname = name;
      inherit testScript rootfsDeps extraWritableMiB;
    };
    # Firecracker boots the uncompressed vmlinux ELF, which lives in the
    # kernel's separate `vmlinux` output (pkgs/kernel/linux.nix) — not in
    # `out`, whose /boot ships only the compressed vmlinuz.
    kernelPath = builtins.toString kernel.vmlinux;

    headlessBuildDeps =
      [
        pkgs.coreutils
        pkgs.grep
        pkgs.sed
        firecracker
      ]
      ++ (
        if hostCpuPin
        then [pkgs.util-linux]
        else []
      );

    headlessFirecrackerScript = ''
      set -eu

      SERIAL_LOG="$TMPDIR/serial.log"
      SERIAL_PIPE="$TMPDIR/serial.pipe"
      FC_LOG="$TMPDIR/fc.log"
      CONFIG="$TMPDIR/vm_config.json"

      VMLINUX=$(ls $KERNEL/boot/vmlinux-* | head -1)
      if [ -z "$VMLINUX" ]; then
        echo "ERROR: No vmlinux kernel image found in $KERNEL/boot/"
        exit 1
      fi

      cp $ROOTFS rootfs.img
      chmod u+w rootfs.img

      echo "Kernel: $VMLINUX"
      echo "Rootfs: rootfs.img ($(ls -lh rootfs.img | awk '{print $5}'))"
      echo "Memory: ${builtins.toString memory} MiB"
      ls -la /dev/kvm 2>/dev/null && echo "KVM: available" || echo "KVM: NOT available"

      cat > "$CONFIG" << CFGEOF
      {
        "boot-source": {
          "kernel_image_path": "$VMLINUX",
          "boot_args": "console=ttyS0 reboot=k panic=1 root=/dev/vda ro init=/init quiet"
        },
        "drives": [
          {
            "drive_id": "rootfs",
            "path_on_host": "$(pwd)/rootfs.img",
            "is_root_device": true,
            "is_read_only": false,
            "cache_type": "Unsafe",
            "io_engine": "Sync"
          }
        ],
        "machine-config": {
          "vcpu_count": ${builtins.toString vcpuCount},
          "mem_size_mib": ${builtins.toString memory},
          "smt": false,
          "track_dirty_pages": false,
          "huge_pages": "None"
        }
      }
      CFGEOF

      unset LD_LIBRARY_PATH || true

      echo "==> Launching Firecracker for test: ${name}"

      rm -f "$SERIAL_PIPE"
      mkfifo "$SERIAL_PIPE"
      tee "$SERIAL_LOG" < "$SERIAL_PIPE" \
        | sed -u \
            -e 's/\r$//' \
            -e '/^[0-9][0-9][0-9][0-9]-[0-9].*\[anonymous-instance:/d' &
      SERIAL_MIRROR_PID=$!

      ${
        if hostCpuPin
        then ''
          host_allowed=$(sed -n 's/^Cpus_allowed_list:[[:space:]]*//p' /proc/self/status)
          ${
            if hostCpuPinIndex == null
            then ''host_cpu=$(printf '%s\n' "$host_allowed" | cut -d , -f 1 | cut -d - -f 1)''
            else ''host_cpu=${builtins.toString hostCpuPinIndex}''
          }
          test -n "$host_cpu"
          ${pkgs.util-linux}/bin/taskset -c "$host_cpu" ${pkgs.coreutils}/bin/true
          # Stop at the first CPU instead of triggering SIGPIPE under pipefail.
          first_cpuinfo_field() {
            sed -n "/^$1[[:space:]]*:/ { s/^[^:]*:[[:space:]]*//; p; q; }" /proc/cpuinfo
          }
          host_model=$(first_cpuinfo_field 'model name')
          test -n "$host_model"
          host_family=$(first_cpuinfo_field 'cpu family')
          host_model_number=$(first_cpuinfo_field model)
          host_stepping=$(first_cpuinfo_field stepping)
          host_microcode=$(first_cpuinfo_field microcode)
          test -n "$host_family" && test -n "$host_model_number" && test -n "$host_stepping" && test -n "$host_microcode"
          host_boot_id=$(cat /proc/sys/kernel/random/boot_id)
          test -n "$host_boot_id"
          printf 'host_name=%s\nhost_boot_id=%s\nhost_cpu_model=%s\nhost_cpu_family=%s\nhost_cpu_model_number=%s\nhost_cpu_stepping=%s\nhost_cpu_microcode=%s\nhost_kernel_release=%s\nhost_allowed_cpus=%s\nhost_pinned_cpu=%s\n' \
            "$(uname -n)" "$host_boot_id" "$host_model" "$host_family" "$host_model_number" \
            "$host_stepping" "$host_microcode" "$(uname -r)" "$host_allowed" "$host_cpu" \
            > "$TMPDIR/host-reference.env"
          FC_EXIT=0
          ${pkgs.util-linux}/bin/taskset -c "$host_cpu" \
            firecracker --no-api --config-file "$CONFIG" > "$SERIAL_PIPE" 2>"$FC_LOG" || FC_EXIT=$?
        ''
        else ''
          FC_EXIT=0
          firecracker --no-api --config-file "$CONFIG" > "$SERIAL_PIPE" 2>"$FC_LOG" || FC_EXIT=$?
        ''
      }
      wait "$SERIAL_MIRROR_PID" 2>/dev/null || true

      echo "Firecracker exited with code: $FC_EXIT"

      if grep -q "TEST_RESULT:PASS" "$SERIAL_LOG"; then
        echo ""
        echo "==> TEST PASSED: ${name}"
        mkdir -p $out
        cp "$SERIAL_LOG" $out/serial.log
        cp "$FC_LOG" $out/fc.log 2>/dev/null || true
        ${
        if hostCpuPin
        then ''cp "$TMPDIR/host-reference.env" $out/host-reference.env''
        else ""
      }
        echo "PASS" > $out/result
      elif grep -q "TEST_RESULT:FAIL" "$SERIAL_LOG"; then
        echo ""
        echo "==> TEST FAILED: ${name}"
        echo "--- serial.log ---"
        cat "$SERIAL_LOG"
        echo "--- fc.log ---"
        cat "$FC_LOG" 2>/dev/null || true
        exit 1
      else
        echo ""
        echo "==> ERROR: No test result marker found in serial output"
        echo "--- serial.log ---"
        cat "$SERIAL_LOG"
        echo "--- fc.log ---"
        cat "$FC_LOG" 2>/dev/null || true
        exit 1
      fi
    '';
  in
    pkgs.mkDerivation {
      pname = "aos-vm-test-${name}";
      version = "0";
      src = null;

      buildDeps = headlessBuildDeps;

      ROOTFS = builtins.toString rootfs;
      KERNEL = kernelPath;

      phases = [
        {
          name = "test";
          script = headlessFirecrackerScript;
        }
      ];

      requiredSystemFeatures = ["kvm"];
    };

  # ---------------------------------------------------------------------------
  # Unified VM test entry point
  # ---------------------------------------------------------------------------
  # Supports two modes:
  #   - System mode (system parameter): selected platform + agent
  #   - Headless mode (rootfsDeps parameter): test script IS init, for package checks
  mkVMTest = {
    name,
    # System mode (selected platform + agent):
    system ? null,
    groupName ? name,
    checks ? [],
    # Headless mode (test script IS init):
    rootfsDeps ? null,
    # Shared:
    testScript ? null,
    extraDisks ? [],
    kernelParams ? [],
    # Null means "harness default", so a caller threading an unset option
    # through does not have to restate the number.
    timeout ? null,
    memory ? null,
    extraWritableMiB ? 0,
    # Headless package tests default to one host CPU unless the fixture opts in.
    headlessVcpuCount ? 1,
    hostCpuPin ? false,
    hostCpuPinIndex ? null,
    seedSELinuxDisabledConfig ? true,
  }:
    if rootfsDeps != null
    then
      if headlessVcpuCount < 1 || headlessVcpuCount > 32
      then throw "mkVMTest headlessVcpuCount must be in 1..32"
      else
        mkHeadlessTest {
          inherit
            name
            testScript
            rootfsDeps
            extraWritableMiB
            hostCpuPin
            hostCpuPinIndex
            ;
          memory =
            if memory != null
            then memory
            else 256;
          vcpuCount = headlessVcpuCount;
        }
    else if system != null
    then let
      systemDisk = mkTestDisk {inherit system seedSELinuxDisabledConfig;};
      systemKernel = system.config.system.build.kernel;
      systemInitrd = system.config.system.build.initrd;

      # Compose Python check fragments into the test source, then
      # append the user's testScript if provided. Both halves are
      # Python now; see lib/testing/checks.nix:composeChecks.
      checksPy =
        if checks != []
        then checksLib.composeChecks {inherit groupName checks;}
        else "";
      composedTestPy =
        if checksPy != "" && testScript != null
        then checksPy + "\n" + testScript
        else if checksPy != ""
        then checksPy
        else if testScript != null
        then testScript
        else throw "mkVMTest '${name}': must provide either testScript or checks (or both)";

      effectiveMemory =
        if memory != null
        then memory
        else 2048;

      effectiveTimeout =
        if timeout != null
        then timeout
        else 120;

      # Driver manifest. The aos-test-driver consumes this JSON to
      # build one FirecrackerMachine; the testScript runs as a
      # Python module via runpy with `vm` exposed as a global. See
      # the v1 spec ("Manifest schema") for the full field list.
      manifest = {
        inherit name;
        timeout = effectiveTimeout;
        machines = [
          {
            name = "vm";
            transport = "firecracker";
            # The driver feeds this to Firecracker as the boot kernel, which
            # must be the uncompressed vmlinux ELF — sourced from the kernel's
            # separate `vmlinux` output (the system's `out` /boot has only the
            # compressed vmlinuz). Matches the system's own kernel build.
            kernel = builtins.toString systemKernel.vmlinux;
            initrd = "${builtins.toString systemInitrd}/initrd.img";
            disk = "${builtins.toString systemDisk}/disk.img";
            # Single-VM tests bake all config into the system /etc; no metadata
            # channel because machine identity is baked into the image.
            metadata = null;
            memory_mib = effectiveMemory;
            vcpu_count = 2;
            # Blank devices for storage checks, presented as /dev/vdb onward.
            extra_disks = map (disk: {inherit (disk) sizeMiB;}) extraDisks;
            # Appended to the harness's own boot arguments, which own the root
            # and console selection. Kernel module parameters live here.
            kernel_params = kernelParams;
          }
        ];
      };
      manifestFile = pkgs.writeTextFile {
        name = "aos-vm-test-${name}-manifest.json";
        text = builtins.toJSON manifest;
        destination = "/manifest.json";
      };
      testPyFile = pkgs.writeTextFile {
        name = "aos-vm-test-${name}-test.py";
        text = composedTestPy;
        destination = "/test.py";
      };

      driverBuildDeps = [
        pkgs.coreutils
        firecracker
        pkgs.socat
        pkgs.python3
        pkgs.aos-test-driver
      ];

      # -----------------------------------------------------------------------
      # Firecracker driver script (system mode)
      # -----------------------------------------------------------------------
      # The host-side glue is now thin: write manifest + test.py into
      # $TMPDIR, exec aos-test-driver, copy logs into $out. Boot
      # plumbing (Firecracker JSON, vsock handshake, agent wait,
      # shutdown) lives in aos_test_driver/firecracker.py.
      firecrackerDriverScript = ''
        set -eu

        # AOS build libs can conflict with the driver's child processes
        # (Firecracker, python's own runtime linker). Match what the
        # bash driver did.
        unset LD_LIBRARY_PATH

        cp ${manifestFile}/manifest.json "$TMPDIR/manifest.json"
        cp ${testPyFile}/test.py         "$TMPDIR/test.py"

        ${pkgs.aos-test-driver}/bin/aos-test-driver \
          --manifest "$TMPDIR/manifest.json" \
          --test     "$TMPDIR/test.py"

        mkdir -p "$out"
        for log in "$TMPDIR"/*-serial.log "$TMPDIR"/*-firecracker.log; do
          [ -f "$log" ] && cp "$log" "$out/"
        done
        echo PASS > "$out/result"
      '';
    in
      pkgs.mkDerivation {
        pname = "aos-vm-test-${name}";
        version = "0";
        src = null;

        buildDeps = driverBuildDeps;

        phases = [
          {
            name = "test";
            script = firecrackerDriverScript;
          }
        ];

        requiredSystemFeatures = ["kvm"];
      }
    else throw "mkVMTest '${name}': must provide either 'system' (for full VM tests) or 'rootfsDeps' (for headless tests)";
in {
  inherit mkVMTest mkTestDisk;
}
