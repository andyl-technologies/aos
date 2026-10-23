##! Runs foreign libtests with a real target kernel and filesystem semantics.
{
  pkgs,
  targetPackages,
  compilation,
  source,
  pname ? "aos-bazel-device-aarch64",
}: let
  kernel = targetPackages.linux;
  runner = pkgs.runCommand "aos-bazel-family-guest-runner" {} ''
    mkdir -p "$out"
    cp ${../../tools/bazel/tests/run_family_vm.py} "$out/run_family_vm.py"
    cp ${../../tools/bazel/tests/family_libtest.py} "$out/family_libtest.py"
  '';
  reboot = targetPackages.runCommand "aos-bazel-family-guest-reboot" {} ''
    cat > reboot.c <<'SOURCE'
    #include <stdio.h>
    #include <sys/reboot.h>
    #include <unistd.h>

    int main(void) {
      sync();
      if (reboot(RB_AUTOBOOT) != 0) {
        perror("reboot");
        return 1;
      }
      return 0;
    }
    SOURCE
    mkdir -p "$out/bin"
    ${targetPackages.stdenv.cc}/bin/cc reboot.c -o "$out/bin/reboot"
  '';
  closure = (pkgs.lib.build.closureInfo {inherit pkgs;}) {
    pname = "${pname}-runtime-closure";
    rootPaths = [
      targetPackages.bash
      targetPackages.coreutils
      targetPackages.util-linux
      targetPackages.python3
      compilation
      runner
      reboot
      source
    ];
  };
  rootfs =
    pkgs.runCommand "${pname}-test-rootfs" {
      buildDeps = [pkgs.e2fsprogs pkgs.fakeroot];
    } ''
      mkdir -p rootfs/nix/store rootfs/dev rootfs/proc rootfs/sys rootfs/tmp rootfs/run rootfs/bin rootfs/build/bazel/execroot
      chmod 1777 rootfs/tmp
      while IFS= read -r store_path; do
        cp -a "$store_path" rootfs/nix/store/
      done < ${closure}/store-paths
      ln -s ${targetPackages.bash}/bin/bash rootfs/bin/sh
      ln -s ${source} rootfs/build/workspace
      ln -s ${source} rootfs/build/bazel/execroot/_main
      cat > rootfs/init <<'INIT'
      #!${targetPackages.bash}/bin/bash
      set -euo pipefail
      export PATH=${targetPackages.coreutils}/bin:${targetPackages.util-linux}/bin:${targetPackages.util-linux}/sbin
      export HOME=/tmp TMPDIR=/tmp LC_ALL=C PYTHONDONTWRITEBYTECODE=1
      mount -t proc proc /proc
      mount -t sysfs sysfs /sys
      mount -t devtmpfs devtmpfs /dev
      finish() {
        sync
        sleep 0.5
        # An orderly reboot drains the serial result marker before QEMU exits.
        # AOS util-linux does not provide reboot(8).
        ${reboot}/bin/reboot
        while :; do sleep 1; done
      }
      trap finish EXIT
      ${targetPackages.python3}/bin/python3 ${runner}/run_family_vm.py \
        --compilation ${compilation} --workspace /build/workspace --output /tmp/results
      INIT
      chmod +x rootfs/init
      mkdir -p "$out"
      rootfs_kib=$(du -sk rootfs | cut -f1)
      image_mib=$((rootfs_kib / 1024 * 2 + 512))
      fakeroot -- mkfs.ext4 -d rootfs -L aos-bazel-tests -m 1 -q "$out/root.img" "''${image_mib}M"
    '';
in
  assert targetPackages.stdenv.hostPlatform.config == "aarch64-unknown-linux-gnu";
    pkgs.runCommand "${pname}-parity" {
      buildDeps = [pkgs.qemu pkgs.coreutils pkgs.python3];
      # Repository VM checks require this scheduling feature, including TCG guests.
      requiredSystemFeatures = ["kvm"];
    } ''
      cp ${rootfs}/root.img root.img
      chmod u+w root.img
      ${pkgs.bash}/bin/bash -euo pipefail <<'VM'
      timeout 600 ${pkgs.qemu}/bin/qemu-system-aarch64 \
        -machine virt -cpu cortex-a72 -accel tcg -smp 4 -m 2048 \
        -kernel ${kernel}/boot/vmlinuz-* \
        -drive file=root.img,format=raw,if=virtio \
        -append 'root=/dev/vda rw rootwait init=/init console=ttyAMA0 sysrq_always_enabled=1 panic=1' \
        -nographic -no-reboot -monitor none -nic none 2>&1 | tee serial.log | tr -d '\r'
      VM
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 - serial.log ${compilation}/parity.json "$out/runtime.json" <<'PYTHON'
      import hashlib
      import json
      from pathlib import Path
      import sys

      serial, manifest, output = map(Path, sys.argv[1:])
      prefix = "AOS_BAZEL_FAMILY_VM_PASS "
      records = [json.loads(line[len(prefix):]) for line in serial.read_text().splitlines() if line.startswith(prefix)]
      if len(records) != 1:
          raise ValueError("foreign guest did not report exactly one successful family execution")
      result = records[0]
      expected = json.loads(manifest.read_text())
      if (result["compilation_sha256"] != hashlib.sha256(manifest.read_bytes()).hexdigest()
              or result["target"] != expected["target"]
              or result["executed_targets"] != len(expected["artifacts"])
              or result["executed_cases"] != expected["compiled_cases"]
              or result["ignored_cases"] != expected["ignored_cases"]):
          raise ValueError("foreign guest executed a different artifact or case inventory")
      result["runtime"] = "AOS AArch64 Linux kernel under source-built QEMU system emulation"
      output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
      PYTHON
      cp serial.log "$out/serial.log"
      cp ${compilation}/parity.json "$out/compilation.json"
    ''
