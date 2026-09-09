##! Boots AArch64 Linux and exercises its public hosted C/C++ toolchain.
{
  pkgs,
  llvmVersion ? null,
}: let
  buildSystem = pkgs.stdenv.buildPlatform.system;
  targetSystem = "aarch64-linux";
  cross = import ../.. {
    system = buildSystem;
    crossSystem = targetSystem;
  };
  targetPackages = cross.pkgs;
  llvm =
    if llvmVersion == null
    then null
    else targetPackages."llvm-${llvmVersion}";
  testName =
    if llvmVersion == null
    then "linux-hosted-toolchain-vm"
    else "linux-hosted-llvm-${llvmVersion}-vm";
  llvmScript =
    if llvm == null
    then ""
    else
      import ./_linux-hosted-llvm-script.nix {
        inherit llvm;
        inherit (targetPackages) glibc gcc;
      };
  targetKernel = targetPackages.linux;
  empty = targetPackages.writeTextFile {
    name = "linux-hosted-toolchain-vm-empty";
    text = "";
  };
  fakeSystem.config.system.build = {
    toplevel = empty;
    kernel = targetKernel;
    systemdSystemPresets = empty;
  };
  rootfs = import ../../lib/build/rootfs.nix {
    pkgs = cross.buildPackages;
    lib = cross.lib;
    system = fakeSystem;
    pname = "${testName}-rootfs";
    shrinkToFit = false;
    minSizeMiB = 2048;
    extraClosures =
      [
        targetPackages.bash
        targetPackages.cc
        targetPackages.coreutils
        targetPackages.grep
        targetPackages.util-linux
      ]
      ++ (
        if llvm == null
        then []
        else [llvm targetPackages.glibc.dev targetPackages.glibc.static]
      );
    symlinkFarmPkgs = [];
    postPopulate = ''
      ln -s ../nix.lower/store rootfs/nix/store
      cat > rootfs/init <<'INIT'
      #!${targetPackages.bash}/bin/bash
      set -euxo pipefail

      export PATH=${targetPackages.cc}/bin:${targetPackages.gcc}/bin:${targetPackages.binutils}/bin:${targetPackages.coreutils}/bin:${targetPackages.grep}/bin:${targetPackages.util-linux}/bin
      export HOME=/tmp
      export TMPDIR=/tmp
      export LC_ALL=C

      mount -t proc proc /proc
      mount -t sysfs sysfs /sys
      cd /tmp

      test "$(gcc -dumpmachine)" = aarch64-unknown-linux-gnu
      test "$(ld --version | head -n 1)" = "GNU ld (GNU Binutils) 2.41"

      cat > hosted.c <<'SOURCE'
      #include <stdio.h>
      #include <string.h>

      __attribute__((noinline)) static int compute(const char *text) {
          char buffer[32];
          strcpy(buffer, text);
          return (int)strlen(buffer) + 36;
      }

      int main(void) {
          return printf("hosted C result: %d\n", compute("ANDYL!")) < 0;
      }
      SOURCE
      cc hosted.c -o hosted-c
      test "$(./hosted-c)" = "hosted C result: 42"

      cat > hosted.cc <<'SOURCE'
      #include <algorithm>
      #include <iostream>
      #include <vector>

      int main() {
          std::vector<int> values{23, 19};
          std::sort(values.begin(), values.end());
          std::cout << "hosted C++ result: " << values[0] + values[1] << '\n';
      }
      SOURCE
      c++ hosted.cc -o hosted-cxx
      test "$(./hosted-cxx)" = "hosted C++ result: 42"

      readelf -h hosted-c > hosted.header
      readelf -W -l hosted-c > hosted.segments
      readelf -d hosted-c > hosted.dynamic
      objdump -d hosted-c > hosted.disassembly

      grep -Eq 'Type:.*DYN' hosted.header
      grep -Eq 'GNU_STACK.*RW ' hosted.segments
      grep -Fq 'GNU_RELRO' hosted.segments
      grep -Fq 'BIND_NOW' hosted.dynamic
      grep -Fq 'paciasp' hosted.disassembly

      cc -fno-PIE -no-pie hosted.c -o hosted-no-pie
      readelf -h hosted-no-pie > hosted-no-pie.header
      grep -Eq 'Type:.*EXEC' hosted-no-pie.header
      test "$(./hosted-no-pie)" = "hosted C result: 42"

      printf 'int main(void) { int value = ; return value; }\n' > invalid.c
      if cc invalid.c -o invalid-program >/tmp/invalid.stdout 2>/tmp/invalid.stderr; then
        echo 'hosted compiler accepted malformed C' >&2
        exit 1
      fi
      test -s /tmp/invalid.stderr

      ${llvmScript}

      echo AOS_HOSTED_TOOLCHAIN_VM_PASS
      sync
      echo b > /proc/sysrq-trigger
      while :; do sleep 1; done
      INIT
      chmod +x rootfs/init
    '';
  };
in
  pkgs.mkDerivation {
    pname = testName;
    version = "0";
    src = null;
    buildDeps = [
      pkgs.qemu
      pkgs.coreutils
      pkgs.grep
    ];
    phases = [
      {
        name = "run";
        script = ''
          cp ${rootfs}/root.img root.img
          chmod u+w root.img

          qemu_status=0
          timeout 600 qemu-system-aarch64 \
            -machine virt \
            -cpu cortex-a72 \
            -accel tcg \
            -smp 4 \
            -m 2048 \
            -kernel ${targetKernel}/boot/vmlinuz-* \
            -drive file=root.img,format=raw,if=virtio \
            -append 'root=/dev/vda rw rootwait init=/init console=ttyAMA0 sysrq_always_enabled=1 panic=1' \
            -nographic \
            -no-reboot \
            -monitor none \
            > serial.log 2>&1 || qemu_status=$?

          tr -d '\r' < serial.log
          if ! grep -Fq AOS_HOSTED_TOOLCHAIN_VM_PASS serial.log; then
            echo "hosted toolchain guest failed before its completion marker (QEMU status $qemu_status)" >&2
            exit 1
          fi
          mkdir -p "$out"
          cp serial.log "$out/"
        '';
      }
    ];
  }
