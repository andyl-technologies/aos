##! Boots AArch64 Linux and exercises its public hosted C/C++ toolchain.
{
  pkgs,
  llvmVersion ? null,
  rustPackage ? null,
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
  rust =
    if rustPackage == null
    then null
    else targetPackages.${rustPackage};
  rustScript =
    if rust == null
    then ""
    else
      import ./_linux-hosted-rust-script.nix {
        inherit rust;
        llvm =
          if rust ? dev
          then targetPackages.llvm
          else null;
      };
  testName =
    if rustPackage != null
    then "linux-hosted-${rustPackage}-vm"
    else if llvmVersion == null
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
        targetPackages.glibc.bin
      ]
      ++ (
        if llvm == null
        then []
        else [llvm targetPackages.glibc.dev targetPackages.glibc.static]
      )
      ++ (
        if rust == null
        then []
        else [rust] ++ pkgs.lib.optional (rust ? dev) rust.dev
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
      for driver in gcc g++ cc c++; do
        for program in as ld; do
          selected=$("$driver" -print-prog-name="$program")
          expected="${targetPackages.binutils}/bin/$program"
          test "$(readlink -f "$selected")" = "$(readlink -f "$expected")"
        done
      done

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

      for script in ldd sotruss xtrace; do
        test "$(head -n 1 ${targetPackages.glibc.bin}/bin/$script)" = '#!${targetPackages.bash}/bin/bash'
        ${targetPackages.glibc.bin}/bin/$script --help > /tmp/libc-$script-help.txt
        test -s /tmp/libc-$script-help.txt
      done
      test "$(head -n 1 ${targetPackages.glibc.bin}/bin/mtrace)" = '#!${targetPackages.perl}/bin/perl'
      ${targetPackages.glibc.bin}/bin/mtrace --help > /tmp/libc-mtrace-help.txt
      test -s /tmp/libc-mtrace-help.txt
      printf '+ 0x1234 0x10\n- 0x1234\n' > /tmp/allocations.trace
      ${targetPackages.glibc.bin}/bin/mtrace /tmp/allocations.trace > /tmp/mtrace-balanced.txt
      grep -Fq 'No memory leaks.' /tmp/mtrace-balanced.txt
      printf '+ 0x1234 0x10\n' > /tmp/allocations.trace
      mtrace_status=0
      ${targetPackages.glibc.bin}/bin/mtrace /tmp/allocations.trace > /tmp/mtrace-leak.txt || mtrace_status=$?
      test "$mtrace_status" -eq 1
      grep -Fq 'Memory not freed:' /tmp/mtrace-leak.txt

      ${targetPackages.glibc.bin}/bin/ldd ./hosted-c > /tmp/hosted-c-libraries.txt
      grep -Fq libc.so.6 /tmp/hosted-c-libraries.txt

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
      ${rustScript}

      echo AOS_HOSTED_TOOLCHAIN_VM_PASS
      sync
      echo b > /proc/sysrq-trigger
      while :; do sleep 1; done
      INIT
      chmod +x rootfs/init
    '';
  };
in
  # Explicit output selection must publish the same completed utility output
  # as the package attribute, not an earlier construction-stage bin output.
  assert targetPackages.glibc.bin.drvPath == targetPackages.glibc.drvPath;
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
