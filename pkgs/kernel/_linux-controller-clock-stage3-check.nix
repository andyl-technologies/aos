##! Cross-compile ARM clock mediation and execute architecture-neutral arithmetic.
{
  mkDerivation,
  linux,
  linuxSource,
  stdenv,
  buildPackages,
  llvm,
  gnumake,
  patch,
  perl,
  python3,
  bc,
  bison,
  flex,
  elfutils,
  openssl,
  zlib,
  gcc-libs,
  rsync,
}: let
  hostInclude = "${buildPackages.elfutils}/include:${buildPackages.openssl}/include:${buildPackages.zlib}/include";
  hostLibrary = "${buildPackages.elfutils}/lib:${buildPackages.openssl}/lib:${buildPackages.zlib}/lib";
  hostCompiler = "env C_INCLUDE_PATH=${hostInclude} LIBRARY_PATH=${hostLibrary} ${buildPackages.cc}/bin/cc";
in
  mkDerivation {
    pname = "linux-controller-clock-stage3-check";
    version = linuxSource.version;
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          cpu = ["x86_64"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    buildDeps = [llvm gnumake patch perl python3 bc bison flex elfutils openssl zlib gcc-libs rsync];
    runtimeDeps = [];
    hardeningDisable = ["all"];

    phases = [
      {
        name = "check";
        script = ''
          cp -a ${linux.dev}/lib/modules/${linuxSource.version}/build kernel
          chmod -R u+w kernel
          cd kernel
          patch -p1 < ${./crucible-controller-clock-7.2.3.patch}
          patch -p1 < ${./crucible-controller-clock-stage2-7.2.3.patch}
          patch -p1 < ${./crucible-controller-clock-stage3-7.2.3.patch}

          export LD_LIBRARY_PATH="${buildPackages.gcc-libs}/lib:${hostLibrary}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          make -j$NIX_BUILD_CORES ARCH=x86_64 CC="$CC" LD="$LD" AR="$AR" \
            NM="$NM" OBJCOPY="${stdenv.binutils}/bin/objcopy" \
            HOSTCC="${hostCompiler}" HOSTCXX="env C_INCLUDE_PATH=${hostInclude} LIBRARY_PATH=${hostLibrary} ${buildPackages.cc}/bin/c++" \
            HOSTLD="${buildPackages.binutils}/bin/ld" HOSTAR="${buildPackages.binutils}/bin/ar" \
            HOSTPKG_CONFIG="${buildPackages.pkg-config}/bin/pkg-config" \
            arch/x86/kvm/crucible-clock.o arch/x86/kvm/lapic.o

          # Start ARM configuration from the same source after checking the shared
          # x86 arithmetic extraction. No host architecture headers are reused.
          make ARCH=x86_64 HOSTCC="${hostCompiler}" mrproper
          make ARCH=arm64 LLVM=${llvm}/bin/ LLVM_IAS=1 \
            HOSTCC="${hostCompiler}" HOSTLD="${buildPackages.binutils}/bin/ld" defconfig
          # The initial component refuses AArch32 guests; this source check uses
          # that profile configuration rather than requiring an unrelated ARMv7
          # backend for the compatibility vDSO. Production kernel features remain.
          $CONFIG_SHELL scripts/config --disable COMPAT
          make ARCH=arm64 LLVM=${llvm}/bin/ LLVM_IAS=1 \
            HOSTCC="${hostCompiler}" olddefconfig
          make -j$NIX_BUILD_CORES ARCH=arm64 LLVM=${llvm}/bin/ LLVM_IAS=1 \
            HOSTCC="${hostCompiler}" HOSTCXX="env C_INCLUDE_PATH=${hostInclude} LIBRARY_PATH=${hostLibrary} ${buildPackages.cc}/bin/c++" \
            HOSTLD="${buildPackages.binutils}/bin/ld" HOSTAR="${buildPackages.binutils}/bin/ar" \
            HOSTPKG_CONFIG="${buildPackages.pkg-config}/bin/pkg-config" \
            arch/arm64/kvm/crucible-clock.o arch/arm64/kvm/arm.o \
            arch/arm64/kvm/arch_timer.o arch/arm64/kvm/sys_regs.o \
            arch/arm64/kvm/hypercalls.o arch/arm64/kvm/pvtime.o \
            arch/arm64/kvm/vgic/vgic-init.o arch/arm64/kvm/vgic/vgic-its.o \
            arch/arm64/kvm/vgic/vgic-mmio-v3.o \
            arch/arm64/kvm/hyp/vhe/switch.o arch/arm64/kvm/hyp/nvhe/switch.o virt/kvm/kvm_main.o

          make -j$NIX_BUILD_CORES ARCH=arm64 LLVM=${llvm}/bin/ LLVM_IAS=1 \
            HOSTCC="${hostCompiler}" headers_install INSTALL_HDR_PATH="$TMPDIR/controller-headers"
          $CC -std=c11 -Wall -Wextra -Werror -I. -I"$TMPDIR/controller-headers/include" \
            ${./crucible-clock-stage3-math-test.c} -o clock-math-test
          ./clock-math-test

          mkdir -p $out
          cat > $out/report << 'REPORT'
          shared x86 controller arithmetic extraction: source compiled
          ARM controller/counter/timer/run/GIC bypass-refusal paths: cross-compiled
          controller arithmetic/ABI/admission-state oracles: pass
          native x86/AArch64 KVM qualification: not executed
          complete device/output/architectural restoration closure: unqualified
          REPORT
        '';
      }
    ];
  }
