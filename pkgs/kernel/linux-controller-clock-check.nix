##! Compile native x86 controller hooks and execute their exact integer arithmetic.
{
  mkDerivation,
  linux,
  linuxSource,
  stdenv,
  buildPackages,
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
in
  mkDerivation {
    pname = "linux-controller-clock-check";
    version = linuxSource.version;
    platformSupport = {
      build = [{abi = ["gnu"]; cpu = ["x86_64"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    buildDeps = [gnumake patch perl python3 bc bison flex elfutils openssl zlib gcc-libs rsync];
    runtimeDeps = [];
    hardeningDisable = ["all"];

    phases = [
      {
        name = "check";
        script = ''
          cp -a ${linux.dev}/lib/modules/${linuxSource.version}/build kernel
          chmod -R u+w kernel
          cd kernel
          test "$(sed -n 's/^#define UTS_MACHINE[[:space:]]*"\([^"]*\)"/\1/p' include/generated/compile.h)" = x86_64
          patch -p1 < ${./crucible-controller-clock-7.2.3.patch}

          export LD_LIBRARY_PATH="${buildPackages.gcc-libs}/lib:${hostLibrary}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          make -j$NIX_BUILD_CORES ARCH=x86_64 CC="$CC" LD="$LD" AR="$AR" \
            NM="$NM" OBJCOPY="${stdenv.binutils}/bin/objcopy" \
            OBJDUMP="${stdenv.binutils}/bin/objdump" READELF="${stdenv.binutils}/bin/readelf" \
            HOSTCC="env C_INCLUDE_PATH=${hostInclude} LIBRARY_PATH=${hostLibrary} ${buildPackages.cc}/bin/cc" \
            HOSTCXX="env C_INCLUDE_PATH=${hostInclude} LIBRARY_PATH=${hostLibrary} ${buildPackages.cc}/bin/c++" \
            HOSTLD="${buildPackages.binutils}/bin/ld" HOSTAR="${buildPackages.binutils}/bin/ar" \
            HOSTPKG_CONFIG="${buildPackages.pkg-config}/bin/pkg-config" \
            arch/x86/kvm/crucible-clock.o arch/x86/kvm/x86.o \
            arch/x86/kvm/vmx/vmx.o arch/x86/kvm/svm/svm.o KCFLAGS="-Werror=override-init"

          make -j$NIX_BUILD_CORES ARCH=x86_64 \
            HOSTCC="env C_INCLUDE_PATH=${hostInclude} LIBRARY_PATH=${hostLibrary} ${buildPackages.cc}/bin/cc" \
            headers_install INSTALL_HDR_PATH="$TMPDIR/controller-headers"

          $CC -std=c11 -Wall -Wextra -Werror \
            -I. -I"$TMPDIR/controller-headers/include" \
            ${./crucible-clock-math-test.c} -o clock-math-test
          ./clock-math-test

          mkdir -p $out
          cat > $out/report << 'REPORT'
          x86 controller clock source hooks compile: pass
          controller integer arithmetic and ABI layout: pass
          native KVM counter/run/stop qualification: not executed
          pvclock/LAPIC/ARM/device mediation: not implemented by this patch
          REPORT
        '';
      }
    ];
  }
