##! edk2 — TianoCore EDK2 UEFI firmware for QEMU
##!
##! Builds the firmware matching the Linux target architecture. x86_64 uses
##! OVMF's split pflash, while aarch64 uses ArmVirt's code image and QEMU's
##! persistent paravirtual variable store:
##!
##!   $out/FV/OVMF_CODE.fd  — read-only firmware code flash
##!   $out/FV/OVMF_VARS.fd  — writable NVRAM variable store template
##!   $out/FV/OVMF.fd       — combined image (single-pflash use)
##!   $out/FV/AAVMF_CODE.fd — aarch64 ArmVirt code flash
##!
##! Two toolchains are deliberately in play:
##!
##!  - BaseTools (host-side C utilities: GenFw, GenFv, VfrCompile, ...)
##!    are ordinary hosted programs and build with the wrapped AOS gcc
##!    from PATH, which provides glibc headers and libuuid via the
##!    usual C_INCLUDE_PATH/LIBRARY_PATH plumbing.
##!
##!  - The firmware itself is freestanding and must NOT see the
##!    ccWrapper: the injected -Wl,-dynamic-linker / -Wl,-rpath flags
##!    corrupt the -nostdlib ELF images that GenFw converts to PE/COFF.
##!    The build points EDK2's GCC toolchain prefix (ENV(GCC_BIN) /
##!    ENV(GCC5_BIN) in tools_def) at a synthesized bin dir of the raw
##!    bootstrap gcc (read from nix-support/orig-cc) plus binutils
##!    resolved from the bootstrap PATH.
##!
##! Source comes from fixed-output archives for the pinned EDK2 revision and
##! each top-level gitlink. OVMF compiles vendored submodule sources directly,
##! while archive downloads avoid both evaluation-time Git access and the
##! irrelevant nested Git histories included by a recursive clone.
{
  mkDerivation,
  fetchurl,
  bootstrapTools,
  gccUnwrapped,
  buildPackages,
  stdenv,
  gnumake,
  python3,
  nasm,
  acpica,
  util-linux,
}: let
  version = "edk2-stable202602";
  buildAarch64Firmware = stdenv.hostPlatform.system == "aarch64-linux";
  buildPython =
    if stdenv.isCross
    then buildPackages.python3
    else python3;
  buildNasm =
    if stdenv.isCross
    then buildPackages.nasm
    else nasm;
  buildAcpica =
    if stdenv.isCross
    then buildPackages.acpica
    else acpica;
  src = fetchurl {
    urls = [
      "https://github.com/tianocore/edk2/archive/b7a715f7c03c45c6b4575bf88596bfd79658b8ce.tar.gz"
    ];
    hash = "sha256-pd+cG+mxfePYMY/SgAN4DPZ56yujyuM6ahiQ1/YNJ90=";
  };
  brotliSrc = fetchurl {
    urls = [
      "https://github.com/google/brotli/archive/e230f474b87134e8c6c85b630084c612057f253e.tar.gz"
    ];
    hash = "sha256-qbo5QCZ95d1zWBpHwugbPrHh32pwQTjFmQINZvNnepI=";
  };
  submoduleSources = [
    {
      path = "BaseTools/Source/C/BrotliCompress/brotli";
      src = brotliSrc;
    }
    {
      path = "CryptoPkg/Library/MbedTlsLib/mbedtls";
      src = fetchurl {
        urls = [
          "https://github.com/ARMmbed/mbedtls/archive/e185d7fd85499c8ce5ca2a54f5cf8fe7dbe3f8df.tar.gz"
        ];
        hash = "sha256-BS3M86QE3OJaRnxv4ESwyFjWCazo6IO1np39R5/dRSg=";
      };
    }
    {
      path = "CryptoPkg/Library/OpensslLib/openssl";
      src = fetchurl {
        urls = [
          "https://github.com/openssl/openssl/archive/aea7aaf2abb04789f5868cbabec406ea43aa84bf.tar.gz"
        ];
        hash = "sha256-DbLFiI54s+4Q31mRyb0Emiyg62k7PESgXzB4qQrdNJo=";
      };
    }
    {
      path = "MdeModulePkg/Library/BrotliCustomDecompressLib/brotli";
      src = brotliSrc;
    }
    {
      path = "MdeModulePkg/Universal/RegularExpressionDxe/oniguruma";
      src = fetchurl {
        urls = [
          "https://github.com/kkos/oniguruma/archive/4ef89209a239c1aea328cf13c05a2807e5c146d1.tar.gz"
        ];
        hash = "sha256-cL/tl+6DkPWsCP6ijj6TCjsz34ccb8GIjI1DbGxrdV0=";
      };
    }
    {
      path = "MdePkg/Library/BaseFdtLib/libfdt";
      src = fetchurl {
        urls = [
          "https://github.com/devicetree-org/pylibfdt/archive/cfff805481bdea27f900c32698171286542b8d3c.tar.gz"
        ];
        hash = "sha256-EZORD0df3gfzzU/hwaNT1puM7bV0lnE0g4/NyCCNIk4=";
      };
    }
    {
      path = "MdePkg/Library/MipiSysTLib/mipisyst";
      src = fetchurl {
        urls = [
          "https://github.com/MIPI-Alliance/public-mipi-sys-t/archive/370b5944c046bab043dd8b133727b2135af7747a.tar.gz"
        ];
        hash = "sha256-n9o7mng0OrK+bwbOY5ZTbn4GWrrCm0fI6y5Cy7TE8As=";
      };
    }
    {
      path = "RedfishPkg/Library/JsonLib/jansson";
      src = fetchurl {
        urls = [
          "https://github.com/akheron/jansson/archive/e9ebfa7e77a6bee77df44e096b100e7131044059.tar.gz"
        ];
        hash = "sha256-55NcDZHW0i9t7nEKJrI+Io7MT+jvfo91ZVjDWZ9ow7Q=";
      };
    }
    {
      path = "SecurityPkg/DeviceSecurity/SpdmLib/libspdm";
      src = fetchurl {
        urls = [
          "https://github.com/DMTF/libspdm/archive/1be116c7b7713fa9003e1bd53b53a34758549eb9.tar.gz"
        ];
        hash = "sha256-WSde3G+1bGKTBebwH+Fz3fnwZc3plfGLiaZOEo6uhgQ=";
      };
    }
    {
      path = "UnitTestFrameworkPkg/Library/CmockaLib/cmocka";
      src = fetchurl {
        urls = [
          "https://github.com/tianocore/edk2-cmocka/archive/1cc9cde3448cdd2e000886a26acf1caac2db7cf1.tar.gz"
        ];
        hash = "sha256-Wc1LgauvrjXZSsXZHPSuWwUSLmiHE81ttR5eTO9HHY8=";
      };
    }
    {
      path = "UnitTestFrameworkPkg/Library/GoogleTestLib/googletest";
      src = fetchurl {
        urls = [
          "https://github.com/google/googletest/archive/86add13493e5c881d7e4ba77fb91c1f57752b3a4.tar.gz"
        ];
        hash = "sha256-PDCVSIuTaxRTjcpk1+aLzeCaihjSoypHtZh37/A0BAM=";
      };
    }
    {
      path = "UnitTestFrameworkPkg/Library/SubhookLib/subhook";
      src = fetchurl {
        urls = [
          "https://github.com/tianocore/edk2-subhook/archive/83d4e1ebef3588fae48b69a7352cc21801cb70bc.tar.gz"
        ];
        hash = "sha256-9lsubdME4ZGF11FlK9XrxyqB1QO/VCA3rLNFDkOrwJU=";
      };
    }
  ];
  unpackSubmodules = builtins.concatStringsSep "\n" (
    builtins.map (
      source: ''
        rm -rf "${source.path}"
        mkdir -p "${source.path}"
        tar xf "${source.src}" --strip-components=1 -C "${source.path}"
      ''
    )
    submoduleSources
  );
in
  mkDerivation {
    pname = "edk2";
    inherit version src;

    buildDeps = [
      gnumake
      python3
      nasm
      acpica
      util-linux
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir edk2
          tar xf "$src" --strip-components=1 -C edk2
          cd edk2
          ${unpackSubmodules}
          chmod -R u+w .
        '';
      }
      {
        name = "basetools";
        script =
          if stdenv.isCross
          then ''
            # BaseTools execute on the Linux build host. Keep their compiler
            # and Python isolated from the Darwin SDK and target wrapper;
            # only the later firmware phase emits freestanding guest code.
            (
              unset AOS_HARDENING_ENABLE AOS_TARGET_ARCH AOS_TARGET_PLATFORM
              unset CPLUS_INCLUDE_PATH MACOSX_DEPLOYMENT_TARGET
              unset NIX_CFLAGS_COMPILE NIX_LDFLAGS SDKROOT
              export CC="$BUILD_CC"
              export CXX="$BUILD_CXX"
              export PYTHON_COMMAND=${buildPython}/bin/python3

              # GCC 14 -Werror trips on EDK2's pre-C99 `Strings[1]`
              # flexible-array idiom and friends; upstream builds with older
              # toolchains. EXTRA_OPTFLAGS lands after the makefiles' own
              # -W flags, so these suppressions win.
              make -C BaseTools/Source/C -j$NIX_BUILD_CORES \
                EXTRA_OPTFLAGS="-Wno-array-bounds -Wno-stringop-overflow -Wno-maybe-uninitialized -Wno-dangling-pointer"
            )
          ''
          else ''
            # header.makefile probes for python via /usr/bin/env unless
            # PYTHON_COMMAND is set; /usr/bin/env doesn't exist in the
            # sandbox.
            export PYTHON_COMMAND=${python3}/bin/python3
            # GCC 14 -Werror trips on EDK2's pre-C99 `Strings[1]`
            # flexible-array idiom and friends; upstream builds with older
            # toolchains. EXTRA_OPTFLAGS lands after the makefiles' own
            # -W flags, so these suppressions win.
            make -C BaseTools/Source/C -j$NIX_BUILD_CORES \
              EXTRA_OPTFLAGS="-Wno-array-bounds -Wno-stringop-overflow -Wno-maybe-uninitialized -Wno-dangling-pointer"
          '';
      }
      {
        name = "build";
        script = ''
          export WORKSPACE=$PWD
          export EDK_TOOLS_PATH=$PWD/BaseTools
          export CONF_PATH=$PWD/Conf
          export PYTHON_COMMAND=${buildPython}/bin/python3
          export PYTHONPATH=$PWD/BaseTools/Source/Python

          mkdir -p Conf
          cp BaseTools/Conf/tools_def.template Conf/tools_def.txt
          cp BaseTools/Conf/build_rule.template Conf/build_rule.txt
          cp BaseTools/Conf/target.template Conf/target.txt

          # GCC 14 promotes maybe-uninitialized to an error under the
          # firmware's -Wall -Werror; upstream gates on older GCC.
          # tools_def.template ships CRLF line endings — normalize first
          # or the append lands before the \r and the tools_def parser
          # skips the whole assignment.
          sed -i 's/\r$//' Conf/tools_def.txt
          ${
            if buildAarch64Firmware
            then ''
              sed -i 's/^\(RELEASE_GCC5_AARCH64_CC_FLAGS *=.*\)$/\1 -Wno-maybe-uninitialized/' \
                Conf/tools_def.txt
            ''
            else ''
              sed -i 's/^\(RELEASE_GCC_X64_CC_FLAGS *=.*\)$/\1 -Wno-maybe-uninitialized/' \
                Conf/tools_def.txt
            ''
          }

          # The generated module makefiles invoke BaseTools by bare name
          # (Trim, GenFw, GenFv, ...) — normally edksetup.sh puts the
          # python BinWrappers and the C bin dir on PATH. The wrappers'
          # `/usr/bin/env bash` shebangs don't resolve in the sandbox.
          sed -i "1s|^#!.*|#!$(command -v bash)|" BaseTools/BinWrappers/PosixLike/*
          export python_exe=${buildPython}/bin/python3
          export PATH="$PWD/BaseTools/BinWrappers/PosixLike:$PWD/BaseTools/Source/C/bin:$PATH"

          # Synthesized firmware toolchain dir: raw bootstrap gcc (no
          # ccWrapper flag injection) plus binutils from the bootstrap
          # PATH. tools_def resolves every tool as <prefix><name>.
          ${
            if buildAarch64Firmware
            then ''
              ORIG_CC=${gccUnwrapped}
            ''
            else if stdenv.isCross
            then "ORIG_CC=${buildPackages.gccUnwrapped}"
            else "ORIG_CC=$(cat ${bootstrapTools}/nix-support/orig-cc)"
          }
          mkdir -p "$PWD/fw-toolchain"
          for t in "$ORIG_CC"/bin/*; do
            ln -sf "$t" "$PWD/fw-toolchain/$(basename "$t")"
          done
          for t in ar ld nm objcopy objdump ranlib readelf size strip addr2line; do
            if [ ! -e "$PWD/fw-toolchain/$t" ]; then
              src=$(command -v "$t" || true)
              [ -n "$src" ] && ln -sf "$src" "$PWD/fw-toolchain/$t"
            fi
          done
          ${
            if buildAarch64Firmware
            then ''
              # The cross GCC output carries the prefixed compiler drivers,
              # while the matching target binutils are a separate stdenv
              # output. EDK2 expects both sets under one GCC5 prefix.
              for t in ${stdenv.binutils}/bin/*; do
                ln -sf "$t" "$PWD/fw-toolchain/$(basename "$t")"
              done
              export GCC5_AARCH64_PREFIX="$PWD/fw-toolchain/${stdenv.hostPlatform.config}-"
            ''
            else ""
          }
          export GCC_BIN="$PWD/fw-toolchain/"
          export GCC5_BIN="$PWD/fw-toolchain/"
          export NASM_PREFIX="${buildNasm}/bin/"
          export IASL_PREFIX="${buildAcpica}/bin/"

          # The wrapper env vars target the hosted ccWrapper; the
          # freestanding firmware build must not inherit them.
          unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH

          # SECURE_BOOT_ENABLE compiles in the authenticated-variable +
          # Secure Boot drivers (SecureBootConfigDxe, AuthVariableLib).
          # SMM_REQUIRE is NOT optional for working SB: OVMF's
          # authenticated variable store lives in SMM, and without it the
          # SecureBoot/SetupMode variables are never exposed and bootctl
          # reports "unsupported". An SMM build REQUIRES QEMU to run with
          # `-machine q35,smm=on` + a secure pflash (see the driver). A
          # SB+SMM OVMF still boots anything while in Setup Mode (no PK
          # enrolled), so the non-SB image tests are unaffected;
          # enforcement begins only once PK/KEK/db are enrolled.
          # TPM2_ENABLE compiles in the TCG2 measured-boot stack so OVMF
          # measures the boot (incl. PCR 7 = Secure Boot state) into an
          # attached vTPM, and exposes the EFI TCG2 protocol that sd-stub
          # uses to extend the UKI sections into PCR 11. Without it the
          # firmware does no measurement and TPM-sealed /var (RFC-0006
          # phase 3) cannot bind to PCR 7/11. Harmless when no TPM is
          # attached (the measurement calls just no-op).
          ${
            if buildAarch64Firmware
            then ''
              $PYTHON_COMMAND BaseTools/Source/Python/build/build.py \
                -a AARCH64 \
                -t GCC5 \
                -b RELEASE \
                -p ArmVirtPkg/ArmVirtQemu.dsc \
                -D SECURE_BOOT_ENABLE=TRUE \
                -D TPM2_ENABLE=TRUE \
                -D TPM2_CONFIG_ENABLE=TRUE \
                -D QEMU_PV_VARS=TRUE \
                -n $NIX_BUILD_CORES
            ''
            else ''
              $PYTHON_COMMAND BaseTools/Source/Python/build/build.py \
                -a X64 \
                -t GCC \
                -b RELEASE \
                -p OvmfPkg/OvmfPkgX64.dsc \
                -D SECURE_BOOT_ENABLE=TRUE \
                -D SMM_REQUIRE=TRUE \
                -D TPM2_ENABLE=TRUE \
                -D TPM2_CONFIG_ENABLE=TRUE \
                -n $NIX_BUILD_CORES
            ''
          }
        '';
      }
      {
        name = "install";
        script =
          if buildAarch64Firmware
          then ''
            mkdir -p $out/FV
            cp Build/ArmVirtQemu-AArch64/RELEASE_GCC5/FV/QEMU_EFI.fd \
              $out/FV/AAVMF_CODE.fd
            truncate -s 64M $out/FV/AAVMF_CODE.fd
          ''
          else ''
            mkdir -p $out/FV
            cp Build/OvmfX64/RELEASE_GCC/FV/OVMF.fd $out/FV/
            cp Build/OvmfX64/RELEASE_GCC/FV/OVMF_CODE.fd $out/FV/
            cp Build/OvmfX64/RELEASE_GCC/FV/OVMF_VARS.fd $out/FV/
          '';
      }
    ];

    meta = {
      description = "edk2 — TianoCore UEFI firmware for QEMU";
      homepage = "https://github.com/tianocore/edk2";
      license = "BSD-2-Clause-Patent";
    };
  }
