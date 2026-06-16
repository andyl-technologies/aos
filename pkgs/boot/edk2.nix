##! edk2 — TianoCore EDK2 UEFI firmware: OVMF for QEMU (x86_64)
##!
##! Builds OvmfPkgX64 from source, producing the split-flash pair the
##! test harness (and any QEMU UEFI boot) consumes:
##!
##!   $out/FV/OVMF_CODE.fd  — read-only firmware code flash
##!   $out/FV/OVMF_VARS.fd  — writable NVRAM variable store template
##!   $out/FV/OVMF.fd       — combined image (single-pflash use)
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
##! Source comes from builtins.fetchGit with submodules=true (pinned
##! rev, pure): OVMF compiles vendored submodule sources directly
##! (openssl for BaseCryptLib, brotli for BaseTools' compressor, ...),
##! so a release tarball — which omits submodules — is not sufficient,
##! and pinning each submodule separately duplicates what the rev pin
##! already guarantees. Precedent: fetchCargoDeps' gitDeps.
{
  mkDerivation,
  bootstrapTools,
  gnumake,
  python3,
  nasm,
  acpica,
  util-linux,
}: let
  version = "edk2-stable202602";
  src = builtins.fetchGit {
    url = "https://github.com/tianocore/edk2.git";
    ref = "refs/tags/${version}";
    rev = "b7a715f7c03c45c6b4575bf88596bfd79658b8ce";
    submodules = true;
    shallow = true;
  };
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
          cp -r $src edk2
          chmod -R u+w edk2
          cd edk2
        '';
      }
      {
        name = "basetools";
        script = ''
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
          export PYTHON_COMMAND=${python3}/bin/python3
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
          sed -i 's/^\(RELEASE_GCC_X64_CC_FLAGS *=.*\)$/\1 -Wno-maybe-uninitialized/' \
            Conf/tools_def.txt

          # The generated module makefiles invoke BaseTools by bare name
          # (Trim, GenFw, GenFv, ...) — normally edksetup.sh puts the
          # python BinWrappers and the C bin dir on PATH. The wrappers'
          # `/usr/bin/env bash` shebangs don't resolve in the sandbox.
          sed -i "1s|^#!.*|#!$(command -v bash)|" BaseTools/BinWrappers/PosixLike/*
          export python_exe=${python3}/bin/python3
          export PATH="$PWD/BaseTools/BinWrappers/PosixLike:$PWD/BaseTools/Source/C/bin:$PATH"

          # Synthesized firmware toolchain dir: raw bootstrap gcc (no
          # ccWrapper flag injection) plus binutils from the bootstrap
          # PATH. tools_def resolves every tool as <prefix><name>.
          ORIG_CC=$(cat ${bootstrapTools}/nix-support/orig-cc)
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
          export GCC_BIN="$PWD/fw-toolchain/"
          export GCC5_BIN="$PWD/fw-toolchain/"
          export NASM_PREFIX="${nasm}/bin/"
          export IASL_PREFIX="${acpica}/bin/"

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
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/FV
          cp Build/OvmfX64/RELEASE_GCC/FV/OVMF.fd $out/FV/
          cp Build/OvmfX64/RELEASE_GCC/FV/OVMF_CODE.fd $out/FV/
          cp Build/OvmfX64/RELEASE_GCC/FV/OVMF_VARS.fd $out/FV/
        '';
      }
    ];

    meta = {
      description = "edk2 — TianoCore UEFI firmware (OVMF for QEMU x86_64)";
      homepage = "https://github.com/tianocore/edk2";
      license = "BSD-2-Clause-Patent";
    };
  }
