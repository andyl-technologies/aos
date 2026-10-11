##! Compile the bounded original PIC receiver source and adverse controls.
{
  lib,
  mkDerivation,
  linux,
  linuxSource,
  linuxStage7Check,
  stdenv,
  buildPackages,
  gnumake,
  coreutils,
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
  fixtures = ./_crucible-pic-source;
  originalPatches = [
    ./crucible-controller-clock-7.2.3.patch
    ./crucible-controller-clock-stage2-7.2.3.patch
    ./crucible-controller-clock-stage3-7.2.3.patch
    ./crucible-controller-clock-stage4-7.2.3.patch
    ./crucible-controller-completion-stage5-7.2.3.patch
    ./crucible-controller-run-return-stage6-7.2.3.patch
    ./crucible-controller-response-bytes-stage7-7.2.3.patch
  ];
  hostInclude = "${buildPackages.elfutils}/include:${buildPackages.openssl}/include:${buildPackages.zlib}/include";
  hostLibrary = "${buildPackages.elfutils}/lib:${buildPackages.openssl}/lib:${buildPackages.zlib}/lib";
  hostCompiler = "env C_INCLUDE_PATH=${hostInclude} LIBRARY_PATH=${hostLibrary} ${buildPackages.cc}/bin/cc";
in
  mkDerivation {
    pname = "linux-controller-pic-source-check";
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
    # The existing two-ISA Stage7 check remains a required independent input.
    # This additional package emits a check report, never an installed kernel.
    buildDeps = [linuxStage7Check gnumake coreutils patch perl python3 bc bison flex elfutils openssl zlib gcc-libs rsync];
    runtimeDeps = [];
    hardeningDisable = ["all"];
    phases = [
      {
        name = "check";
        script = ''
          # Keep source/configuration and source-built host helpers, without
          # staging the ordinary kernel's unrelated compiled object archives.
          rsync -a --exclude='*.o' --exclude='*.a' \
            ${linux.dev}/lib/modules/${linuxSource.version}/build/ kernel/
          chmod -R u+w kernel
          cd kernel
          for sourcePatch in ${lib.concatMapStringsSep " " (sourcePatch: lib.escapeShellArg "${sourcePatch}") originalPatches}; do
            patch --batch --fuzz=0 -p1 < "$sourcePatch" > original-apply.log 2>&1
            cat original-apply.log
            if ${python3}/bin/python3 ${fixtures}/reject-offset.py original-apply.log; then
              :
            else
              exit 1
            fi
          done
          ${python3}/bin/python3 ${fixtures}/apply-source.py "$PWD" ${patch}/bin/patch
          export LD_LIBRARY_PATH="${buildPackages.gcc-libs}/lib:${hostLibrary}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

          # All generated compiler/model files share one finite reservation.
          ${python3}/bin/python3 ${fixtures}/resources.py initialize "$PWD"
          # Preserve the preceding receiver controls at their exact source
          # checkpoint before composing the later original EOI mechanism.
          ${python3}/bin/python3 ${fixtures}/source-guards.py "$PWD" completed
          ${python3}/bin/python3 ${fixtures}/generate-models.py "$PWD" "$CC" "$PWD/pic-controls"
          ${python3}/bin/python3 ${fixtures}/apply-eoi-source.py "$PWD" ${patch}/bin/patch
          ${python3}/bin/python3 ${fixtures}/source-guards.py "$PWD" eoi

          compile_native_unit() {
            nativeObject="$1"
            nativeLog="pic-$(basename "$nativeObject").log"
            ${python3}/bin/python3 ${fixtures}/resources.py check "$PWD"
            if ${coreutils}/bin/timeout 300 ${gnumake}/bin/make -j1 ARCH=x86_64 \
              CC="$CC" LD="$LD" AR="$AR" NM="$NM" \
              OBJCOPY="${stdenv.binutils}/bin/objcopy" \
              HOSTCC="${hostCompiler}" \
              HOSTCXX="env C_INCLUDE_PATH=${hostInclude} LIBRARY_PATH=${hostLibrary} ${buildPackages.cc}/bin/c++" \
              HOSTLD="${buildPackages.binutils}/bin/ld" \
              HOSTAR="${buildPackages.binutils}/bin/ar" \
              HOSTPKG_CONFIG="${buildPackages.pkg-config}/bin/pkg-config" \
              "$nativeObject" > "$nativeLog" 2>&1; then
              cat "$nativeLog"
            else
              cat "$nativeLog"
              exit 1
            fi
            ${python3}/bin/python3 ${fixtures}/check-native-inputs.py "$PWD" "$nativeObject"
            ${python3}/bin/python3 ${fixtures}/resources.py check "$PWD"
          }

          # Object compilation uses the original AOS CONFIG_WERROR configuration.
          # It does not establish that these source inputs form a linked kernel.
          for nativeUnit in i8254 ioapic lapic irq x86 crucible-clock i8259; do
            compile_native_unit "arch/x86/kvm/$nativeUnit.o"
          done
          compile_native_unit virt/kvm/irqchip.o

          ${python3}/bin/python3 ${fixtures}/check-models.py "$PWD/pic-controls" "$PWD"
          ${python3}/bin/python3 ${fixtures}/generate-eoi-models.py "$PWD" "$CC" "$PWD/eoi-controls"
          ${python3}/bin/python3 ${fixtures}/check-eoi-models.py "$PWD/eoi-controls" "$PWD"
          ${python3}/bin/python3 ${fixtures}/resources.py check "$PWD"
          mkdir -p $out
          cp "$PWD/pic-controls/report.json" $out/source-model-report.json
          cp "$PWD/eoi-controls/report.json" $out/original-eoi-model-report.json
          cat > $out/report <<'REPORT'
          eight x86 native source objects: compiled
          one positive and eleven intended adverse source controls: passed
          copied PIC MIT notice and GPL-compatible scope: retained
          one positive and sixteen intended original EOI adverse source controls: passed
          original EOI source lease and row reconciliation: checked
          full kernel linking, physical guest delivery and PIC producer board: unqualified
          ordinary dual-route/coalescing and FirstBegin IRQchip admission: unsupported
          guest delivery, native hardware, Ready and capture: not qualified
          REPORT
        '';
      }
    ];
  }
