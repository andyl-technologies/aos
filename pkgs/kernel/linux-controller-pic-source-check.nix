##! Compile original PIC/FD custody source controls and configured native objects.
{
  lib,
  mkDerivation,
  linux,
  linuxSource,
  linuxStage7Check,
  stdenv,
  buildPackages,
  gnumake,
  bash,
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
  psFixtures = ./_crucible-q35-ps-source;
  psPatches = import (psFixtures + "/patches.nix");
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
    buildDeps = [linuxStage7Check gnumake bash coreutils patch perl python3 bc bison flex elfutils openssl zlib gcc-libs rsync];
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
          ${python3}/bin/python3 ${fixtures}/generate-eoi-models.py "$PWD" "$CC" "$PWD/eoi-controls"
          ${python3}/bin/python3 ${fixtures}/apply-deferred-source.py "$PWD" ${patch}/bin/patch
          ${python3}/bin/python3 ${fixtures}/source-guards.py "$PWD" deferred

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
          ${python3}/bin/python3 ${fixtures}/check-eoi-models.py "$PWD/eoi-controls" "$PWD"
          ${python3}/bin/python3 ${fixtures}/generate-queue-models.py "$PWD" "$CC" "$PWD/queue-controls"
          ${python3}/bin/python3 ${fixtures}/check-queue-models.py "$PWD/queue-controls" "$PWD"
          ${python3}/bin/python3 ${fixtures}/resources.py check "$PWD"
          mkdir -p $out
          cp "$PWD/pic-controls/report.json" $out/source-model-report.json
          cp "$PWD/eoi-controls/report.json" $out/original-eoi-model-report.json
          cp "$PWD/queue-controls/report.json" $out/deferred-pit-model-report.json
          cat > $out/report <<'REPORT'
          eight x86 native source objects: compiled
          one positive and eleven intended adverse source controls: passed
          copied PIC MIT notice and GPL-compatible scope: retained
          one positive and sixteen intended original EOI adverse source controls: passed
          original EOI source lease and row reconciliation: checked
          one positive and nine intended deferred PIT publication controls: passed
          full kernel linking, physical guest delivery and PIC producer board: unqualified
          ordinary dual-route/coalescing and FirstBegin IRQchip admission: unsupported
          guest delivery, native hardware, Ready and capture: not qualified
          REPORT
        '';
      }
      {
        name = "check-fdtable";
        script = ''
          # The preceding PIC checkpoint and every legacy control remain intact.
          # This independent raw tree consumes the complete PS source ancestry.
          cd ..
          ${python3}/bin/python3 -I -B ${psFixtures}/check-disk.py "$PWD"
          mkdir fdtable-kernel
          tar xf ${linuxSource.src} --strip-components=1 -C fdtable-kernel
          cd fdtable-kernel
          for sourceFile in $(find . -type f -name '*.py'); do
            case "$(head -n 1 "$sourceFile")" in
              '#!'*python*) sed -i "1s|.*|#!${buildPackages.python3}/bin/python3|" "$sourceFile" ;;
            esac
          done
          ${coreutils}/bin/timeout 180 ${python3}/bin/python3 -I -B \
            ${psFixtures}/apply-kernel-source.py "$PWD" ${patch}/bin/patch \
            ${lib.concatMapStringsSep " " (sourcePatch: lib.escapeShellArg "${sourcePatch}") psPatches}
          export LD_LIBRARY_PATH="${buildPackages.gcc-libs}/lib:${hostLibrary}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

          # Reuse the existing aggregate budget and ordinary resolved config.
          # Fresh prepare regenerates offsets for this actual patched Task layout.
          ${python3}/bin/python3 -B ${fixtures}/resources.py initialize "$PWD"
          cp ${linux.dev}/lib/modules/${linuxSource.version}/build/.config .config
          native_make() {
            ${coreutils}/bin/timeout 300 ${gnumake}/bin/make -j1 ARCH=x86_64 \
              SHELL="${bash}/bin/bash" CONFIG_SHELL="${bash}/bin/bash" \
              CC="$CC" LD="$LD" AR="$AR" NM="$NM" STRIP="$STRIP" \
              OBJCOPY="${stdenv.binutils}/bin/objcopy" \
              OBJDUMP="${stdenv.binutils}/bin/objdump" \
              READELF="${stdenv.binutils}/bin/readelf" \
              HOSTCC="${hostCompiler}" \
              HOSTCXX="env C_INCLUDE_PATH=${hostInclude} LIBRARY_PATH=${hostLibrary} ${buildPackages.cc}/bin/c++" \
              HOSTLD="${buildPackages.binutils}/bin/ld" \
              HOSTAR="${buildPackages.binutils}/bin/ar" \
              HOSTPKG_CONFIG="${buildPackages.pkg-config}/bin/pkg-config" "$@"
          }
          native_make olddefconfig
          native_make prepare
          native_make modules_prepare
          grep -qx 'CONFIG_WERROR=y' .config
          ${python3}/bin/python3 -B ${fixtures}/resources.py check "$PWD"

          # The existing proposal/check executor owns all compiler/model results.
          # The ordinary FD binary runs on the build-host kernel, not this image.
          ${python3}/bin/python3 -B ${fixtures}/generate-models.py \
            "$PWD" "$CC" "$PWD/fdtable-controls" fdtable
          ${python3}/bin/python3 -B ${fixtures}/check-models.py \
            "$PWD/fdtable-controls" "$PWD" fdtable

          for nativeObject in fs/file.o mm/crucible_allocator.o mm/slub.o virt/kvm/kvm_main.o; do
            ${python3}/bin/python3 -B ${fixtures}/resources.py check "$PWD"
            native_make "$nativeObject"
            ${python3}/bin/python3 -B ${fixtures}/check-native-inputs.py \
              "$PWD" "$nativeObject" fdtable
          done
          ${python3}/bin/python3 -B ${fixtures}/resources.py check "$PWD"
          mkdir -p "$out/fdtable-native-inputs"
          cp fdtable-*.inputs.json "$out/fdtable-native-inputs/"
          cp fdtable-controls/source-bindings.json "$out/fdtable-source-bindings.json"
          cp fdtable-controls/report.json "$out/fdtable-source-model-report.json"
          cat > "$out/fdtable-report" <<'REPORT'
          source-consuming FD controls: 21 cases completed with modeled kernel peers
          ordinary FD controls: build-host growth, exhaustion, concurrency and exec passed
          four configured native source objects: compiled with exact source/dependency records
          legacy PIC/EOI/queue and Stage7 controls: retained as required predecessors
          full image/module link and matching source companion: separate kernel build required
          actual patched-kernel runtime, physical accounting and state preservation: unqualified
          constructor coverage 0x001/required0x7ff; FD_TABLE/CREATE/RUN/Ready remain unsupported
          REPORT
        '';
      }
    ];
  }
