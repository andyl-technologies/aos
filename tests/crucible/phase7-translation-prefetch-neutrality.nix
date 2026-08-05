{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  attrPath ? "checks.crucible.phase7.translationPrefetchNeutrality",
  taskIds ? ["T-PERF-32"],
  dependencies ? [],
}: let
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  patchName = "0046-crucible-translation-prefetch-helper.patch";
  priorPatchFiles = builtins.filter (patch: patch != patchName) series.patchFiles;
  priorPatchList = builtins.concatStringsSep " " priorPatchFiles;
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };
  idleInitramfs = import ./phase2-qemu-live-plugin-quantum-guest.nix {inherit pkgs;};
  taskList = builtins.concatStringsSep "," taskIds;
in
  pkgs.mkDerivation {
    pname = "crucible-phase7-translation-prefetch-neutrality";
    version = "0";
    src = crucibleSrc;

    buildDeps =
      [
        pkgs.coreutils
        pkgs.diffutils
        pkgs.grep
        pkgs.crucible-qemu-plugin
        qemuPackage
        pkgs.rust
        pkgs.sed
        pkgs.patch
        pkgs.tar
        pkgs.xz
      ]
      ++ dependencies;

    GUEST_KERNEL = builtins.toString pkgs.linux;
    GUEST_INITRD = "${idleInitramfs}/initrd.img";
    GUEST_FIRMWARE = "${qemuPackage}/share/qemu/bios-256k.bin";
    GUEST_KERNEL_APPEND = "console=ttyS0 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0 nohz=off";
    ATTR_PATH = attrPath;
    TASK_IDS = taskList;

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "configure";
        script = ''
          export CARGO_HOME="$TMPDIR/cargo"
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          mkdir -p "$CARGO_HOME" .cargo
          sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
              > .cargo/config.toml
        '';
      }
      {
        name = "run-translation-prefetch-neutrality";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          vmlinuz=$(ls "$GUEST_KERNEL"/boot/vmlinuz-* | head -1)
          test -n "$vmlinuz"

          microtest_dir="$TMPDIR/translation-prefetch-patch-microtest"
          mkdir -p "$microtest_dir"
          tar -xf ${qemuPackage.src} -C "$microtest_dir"
          qemu_source="$microtest_dir/qemu-${series.qemuVersion}"
          test ! -e "$qemu_source/accel/tcg/crucible-translation-prefetch.c"
          stock_negative_control=true
          for prior_patch in ${priorPatchList}; do
            patch --batch --fuzz=0 -p1 \
              -d "$qemu_source" \
              -i "${../../pkgs/emulation/qemu-patches}/$prior_patch"
          done
          patch --batch --fuzz=0 -p1 \
            -d "$qemu_source" \
            -i ${../../pkgs/emulation/qemu-patches/0046-crucible-translation-prefetch-helper.patch}
          grep -Fq 'crucible_translation_prefetch_generate' \
            "$qemu_source/accel/tcg/crucible-translation-prefetch.c"
          patched_fixture_exercised=true

          cargo build \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/translation-prefetch-example" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-plugin-fingerprint
          example="$TMPDIR/translation-prefetch-example/debug/examples/crucible-qemu-live-plugin-fingerprint"

          run_leg() {
            mode="$1"
            mode_value="$2"
            run_dir="$TMPDIR/translation-prefetch-$mode"
            report="$TMPDIR/translation-prefetch-$mode.result"
            mkdir -p "$run_dir"
            CRUCIBLE_FP_TRANSLATION_PREFETCH="$mode_value" \
              CRUCIBLE_FP_SECOND_RUN_LOAD=0 \
              CRUCIBLE_FP_TIMEOUT_SECS=240 \
              timeout -k 15 1190 \
              "$example" \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
              "$vmlinuz" \
              "$GUEST_FIRMWARE" \
              "$run_dir" \
              "$GUEST_INITRD" \
              "$GUEST_KERNEL_APPEND" \
              > "$report"

            cat "$report"
            grep -Fxq PASS "$report"
            grep -Fxq "translation_prefetch_experiment=$mode" "$report"
            grep -Eq '^canonical_boundary_log_digest=[0-9a-f]{64}$' "$report"
            grep -Fxq 'deterministic_run_twice=true' "$report"
            grep -Fxq 'aggregate_icount_equals_target=true' "$report"

            for role in run-reference run-repeat; do
              helper_report="$run_dir/$role/translation-prefetch.report"
              test -f "$helper_report"
              grep -Fxq "enabled=$([ "$mode" = on ] && printf true || printf false)" "$helper_report"
              grep -Fxq 'mode=dedicated-demand-tcg-helper' "$helper_report"
              if [ "$mode" = on ]; then
                grep -Fxq 'helper_thread_started=true' "$helper_report"
                requests=$(sed -n 's/^requests=//p' "$helper_report")
                completions=$(sed -n 's/^completions=//p' "$helper_report")
                test -n "$requests"
                test "$requests" -gt 100
                test "$completions" = "$requests"
              else
                grep -Fxq 'helper_thread_started=false' "$helper_report"
                grep -Fxq 'requests=0' "$helper_report"
                grep -Fxq 'completions=0' "$helper_report"
              fi
            done
          }

          run_leg off 0
          run_leg on 1

          sed '/^translation_prefetch_experiment=/d' \
            "$TMPDIR/translation-prefetch-off.result" \
            > "$TMPDIR/translation-prefetch-off.canonical"
          sed '/^translation_prefetch_experiment=/d' \
            "$TMPDIR/translation-prefetch-on.result" \
            > "$TMPDIR/translation-prefetch-on.canonical"
          cmp "$TMPDIR/translation-prefetch-off.canonical" \
            "$TMPDIR/translation-prefetch-on.canonical"

          on_report="$TMPDIR/translation-prefetch-on/run-repeat/translation-prefetch.report"
          requests=$(sed -n 's/^requests=//p' "$on_report")
          completions=$(sed -n 's/^completions=//p' "$on_report")
          log_digest=$(sed -n 's/^canonical_boundary_log_digest=//p' \
            "$TMPDIR/translation-prefetch-on.result")

          mkdir -p "$out"
          cp "$TMPDIR/translation-prefetch-off.result" "$out/off-result"
          cp "$TMPDIR/translation-prefetch-on.result" "$out/on-result"
          cp "$on_report" "$out/helper-report"
          cat > "$out/result" <<RESULT
          PASS
          check=$ATTR_PATH
          gate=gate:translation-prefetch-neutrality
          tasks=$TASK_IDS
          status=complete
          patch_microtest_gate=gate:patch-microtests
          patch=0046-crucible-translation-prefetch-helper.patch
          patched_fixture_exercised=$patched_fixture_exercised
          stock_negative_control=$stock_negative_control
          qemu_package=${qemuPackage}
          qemu_package_version=${qemuPackage.version}
          admission_class=A
          default=off
          corpus=translation-heavy-linux-cold-boot
          mechanism=dedicated-demand-tcg-helper
          helper_thread_started=true
          translation_requests=$requests
          translation_completions=$completions
          fingerprints_bit_identical=true
          canonical_logs_bit_identical=true
          canonical_boundary_log_digest=$log_digest
          divergence_policy=blocking-exact-comparison
          RESULT
        '';
      }
    ];
  }
