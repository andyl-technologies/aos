# Checks actual source-owned quiet completion separately from budget exhaustion.
{
  pkgs,
  lib,
}: let
  source = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-native-prefix-completion-check";
    version = "0";
    src = source;
    LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
    buildDeps = [
      pkgs.coreutils
      pkgs.grep
      pkgs.jq
      pkgs.openssl
      pkgs.pkg-config
      pkgs.protobuf
      pkgs.rust
      pkgs.sed
      pkgs.sqlite
      pkgs.qemu-crucible
      pkgs.crucible-qemu-plugin
    ];
    runtimeDeps = [pkgs.openssl pkgs.sqlite];
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
        name = "build-and-run-native-regression";
        script = ''
          set -eu
          export CARGO_HOME="$TMPDIR/cargo"
          mkdir -p "$CARGO_HOME" .cargo
          sed "s|@vendor@|${cargoDeps}|g" \
            "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml
          cargo test --frozen --offline --release --no-run \
            -j"$NIX_BUILD_CORES" \
            --message-format=json-render-diagnostics \
            --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/target" \
            -p crucible-qemu-host --test native_owned_prefix > "$TMPDIR/messages.jsonl"
          binary=$(jq -r \
            'select(.reason == "compiler-artifact" and .target.name == "native_owned_prefix" and .profile.test == true and .executable != null) | .executable' \
            "$TMPDIR/messages.jsonl")
          test -f "$binary"
          export CRUCIBLE_NATIVE_PROBE_QEMU="${pkgs.qemu-crucible}/bin/qemu-system-x86_64"
          export CRUCIBLE_NATIVE_PROBE_PLUGIN="${pkgs.crucible-qemu-plugin}/lib/qemu/plugins/crucible-qemu-plugin.so"
          test -x "$CRUCIBLE_NATIVE_PROBE_QEMU"
          test -f "$CRUCIBLE_NATIVE_PROBE_PLUGIN"
          "$binary" --list --ignored > "$TMPDIR/native-tests.txt"
          mkdir -p "$out/evidence"
          cp "$TMPDIR/native-tests.txt" "$out/evidence/native-tests.txt"
          sha256sum "$binary" > "$out/evidence/host-test-elf.sha256"
          for selected in \
            actual_native_session_consumes_original_initial_custody_into_quiet_operation \
            actual_native_session_completes_quiet_interval_at_exclusive_limit; do
            test "$(grep -Fxc "$selected: test" "$TMPDIR/native-tests.txt")" -eq 1
            timeout --signal=TERM --kill-after=30s 15m \
              "$binary" --ignored --exact "$selected" --nocapture \
              > "$out/evidence/$selected.log" 2>&1
            grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$out/evidence/$selected.log"
          done
          grep -Fxq 'native_prefix_control=limit350,raw4,evaluated100,partial,acknowledged,reaped' \
            "$out/evidence/actual_native_session_consumes_original_initial_custody_into_quiet_operation.log"
          grep -Fxq 'native_prefix_completion=exclusive151,raw3,evaluated100,completed,acknowledged,reaped' \
            "$out/evidence/actual_native_session_completes_quiet_interval_at_exclusive_limit.log"
          sha256sum "$CRUCIBLE_NATIVE_PROBE_QEMU" "$CRUCIBLE_NATIVE_PROBE_PLUGIN" \
            > "$out/evidence/native-artifacts.sha256"
          {
            echo PASS
            echo check=checks.crucible.phase2.nativePrefixCompletion
            echo native_tests=2
            echo scope=source-prefix-completion-and-partial-control
            echo common_ready=unqualified
            echo native_capture=unqualified
          } > "$out/result"
        '';
      }
    ];
  }
