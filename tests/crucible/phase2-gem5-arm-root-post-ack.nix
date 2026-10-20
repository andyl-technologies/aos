# Requires actual new ARM native output after source-gone twin restoration and ACK.
{
  pkgs,
  lib,
}: let
  source = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  profile = pkgs.gem5-arm-root-model-profile;
  reference = pkgs.crucible-reference-implementation.passthru.binaries;
  selected = "node_observed_executor::factory::arm_root::cold_tests::post_ack::actual_ordinary_root_twins_produce_next_native_byte_after_source_gone_and_ack";
in
  pkgs.mkDerivation {
    pname = "crucible-gem5-arm-root-post-ack-check";
    version = "0";
    src = source;
    LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
    OPENSSL_DIR = "${pkgs.openssl}";
    OPENSSL_NO_VENDOR = "1";
    OPENSSL_STATIC = "0";
    PROTOC = "${pkgs.protobuf}/bin/protoc";
    # This compile-time policy still requires actual native qualification.
    CRUCIBLE_GEM5_ARM_ROOT_MODEL_MANIFEST = "${profile}/share/crucible/gem5/arm-model-profile.json";
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
      profile
      reference
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
        name = "build-and-run-arm-root-post-ack";
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
            -p crucible-daemon --lib > "$TMPDIR/messages.jsonl"
          binary=$(jq -r \
            'select(.reason == "compiler-artifact" and .target.name == "crucible_daemon" and .profile.test == true and .executable != null) | .executable' \
            "$TMPDIR/messages.jsonl")
          test -f "$binary"
          export CRUCIBLE_REFERENCE_DEVICE="${reference}/bin/crucible-reference-device"
          test -x "$CRUCIBLE_REFERENCE_DEVICE"
          "$binary" --list --ignored > "$TMPDIR/native-tests.txt"
          test "$(grep -Fxc '${selected}: test' "$TMPDIR/native-tests.txt")" -eq 1
          mkdir -p "$out/evidence"
          cp "$TMPDIR/native-tests.txt" "$out/evidence/native-tests.txt"
          sha256sum "$binary" > "$out/evidence/host-test-elf.sha256"
          status=0
          timeout --signal=TERM --kill-after=30s 15m \
            "$binary" --ignored --exact '${selected}' --nocapture \
            > "$out/evidence/arm-root-post-ack.log" 2>&1 || status=$?
          cat "$out/evidence/arm-root-post-ack.log"
          test "$status" -eq 0
          grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' \
            "$out/evidence/arm-root-post-ack.log"
          grep -Fxq \
            'arm_root_post_ack=source-gone,twin-fresh-native-byte,foreign-custody-refused,common-ack,children-reclaimed' \
            "$out/evidence/arm-root-post-ack.log"
          sha256sum "$CRUCIBLE_GEM5_ARM_ROOT_MODEL_MANIFEST" "$CRUCIBLE_REFERENCE_DEVICE" \
            > "$out/evidence/installed-artifacts.sha256"
          {
            echo PASS
            echo check=gem5-arm-root-post-ack-direct-expression
            echo native_tests=1
            echo scope=fixed-aarch64-full-system-source-gone-post-ack-pl011-continuation
            echo device_slice=pl011-held-byte-one-ack-and-new-native-byte-two
            echo foreign_custody=receipt-and-ack-refused
            echo source_retirement=before-both-fresh-constructions
            echo userspace_boot=unqualified
            echo capture_restore=held-cut-snapshot-and-source-gone-twin-continuation
            echo general_full_system=unqualified
            echo general_device_parity=unqualified
          } > "$out/result"
        '';
      }
    ];

    meta.description = "Checks actual ARM post-ACK native PL011 continuation in source-gone fresh twins";
  }
