{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase9.gates.campaignMetadataMillion",
}: let
  source = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase9-campaign-metadata-million";
    version = "0";
    LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
    src = source;

    buildDeps = [
      pkgs.coreutils
      pkgs.grep
      pkgs.openssl
      pkgs.pkg-config
      pkgs.protobuf
      pkgs.rust
      pkgs.sed
      pkgs.crucible

      pkgs.sqlite
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
        name = "configure";
        script = ''
          export CARGO_HOME="$TMPDIR/cargo"
          mkdir -p "$CARGO_HOME" .cargo
          sed "s|@vendor@|${cargoDeps}|g" \
            "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml
        '';
      }
      {
        name = "run-million-admission-gate";
        script = ''
          set -eu
          target="$TMPDIR/campaign-performance-target"
          test_name=gate_campaign_metadata_million
          cargo test --frozen --offline --release \
            --manifest-path crates/Cargo.toml --target-dir "$target" \
            -p crucible-daemon --test "$test_name" --no-run

          mkdir -p "$out/evidence"
          cargo test --frozen --offline --release \
            --manifest-path crates/Cargo.toml --target-dir "$target" \
            -p crucible-daemon --test "$test_name" \
            million_admission_ancestry_capacity_probe -- \
            --exact --nocapture --test-threads=1 \
            > "$out/evidence/capacity-probe.log" 2>&1
          capacity=$(grep '^campaign_million_capacity required=[0-9]* limit=[0-9]*$' \
            "$out/evidence/capacity-probe.log")
          test "$(printf '%s\n' "$capacity" | grep -c '^campaign_million_capacity ')" -eq 1
          required=$(printf '%s\n' "$capacity" | sed -n 's/^.*required=\([0-9]*\) limit=.*$/\1/p')
          limit=$(printf '%s\n' "$capacity" | sed -n 's/^.*limit=\([0-9]*\)$/\1/p')
          test "$required" -eq 187503
          if [ "$limit" -lt "$required" ]; then
            cat > "$out/result" <<RESULT
          BLOCKED
          gate=gate:campaign-metadata-million
          check=${attrPath}
          reason=authenticated-ancestry-limit
          required_ancestry=$required
          available_ancestry=$limit
          admissions_required=1000000
          RESULT
            exit 0
          fi

          mkdir -m 700 "$TMPDIR/campaign-million-store"
          cp ${pkgs.crucible}/bin/crucible "$TMPDIR/campaign-million-planner"
          chmod 0500 "$TMPDIR/campaign-million-planner"
          export CRUCIBLE_CAMPAIGN_MILLION_STORAGE_ROOT="$TMPDIR/campaign-million-store"
          export CRUCIBLE_CAMPAIGN_MILLION_PLANNER_EXECUTABLE="$TMPDIR/campaign-million-planner"
          if ! timeout -k 60 604800 cargo test --frozen --offline --release \
            --manifest-path crates/Cargo.toml --target-dir "$target" \
            -p crucible-daemon --test "$test_name" \
            million_real_admissions_fit_compact_metadata_budget -- \
            --ignored --exact --nocapture --test-threads=1 \
            > "$out/evidence/million-admissions.log" 2>&1; then
            cat "$out/evidence/million-admissions.log" >&2
            exit 1
          fi
          grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' \
            "$out/evidence/million-admissions.log"
          profile=$(grep '^campaign_million_profile admissions=1000000 requests=62500 request_size=16 ' \
            "$out/evidence/million-admissions.log")
          test "$(printf '%s\n' "$profile" | grep -c '^campaign_million_profile ')" -eq 1
          printf '%s\n' "$profile" > "$out/evidence/profile.env"
          profile_sha=$(sha256sum "$out/evidence/profile.env" | cut -d ' ' -f 1)
          raw_sha=$(sha256sum "$out/evidence/million-admissions.log" | cut -d ' ' -f 1)
          cat > "$out/result" <<RESULT
          PASS
          gate=gate:campaign-metadata-million
          check=${attrPath}
          task=T-CAM-9.2
          admissions=1000000
          requests=62500
          request_size=16
          storage_backend=sqlite
          planner_supervisor=packaged-process
          hot_and_cold_paged_queue=true
          fixed_object_index_physical_rss_ratchets=true
          profile_sha256=$profile_sha
          raw_sha256=$raw_sha
          RESULT
        '';
      }
    ];
  }
