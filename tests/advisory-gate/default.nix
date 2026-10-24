{pkgs}: let
  snapshot = builtins.fromJSON (builtins.readFile ../../security/advisories/snapshot.json);
  rustsecDatabase = pkgs.lib.fetchgit {
    url = "https://github.com/RustSec/advisory-db.git";
    rev = snapshot.rustsec_revision;
    hash = "sha256-lsBWFc/tcGSNzaHGn3FCtdlLbYFTmNWNYV0cQUFqOEw=";
    leaveDotGit = true;
    git = pkgs.git-minimal;
    caCertificates = pkgs.ca-certificates;
    coreutils = pkgs.coreutils;
  };
  cargoVendor = pkgs.aos.passthru.cargoDeps;
  accacheVendor = pkgs.accache.passthru.cargoDeps;
in
  pkgs.mkDerivation {
    pname = "aos-advisory-gate";
    version = "1";
    src = null;
    buildDeps = [pkgs.cargo-deny pkgs.git-minimal pkgs.python3 pkgs.rust];
    phases = [
      {
        name = "check";
        script = ''
          repository="$TMPDIR/repository"
          mkdir -p "$repository/crates" "$repository/pkgs" "$repository/security/advisories" "$repository/tools" "$repository/tests/advisory-gate"
          cp -R ${../../crates}/. "$repository/crates/"
          cp ${../../pkgs/security/openssl.nix} "$repository/pkgs/openssl.nix"
          cp ${../../pkgs/db/sqlite.nix} "$repository/pkgs/sqlite.nix"
          cp ${../../pkgs/networking/libssh2.nix} "$repository/pkgs/libssh2.nix"
          cp ${../../pkgs/compression/zlib.nix} "$repository/pkgs/zlib.nix"
          mkdir -p "$repository/pkgs/security" "$repository/pkgs/db" "$repository/pkgs/networking" "$repository/pkgs/compression"
          mv "$repository/pkgs/openssl.nix" "$repository/pkgs/security/openssl.nix"
          mv "$repository/pkgs/sqlite.nix" "$repository/pkgs/db/sqlite.nix"
          mv "$repository/pkgs/libssh2.nix" "$repository/pkgs/networking/libssh2.nix"
          mv "$repository/pkgs/zlib.nix" "$repository/pkgs/compression/zlib.nix"
          cp ${../../security/advisories/deny.toml} "$repository/security/advisories/deny.toml"
          cp ${../../security/advisories/exceptions.json} "$repository/security/advisories/exceptions.json"
          cp ${../../security/advisories/native-inventory.json} "$repository/security/advisories/native-inventory.json"
          cp ${../../security/advisories/snapshot.json} "$repository/security/advisories/snapshot.json"
          cp ${../../tools/advisory-gate.py} "$repository/tools/advisory-gate.py"
          cp ${./test_advisory_gate.py} "$repository/tests/advisory-gate/test_advisory_gate.py"
          chmod -R u+w "$repository"

          cd "$repository"
          python3 -m unittest discover -s tests/advisory-gate -p 'test_*.py'
          export CARGO_HOME="$TMPDIR/cargo-home"
          mkdir -p "$CARGO_HOME" .cargo
          if [ -f ${cargoVendor}/.cargo/config.toml ]; then
            sed "s|@vendor@|${cargoVendor}|g" ${cargoVendor}/.cargo/config.toml > .cargo/config.toml
          else
            printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoVendor}"\n' > .cargo/config.toml
          fi

          export AOS_ADVISORY_DB_ROOT="$TMPDIR/advisory-databases"
          mkdir -p "$AOS_ADVISORY_DB_ROOT"
          cp -R ${rustsecDatabase} "$AOS_ADVISORY_DB_ROOT/advisory-db-3157b0e258782691"
          chmod -R u+w "$AOS_ADVISORY_DB_ROOT"

          cargoReports=
          for target in \
            x86_64-unknown-linux-gnu \
            aarch64-unknown-linux-gnu \
            x86_64-apple-darwin \
            aarch64-apple-darwin \
            wasm32-unknown-unknown
          do
            report="$TMPDIR/cargo-deny-$target.jsonl"
            set +e
            cargo-deny -f json \
              --manifest-path crates/Cargo.toml \
              --config security/advisories/deny.toml \
              --target "$target" \
              --all-features \
              --offline \
              --locked \
              check advisories 2> "$report"
            status=$?
            set -e
            if [ "$status" -ne 0 ] && [ "$status" -ne 1 ]; then
              cat "$report" >&2
              exit "$status"
            fi
            if [ "$status" -eq 1 ] && [ ! -s "$report" ]; then
              echo "cargo-deny returned findings without a JSON report for $target" >&2
              exit 1
            fi
            cargoReports="$cargoReports --cargo-report $report"
          done

          if [ -f ${accacheVendor}/.cargo/config.toml ]; then
            sed "s|@vendor@|${accacheVendor}|g" ${accacheVendor}/.cargo/config.toml > .cargo/config.toml
          else
            printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${accacheVendor}"\n' > .cargo/config.toml
          fi

          report="$TMPDIR/cargo-deny-accache.jsonl"
          set +e
          cargo-deny -f json \
            --manifest-path crates/accache/Cargo.toml \
            --config security/advisories/deny.toml \
            --target x86_64-unknown-linux-gnu \
            --all-features \
            --offline \
            --locked \
            check advisories 2> "$report"
          status=$?
          set -e
          if [ "$status" -ne 0 ] && [ "$status" -ne 1 ]; then
            cat "$report" >&2
            exit "$status"
          fi
          cargoReports="$cargoReports --cargo-report $report"

          python3 tools/advisory-gate.py \
            --repository "$repository" \
            --snapshot security/advisories/snapshot.json \
            --exceptions security/advisories/exceptions.json \
            --native-inventory security/advisories/native-inventory.json \
            --lock crates/Cargo.lock \
            --lock crates/accache/Cargo.lock \
            --today "$(date -u +%F)" \
            $cargoReports

          mkdir -p "$out"
          printf 'PASS\n' > "$out/result"
        '';
      }
    ];
  }
