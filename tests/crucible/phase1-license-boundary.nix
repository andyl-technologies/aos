{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.gates.licenseBoundary",
  taskIds ? ["BOUND-1" "BOUND-2" "BOUND-3" "BOUND-4" "BOUND-5" "BOUND-6" "BOUND-7" "BOUND-8" "BOUND-9" "BOUND-10" "BOUND-11" "BOUND-12"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase1-license-boundary";
    version = "0";
    src = crucibleSrc;

    buildDeps = [pkgs.coreutils pkgs.rust pkgs.sed];

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
          printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
            > .cargo/config.toml
        '';
      }
      {
        name = "run-license-boundary";
        script = ''
          cd crates
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-license-boundary-target" \
            -p crucible-harness \
            --test gate_license_boundary \
            -- --test-threads=1
        '';
      }
      {
        name = "write-result";
        script = ''
          mkdir -p "$out"
          cat > "$out/result" <<'RESULT'
          PASS
          check=${attrPath}
          gate=gate:license-boundary
          tasks=${builtins.concatStringsSep "," taskIds}
          rust_test=crucible-harness::gate_license_boundary
          RESULT
        '';
      }
    ];
  }
