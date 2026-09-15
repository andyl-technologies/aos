{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.basicBlockCoverage",
  taskIds ? ["T-ADV-10" "T-PLUG-15" "T-PERF-15"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase6-basic-block-coverage";
    version = "0";
    src = crucibleSrc;
    buildDeps = [pkgs.coreutils pkgs.grep pkgs.rust pkgs.sed] ++ dependencies;
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
          cd source
          mkdir -p "$CARGO_HOME" .cargo
          sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
            > .cargo/config.toml
        '';
      }
      {
        name = "run-current-coverage-contracts";
        script = ''
          set -eu
          cd source
          target="$TMPDIR/basic-block-coverage-target"
          cargo test --frozen --offline --target-dir "$target" \
            --manifest-path crates/Cargo.toml -p crucible \
            --test gate_basic_block_coverage -- --test-threads=1
          cargo test --frozen --offline --target-dir "$target" \
            --manifest-path crates/Cargo.toml -p crucible-qemu \
            mapped_quantum::coverage_tests --lib -- --test-threads=1
          cargo test --frozen --offline --target-dir "$target" \
            --manifest-path crates/Cargo.toml -p crucible-qemu-plugin \
            coverage --lib -- --test-threads=1
        '';
      }
      {
        name = "write-result";
        script = ''
          mkdir -p "$out"
          cat > "$out/result" <<'RESULT'
          PASS
          check=${attrPath}
          tasks=${builtins.concatStringsSep "," taskIds}
          open_tasks=${builtins.concatStringsSep "," openTaskIds}
          gate=gate:basic-block-coverage
          transport=aggregate-shmem-coverage
          restore_generation_acknowledged=true
          coverage_opt_in=true
          canonical_fingerprint_effect=none
          RESULT
        '';
      }
    ];
  }
