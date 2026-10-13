# Local release-only equivalence of production-enabled BLAKE3 dispatch paths.
# The matrix records unsupported CPUs explicitly and qualifies identities only.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.ram.blake3Backends",
}: let
  src = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib src;};
  workspace = builtins.readFile ../../crates/Cargo.toml;
  lock = builtins.readFile ../../crates/Cargo.lock;
  productionFeatures = ''blake3 = { version = "1", default-features = false, features = ["std", "pure"] }'';
  selectedTest = "ram::tests::backend_equivalence::persistent_ram_and_checkpoint_identities_match_selected_blake3_backend";
  profiles = [
    {
      name = "portable";
      features = ["blake3/no_sse2" "blake3/no_sse41" "blake3/no_avx2" "blake3/no_avx512"];
    }
    {
      name = "sse2";
      features = ["blake3/no_sse41" "blake3/no_avx2" "blake3/no_avx512"];
    }
    {
      name = "sse41";
      features = ["blake3/no_avx2" "blake3/no_avx512"];
    }
    {
      name = "avx2";
      features = ["blake3/no_avx512"];
    }
  ];
  runProfile = profile: let
    features = builtins.concatStringsSep "," profile.features;
  in ''
    export CRUCIBLE_TEST_BLAKE3_BACKEND=${lib.escapeShellArg profile.name}
    cargo test --release --frozen --offline --manifest-path crates/Cargo.toml \
      --package crucible-cas --lib --features ${lib.escapeShellArg features} \
      --target-dir "$PWD/backend-targets/${profile.name}" \
      -- ${lib.escapeShellArg selectedTest} --exact --test-threads=1 --nocapture \
      > "$out/evidence/${profile.name}.log" 2>&1
    grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored;' "$out/evidence/${profile.name}.log"
    test "$(grep -c '^BLAKE3_BACKEND ' "$out/evidence/${profile.name}.log")" -eq 1
    if grep -Fxq 'BLAKE3_BACKEND requested=${profile.name} selected=${profile.name} status=executed' \
      "$out/evidence/${profile.name}.log"; then
      grep '^RAM_IDENTITY ' "$out/evidence/${profile.name}.log" > "$out/evidence/${profile.name}.identity"
      test "$(wc -l < "$out/evidence/${profile.name}.identity")" -eq 30
      ${lib.optionalString (profile.name != "portable") ''
      cmp "$out/evidence/portable.identity" "$out/evidence/${profile.name}.identity"
    ''}
      printf '%s\texecuted\tidentical\n' ${lib.escapeShellArg profile.name} >> "$out/matrix.tsv"
    else
      grep -Eq '^BLAKE3_BACKEND requested=${profile.name} selected=[a-z0-9]+ status=not-executed reason=unsupported-cpu$' \
        "$out/evidence/${profile.name}.log"
      test "$(grep -c '^RAM_IDENTITY ' "$out/evidence/${profile.name}.log" || true)" -eq 0
      ${lib.optionalString (profile.name == "portable") ''exit 1''}
      printf '%s\tnot-executed\tunsupported-cpu\n' ${lib.escapeShellArg profile.name} >> "$out/matrix.tsv"
    fi
  '';
in
  if !lib.hasInfix productionFeatures workspace
  then throw "BLAKE3 backend qualification requires the actual std+pure production build; review the matrix when features change"
  else if !lib.hasInfix "name = \"blake3\"\nversion = \"1.8.5\"" lock
  then throw "BLAKE3 backend qualification controls must be reviewed against the actual pinned library"
  else
    pkgs.mkDerivation {
      pname = "crucible-ram-blake3-backends";
      version = "0";
      inherit src;
      preferLocalBuild = true;
      allowSubstitutes = false;
      buildDeps = [pkgs.coreutils pkgs.grep pkgs.sed pkgs.rust pkgs.pkg-config pkgs.sqlite];
      runtimeDeps = [pkgs.sqlite];
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
            export CARGO_HOME="$PWD/qualification-cargo"
            export CARGO_INCREMENTAL=0
            export LIBSQLITE3_SYS_USE_PKG_CONFIG=1
            export RUSTFLAGS="-C link-arg=-Wl,-rpath,${pkgs.sqlite}/lib"
            unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
            mkdir -p "$CARGO_HOME" .cargo
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml
          '';
        }
        {
          name = "qualify-production-backends";
          script = ''
            set -eu
            mkdir -p "$out/evidence"
            printf 'backend\tstatus\tidentity\n' > "$out/matrix.tsv"
            ${lib.concatMapStringsSep "\n" runProfile profiles}
            printf 'avx512\tnot-executed\tdisabled-by-production-pure\n' >> "$out/matrix.tsv"
            printf 'neon\tnot-executed\tdisabled-by-production-pure\n' >> "$out/matrix.tsv"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            qualification=local-component-identities-only
            blake3_version=1.8.5
            production_features=std,pure
            profile=release
            executed_backends=see-matrix.tsv
            unsupported_backends=explicit-not-executed
            canonical_identity_rows_per_executed_backend=30
            guest_performance_qualified=false
            native_vm_qualified=false
            RESULT
          '';
        }
      ];
    }
