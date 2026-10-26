##! Exercises native first-host admission, normal role changes and recovery.
{
  pkgs,
  lib,
  mkSystem,
}: let
  fixture = import ../../tests/effects/boot-metadata-fixture.nix {inherit pkgs lib;};
  handoffFixture = import ../../tests/effects/boot-handoff-fixture.nix {inherit pkgs lib;};
  inputs = (lib.build.closureInfo {inherit pkgs;}) {
    rootPaths = [fixture handoffFixture];
    pname = "boot-bootstrap-inputs";
  };
  driver = pkgs.aos-boot-configuration-test-driver;
in
  pkgs.mkDerivation {
    pname = "boot-configuration-check";
    version = "0";
    src = null;
    buildDeps = [driver inputs pkgs.coreutils pkgs.grep pkgs.nix];
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          mkdir -p "$out" /build/aos-boot-bootstrap-state
          evaluation_store_root="/build/aos-boot-handoff-state/source-store"
          evaluation_store="local?root=$evaluation_store_root"
          mkdir -p "$evaluation_store_root/nix/store"
          while IFS= read -r store_path; do
            cp -a --no-preserve=ownership "$store_path" "$evaluation_store_root/nix/store/"
          done < ${inputs}/store-paths
          ${pkgs.nix}/bin/nix-store --store "$evaluation_store" --init
          ${pkgs.nix}/bin/nix-store --store "$evaluation_store" --load-db < ${inputs}/registration
          export AOS_NIX_EVAL_STORE="$evaluation_store"
          export AOS_NIX_STORE=${pkgs.nix}/bin/nix-store
          export AOS_NIX_INSTANTIATE=${pkgs.nix}/bin/nix-instantiate
          export AOS_PACKAGE_MODULE_LIBRARY=${lib.packageModuleLibrary}
          export AOS_BOOT_CONFIGURATION_FIXTURE=${fixture}/fixture.json
          export AOS_BOOT_HANDOFF_FIXTURE=${handoffFixture}/fixture.json
          export PATH=${pkgs.nix}/bin:$PATH
          case_index=0
          for executable in ${driver}/bin/aos_package_manager-*; do
            for test_case in \
              boot_configuration::integration::checked_metadata_adoption_recovers_and_preserves_operator_sources \
              config_eval::provisioning_evaluator::tests::source_built_provisioning_results_match_declared_wire_contracts \
              boot_configuration::integration::committed_dynamic_receipts_cross_stores_with_exact_authority; do
              # Libtest otherwise reports success when an exact filter matches nothing.
              listing="$("$executable" "$test_case" --exact --list --ignored --format=terse)"
              test "$listing" = "$test_case: test"
              case_index=$((case_index + 1))
              log="$out/case-$case_index.log"
              if ! "$executable" "$test_case" --exact --ignored --nocapture > "$log" 2>&1; then
                cat "$log" >&2
                exit 1
              fi
              ${pkgs.grep}/bin/grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored;' "$log"
              printf '%s\n' "$test_case" >> "$out/cases.txt"
            done
          done
          test "$case_index" -eq 3
          echo PASS > "$out/result"
        '';
      }
    ];
  }
