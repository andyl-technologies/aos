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
    buildDeps = [driver inputs pkgs.coreutils pkgs.nix];
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
          for executable in ${driver}/bin/aos_package-*; do
            "$executable" --exact \
              boot_configuration::integration::checked_metadata_adoption_recovers_and_preserves_operator_sources \
              --ignored --nocapture
            "$executable" --exact \
              config_eval::provisioning_evaluator::tests::source_built_provisioning_results_match_declared_wire_contracts \
              --ignored --nocapture
            "$executable" --exact \
              boot_configuration::integration::committed_dynamic_receipts_cross_stores_with_exact_authority \
              --ignored --nocapture
          done
          echo PASS > "$out/result"
        '';
      }
    ];
  }
