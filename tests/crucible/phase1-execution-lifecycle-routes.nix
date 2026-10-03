{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.executionLifecycleRoutes",
  taskIds ? ["T-EXEC-7" "T-PAT-9"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  apiLifecycle = builtins.readFile ../../crates/crucible-api/src/vm_lifecycle.rs;
  daemonLifecycle = builtins.readFile ../../crates/crucible-daemon/src/qemu_campaign_lifecycle.rs;
  daemonLauncher = builtins.readFile ../../crates/crucible-daemon/src/qemu_lifecycle_launcher.rs;
  bakedReplay = builtins.readFile ../../crates/crucible-daemon/src/qemu_baked_genesis.rs;

  inherit (import ./_lib.nix {inherit lib;}) failuresFor;

  failures =
    failuresFor "crates/crucible-api/src/vm_lifecycle.rs" apiLifecycle [
      {
        label = "operation-specific exact-resume builder";
        needle = "pub fn build_production_vm_exact_resume_lifecycle<L>(";
      }
      {
        label = "atomic exact-restore admission";
        needle = "pub fn into_atomic_restore(";
      }
      {
        label = "typed baked-replay admission";
        needle = "pub fn into_replay_admission(";
      }
    ]
    ++ failuresFor "crates/crucible-daemon/src/qemu_campaign_lifecycle.rs" daemonLifecycle [
      {
        label = "production exact-resume route";
        needle = "build_production_vm_exact_resume_lifecycle(scenario, source, &config, decoded, launcher)";
      }
    ]
    ++ failuresFor "crates/crucible-daemon/src/qemu_lifecycle_launcher.rs" daemonLauncher [
      {
        label = "single restored-generation launcher";
        needle = "fn launch_restored(";
      }
      {
        label = "atomic restore consumption";
        needle = "admission.into_atomic_restore(request, run_directory, process_contract)";
      }
    ]
    ++ failuresFor "crates/crucible-daemon/src/qemu_baked_genesis.rs" bakedReplay [
      {
        label = "typed baked-replay catalog";
        needle = "pub struct ProductionBakedGenesisReplayCatalogFactory<R>";
      }
      {
        label = "baked replay consumes replay-only admission";
        needle = ".into_replay_admission(";
      }
    ];
in
  if failures != []
  then throw "crucible execution lifecycle route check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-execution-lifecycle-routes";
      version = "0";
      LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
      runtimeDeps = [pkgs.sqlite];
      src = crucibleSrc;
      buildDeps = [pkgs.rust pkgs.sed pkgs.pkg-config pkgs.sqlite];

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
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml
          '';
        }
        {
          name = "run-lifecycle-route-tests";
          script = ''
            cargo test --frozen --offline \
              --target-dir "$TMPDIR/execution-lifecycle-routes-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-daemon --lib \
              qemu_campaign_lifecycle::tests::exact_resume_is_rejected_before_resource_installation \
              -- --exact
            cargo test --frozen --offline \
              --target-dir "$TMPDIR/execution-lifecycle-routes-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-daemon --lib \
              qemu_baked_genesis::tests::baked_catalog_routes_by_the_complete_world_scenario_basis \
              -- --exact
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
            exact_resume_route=authenticated-lifecycle-to-atomic-request-to-launch-restored
            baked_replay_route=typed-baked-catalog-to-replay-only-exact-admission
            qemu_realization_facade=absent
            RESULT
          '';
        }
      ];
    }
