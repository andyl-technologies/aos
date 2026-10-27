{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.aosAbilityBaselineAdapter",
}: let
  src = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;
  adapter = builtins.readFile ../../crates/activation/aos-activation-crucible/src/lib.rs;
  profile = builtins.readFile ../../modules/profiles/ability-crucible.nix;
  package = builtins.readFile ../../pkgs/tools/aos-ability-crucible.nix;
  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;
  failures =
    failuresFor "crates/activation/aos-activation-crucible/src/lib.rs" adapter [
      {
        label = "production observer event schema";
        needle = "aos.ability-execution-boundary-event/v1";
      }
      {
        label = "generic guest assertion mapping";
        needle = "GuestCommand::always";
      }
      {
        label = "generic guest event mapping";
        needle = "GuestCommand::event";
      }
      {
        label = "generic guest coverage mapping";
        needle = "GuestCommand::coverage";
      }
      {
        label = "host assertion verdict integration";
        needle = "check_assertion_violation_reproduction";
      }
      {
        label = "restart continuity is fail closed";
        needle = "executor boundary order is invalid";
      }
      {
        label = "ack follows marker processing";
        needle = "self.process_event(&event)?;";
      }
    ]
    ++ failuresFor "modules/profiles/ability-crucible.nix" profile [
      {
        label = "profile defaults disabled";
        needle = "default = false;";
      }
      {
        label = "protected root runtime directory";
        needle = ''RuntimeDirectoryMode = "0700";'';
      }
      {
        label = "activation requires ready adapter";
        needle = ''requires = ["aos-ability-crucible.service"];'';
      }
      {
        label = "closed baseline marker declarations";
        needle = "required_marker_kinds";
      }
    ]
    ++ failuresFor "pkgs/tools/aos-ability-crucible.nix" package [
      {
        label = "separate optional package";
        needle = ''pname = "aos-ability-crucible";'';
      }
      {
        label = "static guest artifact";
        needle = "target-feature=+crt-static";
      }
    ]
    ++ forbiddenFor "crates/activation/aos-activation-crucible/src/lib.rs" adapter [
      {
        label = "advanced campaign dependency";
        needle = "aos-campaign";
      }
      {
        label = "QEMU implementation dependency";
        needle = "crucible_qemu";
      }
      {
        label = "shared-memory dependency";
        needle = "crucible_shmem";
      }
      {
        label = "unsafe implementation";
        needle = "unsafe ";
      }
    ];
in
  if failures != []
  then throw "AOS ability baseline Crucible adapter check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase4-aos-ability-baseline-adapter";
      inherit src;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        pkgs.sed
      ];

      phases = [
        {
          name = "run-adapter-gates";
          script = ''
            set -eu
            cd crates
            crucible-cargo test \
              -p aos-activation-crucible \
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
            ordinary_executor_observer=true
            generic_markers=assertion,event,coverage,lifecycle
            host_verdict_and_reproduction=true
            live_qemu_plugin_transport=checks.crucible.phase2.qemuLiveWhiteboxDoorbell
            composed_native_activation=separate-required-gate
            exact_marker_interruption=production-native-baseline-flight
            typed_fault_selection_replay=blocked-pr194-selectable-protocol
            adapter_restart_monitor=fail-closed-no-reconstruction
            partial_marker_delivery=incomplete-no-ack
            RESULT
          '';
        }
      ];
    }
