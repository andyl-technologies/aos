{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.aosAbilityBaselineAdapter",
}: let
  src = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  adapter = builtins.readFile ../../crates/aos-ability-crucible/src/lib.rs;
  profile = builtins.readFile ../../modules/profiles/ability-crucible.nix;
  package = builtins.readFile ../../pkgs/tools/aos-ability-crucible.nix;
  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;
  failures =
    failuresFor "crates/aos-ability-crucible/src/lib.rs" adapter [
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
    ++ forbiddenFor "crates/aos-ability-crucible/src/lib.rs" adapter [
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
    pkgs.mkDerivation {
      pname = "crucible-phase4-aos-ability-baseline-adapter";
      version = "0";
      inherit src;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        pkgs.rust
        pkgs.sed
      ];

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
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            sed "s|@vendor@|${cargoDeps}|g" \
              "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml
          '';
        }
        {
          name = "run-adapter-gates";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/aos-ability-crucible-target" \
              -p aos-ability-crucible \
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
            exact_marker_interruption=blocked-pr194-pending-choice
            typed_fault_selection_replay=blocked-pr194-selectable-protocol
            adapter_restart_monitor=fail-closed-no-reconstruction
            partial_marker_delivery=incomplete-no-ack
            RESULT
          '';
        }
      ];
    }
