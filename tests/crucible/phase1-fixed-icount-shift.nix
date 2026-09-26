{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.fixedIcountShift",
  taskIds ? ["T-TIME-2"],
}: let
  root = ../..;
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  rustFilesUnder = relativeRoot: let
    absoluteRoot = root + "/${relativeRoot}";
    entries = builtins.readDir absoluteRoot;
  in
    lib.concatMap (
      name: let
        kind = entries.${name};
        relative = "${relativeRoot}/${name}";
      in
        if kind == "regular" && lib.hasSuffix ".rs" name
        then [relative]
        else if kind == "directory"
        then rustFilesUnder relative
        else []
    )
    (builtins.attrNames entries);

  launchRust =
    builtins.concatStringsSep "\n"
    (map (relative: builtins.readFile (root + "/${relative}"))
      (["crates/crucible-qemu/src/launch.rs"] ++ rustFilesUnder "crates/crucible-qemu/src/launch"));
  launchTest =
    builtins.readFile ../../crates/crucible-qemu/tests/deterministic_launch.rs
    + builtins.readFile ../../crates/crucible-qemu/tests/deterministic_launch/launch_artifacts.rs;
  timeSpec = builtins.readFile ../../docs/rfcs/0010-crucible/09-virtual-time-icount.md;
  decisionRegister = builtins.readFile ../../docs/rfcs/0010-crucible/31-decision-register.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "crates/crucible-qemu/src/launch*.rs" launchRust [
      {
        label = "launch pins shift zero";
        needle = "const ICOUNT_SHIFT: u8 = 0;";
      }
      {
        label = "pre-spawn auto shift is rejected";
        needle = "QemuPreSpawnLaunchValidationError::IcountShiftAuto";
      }
      {
        label = "pre-spawn nonzero shift is rejected";
        needle = "if shift != 0 {";
      }
      {
        label = "QEMU launch argument pins fixed shift";
        needle = "\"shift={ICOUNT_SHIFT},sleep=off,align=off,rr_switch_quantum={}\",";
      }
      {
        label = "scenario hash records shift";
        needle = "format!(\"qemu_icount_shift={ICOUNT_SHIFT}\"),";
      }
      {
        label = "scenario hash records picosecond ticks";
        needle = "\"sim_tick=picosecond\".to_owned(),";
      }
      {
        label = "scenario hash records ticks per nanosecond";
        needle = "format!(\"sim_ticks_per_ns={SIM_TICKS_PER_NS}\"),";
      }
      {
        label = "scenario hash records ticks per instruction";
        needle = "format!(\"sim_ticks_per_instruction={SIM_TICKS_PER_INSTRUCTION}\"),";
      }
      {
        label = "scenario hash floors guest nanoseconds only at projection";
        needle = "format!(\"virtual_time_ns=floor(sim_tick/{SIM_TICKS_PER_NS})\"),";
      }
      {
        label = "validated node-scale scenario material API";
        needle = "pub fn scenario_hash_material_for_nodes(";
      }
      {
        label = "validated material calls canonical node scale validation";
        needle = "canonical_node_tick_scale_lines(node_ids)?";
      }
      {
        label = "canonical node scale material helper";
        needle = "pub(super) fn canonical_node_tick_scale_lines(";
      }
      {
        label = "node scale material sorted by node id";
        needle = "ordered.sort();";
      }
      {
        label = "node scale material records fixed scale";
        needle = "format!(\"node_sim_ticks_per_ns[{node_id}]={SIM_TICKS_PER_NS}\")";
      }
      {
        label = "duplicate node id is rejected";
        needle = "DuplicateNodeId";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/deterministic_launch.rs" launchTest [
      {
        label = "per-node fixed tick scale regression test";
        needle = "launch_profile_pins_fixed_tick_scale_for_each_node";
      }
      {
        label = "default shift enters launch identity";
        needle = "\"qemu_icount_shift=0\"";
      }
      {
        label = "picosecond scale enters launch identity";
        needle = "\"sim_ticks_per_instruction=50\"";
      }
      {
        label = "nanosecond projection enters launch identity";
        needle = "\"virtual_time_ns=floor(sim_tick/1000)\"";
      }
      {
        label = "node scale material records node declaration";
        needle = "node_sim_ticks_per_ns[vm-a]=1000";
      }
      {
        label = "node scale material canonical order assertion";
        needle = "node scale material must be sorted by node id";
      }
      {
        label = "duplicate node id rejection regression";
        needle = "LaunchProfileError::DuplicateNodeId";
      }
      {
        label = "pre-spawn nonzero rejection regression";
        needle = "QemuPreSpawnLaunchValidationError::IcountShiftInvalid";
      }
      {
        label = "pre-spawn auto rejection regression";
        needle = "QemuPreSpawnLaunchValidationError::IcountShiftAuto";
      }
      {
        label = "launch arguments pin default shift";
        needle = "shift=0,sleep=off,align=off";
      }
      {
        label = "shift participates in scenario identity";
        needle = "launch_material_feeds_scenario_identity";
      }
      {
        label = "changed launch material enters scenario identity";
        needle = "assert_ne!(base_scenario.id(), changed_scenario.id());";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/09-virtual-time-icount.md" timeSpec [
      {
        label = "picosecond retirement step documented";
        needle = "50 ticks per retired instruction";
      }
      {
        label = "internal shift is not a nanosecond clock";
        needle = "not a selectable nanosecond time scale in `sim` mode";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/31-decision-register.md" decisionRegister [
      {
        label = "icount shift decision";
        needle = "D-2";
      }
      {
        label = "picosecond retirement step decided";
        needle = "per retired instruction; an authorized idle jump";
      }
      {
        label = "fixed scale is content addressed";
        needle = "The fixed scale is bound into scenario, launch,";
      }
      {
        label = "default shift documented";
        needle = "`-icount shift=0`";
      }
      {
        label = "nanosecond projection is derived";
        needle = "floor(logical_ticks / 1000)";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes fixed-icount-shift check";
        needle = "fixedIcountShift = import ./phase1-fixed-icount-shift.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 fixed-icount-shift check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-fixed-icount-shift";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
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
            if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
              sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
            else
              printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
                > .cargo/config.toml
            fi
          '';
        }
        {
          name = "run-fixed-icount-shift";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-fixed-icount-shift-target" \
              -p crucible-qemu \
              --test deterministic_launch \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            default_shift=0
            sim_ticks_per_ns=1000
            sim_ticks_per_instruction=50
            auto_shift=forbidden
            scenario_hash=qemu_icount_shift,sim_ticks_per_ns,sim_ticks_per_instruction
            per_node_tick_scale=fixed
            decision_register=D-2
            RESULT
          '';
        }
      ];
    }
