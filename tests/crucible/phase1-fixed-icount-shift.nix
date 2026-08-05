{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.fixedIcountShift",
  taskIds ? ["T-TIME-2"],
}: let
  root = ../..;
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

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
  launchLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
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
        label = "candidate carries fixed-or-auto shift request";
        needle = "pub icount_shift: IcountShiftSetting,";
      }
      {
        label = "default launch pins shift zero";
        needle = "icount_shift: IcountShiftSetting::Fixed(0),";
      }
      {
        label = "auto shift is rejected";
        needle = "IcountShiftSetting::Auto => return Err(LaunchProfileError::IcountShiftAuto),";
      }
      {
        label = "fixed shift validator";
        needle = "fn validate_icount_shift(shift: u8) -> Result<u8, LaunchProfileError>";
      }
      {
        label = "QEMU launch argument pins fixed shift";
        needle = "\"shift={},sleep=off,align=off,rr_switch_quantum={}\",";
      }
      {
        label = "scenario hash records shift";
        needle = "format!(\"icount_shift={}\", self.icount_shift),";
      }
      {
        label = "scenario hash records derived virtual time";
        needle = "\"virtual_time_ns=icount<<shift\".to_owned(),";
      }
      {
        label = "node shift declaration type";
        needle = "pub struct NodeIcountShift";
      }
      {
        label = "node shift validation API";
        needle = "pub fn validate_node_icount_shifts(";
      }
      {
        label = "validated node-shift scenario material API";
        needle = "pub fn scenario_hash_material_for_nodes(";
      }
      {
        label = "validated material calls canonical node shift validation";
        needle = "canonical_node_icount_shift_lines(self.icount_shift, node_shifts)?";
      }
      {
        label = "canonical node shift material helper";
        needle = "fn canonical_node_icount_shift_lines(";
      }
      {
        label = "node shift material sorted by node id";
        needle = "ordered.sort_by(|left, right| left.0.cmp(&right.0));";
      }
      {
        label = "duplicate node shift declaration rejection";
        needle = "DuplicateNodeIcountShift";
      }
      {
        label = "node shift mismatch error";
        needle = "IcountShiftMismatch";
      }
      {
        label = "node shift validation checks unsupported shifts";
        needle = "validate_icount_shift(node_shift.shift)?;";
      }
      {
        label = "node shift validation compares against scenario";
        needle = "if node_shift.shift != scenario_shift";
      }
      {
        label = "node shift declarations enter scenario material";
        needle = "format!(\"node_icount_shift[{node_id}]={shift}\")";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" launchLib [
      {
        label = "node shift type exported";
        needle = "NodeIcountShift";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/deterministic_launch.rs" launchTest [
      {
        label = "per-node mismatch regression test";
        needle = "launch_profile_rejects_per_node_icount_shift_mismatch";
      }
      {
        label = "default shift assertion";
        needle = "assert_eq!(profile.icount_shift(), 0);";
      }
      {
        label = "matching node shifts pass";
        needle = "NodeIcountShift::new(\"vm-b\", 0)";
      }
      {
        label = "validated material path is tested";
        needle = "scenario_hash_material_for_nodes";
      }
      {
        label = "node shift material records node declaration";
        needle = "node_icount_shift[vm-a]=0";
      }
      {
        label = "node shift material canonical order assertion";
        needle = "node shift material must be sorted by node id";
      }
      {
        label = "mismatching node shift is rejected";
        needle = "NodeIcountShift::new(\"vm-b\", 1)";
      }
      {
        label = "mismatch reports both shifts";
        needle = "LaunchProfileError::IcountShiftMismatch";
      }
      {
        label = "unsupported shift rejection regression";
        needle = "LaunchProfileError::IcountShiftTooLarge { shift: 63 }";
      }
      {
        label = "duplicate node shift rejection regression";
        needle = "LaunchProfileError::DuplicateNodeIcountShift";
      }
      {
        label = "auto rejection regression";
        needle = "IcountShiftSetting::Auto";
      }
      {
        label = "launch arguments pin default shift";
        needle = "shift=0,sleep=off,align=off";
      }
      {
        label = "hash material records default shift";
        needle = "icount_shift=0";
      }
      {
        label = "shift participates in scenario identity";
        needle = "launch_material_feeds_scenario_identity";
      }
      {
        label = "shift change enters scenario identity";
        needle = "assert_ne!(base_scenario.id(), shifted_scenario.id());";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/09-virtual-time-icount.md" timeSpec [
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/31-decision-register.md" decisionRegister [
      {
        label = "icount shift decision";
        needle = "D-2";
      }
      {
        label = "auto shift forbidden";
        needle = "never `-icount shift=auto`";
      }
      {
        label = "shift is content addressed";
        needle = "part of the scenario's content hash";
      }
      {
        label = "default shift documented";
        needle = "`shift=0`, so one retired guest instruction advances virtual time by one";
      }
      {
        label = "default shift rationale";
        needle = "preserves the finest timer resolution";
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
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
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
            auto_shift=forbidden
            scenario_hash=icount_shift
            per_node_shift=must_match_scenario
            decision_register=D-2
            RESULT
          '';
        }
      ];
    }
