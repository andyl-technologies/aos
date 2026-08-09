{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.timeClockSkew",
  taskIds ? ["T-TIME-4"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  crateTests = builtins.readFile ../../crates/crucible/src/tests/model_core.rs;
  publicTest = builtins.readFile ../../crates/crucible/tests/time_clock_skew.rs;
  qemuLaunch =
    builtins.readFile ../../crates/crucible-qemu/src/launch.rs
    + builtins.readFile ../../crates/crucible-qemu/src/launch/canonical.rs;
  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  qemuValidation =
    builtins.readFile ../../crates/crucible-qemu/src/launch/validation.rs
    + builtins.readFile ../../crates/crucible-qemu/src/launch/validation/values.rs;
  qemuTest =
    builtins.readFile ../../crates/crucible-qemu/tests/deterministic_launch.rs
    + builtins.readFile ../../crates/crucible-qemu/tests/deterministic_launch/launch_artifacts.rs;
  timeSpec = builtins.readFile ../../docs/rfcs/0010-crucible/09-virtual-time-icount.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "fixed-point drift rate type";
        needle = "pub struct ClockDriftRate";
      }
      {
        label = "drift rate numerator";
        needle = "pub numerator: u64";
      }
      {
        label = "drift rate denominator";
        needle = "pub denominator: u64";
      }
      {
        label = "perfect drift rate";
        needle = "pub const ONE: Self";
      }
      {
        label = "zero denominator rejection";
        needle = "denominator == 0";
      }
      {
        label = "fixed-point multiply";
        needle = "u128::from(virtual_time.nanos) * u128::from(self.numerator)";
      }
      {
        label = "fixed-point floor division";
        needle = "drifted / u128::from(self.denominator)";
      }
      {
        label = "semantic perfect drift rate";
        needle = "pub fn is_one(self) -> bool";
      }
      {
        label = "guest visible overflow error";
        needle = "GuestVisibleTimeOverflow";
      }
      {
        label = "node clock skew type";
        needle = "pub struct NodeClockSkew";
      }
      {
        label = "clock skew offset";
        needle = "pub offset: SimOffset";
      }
      {
        label = "clock skew drift rate";
        needle = "pub drift_rate: ClockDriftRate";
      }
      {
        label = "perfect clock default";
        needle = "pub const PERFECT: Self";
      }
      {
        label = "guest-visible time API";
        needle = "pub fn guest_visible_time(";
      }
      {
        label = "semantic perfect clock";
        needle = "pub fn is_perfect(self) -> bool";
      }
      {
        label = "checked skew offset overflow";
        needle = "GuestVisibleTimeOffsetOverflow";
      }
      {
        label = "perfect clock material omitted";
        needle = "Ok((!self.is_perfect()).then(||";
      }
      {
        label = "invalid material drift rejection";
        needle = "return Err(TimeConversionError::InvalidDriftRate";
      }
      {
        label = "checked offset conversion";
        needle = "u64::try_from(shifted)";
      }
      {
        label = "offset enters scenario material";
        needle = "clock_skew_offset_ns=";
      }
      {
        label = "drift enters scenario material";
        needle = "clock_drift_rate=";
      }
      {
        label = "rounding enters scenario material";
        needle = "clock_drift_rounding=floor";
      }
      {
        label = "guest-visible-only material";
        needle = "clock_skew_applies_to=guest-visible-only";
      }
      {
        label = "unskewed scheduling axis material";
        needle = "clock_skew_scheduling_axis=unskewed-icount-derived";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/model.rs" model [
      {
        label = "floating-point time math";
        needle = "f64";
      }
      {
        label = "floating-point time math";
        needle = "f32";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "clock skew exports";
        needle = "ClockDriftRate";
      }
      {
        label = "node clock skew export";
        needle = "NodeClockSkew";
      }
    ]
    ++ failuresFor "crates/crucible/src/tests/model_core.rs" crateTests [
      {
        label = "guest-visible-only unit test";
        needle = "clock_skew_applies_fixed_point_drift_to_guest_reads_only";
      }
      {
        label = "floor rounding unit test";
        needle = "clock_skew_uses_floor_rounding_without_floating_point";
      }
      {
        label = "invalid drift unit test";
        needle = "clock_skew_rejects_invalid_drift_rate_and_overflow";
      }
      {
        label = "perfect material unit test";
        needle = "clock_skew_hash_material_omits_perfect_clock_and_records_overrides";
      }
      {
        label = "equivalent perfect material unit assertion";
        needle = "equivalent_perfect_material";
      }
    ]
    ++ failuresFor "crates/crucible/tests/time_clock_skew.rs" publicTest [
      {
        label = "public guest-visible-only test";
        needle = "clock_skew_distorts_guest_visible_time_without_moving_scheduler_time";
      }
      {
        label = "public floor rounding test";
        needle = "clock_skew_uses_integer_floor_rounding_and_epoch_saturation";
      }
      {
        label = "public perfect material test";
        needle = "clock_skew_material_keeps_default_byte_identical_to_absence";
      }
      {
        label = "public equivalent perfect assertion";
        needle = "equivalent_no_skew";
      }
      {
        label = "public invalid drift test";
        needle = "clock_skew_rejects_invalid_or_overflowing_time";
      }
      {
        label = "public offset overflow assertion";
        needle = "GuestVisibleTimeOffsetOverflow";
      }
      {
        label = "public invalid material assertion";
        needle = ".scenario_hash_material()";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/launch.rs" qemuLaunch [
      {
        label = "node clock skew declaration";
        needle = "pub struct NodeClockSkewDeclaration";
      }
      {
        label = "node timing material API";
        needle = "pub fn scenario_hash_material_for_node_timing";
      }
      {
        label = "node clock skew canonical lines";
        needle = "fn canonical_node_clock_skew_lines";
      }
      {
        label = "node-keyed skew offset material";
        needle = "node_clock_skew_offset_ns[";
      }
      {
        label = "node-keyed drift material";
        needle = "node_clock_drift_rate[";
      }
      {
        label = "perfect node clock omitted";
        needle = "if skew.is_perfect()";
      }
      {
        label = "invalid drift rejected before material";
        needle = "InvalidNodeClockDriftRate";
      }
      {
        label = "duplicate node skew rejected";
        needle = "DuplicateNodeClockSkew";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "node clock skew declaration export";
        needle = "NodeClockSkewDeclaration";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/launch/validation.rs" qemuValidation [
      {
        label = "invalid node drift error";
        needle = "InvalidNodeClockDriftRate";
      }
      {
        label = "duplicate node clock skew error";
        needle = "DuplicateNodeClockSkew";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/deterministic_launch.rs" qemuTest [
      {
        label = "launch skew material test";
        needle = "launch_profile_records_per_node_clock_skew_material";
      }
      {
        label = "launch skew invalid material test";
        needle = "launch_profile_rejects_invalid_node_clock_skew_material";
      }
      {
        label = "launch skew material feeds scenario identity";
        needle = "ScenarioDef::from_canonical_material";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/09-virtual-time-icount.md" timeSpec [
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes clock-skew check";
        needle = "timeClockSkew = import ./phase1-time-clock-skew.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 time clock-skew check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-time-clock-skew";
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
          name = "run-time-clock-skew";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-time-clock-skew-target" \
              -p crucible \
              --lib clock_skew \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-time-clock-skew-target" \
              -p crucible \
              --test time_clock_skew \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-time-clock-skew-target" \
              -p crucible-qemu \
              --test deterministic_launch \
              clock_skew \
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
            skew_axis=guest-visible-only
            scheduling_axis=unskewed-icount-derived
            drift_rate=fixed-point-rational
            drift_rounding=floor
            perfect_clock_material=omitted
            RESULT
          '';
        }
      ];
    }
