{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.timeVocabulary",
  taskIds ? ["T-TIME-1"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "icount type";
        needle = "pub struct Icount";
      }
      {
        label = "shift type";
        needle = "pub struct Shift";
      }
      {
        label = "virtual instant type";
        needle = "pub struct VirtualInstant";
      }
      {
        label = "sim instant alias";
        needle = "pub type SimInstant = VirtualInstant;";
      }
      {
        label = "unsigned duration type";
        needle = "pub struct SimDuration";
      }
      {
        label = "signed offset type";
        needle = "pub struct SimOffset";
      }
      {
        label = "icount to virtual conversion";
        needle = "pub fn to_virtual(self, shift: Shift) -> Result<VirtualInstant, TimeConversionError>";
      }
      {
        label = "floor conversion";
        needle = "pub fn to_icount_floor(self, shift: Shift) -> Result<Icount, TimeConversionError>";
      }
      {
        label = "ceil conversion";
        needle = "pub fn to_icount_ceil(self, shift: Shift) -> Result<Icount, TimeConversionError>";
      }
      {
        label = "checked conversion scale";
        needle = "fn scale_for_shift(shift: Shift) -> Result<u64, TimeConversionError>";
      }
      {
        label = "checked virtual time multiplication";
        needle = ".checked_mul(scale)";
      }
      {
        label = "duration since saturates";
        needle = "self.nanos.saturating_sub(earlier.nanos)";
      }
      {
        label = "skew saturates at epoch";
        needle = "Self::EPOCH";
      }
      {
        label = "point plus duration only";
        needle = "impl ops::Add<SimDuration> for VirtualInstant";
      }
      {
        label = "duration arithmetic is unsigned";
        needle = "impl ops::Add for SimDuration";
      }
      {
        label = "duration scalar multiply is unsigned";
        needle = "impl ops::Mul<u64> for SimDuration";
      }
      {
        label = "conversion error type";
        needle = "pub enum TimeConversionError";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/model.rs" model [
      {
        label = "point plus point implementation";
        needle = "impl ops::Add<VirtualInstant> for VirtualInstant";
      }
      {
        label = "point plus point shorthand implementation";
        needle = "impl ops::Add for VirtualInstant";
      }
      {
        label = "floating point time math";
        needle = "f64";
      }
      {
        label = "floating point time math";
        needle = "f32";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "SimDuration export";
        needle = "SimDuration,";
      }
      {
        label = "SimInstant export";
        needle = "SimInstant,";
      }
      {
        label = "SimOffset export";
        needle = "SimOffset,";
      }
      {
        label = "conversion test";
        needle = "time_vocabulary_converts_icount_and_virtual_instants_exactly";
      }
      {
        label = "duration and offset distinction test";
        needle = "time_vocabulary_keeps_duration_and_offset_distinct";
      }
      {
        label = "invalid shift and overflow test";
        needle = "time_vocabulary_rejects_invalid_shift_and_virtual_time_overflow";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes time vocabulary check";
        needle = "timeVocabulary = import ./phase1-time-vocabulary.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 time vocabulary check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase1-time-vocabulary";

      buildDeps = [
        pkgs.coreutils
        pkgs.sed
      ];

      phases = [
        {
          name = "run-time-vocabulary";
          script = ''
            set -eu
            cd crates
            crucible-cargo test \
              -p crucible \
              --lib \
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
            types=Icount,Shift,VirtualInstant,SimInstant,SimDuration,SimOffset
            conversions=to_virtual,to_icount_floor,to_icount_ceil
            point_plus_point=false
            floating_time_math=false
            RESULT
          '';
        }
      ];
    }
