{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.faultIntegerRates",
  taskIds ? ["T-FAULT-4"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  decision = builtins.readFile ../../crates/crucible/src/decision.rs;
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  deviceFault = builtins.readFile ../../crates/crucible-device/src/fault.rs;
  netlinkFault = builtins.readFile ../../crates/crucible-device/src/netlink/fault.rs;
  netlinkLink = builtins.readFile ../../crates/crucible-device/src/netlink/link.rs;
  integerRatesTest = builtins.readFile ../../crates/crucible/tests/fault_integer_rates.rs;
  resolveRngTest = builtins.readFile ../../crates/crucible/tests/scheduler_resolve_rng.rs;
  faultDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17-fault-injection.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/17-fault-injection.md" faultDoc [
      {
        label = "T-FAULT-4 checked off";
        needle = "- [x] **T-FAULT-4**";
      }
      {
        label = "T-FAULT-4 completion note";
        needle = "Completed by `checks.crucible.phase4.faultIntegerRates`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "basis-point denominator";
        needle = "pub const DENOMINATOR: u32 = MAX_FAULT_RATE_BASIS_POINTS";
      }
      {
        label = "basis-point bucket reduction";
        needle = "pub const fn draw_bucket(raw_draw: u64) -> u16";
      }
      {
        label = "basis-point exact Bernoulli";
        needle = "pub const fn fires_on_draw(self, raw_draw: u64) -> bool";
      }
      {
        label = "integer Bernoulli comparison";
        needle = "Self::draw_bucket(raw_draw) < self.basis_points";
      }
      {
        label = "canonical fault rates";
        needle = "rate_basis_points";
      }
      {
        label = "integer duration canonical material";
        needle = "jitter_nanos";
      }
      {
        label = "integer bandwidth canonical material";
        needle = "bits_per_second";
      }
      {
        label = "plan TOML serde schema";
        needle = "struct PlanToml";
      }
    ]
    ++ failuresFor "crates/crucible/src/decision.rs" decision [
      {
        label = "basis-point recorder API";
        needle = "pub fn decide_fault_basis_points";
      }
      {
        label = "recorder uses basis-point type";
        needle = "rate: FaultRateBasisPoints";
      }
      {
        label = "raw draw recorded first";
        needle = "let value = self.draw_u64(stream);";
      }
      {
        label = "basis-point decision derived from draw";
        needle = "let fired = rate.fires_on_draw(value);";
      }
      {
        label = "derived fault outcome recorded";
        needle = "Decision::FaultFires(FaultDecision { at, fault, fired })";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "scheduler probabilistic choice payload";
        needle = "pub struct SchedulerResolveFaultChoice";
      }
      {
        label = "scheduler payload stores basis-point rate";
        needle = "pub rate: FaultRateBasisPoints";
      }
      {
        label = "scheduler resolves with basis-point recorder";
        needle = "recorder.decide_fault_basis_points";
      }
      {
        label = "scheduler canonical material uses basis points";
        needle = "payload_rate_basis_points";
      }
      {
        label = "scheduler canonical material serializes integer rate";
        needle = "choice.rate.basis_points()";
      }
    ]
    ++ failuresFor "crates/crucible-device/src/fault.rs" deviceFault [
      {
        label = "exact integer probability";
        needle = "pub struct Probability";
      }
      {
        label = "probability modulo comparison";
        needle = "(draw % self.denominator) < self.numerator";
      }
      {
        label = "integer serialization delay";
        needle = "pub fn serialization_delay_ns";
      }
      {
        label = "wide integer delay arithmetic";
        needle = "u128::from(len_bytes) * 1_000_000_000_u128 / u128::from(bandwidth_bytes_per_sec)";
      }
      {
        label = "integer jitter transform";
        needle = "pub fn jitter_shift_ns";
      }
      {
        label = "overflow-safe jitter modulus";
        needle = "window_ns.checked_add(1)";
      }
    ]
    ++ failuresFor "crates/crucible-device/src/netlink/fault.rs" netlinkFault [
      {
        label = "netlink integer probability test";
        needle = "probability_fires_on_exact_fraction_without_float";
      }
      {
        label = "netlink integer serialization test";
        needle = "serialization_delay_is_integer_and_saturating";
      }
      {
        label = "netlink integer jitter test";
        needle = "jitter_and_reorder_shifts_stay_within_window";
      }
    ]
    ++ failuresFor "crates/crucible-device/src/netlink/link.rs" netlinkLink [
      {
        label = "serialization delay applied as integer";
        needle = "let serialization = self.faults.serialization_delay_ns(len);";
      }
      {
        label = "integer checked serialization addition";
        needle = "checked_add(serialization)";
      }
      {
        label = "integer checked jitter addition";
        needle = "checked_add(jitter)";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "decimal rate is rejected from plan fault TOML";
        needle = "rate = 1.5";
      }
      {
        label = "unsupported decimal rate parse path";
        needle = "unsupported_fault_param_toml";
      }
    ]
    ++ failuresFor "crates/crucible/tests/fault_integer_rates.rs" integerRatesTest [
      {
        label = "basis-point bucket test";
        needle = "basis_point_rates_compare_integer_buckets";
      }
      {
        label = "basis-point recorder test";
        needle = "decision_recorder_records_basis_point_faults_from_seeded_draws";
      }
      {
        label = "integer canonical material test";
        needle = "fault_canonical_material_uses_integer_rate_time_and_bandwidth_units";
      }
      {
        label = "float-free scheduled plan test";
        needle = "scheduled_plan_toml_is_float_free_for_fault_entries";
      }
      {
        label = "decimal plan fault rejection test";
        needle = "scheduled_plan_toml_rejects_decimal_fault_parameters";
      }
      {
        label = "bucket equal rate does not fire";
        needle = "bucket == rate must not fire";
      }
      {
        label = "bucket below rate fires";
        needle = "bucket < rate must fire";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_resolve_rng.rs" resolveRngTest [
      {
        label = "scheduler exact basis-point test";
        needle = "probabilistic_resolve_uses_exact_basis_point_rate_comparison";
      }
      {
        label = "scheduler test derives bucket";
        needle = "FaultRateBasisPoints::draw_bucket";
      }
      {
        label = "scheduler test stores basis-point payload";
        needle = "rate: FaultRateBasisPoints::from_basis_points";
      }
      {
        label = "scheduler boundary non-fire";
        needle = "assert_fault_decision(&record.decisions[1], &fault_a, false)";
      }
      {
        label = "scheduler boundary fire";
        needle = "assert_fault_decision(&record.decisions[3], &fault_b, true)";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 fault integer rates import";
        needle = "faultIntegerRates = import ./phase4-fault-integer-rates.nix";
      }
      {
        label = "phase4 fault integer rates attr path";
        needle = "attrPath = \"checks.crucible.phase4.faultIntegerRates\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/model.rs" model [
      {
        label = "f64 in model fault rate path";
        needle = "f64";
      }
      {
        label = "f32 in model fault rate path";
        needle = "f32";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/decision.rs" decision [
      {
        label = "raw threshold fault recorder";
        needle = "pub fn decide_fault(";
      }
      {
        label = "f64 in decision path";
        needle = "f64";
      }
      {
        label = "f32 in decision path";
        needle = "f32";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "raw threshold field in scheduler";
        needle = "fire_below";
      }
      {
        label = "raw threshold canonical material";
        needle = "payload_fire_below";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_resolve_rng.rs" resolveRngTest [
      {
        label = "raw threshold fixture";
        needle = "fire_below";
      }
    ]
    ++ forbiddenFor "crates/crucible-device/src/fault.rs" deviceFault [
      {
        label = "f64 in device fault path";
        needle = "f64";
      }
      {
        label = "f32 in device fault path";
        needle = "f32";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/fault_integer_rates.rs" integerRatesTest [
      {
        label = "f64 in integer-rates test";
        needle = "f64";
      }
      {
        label = "f32 in integer-rates test";
        needle = "f32";
      }
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "unfinished todo";
        needle = "todo!";
      }
      {
        label = "unfinished unimplemented";
        needle = "unimplemented!";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 fault-integer-rates check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-fault-integer-rates";
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
          name = "run-fault-integer-rates";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-fault-integer-rates-target" \
              -p crucible \
              --test fault_integer_rates \
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
            tasks=${taskList}
            rate_unit=basis-points
            rate_denominator=10000
            bernoulli=integer-bucket-comparison
            time_unit=virtual-nanoseconds
            bandwidth_unit=bits-per-virtual-second
            RESULT
          '';
        }
      ];
    }
