{
  pkgs,
  lib,
}: let
  phase0S4 = import ./phase0-s4.nix {inherit pkgs;};

  shmemSource = builtins.concatStringsSep "\n" [
    (import ./_crucible-shmem-source.nix {inherit lib;})
    (builtins.readFile ../../crates/crucible-shmem/src/shmem/delivery_errors.rs)
  ];
  lookaheadTest = builtins.readFile ../../crates/crucible-shmem/tests/lookahead_gate.rs;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "crates/crucible-shmem/src/lib.rs + shmem/delivery_errors.rs" shmemSource [
      {
        label = "opaque advance ceiling type";
        needle = "pub struct AdvanceCeiling";
      }
      {
        label = "advance ceiling current accessor";
        needle = "pub fn current_icount(&self) -> u64";
      }
      {
        label = "advance ceiling max accessor";
        needle = "pub fn max_advance_icount(&self) -> u64";
      }
      {
        label = "lookahead ceiling helper";
        needle = "pub fn authorize_advance_ceiling";
      }
      {
        label = "possible delivery rejection";
        needle = "AdvanceReachesPossibleDelivery";
      }
      {
        label = "late delivery rejection";
        needle = "DeliveryAlreadyPassed";
      }
      {
        label = "future delivery validation helper";
        needle = "pub fn validate_frame_delivery_is_future";
      }
      {
        label = "ceiling blocks possible delivery";
        needle = "max_advance_icount >= earliest_possible_delivery_icount";
      }
      {
        label = "late frame blocks passed delivery";
        needle = "frame.delivery_icount < consumer_current_icount";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/tests/lookahead_gate.rs" lookaheadTest [
      {
        label = "authorized ceiling test";
        needle = "lookahead_gate_authorizes_ceiling_before_possible_delivery";
      }
      {
        label = "ceiling at possible delivery rejection test";
        needle = "lookahead_gate_rejects_ceiling_at_possible_delivery";
      }
      {
        label = "ceiling past possible delivery rejection test";
        needle = "lookahead_gate_rejects_ceiling_past_possible_delivery";
      }
      {
        label = "ceiling before current rejection test";
        needle = "lookahead_gate_rejects_ceiling_before_current_icount";
      }
      {
        label = "exact-current delivery admission test";
        needle = "lookahead_gate_allows_exact_current_delivery_icount";
      }
      {
        label = "passed delivery rejection test";
        needle = "lookahead_gate_rejects_already_passed_delivery_icount";
      }
      {
        label = "exact delivery after future enqueue test";
        needle = "lookahead_gate_allows_future_frame_to_deliver_at_exact_icount";
      }
    ]
    ++ forbiddenFor "crates/crucible-shmem/tests/lookahead_gate.rs" lookaheadTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
    ]
    ++ forbiddenFor "crates/crucible-shmem/src/lib.rs + shmem/delivery_errors.rs" shmemSource [
      {
        label = "public current icount field bypass";
        needle = "pub struct AdvanceCeiling {\n    pub current_icount: u64";
      }
      {
        label = "public max advance icount field bypass";
        needle = "pub struct AdvanceCeiling {\n    current_icount: u64,\n    pub max_advance_icount: u64";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismContract [
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes lookahead gate check";
        needle = "lookaheadGate = import ./phase1-lookahead-gate.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 lookahead gate check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-lookahead-gate";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
      ];

      phases = [
        {
          name = "record-lookahead-gate";
          script = ''
            set -eu
            s4_result="${phase0S4}/result"

            grep -q '^PASS$' "$s4_result"
            grep -q '^consumer_ceiling=delivery_icount_minus_1_until_group_present$' "$s4_result"
            grep -q '^producer_skew_ceiling_wait_observed=true$' "$s4_result"
            grep -q '^consumer_skew_early_peek_observed=true$' "$s4_result"
            grep -q '^late_enqueue_negative_control_failed=true$' "$s4_result"
            grep -q '^late_delivery_failures=0$' "$s4_result"
            grep -q '^early_delivery_failures=0$' "$s4_result"

            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.lookaheadGate
            tasks=T-DET-12
            crate=crucible-shmem
            lookahead_helper=authorize_advance_ceiling
            late_delivery_helper=validate_frame_delivery_is_future
            ceiling_rule=max_advance_icount_lt_earliest_possible_delivery_icount
            late_delivery_policy=fail_loudly
            phase0_evidence=checks.crucible.phase0.s4ShmemVisibility
            RESULT
          '';
        }
      ];
    }
