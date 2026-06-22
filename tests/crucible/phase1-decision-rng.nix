{
  pkgs,
  lib,
}: let
  simLib = builtins.readFile ../../crates/crucible-sim/src/lib.rs;
  decisionRngTest = builtins.readFile ../../crates/crucible-sim/tests/decision_rng.rs;
  layer0Gate = builtins.readFile ../../crates/crucible-sim/tests/gate_layer0_determinism.rs;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  defaultChecks = builtins.readFile ./default.nix;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  failures =
    failuresFor "crates/crucible-sim/src/lib.rs" simLib [
      {
        label = "decision RNG type";
        needle = "pub struct DecisionRng";
      }
      {
        label = "decision stream type";
        needle = "pub struct DecisionStream";
      }
      {
        label = "fixed PRNG algorithm";
        needle = "pub const DECISION_RNG_ALGORITHM: &str = \"splitmix64-v1\";";
      }
      {
        label = "stable name hash domain";
        needle = "pub const DECISION_RNG_NAME_HASH_DOMAIN";
      }
      {
        label = "stable name hash helper";
        needle = "pub fn stable_name_hash";
      }
      {
        label = "seed xor name hash";
        needle = "self.seed ^ stable_name_hash(entity_name)";
      }
      {
        label = "fixed PRNG implementation";
        needle = "fn splitmix64";
      }
    ]
    ++ forbiddenFor "crates/crucible-sim/src/lib.rs" simLib [
      {
        label = "default randomized hasher";
        needle = "DefaultHasher";
      }
      {
        label = "host/thread RNG";
        needle = "thread_rng";
      }
      {
        label = "ambient random";
        needle = "rand::random";
      }
    ]
    ++ failuresFor "crates/crucible-sim/tests/decision_rng.rs" decisionRngTest [
      {
        label = "seed XOR stable hash test";
        needle = "decision_rng_forks_by_seed_xor_stable_name_hash";
      }
      {
        label = "construction-order independence test";
        needle = "decision_rng_streams_are_independent_of_construction_order";
      }
      {
        label = "fixed algorithm test";
        needle = "decision_rng_uses_fixed_cross_platform_algorithm";
      }
      {
        label = "known-vector stream";
        needle = "DecisionRng::new(0).fork(\"known-vector\")";
      }
      {
        label = "first splitmix64 vector";
        needle = "0xfe32_417a_273f_d586";
      }
      {
        label = "second splitmix64 vector";
        needle = "0x44bf_2b53_3f3e_07fd";
      }
      {
        label = "name and seed sensitivity test";
        needle = "decision_rng_streams_change_with_name_and_seed";
      }
    ]
    ++ failuresFor "crates/crucible-sim/tests/gate_layer0_determinism.rs" layer0Gate [
      {
        label = "layer0 gate uses real decision RNG";
        needle = "DecisionRng::new";
      }
      {
        label = "layer0 gate uses stable name hash";
        needle = "stable_name_hash";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismContract [
      {
        label = "T-DET-15 checklist complete";
        needle = "- [x] **T-DET-15**";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes decision RNG check";
        needle = "decisionRng = import ./phase1-decision-rng.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 decision RNG check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-decision-rng";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils];

      phases = [
        {
          name = "record-decision-rng";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.decisionRng
            tasks=T-DET-15
            crate=crucible-sim
            prng=splitmix64-v1
            fork_rule=seed_xor_stable_name_hash
            construction_order_perturbs_streams=false
            host_rng_used=false
            RESULT
          '';
        }
      ];
    }
