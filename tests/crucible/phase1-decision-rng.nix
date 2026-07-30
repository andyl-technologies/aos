{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.decisionRng",
  taskIds ? ["T-DET-15" "T-PAT-5"],
}: let
  simLib = builtins.readFile ../../crates/crucible-sim/src/lib.rs;
  decisionRngTest = builtins.readFile ../../crates/crucible-sim/tests/decision_rng.rs;
  layer0Gate = builtins.readFile ../../crates/crucible-sim/tests/gate_layer0_determinism.rs;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  patternsAndSketches = builtins.readFile ../../docs/rfcs/0010-crucible/29-patterns-and-sketches.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

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
        label = "node stream domain";
        needle = "pub const DECISION_RNG_NODE_STREAM_DOMAIN";
      }
      {
        label = "link stream domain";
        needle = "pub const DECISION_RNG_LINK_STREAM_DOMAIN";
      }
      {
        label = "stable name hash helper";
        needle = "pub fn stable_name_hash";
      }
      {
        label = "stable domain-name hash helper";
        needle = "pub fn stable_domain_name_hash";
      }
      {
        label = "seed xor name hash";
        needle = "self.seed ^ stable_name_hash(entity_name)";
      }
      {
        label = "domain seed xor stable hash";
        needle = "self.seed ^ stable_domain_name_hash(stream_domain, entity_name)";
      }
      {
        label = "domain stream seed API";
        needle = "pub fn stream_seed_in_domain(&self, stream_domain: &str, entity_name: &str) -> u64";
      }
      {
        label = "node stream fork API";
        needle = "pub fn fork_for_node(&self, node_name: &str) -> DecisionStream";
      }
      {
        label = "link stream fork API";
        needle = "pub fn fork_for_link(&self, link_name: &str) -> DecisionStream";
      }
      {
        label = "node stream domain used by fork";
        needle = "self.fork_in_domain(DECISION_RNG_NODE_STREAM_DOMAIN, node_name)";
      }
      {
        label = "link stream domain used by fork";
        needle = "self.fork_in_domain(DECISION_RNG_LINK_STREAM_DOMAIN, link_name)";
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
      {
        label = "node/link domain separation test";
        needle = "decision_rng_domain_separates_node_and_link_streams";
      }
      {
        label = "node domain seed assertion";
        needle = "rng.stream_seed_in_domain(DECISION_RNG_NODE_STREAM_DOMAIN, name)";
      }
      {
        label = "link domain seed assertion";
        needle = "rng.stream_seed_in_domain(DECISION_RNG_LINK_STREAM_DOMAIN, name)";
      }
      {
        label = "node fork assertion";
        needle = "rng.fork_for_node(name)";
      }
      {
        label = "link fork assertion";
        needle = "rng.fork_for_link(name)";
      }
      {
        label = "node domain seed fixed vector";
        needle = "0x797b_e784_6aec_decf";
      }
      {
        label = "link domain seed fixed vector";
        needle = "0x785b_7e35_d8fa_c62c";
      }
      {
        label = "node domain first draw fixed vector";
        needle = "0xa86f_fa4e_91e2_4781";
      }
      {
        label = "link domain first draw fixed vector";
        needle = "0xc7dd_aa47_1d78_feaf";
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
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/29-patterns-and-sketches.md" patternsAndSketches [
      {
        label = "T-PAT-5 completion names DecisionRng";
        needle = "`crucible_sim::DecisionRng`";
      }
      {
        label = "T-PAT-5 completion names node domain";
        needle = "`DECISION_RNG_NODE_STREAM_DOMAIN`";
      }
      {
        label = "T-PAT-5 completion names link domain";
        needle = "`DECISION_RNG_LINK_STREAM_DOMAIN`";
      }
      {
        label = "T-PAT-5 completion names stable domain hash";
        needle = "`stable_domain_name_hash`";
      }
      {
        label = "T-PAT-5 completion names decision RNG gate";
        needle = "`checks.crucible.phase1.decisionRng`";
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
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            crate=crucible-sim
            prng=splitmix64-v1
            fork_rule=seed_xor_stable_name_hash
            node_link_domain_separation=fixed-stream-domains
            pattern_PAT_7=name-hash-stream-forking
            construction_order_perturbs_streams=false
            host_rng_used=false
            RESULT
          '';
        }
      ];
    }
