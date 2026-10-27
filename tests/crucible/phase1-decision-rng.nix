{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.decisionRng",
  taskIds ? ["T-DET-15" "T-PAT-5"],
}: let
  simLib = builtins.readFile ../../crates/crucible/crucible-determinism/src/lib.rs;
  decisionRngTest = builtins.readFile ../../crates/crucible/crucible-determinism/tests/decision_rng.rs;
  layer0Gate = builtins.readFile ../../crates/crucible/crucible-determinism/tests/gate_layer0_determinism.rs;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  patternsAndSketches = builtins.readFile ../../docs/rfcs/0010-crucible/29-patterns-and-sketches.md;
  rngDrawModel = builtins.readFile ../../crates/crucible/crucible-engine/src/model/materialized/rng_draw.rs;
  decisionCodec = builtins.readFile ../../crates/crucible/crucible-engine/src/model/binary_state.rs;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "crates/crucible/crucible-determinism/src/lib.rs" simLib [
      {
        label = "decision RNG type";
        needle = "pub struct DecisionRng";
      }
      {
        label = "decision stream type";
        needle = "pub struct DecisionStream";
      }
      {
        label = "keyed PRNG algorithm";
        needle = "pub const DECISION_RNG_ALGORITHM: &str = \"keyed-blake3-v2\";";
      }
      {
        label = "refused legacy algorithm";
        needle = "pub const DECISION_RNG_LEGACY_ALGORITHM: &str = \"splitmix64-v1\";";
      }
      {
        label = "world-key derivation context";
        needle = "pub const DECISION_RNG_WORLD_KEY_CONTEXT";
      }
      {
        label = "stable name domain";
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
        label = "BLAKE3 world-key derivation";
        needle = "blake3::derive_key(DECISION_RNG_WORLD_KEY_CONTEXT";
      }
      {
        label = "BLAKE3 keyed draw";
        needle = "blake3::Hasher::new_keyed(&self.stream_key)";
      }
      {
        label = "length-prefixed draw fields";
        needle = "fn write_length_prefixed";
      }
      {
        label = "position-addressed draw";
        needle = "pub fn draw_at(&self, position: u64) -> u64";
      }
      {
        label = "event-keyed stream API";
        needle = "pub fn event_in_domain(";
      }
      {
        label = "domain stream id API";
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
    ]
    ++ forbiddenFor "crates/crucible/crucible-determinism/src/lib.rs" simLib [
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
      {
        label = "sequential legacy PRNG";
        needle = "fn splitmix64";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-determinism/tests/decision_rng.rs" decisionRngTest [
      {
        label = "published-derivation reference test";
        needle = "decision_rng_matches_the_published_derivation";
      }
      {
        label = "construction-order independence test";
        needle = "decision_rng_streams_are_independent_of_construction_order";
      }
      {
        label = "draw-order independence test";
        needle = "decision_rng_event_draws_are_independent_of_draw_order";
      }
      {
        label = "fixed vector test";
        needle = "decision_rng_keeps_fixed_cross_platform_vectors";
      }
      {
        label = "known-vector stream";
        needle = "DecisionRng::new(0).fork(\"known-vector\")";
      }
      {
        label = "first keyed vector";
        needle = "0x1e76_8e32_8b90_978a";
      }
      {
        label = "second keyed vector";
        needle = "0x7227_aa57_219e_8e38";
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
        label = "length-prefix separation test";
        needle = "decision_rng_length_prefixes_keep_adjacent_fields_apart";
      }
      {
        label = "algorithm naming test";
        needle = "decision_rng_names_the_keyed_algorithm_and_refused_legacy";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-determinism/tests/gate_layer0_determinism.rs" layer0Gate [
      {
        label = "layer0 gate uses real decision RNG";
        needle = "DecisionRng::new";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/src/model/materialized/rng_draw.rs" rngDrawModel [
      {
        label = "recorded draws carry a typed address";
        needle = "pub address: RngDrawAddress,";
      }
      {
        label = "link-frame draw address";
        needle = "LinkFrame {";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/src/model/binary_state.rs" decisionCodec [
      {
        label = "unaddressed draw encoding is refused";
        needle = "rng draw without a draw address is a retired decision encoding and is refused";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismContract [
      {
        label = "DET-26 requires recorded draw addresses";
        needle = "recorded draw MUST carry its stream and its full draw address";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/29-patterns-and-sketches.md" patternsAndSketches [
      {
        label = "T-PAT-5 completion names DecisionRng";
        needle = "`crucible_determinism::DecisionRng`";
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
        label = "T-PAT-5 completion names keyed derivation";
        needle = "`keyed-blake3-v2`";
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
            prng=keyed-blake3-v2
            fork_rule=blake3_keyed_stream_key
            refused_legacy=splitmix64-v1
            recorded_draw_address=ordinal,link-frame
            node_link_domain_separation=fixed-stream-domains
            pattern_PAT_7=keyed-stream-derivation
            construction_order_perturbs_streams=false
            host_rng_used=false
            RESULT
          '';
        }
      ];
    }
