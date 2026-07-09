{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.decisionRecording",
  taskIds ? ["T-DET-16" "T-DET-31" "T-EXEC-19" "T-EXEC-20" "T-PAT-5"],
}: let
  root = ../..;
  decisionRust = builtins.readFile ../../crates/crucible/src/decision.rs;
  modelRust = builtins.readFile ../../crates/crucible/src/model.rs;
  libRust = builtins.readFile ../../crates/crucible/src/lib.rs;
  manifest = builtins.readFile ../../crates/crucible/Cargo.toml;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  executionModel = builtins.readFile ../../docs/rfcs/0010-crucible/05-execution-model.md;
  patternsAndSketches = builtins.readFile ../../docs/rfcs/0010-crucible/29-patterns-and-sketches.md;
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

  engineCode =
    builtins.concatStringsSep "\n" (
      map (relative: builtins.readFile (root + "/${relative}"))
      (rustFilesUnder "crates/crucible/src")
    );
  scrubLintVocabulary = content:
    builtins.replaceStrings
    [
      ''"thread_rng"''
      ''"rand::"''
      ''"rand::rng"''
      ''"rand::random"''
      ''"DefaultHasher"''
      ''"RandomState"''
      ''"HashMap"''
    ]
    [
      ''"lint-vocabulary-thread-rng"''
      ''"lint-vocabulary-rand-path"''
      ''"lint-vocabulary-rand-rng"''
      ''"lint-vocabulary-rand-random"''
      ''"lint-vocabulary-default-hasher"''
      ''"lint-vocabulary-random-state"''
      ''"lint-vocabulary-hash-map"''
    ]
    content;
  engineCodeOutsideLintVocabulary =
    builtins.concatStringsSep "\n" (
      map (
        relative: let
          content = builtins.readFile (root + "/${relative}");
        in
          if relative == "crates/crucible/src/trigger.rs"
          then scrubLintVocabulary content
          else content
      )
      (rustFilesUnder "crates/crucible/src")
    );
  engineCodeOutsideDecision =
    builtins.concatStringsSep "\n" (
      map (relative: builtins.readFile (root + "/${relative}"))
      (builtins.filter (
          relative:
            relative != "crates/crucible/src/decision.rs"
            && relative != "crates/crucible/src/model.rs"
        )
        (rustFilesUnder "crates/crucible/src"))
    );

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
    failuresFor "crates/crucible/src/decision.rs" decisionRust [
      {
        label = "decision recorder type";
        needle = "pub struct DecisionRecorder";
      }
      {
        label = "seeded decision RNG ownership";
        needle = "rng: DecisionRng";
      }
      {
        label = "per-stream fork cache";
        needle = "streams: BTreeMap<RngStreamId, DecisionStream>";
      }
      {
        label = "domain-aware name-hash fork path";
        needle = ".or_insert_with(|| self.rng.fork_in_domain(&stream.domain, &stream.name))";
      }
      {
        label = "existing schedule hydration";
        needle = "hydrate_streams(&rng, configuration.schedule.decisions())";
      }
      {
        label = "raw draw is recorded";
        needle = "Decision::RngDraw";
      }
      {
        label = "recorded raw draw carries stream id";
        needle = "Decision::RngDraw(RngDecision { stream, value })";
      }
      {
        label = "probabilistic fault is recorded";
        needle = "Decision::FaultFires";
      }
      {
        label = "app-random draw is recorded";
        needle = "Decision::AppRandom";
      }
      {
        label = "app-random draw carries stream id";
        needle = "Decision::AppRandom(AppRandomDecision {\n            node,\n            stream,";
      }
      {
        label = "app-random request-id path";
        needle = "pub fn serve_app_random_request";
      }
      {
        label = "app-random override path";
        needle = "pub fn serve_app_random_override";
      }
      {
        label = "default RR preemption derivation";
        needle = "pub fn default_rr_preemption";
      }
      {
        label = "preemption override recording";
        needle = "pub fn record_preemption_override";
      }
      {
        label = "schedule append path";
        needle = "self.configuration = step(&self.configuration, decision);";
      }
      {
        label = "branch coverage marker";
        needle = "assert_decision_rng_branch_coverage(";
      }
      {
        label = "per-entity coverage marker";
        needle = "assert_per_entity_rng_forking_coverage(";
      }
      {
        label = "node/link domain separation coverage marker";
        needle = "decision_recorder_domain_separates_same_name_node_and_link_streams";
      }
      {
        label = "resume coverage marker";
        needle = "decision_recorder_resumes_stream_positions_from_existing_schedule";
      }
      {
        label = "app-random request-id coverage marker";
        needle = "decision_recorder_records_app_random_guest_request_id";
      }
      {
        label = "preemption default coverage marker";
        needle = "decision_recorder_derives_default_rr_preemption_without_recording_schedule";
      }
      {
        label = "preemption override coverage marker";
        needle = "decision_recorder_records_preemption_overrides_in_schedule";
      }
      {
        label = "preemption invalid-shape coverage marker";
        needle = "decision_recorder_rejects_invalid_default_preemption_shape";
      }
      {
        label = "preemption overflow coverage marker";
        needle = "decision_recorder_derives_default_rr_preemption_without_overflow";
      }
      {
        label = "app-random override coverage marker";
        needle = "decision_recorder_serves_app_random_override_without_rerolling_stream";
      }
      {
        label = "domain-aware resume expected stream";
        needle = "fork_in_domain(&stream.domain, &stream.name)";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" modelRust [
      {
        label = "RngStreamId type";
        needle = "pub struct RngStreamId";
      }
      {
        label = "RngStreamId domain field";
        needle = "pub domain: String";
      }
      {
        label = "RngStreamId default constructor";
        needle = "pub fn from_name(name: impl Into<String>) -> Self";
      }
      {
        label = "RngStreamId node constructor";
        needle = "pub fn for_node(name: impl Into<String>) -> Self";
      }
      {
        label = "RngStreamId link constructor";
        needle = "pub fn for_link(name: impl Into<String>) -> Self";
      }
      {
        label = "RngStreamId node domain constant";
        needle = "DECISION_RNG_NODE_STREAM_DOMAIN";
      }
      {
        label = "RngStreamId link domain constant";
        needle = "DECISION_RNG_LINK_STREAM_DOMAIN";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libRust [
      {
        label = "decision module";
        needle = "pub mod decision;";
      }
      {
        label = "decision recorder export";
        needle = "pub use decision::{DecisionRecordError, DecisionRecorder};";
      }
    ]
    ++ failuresFor "crates/crucible/Cargo.toml" manifest [
      {
        label = "engine depends on deterministic L0 primitives";
        needle = "crucible-sim = { path = \"../crucible-sim\" }";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismContract [
      {
        label = "T-DET-16 checklist complete";
        needle = "- [x] **T-DET-16**";
      }
      {
        label = "T-DET-31 checklist complete";
        needle = "- [x] **T-DET-31**";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/05-execution-model.md" executionModel [
      {
        label = "T-EXEC-2 checklist complete";
        needle = "- [x] **T-EXEC-2**";
      }
      {
        label = "EXEC-9 requires recorded RngStreamId";
        needle = "A `Decision::RngDraw` MUST record its\n  `RngStreamId`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/29-patterns-and-sketches.md" patternsAndSketches [
      {
        label = "T-PAT-5 checklist complete";
        needle = "- [x] **T-PAT-5**";
      }
      {
        label = "T-PAT-5 completion names decision recorder";
        needle = "`crucible::decision::DecisionRecorder`";
      }
      {
        label = "T-PAT-5 completion names RngStreamId";
        needle = "`RngStreamId`";
      }
      {
        label = "T-PAT-5 completion says RngStreamId is domain-qualified";
        needle = "domain-qualified `RngStreamId`";
      }
      {
        label = "T-PAT-5 completion names decision recording gate";
        needle = "`checks.crucible.phase1.decisionRecording`";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes decision recording check";
        needle = "decisionRecording = import ./phase1-decision-recording.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/src outside lint vocabulary" engineCodeOutsideLintVocabulary [
      {
        label = "ambient rand crate use";
        needle = "rand::";
      }
      {
        label = "thread/global RNG";
        needle = "thread_rng";
      }
      {
        label = "default randomized hasher";
        needle = "DefaultHasher";
      }
      {
        label = "randomized hash state";
        needle = "RandomState";
      }
      {
        label = "host wall clock";
        needle = "SystemTime::now";
      }
      {
        label = "host monotonic clock";
        needle = "Instant::now";
      }
      {
        label = "host monotonic clock import";
        needle = "std::time::Instant";
      }
      {
        label = "ordering-significant unordered map";
        needle = "HashMap";
      }
    ]
    ++ forbiddenFor "crates/crucible/src outside decision.rs" engineCodeOutsideDecision [
      {
        label = "direct decision RNG import outside recorder";
        needle = "use crucible_sim::DecisionRng";
      }
      {
        label = "direct decision RNG grouped import outside recorder";
        needle = "DecisionRng,";
      }
      {
        label = "direct decision RNG construction outside recorder";
        needle = "DecisionRng::new";
      }
      {
        label = "direct decision RNG field outside recorder";
        needle = "rng: DecisionRng,";
      }
      {
        label = "direct decision stream use outside recorder";
        needle = "DecisionStream";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 decision recording check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-decision-recording";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils];

      phases = [
        {
          name = "record-decision-recording";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            gate=gate:layer0-determinism
            tasks=${builtins.concatStringsSep "," taskIds}
            crate=crucible
            recorder=DecisionRecorder
            rng_source=crucible-sim::DecisionRng
            app_random_source=single-seeded-decision-rng
            app_random_stream_fork=per-node-stream-name
            app_random_records=RngDraw+Decision::AppRandom
            schedule_records=rng-draw,fault-fires,app-random,preemption-override
            default_preemption=derived-audit-only
            app_random_request_id=caller-supplied
            app_random_override=recorded-value-no-reroll
            pattern_PAT_7_recording=draws-carry-rng-stream-id
            engine_ambient_randomness=false
            ambient_fw_cfg_entropy=separate-launch-entropy
            RESULT
          '';
        }
      ];
    }
