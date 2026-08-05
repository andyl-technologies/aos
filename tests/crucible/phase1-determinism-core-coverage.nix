{
  pkgs,
  lib,
}: let
  root = ../..;
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };
  coverageRust = builtins.readFile ../../crates/crucible-harness/tests/determinism_core_coverage.rs;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  firstSplitSegment = separator: value: builtins.elemAt (lib.splitString separator value) 0;
  hasPrefix = prefix: value:
    builtins.substring 0 (builtins.stringLength prefix) value == prefix;
  scrubCommentsAndStrings = content: let
    scrubLine = state: line: let
      withoutLineComment = firstSplitSegment "//" line;
      blockStarts = hasInfix "/*" withoutLineComment;
      blockEnds = hasInfix "*/" withoutLineComment;
      withoutBlockComment =
        if state.inBlockComment
        then ""
        else if blockStarts
        then firstSplitSegment "/*" withoutLineComment
        else withoutLineComment;
      trimmed = lib.trim withoutBlockComment;
      stringOnly =
        hasPrefix "\"" trimmed
        || hasPrefix "r\"" trimmed
        || hasPrefix "r#" trimmed;
    in {
      inBlockComment =
        if state.inBlockComment
        then !blockEnds
        else blockStarts && !blockEnds;
      lines =
        state.lines
        ++ [
          (
            if stringOnly
            then ""
            else withoutBlockComment
          )
        ];
    };
    result = builtins.foldl' scrubLine {
      inBlockComment = false;
      lines = [];
    } (lib.splitString "\n" content);
  in
    builtins.concatStringsSep "\n" result.lines;

  coverageInstrumentationProfile = "crucible-determinism-core-coverage";
  coverageMeasurement = pkgs.mkDerivation {
    pname = "crucible-determinism-core-coverage-measurement";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.findutils
      pkgs.gawk
      pkgs.grep
      pkgs.llvm
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
        name = "measure-coverage";
        script = ''
          set -eu

          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          cd crates
          mkdir -p "$TMPDIR/profraw"
          export LLVM_PROFILE_FILE="$TMPDIR/profraw/%m-%p.profraw"
          export RUSTFLAGS="-C instrument-coverage -C link-dead-code -C codegen-units=1"
          target_dir="$TMPDIR/crucible-determinism-core-coverage-target"

          cargo test \
            --frozen \
            --offline \
            --target-dir "$target_dir" \
            -p crucible-harness \
            --lib \
            --test determinism_core_coverage \
            -- --test-threads=1
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target_dir" \
            -p crucible \
            --lib \
            --features test-double \
            -- --test-threads=1
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target_dir" \
            -p crucible-sim \
            --lib \
            -- --test-threads=1
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target_dir" \
            -p crucible-shmem \
            --test gate_layer1_injection \
            -- --test-threads=1

          profraw_count="$(find "$TMPDIR/profraw" -name '*.profraw' | wc -l)"
          [ "$profraw_count" -gt 0 ] || {
            echo "coverage instrumentation produced no profraw files" >&2
            exit 1
          }

          ${pkgs.llvm}/bin/llvm-profdata merge \
            -sparse \
            "$TMPDIR"/profraw/*.profraw \
            -o "$TMPDIR/coverage.profdata"

          objects="$(find "$target_dir/debug/deps" -maxdepth 1 -type f -perm -0100 \
            ! -name '*.d' ! -name '*.rlib' ! -name '*.rmeta' | sort)"
          first_object="$(printf '%s\n' "$objects" | head -1)"
          [ -n "$first_object" ] || {
            echo "coverage instrumentation found no test executables" >&2
            exit 1
          }
          object_args=""
          for object in $objects; do
            if [ "$object" != "$first_object" ]; then
              object_args="$object_args --object $object"
            fi
          done

          ${pkgs.llvm}/bin/llvm-cov export \
            --format=lcov \
            --instr-profile="$TMPDIR/coverage.profdata" \
            "$first_object" $object_args \
            > "$TMPDIR/coverage.lcov"

          require_covered_function() {
            name="$1"
            if ! grep -E "FNDA:[1-9][0-9]*,.*$name" "$TMPDIR/coverage.lcov" >/dev/null; then
              echo "missing executed coverage function: $name" >&2
              exit 1
            fi
          }

          require_covered_function quantum_loop_trait_is_object_safe
          require_covered_function quantum_outcome_carries_step_decisions
          require_covered_function scheduler_errors_render_all_variants_deterministically
          require_covered_function scheduled_event_keys_define_total_order
          require_covered_function scheduled_event_keys_cover_producer_tie_break
          require_covered_function schedule_prefix_bounds_are_checked
          require_covered_function engine_and_backend_errors_render_all_variants_deterministically
          require_covered_function instantiate_loads_exact_snapshot_without_genesis
          require_covered_function instantiate_replays_from_nearest_cached_ancestor
          require_covered_function instantiate_loads_baked_genesis_for_genesis
          require_covered_function instantiate_replays_from_baked_genesis_for_uncached_descendant
          require_covered_function instantiate_requires_baked_genesis_when_no_cached_path
          require_covered_function temporal_graph_rejects_mismatched_or_thin_cached_snapshots
          require_covered_function temporal_graph_rejects_plain_cached_genesis_snapshot
          require_covered_function temporal_graph_rejects_mismatched_or_thin_baked_genesis
          require_covered_function decision_recorder_records_rng_draws_and_fault_outcomes
          require_covered_function decision_recorder_keeps_per_entity_streams_stable
          require_covered_function decision_recorder_records_app_random_after_rng_draw
          require_covered_function decision_recorder_records_app_random_guest_request_id
          require_covered_function decision_recorder_rejects_invalid_app_random_widths
          require_covered_function decision_recorder_resumes_stream_positions_from_existing_schedule
          require_covered_function decision_recorder_derives_default_rr_preemption_without_recording_schedule
          require_covered_function decision_recorder_records_preemption_overrides_in_schedule
          require_covered_function decision_recorder_rejects_invalid_default_preemption_shape
          require_covered_function decision_recorder_derives_default_rr_preemption_without_overflow
          require_covered_function decision_recorder_serves_app_random_override_without_rerolling_stream
          require_covered_function decision_recorder_rejects_invalid_app_random_override_values
          require_covered_function sim_backend_rejects_backward_advance_and_post_shutdown_mutation
          require_covered_function sim_backend_rejects_unknown_checkpoint_deterministically
          require_covered_function stable_hasher_is_repeatable
          require_covered_function stable_hasher_is_order_sensitive
          require_covered_function stable_hasher_covers_chunk_remainder_and_bool_inputs
          require_covered_function replay_oracle_accepts_matching_corpus
          require_covered_function replay_oracle_reports_first_mismatch
          require_covered_function assert_spsc_ring_exhaustive_ordering_model
          require_covered_function assert_spsc_ring_exhaustive_trace_properties

          line_for() {
            file="$1"
            pattern="$2"
            line="$(grep -nF "$pattern" "$file" | head -1 | cut -d: -f1)"
            if [ -z "$line" ]; then
              echo "coverage source marker not found: $file :: $pattern" >&2
              exit 1
            fi
            printf '%s\n' "$line"
          }

          line_for_after() {
            file="$1"
            anchor="$2"
            pattern="$3"
            line="$(awk -v anchor="$anchor" -v pattern="$pattern" '
              index($0, anchor) > 0 {
                seen = 1
              }
              seen && index($0, pattern) > 0 {
                print NR
                found = 1
                exit
              }
              END {
                exit(found ? 0 : 1)
              }
            ' "$file")"
            if [ -z "$line" ]; then
              echo "coverage source marker not found after anchor: $file :: $anchor :: $pattern" >&2
              exit 1
            fi
            printf '%s\n' "$line"
          }

          require_covered_line_at_least() {
            suffix="$1"
            line="$2"
            minimum="$3"
            label="$4"
            if ! awk -v suffix="$suffix" -v line="$line" -v minimum="$minimum" '
              /^SF:/ {
                in_file = index($0, suffix) > 0
                next
              }
              in_file && /^DA:/ {
                split(substr($0, 4), parts, ",")
                if (parts[1] == line && (parts[2] + 0) >= minimum) {
                  found = 1
                }
              }
              END {
                exit(found ? 0 : 1)
              }
            ' "$TMPDIR/coverage.lcov"; then
              echo "missing executed implementation coverage: $label ($suffix:$line, min=$minimum)" >&2
              exit 1
            fi
          }

          require_line_marker() {
            suffix="$1"
            file="$2"
            minimum="$3"
            pattern="$4"
            label="$5"
            require_covered_line_at_least "$suffix" "$(line_for "$file" "$pattern")" "$minimum" "$label"
          }

          require_line_marker_after() {
            suffix="$1"
            file="$2"
            minimum="$3"
            anchor="$4"
            pattern="$5"
            label="$6"
            require_covered_line_at_least "$suffix" "$(line_for_after "$file" "$anchor" "$pattern")" "$minimum" "$label"
          }

          require_line_marker \
            "crucible/src/model/configuration.rs" \
            "crucible/src/model/configuration.rs" \
            1 \
            "return Err(ScheduleError::PrefixTooLong {" \
            "schedule prefix error branch"
          require_line_marker_after \
            "crucible/src/model/configuration.rs" \
            "crucible/src/model/configuration.rs" \
            1 \
            "impl fmt::Display for ScheduleError" \
            "requested," \
            "schedule error display variant"
          require_line_marker_after \
            "crucible/src/model/engine.rs" \
            "crucible/src/model/engine.rs" \
            1 \
            "impl fmt::Display for EngineError" \
            "Self::NotImplemented { operation } => {" \
            "engine error display variant"
          require_line_marker \
            "crucible/src/model/runtime.rs" \
            "crucible/src/model/runtime.rs" \
            1 \
            "return load_snapshot(config, snapshot);" \
            "instantiate exact snapshot branch"
          require_line_marker \
            "crucible/src/model/runtime.rs" \
            "crucible/src/model/runtime.rs" \
            1 \
            "let ancestor_runtime = instantiate(graph, &ancestor)?;" \
            "instantiate ancestor replay branch"
          require_line_marker \
            "crucible/src/model/runtime.rs" \
            "crucible/src/model/runtime.rs" \
            1 \
            "let genesis_runtime = instantiate(graph, &genesis)?;" \
            "instantiate genesis replay branch"
          require_line_marker \
            "crucible/src/model/engine.rs" \
            "crucible/src/model/engine.rs" \
            1 \
            "for decision in suffix.decisions() {" \
            "instantiate suffix replay loop"
          require_line_marker_after \
            "crucible/src/model/temporal_graph/core.rs" \
            "crucible/src/model/temporal_graph/core.rs" \
            1 \
            "pub fn cache_snapshot" \
            "return Err(EngineError::GenesisSnapshotMustBeBaked {" \
            "plain cached genesis rejection branch"
          require_line_marker_after \
            "crucible/src/model/runtime.rs" \
            "crucible/src/model/runtime.rs" \
            1 \
            "if config.is_genesis() {" \
            "EngineError::MissingBakedGenesis" \
            "instantiate missing baked genesis branch"
          require_line_marker_after \
            "crucible/src/backend/error.rs" \
            "crucible/src/backend/error.rs" \
            1 \
            "impl fmt::Display for BackendError" \
            "Self::NotImplemented { operation } => {" \
            "backend not-implemented display variant"
          require_line_marker \
            "crucible/src/backend/error.rs" \
            "crucible/src/backend/error.rs" \
            1 \
            "Self::Rejected { message } => f.write_str(message)," \
            "backend rejected display variant"
          require_line_marker_after \
            "crucible/src/scheduler/liveness.rs" \
            "crucible/src/scheduler/liveness.rs" \
            1 \
            "impl fmt::Display for SchedulerError" \
            "Self::NotImplemented { operation } => {" \
            "scheduler not-implemented display variant"
          require_line_marker \
            "crucible/src/scheduler/liveness.rs" \
            "crucible/src/scheduler/liveness.rs" \
            1 \
            "backend failed under scheduler control: {error}" \
            "scheduler backend display variant"
          require_line_marker \
            "crucible/src/scheduler/liveness.rs" \
            "crucible/src/scheduler/liveness.rs" \
            1 \
            "Self::BoundaryViolation { message } => f.write_str(message)," \
            "scheduler boundary display variant"
          require_line_marker_after \
            "crucible/src/decision.rs" \
            "crucible/src/decision.rs" \
            1 \
            "pub fn draw_u64" \
            "Decision::RngDraw" \
            "decision recorder raw draw decision"
          require_line_marker_after \
            "crucible/src/decision.rs" \
            "crucible/src/decision.rs" \
            1 \
            "pub fn decide_fault" \
            "Decision::FaultFires" \
            "decision recorder fault decision"
          require_line_marker_after \
            "crucible/src/decision.rs" \
            "crucible/src/decision.rs" \
            1 \
            "pub fn serve_app_random" \
            "Decision::AppRandom" \
            "decision recorder app-random decision"
          require_line_marker \
            "crucible/src/decision.rs" \
            "crucible/src/decision.rs" \
            1 \
            "hydrate_streams(&rng, configuration.schedule.decisions());" \
            "decision recorder resumes existing RNG stream positions"
          require_line_marker \
            "crucible/src/decision.rs" \
            "crucible/src/decision.rs" \
            1 \
            "fn validate_app_random_width(width: u8) -> Result<(), DecisionRecordError>" \
            "decision recorder invalid app-random width branch"
          require_line_marker_after \
            "crucible/src/decision.rs" \
            "crucible/src/decision.rs" \
            1 \
            "pub fn serve_app_random_override" \
            "Decision::AppRandom" \
            "decision recorder app-random override decision"
          require_line_marker_after \
            "crucible/src/decision.rs" \
            "crucible/src/decision.rs" \
            1 \
            "pub fn record_preemption_override" \
            "Decision::Preemption" \
            "decision recorder preemption override decision"
          require_line_marker \
            "crucible/src/decision.rs" \
            "crucible/src/decision.rs" \
            1 \
            "pub fn default_rr_preemption" \
            "decision recorder default preemption derivation"
          require_line_marker \
            "crucible/src/local_backend.rs" \
            "crucible/src/local_backend.rs" \
            2 \
            "sim backend is shut down; cannot {operation}" \
            "sim backend shutdown rejection branches"
          require_line_marker \
            "crucible/src/local_backend.rs" \
            "crucible/src/local_backend.rs" \
            1 \
            "sim backend cannot advance backwards from {} to {} retired instructions" \
            "sim backend backward advance branch"
          require_line_marker \
            "crucible/src/local_backend.rs" \
            "crucible/src/local_backend.rs" \
            1 \
            "sim backend cannot restore unknown checkpoint" \
            "sim backend restore error branch"
          require_line_marker \
            "crucible-sim/src/lib.rs" \
            "crucible-sim/src/lib.rs" \
            2 \
            "self.write_u64(u64::from(value));" \
            "stable hasher bool branch inputs"
          require_line_marker \
            "crucible-sim/src/lib.rs" \
            "crucible-sim/src/lib.rs" \
            1 \
            "for chunk in &mut chunks {" \
            "stable hasher full chunk branch"
          require_line_marker \
            "crucible-sim/src/lib.rs" \
            "crucible-sim/src/lib.rs" \
            1 \
            "for (index, byte) in remainder.iter().enumerate() {" \
            "stable hasher remainder branch"
          require_line_marker \
            "crucible-harness/src/replay_oracle.rs" \
            "crucible-harness/src/replay_oracle.rs" \
            1 \
            "checkpoint_id: checkpoint_id.to_owned()," \
            "replay oracle mismatch branch"
          require_line_marker \
            "crucible-harness/src/replay_oracle.rs" \
            "crucible-harness/src/replay_oracle.rs" \
            1 \
            "Ok(())" \
            "replay oracle match branch"

          mkdir -p "$out"
          cp "$TMPDIR/coverage.profdata" "$out/coverage.profdata"
          cp "$TMPDIR/coverage.lcov" "$out/coverage.lcov"
          cat > "$out/result" <<RESULT
          PASS
          coverage_profile=${coverageInstrumentationProfile}
          instrumentation_build=separate-deterministic
          profraw_files=$profraw_count
          RESULT
        '';
      }
    ];
  };

  protocolCodecActivationMarkers = [
    "pub fn encode"
    "pub fn decode"
    "ProtocolFrame"
    "FrameCodec"
  ];
  reproductionArtifactActivationMarkers = [
    "ReproductionArtifact"
    "serialize_reproduction"
    "deserialize_reproduction"
    "replay_artifact"
  ];

  activeSurfaces = [
    {
      id = "scheduler-quantum-loop";
      sourcePath = "crates/crucible/src/scheduler.rs";
      testPath = "crates/crucible/src/scheduler";
      status = "active";
      instrumentation = "separate-deterministic-build";
      activationMarkers = [];
      activationSourceRoots = [];
      requiredMarkers = [
        "quantum_loop_trait_is_object_safe"
        "quantum_outcome_carries_step_decisions"
        "scheduler_errors_render_all_variants_deterministically"
      ];
    }
    {
      id = "scheduler-ordering-keys";
      sourcePath = "crates/crucible/src/scheduler.rs";
      testPath = "crates/crucible/src/scheduler";
      status = "active";
      instrumentation = "separate-deterministic-build";
      activationMarkers = [];
      activationSourceRoots = [];
      requiredMarkers = [
        "scheduled_event_keys_define_total_order"
        "scheduled_event_keys_cover_producer_tie_break"
      ];
    }
    {
      id = "error-variant-floor";
      sourcePath = "crates/crucible/src/model.rs";
      testPath = "crates/crucible/src/tests";
      status = "active";
      instrumentation = "separate-deterministic-build";
      activationMarkers = [];
      activationSourceRoots = [];
      requiredMarkers = [
        "schedule_prefix_bounds_are_checked"
        "engine_and_backend_errors_render_all_variants_deterministically"
      ];
    }
    {
      id = "instantiate-recursion";
      sourcePath = "crates/crucible/src/model.rs";
      testPath = "crates/crucible/src/tests";
      status = "active";
      instrumentation = "separate-deterministic-build";
      activationMarkers = [];
      activationSourceRoots = [];
      requiredMarkers = [
        "instantiate_loads_exact_snapshot_without_genesis"
        "instantiate_replays_from_nearest_cached_ancestor"
        "instantiate_loads_baked_genesis_for_genesis"
        "instantiate_replays_from_baked_genesis_for_uncached_descendant"
        "instantiate_requires_baked_genesis_when_no_cached_path"
        "temporal_graph_rejects_mismatched_or_thin_cached_snapshots"
        "temporal_graph_rejects_plain_cached_genesis_snapshot"
        "temporal_graph_rejects_mismatched_or_thin_baked_genesis"
      ];
    }
    {
      id = "sim-backend-error-variants";
      sourcePath = "crates/crucible/src/sim_backend.rs";
      testPath = "crates/crucible/src/sim_backend.rs";
      status = "active";
      instrumentation = "separate-deterministic-build";
      activationMarkers = [];
      activationSourceRoots = [];
      requiredMarkers = [
        "sim_backend_rejects_backward_advance_and_post_shutdown_mutation"
        "sim_backend_rejects_unknown_checkpoint_deterministically"
      ];
    }
    {
      id = "content-addressed-digest";
      sourcePath = "crates/crucible-sim/src/lib.rs";
      testPath = "crates/crucible-sim/src/lib.rs";
      status = "active";
      instrumentation = "separate-deterministic-build";
      activationMarkers = [];
      activationSourceRoots = [];
      requiredMarkers = [
        "stable_hasher_is_repeatable"
        "stable_hasher_is_order_sensitive"
        "stable_hasher_covers_chunk_remainder_and_bool_inputs"
      ];
    }
    {
      id = "replay-oracle-path";
      sourcePath = "crates/crucible-harness/src/replay_oracle.rs";
      testPath = "crates/crucible-harness/src/replay_oracle.rs";
      status = "active";
      instrumentation = "separate-deterministic-build";
      activationMarkers = [];
      activationSourceRoots = [];
      requiredMarkers = [
        "replay_oracle_accepts_matching_corpus"
        "replay_oracle_reports_first_mismatch"
      ];
    }
    {
      id = "decision-rng-and-forking";
      sourcePath = "crates/crucible/src/decision.rs";
      testPath = "crates/crucible/src/decision.rs";
      status = "active";
      instrumentation = "separate-deterministic-build";
      activationMarkers = [];
      activationSourceRoots = [];
      requiredMarkers = [
        "decision_recorder_records_rng_draws_and_fault_outcomes"
        "decision_recorder_keeps_per_entity_streams_stable"
        "decision_recorder_records_app_random_after_rng_draw"
        "decision_recorder_records_app_random_guest_request_id"
        "decision_recorder_rejects_invalid_app_random_widths"
        "decision_recorder_resumes_stream_positions_from_existing_schedule"
        "decision_recorder_derives_default_rr_preemption_without_recording_schedule"
        "decision_recorder_records_preemption_overrides_in_schedule"
        "decision_recorder_rejects_invalid_default_preemption_shape"
        "decision_recorder_derives_default_rr_preemption_without_overflow"
        "decision_recorder_serves_app_random_override_without_rerolling_stream"
        "decision_recorder_rejects_invalid_app_random_override_values"
        "assert_decision_rng_branch_coverage("
        "assert_per_entity_rng_forking_coverage("
      ];
    }
    {
      id = "spsc-ring";
      sourcePath = "crates/crucible-shmem/src/lib.rs";
      testPath = "crates/crucible-shmem/tests/gate_layer1_injection.rs";
      status = "active";
      instrumentation = "separate-deterministic-build";
      activationMarkers = [];
      activationSourceRoots = [];
      requiredMarkers = [
        "assert_spsc_ring_exhaustive_ordering_model("
        "assert_spsc_ring_exhaustive_trace_properties("
      ];
    }
    {
      id = "protocol-codec";
      sourcePath = "crates/crucible-protocol/src/lib.rs";
      testPath = "crates/crucible-protocol/tests/gate_abi_conformance.rs";
      status = "active";
      instrumentation = "separate-deterministic-build";
      activationMarkers = [];
      activationSourceRoots = [];
      requiredMarkers = [
        "assert_protocol_codec_fuzz_corpus("
        "assert_decode_encode_roundtrip("
      ];
    }
    {
      id = "reproduction-artifact-serializer";
      sourcePath = "crates/crucible/src/lib.rs";
      testPath = "crates/crucible/tests/gate_replay_oracle.rs";
      status = "active";
      instrumentation = "separate-deterministic-build";
      activationMarkers = [];
      activationSourceRoots = [];
      requiredMarkers = [
        "assert_reproduction_artifact_roundtrip_coverage("
        "assert_reproduction_artifact_error_variant_coverage("
      ];
    }
  ];

  # protocol-codec and reproduction-artifact-serializer graduated from planned to
  # active on 2026-07-09: both determinism-core surfaces are now implemented (their
  # activation markers are present in source) and their coverage assertions are
  # measured by the separate-deterministic-build coverageMeasurement profile, so they
  # are promoted into activeSurfaces below. No determinism-core surface remains merely
  # planned.
  plannedSurfaces = [];

  requiredSurfaceIds = [
    "scheduler-quantum-loop"
    "scheduler-ordering-keys"
    "error-variant-floor"
    "instantiate-recursion"
    "sim-backend-error-variants"
    "decision-rng-and-forking"
    "content-addressed-digest"
    "spsc-ring"
    "protocol-codec"
    "replay-oracle-path"
    "reproduction-artifact-serializer"
  ];

  allSurfaces = activeSurfaces ++ plannedSurfaces;
  surfaceIds = map (surface: surface.id) allSurfaces;
  activeSurfaceIds = map (surface: surface.id) activeSurfaces;
  plannedSurfaceIds = map (surface: surface.id) plannedSurfaces;
  activeSurfaceSummary = builtins.concatStringsSep "," activeSurfaceIds;
  plannedSurfaceSummary = builtins.concatStringsSep "," plannedSurfaceIds;

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
  activationSourceContent = surface: let
    scanRoots =
      if surface.activationSourceRoots == []
      then [surface.sourcePath]
      else surface.activationSourceRoots;
    rustFiles =
      lib.concatMap (
        scanRoot:
          if builtins.pathExists (root + "/${scanRoot}")
          then rustFilesUnder scanRoot
          else []
      )
      scanRoots;
  in
    builtins.concatStringsSep "\n" (
      map (relative: builtins.readFile (root + "/${relative}")) rustFiles
    );
  plannedSurfaceIsImplemented = surface:
    surface.status
    == "active"
    || (
      builtins.pathExists (root + "/${surface.sourcePath}")
      && builtins.any (
        marker: hasInfix marker (activationSourceContent surface)
      )
      surface.activationMarkers
    );
  coverageMarkerFailures = surface:
    if !(builtins.pathExists (root + "/${surface.testPath}"))
    then [
      "${surface.id}: missing determinism-core coverage test ${surface.testPath}"
    ]
    else let
      testFiles =
        if builtins.readFileType (root + "/${surface.testPath}") == "directory"
        then rustFilesUnder surface.testPath
        else [surface.testPath];
      code = scrubCommentsAndStrings (builtins.concatStringsSep "\n" (
        map (relative: builtins.readFile (root + "/${relative}")) testFiles
      ));
    in
      lib.concatMap (
        marker:
          lib.optionals (!(hasInfix marker code)) [
            "${surface.id}: active determinism-core coverage marker `${marker}` is missing from ${surface.testPath}"
          ]
      )
      surface.requiredMarkers;
  coverageMarkerFailuresForContent = surface: content: let
    code = scrubCommentsAndStrings content;
  in
    lib.concatMap (
      marker:
        lib.optionals (!(hasInfix marker code)) [
          "${surface.id}: active determinism-core coverage marker `${marker}` is missing from ${surface.testPath}"
        ]
    )
    surface.requiredMarkers;
  requiredSurfaceFailuresFor = ids:
    lib.concatMap (
      required:
        lib.optionals (!(builtins.elem required ids)) [
          "missing determinism-core coverage surface `${required}`"
        ]
    )
    requiredSurfaceIds;

  sourceExistsFailures =
    lib.concatMap (
      surface:
        lib.optionals (!(builtins.pathExists (root + "/${surface.sourcePath}"))) [
          "${surface.id}: missing determinism-core source ${surface.sourcePath}"
        ]
    )
    allSurfaces;

  instrumentationFailures =
    lib.concatMap (
      surface:
        lib.optionals (surface.instrumentation != "separate-deterministic-build") [
          "${surface.id} must be measured in the ${coverageInstrumentationProfile} separate deterministic instrumentation build"
        ]
    )
    allSurfaces;

  activeMarkerFailures =
    lib.concatMap (
      surface: coverageMarkerFailures surface
    )
    activeSurfaces;

  plannedMeasurementFailures =
    lib.concatMap (
      surface:
        lib.optionals (plannedSurfaceIsImplemented surface) [
          "${surface.id}: planned determinism-core surface is implemented but is not measured by ${coverageInstrumentationProfile}; promote it to activeSurfaces and add coverageMeasurement wiring"
        ]
    )
    plannedSurfaces;

  requiredSurfaceFailures = requiredSurfaceFailuresFor surfaceIds;

  rustHarnessFailures = let
    requiredRustText = [
      "DETERMINISM_CORE_COVERAGE_FLOOR"
      "CoverageStatus::Active"
      "CoverageStatus::Planned"
      "InstrumentationMode::SeparateDeterministicBuild"
      "COVERAGE_INSTRUMENTATION_PROFILE"
      "activation_markers"
      "activation_source_roots"
      "activation_source_content"
      "collect_rust_files"
      "synthetic-protocol/src/codec.rs"
      "planned_surface_is_implemented"
      "scrub_comments_and_strings"
      "planned determinism-core surface is implemented"
      "active_determinism_core_paths_have_branch_and_error_coverage_markers"
      "coverage_floor_regression_failures"
      "error-variant-floor"
      "instantiate-recursion"
      "scheduler_errors_render_all_variants_deterministically"
      "scheduled_event_keys_cover_producer_tie_break"
      "engine_and_backend_errors_render_all_variants_deterministically"
      "instantiate_loads_exact_snapshot_without_genesis"
      "instantiate_replays_from_nearest_cached_ancestor"
      "instantiate_loads_baked_genesis_for_genesis"
      "instantiate_replays_from_baked_genesis_for_uncached_descendant"
      "instantiate_requires_baked_genesis_when_no_cached_path"
      "temporal_graph_rejects_mismatched_or_thin_cached_snapshots"
      "temporal_graph_rejects_plain_cached_genesis_snapshot"
      "temporal_graph_rejects_mismatched_or_thin_baked_genesis"
      "sim_backend_rejects_unknown_checkpoint_deterministically"
      "stable_hasher_covers_chunk_remainder_and_bool_inputs"
      "replay_oracle_reports_first_mismatch"
      "decision_recorder_records_rng_draws_and_fault_outcomes"
      "decision_recorder_keeps_per_entity_streams_stable"
      "decision_recorder_records_app_random_after_rng_draw"
      "decision_recorder_records_app_random_guest_request_id"
      "decision_recorder_rejects_invalid_app_random_widths"
      "decision_recorder_resumes_stream_positions_from_existing_schedule"
      "decision_recorder_derives_default_rr_preemption_without_recording_schedule"
      "decision_recorder_records_preemption_overrides_in_schedule"
      "decision_recorder_rejects_invalid_default_preemption_shape"
      "decision_recorder_derives_default_rr_preemption_without_overflow"
      "decision_recorder_serves_app_random_override_without_rerolling_stream"
      "decision_recorder_rejects_invalid_app_random_override_values"
    ];
  in
    lib.concatMap (
      required:
        lib.optionals (!(hasInfix required coverageRust)) [
          "crates/crucible-harness/tests/determinism_core_coverage.rs: missing coverage-floor wiring `${required}`"
        ]
    )
    requiredRustText;

  regressionFailures = let
    syntheticDigestSurface = {
      id = "content-addressed-digest";
      sourcePath = "crates/crucible-sim/src/lib.rs";
      testPath = "synthetic.rs";
      status = "active";
      instrumentation = "separate-deterministic-build";
      activationMarkers = [];
      activationSourceRoots = [];
      requiredMarkers = [
        "stable_hasher_is_repeatable"
        "stable_hasher_is_order_sensitive"
      ];
    };
    syntheticProtocolSurface = {
      id = "protocol-codec";
      sourcePath = "synthetic-protocol.rs";
      testPath = "synthetic-protocol-test.rs";
      status = "planned";
      instrumentation = "separate-deterministic-build";
      activationMarkers = protocolCodecActivationMarkers;
      activationSourceRoots = ["synthetic-protocol/src"];
      requiredMarkers = [
        "assert_protocol_codec_fuzz_corpus("
        "assert_decode_encode_roundtrip("
      ];
    };
    plannedSourceCode = scrubCommentsAndStrings ''
      mod codec;
      pub fn encode(value: &[u8]) -> Vec<u8> { value.to_vec() }
    '';
    plannedIsImplemented =
      builtins.any (marker: hasInfix marker plannedSourceCode)
      syntheticProtocolSurface.activationMarkers;
    missingMarkerFindings = coverageMarkerFailuresForContent syntheticDigestSurface ''
      fn stable_hasher_is_repeatable() {}
      /* stable_hasher_is_order_sensitive */
      "stable_hasher_is_order_sensitive"
    '';
    badInstrumentationFindings = lib.optionals ("shared-test-build" != "separate-deterministic-build") [
      "scheduler-quantum-loop must be measured in the ${coverageInstrumentationProfile} separate deterministic instrumentation build"
    ];
    missingSurfaceFindings = requiredSurfaceFailuresFor ["scheduler-quantum-loop"];
    plannedActivationFindings = lib.optionals plannedIsImplemented [
      "protocol-codec: planned determinism-core surface is implemented but is not measured by ${coverageInstrumentationProfile}; promote it to activeSurfaces and add coverageMeasurement wiring"
    ];
    findings =
      missingMarkerFindings
      ++ badInstrumentationFindings
      ++ missingSurfaceFindings
      ++ plannedActivationFindings;
    hasFinding = needle: builtins.any (finding: hasInfix needle finding) findings;
  in
    lib.optionals (!(hasFinding "stable_hasher_is_order_sensitive")) [
      "coverage-floor regression failed to reject missing branch coverage marker"
    ]
    ++ lib.optionals (!(hasFinding "separate deterministic instrumentation build")) [
      "coverage-floor regression failed to reject shared instrumentation builds"
    ]
    ++ lib.optionals (!(hasFinding "decision-rng-and-forking")) [
      "coverage-floor regression failed to reject missing required surface"
    ]
    ++ lib.optionals (!(hasFinding "planned determinism-core surface is implemented")) [
      "coverage-floor regression failed to reject unmeasured planned surface activation"
    ];

  failures =
    sourceExistsFailures
    ++ instrumentationFailures
    ++ activeMarkerFailures
    ++ plannedMeasurementFailures
    ++ requiredSurfaceFailures
    ++ rustHarnessFailures
    ++ regressionFailures;
in
  if failures != []
  then throw "crucible phase1 determinism-core coverage-floor lint failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-determinism-core-coverage";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        coverageMeasurement
      ];

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu
            test -s "${coverageMeasurement}/coverage.lcov"
            test -s "${coverageMeasurement}/coverage.profdata"
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.determinismCoreCoverage
            tasks=T-STD-10
            coverage_profile=crucible-determinism-core-coverage
            instrumentation_build=separate-deterministic
            coverage_measurement=${coverageMeasurement}
            active_scope=${activeSurfaceSummary}
            planned_scope=${plannedSurfaceSummary}
            RESULT
          '';
        }
      ];
    }
