{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.faultDecisionRng",
  taskIds ? ["T-FAULT-3"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  decision = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/src/decision.rs;
  };
  device = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/src/device.rs;
  };
  deviceSubnode = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/src/device_subnode.rs;
  };
  libSource = import ./_crucible-tests-source.nix {inherit lib;};
  resolveRngTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/tests/scheduler_resolve_rng.rs;
  };
  faultDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17-fault-injection.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  faultDecisionSources = builtins.concatStringsSep "\n" [
    scheduler
    decision
    device
    deviceSubnode
    resolveRngTest
  ];
  failures =
    failuresFor "docs/rfcs/0010-crucible/17-fault-injection.md" faultDoc [
      {
        label = "T-FAULT-3 completion note";
        needle = "Completed by `checks.crucible.phase4.faultDecisionRng`";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "probabilistic choice payload";
        needle = "pub struct SchedulerResolveFaultChoice";
      }
      {
        label = "probabilistic resolve helper";
        needle = "pub fn resolve_probabilistic_decisions";
      }
      {
        label = "canonical event order";
        needle = "for event in ordered_scheduled_events(resolved_events)";
      }
      {
        label = "seeded scheduler recorder";
        needle = "DecisionRecorder::new(configuration)";
      }
      {
        label = "fault outcome recording";
        needle = "recorder.decide_fault_basis_points";
      }
      {
        label = "live quantum probabilistic resolve";
        needle = "resolve_probabilistic_decisions_from_seed(";
      }
      {
        label = "rng draw cursor update";
        needle = "Decision::RngDraw(draw)";
      }
      {
        label = "per-stream cursor update";
        needle = "advance_decision_rng_cursor_for(draw.stream.clone())";
      }
    ]
    ++ failuresFor "crates/crucible/src/decision.rs" decision [
      {
        label = "seeded recorder construction";
        needle = "let rng = configuration.def.seed().decision_rng();";
      }
      {
        label = "schedule hydration";
        needle = "fn hydrate_streams";
      }
      {
        label = "hydrate from recorded rng draws";
        needle = "if let Decision::RngDraw(RngDecision { stream, .. }) = decision";
      }
      {
        label = "fault decision API";
        needle = "pub fn decide_fault";
      }
      {
        label = "fault draw through stream";
        needle = "let value = self.draw_u64(stream);";
      }
      {
        label = "fault outcome decision";
        needle = "Decision::FaultFires(FaultDecision { at, fault, fired })";
      }
      {
        label = "recorded outcome API";
        needle = "pub fn record_fault_outcome";
      }
    ]
    ++ failuresFor "crates/crucible/src/device.rs" device [
      {
        label = "device stream id";
        needle = "pub fn device_stream_id";
      }
      {
        label = "device stream name-hash domain";
        needle = "RngStreamId::for_device";
      }
      {
        label = "device fault recorder";
        needle = "pub fn record_device_fault";
      }
      {
        label = "device fault raw draw";
        needle = "recorder.draw_u64(stream)";
      }
      {
        label = "device fault recorded outcome";
        needle = "recorder.record_fault_outcome";
      }
      {
        label = "link fault recorded decisions";
        needle = "pub fn emit_link_frame_with_recorded_faults";
      }
      {
        label = "link raw draw decisions";
        needle = "Decision::RngDraw(RngDecision";
      }
      {
        label = "link fault outcome decisions";
        needle = "push_link_fault_outcome";
      }
    ]
    ++ failuresFor "crates/crucible/src/device_subnode.rs" deviceSubnode [
      {
        label = "device-subnode ordered recompute";
        needle = "fn resolve_all";
      }
      {
        label = "device RNG from seed and device id";
        needle = "crate::device::device_rng(self.seed, &self.device_id, before)";
      }
      {
        label = "device stream id";
        needle = "crate::device::device_stream_id(&self.device_id)";
      }
      {
        label = "device-subnode raw draw decisions";
        needle = "Decision::RngDraw(RngDecision";
      }
      {
        label = "device-subnode fault outcome decisions";
        needle = "push_fault_outcome";
      }
      {
        label = "block device fault RNG regression";
        needle = "fault_choices_are_drawn_from_the_device_rng_and_recorded_as_decisions";
      }
      {
        label = "9p device fault RNG regression";
        needle = "ninep_fault_choices_use_the_same_scheduler_bridge";
      }
      {
        label = "block recorded fired outcome";
        needle = "the loss fault outcome must be recorded as fired";
      }
      {
        label = "9p recorded fired outcome";
        needle = "the 9p duplicate fault outcome must be recorded as fired";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "reproduction artifact replay test";
        needle = "reproduction_artifact_is_self_contained_and_replay_checked";
      }
      {
        label = "recorded fault outcome in replay artifact";
        needle = "Decision::FaultFires(FaultDecision";
      }
      {
        label = "recorded RNG draw in replay artifact";
        needle = "Decision::RngDraw(RngDecision";
      }
      {
        label = "offline recorded artifact replay";
        needle = "ReproductionArtifact::from_recorded_parts";
      }
      {
        label = "artifact replay execution";
        needle = ".replay()";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_resolve_rng.rs" resolveRngTest [
      {
        label = "total-order probabilistic test";
        needle = "probabilistic_resolve_records_rng_draw_and_fault_outcome_in_total_order";
      }
      {
        label = "prior schedule hydration test";
        needle = "probabilistic_resolve_hydrates_streams_from_prior_schedule_decisions";
      }
      {
        label = "deterministic event ignore test";
        needle = "resolve_probabilistic_decisions_ignores_deterministic_events";
      }
      {
        label = "recorded replay no reroll test";
        needle = "probabilistic_fault_replay_records_outcome_without_rerolling";
      }
      {
        label = "recorded schedule replay test";
        needle = "recorded_probabilistic_fault_schedule_replay_uses_recorded_outcome";
      }
      {
        label = "link stream domain used";
        needle = "RngStreamId::for_link";
      }
      {
        label = "raw draw assertion";
        needle = "Decision::RngDraw";
      }
      {
        label = "fault outcome assertion";
        needle = "Decision::FaultFires";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 fault decision RNG import";
        needle = "faultDecisionRng = import ./phase4-fault-decision-rng.nix";
      }
      {
        label = "phase4 fault decision RNG attr path";
        needle = "attrPath = \"checks.crucible.phase4.faultDecisionRng\"";
      }
    ]
    ++ forbiddenFor "fault decision RNG sources" faultDecisionSources [
      {
        label = "host wall-clock";
        needle = "SystemTime::now";
      }
      {
        label = "host monotonic time";
        needle = "Instant::now";
      }
      {
        label = "thread/global RNG";
        needle = "thread_rng";
      }
      {
        label = "thread/global RNG";
        needle = "rand::rng";
      }
      {
        label = "thread/global RNG";
        needle = "rand::random";
      }
      {
        label = "host RNG";
        needle = "OsRng";
      }
      {
        label = "host RNG";
        needle = "getrandom";
      }
      {
        label = "host thread scheduling";
        needle = "std::thread";
      }
      {
        label = "host thread scheduling";
        needle = "sleep(";
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
  then throw "crucible phase4 fault-decision-rng check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-fault-decision-rng";
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
          name = "run-fault-decision-rng";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-fault-decision-rng-target" \
              -p crucible \
              --test scheduler_resolve_rng \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-fault-decision-rng-target" \
              -p crucible \
              decision_recorder_records_rng_draws_and_fault_outcomes \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-fault-decision-rng-target" \
              -p crucible \
              link_emit_records_seeded_rng_draws_fault_outcomes_and_cursor \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-fault-decision-rng-target" \
              -p crucible \
              fault_choices_are_drawn_from_the_device_rng_and_recorded_as_decisions \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-fault-decision-rng-target" \
              -p crucible \
              ninep_fault_choices_use_the_same_scheduler_bridge \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-fault-decision-rng-target" \
              -p crucible \
              reproduction_artifact_is_self_contained_and_replay_checked \
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
            component=crucible-faults
            probabilistic_faults=seeded-decision-rng
            ordering=scheduler-total-order
            recorded_decisions=RngDraw+FaultFires
            replay_reroll=false
            RESULT
          '';
        }
      ];
    }
