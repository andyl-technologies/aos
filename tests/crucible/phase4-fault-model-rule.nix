{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.faultModelRule",
  taskIds ? ["T-FAULT-2"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  harnessLint = builtins.readFile ../../crates/crucible-harness/tests/harness_lint.rs;
  harnessScan = builtins.readFile ../../crates/crucible-harness/tests/support/harness_lint/scan.rs;
  faultRuleTest = builtins.readFile ../../crates/crucible/tests/fault_model_rule.rs;
  faultDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17-fault-injection.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  faultApplySources = builtins.concatStringsSep "\n" [
    scheduler
    faultRuleTest
  ];
  failures =
    failuresFor "docs/rfcs/0010-crucible/17-fault-injection.md" faultDoc [
      {
        label = "T-FAULT-2 completion note";
        needle = "Completed by `checks.crucible.phase4.faultModelRule`";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "fault effect application path";
        needle = "fn apply_trigger_effect";
      }
      {
        label = "atomic cloned trigger action state";
        needle = "let mut trigger_actions = self.trigger_actions.clone();";
      }
      {
        label = "state committed after event log append";
        needle = "self.trigger_actions = trigger_actions;";
      }
      {
        label = "fault injection touches modeled active faults";
        needle = "state.active_faults.insert(tag.clone(), fault.clone())";
      }
      {
        label = "fault heal touches modeled active faults";
        needle = "state.active_faults.remove(tag)";
      }
      {
        label = "fault application receives world topology read-only";
        needle = "self.trigger_static_topology.as_ref()";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/support/harness_lint/scan.rs" harnessScan [
      {
        label = "fault apply path lint function";
        needle = "pub(super) fn fault_apply_path_failures";
      }
      {
        label = "fault apply required patterns";
        needle = "FAULT_APPLY_REQUIRED_PATTERNS";
      }
      {
        label = "fault apply forbidden patterns";
        needle = "FAULT_APPLY_FORBIDDEN_PATTERNS";
      }
      {
        label = "fault apply source extractor";
        needle = "function_token_range(&tokens, \"apply_trigger_effect\")";
      }
      {
        label = "host filesystem rejected";
        needle = "host filesystem";
      }
      {
        label = "host thread scheduling rejected";
        needle = "host thread scheduling";
      }
      {
        label = "topology mutation rejected";
        needle = "topology mutation";
      }
      {
        label = "fault lint wired into custom tier";
        needle = "findings.extend(fault_apply_path_failures(path, content));";
      }
      {
        label = "fault apply direct effect guard";
        needle = "fault_apply_direct_effect_failures";
      }
      {
        label = "comment and string resistant fault effects";
        needle = "scrub_comments_and_strings(content)";
      }
      {
        label = "thread RNG catalog entry";
        needle = "\"rand::rng\"";
      }
      {
        label = "entropy catalog entry";
        needle = "\"from_entropy\"";
      }
      {
        label = "host RNG catalog entry";
        needle = "\"OsRng\"";
      }
      {
        label = "host getrandom catalog entry";
        needle = "\"getrandom\"";
      }
      {
        label = "filesystem read_dir catalog entry";
        needle = "\"read_dir\"";
      }
      {
        label = "filesystem metadata catalog entry";
        needle = "\"metadata\"";
      }
      {
        label = "scheduler topology catalog entry";
        needle = "\"SchedulerLookaheadGraph\"";
      }
      {
        label = "world topology catalog entry";
        needle = "\"WorldStaticTopology\"";
      }
      {
        label = "effective topology catalog entry";
        needle = "\"with_effective_topology_edges\"";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/harness_lint.rs" harnessLint [
      {
        label = "fault apply path lint regression";
        needle = "harness_lint_rejects_host_or_topology_mutation_in_fault_apply_path";
      }
      {
        label = "fault apply path directness regression";
        needle = "harness_lint_rejects_non_direct_fault_apply_path_effects";
      }
      {
        label = "real scheduler fault apply path regression";
        needle = "harness_lint_accepts_scheduler_fault_apply_path";
      }
      {
        label = "scheduler custom-tier fault apply path regression";
        needle = "harness_lint_custom_static_analysis_covers_scheduler_fault_apply_path";
      }
      {
        label = "host wall-clock regression assertion";
        needle = "assert_contains(&findings, \"host wall-clock\")";
      }
      {
        label = "topology mutation regression assertion";
        needle = "assert_contains(&findings, \"topology mutation\")";
      }
    ]
    ++ failuresFor "crates/crucible/tests/fault_model_rule.rs" faultRuleTest [
      {
        label = "modeled-only fault test";
        needle = "fault_application_changes_active_faults_not_schedule_or_static_topology";
      }
      {
        label = "fault injection action exercised";
        needle = "Action::InjectFault";
      }
      {
        label = "fault heal action exercised";
        needle = "Action::HealFault";
      }
      {
        label = "schedule unchanged";
        needle = "assert_eq!(scheduler.configuration().schedule, before_schedule)";
      }
      {
        label = "scheduler static topology unchanged";
        needle = "assert_eq!(scheduler.trigger_static_topology(), Some(&before_topology))";
      }
      {
        label = "world static topology unchanged";
        needle = "assert_eq!(world.static_topology(), before_world_topology)";
      }
      {
        label = "fault path does not append schedule decisions";
        needle = "SchedulerEventLogPayload::Decision(_)";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 fault model rule import";
        needle = "faultModelRule = import ./phase4-fault-model-rule.nix";
      }
      {
        label = "phase4 fault model rule attr path";
        needle = "attrPath = \"checks.crucible.phase4.faultModelRule\"";
      }
    ]
    ++ forbiddenFor "fault apply modeled-only sources" faultApplySources [
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
        needle = "rand::random";
      }
      {
        label = "thread/global RNG";
        needle = "rand::rng";
      }
      {
        label = "thread/global RNG";
        needle = "from_entropy";
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
        label = "host filesystem";
        needle = "std::fs";
      }
      {
        label = "host filesystem";
        needle = "fs::";
      }
      {
        label = "host filesystem";
        needle = "File::";
      }
      {
        label = "host filesystem";
        needle = "read_dir";
      }
      {
        label = "host filesystem";
        needle = "metadata";
      }
      {
        label = "host thread scheduling";
        needle = "std::thread";
      }
      {
        label = "host thread scheduling";
        needle = "thread::sleep";
      }
      {
        label = "host thread scheduling";
        needle = "thread::spawn";
      }
      {
        label = "host thread scheduling";
        needle = "yield_now";
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
  then throw "crucible phase4 fault-model-rule check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-fault-model-rule";
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
          name = "run-fault-model-rule";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-fault-model-rule-target" \
              -p crucible \
              --test fault_model_rule \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-fault-model-rule-target" \
              -p crucible-harness \
              --test harness_lint \
              fault_apply_path \
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
            modeled_behavior_only=true
            fault_apply_host_dependencies=forbidden
            fault_apply_topology_mutation=forbidden
            RESULT
          '';
        }
      ];
    }
