{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.triggerVerdictComposition",
  taskIds ? ["T-TRIG-17"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libRs = builtins.readFile ../../crates/crucible/src/lib.rs;
  verdictTest = builtins.readFile ../../crates/crucible/tests/trigger_verdict_composition.rs;
  triggerDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17a-conditions-and-triggers.md;
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

  taskList = builtins.concatStringsSep "," taskIds;
  verdictSources = builtins.concatStringsSep "\n" [
    scheduler
    libRs
    verdictTest
  ];
  failures =
    failuresFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
      {
        label = "T-TRIG-17 checked off";
        needle = "- [x] **T-TRIG-17**";
      }
      {
        label = "T-TRIG-17 completion note";
        needle = "Completed by `checks.crucible.phase4.triggerVerdictComposition`";
      }
      {
        label = "event graph replay gate complete";
        needle = "Completed by `checks.crucible.phase4.gates.replayOracle`";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "assertion run verdict type";
        needle = "pub enum AssertionRunVerdict";
      }
      {
        label = "assertion failure type";
        needle = "pub struct AssertionVerdictFailure";
      }
      {
        label = "composed run verdict type";
        needle = "pub enum ComposedRunVerdict";
      }
      {
        label = "composed failure type";
        needle = "pub enum ComposedRunVerdictFailure";
      }
      {
        label = "trigger assertion composition API";
        needle = "pub fn compose_run_verdict";
      }
      {
        label = "offline event-log composition API";
        needle = "pub fn compose_run_verdict_from_event_log";
      }
      {
        label = "offline replay validates event log hashes";
        needle = "entry.has_valid_content_hash()";
      }
      {
        label = "termination request recorded";
        needle = "termination_requested";
      }
      {
        label = "explicit pass action handled";
        needle = "Action::Pass";
      }
      {
        label = "explicit fail action handled";
        needle = "Action::Fail { reason }";
      }
      {
        label = "explicit fail is sticky";
        needle = "verdict.failed_reason.is_some()";
      }
      {
        label = "assertion failures included";
        needle = "ComposedRunVerdictFailure::Assertion";
      }
      {
        label = "assertion failures normalized";
        needle = "assertion_failures.sort()";
      }
      {
        label = "trigger failures included";
        needle = "ComposedRunVerdictFailure::Trigger";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libRs [
      {
        label = "assertion run verdict exported";
        needle = "AssertionRunVerdict";
      }
      {
        label = "composed run verdict exported";
        needle = "ComposedRunVerdict";
      }
      {
        label = "composed failure exported";
        needle = "ComposedRunVerdictFailure";
      }
    ]
    ++ failuresFor "crates/crucible/tests/trigger_verdict_composition.rs" verdictTest [
      {
        label = "sticky explicit failure test";
        needle = "explicit_fail_is_sticky_over_later_pass";
      }
      {
        label = "pass updates until failure test";
        needle = "pass_updates_until_a_failure_becomes_sticky";
      }
      {
        label = "assertion failure overrides pass test";
        needle = "explicit_pass_cannot_mask_assertion_failure";
      }
      {
        label = "deterministic online offline composition test";
        needle = "trigger_fail_and_assertion_failures_compose_deterministically";
      }
      {
        label = "offline replay exercised";
        needle = "compose_run_verdict_from_event_log(&event_log_entries";
      }
      {
        label = "passing composition test";
        needle = "passed_assertions_and_trigger_pass_compose_to_pass";
      }
      {
        label = "composition API exercised";
        needle = "compose_run_verdict";
      }
      {
        label = "failed assertion verdict exercised";
        needle = "AssertionRunVerdict::failed";
      }
      {
        label = "assertion pass cannot mask test assertion";
        needle = "assertion failure should override explicit Pass";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes trigger verdict composition check";
        needle = "triggerVerdictComposition = import ./phase4-trigger-verdict-composition.nix";
      }
    ]
    ++ forbiddenFor "trigger verdict composition sources" verdictSources [
      {
        label = "trigger action decision variant";
        needle = "Decision::Trigger";
      }
      {
        label = "host wall clock";
        needle = "std::time";
      }
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending implementation panic";
        needle = "implementation is pending";
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
  then throw "crucible phase4 trigger-verdict-composition check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-trigger-verdict-composition";
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
          name = "run-trigger-verdict-composition";
          script = ''
            cargo test \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test trigger_verdict_composition \
              -- --test-threads=1
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/nix-support"
            {
              echo "attr=${attrPath}"
              echo "tasks=${taskList}"
              echo "gate=phase4-trigger-verdict-composition"
              echo "trigger_failures_are_sticky=true"
              echo "assertion_failures_override_trigger_pass=true"
              echo "online_offline_verdict_composition_identical=true"
              echo "event_log_verdict_replay=true"
              echo "verdict_termination_request_recorded=true"
            } > "$out/nix-support/metadata"
          '';
        }
      ];
    }
