{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliResumeWorkflow",
  taskIds ? ["T-CLI-10"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  cliMain = import ./_cli-source.nix {inherit lib;};
  cliMachineReadable = builtins.readFile ../../crates/crucible-cli/tests/machine_readable.rs;
  campaignProcessTest = builtins.readFile ../../crates/crucible-cli/tests/campaign_process.rs;
  cliCampaignRun = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-cli/src/cli/campaign_run.rs;
  };
  daemonCampaignLifecycle = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-daemon/src/qemu_campaign_lifecycle.rs;
  };
  apiVmLifecycle = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-api/src/vm_lifecycle.rs;
  };
  defaultChecks = builtins.readFile ./default.nix;

  hasInfix = needle: haystack:
    needle
    == ""
    || builtins.replaceStrings [needle] [""] haystack != haystack;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  forbiddenFor = fileLabel: content: forbidden:
    lib.concatMap (
      item:
        lib.optionals (hasInfix item.needle content) [
          "${fileLabel}: forbidden ${item.label}: `${item.needle}`"
        ]
    )
    forbidden;

  failures =
    failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-10 completion";
        needle = "[x] **T-CLI-10** Implement Campaign-owned `resume` from an authenticated";
      }
      {
        label = "source replay from genesis";
        needle = "replays the source attempt from scenario genesis";
      }
      {
        label = "version-nine exact capture";
        needle = "captures one workflow-local version-nine exact descriptor";
      }
      {
        label = "fresh continuation process";
        needle = "fresh QEMU process as an `AfterAttempt` continuation";
      }
      {
        label = "closed fallback policy";
        needle = "No remote/session, cached-parent, or nearest-checkpoint fallback";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI resume completion";
        needle = "`T-CLI-10` is completed through `checks.crucible.phase5.cliResumeWorkflow`";
      }
      {
        label = "authenticated Campaign savepoint";
        needle = "accepts only an authenticated portable Campaign savepoint";
      }
      {
        label = "production exact-resume lifecycle";
        needle = "production exact-resume lifecycle";
      }
      {
        label = "closed model fallback";
        needle = "model-only fallbacks are rejected";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "resume arguments";
        needle = "struct ResumeArgs";
      }
      {
        label = "resume savepoint handle decoder";
        needle = "fn decode_savepoint_handle";
      }
      {
        label = "resume planner";
        needle = "fn plan_resume_invocation";
      }
      {
        label = "authenticated replay closure field";
        needle = "campaign-replay-closure";
      }
      {
        label = "bare hash rejection regression";
        needle = "cli_resume_workflow_rejects_bare_hash_without_authenticated_handle";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/cli/campaign_run.rs" cliCampaignRun [
      {
        label = "campaign resume admission";
        needle = "fn guarded_campaign_resume_eligible";
      }
      {
        label = "campaign-owned QEMU resume";
        needle = "fn run_local_qemu_campaign_resume_workflow";
      }
      {
        label = "authenticated resume result";
        needle = "campaign completed without authenticated resume evidence";
      }
      {
        label = "transient exact-store cleanup";
        needle = "fn complete_transient_checkpoint_workflow";
      }
    ]
    ++ failuresFor "crates/crucible-daemon/src/qemu_campaign_lifecycle.rs" daemonCampaignLifecycle [
      {
        label = "exact resume entry";
        needle = "pub fn begin_resume";
      }
      {
        label = "repository resume authentication";
        needle = "install_attempt_production_resume_checkpoint(";
      }
      {
        label = "production exact lifecycle construction";
        needle = "build_production_vm_exact_resume_lifecycle(";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/vm_lifecycle.rs" apiVmLifecycle [
      {
        label = "authenticated exact-resume lifecycle";
        needle = "pub fn build_production_vm_exact_resume_lifecycle";
      }
      {
        label = "decoded exact checkpoint authority";
        needle = "decoded: DecodedProductionExactCheckpoint";
      }
    ]
    ++ failuresFor "crates/crucible-cli/tests/machine_readable.rs" cliMachineReadable [
    ]
    ++ failuresFor "crates/crucible-cli/tests/campaign_process.rs" campaignProcessTest [
      {
        label = "packaged Campaign save and native resume regression";
        needle = "campaign_virtual_time_save_feeds_native_resume";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI resume workflow check";
        needle = "cliResumeWorkflow = import ./phase5-cli-resume-workflow.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 CLI resume workflow check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-cli-resume-workflow";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

      ATTR_PATH = attrPath;
      TASK_IDS = builtins.concatStringsSep "," taskIds;
      OPEN_TASK_IDS = builtins.concatStringsSep "," openTaskIds;
      DEPENDENCY_COUNT = toString (builtins.length dependencies);
      DEPENDENCY_PATHS = builtins.concatStringsSep ":" dependencies;

      phases = [
        {
          name = "unpack";
          script = ''
            set -eu
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "configure";
          script = ''
            set -eu
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
          name = "run-cli-resume-workflow";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-resume-workflow-target" \
              -p crucible-cli \
              cli_resume \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-resume-workflow-target" \
              -p crucible-cli \
              campaign_virtual_time_save_exports_closure_for_resume_and_replay_readers \
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
            check=$ATTR_PATH
            tasks=$TASK_IDS
            open_tasks=$OPEN_TASK_IDS
            status=complete
            evidence_scope=campaign-exact-resume-unit-and-process-admission
            component=crucible-cli
            contract=authenticated-campaign-resume
            process_qemu_resume=packaged-live-asset-admission
            dependencies=$DEPENDENCY_COUNT
            RESULT
          '';
        }
      ];
    }
