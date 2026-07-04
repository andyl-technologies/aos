{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliReplayCheck",
  taskIds ? ["T-CLI-12"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  cliMain = builtins.readFile ../../crates/crucible-cli/src/main.rs;
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

  failures =
    failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-12 remains open";
        needle = "- [ ] **T-CLI-12** Implement `replay`";
      }
      {
        label = "T-CLI-12 replay check progress note";
        needle = "Work in progress under `checks.crucible.phase5.cliReplayCheck`";
      }
      {
        label = "replay bisect progress";
        needle = "artifact-to-artifact `--bisect <other-artifact>`";
      }
      {
        label = "content-addressed replay component resolution progress";
        needle = "resolves missing content-addressed component payloads";
      }
      {
        label = "replay identity before store progress";
        needle = "pinned identity path before store access";
      }
      {
        label = "replay inline store validation progress";
        needle = "validates declared DAG-store references against inline payloads";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI replay check progress note";
        needle = "`T-CLI-12` remains open. `checks.crucible.phase5.cliReplayCheck` currently";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "replay check flag";
        needle = "check: Option<PathBuf>";
      }
      {
        label = "replay bisect flag";
        needle = "bisect: Option<PathBuf>";
      }
      {
        label = "replay canonical log reconstruction";
        needle = "let canonical_log_bytes = canonical_log_entry_bytes(&canonical_log);";
      }
      {
        label = "replay component hydration";
        needle = "fn hydrate_replay_artifact_components";
      }
      {
        label = "replay component store URI resolution";
        needle = "parse_blake3_content_hash(\"component store URI\"";
      }
      {
        label = "replay bisect implementation";
        needle = "fn replay_bisect_artifacts";
      }
      {
        label = "replay bisect divergence error";
        needle = "replay --bisect divergence";
      }
      {
        label = "dedicated replay check error";
        needle = "CliError::ReplayCheck";
      }
      {
        label = "byte mismatch diagnostic";
        needle = "replay --check mismatch";
      }
      {
        label = "byte mismatch first difference";
        needle = "first_diff_byte=";
      }
      {
        label = "byte mismatch length diagnostics";
        needle = "original_len=";
      }
      {
        label = "byte mismatch replayed length diagnostics";
        needle = "replayed_len=";
      }
      {
        label = "byte-identical replay check test";
        needle = "cli_replay_check_accepts_byte_identical_canonical_log";
      }
      {
        label = "content-addressed component replay test";
        needle = "cli_replay_resolves_content_addressed_component_payloads";
      }
      {
        label = "externalized identity priority test";
        needle = "cli_replay_externalized_identity_mismatch_keeps_identity_exit";
      }
      {
        label = "inline payload store URI mismatch test";
        needle = "cli_replay_rejects_inline_component_store_uri_mismatch";
      }
      {
        label = "replay check uses public JSONL trace bytes";
        needle = "emit_canonical_trace(OutputFormat::Jsonl";
      }
      {
        label = "replay check reconstructs decision payload summaries";
        needle = "fn decision_payload_summary";
      }
      {
        label = "mismatched replay check test";
        needle = "cli_replay_check_rejects_mismatch_with_failure_exit";
      }
      {
        label = "replay help advertises check";
        needle = "--check <original-log>";
      }
      {
        label = "replay help advertises bisect";
        needle = "--bisect <other-artifact>";
      }
      {
        label = "future replay --to remains rejected";
        needle = "\"--to\", \"savepoint\"";
      }
      {
        label = "replay bisect divergence test";
        needle = "cli_replay_bisects_artifact_divergence";
      }
      {
        label = "replay bisect identical test";
        needle = "cli_replay_bisect_accepts_identical_artifacts";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI replay check";
        needle = "cliReplayCheck = import ./phase5-cli-replay-check.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 CLI replay check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-cli-replay-check";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

      ATTR_PATH = attrPath;
      TASK_IDS = builtins.concatStringsSep "," taskIds;
      DEPENDENCY_COUNT = toString (builtins.length dependencies);
      DEPENDENCY_PATHS = builtins.concatStringsSep ":" dependencies;

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
          name = "run-cli-replay-check";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-replay-check-target" \
              -p crucible-cli \
              cli_replay \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-replay-check-target" \
              -p crucible-cli \
              cli_help_surface_rejects_unimplemented_future_flags \
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
            component=crucible-cli
            replay_check=byte-identical-canonical-log
            dependencies=$DEPENDENCY_COUNT
            RESULT
          '';
        }
      ];
    }
