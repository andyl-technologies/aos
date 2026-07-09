{
  attrPath ? "checks.crucible.phase6.triageCliSurface",
  dependencies ? [],
  lib,
  pkgs,
  taskIds ? ["T-TRI-8"],
}: let
  # Substring scan by index. The regex form (builtins.match ".*needle.*")
  # overflows the Nix regex engine's stack on large haystacks such as the CLI
  # main.rs, so use a linear index walk instead.
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
    builtins.any (index: builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (! hasInfix requirement.needle content) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  forbiddenFailuresFor = fileLabel: content: forbidden:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    forbidden;

  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  triageDoc = builtins.readFile ../../docs/rfcs/0010-crucible/34-failure-triage.md;
  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  cliSource = builtins.readFile ../../crates/crucible-cli/src/main.rs;
  defaultChecks = builtins.readFile ./default.nix;
  taskList = builtins.concatStringsSep "," taskIds;

  failures =
    failuresFor "docs/rfcs/0010-crucible/34-failure-triage.md" triageDoc [
      {
        label = "T-TRI-8 checked off";
        needle = "- [x] **T-TRI-8**";
      }
      {
        label = "T-TRI-8 completion note";
        needle = "Completed by `checks.crucible.phase6.triageCliSurface`";
      }
      {
        label = "forward reference resolved";
        needle = "`crucible triage` is added to 23's CLI surface";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "triage in closed subcommand set";
        needle = "triage     Cluster, dedup, and minimize discovered failures (34).";
      }
      {
        label = "triage command shape";
        needle = "crucible triage <FINDINGS> [FLAGS]";
      }
      {
        label = "policy help copy";
        needle = "--policy <coarse|default|fine|exact>";
      }
      {
        label = "minimize help copy";
        needle = "--minimize <none|representative|all>";
      }
      {
        label = "report help copy";
        needle = "--report <dir>";
      }
      {
        label = "markdown format help copy";
        needle = "--format <jsonl|json|table|markdown>";
      }
      {
        label = "triage markdown scope";
        needle = "`markdown` is reserved";
      }
      {
        label = "recompute help copy";
        needle = "--recompute-signatures";
      }
      {
        label = "compare help copy";
        needle = "--compare <other-triage-result>";
      }
      {
        label = "uniform triage exit code one";
        needle = "cluster's minimization failed its signature-preservation assertion";
      }
      {
        label = "malformed ledger exit";
        needle = "`5` = malformed/unresolvable findings ledger or artifact";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/34-failure-triage.md" triageDoc [
      {
        label = "single findings path copy";
        needle = "a content hash of a stored ledger, or one artifact/ledger file path";
      }
      {
        label = "jsonl default copy";
        needle = "--format <jsonl|json|table|markdown>     Report rendering (§34.5.2). Default: jsonl.";
      }
      {
        label = "usage parse exit note";
        needle = "parse-time usage errors";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "T-TRI-8 plan summary";
        needle = "`T-TRI-8` is green through";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliSource [
      {
        label = "command factory help rendering";
        needle = "use clap::CommandFactory;";
      }
      {
        label = "triage help regression";
        needle = "cli_triage_help_surface_lists_required_flags_and_exit_code_contract";
      }
      {
        label = "top-level help rendering";
        needle = "render_long_help";
      }
      {
        label = "try_parse main";
        needle = "Cli::try_parse()";
      }
      {
        label = "parse error exit helper";
        needle = "fn cli_parse_error_exit_code";
      }
      {
        label = "triage subcommand help lookup";
        needle = "find_subcommand_mut(\"triage\")";
      }
      {
        label = "format value set";
        needle = "value_name = \"jsonl|json|table|markdown\"";
      }
      {
        label = "policy value set";
        needle = "value_name = \"coarse|default|fine|exact\"";
      }
      {
        label = "minimize value set";
        needle = "value_name = \"none|representative|all\"";
      }
      {
        label = "triage exit code";
        needle = "Self::Triage(_) => 1";
      }
      {
        label = "backend exit code";
        needle = "Self::Backend(_) => 4";
      }
      {
        label = "artifact exit code";
        needle = "Self::Artifact(_) => 5";
      }
      {
        label = "usage exit code";
        needle = "Self::Usage(_) => 64";
      }
      {
        label = "missing findings parse regression";
        needle = "missing triage findings must be a parse error";
      }
      {
        label = "invalid policy parse regression";
        needle = "invalid triage policy must be a parse error";
      }
      {
        label = "focused cargo test in source gate";
        needle = "cli_triage_help_surface_lists_required_flags_and_exit_code_contract";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "triage CLI surface wiring";
        needle = "triageCliSurface = greenBeforeAdvance";
      }
      {
        label = "triage CLI surface attr path";
        needle = "checks.crucible.phase6.triageCliSurface";
      }
      {
        label = "triage CLI surface gate import";
        needle = "phase6-triage-cli-surface.nix";
      }
      {
        label = "triage CLI surface task id";
        needle = "taskIds = [\"T-TRI-8\"]";
      }
      {
        label = "triage thin-driver raw dependency";
        needle = "phase6.triageThinDriver.rawGate";
      }
      {
        label = "CLI skeleton dependency";
        needle = "phase5.cliSkeleton";
      }
    ]
    ++ forbiddenFailuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "stale triage file link";
        needle = "34-triage-clustering.md";
      }
      {
        label = "boolean minimize copy";
        needle = "--minimize                Minimize";
      }
    ]
    ++ forbiddenFailuresFor "docs/rfcs/0010-crucible/34-failure-triage.md" triageDoc [
      {
        label = "unsupported glob findings copy";
        needle = "glob of artifact files";
      }
      {
        label = "stale table default";
        needle = "Default: table.";
      }
    ];

in
  if failures != []
  then throw "crucible phase6 triage CLI surface check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-triage-cli-surface";
      version = "0";
      src = crucibleSrc;

      buildDeps =
        [
          pkgs.coreutils
          pkgs.rust
          pkgs.sed
        ]
        ++ dependencies;

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
          name = "run-triage-cli-surface-test";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-triage-cli-surface-target" \
              -p crucible-cli \
              --bin crucible \
              cli_triage_help_surface_lists_required_flags_and_exit_code_contract \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out/nix-support"
            {
              echo "crucible_gate=phase6-triage-cli-surface"
              echo "attr_path=${attrPath}"
              echo "task_ids=${taskList}"
              echo "cargo_deps=${cargoDeps}"
              echo "rust_test=crucible-cli::cli_triage_help_surface_lists_required_flags_and_exit_code_contract"
            } > "$out/nix-support/hydra-build-products"
          '';
        }
      ];
    }
