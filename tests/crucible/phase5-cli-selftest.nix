{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliSelftest",
  taskIds ? ["T-CLI-8"],
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
  cliManifest = builtins.readFile ../../crates/crucible-cli/Cargo.toml;
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
        label = "T-CLI-8 remains open";
        needle = "- [ ] **T-CLI-8** Implement `selftest`";
      }
      {
        label = "T-CLI-8 progress note";
        needle = "Work in progress under `checks.crucible.phase5.cliSelftest`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI selftest progress note";
        needle = "`T-CLI-8` remains open. `checks.crucible.phase5.cliSelftest` currently";
      }
    ]
    ++ failuresFor "crates/crucible-cli/Cargo.toml" cliManifest [
      {
        label = "CLI dev-tests against canonical gate catalog";
        needle = "crucible-harness = { path = \"../crucible-harness\" }";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "selftest gates flag";
        needle = "gates: Option<String>";
      }
      {
        label = "selftest qemu flag";
        needle = "with_qemu: bool";
      }
      {
        label = "built-in corpus selftest gate subset";
        needle = "BUILT_IN_CORPUS_SELFTEST_GATES";
      }
      {
        label = "canonical gate validation";
        needle = "CANONICAL_GATE_NAMES";
      }
      {
        label = "canonical gate catalog drift test";
        needle = "cli_selftest_canonical_gate_names_match_harness_catalog";
      }
      {
        label = "dev-test canonical gate catalog source";
        needle = "crucible_harness::canonical_gates()";
      }
      {
        label = "selftest gate planner";
        needle = "fn plan_selftest_gates";
      }
      {
        label = "per-gate selftest report";
        needle = "struct SelftestGateReport";
      }
      {
        label = "per-gate output row";
        needle = "crucible: selftest gate=";
      }
      {
        label = "built-in corpus runner";
        needle = "crucible::built_in_example_corpus";
      }
      {
        label = "selected gates test";
        needle = "gate:replay-oracle";
      }
      {
        label = "empty gate entry rejection";
        needle = "empty selftest gate component must be rejected";
      }
      {
        label = "duplicate gate rejection";
        needle = "duplicate selftest gate must be rejected";
      }
      {
        label = "unsupported qemu gate rejection";
        needle = "real-QEMU selftest gate must not be silently accepted";
      }
      {
        label = "with-qemu discovery error";
        needle = "real-QEMU selftest gate runner";
      }
      {
        label = "gate validation before qemu discovery";
        needle = "invalid selftest gate must be rejected before qemu discovery";
      }
      {
        label = "with-qemu exit code";
        needle = "assert_eq!(error.exit_code(), 4);";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI selftest check";
        needle = "cliSelftest = import ./phase5-cli-selftest.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 CLI selftest check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-cli-selftest";
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
          name = "run-cli-selftest";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-selftest-target" \
              -p crucible-cli \
              cli_selftest \
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
            selftest=built-in-corpus-replay-oracle
            dependencies=$DEPENDENCY_COUNT
            RESULT
          '';
        }
      ];
    }
