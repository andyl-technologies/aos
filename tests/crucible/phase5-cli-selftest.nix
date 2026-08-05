{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliSelftest",
  taskIds ? ["T-CLI-8"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  helpSurface = builtins.readFile ../../crates/crucible-cli/tests/help_surface.rs;
  cliMain = import ./_cli-source.nix {inherit lib;};
  cliManifest = builtins.readFile ../../crates/crucible-cli/Cargo.toml;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-8 packaged production selftest evidence";
        needle = "Completed under `checks.crucible.phase5.cliSelftest`";
      }
      {
        label = "T-CLI-8 unmodified stock-kernel evidence";
        needle = "packaged production CLI against the unmodified stock Linux kernel";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI selftest completion note";
        needle = "`T-CLI-8` is completed through `checks.crucible.phase5.cliSelftest`";
      }
      {
        label = "phase5 packaged production selftest execution";
        needle = "process invocation of the packaged production\n  `crucible selftest --with-qemu` process";
      }
    ]
    ++ failuresFor "crates/crucible-cli/tests/help_surface.rs" helpSurface [
      {
        label = "production selftest excludes test-double options";
        needle = "cli_production_selftest_help_excludes_test_double_options";
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
        label = "selftest corpus flag";
        needle = "corpus: Option<PathBuf>";
      }
      {
        label = "built-in corpus selftest gate subset";
        needle = "BUILT_IN_CORPUS_SELFTEST_GATES";
      }
      {
        label = "real qemu selftest gate subset";
        needle = "REAL_QEMU_SELFTEST_GATES";
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
        label = "real-QEMU gates execute the live backend";
        needle = "probe.run_probe(backend)?";
      }
      {
        label = "real-QEMU selftest icount evidence";
        needle = "live_qemu_icount";
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
        label = "corpus manifest loader";
        needle = "fn verify_selftest_corpus_manifest";
      }
      {
        label = "corpus manifest fixture resolver";
        needle = "fn verify_selftest_fixture_by_name";
      }
      {
        label = "qemu discovery runner";
        needle = "fn require_selftest_qemu_backend";
      }
      {
        label = "qemu identity report field";
        needle = "qemu_build_id: Option<String>";
      }
      {
        label = "runner report field";
        needle = "SelftestGateRunner";
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
        label = "qemu gate requires flag";
        needle = "real-QEMU selftest gate must require --with-qemu";
      }
      {
        label = "with-qemu discovery error";
        needle = "selftest --with-qemu without artifacts must fail discovery";
      }
      {
        label = "gate validation before qemu discovery";
        needle = "invalid selftest gate must be rejected before qemu discovery";
      }
      {
        label = "with-qemu exit code";
        needle = "assert_eq!(error.exit_code(), 4);";
      }
      {
        label = "positive qemu selftest report";
        needle = "qemu_report.gates.iter().all";
      }
      {
        label = "file-backed corpus test";
        needle = "selftest-corpus.txt";
      }
    ]
    ++ forbiddenFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "stale qemu runner blocker";
        needle = "real-QEMU selftest gate runner tracked by T-CLI-8";
      }
      {
        label = "stale extended runner blocker";
        needle = "real-QEMU and extended gate runners remain tracked by T-CLI-8";
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
        pkgs.crucible
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

            "${pkgs.crucible}/bin/crucible" \
              --artifact-dir "$TMPDIR/crucible-cli-selftest-artifacts" \
              selftest \
              --with-qemu \
              > "$TMPDIR/production-selftest.out"

            for gate in \
              gate:single-vm-fingerprint \
              gate:any-guest \
              gate:qemu-inert
            do
              row="$(
                sed -n \
                  "\\|gate=$gate status=PASS runner=qemu .* qemu=.* live-icount=[0-9][0-9]* live-fingerprint=blake3:[0-9a-f][0-9a-f]*|p" \
                  "$TMPDIR/production-selftest.out"
              )"
              test -n "$row"
            done
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
            evidence_scope=packaged-production-cli-live-qemu
            component=crucible-cli
            selftest=production-process-three-live-qemu-gates
            guest_kernel=unmodified-stock-linux
            corpus_manifest=true
            dependencies=$DEPENDENCY_COUNT
            RESULT
          '';
        }
      ];
    }
