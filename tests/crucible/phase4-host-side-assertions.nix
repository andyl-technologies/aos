{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.hostSideAssertions",
  taskIds ? ["T-ASRT-5"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  trigger = builtins.readFile ../../crates/crucible/src/trigger.rs;
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  hostSideAssertionsTest = builtins.readFile ../../crates/crucible/tests/host_side_assertions.rs;
  assertionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
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
  failures =
    failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionDoc [
      {
        label = "T-ASRT-5 checked off";
        needle = "- [x] **T-ASRT-5**";
      }
      {
        label = "T-ASRT-5 completion note";
        needle = "Completed by `checks.crucible.phase4.hostSideAssertions`";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "host assertion oracle trait";
        needle = "pub trait HostAssertionOracle";
      }
      {
        label = "black-box host oracle";
        needle = "pub struct BlackBoxHostOracle";
      }
      {
        label = "host assertion evaluator";
        needle = "pub struct HostAssertionEvaluator";
      }
      {
        label = "host outcome kind";
        needle = "pub enum HostAssertionOutcomeKind";
      }
      {
        label = "host assertion outcome";
        needle = "pub struct HostAssertionOutcome";
      }
      {
        label = "host assertion report";
        needle = "pub struct HostAssertionReport";
      }
      {
        label = "streaming observation";
        needle = "pub fn observe_prefix";
      }
      {
        label = "final assertion report";
        needle = "pub fn finalize_prefix";
      }
      {
        label = "observed-state host predicate input";
        needle = "ObservedState<'_>";
      }
      {
        label = "always quantifier branch";
        needle = "Property::Always";
      }
      {
        label = "sometimes quantifier branch";
        needle = "Property::Sometimes";
      }
      {
        label = "eventually quantifier branch";
        needle = "Property::Eventually";
      }
      {
        label = "after-quiescence quantifier branch";
        needle = "Property::AfterQuiescence";
      }
      {
        label = "reachable quantifier branch";
        needle = "Property::Reachable";
      }
      {
        label = "unreachable dual";
        needle = "ReachabilityExpectation::Unreachable";
      }
      {
        label = "reachable warning disposition";
        needle = "ReachableDisposition::Warn";
      }
      {
        label = "reachable failure disposition";
        needle = "ReachableDisposition::Fail";
      }
      {
        label = "assertion verdict failure normalization";
        needle = "AssertionRunVerdict::failed";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "black-box oracle export";
        needle = "BlackBoxHostOracle";
      }
      {
        label = "host evaluator export";
        needle = "HostAssertionEvaluator";
      }
      {
        label = "host oracle export";
        needle = "HostAssertionOracle";
      }
      {
        label = "host outcome export";
        needle = "HostAssertionOutcome";
      }
      {
        label = "host outcome kind export";
        needle = "HostAssertionOutcomeKind";
      }
      {
        label = "host report export";
        needle = "HostAssertionReport";
      }
    ]
    ++ failuresFor "crates/crucible/tests/host_side_assertions.rs" hostSideAssertionsTest [
      {
        label = "black-box all quantifiers test";
        needle = "host_side_assertions_grade_all_five_quantifiers_in_black_box_mode";
      }
      {
        label = "failure and warning test";
        needle = "host_side_assertions_report_failures_and_warnings_without_guest_cooperation";
      }
      {
        label = "named observed-state predicate test";
        needle = "host_named_predicates_receive_read_only_observed_state";
      }
      {
        label = "determinism static test";
        needle = "host_assertion_evaluator_avoids_host_time_rng_and_unordered_maps";
      }
      {
        label = "default black-box oracle used";
        needle = "BlackBoxHostOracle";
      }
      {
        label = "always property covered";
        needle = "Property::Always";
      }
      {
        label = "sometimes property covered";
        needle = "Property::Sometimes";
      }
      {
        label = "eventually property covered";
        needle = "Property::Eventually";
      }
      {
        label = "after-quiescence property covered";
        needle = "Property::AfterQuiescence";
      }
      {
        label = "reachable property covered";
        needle = "Property::Reachable";
      }
      {
        label = "named host predicate fixture";
        needle = "Predicate::named(\"saw-ordering\")";
      }
      {
        label = "observed ordering facts supplied to host predicate";
        needle = "state.ordering_facts()";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 host-side assertions check import";
        needle = "hostSideAssertions = import ./phase4-host-side-assertions.nix";
      }
      {
        label = "phase4 host-side assertions attr path";
        needle = "attrPath = \"checks.crucible.phase4.hostSideAssertions\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "host wall-clock dependency";
        needle = "SystemTime";
      }
      {
        label = "host instant dependency";
        needle = "Instant";
      }
      {
        label = "std time dependency";
        needle = "std::time";
      }
      {
        label = "unordered hash map";
        needle = "HashMap";
      }
      {
        label = "unordered hash set";
        needle = "HashSet";
      }
      {
        label = "thread-local RNG";
        needle = "thread_rng";
      }
      {
        label = "runtime RNG import";
        needle = "rand::";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/host_side_assertions.rs" hostSideAssertionsTest [
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
  then throw "crucible phase4 host-side-assertions check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-host-side-assertions";
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
          name = "run-host-side-assertions";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-host-side-assertions-target" \
              -p crucible \
              --test host_side_assertions \
              --test observed_state_materialization \
              --test observable_condition_leaves \
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
            host_side_assertions_over_observed_state=true
            RESULT
          '';
        }
      ];
    }
