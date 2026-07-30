{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.propertyConfiguration",
  taskIds ? ["T-ASRT-3"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  configurationTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/tests/property_configuration.rs;
  };
  vocabularyTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/tests/property_vocabulary.rs;
  };
  assertionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionDoc [
      {
        label = "T-ASRT-3 completion note";
        needle = "Completed by `checks.crucible.phase4.propertyConfiguration`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "assertion definition";
        needle = "pub struct AssertionDef";
      }
      {
        label = "stable assertion id field";
        needle = "pub id: AssertionId,";
      }
      {
        label = "human-readable assertion message field";
        needle = "pub message: String,";
      }
      {
        label = "Eventually deadline uses virtual time";
        needle = "deadline: VirtualTime,";
      }
      {
        label = "TOML accepts only virtual-time deadline ticks";
        needle = "deadline_ticks: Option<u64>,";
      }
      {
        label = "Reachable expectation field";
        needle = "expectation: ReachabilityExpectation,";
      }
      {
        label = "ordinary reachable disposition";
        needle = "on_unreached: ReachableDisposition,";
      }
      {
        label = "reachable warn disposition";
        needle = "ReachableDisposition::Warn";
      }
      {
        label = "reachable fail disposition";
        needle = "ReachableDisposition::Fail";
      }
      {
        label = "unreachable dual";
        needle = "ReachabilityExpectation::Unreachable";
      }
      {
        label = "reachable TOML defaults omitted disposition to warn";
        needle = "#[serde(default = \"reachable_disposition_warn_toml\")]";
      }
      {
        label = "reachable TOML default helper";
        needle = "fn reachable_disposition_warn_toml() -> ReachableDispositionToml";
      }
      {
        label = "property TOML denies unknown fields";
        needle = "#[serde(deny_unknown_fields)]\npub(super) struct PropertyToml";
      }
      {
        label = "reachability TOML denies unknown fields";
        needle = "#[serde(deny_unknown_fields)]\n#[serde(tag = \"kind\", rename_all = \"snake_case\")]\npub(super) enum ReachabilityExpectationToml";
      }
      {
        label = "canonical assertion id material";
        needle = "assertion_id_len={}";
      }
      {
        label = "canonical assertion message material";
        needle = "message_len={}";
      }
      {
        label = "canonical Eventually deadline material";
        needle = "deadline_ticks={}";
      }
      {
        label = "canonical reachable disposition material";
        needle = "on_unreached={}";
      }
    ]
    ++ failuresFor "crates/crucible/tests/property_configuration.rs" configurationTest [
      {
        label = "configuration canonical and hash test";
        needle = "property_configuration_is_canonical_and_hash_affecting";
      }
      {
        label = "configuration round trip test";
        needle = "property_configuration_round_trips_through_toml_and_binary";
      }
      {
        label = "reachable default warn test";
        needle = "reachable_toml_defaults_never_reached_disposition_to_warn";
      }
      {
        label = "wall-clock/nondeterministic rejection test";
        needle = "scenario_validation_rejects_wall_clock_and_nondeterministic_property_parameters";
      }
      {
        label = "unknown disposition rejection test";
        needle = "scenario_validation_rejects_unknown_reachable_dispositions";
      }
      {
        label = "stable id hash assertion";
        needle = "stable assertion id must affect properties identity";
      }
      {
        label = "message hash assertion";
        needle = "assertion message must affect properties identity";
      }
      {
        label = "deadline hash assertion";
        needle = "Eventually virtual-time deadline must affect properties identity";
      }
      {
        label = "reachable disposition hash assertion";
        needle = "Reachable never-reached disposition must affect properties identity";
      }
      {
        label = "reachable expectation hash assertion";
        needle = "Reachable ordinary/unreachable dual must affect properties identity";
      }
      {
        label = "host seconds rejected";
        needle = "deadline_seconds";
      }
      {
        label = "host wall clock rejected";
        needle = "deadline_wall_clock_seconds";
      }
      {
        label = "system time rejected";
        needle = "deadline_from_system_time";
      }
    ]
    ++ failuresFor "crates/crucible/tests/property_vocabulary.rs" vocabularyTest [
      {
        label = "missing reachable expectation remains invalid";
        needle = "property kind `reachable` missing `expectation`";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 property configuration check import";
        needle = "propertyConfiguration = import ./phase4-property-configuration.nix";
      }
      {
        label = "phase4 property configuration attr path";
        needle = "attrPath = \"checks.crucible.phase4.propertyConfiguration\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/property_configuration.rs" configurationTest [
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
  then throw "crucible phase4 property-configuration check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-property-configuration";
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
          name = "run-property-configuration";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-property-configuration-target" \
              -p crucible \
              --test property_configuration \
              --test property_vocabulary \
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
            property_configuration_validated=true
            RESULT
          '';
        }
      ];
    }
