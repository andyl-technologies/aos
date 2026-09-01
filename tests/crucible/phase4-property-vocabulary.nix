{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.propertyVocabulary",
  taskIds ? ["T-ASRT-1"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  crucibleSourceRoot = ../../crates/crucible/src;
  model = import ./_crucible-model-source.nix {inherit lib;};
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  propertyTest = builtins.readFile ../../crates/crucible/tests/property_vocabulary.rs;
  conditionTest = builtins.readFile ../../crates/crucible/tests/condition_vocabulary_shared.rs;
  assertionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
  defaultChecks = builtins.readFile ./default.nix;

  sourceFilesIn = dir: prefix: let
    entries = builtins.readDir dir;
  in
    lib.concatMap (
      name: let
        kind = entries.${name};
        path = dir + "/${name}";
        relative =
          if prefix == ""
          then name
          else "${prefix}/${name}";
      in
        if kind == "directory"
        then sourceFilesIn path relative
        else if lib.hasSuffix ".rs" name
        then [
          {
            label = "crates/crucible/src/${relative}";
            content = builtins.readFile path;
          }
        ]
        else []
    )
    (builtins.attrNames entries);
  crucibleSourceFiles = sourceFilesIn crucibleSourceRoot "";

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  forbiddenForSources = requirements:
    lib.concatMap (
      source:
        lib.concatMap (
          requirement:
            lib.optionals (hasInfix requirement.needle source.content) [
              "${source.label}: forbidden ${requirement.label}: `${requirement.needle}`"
            ]
        )
        requirements
    )
    crucibleSourceFiles;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionDoc [
      {
        label = "T-ASRT-1 completion note";
        needle = "Completed by `checks.crucible.phase4.propertyVocabulary`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "property schema version";
        needle = "pub const PROPERTY_SCHEMA_VERSION: u32 = 1;";
      }
      {
        label = "property schema domain";
        needle = "pub const PROPERTY_SCHEMA_DOMAIN: &str = \"crucible.model.properties.v1\";";
      }
      {
        label = "closed quantifier count";
        needle = "pub const PROPERTY_QUANTIFIER_COUNT: usize = 5;";
      }
      {
        label = "property kind enum";
        needle = "pub enum PropertyKind";
      }
      {
        label = "closed property kind order";
        needle = "pub const ALL: [Self; PROPERTY_QUANTIFIER_COUNT]";
      }
      {
        label = "always kind";
        needle = "Always,";
      }
      {
        label = "sometimes kind";
        needle = "Sometimes,";
      }
      {
        label = "eventually kind";
        needle = "Eventually,";
      }
      {
        label = "after-quiescence kind";
        needle = "AfterQuiescence,";
      }
      {
        label = "reachable kind";
        needle = "Reachable,";
      }
      {
        label = "binary property tag parser";
        needle = "pub const fn from_binary_tag(tag: u8) -> Option<Self>";
      }
      {
        label = "canonical property labels";
        needle = "pub const fn canonical_label(self) -> &'static str";
      }
      {
        label = "toml property labels";
        needle = "pub const fn toml_kind(self) -> &'static str";
      }
      {
        label = "toml property parser";
        needle = "pub const fn from_toml_kind(kind: &str) -> Option<Self>";
      }
      {
        label = "property kind accessor";
        needle = "pub const fn kind(&self) -> PropertyKind";
      }
      {
        label = "property enum";
        needle = "pub enum Property";
      }
      {
        label = "reachable unreachable dual";
        needle = "ReachabilityExpectation::Unreachable";
      }
      {
        label = "shared predicate enum";
        needle = "pub enum Predicate";
      }
      {
        label = "properties hash domain uses schema domain";
        needle = "PROPERTY_SCHEMA_DOMAIN,";
      }
      {
        label = "property toml kind field";
        needle = "kind: String,";
      }
      {
        label = "property toml parser uses vocabulary";
        needle = "PropertyKind::from_toml_kind(&kind)";
      }
      {
        label = "property toml requires fields by kind";
        needle = "property kind `{}` missing `{field_name}`";
      }
      {
        label = "property toml rejects extra fields by kind";
        needle = "property kind `{}` has unexpected `{field_name}`";
      }
      {
        label = "versioned properties binary magic";
        needle = "const PROPERTIES_BINARY_MAGIC: &[u8] = b\"crucible.properties.v1\\0\";";
      }
      {
        label = "invalid property tag rejected";
        needle = "invalid property tag";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "single condition alias";
        needle = "pub type Condition = Predicate;";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "property kind export";
        needle = "PropertyKind";
      }
      {
        label = "property schema version export";
        needle = "PROPERTY_SCHEMA_VERSION";
      }
      {
        label = "action export";
        needle = "Action,";
      }
      {
        label = "condition export";
        needle = "Condition, ConditionEvaluation";
      }
    ]
    ++ failuresFor "crates/crucible/tests/property_vocabulary.rs" propertyTest [
      {
        label = "closed versioned vocabulary test";
        needle = "property_vocabulary_is_closed_and_versioned";
      }
      {
        label = "all quantifier round trip test";
        needle = "all_property_quantifiers_round_trip_through_versioned_properties_schema";
      }
      {
        label = "unknown quantifier rejection test";
        needle = "property_toml_rejects_unknown_quantifier_kind";
      }
      {
        label = "toml field shape rejection test";
        needle = "property_toml_enforces_quantifier_specific_fields";
      }
      {
        label = "shared condition type test";
        needle = "assertions_and_triggers_share_one_condition_type";
      }
      {
        label = "reachable warn coverage";
        needle = "ReachableDisposition::Warn";
      }
      {
        label = "reachable fail coverage";
        needle = "ReachableDisposition::Fail";
      }
      {
        label = "unreachable dual coverage";
        needle = "ReachabilityExpectation::Unreachable";
      }
    ]
    ++ failuresFor "crates/crucible/tests/condition_vocabulary_shared.rs" conditionTest [
      {
        label = "existing assertion trigger shared type test";
        needle = "predicate_used_by_assertion_is_the_trigger_condition_type";
      }
      {
        label = "eventually trigger/property predicate reuse test";
        needle = "eventually_trigger_and_property_predicates_are_trigger_usable";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 property vocabulary check import";
        needle = "propertyVocabulary = import ./phase4-property-vocabulary.nix";
      }
      {
        label = "phase4 property vocabulary attr path";
        needle = "attrPath = \"checks.crucible.phase4.propertyVocabulary\"";
      }
    ]
    ++ forbiddenForSources [
      {
        label = "runtime model checker type";
        needle = "ModelChecker";
      }
      {
        label = "runtime model checker module";
        needle = "model_checker";
      }
      {
        label = "runtime model-check function";
        needle = "model_check";
      }
      {
        label = "runtime modelCheck function";
        needle = "modelCheck";
      }
      {
        label = "runtime spec-language evaluator";
        needle = "SpecLanguage";
      }
      {
        label = "runtime spec evaluator";
        needle = "SpecEvaluator";
      }
      {
        label = "runtime LTL evaluator";
        needle = "LtlEvaluator";
      }
      {
        label = "runtime formal-spec evaluator";
        needle = "FormalSpecEvaluator";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/property_vocabulary.rs" propertyTest [
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
  then throw "crucible phase4 property-vocabulary check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-property-vocabulary";
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
          name = "run-property-vocabulary";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-property-vocabulary-target" \
              -p crucible \
              --test property_vocabulary \
              --test condition_vocabulary_shared \
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
            schema=property-vocabulary-v1
            quantifiers=5
            RESULT
          '';
        }
      ];
    }
