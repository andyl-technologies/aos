{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialScenarioDefValue",
  taskIds ? ["T-SPAT-1"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  model = builtins.readFile ../../crates/crucible/src/model.rs;
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  defaultChecks = builtins.readFile ./default.nix;
  spatialGraph = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;

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

  failures =
    failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-1 checked off";
        needle = "- [x] **T-SPAT-1**";
      }
      {
        label = "T-SPAT-1 completion names tuple form";
        needle = "`ScenarioDefForm` is the";
      }
      {
        label = "T-SPAT-1 completion names test";
        needle = "`scenario_def_form_is_immutable_pure_four_tuple_value`";
      }
      {
        label = "T-SPAT-1 completion names gate";
        needle = "`checks.crucible.phase1.spatialScenarioDefValue`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "executable scenario handle";
        needle = "pub struct ScenarioDef";
      }
      {
        label = "scenario id is private";
        needle = "id: ContentHash";
      }
      {
        label = "scenario seed is private";
        needle = "seed: Seed";
      }
      {
        label = "scenario form type";
        needle = "pub struct ScenarioDefForm";
      }
      {
        label = "scenario form world tuple field";
        needle = "world: World";
      }
      {
        label = "scenario form plan tuple field";
        needle = "plan: Plan";
      }
      {
        label = "scenario form properties tuple field";
        needle = "properties: Properties";
      }
      {
        label = "scenario form seed tuple field";
        needle = "seed: Seed";
      }
      {
        label = "scenario form validated constructor";
        needle = "pub fn from_components(";
      }
      {
        label = "scenario form clones world component";
        needle = "world: world.clone()";
      }
      {
        label = "scenario form clones plan component";
        needle = "plan: plan.clone()";
      }
      {
        label = "scenario form clones properties component";
        needle = "properties: properties.clone()";
      }
      {
        label = "world accessor";
        needle = "pub fn world(&self) -> &World";
      }
      {
        label = "plan accessor";
        needle = "pub fn plan(&self) -> &Plan";
      }
      {
        label = "properties accessor";
        needle = "pub fn properties(&self) -> &Properties";
      }
      {
        label = "seed accessor";
        needle = "pub fn seed(&self) -> Seed";
      }
      {
        label = "scenario reconstruction";
        needle = "pub fn scenario_def(&self) -> ScenarioDef";
      }
      {
        label = "scenario identity material helper";
        needle = "fn scenario_world_plan_properties_seed_material";
      }
      {
        label = "scenario material uses world ref";
        needle = "world_ref={}";
      }
      {
        label = "scenario material uses plan ref";
        needle = "plan_ref={}";
      }
      {
        label = "scenario material uses properties ref";
        needle = "properties_ref={}";
      }
      {
        label = "scenario material uses seed material";
        needle = "seed_material(seed)";
      }
      {
        label = "content-addressed blob refs";
        needle = "pub struct ContentAddressedBlobRef";
      }
      {
        label = "host path image refs rejected";
        needle = "ScenarioImageReferenceNotContentAddressed";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/model.rs" model [
      {
        label = "public scenario id field";
        needle = "pub id: ContentHash,\n    /// The root entropy carried by this scenario definition.";
      }
      {
        # Scoped to the ScenarioDef seed field via its unique doc comment. The bare
        # `pub seed: Seed,\n}` matched four OTHER structs that legitimately carry a
        # public seed as their last field; the doc-comment anchor pins this to
        # ScenarioDef's own field. Rescoped 2026-07-09.
        label = "public scenario seed field";
        needle = "/// The root entropy carried by this scenario definition.\n    pub seed: Seed,";
      }
      {
        label = "host wall-clock API";
        needle = "SystemTime";
      }
      {
        label = "host wall-clock instant API";
        needle = "Instant::now";
      }
      {
        label = "host wall-clock epoch API";
        needle = "UNIX_EPOCH";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "focused scenario value test";
        needle = "fn scenario_def_form_is_immutable_pure_four_tuple_value()";
      }
      {
        label = "test asserts world component accessor";
        needle = "assert_eq!(form.world(), &world);";
      }
      {
        label = "test asserts plan component accessor";
        needle = "assert_eq!(form.plan(), &plan);";
      }
      {
        label = "test asserts properties component accessor";
        needle = "assert_eq!(form.properties(), &properties);";
      }
      {
        label = "test asserts seed component accessor";
        needle = "assert_eq!(form.seed(), seed);";
      }
      {
        label = "test proves equal content equal id";
        needle = "assert_eq!(left.id(), right.id());";
      }
      {
        label = "test proves world identity sensitivity";
        needle = "changed-world form should be valid";
      }
      {
        label = "test proves plan identity sensitivity";
        needle = "changed-plan form should be valid";
      }
      {
        label = "test proves properties identity sensitivity";
        needle = "changed-properties form should be valid";
      }
      {
        label = "test proves seed identity sensitivity";
        needle = "changed-seed form should be valid";
      }
      {
        label = "test rejects host image path";
        needle = "ContentAddressedBlobRef::parse(\"kernel\", \"/nix/store/not-a-content-ref\")";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes scenario definition value check";
        needle = "spatialScenarioDefValue = import ./phase1-spatial-scenario-def-value.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 spatial scenario-def value check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-spatial-scenario-def-value";
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
          name = "run-spatial-scenario-def-value";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-scenario-def-value-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib \
              scenario_def_form_is_immutable_pure_four_tuple_value \
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
            tasks=${builtins.concatStringsSep "," taskIds}
            component=scenario-def-value
            tuple=World,Plan,Properties,Seed
            equal_content_equal_id=true
            host_paths=false
            wall_clock=false
            RESULT
          '';
        }
      ];
    }
