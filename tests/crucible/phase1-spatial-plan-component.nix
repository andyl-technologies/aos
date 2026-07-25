{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialPlanComponent",
  taskIds ? ["T-SPAT-12"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
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

  failures =
    failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-12 checked off";
        needle = "- [x] **T-SPAT-12**";
      }
      {
        label = "T-SPAT-12 completion names independent plan hash";
        needle = "`Plan` now carries an";
      }
      {
        label = "T-SPAT-12 completion names scenario composition";
        needle = "`World::scenario_def_with_plan`";
      }
      {
        label = "T-SPAT-12 completion names gate";
        needle = "`checks.crucible.phase1.spatialPlanComponent`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "private plan identity field";
        needle = ''
          pub struct Plan {
              /// The independently content-addressed plan identity.
              id: ContentHash,
        '';
      }
      {
        label = "plan content hash accessor";
        needle = "pub fn content_hash(&self) -> ContentHash";
      }
      {
        label = "plan hash domain";
        needle = "\"crucible.model.plan.v1\"";
      }
      {
        label = "plan canonical entry helper";
        needle = "fn canonical_plan_entries(entries: &[PlanEntry]) -> Vec<PlanEntry>";
      }
      {
        label = "virtual-time plan ordering";
        needle = "plan_entry_time(left)";
      }
      {
        label = "plan material helper";
        needle = "fn plan_material(plan: &Plan) -> String";
      }
      {
        label = "plan entry material helper";
        needle = "fn plan_entry_material(entry: &PlanEntry) -> String";
      }
      {
        label = "membership fault material helper";
        needle = "fn membership_fault_material(fault: &MembershipFault) -> String";
      }
      {
        label = "world-plan scenario helper";
        needle = "pub fn scenario_def_with_plan(&self, plan: &Plan) -> Result<ScenarioDef, EngineError>";
      }
      {
        label = "scenario world-plan domain";
        needle = "\"crucible.model.world-plan-properties-seed-scenario.v1\"";
      }
      {
        label = "scenario component material";
        needle = "fn scenario_world_plan_properties_seed_material";
      }
      {
        label = "scenario includes world component hash";
        needle = "content_hash_hex(canonical_world_identity(world))";
      }
      {
        label = "scenario includes plan component hash";
        needle = "content_hash_hex(plan.content_hash())";
      }
      {
        label = "scenario includes empty properties compatibility";
        needle = "Ok(self.scenario_def_from_components(plan, &Properties::empty(), Seed::default()))";
      }
      {
        label = "world validates plan before scenario composition";
        needle = "plan.validate_for_world(self)?;";
      }
    ]
    ++ lib.optionals (hasInfix ''
      pub struct Plan {
          /// The independently content-addressed plan identity.
          pub id: ContentHash,
    ''
    model) [
      "crates/crucible/src/model.rs: plan identity field must not be public"
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "plan content-address test";
        needle = "plan_content_address_is_orthogonal_and_canonical";
      }
      {
        label = "test checks authoring order";
        needle = "let authored_order = vec![";
      }
      {
        label = "test checks canonical entries";
        needle = "assert_eq!(plan.entries(), same_plan.entries());";
      }
      {
        label = "test checks plan reuse across compatible worlds";
        needle = "same_plan_changed_world.content_hash()";
      }
      {
        label = "test checks scenario plan sensitivity";
        needle = "plan should affect scenario identity";
      }
      {
        label = "test checks empty-plan compatibility";
        needle = "let empty_plan = Plan::empty();";
      }
      {
        label = "test rejects incompatible world";
        needle = "incompatible_world.scenario_def_with_plan(&plan)";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes spatial plan component check";
        needle = "spatialPlanComponent = import ./phase1-spatial-plan-component.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 spatial plan component check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-spatial-plan-component";
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
          name = "run-spatial-plan-component";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-plan-component-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib \
              plan_content_address \
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
            related_gates=gate:content-address,gate:e2e-determinism
            spatial_graph_task=orthogonal-plan-component
            component=plan
            canonical_order=virtual-time
            scenario_identity=world-ref-plus-plan-ref
            RESULT
          '';
        }
      ];
    }
