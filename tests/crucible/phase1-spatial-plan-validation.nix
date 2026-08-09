{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialPlanValidation",
  taskIds ? ["T-SPAT-20"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;
  spatialGraph = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-20 completion names focused test";
        needle = "`plan_validation_reports_precise_fault_heal_and_time_errors`";
      }
      {
        label = "T-SPAT-20 completion names gate";
        needle = "`checks.crucible.phase1.spatialPlanValidation`";
      }
      {
        label = "T-SPAT-20 completion names localized errors";
        needle = "localized `EngineError` payloads";
      }
      {
        label = "T-SPAT-20 completion names unsupported fault params";
        needle = "unsupported fault-parameter fields";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "typed unsigned virtual time";
        needle = "pub struct VirtualTime";
      }
      {
        label = "virtual time tick is u64";
        needle = "pub ticks: u64";
      }
      {
        label = "membership fault enum";
        needle = "pub enum MembershipFault";
      }
      {
        label = "crash fault params";
        needle = "Crash {";
      }
      {
        label = "partition fault params";
        needle = "Partition {";
      }
      {
        label = "isolate fault params";
        needle = "Isolate {";
      }
      {
        label = "not-yet-joined fault params";
        needle = "NotYetJoined {";
      }
      {
        label = "plan entry enum";
        needle = "pub enum PlanEntry";
      }
      {
        label = "world-validated plan constructor";
        needle = "pub fn from_entries_for_world(";
      }
      {
        label = "plan validation pass";
        needle = "fn validate_plan_entries_for_world(";
      }
      {
        label = "fault parameter validation";
        needle = "fn validate_membership_fault_for_world(";
      }
      {
        label = "heal tag validation";
        needle = "fn validate_plan_heal(";
      }
      {
        label = "node target validation";
        needle = "validate_plan_node(node, node_ids)?;";
      }
      {
        label = "localized unknown node error";
        needle = "PlanFaultUnknownNode { node: node.clone() }";
      }
      {
        label = "localized unknown link error";
        needle = "PlanFaultUnknownLink {";
      }
      {
        label = "unknown link preserves endpoint a";
        needle = "endpoint_a: endpoint_a.clone()";
      }
      {
        label = "unknown link preserves endpoint b";
        needle = "endpoint_b: endpoint_b.clone()";
      }
      {
        label = "localized unknown heal tag";
        needle = "PlanHealUnknownTag { tag: tag.clone() }";
      }
      {
        label = "localized heal timing error";
        needle = "PlanHealBeforeActivate";
      }
      {
        label = "heal must follow activation";
        needle = "activate_at < *heal_at";
      }
      {
        label = "localized not-yet-joined time error";
        needle = "PlanNotYetJoinedAfterStart";
      }
      {
        label = "localized negative serialized time error";
        needle = "PlanNegativeTime";
      }
      {
        label = "localized unknown direction error";
        needle = "PlanFaultUnknownDirection";
      }
      {
        label = "localized unsupported fault param error";
        needle = "PlanFaultUnsupportedParam";
      }
      {
        label = "not-yet-joined is start-only";
        needle = "if at != VirtualTime::default()";
      }
      {
        label = "plan TOML pre-validation";
        needle = "fn validate_plan_entries_in_toml(";
      }
      {
        label = "negative TOML time rejection";
        needle = "at_ticks < 0";
      }
      {
        label = "serialized partition direction validation";
        needle = "fn validate_partition_direction_toml_value(";
      }
      {
        label = "supported partition direction spellings";
        needle = "\"endpoint_a_to_endpoint_b\" | \"endpoint_b_to_endpoint_a\"";
      }
      {
        label = "serialized unsupported fault param validation";
        needle = "PlanFaultUnsupportedParam {";
      }
      {
        label = "partition params canonicalized";
        needle = "fn canonical_membership_fault(";
      }
      {
        label = "partition direction inversion";
        needle = "fn inverted_partition_direction(";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "focused plan validation test";
        needle = "fn plan_validation_reports_precise_fault_heal_and_time_errors()";
      }
      {
        label = "crash target coverage";
        needle = "unknown_crash_target";
      }
      {
        label = "isolate target coverage";
        needle = "unknown_isolate_target";
      }
      {
        label = "partition link coverage";
        needle = "unknown_partition_link";
      }
      {
        label = "unknown heal coverage";
        needle = "unknown_heal_tag";
      }
      {
        label = "heal time coverage";
        needle = "heal_before_activate";
      }
      {
        label = "not-yet-joined time coverage";
        needle = "not_yet_joined_after_start";
      }
      {
        label = "start-time not-yet-joined accepted";
        needle = "start_time_not_yet_joined";
      }
      {
        label = "direction params canonicalized";
        needle = "direction_a_to_b.content_hash()";
      }
      {
        label = "unknown node exact error asserted";
        needle = "Err(EngineError::PlanFaultUnknownNode { node })";
      }
      {
        label = "unknown link exact error asserted";
        needle = "Err(EngineError::PlanFaultUnknownLink {";
      }
      {
        label = "unknown heal exact error asserted";
        needle = "Err(EngineError::PlanHealUnknownTag { tag })";
      }
      {
        label = "heal-before-activate exact error asserted";
        needle = "Err(EngineError::PlanHealBeforeActivate {";
      }
      {
        label = "not-yet-joined exact error asserted";
        needle = "Err(EngineError::PlanNotYetJoinedAfterStart { node, at })";
      }
      {
        label = "negative time TOML coverage";
        needle = "negative_time_toml";
      }
      {
        label = "unknown direction TOML coverage";
        needle = "unknown_direction_toml";
      }
      {
        label = "unsupported fault param TOML coverage";
        needle = "unsupported_fault_param_toml";
      }
      {
        label = "full scenario TOML negative time coverage";
        needle = "scenario_negative_time_toml";
      }
      {
        label = "negative time exact error asserted";
        needle = "Err(EngineError::PlanNegativeTime { entry, at_ticks })";
      }
      {
        label = "unknown direction exact error asserted";
        needle = "Err(EngineError::PlanFaultUnknownDirection { entry, direction })";
      }
      {
        label = "unsupported param exact error asserted";
        needle = "Err(EngineError::PlanFaultUnsupportedParam { entry, field })";
      }
      {
        label = "activation time payload asserted";
        needle = "activate_at.ticks == 20";
      }
      {
        label = "heal time payload asserted";
        needle = "heal_at.ticks == 10";
      }
      {
        label = "late not-yet-joined time payload asserted";
        needle = "at.ticks == 1";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes spatial plan validation check";
        needle = "spatialPlanValidation = import ./phase1-spatial-plan-validation.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 spatial plan validation check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-spatial-plan-validation";
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
          name = "run-spatial-plan-validation";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-plan-validation-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib \
              plan_validation_reports_precise_fault_heal_and_time_errors \
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
            component=plan-validation
            fault_params=localized
            unsupported_fault_params=rejected
            heal_tags=localized
            plan_times=localized
            RESULT
          '';
        }
      ];
    }
