{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialMembershipFaults",
  taskIds ? ["T-SPAT-11"],
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
        label = "T-SPAT-11 checked off";
        needle = "- [x] **T-SPAT-11**";
      }
      {
        label = "T-SPAT-11 completion names Plan";
        needle = "`Plan` and `PlanEntry`";
      }
      {
        label = "T-SPAT-11 completion names membership faults";
        needle = "`MembershipFault` values";
      }
      {
        label = "T-SPAT-11 completion names not-yet-joined coverage";
        needle = "not-yet-joined nodes remain declared participants";
      }
      {
        label = "T-SPAT-11 completion maps rejoin to heal";
        needle = "rejoin expressed as healing the `NotYetJoined` tag";
      }
      {
        label = "T-SPAT-11 completion names gate";
        needle = "`checks.crucible.phase1.spatialMembershipFaults`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "fault tag type";
        needle = "pub struct FaultTag";
      }
      {
        label = "restart policy type";
        needle = "pub enum RestartPolicy";
      }
      {
        label = "partition direction type";
        needle = "pub enum PartitionDirection";
      }
      {
        label = "membership fault enum";
        needle = "pub enum MembershipFault";
      }
      {
        label = "not-yet-joined fault variant";
        needle = "NotYetJoined";
      }
      {
        label = "plan entry enum";
        needle = "pub enum PlanEntry";
      }
      {
        label = "plan type";
        needle = "pub struct Plan";
      }
      {
        label = "world-validated plan constructor";
        needle = "pub fn from_entries_for_world(";
      }
      {
        label = "plan world validation";
        needle = "fn validate_plan_entries_for_world(";
      }
      {
        label = "membership fault world validation";
        needle = "fn validate_membership_fault_for_world(";
      }
      {
        label = "unknown node rejection";
        needle = "PlanFaultUnknownNode";
      }
      {
        label = "unknown link rejection";
        needle = "PlanFaultUnknownLink";
      }
      {
        label = "unknown heal tag rejection";
        needle = "PlanHealUnknownTag";
      }
      {
        label = "heal-before-activate rejection";
        needle = "PlanHealBeforeActivate";
      }
      {
        label = "late not-yet-joined rejection";
        needle = "PlanNotYetJoinedAfterStart";
      }
      {
        label = "time-aware heal validation";
        needle = "fn validate_plan_heal(";
      }
      {
        label = "heal requires prior activation time";
        needle = "activate_at < *heal_at";
      }
      ]
    ++ forbiddenFor "crates/crucible/src/model.rs" model [
      {
        label = "dynamic add-node plan operation";
        needle = "AddNode";
      }
      {
        label = "dynamic remove-node plan operation";
        needle = "RemoveNode";
      }
      {
        label = "dynamic create-link plan operation";
        needle = "CreateLink";
      }
      {
        label = "dynamic destroy-link plan operation";
        needle = "DestroyLink";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "plan type exported";
        needle = "Plan, PlanEntry";
      }
      {
        label = "membership fault type exported";
        needle = "MembershipFault";
      }
      {
        label = "valid membership fault test";
        needle = "membership_plan_faults_layer_over_static_world_topology";
      }
      {
        label = "invalid membership target test";
        needle = "membership_plan_rejects_dynamic_or_undeclared_topology_targets";
      }
      {
        label = "not-yet-joined test coverage";
        needle = "MembershipFault::NotYetJoined";
      }
      {
        label = "heal-before-activate test coverage";
        needle = "heal_before_activate";
      }
      {
        label = "late not-yet-joined test coverage";
        needle = "not_yet_joined_after_start";
      }
      {
        label = "duplicate tag timing coverage";
        needle = "replaced_tag_heals_after_first_activation";
      }
      {
        label = "static topology remains world-derived";
        needle = "assert_eq!(world.static_topology(), topology);";
      }
      {
        label = "not-yet-joined remains baked";
        needle = "assert_eq!(topology.bake_nodes, topology.participants);";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes spatial membership faults check";
        needle = "spatialMembershipFaults = import ./phase1-spatial-membership-faults.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 spatial membership faults check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-spatial-membership-faults";
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
          name = "run-spatial-membership-faults";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-membership-faults-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib \
              membership_plan \
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
            related_gates=gate:e2e-determinism
            spatial_graph_task=membership-faults-over-static-topology
            plan_faults=crash,partition,isolate,not-yet-joined,heal
            topology_mutation=forbidden
            RESULT
          '';
        }
      ];
    }
