{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.executionReadyPoint",
  taskIds ? ["T-EXEC-9" "T-SPAT-6"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  qemuRealization = builtins.readFile ../../crates/crucible-qemu/src/realization.rs;
  defaultChecks = builtins.readFile ./default.nix;
  rfc = builtins.readFile ../../docs/rfcs/0010-crucible/05-execution-model.md;
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
    failuresFor "docs/rfcs/0010-crucible/05-execution-model.md" rfc [
      {
        label = "T-EXEC-9 checked off";
        needle = "- [x] **T-EXEC-9**";
      }
      {
        label = "T-EXEC-9 completion note";
        needle = "Completed by `crates/crucible/src/model.rs`: `World::from_nodes` builds";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-6 checked off";
        needle = "- [x] **T-SPAT-6**";
      }
      {
        label = "T-SPAT-6 completion names ReadyPoint";
        needle = "the `ReadyPoint` enum includes";
      }
      {
        label = "T-SPAT-6 completion names white-box opt-in";
        needle = "rejects `AgentSignal` unless";
      }
      {
        label = "T-SPAT-6 completion names ready-point gate";
        needle = "`checks.crucible.phase1.executionReadyPoint`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "world nodes constructor";
        needle = "pub fn from_nodes(nodes: Vec<WorldNode>) -> Result<Self, EngineError>";
      }
      {
        label = "canonical world node ordering";
        needle = "fn canonical_world_nodes(nodes: &[WorldNode]) -> Vec<WorldNode>";
      }
      {
        label = "shared ready point validator";
        needle = "pub fn validate_ready_point_policies(&self) -> Result<(), EngineError>";
      }
      {
        label = "world node config";
        needle = "pub struct WorldNode";
      }
      {
        label = "ready point enum";
        needle = "pub enum ReadyPoint";
      }
      {
        label = "fixed icount ready point";
        needle = "FixedIcount";
      }
      {
        label = "network idle ready point";
        needle = "NetworkIdle";
      }
      {
        label = "console marker ready point";
        needle = "ConsoleMarker";
      }
      {
        label = "agent signal ready point";
        needle = "AgentSignal";
      }
      {
        label = "white-box policy";
        needle = "pub enum WhiteBoxPolicy";
      }
      {
        label = "agent signal opt-in validation";
        needle = "WhiteBoxReadyPointWithoutOptIn";
      }
      {
        label = "duplicate node validation";
        needle = "DuplicateWorldNodeId";
      }
      {
        label = "ready point material hash input";
        needle = "fn ready_point_material(ready_point: &ReadyPoint) -> String";
      }
      {
        label = "world node material hash input";
        needle = "fn world_nodes_material(nodes: &[WorldNode]) -> String";
      }
      {
        label = "bake validates world ready points";
        needle = "world.validate_ready_point_policies()?;";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "canonical ready point hash test";
        needle = "world_ready_point_policies_are_hashed_canonically";
      }
      {
        label = "agent signal opt-in test";
        needle = "world_ready_point_rejects_agent_signal_without_white_box_opt_in";
      }
      {
        label = "per-policy bake determinism test";
        needle = "bake_is_content_identical_for_each_ready_point_policy";
      }
      {
        label = "ready point material sensitivity test";
        needle = "ready_point_policy_material_affects_baked_genesis";
      }
      {
        label = "fixed icount test coverage";
        needle = "ReadyPoint::FixedIcount";
      }
      {
        label = "network idle test coverage";
        needle = "ReadyPoint::NetworkIdle";
      }
      {
        label = "console marker test coverage";
        needle = "ReadyPoint::ConsoleMarker";
      }
      {
        label = "agent signal test coverage";
        needle = "ReadyPoint::AgentSignal";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/realization.rs" qemuRealization [
      {
        label = "QEMU bake validates world ready points";
        needle = ".validate_ready_point_policies()";
      }
      {
        label = "QEMU ready point policy error";
        needle = "ReadyPointPolicy";
      }
      {
        label = "QEMU agent signal opt-in regression";
        needle = "qemu_bake_rejects_agent_signal_without_white_box_opt_in";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes ready-point execution check";
        needle = "executionReadyPoint = import ./phase1-execution-ready-point.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 execution ready-point check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-execution-ready-point";
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
          name = "run-execution-ready-point";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-execution-ready-point-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib \
              ready_point \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-execution-ready-point-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --lib \
              qemu_bake_rejects_agent_signal_without_white_box_opt_in \
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
            related_gates=gate:content-address,gate:any-guest
            ready_point_policies=fixed-icount,network-idle,console-marker,agent-signal
            spatial_graph_task=ready-point-policy-set-white-box-opt-in
            white_box_agent_signal=requires-opt-in
            bake_ready_point_determinism=content-identical-per-policy
            qemu_bake_ready_point_validation=rejects-invalid-agent-signal-before-executor
            RESULT
          '';
        }
      ];
    }
