{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerLinkLatencyFloor",
  taskIds ? ["T-SCHED-10"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  spatialDoc = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;
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

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-10 checked off";
        needle = "- [x] **T-SCHED-10**";
      }
      {
        label = "T-SCHED-10 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerLinkLatencyFloor`";
      }
      {
        label = "minimum latency floor requirement";
        needle = "minimum link-latency floor";
      }
      {
        label = "scenario hash requirement";
        needle = "include it in the scenario content hash";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialDoc [
      {
        label = "spatial graph defines floor";
        needle = "pub const MIN_LINK_LATENCY";
      }
      {
        label = "spatial graph rejects zero";
        needle = "a link MUST have a strictly positive latency";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "minimum latency constant";
        needle = "pub const MIN_LINK_LATENCY: SimDuration";
      }
      {
        label = "default link uses floor";
        needle = "MIN_LINK_LATENCY,";
      }
      {
        label = "transport constructor validates floor";
        needle = "validate_link_transport(&link)?";
      }
      {
        label = "world validation revalidates links";
        needle = "validate_world_links(&nodes, &links)?";
      }
      {
        label = "latency-below-floor error";
        needle = "WorldLinkLatencyBelowFloor";
      }
      {
        label = "jitter-below-floor error";
        needle = "WorldLinkJitterBelowLatencyFloor";
      }
      {
        label = "latency floor comparison";
        needle = "latency < MIN_LINK_LATENCY";
      }
      {
        label = "effective jitter floor comparison";
        needle = "effective < MIN_LINK_LATENCY.nanos";
      }
      {
        label = "floor enters canonical world material";
        needle = "min_link_latency_ns={}";
      }
      {
        label = "world hash is computed from canonical world material";
        needle = "ContentHash::from_canonical_material(\n                \"crucible.model.world.v1\",\n                &world_material(&nodes, &links),";
      }
      {
        label = "scenario hash includes world ref";
        needle = "world_ref={}";
      }
      {
        label = "lookahead graph uses effective link latency";
        needle = "minimum_latency: link_minimum_latency(&link)";
      }
      {
        label = "jitter-reduced minimum latency";
        needle = "link.latency().nanos.saturating_sub(link.jitter().nanos)";
      }
      {
        label = "binary read validates transport floor";
        needle = "LinkDef::with_transport(endpoint_a, endpoint_b, latency, jitter, loss, bandwidth_bps)";
      }
      {
        label = "TOML read validates transport floor";
        needle = "LinkDef::with_transport(\n        NodeId";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "minimum latency exported";
        needle = "MIN_LINK_LATENCY";
      }
      {
        label = "scheduler floor regression";
        needle = "scheduler_link_latency_floor_rejects_subfloor_before_hashing_and_enters_world_material";
      }
      {
        label = "constructor floor rejection assertion";
        needle = "Err(EngineError::WorldLinkLatencyBelowFloor { latency, minimum, .. })";
      }
      {
        label = "TOML floor rejection assertion";
        needle = "parsed_subfloor";
      }
      {
        label = "world material includes floor assertion";
        needle = "material.contains(\"min_link_latency_ns=1\")";
      }
      {
        label = "scenario identity changes with latency";
        needle = "floor_world.scenario_def().id()";
      }
      {
        label = "lookahead graph uses floor";
        needle = "floor_world.static_topology().lookahead_graph[0].minimum_latency";
      }
      {
        label = "existing transport identity test";
        needle = "world_link_transport_material_affects_world_identity";
      }
      {
        label = "existing invalid transport test";
        needle = "world_link_transport_rejects_invalid_floor_and_loss";
      }
      {
        label = "canonicalization hash regression";
        needle = "canonicalization_hashes_meaning_not_authoring_spelling";
      }
      {
        label = "latency floor canonicalization golden";
        needle = "2f107a46c69f789cd0fa04ed4bca6e7c1d780594789e2167a80bf0dfe3bc21c3";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler link-latency floor check";
        needle = "schedulerLinkLatencyFloor = import ./phase3-scheduler-link-latency-floor.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler link-latency floor check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-link-latency-floor";
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
          name = "run-scheduler-link-latency-floor";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-link-latency-floor-target" \
              -p crucible \
              --lib \
              scheduler_link_latency_floor \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-link-latency-floor-target" \
              -p crucible \
              --lib \
              world_link_transport \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-link-latency-floor-target" \
              -p crucible \
              --lib \
              canonicalization_hashes_meaning_not_authoring_spelling \
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
            component=crucible-scheduler
            min_link_latency_ns=1
            rejection=zero-and-subfloor-effective-link-latency
            scenario_identity=world-ref-includes-min-link-latency-floor
            lookahead=floor-backed-static-topology
            RESULT
          '';
        }
      ];
    }
