{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialLinkTransport",
  taskIds ? ["T-SPAT-8"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;
  spatialGraph = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-8 completion names latency floor";
        needle = "`MIN_LINK_LATENCY` is exported as";
      }
      {
        label = "T-SPAT-8 completion names fixed-point loss";
        needle = "`LinkLossProbability` stores loss as fixed-point millionths";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "minimum link latency";
        needle = "pub const MIN_LINK_LATENCY: SimDuration";
      }
      {
        label = "fixed-point loss type";
        needle = "pub struct LinkLossProbability";
      }
      {
        label = "lossless probability";
        needle = "pub const ZERO: Self";
      }
      {
        label = "always-drop probability";
        needle = "pub const ONE: Self";
      }
      {
        label = "loss range constructor";
        needle = "pub fn from_millionths(millionths: u32) -> Result<Self, EngineError>";
      }
      {
        label = "transport constructor";
        needle = "pub fn with_transport(";
      }
      {
        label = "latency accessor";
        needle = "pub fn latency(&self) -> SimDuration";
      }
      {
        label = "jitter accessor";
        needle = "pub fn jitter(&self) -> SimDuration";
      }
      {
        label = "loss accessor";
        needle = "pub fn loss(&self) -> LinkLossProbability";
      }
      {
        label = "bandwidth accessor";
        needle = "pub fn bandwidth_bps(&self) -> Option<u64>";
      }
      {
        label = "latency floor error";
        needle = "WorldLinkLatencyBelowFloor";
      }
      {
        label = "jitter floor error";
        needle = "WorldLinkJitterBelowLatencyFloor";
      }
      {
        label = "loss range error";
        needle = "LinkLossProbabilityOutOfRange";
      }
      {
        label = "transport validator";
        needle = "fn validate_link_transport(link: &LinkDef) -> Result<(), EngineError>";
      }
      {
        label = "latency material";
        needle = "link_latency_ns={}";
      }
      {
        label = "minimum latency floor material";
        needle = "min_link_latency_ns={}";
      }
      {
        label = "jitter material";
        needle = "link_jitter_ns={}";
      }
      {
        label = "loss material";
        needle = "link_loss_millionths={}";
      }
      {
        label = "bandwidth material";
        needle = "link_bandwidth_bps={}";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "loss type exported";
        needle = "LinkLossProbability";
      }
      {
        label = "minimum latency exported";
        needle = "MIN_LINK_LATENCY";
      }
      {
        label = "transport material test";
        needle = "world_link_transport_material_affects_world_identity";
      }
      {
        label = "transport rejection test";
        needle = "world_link_transport_rejects_invalid_floor_and_loss";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes spatial link transport check";
        needle = "spatialLinkTransport = import ./phase1-spatial-link-transport.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 spatial link transport check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-spatial-link-transport";
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
          name = "run-spatial-link-transport";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-link-transport-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib \
              world_link_transport \
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
            related_gates=gate:e2e-determinism,gate:content-address
            spatial_graph_task=link-latency-jitter-loss-floor
            min_link_latency_ns=1
            link_jitter_floor=latency-minus-jitter-must-stay-at-floor
            link_loss=fixed-point-millionths
            link_transport_material=latency,jitter,loss,bandwidth
            RESULT
          '';
        }
      ];
    }
