{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.networkLinkSubnode",
  taskIds ? ["T-IO-9"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  networkLink = builtins.readFile ../../crates/crucible/src/network_link_subnode.rs;
  schedulerSource = builtins.readFile ../../crates/crucible/src/scheduler.rs;
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  focusedTest = builtins.readFile ../../crates/crucible/tests/network_link_subnode.rs;
  cargoManifest = builtins.readFile ../../crates/crucible/Cargo.toml;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  ioDoc = builtins.readFile ../../docs/rfcs/0010-crucible/15-io-subnodes.md;
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
    failuresFor "docs/rfcs/0010-crucible/15-io-subnodes.md" ioDoc [
      {
        label = "T-IO-9 checked off";
        needle = "- [x] **T-IO-9**";
      }
      {
        label = "T-IO-9 completion note";
        needle = "Completed by `checks.crucible.phase3.networkLinkSubnode`";
      }
      {
        label = "network link model note";
        needle = "`NetworkLinkSubNode` models directed inter-VM frames";
      }
      {
        label = "SLOT_NET_ROUTER note";
        needle = "`SLOT_NET_ROUTER`";
      }
      {
        label = "fault perturbation note";
        needle = "latency, jitter, reorder, bandwidth, loss, duplicate, and corruption";
      }
    ]
    ++ failuresFor "crates/crucible/src/network_link_subnode.rs" networkLink [
      {
        label = "network link module header";
        needle = "Deterministic network-link sub-node model";
      }
      {
        label = "router slot constant";
        needle = "pub const NETWORK_ROUTER_SLOT_NAME: &str = \"SLOT_NET_ROUTER\"";
      }
      {
        label = "router slot index";
        needle = "pub const NETWORK_ROUTER_SLOT_INDEX: u32 = 31";
      }
      {
        label = "router slot node name";
        needle = "pub const NETWORK_ROUTER_SLOT_NODE_NAME: &str = \"slot-31\"";
      }
      {
        label = "frame input";
        needle = "pub struct NetworkLinkFrame";
      }
      {
        label = "effective fault table";
        needle = "pub struct NetworkLinkEffectiveFaults";
      }
      {
        label = "link subnode";
        needle = "pub struct NetworkLinkSubNode";
      }
      {
        label = "planning entrypoint";
        needle = "pub fn plan_frame";
      }
      {
        label = "base latency perturbation";
        needle = "base_latency: self.link.latency()";
      }
      {
        label = "bandwidth delay";
        needle = "fn bandwidth_delay";
      }
      {
        label = "seeded jitter/reorder delay";
        needle = "fn uniform_delay";
      }
      {
        label = "seeded loss and duplicate";
        needle = "fn bernoulli_fires";
      }
      {
        label = "seeded corruption";
        needle = "fn corrupt_payload_if_needed";
      }
      {
        label = "router event producer";
        needle = "network_router_node()";
      }
      {
        label = "backend input delivery";
        needle = "ScheduledEventPayload::BackendInput";
      }
      {
        label = "source producer preserves source-local sequences";
        needle = "link.source.clone()";
      }
      {
        label = "directed endpoint validation";
        needle = "fn link_has_directed_endpoints";
      }
      {
        label = "overflow errors";
        needle = "DeliveryTimeOverflow";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/network_link_subnode.rs" networkLink [
      {
        label = "wall-clock dependency";
        needle = "SystemTime";
      }
      {
        label = "instant dependency";
        needle = "std::time::Instant";
      }
      {
        label = "thread sleep dependency";
        needle = "std::thread::sleep";
      }
      {
        label = "host filesystem API";
        needle = "std::fs";
      }
      {
        label = "unordered hash map";
        needle = "HashMap";
      }
      {
        label = "panic unwrap";
        needle = ".unwrap()";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "network module exported";
        needle = "pub mod network_link_subnode";
      }
      {
        label = "network link type exported";
        needle = "NetworkLinkSubNode";
      }
      {
        label = "network router exported";
        needle = "network_router_node";
      }
      {
        label = "scheduler resolve helper exported";
        needle = "resolve_network_link_frame";
      }
    ]
    ++ failuresFor "crates/crucible/tests/network_link_subnode.rs" focusedTest [
      {
        label = "focused test header";
        needle = "Checks T-IO-9 deterministic network-link sub-node planning";
      }
      {
        label = "latency bandwidth jitter reorder test";
        needle = "network_link_latency_bandwidth_jitter_and_reorder_set_delivery_icount";
      }
      {
        label = "observed vector interleaving test";
        needle = "network_link_observed_vectors_match_across_host_interleavings";
      }
      {
        label = "host timing negative control";
        needle = "network_link_host_timing_negative_control_differs";
      }
      {
        label = "loss test";
        needle = "network_link_loss_drops_before_duplicate_or_corrupt_outputs";
      }
      {
        label = "duplicate corrupt test";
        needle = "network_link_duplicate_and_corruption_are_seeded_payload_perturbations";
      }
      {
        label = "reorder passing test";
        needle = "network_link_reorder_can_pass_peer_frame_deterministically";
      }
      {
        label = "validation test";
        needle = "network_link_rejects_invalid_endpoints_bandwidth_and_sequence_overflow";
      }
      {
        label = "source-local sequence collision regression";
        needle = "network_link_event_keys_stay_unique_for_source_local_sequences";
      }
      {
        label = "scheduler RESOLVE helper regression";
        needle = "scheduler_resolve_network_link_frame_applies_effective_fault_table";
      }
      {
        label = "router slot assertion";
        needle = "NETWORK_ROUTER_SLOT_NAME";
      }
    ]
    ++ failuresFor "crates/crucible/Cargo.toml" cargoManifest [
      {
        label = "network link named test";
        needle = ''
          name = "network_link_subnode"
          path = "tests/network_link_subnode.rs"
          required-features = ["test-double"]'';
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
      {
        label = "canonical layer1 gate target";
        needle = ''
          gate: "gate:layer1-injection",
                  package: "crucible",
                  test_target: "network_link_subnode",
                  required_features: &["test-double"],
                  placeholder: false,'';
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" schedulerSource [
      {
        label = "scheduler RESOLVE helper";
        needle = "pub fn resolve_network_link_frame";
      }
      {
        label = "scheduler calls link planner";
        needle = ".plan_frame(frame, faults)";
      }
      {
        label = "scheduler emits scheduled events";
        needle = ".to_scheduled_event(link)";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes network link subnode check";
        needle = "networkLinkSubnode = import ./phase3-network-link-subnode.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 network-link subnode check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-network-link-subnode";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
      ];

      phases = [
        "unpackPhase"
        "buildPhase"
        "installPhase"
      ];

      buildPhase = ''
        runHook preBuild

        export CARGO_HOME="$TMPDIR/cargo-home"
        export CARGO_TARGET_DIR="$TMPDIR/crucible-network-link-subnode-target"
        mkdir -p "$CARGO_HOME"
        cp -R ${cargoDeps}/. "$CARGO_HOME"/
        chmod -R u+w "$CARGO_HOME"

        cd crates
        cargo test --frozen --offline -p crucible --features test-double --test network_link_subnode -- --test-threads=1

        runHook postBuild
      '';

      installPhase = ''
        runHook preInstall
        mkdir -p "$out"
        cat > "$out/metadata.txt" <<EOF
        attr=${attrPath}
        tasks=${taskList}
        gate=network-link-subnode
        coverage=latency-bandwidth-jitter-reorder-loss-duplicate-corrupt-slot-net-router
        EOF
        runHook postInstall
      '';
    }
