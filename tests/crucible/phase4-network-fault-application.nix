{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.networkFaultApplication",
  taskIds ? ["T-FAULT-6"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  deviceBridge = builtins.readFile ../../crates/crucible/src/device.rs;
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  linkFaults = builtins.readFile ../../crates/crucible-device/src/netlink/fault.rs;
  linkResolve = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-device/src/netlink/link.rs;
  };
  faultTest = builtins.readFile ../../crates/crucible/tests/network_fault_application.rs;
  faultDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17-fault-injection.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/17-fault-injection.md" faultDoc [
      {
        label = "T-FAULT-6 completion note";
        needle = "Completed by `checks.crucible.phase4.networkFaultApplication`";
      }
    ]
    ++ failuresFor "crates/crucible/src/device.rs" deviceBridge [
      {
        label = "directed link orientation";
        needle = "pub enum NetworkLinkDirection";
      }
      {
        label = "combined network lowering";
        needle = "pub fn link_faults_from_combined_network";
      }
      {
        label = "combined network application result";
        needle = "pub struct NetworkFaultApplication";
      }
      {
        label = "combined network link plus topology application";
        needle = "pub fn apply_combined_network_faults";
      }
      {
        label = "scheduler-queued network application";
        needle = "pub fn apply_combined_network_faults_to_scheduler";
      }
      {
        label = "scheduler-queued network heal";
        needle = "pub fn heal_combined_network_faults_to_scheduler";
      }
      {
        label = "scheduler topology queue from bridge";
        needle = "scheduler.schedule_topology_change(change)?";
      }
      {
        label = "heal restores topology edges";
        needle = "SchedulerTopologyChange::heal(sequence, restored_edges)";
      }
      {
        label = "partial heal filters still-partitioned restores";
        needle = "!remaining_removed_endpoints.contains(&edge.endpoint())";
      }
      {
        label = "partial heal queues remaining partition removal";
        needle = "SchedulerTopologyChange::partition";
      }
      {
        label = "live link application";
        needle = "pub fn apply_combined_network_faults_to_link";
      }
      {
        label = "partition endpoint removal";
        needle = "pub fn network_partition_removed_edges";
      }
      {
        label = "partition topology change";
        needle = "pub fn network_partition_change";
      }
      {
        label = "basis-point probability lowering";
        needle = "FaultRateBasisPoints::DENOMINATOR";
      }
      {
        label = "exact bit-rate bandwidth lowering";
        needle = "bandwidth_bits_per_sec";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "directed link orientation export";
        needle = "NetworkLinkDirection";
      }
      {
        label = "network application result export";
        needle = "NetworkFaultApplication";
      }
      {
        label = "combined network application export";
        needle = "apply_combined_network_faults";
      }
      {
        label = "scheduler network application export";
        needle = "apply_combined_network_faults_to_scheduler";
      }
      {
        label = "scheduler network heal export";
        needle = "heal_combined_network_faults_to_scheduler";
      }
      {
        label = "link lowering export";
        needle = "link_faults_from_combined_network";
      }
      {
        label = "partition helper export";
        needle = "network_partition_removed_edges";
      }
    ]
    ++ failuresFor "crates/crucible-device/src/netlink/fault.rs" linkFaults [
      {
        label = "directed partition bit";
        needle = "pub partitioned: bool";
      }
      {
        label = "multiple loss rates";
        needle = "pub additional_loss: Vec<Probability>";
      }
      {
        label = "exact bit-rate limits";
        needle = "pub bandwidth_bits_per_sec: Vec<u64>";
      }
      {
        label = "corruption strategies";
        needle = "pub corruption_strategies: Vec<LinkCorruptionStrategy>";
      }
      {
        label = "summed bandwidth delay";
        needle = "pub fn serialization_delay_ns(&self, len_bytes: u64) -> u64";
      }
      {
        label = "strategy draw accounting";
        needle = "pub fn corrupt_bit_draws(&self) -> u32";
      }
      {
        label = "shared loss any-fires predicate";
        needle = "pub fn loss_fires(&self, loss_draw: u64, additional_loss_draws: &[u64]) -> bool";
      }
      {
        label = "seeded field/truncation strategy draws";
        needle = "Self::FieldMutation | Self::Truncation { .. } => 1";
      }
      {
        label = "seeded field-mutation docs";
        needle = "payload byte selected by a deterministic corruption selector draw";
      }
    ]
    ++ failuresFor "crates/crucible-device/src/netlink/link.rs" linkResolve [
      {
        label = "partition drop application";
        needle = "self.faults.partitioned";
      }
      {
        label = "fault-table RNG draw profile";
        needle = "FrameDraws::from_rng_for_faults";
      }
      {
        label = "loss any-fires application";
        needle = "self.faults.loss_fires";
      }
      {
        label = "payload mutation application";
        needle = "fn corrupt_link_payload";
      }
      {
        label = "seeded field mutation selector";
        needle = "let index = (draw % payload.len() as u64) as usize";
      }
      {
        label = "seeded truncation length selector";
        needle = "let remove = (draw % limit as u64) as usize + 1";
      }
      {
        label = "link serialization uses effective table";
        needle = "self.faults.serialization_delay_ns(len)";
      }
    ]
    ++ failuresFor "crates/crucible/tests/network_fault_application.rs" faultTest [
      {
        label = "resolve path test";
        needle = "combined_network_faults_apply_to_netlink_resolve_path";
      }
      {
        label = "loss any-fires test";
        needle = "overlapping_loss_rates_drop_when_any_rate_fires";
      }
      {
        label = "partition topology test";
        needle = "partition_faults_remove_only_covered_scheduler_edges";
      }
      {
        label = "bridge-produced topology application";
        needle = "crucible::apply_combined_network_faults_to_scheduler";
      }
      {
        label = "bridge-produced heal application";
        needle = "crucible::heal_combined_network_faults_to_scheduler";
      }
      {
        label = "scheduler topology application assertion";
        needle = "authorize_cross_node_send";
      }
      {
        label = "heal restore assertion";
        needle = "the bridge-produced heal restores the covered scheduler edge";
      }
      {
        label = "partial partition heal regression";
        needle = "partial_partition_heal_restores_only_uncovered_edges";
      }
      {
        label = "partial heal keeps remaining partition";
        needle = "B->A stays removed because another active partition still covers it";
      }
      {
        label = "partition recording regression";
        needle = "partition_drop_does_not_record_loss_fault_fire";
      }
      {
        label = "loss false under partition assertion";
        needle = "Some(false)";
      }
      {
        label = "directed partition drop assertion";
        needle = "dropped_direction.partitioned";
      }
      {
        label = "lookahead recompute assertion";
        needle = "take_lookahead_recompute";
      }
      {
        label = "payload mutation assertion";
        needle = "vec![0x81, 0, 0]";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 network fault application import";
        needle = "networkFaultApplication = import ./phase4-network-fault-application.nix";
      }
      {
        label = "phase4 network fault application attr path";
        needle = "attrPath = \"checks.crucible.phase4.networkFaultApplication\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/network_fault_application.rs" faultTest [
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
  then throw "crucible phase4 network-fault-application check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-network-fault-application";
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
          name = "run-network-fault-application";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-network-fault-application-target" \
              -p crucible \
              --test network_fault_application \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-network-fault-application-target" \
              -p crucible-device \
              netlink \
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
            link_faults=applied-at-resolve
            loss=any-fires
            bandwidth=exact-bit-rate-summed
            partition=scheduler-effective-edge-removal
            RESULT
          '';
        }
      ];
    }
