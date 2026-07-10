{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerTopologyChange",
  taskIds ? ["T-SCHED-22"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  simBackend = builtins.readFile ../../crates/crucible/src/sim_backend.rs;
  qemuQuantum = builtins.readFile ../../crates/crucible-qemu/src/quantum.rs;
  topologyChangeTest = builtins.readFile ../../crates/crucible/tests/scheduler_topology_change.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
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
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-22 checked off";
        needle = "- [x] **T-SCHED-22**";
      }
      {
        label = "T-SCHED-22 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerTopologyChange`";
      }
      {
        label = "boundary recompute note";
        needle = "before the next PICK";
      }
      {
        label = "send freeze note";
        needle = "cross-node sends while a topology change is pending";
      }
      {
        label = "runtime queue note";
        needle = "runtime `queue_topology_change` APIs";
      }
      {
        label = "production adapter note";
        needle = "SimDouble and QEMU outbound emission paths require an explicit scheduler send authorizer";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "topology change trigger";
        needle = "pub enum SchedulerTopologyChangeTrigger";
      }
      {
        label = "topology change payload";
        needle = "pub struct SchedulerTopologyChange";
      }
      {
        label = "scenario queues topology changes";
        needle = "pub topology_changes: Vec<SchedulerTopologyChange>";
      }
      {
        label = "actor topology message";
        needle = "QueueTopologyChange(SchedulerTopologyChange)";
      }
      {
        label = "actor topology queue method";
        needle = "pub fn queue_topology_change";
      }
      {
        label = "boundary apply helper";
        needle = "fn apply_topology_changes_at_boundary";
      }
      {
        label = "boundary before pick";
        needle = "let topology_recomputed = self.apply_topology_changes_at_boundary()?;";
      }
      {
        label = "lookahead recompute from graph";
        needle = "let recomputed_lookahead = graph.lookahead(&node.id);";
      }
      {
        label = "send freeze helper";
        needle = "pub fn authorize_cross_node_send";
      }
      {
        label = "send authorizer trait";
        needle = "pub trait SchedulerSendAuthorizer";
      }
      {
        label = "scheduler implements send authorizer";
        needle = "impl SchedulerSendAuthorizer for SingleScheduler";
      }
      {
        label = "send freeze diagnostic";
        needle = "cross-node sends frozen while topology change is pending";
      }
      {
        label = "topology-only liveness progress";
        needle = "if scheduler.last_topology_recompute";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "topology change export";
        needle = "SchedulerTopologyChange";
      }
      {
        label = "topology trigger export";
        needle = "SchedulerTopologyChangeTrigger";
      }
      {
        label = "send authorization export";
        needle = "SchedulerSendAuthorization";
      }
      {
        label = "send authorizer export";
        needle = "SchedulerSendAuthorizer";
      }
    ]
    ++ failuresFor "crates/crucible/src/sim_backend.rs" simBackend [
      {
        label = "sim quantum requires authorizer";
        needle = "send_authorizer: &dyn SchedulerSendAuthorizer,";
      }
      {
        label = "sim outbound enqueue receives authorizer";
        needle = "self.enqueue_outbound_frame(outbound, send_authorizer)?;";
      }
      {
        label = "sim outbound enqueue authorizes send";
        needle = "send_authorizer.authorize_cross_node_send(&producer, &consumer)?;";
      }
      {
        label = "sim authorizer regression";
        needle = "sim_double_outbound_enqueue_uses_scheduler_send_authorizer";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/sim_backend.rs" simBackend [
      {
        label = "optional sim send authorizer";
        needle = "Option<&dyn SchedulerSendAuthorizer>";
      }
      {
        label = "opt-in sim authorizer wrapper";
        needle = "advance_scripted_quantum_with_send_authorizer";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/quantum.rs" qemuQuantum [
      {
        label = "qemu stores mandatory send authorizer";
        needle = "send_authorizer: &'a dyn SchedulerSendAuthorizer";
      }
      {
        label = "qemu constructor requires send authorizer";
        needle = "send_authorizer: &'a dyn SchedulerSendAuthorizer,";
      }
      {
        label = "qemu outbound enqueue authorization";
        needle = "self.authorize_outbound_send(\"enqueue outbound frame\")?;";
      }
      {
        label = "qemu outbound dequeue authorization";
        needle = "self.authorize_outbound_send(\"dequeue outbound frame\")?;";
      }
      {
        label = "qemu authorized drain helper";
        needle = "fn dequeue_authorized_emitted_outbound";
      }
      {
        label = "qemu outbound uses mandatory authorizer";
        needle = ".authorize_cross_node_send(&producer, &consumer)";
      }
      {
        label = "qemu enqueue regression";
        needle = "qemu_quantum_outbound_enqueue_uses_scheduler_send_authorizer";
      }
      {
        label = "qemu dequeue regression";
        needle = "qemu_quantum_outbound_dequeue_uses_scheduler_send_authorizer";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu/src/quantum.rs" qemuQuantum [
      {
        label = "optional qemu send authorizer";
        needle = "send_authorizer: Option<&'a dyn SchedulerSendAuthorizer>";
      }
      {
        label = "opt-in qemu authorizer setter";
        needle = "pub fn with_send_authorizer";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_topology_change.rs" topologyChangeTest [
      {
        label = "runtime queue test";
        needle = "runtime_topology_change_queue_recomputes_before_next_pick";
      }
      {
        label = "actor queue test";
        needle = "actor_topology_change_message_recomputes_before_next_pick";
      }
      {
        label = "lowered lookahead before pick test";
        needle = "topology_change_recomputes_lowered_lookahead_before_pick";
      }
      {
        label = "send freeze test";
        needle = "pending_topology_change_freezes_cross_node_sends_until_boundary";
      }
      {
        label = "in-flight stale horizon test";
        needle = "lowered_lookahead_prevents_inflight_frame_delivery_under_stale_horizon";
      }
      {
        label = "topology-only liveness test";
        needle = "topology_only_boundary_progress_does_not_deadlock_liveness";
      }
      {
        label = "old horizon sentinel";
        needle = "finite_lookahead(20)";
      }
      {
        label = "new lowered horizon sentinel";
        needle = "finite_lookahead(5)";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_topology_change.rs" topologyChangeTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler topology-change check";
        needle = "schedulerTopologyChange = import ./phase3-scheduler-topology-change.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler topology-change check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-topology-change";
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
          name = "run-scheduler-topology-change";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-topology-change-target" \
              -p crucible \
              --test scheduler_topology_change \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-topology-change-target" \
              -p crucible \
              --features test-double \
              sim_double_outbound_enqueue_uses_scheduler_send_authorizer \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-topology-change-target" \
              -p crucible-qemu \
              qemu_quantum_outbound \
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
            topology_change=boundary-lookahead-recompute-before-pick
            pending_change_send_freeze=true
            stale_horizon_delivery=false
            RESULT
          '';
        }
      ];
    }
