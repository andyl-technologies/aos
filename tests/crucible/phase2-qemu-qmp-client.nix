{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuQmpClient",
  taskIds ? ["T-QEMU-4"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  qemuCargo = builtins.readFile ../../crates/crucible-qemu/Cargo.toml;
  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  qmpLib = builtins.readFile ../../crates/crucible-qemu/src/qmp.rs;
  qmpSnapshotTag = builtins.readFile ../../crates/crucible-qemu/src/qmp/snapshot_tag.rs;
  qmpSurface = qmpLib + qmpSnapshotTag;
  qmpTest = builtins.readFile ../../crates/crucible-qemu/tests/qmp.rs;
  qemuSpec = builtins.readFile ../../docs/rfcs/0010-crucible/10-qemu-integration.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/10-qemu-integration.md" qemuSpec [
      {
        label = "QEMU-19 typed QMP client requirement";
        needle = "**[QEMU-19]** The host MUST provide a typed QMP client";
      }
      {
        label = "QEMU-20 snapshot tag requirement";
        needle = "QMP snapshot tag MUST be derived from the checkpoint's content address";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/Cargo.toml" qemuCargo [
      {
        label = "serde_json dependency";
        needle = "serde_json = { workspace = true }";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "qmp module";
        needle = "mod qmp;";
      }
      {
        label = "qmp client export";
        needle = "QmpClient";
      }
      {
        label = "qmp job poll policy export";
        needle = "QmpJobPollPolicy";
      }
      {
        label = "snapshot tag export";
        needle = "QmpSnapshotTag";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/qmp*.rs" qmpSurface [
      {
        label = "typed client";
        needle = "pub struct QmpClient";
      }
      {
        label = "capability negotiation";
        needle = "QMP_CAPABILITIES_COMMAND";
      }
      {
        label = "connect negotiates capabilities";
        needle = "pub fn connect";
      }
      {
        label = "savevm API";
        needle = "pub fn savevm";
      }
      {
        label = "loadvm API";
        needle = "pub fn loadvm";
      }
      {
        label = "snapshot delete API";
        needle = "pub fn delete_snapshot";
      }
      {
        label = "quit API";
        needle = "pub fn quit";
      }
      {
        label = "hot-fork plugin barrier hold API";
        needle = "pub fn hold_hot_fork_plugin_barrier";
      }
      {
        label = "hot-fork plugin barrier query API";
        needle = "pub fn query_hot_fork_plugin_barrier";
      }
      {
        label = "hot-fork plugin barrier release API";
        needle = "pub fn release_hot_fork_plugin_barrier";
      }
      {
        label = "query-jobs wire command";
        needle = "QMP_QUERY_JOBS_COMMAND";
      }
      {
        label = "snapshot-save wire command";
        needle = "QMP_SNAPSHOT_SAVE_COMMAND";
      }
      {
        label = "snapshot-load wire command";
        needle = "QMP_SNAPSHOT_LOAD_COMMAND";
      }
      {
        label = "snapshot-delete wire command";
        needle = "QMP_SNAPSHOT_DELETE_COMMAND";
      }
      {
        label = "async event skipping";
        needle = "response.get(\"event\").is_some()";
      }
      {
        label = "typed command error";
        needle = "QmpError::Command";
      }
      {
        label = "typed snapshot job failure";
        needle = "QmpError::JobFailed";
      }
      {
        label = "snapshot job polling";
        needle = "fn wait_for_job";
      }
      {
        label = "explicit job poll policy";
        needle = "pub struct QmpJobPollPolicy";
      }
      {
        label = "connect with job poll policy";
        needle = "connect_with_job_poll_policy";
      }
      {
        label = "real job poll interval";
        needle = "QMP_JOB_QUERY_INTERVAL";
      }
      {
        label = "checkpoint-derived tag";
        needle = "from_checkpoint_content_address";
      }
      {
        label = "content hash tag input";
        needle = "address: ContentHash";
      }
      {
        label = "checkpoint tag input";
        needle = "from_checkpoint(checkpoint: &Checkpoint)";
      }
      {
        label = "checkpoint model import";
        needle = "use crucible::{Checkpoint, ContentHash}";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu/src/qmp*.rs" qmpSurface [
      {
        label = "public arbitrary execute path";
        needle = "pub fn " + "execute";
      }
      {
        label = "stringly checkpoint address input";
        needle = "address: impl " + "AsRef" + "<str>";
      }
      {
        label = "stringly checkpoint address conversion";
        needle = "address." + "as_ref()";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/qmp.rs" qmpTest [
      {
        label = "connect negotiation test";
        needle = "qmp_connect_reads_greeting_and_negotiates_capabilities";
      }
      {
        label = "snapshot command tag test";
        needle = "savevm_uses_snapshot_save_with_checkpoint_derived_tag";
      }
      {
        label = "content hash tag derivation test";
        needle = "snapshot_tags_are_derived_from_checkpoint_content_hash";
      }
      {
        label = "loadvm quit test";
        needle = "loadvm_and_quit_are_typed_qmp_commands";
      }
      {
        label = "snapshot delete test";
        needle = "snapshot_delete_uses_the_same_tag_and_vmstate_device";
      }
      {
        label = "event skipping test";
        needle = "qmp_client_skips_async_events_until_command_return";
      }
      {
        label = "snapshot job error test";
        needle = "qmp_snapshot_job_error_is_typed_result_error";
      }
      {
        label = "snapshot job polling test";
        needle = "qmp_snapshot_job_polling_waits_until_concluded";
      }
      {
        label = "snapshot job timeout test";
        needle = "qmp_snapshot_job_timeout_is_typed_result_error";
      }
      {
        label = "typed error test";
        needle = "qmp_error_response_is_typed_result_error";
      }
      {
        label = "hot-fork plugin barrier command test";
        needle = "hot_fork_plugin_barrier_holds_queries_and_releases_oob";
      }
      {
        label = "hot-fork plugin barrier malformed-response test";
        needle = "hot_fork_plugin_barrier_rejects_malformed_or_wrong_action_state";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes qmp client check";
        needle = "qemuQmpClient = import ./phase2-qemu-qmp-client.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 qemu QMP client check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-qmp-client";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
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
          name = "run-qemu-qmp-client";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-qmp-client-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test qmp \
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
            check_scope=task-level
            related_gates=gate:control-responsive,gate:replay-oracle,gate:content-address
            rust_test=crucible-qemu::qmp
            commands=qmp_capabilities,snapshot-save,snapshot-load,snapshot-delete,query-jobs,crucible-hot-fork-plugin-barrier,crucible-hot-fork-rcu-barrier,crucible-hot-fork-bh-timer-barrier,crucible-hot-fork-block-barrier,crucible-hot-fork-template,query-crucible-hot-fork-readiness,query-crucible-hot-fork-thread-inventory,query-crucible-hot-fork-rcu-inventory,query-crucible-hot-fork-aio-inventory,query-crucible-hot-fork-aio-handler-inventory,query-crucible-hot-fork-block-backend-inventory,query-crucible-hot-fork-plugin-resource-inventory,query-crucible-hot-fork-bottom-half-inventory,query-crucible-hot-fork-mutex-inventory,query-crucible-hot-fork-timer-inventory,quit
            public_api=connect,savevm,loadvm,delete_snapshot,hold_hot_fork_plugin_barrier,query_hot_fork_plugin_barrier,release_hot_fork_plugin_barrier,hold_hot_fork_rcu_barrier,query_hot_fork_rcu_barrier,release_hot_fork_rcu_barrier,hold_hot_fork_bh_timer_barrier,query_hot_fork_bh_timer_barrier,release_hot_fork_bh_timer_barrier,hold_hot_fork_block_barrier,query_hot_fork_block_barrier,release_hot_fork_block_barrier,prepare_hot_fork_template,query_hot_fork_template,abort_hot_fork_template,query_hot_fork_readiness,query_hot_fork_thread_inventory,query_hot_fork_rcu_inventory,query_hot_fork_aio_inventory,query_hot_fork_aio_handler_inventory,query_hot_fork_block_backend_inventory,query_hot_fork_bottom_half_inventory,query_hot_fork_mutex_inventory,query_hot_fork_timer_inventory,quit
            capabilities=oob-required
            aio_handler_transport=exec-oob
            block_backend_transport=exec-oob
            bottom_half_transport=exec-oob
            async_events=skipped-until-return-or-error
            errors=typed-result
            snapshot_tag=checkpoint-content-address-derived
            snapshot_job_polling=query-jobs-with-explicit-policy
            arbitrary_execute=false
            RESULT
          '';
        }
      ];
    }
