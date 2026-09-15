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
  qmpSurface = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/src/qmp.rs;
  };
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
        label = "QEMU-20 version-nine checkpoint requirement";
        needle = "Production checkpoints MUST capture and restore complete\n  version-nine state";
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
        label = "contained savevm primitive";
        needle = "pub(crate) fn savevm";
      }
      {
        label = "contained exact restore primitive";
        needle = "pub(crate) fn restore_exact_checkpoint";
      }
      {
        label = "snapshot delete API";
        needle = "pub(crate) fn delete_snapshot";
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
        needle = "connect_with_policies";
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
      {
        label = "public monolithic VMState load API";
        needle = "pub fn " + "loadvm";
      }
      {
        label = "monolithic VMState load wire command";
        needle = "QMP_SNAPSHOT_" + "LOAD_COMMAND";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/qmp.rs" qmpTest [
      {
        label = "connect negotiation test";
        needle = "qmp_connect_reads_greeting_and_negotiates_capabilities";
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
            commands=qmp_capabilities,snapshot-save,crucible-checkpoint-restore,snapshot-delete,query-jobs,crucible-hot-fork-plugin-barrier,crucible-hot-fork-rcu-barrier,crucible-hot-fork-async-worker-barrier,crucible-hot-fork-block-barrier,crucible-hot-fork-template,crucible-hot-fork-private-rings,query-crucible-hot-fork-plugin-resource-inventory,quit
            client_api=connect-with-policies-and-typed-bounded-commands
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
