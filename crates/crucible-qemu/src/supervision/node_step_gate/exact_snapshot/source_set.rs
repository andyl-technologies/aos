//! Native VMState source validation shared by guarded hot-fork flights.

use super::child_support::FileIdentity;
use super::*;
use crate::{
    DEFAULT_VMSTATE_NODE_NAME, QmpHotForkProof, QmpHotForkSourceGraphReceipt,
    QmpHotForkTemplateState,
};

use sha2::{Digest as _, Sha256};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};

const SOURCE_ROLLBACK_POLLS: u32 = 100;
const SOURCE_ROLLBACK_POLL_INTERVAL: Duration = Duration::from_millis(10);

pub(super) fn require_vmstate_source(
    state: &QmpHotForkTemplateState,
) -> Result<(), QemuLiveNodeStepGateError> {
    let block = state.block_barrier();
    let source = block.snapshot_sources();
    if !state.transaction_active()
        || !block.snapshot_complete()
        || !block.quiescent()
        || !source.frozen()
        || source.root_count() != 1
        || source.node_count() != 2
        || source.originally_writable_root_count() != 1
        || source.originally_writable_backend_count() != 0
        || block.backend_count() != 0
        || block.writable_backends() != 0
        || !block.snapshot_roots().is_empty()
        || !state.acknowledges(QmpHotForkProof::BlockSnapshot)
        || !state.acknowledges(QmpHotForkProof::AioBottomHalvesAndTimers)
    {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!("unexpected native VMState source proof: {state:?}"),
        });
    }
    Ok(())
}

/// Authenticates the typed native receipt against the independently pinned file.
///
/// # Errors
///
/// Returns an error when the VMState-only graph, retained file identity, or
/// complete contents differ, or its metadata or bytes cannot be read.
pub(super) fn require_vmstate_graph(
    graph: &QmpHotForkSourceGraphReceipt,
    source_file: &File,
    expected: FileIdentity,
) -> Result<(), QemuLiveNodeStepGateError> {
    let [root, file] = graph.members.as_slice() else {
        return Err(invariant(
            "native VMState graph does not contain exactly two nodes",
        ));
    };
    if graph.root_count != 1
        || root.root_node_name != DEFAULT_VMSTATE_NODE_NAME
        || root.driver_name != "qcow2"
        || root.backend_id != 0
        || root.file_backed
        || file.edge_name != "file"
        || file.driver_name != "file"
        || !file.file_backed
        || !file.originally_writable_file
        || (file.file_device, file.file_inode, file.file_size)
            != (expected.device, expected.inode, expected.length)
    {
        return Err(invariant(
            "native graph differs from the retained VMState-only source",
        ));
    }

    let io_error = |source| QemuLiveNodeStepGateError::PrepareRunDirectory {
        path: crate::DEFAULT_VMSTATE_FILE_NAME.into(),
        source,
    };
    let inspect = || source_file.metadata().map_err(io_error);
    let before = inspect()?;
    if !before.is_file()
        || (before.dev(), before.ino(), before.len())
            != (expected.device, expected.inode, expected.length)
    {
        return Err(invariant("retained VMState graph file identity changed"));
    }

    // The duplicate shares the pinned source's open-file description. Positional reads
    // authenticate all bytes without changing its file position.
    let mut digest = Sha256::new();
    let mut position = 0;
    let mut buffer = [0; 64 * 1024];
    while position < expected.length {
        let remaining = expected.length - position;
        let bound = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_error| invariant("VMState graph read bound overflowed"))?;
        let count = source_file
            .read_at(&mut buffer[..bound], position)
            .map_err(io_error)?;
        if count == 0 {
            return Err(invariant(
                "retained VMState graph file ended during authentication",
            ));
        }
        digest.update(&buffer[..count]);
        position += count as u64;
    }
    let after = inspect()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || (before.mtime(), before.mtime_nsec()) != (after.mtime(), after.mtime_nsec())
        || format!("{:x}", digest.finalize()) != file.file_sha256
    {
        return Err(invariant(
            "retained VMState graph file contents changed or differ",
        ));
    }
    Ok(())
}

/// Boundedly restores the native VMState source owned by `generation`.
pub(super) fn abort_vmstate_source_transaction(
    node: &mut QemuNode,
    generation: u64,
) -> Result<(), QemuLiveNodeStepGateError> {
    for poll in 0..SOURCE_ROLLBACK_POLLS {
        let state = node
            .abort_hot_fork_template()
            .map_err(|source| qmp_operation("abort retained native source set", source))?;
        if state.generation() != generation {
            return Err(invariant(
                "source restoration changed its transaction generation",
            ));
        }
        if state.rollback_complete() {
            if state.block_barrier().snapshot_sources().frozen() {
                return Err(invariant("source provenance survived completed rollback"));
            }
            return Ok(());
        }
        if poll + 1 < SOURCE_ROLLBACK_POLLS {
            // Native reopen runs on the main loop. Keep its pending transaction
            // owned and give that loop time before the next explicit abort.
            thread::sleep(SOURCE_ROLLBACK_POLL_INTERVAL);
        }
    }
    Err(invariant(
        "native source restoration exceeded the bounded abort exchanges",
    ))
}

fn invariant(reason: &str) -> QemuLiveNodeStepGateError {
    QemuLiveNodeStepGateError::ExactSnapshotInvariant {
        reason: reason.to_owned(),
    }
}

fn qmp_operation(
    operation: &'static str,
    source: QemuNodeChannelError,
) -> QemuLiveNodeStepGateError {
    QemuLiveNodeStepGateError::node_op(
        operation,
        QemuNodeError::from_channel(crate::QemuNodeChannelPlane::QmpMachineControl, source),
    )
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- exact graph custody fixtures fail at the offending operation.
    #![allow(clippy::expect_used)]

    use std::io::{BufRead as _, BufReader, Seek as _, SeekFrom, Write as _};
    use std::os::unix::net::UnixStream;

    use super::*;
    use serde_json::{Value, json};

    fn vmstate_source() -> (tempfile::NamedTempFile, FileIdentity, Value) {
        let bytes = vec![0x5a; 64 * 1024 + 17];
        let mut source = tempfile::NamedTempFile::new().expect("source file");
        source.write_all(&bytes).expect("source contents");
        let identity = child_support::file_identity(source.path()).expect("source identity");
        let receipt = json!({
            "schema-version": 1, "qemu-pid": 451, "template-generation": 7,
            "runstate-generation": 2, "vmstop-generation": 3,
            "vmstop-request-generation": 4, "barrier-generation": 5,
            "graph-barrier-generation": 6, "graph-mutation-generation": 8,
            "snapshot-generation": 9, "backend-generation": 10,
            "root-count": 1, "node-count": 2,
            "members": [
                { "root-index": 0, "node-index": 0, "parent-index": -1,
                  "backend-id": 0, "backend-name": "", "root-node-name": "vmstate",
                  "node-name": "vmstate", "edge-name": "", "driver-name": "qcow2",
                  "file-backed": false, "originally-writable-file": false,
                  "file-path": "", "file-device": 0, "file-inode": 0,
                  "file-size": 0, "file-sha256": "" },
                { "root-index": 0, "node-index": 1, "parent-index": 0,
                  "backend-id": 0, "backend-name": "", "root-node-name": "vmstate",
                  "node-name": "", "edge-name": "file", "driver-name": "file",
                  "file-backed": true, "originally-writable-file": true,
                  "file-path": "/not-a-reopening-authority", "file-device": identity.device,
                  "file-inode": identity.inode, "file-size": identity.length,
                  "file-sha256": format!("{:x}", Sha256::digest(&bytes)) }
            ]
        });
        (source, identity, receipt)
    }

    // Only the wire peer is a fixture. The public QMP command and closed
    // receipt parser execute unchanged, with the original process/template.
    fn query(response: Value) -> Result<QmpHotForkSourceGraphReceipt, crate::QmpError> {
        let (client, mut peer) = UnixStream::pair().expect("QMP pair");
        peer.set_read_timeout(Some(Duration::from_secs(3)))
            .expect("peer deadline");
        let server = thread::spawn(move || {
            writeln!(
                peer,
                "{}",
                json!({"QMP": {"version": {}, "capabilities": []}})
            )
            .expect("greeting");
            writeln!(peer, "{}", json!({"return": {}})).expect("capabilities response");
            writeln!(peer, "{response}").expect("graph response");

            let mut reader = BufReader::new(peer);
            let mut command = String::new();
            reader
                .read_line(&mut command)
                .expect("capabilities command");
            command.clear();
            reader.read_line(&mut command).expect("graph command");
            let command: Value = serde_json::from_str(&command).expect("typed request");
            assert_eq!(command["exec-oob"], "crucible-hot-fork-source-graph");
            assert_eq!(command["arguments"]["expected-qemu-pid"], 451);
            assert_eq!(command["arguments"]["expected-template-generation"], 7);
        });
        let result = crate::QmpClient::connect(client)
            .and_then(|mut client| client.query_hot_fork_source_graph(451, 7));
        server.join().expect("QMP peer");
        result
    }

    #[test]
    fn vmstate_graph_authenticates_pinned_bytes_without_changing_shared_offset() {
        let (mut source, identity, receipt) = vmstate_source();
        let mut duplicate = source.as_file().try_clone().expect("pinned duplicate");
        source.seek(SeekFrom::Start(3)).expect("original position");
        let graph = query(json!({"return": receipt})).expect("typed graph receipt");

        require_vmstate_graph(&graph, &duplicate, identity).expect("authenticated graph");
        assert_eq!(duplicate.stream_position().expect("duplicate position"), 3);
        assert_eq!(source.stream_position().expect("original position"), 3);
    }

    #[test]
    fn vmstate_graph_refuses_foreign_files_changed_bytes_and_unexpected_roots() {
        let (source, identity, receipt) = vmstate_source();
        for (field, value) in [
            ("file-inode", json!(identity.inode + 1)),
            ("file-size", json!(identity.length + 1)),
            ("file-sha256", json!("0".repeat(64))),
            ("originally-writable-file", json!(false)),
            ("edge-name", json!("backing")),
        ] {
            let mut changed = receipt.clone();
            changed["members"][1][field] = value;
            let graph = query(json!({"return": changed})).expect("well-formed graph");
            assert!(
                require_vmstate_graph(&graph, source.as_file(), identity).is_err(),
                "{field}"
            );
        }
        let mut changed = receipt.clone();
        changed["members"][0]["node-name"] = json!("foreign");
        for member in changed["members"].as_array_mut().expect("members") {
            member["root-node-name"] = json!("foreign");
        }
        let graph = query(json!({"return": changed})).expect("well-formed foreign root");
        assert!(require_vmstate_graph(&graph, source.as_file(), identity).is_err());

        let foreign = tempfile::NamedTempFile::new().expect("foreign descriptor");
        let graph = query(json!({"return": receipt})).expect("typed graph");
        assert!(require_vmstate_graph(&graph, foreign.as_file(), identity).is_err());
        source
            .as_file()
            .write_at(&[0x33], 0)
            .expect("changed source byte");
        assert!(require_vmstate_graph(&graph, source.as_file(), identity).is_err());
    }

    #[test]
    fn vmstate_graph_query_preserves_native_refusal_and_original_identity_checks() {
        assert!(
            query(json!({"error": {"class": "GenericError", "desc": "receipt refused"}})).is_err()
        );
        let (_, _, receipt) = vmstate_source();
        for (field, value) in [
            ("qemu-pid", 452),
            ("template-generation", 8),
            ("root-count", 2),
            ("node-count", 3),
        ] {
            let mut changed = receipt.clone();
            changed[field] = json!(value);
            assert!(query(json!({"return": changed})).is_err(), "{field}");
        }
    }
}
