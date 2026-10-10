//! Launch descriptor retirement after an authenticated native disk seal.

use std::io::{self, Cursor, Read, Write};
use std::time::Duration;

use serde_json::{Value, json};

use super::*;
use crate::qmp::QmpCommandKind;
use crate::qmp::hot_fork::parse_hot_fork_block_seal_state;

struct ScriptedStream {
    input: Cursor<Vec<u8>>,
    written: Vec<u8>,
}

impl Read for ScriptedStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.input.read(buffer)
    }
}

impl Write for ScriptedStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.written.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl QmpTimeoutStream for ScriptedStream {
    fn set_qmp_read_timeout(&mut self, _timeout: Duration) -> io::Result<()> {
        Ok(())
    }

    fn set_qmp_write_timeout(&mut self, _timeout: Duration) -> io::Result<()> {
        Ok(())
    }
}

fn channel(responses: &[Value]) -> Result<QemuQmpVmStateControlChannel<ScriptedStream>, QmpError> {
    let greeting = json!({"QMP": {"version": {}, "capabilities": []}});
    let capabilities = json!({"return": {}});
    let mut input = Vec::new();
    for response in [&greeting, &capabilities].into_iter().chain(responses) {
        input.extend_from_slice(response.to_string().as_bytes());
        input.push(b'\n');
    }
    QmpClient::connect(ScriptedStream {
        input: Cursor::new(input),
        written: Vec::new(),
    })
    .map(QemuQmpVmStateControlChannel::new)
}

fn seal_fixture(
    snapshot: &str,
    overlay: &str,
    inode: u64,
) -> Result<
    (
        crate::QmpHotForkBlockSealState,
        crate::QmpHotForkBlockSealRequest,
        Value,
    ),
    QmpError,
> {
    let candidate = json!({
        "backend-id": 2, "backend-name": "root", "root-node-name": snapshot,
        "file-path": "/private/root.qcow2", "file-device": 12,
        "file-inode": inode, "virtual-size": 4096,
    });
    let mut state = json!({
        "schema-version": 1, "qemu-pid": 431, "receipt-generation": 0,
        "backend-generation": 7, "graph-mutation-generation": 9,
        "barrier-held": false, "barrier-generation": 0, "barrier-quiescent": false,
        "candidates": [candidate], "sealed-roots": [],
    });
    let inventory = parse_hot_fork_block_seal_state(&state, QmpCommandKind::QueryHotForkBlockSeal)?;
    let request =
        crate::QmpHotForkBlockSealRequest::new(inventory.candidates()[0].clone(), overlay)?;

    state["receipt-generation"] = json!(1);
    state["barrier-held"] = json!(true);
    state["barrier-generation"] = json!(11);
    state["barrier-quiescent"] = json!(true);
    state["sealed-roots"] = json!([{
        "backend-id": 2, "backend-name": "root", "overlay-node-name": overlay,
        "snapshot-node-name": snapshot, "snapshot-file-path": "/private/root.qcow2",
        "snapshot-file-device": 12, "snapshot-file-inode": inode, "virtual-size": 4096,
        "overlay-empty": true, "snapshot-read-only": true,
    }]);
    Ok((inventory, request, json!({"return": state})))
}

fn commands(
    channel: &QemuQmpVmStateControlChannel<ScriptedStream>,
) -> Result<Vec<Value>, serde_json::Error> {
    String::from_utf8_lossy(&channel.client.stream.get_ref().written)
        .lines()
        .map(serde_json::from_str)
        .collect()
}

#[test]
fn launch_fdsets_retire_after_sealing_and_only_once() -> Result<(), Box<dyn std::error::Error>> {
    let (inventory, request, sealed) = seal_fixture("original", "private-one", 34)?;
    let (next_inventory, next_request, next_sealed) =
        seal_fixture("private-one", "private-two", 35)?;
    let mut channel = channel(&[sealed, json!({"return": {}}), next_sealed])?;
    channel.retain_guarded_launch_fdsets_until_disk_seal();
    assert_eq!(commands(&channel)?.len(), 1);

    channel.seal_hot_fork_block_roots(&inventory, &[request])?;
    assert!(!channel.guarded_launch_fdsets_pending);
    channel.seal_hot_fork_block_roots(&next_inventory, &[next_request])?;

    let commands = commands(&channel)?;
    assert_eq!(commands.len(), 4);
    assert_eq!(commands[1]["execute"], "crucible-hot-fork-block-seal");
    assert_eq!(commands[2]["execute"], "x-crucible-adopt-launch-fdsets");
    assert_eq!(commands[2]["arguments"]["root-overlay"], true);
    assert_eq!(commands[3]["execute"], "crucible-hot-fork-block-seal");
    Ok(())
}

#[test]
fn seal_refusal_retains_launch_custody_without_adoption() -> Result<(), Box<dyn std::error::Error>>
{
    let (inventory, request, mut malformed) = seal_fixture("original", "private", 34)?;
    malformed["return"]["sealed-roots"][0]["snapshot-file-inode"] = json!(99);
    let refusal = json!({"error": {"class": "GenericError", "desc": "seal refused"}});
    for response in [refusal, malformed] {
        let mut channel = channel(&[response])?;
        channel.retain_guarded_launch_fdsets_until_disk_seal();

        assert!(
            channel
                .seal_hot_fork_block_roots(&inventory, std::slice::from_ref(&request))
                .is_err()
        );
        assert!(channel.guarded_launch_fdsets_pending);
        assert_eq!(commands(&channel)?.len(), 2);
    }
    Ok(())
}

#[test]
fn adoption_failure_cannot_publish_seal_custody() -> Result<(), Box<dyn std::error::Error>> {
    let (inventory, request, sealed) = seal_fixture("original", "private", 34)?;
    let refusal = json!({"error": {"class": "GenericError", "desc": "adoption refused"}});
    for responses in [vec![sealed.clone(), refusal], vec![sealed.clone()]] {
        let mut channel = channel(&responses)?;
        channel.retain_guarded_launch_fdsets_until_disk_seal();

        assert!(
            channel
                .seal_hot_fork_block_roots(&inventory, std::slice::from_ref(&request))
                .is_err()
        );
        assert!(channel.guarded_launch_fdsets_pending);
        assert_eq!(commands(&channel)?.len(), 3);
        assert_eq!(
            channel.client.query_hot_fork_block_seal(),
            Err(QmpError::ConnectionPoisoned)
        );
    }
    Ok(())
}

#[test]
fn adopted_child_channel_has_no_launch_fdsets_to_retire() -> Result<(), Box<dyn std::error::Error>>
{
    let (inventory, request, sealed) = seal_fixture("child", "private", 34)?;
    let mut channel = channel(&[sealed])?;

    channel.seal_hot_fork_block_roots(&inventory, &[request])?;
    assert!(!channel.guarded_launch_fdsets_pending);
    assert_eq!(commands(&channel)?.len(), 2);
    Ok(())
}
