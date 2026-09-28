//! Root-owned, write-through guest operation and process records.
//!
//! Each operation is reserved before an effect. A reservation without a
//! committed result is indeterminate after restart and is never reissued.
//!
//! ```text
//! attach-<execution> = canonical JSON { version:3, execution, original_authorize,
//!                                    original_ticket, custody, io:"stream"|"pty" }
//! ```
//!
//! Every present attach row, including legacy byte-one and partial v3 rows,
//! permanently refuses another transfer; readback never reconstructs custody.

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use aos_sandbox_agent::{AgentOperationRequestV1, AgentRuntimeBindingV1};
use aos_sandbox_core::{ExecutionId, ObjectDigest};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::GuestProcessEffectErrorV1;

const LEDGER_PATH: &str = "/var/lib/aos-sandbox-agent/guest-effects-v1";
const O_CLOEXEC: i32 = 0o2_000_000;
const O_NOFOLLOW: i32 = 0o400_000;
const MAX_RECORD_BYTES: u64 = 1_048_576;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct StoredOutcome {
    pub(super) phase: u8,
    pub(super) result: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
struct OperationRecord {
    version: u8,
    request: [u8; 32],
    runtime: [u8; 32],
    outcome: Option<StoredOutcome>,
}

#[derive(Deserialize, Serialize)]
struct QuiesceRecord {
    version: u8,
    quiesced: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct ProcessRecord {
    pub(super) version: u8,
    pub(super) runtime: [u8; 32],
    pub(super) operation: [u8; 16],
    pub(super) execution: [u8; 16],
    pub(super) incarnation: [u8; 16],
    pub(super) assignment_epoch: u64,
    pub(super) principal: [u8; 16],
    pub(super) audit: [u8; 16],
    pub(super) uid: u32,
    pub(super) pid: u32,
    pub(super) start_ticks: u64,
    pub(super) pty: bool,
    #[serde(default)]
    pub(super) attach_io: Option<AttachIoShapeV3>,
    pub(super) canceled: bool,
    #[serde(default)]
    pub(super) terminal: Option<StoredOutcome>,
}

/// Records only the live topology admitted by the original ExecutionSpec.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum AttachIoShapeV3 {
    Stream,
    Pty,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AttachReservationV3 {
    version: u8,
    execution: [u8; 16],
    original_authorize: [u8; 16],
    original_ticket: [u8; 32],
    custody: [u8; 32],
    io: AttachIoShapeV3,
}

pub(super) enum Reservation {
    Fresh,
    Replayed(StoredOutcome),
}

#[derive(Clone)]
pub(super) struct Ledger {
    root: PathBuf,
    effect_barrier: Arc<Mutex<()>>,
}

impl Ledger {
    pub(super) fn open() -> Result<Self, GuestProcessEffectErrorV1> {
        let root = PathBuf::from(LEDGER_PATH);
        for parent in ["/var", "/var/lib", "/var/lib/aos-sandbox-agent"] {
            verify_directory(Path::new(parent), false)?;
        }
        verify_directory(&root, true)?;
        Ok(Self {
            root,
            effect_barrier: Arc::new(Mutex::new(())),
        })
    }

    /// Shares the owner barrier with terminal publication and descriptor send.
    ///
    /// The caller retains this cut through its last effect, not merely through
    /// a process read. Ledger methods do not reacquire it recursively.
    pub(super) fn effect_barrier(&self) -> Arc<Mutex<()>> {
        Arc::clone(&self.effect_barrier)
    }

    pub(super) fn processes(&self) -> Result<Vec<ProcessRecord>, GuestProcessEffectErrorV1> {
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or(GuestProcessEffectErrorV1::LedgerConflict)?;
            if let Some(execution) = name.strip_prefix("process-") {
                if execution.len() != 32 || !execution.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(GuestProcessEffectErrorV1::LedgerConflict);
                }
                let record: ProcessRecord = read_record(&entry.path())?;
                validate_process(&record)?;
                records.push(record);
            }
        }
        Ok(records)
    }

    pub(super) fn has_ambiguous_operation(
        &self,
        current: &AgentOperationRequestV1,
    ) -> Result<bool, GuestProcessEffectErrorV1> {
        let current_name = format!("operation-{}", hex_bytes(current.operation_id().as_bytes()));
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or(GuestProcessEffectErrorV1::LedgerConflict)?;
            if let Some(operation) = name.strip_prefix("operation-") {
                if operation.len() != 32 || !operation.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(GuestProcessEffectErrorV1::LedgerConflict);
                }
                let record: OperationRecord = read_record(&entry.path())?;
                if record.version != 1 {
                    return Err(GuestProcessEffectErrorV1::LedgerConflict);
                }
                if name != current_name && record.outcome.is_none() {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    pub(super) fn read_quiesced(&self) -> Result<bool, GuestProcessEffectErrorV1> {
        let path = self.root.join("quiesce-v1");
        let record: QuiesceRecord = match read_record(&path) {
            Ok(record) => record,
            Err(GuestProcessEffectErrorV1::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        if record.version != 1 {
            return Err(GuestProcessEffectErrorV1::LedgerConflict);
        }
        Ok(record.quiesced)
    }

    pub(super) fn write_quiesced(&self, quiesced: bool) -> Result<(), GuestProcessEffectErrorV1> {
        replace_record(
            &self.root.join("quiesce-v1"),
            &QuiesceRecord {
                version: 1,
                quiesced,
            },
        )?;
        self.sync_directory()
    }

    pub(super) fn reserve(
        &self,
        request: &AgentOperationRequestV1,
        runtime: &AgentRuntimeBindingV1,
        channel: ObjectDigest,
    ) -> Result<Reservation, GuestProcessEffectErrorV1> {
        let path = self.operation_path(request);
        let expected = OperationRecord {
            version: 1,
            request: *request.request_commitment().as_bytes(),
            runtime: runtime_commitment(runtime, channel),
            outcome: None,
        };

        match create_record(&path, &expected) {
            Ok(()) => {
                self.sync_directory()?;
                Ok(Reservation::Fresh)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing: OperationRecord = read_record(&path)?;
                if existing.version != 1
                    || existing.request != expected.request
                    || existing.runtime != expected.runtime
                {
                    return Err(GuestProcessEffectErrorV1::LedgerConflict);
                }
                existing
                    .outcome
                    .map(Reservation::Replayed)
                    .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub(super) fn complete(
        &self,
        request: &AgentOperationRequestV1,
        runtime: &AgentRuntimeBindingV1,
        channel: ObjectDigest,
        outcome: StoredOutcome,
    ) -> Result<(), GuestProcessEffectErrorV1> {
        let record = OperationRecord {
            version: 1,
            request: *request.request_commitment().as_bytes(),
            runtime: runtime_commitment(runtime, channel),
            outcome: Some(outcome),
        };
        replace_record(&self.operation_path(request), &record)?;
        self.sync_directory()?;
        Ok(())
    }

    pub(super) fn write_process(
        &self,
        execution: ExecutionId,
        record: &ProcessRecord,
    ) -> Result<(), GuestProcessEffectErrorV1> {
        create_record(&self.process_path(execution), record)?;
        self.sync_directory()?;
        Ok(())
    }

    pub(super) fn read_process(
        &self,
        execution: ExecutionId,
    ) -> Result<ProcessRecord, GuestProcessEffectErrorV1> {
        let record: ProcessRecord = read_record(&self.process_path(execution))?;
        validate_process(&record)?;
        Ok(record)
    }

    pub(super) fn read_process_bytes(
        &self,
        execution: [u8; 16],
    ) -> Result<ProcessRecord, GuestProcessEffectErrorV1> {
        self.read_process(ExecutionId::from_bytes(execution))
    }

    pub(super) fn reserve_attach(
        &self,
        execution: [u8; 16],
    ) -> Result<(), GuestProcessEffectErrorV1> {
        create_record(
            &self.root.join(format!("attach-{}", hex_bytes(&execution))),
            &1_u8,
        )?;
        self.sync_directory()
    }

    pub(super) fn reserve_original_attach_v3(
        &self,
        process: &ProcessRecord,
        ticket: [u8; 32],
        custody: [u8; 32],
    ) -> Result<(), GuestProcessEffectErrorV1> {
        let io = process
            .attach_io
            .ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
        if ticket == [0; 32] || custody == [0; 32] || process.canceled || process.terminal.is_some()
        {
            return Err(GuestProcessEffectErrorV1::InvalidRequest);
        }
        // One logical slot refuses every old/partial/replayed row. Ticket or
        // topology substitution cannot create a second slot for this process.
        let path = self
            .root
            .join(format!("attach-{}", hex_bytes(&process.execution)));
        let expected = AttachReservationV3 {
            version: 3,
            execution: process.execution,
            original_authorize: process.operation,
            original_ticket: ticket,
            custody,
            io,
        };
        create_record(&path, &expected)?;
        self.sync_directory()?;
        let exact =
            serde_json::to_vec(&expected).map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
        if read_record_bytes(&path)? != exact {
            return Err(GuestProcessEffectErrorV1::LedgerConflict);
        }
        Ok(())
    }

    pub(super) fn replace_process(
        &self,
        execution: ExecutionId,
        record: &ProcessRecord,
    ) -> Result<(), GuestProcessEffectErrorV1> {
        replace_record(&self.process_path(execution), record)?;
        self.sync_directory()?;
        Ok(())
    }

    fn operation_path(&self, request: &AgentOperationRequestV1) -> PathBuf {
        self.root.join(format!(
            "operation-{}",
            hex_bytes(request.operation_id().as_bytes())
        ))
    }

    fn process_path(&self, execution: ExecutionId) -> PathBuf {
        self.root
            .join(format!("process-{}", hex_bytes(execution.as_bytes())))
    }

    fn sync_directory(&self) -> Result<(), GuestProcessEffectErrorV1> {
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
}

fn verify_directory(path: &Path, private: bool) -> Result<(), GuestProcessEffectErrorV1> {
    if !path.exists() {
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    let writable_bits = if private { 0o077 } else { 0o022 };
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & writable_bits != 0 {
        return Err(GuestProcessEffectErrorV1::UnprotectedLedger);
    }
    Ok(())
}

fn validate_process(record: &ProcessRecord) -> Result<(), GuestProcessEffectErrorV1> {
    if record.version != 1
        || record.execution == [0; 16]
        || record.incarnation == [0; 16]
        || record.assignment_epoch == 0
        || record.pid == 0
        || record.start_ticks == 0
    {
        return Err(GuestProcessEffectErrorV1::LedgerConflict);
    }
    Ok(())
}

pub(super) fn runtime_identity(runtime: &AgentRuntimeBindingV1) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-guest-effect-runtime-v1\0");
    digest.update(runtime.sandbox().as_bytes());
    digest.update(runtime.incarnation().as_bytes());
    digest.update(runtime.assignment_epoch().get().to_be_bytes());
    digest.update(runtime.assignment_digest().as_bytes());
    digest.update(runtime.desired_generation().get().to_be_bytes());
    digest.update(runtime.namespace_generation().get().to_be_bytes());
    digest.update(runtime.payload_boot_id());
    digest.finalize().into()
}

fn runtime_commitment(runtime: &AgentRuntimeBindingV1, channel: ObjectDigest) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-guest-effect-channel-v1\0");
    digest.update(runtime_identity(runtime));
    digest.update(channel.as_bytes());
    digest.finalize().into()
}

fn create_record<T: Serialize>(path: &Path, record: &T) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(O_CLOEXEC | O_NOFOLLOW)
        .open(path)?;
    serde_json::to_writer(&mut file, record).map_err(std::io::Error::other)?;
    file.flush()?;
    file.sync_all()
}

fn replace_record<T: Serialize>(path: &Path, record: &T) -> std::io::Result<()> {
    let temporary = path.with_extension("next");
    create_record(&temporary, record)?;
    fs::rename(temporary, path)
}

fn read_record<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, GuestProcessEffectErrorV1> {
    serde_json::from_slice(&read_record_bytes(path)?)
        .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)
}

fn read_record_bytes(path: &Path) -> Result<Vec<u8>, GuestProcessEffectErrorV1> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_CLOEXEC | O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.len() > MAX_RECORD_BYTES
    {
        return Err(GuestProcessEffectErrorV1::UnprotectedLedger);
    }
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(GuestProcessEffectErrorV1::LedgerConflict);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    #[ignore = "requires the dedicated root-owned Guest ledger fixture"]
    fn protected_original_ticket_slot_and_shared_barrier_never_adopt_replay() {
        assert_eq!(rustix::process::getuid().as_raw(), 0);
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let ledger = Ledger {
            root: directory.path().to_path_buf(),
            effect_barrier: Arc::new(Mutex::new(())),
        };
        let process = ProcessRecord {
            version: 1,
            runtime: [1; 32],
            operation: [2; 16],
            execution: [3; 16],
            incarnation: [4; 16],
            assignment_epoch: 1,
            principal: [5; 16],
            audit: [6; 16],
            uid: 1001,
            pid: 1,
            start_ticks: 1,
            pty: true,
            attach_io: Some(AttachIoShapeV3::Pty),
            canceled: false,
            terminal: None,
        };
        let barrier = ledger.effect_barrier();
        let held = barrier.lock().unwrap();
        let contender = ledger.clone();
        let (started, ready) = std::sync::mpsc::channel();
        let (finished, result) = std::sync::mpsc::channel();
        let other = std::thread::spawn(move || {
            started.send(()).unwrap();
            let barrier = contender.effect_barrier();
            let _held = barrier.lock().unwrap();
            finished.send(()).unwrap();
        });
        ready.recv().unwrap();
        assert!(matches!(
            result.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));

        ledger
            .reserve_original_attach_v3(&process, [7; 32], [8; 32])
            .unwrap();
        let path = ledger
            .root
            .join(format!("attach-{}", hex_bytes(&process.execution)));
        let original = read_record_bytes(&path).unwrap();
        assert!(
            ledger
                .reserve_original_attach_v3(&process, [7; 32], [8; 32])
                .is_err()
        );
        assert!(
            ledger
                .reserve_original_attach_v3(&process, [9; 32], [10; 32])
                .is_err()
        );
        assert_eq!(read_record_bytes(&path).unwrap(), original);

        drop(held);
        result
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        other.join().unwrap();
        for (execution, row) in [
            ([11; 16], b"1".as_slice()),
            ([12; 16], b"{\"version\":3".as_slice()),
        ] {
            let mut changed = process.clone();
            changed.execution = execution;
            let path = ledger
                .root
                .join(format!("attach-{}", hex_bytes(&execution)));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .unwrap();
            file.write_all(row).unwrap();
            file.sync_all().unwrap();
            assert!(
                ledger
                    .reserve_original_attach_v3(&changed, [7; 32], [8; 32])
                    .is_err()
            );
        }

        for (attach_io, canceled) in [(None, false), (Some(AttachIoShapeV3::Pty), true)] {
            let mut closed = process.clone();
            closed.execution = [13; 16];
            closed.attach_io = attach_io;
            closed.canceled = canceled;
            assert!(
                ledger
                    .reserve_original_attach_v3(&closed, [7; 32], [8; 32])
                    .is_err()
            );
            assert!(
                !ledger
                    .root
                    .join(format!("attach-{}", hex_bytes(&closed.execution)))
                    .exists()
            );
        }
    }

    #[test]
    fn legacy_partial_foreign_and_cross_topology_rows_cannot_reconstruct_a_consume() {
        let original = AttachReservationV3 {
            version: 3,
            execution: [1; 16],
            original_authorize: [2; 16],
            original_ticket: [3; 32],
            custody: [4; 32],
            io: AttachIoShapeV3::Pty,
        };
        let bytes = serde_json::to_vec(&original).unwrap();
        assert_eq!(
            serde_json::from_slice::<AttachReservationV3>(&bytes).unwrap(),
            original
        );
        assert!(serde_json::from_slice::<AttachReservationV3>(b"1").is_err());
        for length in 0..bytes.len() {
            assert!(serde_json::from_slice::<AttachReservationV3>(&bytes[..length]).is_err());
        }
        let mut foreign = serde_json::to_value(&original).unwrap();
        foreign
            .as_object_mut()
            .unwrap()
            .insert("authorizes".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<AttachReservationV3>(foreign).is_err());
        let stream = AttachReservationV3 {
            io: AttachIoShapeV3::Stream,
            ..original
        };
        assert_ne!(serde_json::to_vec(&stream).unwrap(), bytes);
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 15) as usize] as char);
    }
    encoded
}
