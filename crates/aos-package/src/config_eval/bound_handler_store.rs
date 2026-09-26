//! Durable, call-scoped storage for binding-driven handler invocations.
//!
//! Each call owns one private directory containing its journal, transaction
//! blobs, and handler artifact root. Terminal owners remove that whole
//! directory. A restart reopens only a canonical journal and never discovers
//! an executable or provider through the filesystem.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use aos_ability_model::TransactionId;
use aos_provider_protocol::{DurableRequest, InvocationResult};
use serde::{Deserialize, Serialize};

use super::bound_handler::BoundHandlerIdentity;
use super::transaction_blob::TransactionBlobStore;

const CALL_DIRECTORY: &str = "bound-handler-calls";
const JOURNAL_FILE: &str = "journal.json";
const LOCK_FILE: &str = "call.lock";
const JOURNAL_SCHEMA: &str = "aos.ability.bound-handler-call/v1";
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum BoundCallPhase {
    Draft,
    Prepared,
    Executing,
    Terminal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BoundCallJournal {
    schema: String,
    pub(super) transaction: TransactionId,
    pub(super) authority: BoundHandlerIdentity,
    pub(super) request: Option<DurableRequest>,
    pub(super) phase: BoundCallPhase,
    pub(super) result: Option<InvocationResult>,
}

impl BoundCallJournal {
    pub(super) fn draft(transaction: TransactionId, authority: BoundHandlerIdentity) -> Self {
        Self {
            schema: JOURNAL_SCHEMA.into(),
            transaction,
            authority,
            request: None,
            phase: BoundCallPhase::Draft,
            result: None,
        }
    }

    pub(super) fn prepared(
        transaction: TransactionId,
        authority: BoundHandlerIdentity,
        request: DurableRequest,
    ) -> Self {
        Self {
            schema: JOURNAL_SCHEMA.into(),
            transaction,
            authority,
            request: Some(request),
            phase: BoundCallPhase::Prepared,
            result: None,
        }
    }

    fn validate(&self, transaction: &TransactionId) -> io::Result<()> {
        if self.schema != JOURNAL_SCHEMA
            || &self.transaction != transaction
            || matches!(
                self.phase,
                BoundCallPhase::Prepared | BoundCallPhase::Executing | BoundCallPhase::Terminal
            ) != self.request.is_some()
            || (self.phase == BoundCallPhase::Terminal) != self.result.is_some()
        {
            return Err(invalid("bound-handler journal is internally inconsistent"));
        }
        Ok(())
    }
}

pub(super) struct BoundCallStore {
    directory: PathBuf,
    _lock: File,
    blobs: TransactionBlobStore,
    journal: BoundCallJournal,
}

impl BoundCallStore {
    pub(super) fn create(
        runtime_root: &Path,
        journal: BoundCallJournal,
        handler_artifact: &Path,
    ) -> io::Result<Self> {
        let calls = calls_directory(runtime_root)?;
        let directory = calls.join(journal.transaction.0.as_str());
        match fs::symlink_metadata(&directory) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "bound-handler call already exists",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        create_private_directory(&directory)?;
        sync_directory(&calls)?;

        let result = (|| {
            let lock = create_call_lock(&directory)?;
            crate::store::create_config_gc_roots(
                &directory,
                &[],
                &[handler_artifact.display().to_string()],
            )
            .map_err(invalid)?;
            publish_journal(&directory, &journal)?;
            let blobs = TransactionBlobStore::open(&directory, &journal.transaction)?;
            Ok(Self {
                directory: directory.clone(),
                _lock: lock,
                blobs,
                journal,
            })
        })();
        if result.is_err() {
            let _ = remove_call_directory(&directory);
        }
        result
    }

    pub(super) fn open(runtime_root: &Path, transaction: &TransactionId) -> io::Result<Self> {
        let calls = calls_directory(runtime_root)?;
        let directory = calls.join(transaction.0.as_str());
        require_real_directory(&directory)?;
        let lock = open_call_lock(&directory)?
            .ok_or_else(|| invalid("bound-handler call is already open"))?;
        let journal = read_journal(&directory, transaction)?;
        let blobs = TransactionBlobStore::open(&directory, transaction)?;
        Ok(Self {
            directory,
            _lock: lock,
            blobs,
            journal,
        })
    }

    pub(super) const fn journal(&self) -> &BoundCallJournal {
        &self.journal
    }

    pub(super) const fn blobs(&self) -> &TransactionBlobStore {
        &self.blobs
    }

    pub(super) fn replace(&mut self, journal: BoundCallJournal) -> io::Result<()> {
        if journal.transaction != self.journal.transaction
            || journal.authority != self.journal.authority
        {
            return Err(invalid(
                "replacement bound-handler journal changed call identity",
            ));
        }
        journal.validate(&self.journal.transaction)?;
        publish_journal(&self.directory, &journal)?;
        self.journal = journal;
        Ok(())
    }

    pub(super) fn cleanup(self) -> io::Result<()> {
        remove_call_directory(&self.directory)
    }

    #[cfg(test)]
    pub(super) fn directory(&self) -> &Path {
        &self.directory
    }
}

pub(super) fn recover_runtime(runtime_root: &Path) -> io::Result<()> {
    let calls = calls_directory(runtime_root)?;
    for entry in fs::read_dir(&calls)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            return Err(invalid("bound-handler call directory name is not UTF-8"));
        };
        let transaction = TransactionId(aos_ability_model::LocalKey::new(name).map_err(invalid)?);
        let directory = entry.path();
        require_real_directory(&directory)?;
        if !directory.join(LOCK_FILE).try_exists()? {
            remove_call_directory(&directory)?;
            continue;
        }
        let Some(_lock) = open_call_lock(&directory)? else {
            continue;
        };
        let journal = match read_journal(&directory, &transaction) {
            Ok(journal) => journal,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                remove_call_directory(&directory)?;
                continue;
            }
            Err(error) => return Err(error),
        };
        if matches!(
            journal.phase,
            BoundCallPhase::Draft | BoundCallPhase::Terminal
        ) {
            remove_call_directory(&directory)?;
        }
    }
    sync_directory(&calls)
}

fn calls_directory(runtime_root: &Path) -> io::Result<PathBuf> {
    create_private_directory(runtime_root)?;
    let calls = runtime_root.join(CALL_DIRECTORY);
    create_private_directory(&calls)?;
    sync_directory(runtime_root)?;
    Ok(calls)
}

fn create_call_lock(directory: &Path) -> io::Result<File> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(LOCK_FILE))?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive).map_err(io::Error::from)?;
    Ok(lock)
}

fn open_call_lock(directory: &Path) -> io::Result<Option<File>> {
    let path = directory.join(LOCK_FILE);
    require_regular_file(&path)?;
    let lock = OpenOptions::new().read(true).write(true).open(path)?;
    match rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(Some(lock)),
        Err(error) if error == rustix::io::Errno::WOULDBLOCK => Ok(None),
        Err(error) => Err(io::Error::from(error)),
    }
}

fn publish_journal(directory: &Path, journal: &BoundCallJournal) -> io::Result<()> {
    journal.validate(&journal.transaction)?;
    let bytes = aos_contract::canonical::to_vec(journal).map_err(invalid)?;
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = directory.join(format!(".journal-{}-{sequence}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, directory.join(JOURNAL_FILE))?;
    sync_directory(directory)
}

fn read_journal(directory: &Path, transaction: &TransactionId) -> io::Result<BoundCallJournal> {
    let path = directory.join(JOURNAL_FILE);
    require_regular_file(&path)?;
    let bytes = fs::read(&path)?;
    let value = aos_contract::canonical::parse_json(&bytes, "bound-handler call journal")
        .map_err(invalid)?;
    let journal: BoundCallJournal = serde_json::from_value(value).map_err(invalid)?;
    if aos_contract::canonical::to_vec(&journal).map_err(invalid)? != bytes {
        return Err(invalid("bound-handler journal is not canonical"));
    }
    journal.validate(transaction)?;
    Ok(journal)
}

fn remove_call_directory(directory: &Path) -> io::Result<()> {
    require_real_directory(directory)?;
    let parent = directory
        .parent()
        .ok_or_else(|| invalid("bound-handler call has no parent directory"))?;
    fs::remove_dir_all(directory)?;
    sync_directory(parent)
}

fn create_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    require_real_directory(path)?;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions)
}

fn require_real_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("bound-handler path is not a real directory"));
    }
    Ok(())
}

fn require_regular_file(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(invalid("bound-handler path is not a regular file"));
    }
    Ok(())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aos_ability_model::{
        AbilityValue, InterfaceKey, InterfaceName, LocalKey, MethodReference, MethodSemantics,
        ResourceId, ResourceLifetime, ResourceReference, TransactionId,
    };
    use aos_contract::Sha256Digest;
    use aos_provider_protocol::{DurableRequest, REQUEST_SCHEMA, RecoveryMethods};

    use super::*;

    fn transaction(name: &str) -> TransactionId {
        TransactionId(LocalKey::new(name).expect("transaction name"))
    }

    fn authority() -> BoundHandlerIdentity {
        super::super::bound_handler::tests::identity_fixture()
    }

    fn request() -> DurableRequest {
        let interface = InterfaceKey {
            name: InterfaceName::new("aos.test.handler").expect("interface name"),
            abi: std::num::NonZeroU32::MIN,
            descriptor: Sha256Digest::of_bytes("handler interface"),
        };
        let resource: ResourceId = serde_json::from_value(serde_json::json!({
            "provider": {
                "environment": {"authority":"test","key":"host","stage":"host"},
                "key":"provider"
            },
            "key":"resource"
        }))
        .expect("resource identity");
        DurableRequest {
            schema: REQUEST_SCHEMA.into(),
            handler: LocalKey::new("handler").expect("handler key"),
            method: MethodReference {
                interface: interface.clone(),
                method: LocalKey::new("apply").expect("method key"),
            },
            semantics: MethodSemantics::ordinary(aos_ability_model::AccessMode::Read),
            recovery: RecoveryMethods {
                reconcile: None,
                cancel: None,
                compensate: None,
            },
            target: ResourceReference {
                interface,
                resource,
                operations: vec![LocalKey::new("apply").expect("operation key")],
                lifetime: ResourceLifetime::Instance,
            },
            inputs: AbilityValue::new(serde_json::Value::Bool(true)).expect("inputs"),
            resources: Vec::new(),
            native_context_digest: Sha256Digest::of_bytes("resource set"),
        }
    }

    #[test]
    fn terminal_calls_are_removed_during_restart_recovery() {
        let temporary = tempfile::tempdir().expect("runtime root");
        let artifact = tempfile::tempdir().expect("handler artifact");
        let transaction = transaction("terminal-call");
        let mut store = BoundCallStore::create(
            temporary.path(),
            BoundCallJournal::prepared(transaction.clone(), authority(), request()),
            artifact.path(),
        )
        .expect("call store");
        let directory = store.directory().to_path_buf();
        let mut terminal = store.journal().clone();
        terminal.phase = BoundCallPhase::Terminal;
        terminal.result = Some(InvocationResult {
            schema: aos_provider_protocol::RESULT_SCHEMA.into(),
            disposition: aos_provider_protocol::InvocationDisposition::Completed,
            evidence: AbilityValue::new(serde_json::Value::Bool(true)).expect("evidence"),
            outputs: BTreeMap::new(),
            native_context_digest: request().native_context_digest,
        });
        store.replace(terminal).expect("terminal journal");
        drop(store);

        recover_runtime(temporary.path()).expect("restart cleanup");

        assert!(!directory.exists());
    }

    #[test]
    fn cleanup_removes_journal_blobs_and_gc_roots_together() {
        let temporary = tempfile::tempdir().expect("runtime root");
        let artifact = tempfile::tempdir().expect("handler artifact");
        let transaction = transaction("cleanup-call");
        let store = BoundCallStore::create(
            temporary.path(),
            BoundCallJournal::prepared(transaction.clone(), authority(), request()),
            artifact.path(),
        )
        .expect("call store");
        let directory = store.directory().to_path_buf();
        assert!(directory.join("cfgsrc").is_dir());

        store.cleanup().expect("terminal cleanup");

        assert!(!directory.exists());
    }

    #[test]
    fn restart_recovery_skips_active_calls_then_removes_abandoned_drafts() {
        let temporary = tempfile::tempdir().expect("runtime root");
        let artifact = tempfile::tempdir().expect("handler artifact");
        let transaction = transaction("active-draft");
        let store = BoundCallStore::create(
            temporary.path(),
            BoundCallJournal::draft(transaction, authority()),
            artifact.path(),
        )
        .expect("call store");
        let directory = store.directory().to_path_buf();

        recover_runtime(temporary.path()).expect("active recovery pass");
        assert!(directory.exists());

        drop(store);
        recover_runtime(temporary.path()).expect("abandoned draft recovery pass");
        assert!(!directory.exists());
    }

    #[test]
    fn restart_recovery_retains_prepared_calls() {
        let temporary = tempfile::tempdir().expect("runtime root");
        let artifact = tempfile::tempdir().expect("handler artifact");
        let transaction = transaction("prepared-call");
        let store = BoundCallStore::create(
            temporary.path(),
            BoundCallJournal::prepared(transaction.clone(), authority(), request()),
            artifact.path(),
        )
        .expect("call store");
        let directory = store.directory().to_path_buf();
        drop(store);

        recover_runtime(temporary.path()).expect("restart recovery");
        assert!(directory.exists());

        BoundCallStore::open(temporary.path(), &transaction)
            .expect("retained prepared call")
            .cleanup()
            .expect("cleanup");
    }

    #[test]
    fn restart_recovery_removes_prejournal_call_directories() {
        let temporary = tempfile::tempdir().expect("runtime root");
        let directory = calls_directory(temporary.path())
            .expect("call directory")
            .join("partial-call");
        create_private_directory(&directory).expect("partial call directory");

        recover_runtime(temporary.path()).expect("restart recovery");

        assert!(!directory.exists());
    }
}
