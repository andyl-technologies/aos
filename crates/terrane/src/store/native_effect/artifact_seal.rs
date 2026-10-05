//! Seals actual synchronized container descriptors before journal commitment.
//!
//! A seal originates only inside the native worker after the same nofollow
//! descriptor has supplied the verified bytes and durable synchronization. Its
//! private fields retain the original physical observations and exclusions.
//! Decoded journal bytes cannot construct a seal or select creator authority.
//!
//! ```text
//! durable Pending -> installed bytes -> descriptor + directory sync -> seal
//! seal + exact current Pending -> protected Committed + directory sync
//! ```

#[path = "artifact_seal/pending.rs"]
pub(super) mod pending;

/// Exposes closed Pending requests and receipts to retained native producers.
pub(super) use pending::{PendingReceipt, PendingRequest};

use super::{
    ExactRead, FencePolicy, MetadataStamp, NamedFence, NativeEffectFailure, NativeExclusion,
    NativeFsEffect, NativeOpenedDirectory, OwnedFinalCheck, ParentFence, Plan, check_opened_name,
    open_native,
};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use terrane_core::gc::{ArtifactBinding, CreationJournal, JournalState};
use terrane_core::identity::{IdentityKind, TERRANE_V1};

#[cfg(test)]
use super::EffectFault;
#[cfg(all(test, feature = "tokio"))]
use super::{TestGate, TestGatePhase, wait_test_gate};

/// Fixes the only body and registered path from which a worker may make a seal.
pub(super) struct SealRequest {
    root: PathBuf,
    key: String,
    path: PathBuf,
    bytes: Vec<u8>,
    owner: u32,
    pending: PendingReceipt,
    result: mpsc::Sender<NativeArtifactSeal>,
}

impl SealRequest {
    /// Borrows the exact artifact name for test phase selection.
    #[cfg(test)]
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

/// Consumes the executor's one-shot result without allowing caller population.
pub(super) struct SealReceiver {
    result: mpsc::Receiver<NativeArtifactSeal>,
}

impl SealReceiver {
    /// Takes the actual completed worker result exactly once.
    ///
    /// # Errors
    /// Returns `Unsupported` when a binding acknowledged without producing a
    /// native seal, including a no-op callback or abandoned execution.
    pub(super) fn take(self) -> Result<NativeArtifactSeal, NativeEffectFailure> {
        self.result.try_recv().map_err(|_| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "native artifact seal unavailable",
            )
            .into()
        })
    }
}

/// Owns the actual descriptor and every original physical hold through commitment.
pub(super) struct NativeArtifactSeal {
    file: File,
    path: PathBuf,
    root: PathBuf,
    key: String,
    bytes: Vec<u8>,
    stamp: MetadataStamp,
    owner: u32,
    directories: Vec<NativeOpenedDirectory>,
    projection: Projection,
    pending: PendingReceipt,
}

/// Fixes one Pending-to-Committed transition using an executor-produced seal.
pub(super) struct CommitRequest {
    seal: NativeArtifactSeal,
    control: PathBuf,
    pending: Vec<u8>,
    binding: ArtifactBinding,
    journal: PathBuf,
    temporary: PathBuf,
    result: mpsc::Sender<CommittedReceipt>,
}

struct CommittedReceipt;

/// Takes native acknowledgment only after complete protected commitment durability.
pub(super) struct CommitReceiver {
    result: mpsc::Receiver<CommittedReceipt>,
}

impl CommitReceiver {
    /// Consumes one actual durable commitment acknowledgment.
    ///
    /// # Errors
    /// Returns `Unsupported` after an unexecuted or no-op success or a binding
    /// which swallowed a physical failure before the native worker completed.
    pub(super) fn take(self) -> Result<(), NativeEffectFailure> {
        self.result.try_recv().map(|_| ()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "native creation commitment unavailable",
            )
            .into()
        })
    }
}

impl CommitRequest {
    /// Borrows the derived staging name for exact absent-preimage capture.
    pub(super) fn temporary_path(&self) -> &Path {
        &self.temporary
    }

    /// Borrows the exact registered journal destination for test phase selection.
    #[cfg(test)]
    pub(super) fn journal_path(&self) -> &Path {
        &self.journal
    }
}

/// Constructs an empty result channel and the closed descriptor-seal request.
///
/// # Errors
/// Rejects a noncanonical container key from the genuine Pending receipt. Only
/// native execution can fill the newly constructed artifact result channel.
pub(super) fn seal_plan(
    pending: PendingReceipt,
    bytes: &[u8],
) -> Result<(Plan, SealReceiver), NativeEffectFailure> {
    let root = pending.root().to_owned();
    let key = pending.key().to_owned();
    let owner = pending.owner();
    container_key(&key)?;
    let (sender, receiver) = mpsc::channel();
    Ok((
        Plan::SealArtifact(Box::new(SealRequest {
            path: root.join(&key),
            root,
            key,
            bytes: bytes.to_vec(),
            owner,
            pending,
            result: sender,
        })),
        SealReceiver { result: receiver },
    ))
}

/// Derives a fixed protected commitment from a seal and exact Pending bytes.
///
/// The temporary suffix belongs to the independent registered 16-byte staging
/// domain. The incarnation nonce is retained verbatim from the durable Pending.
///
/// # Errors
/// Rejects malformed or non-Pending data, wrong key associations, body bindings,
/// or an invalid control path. Execution independently refreshes all inputs.
pub(super) fn commit_plan(
    seal: NativeArtifactSeal,
    control: &Path,
    pending: &[u8],
    binding: ArtifactBinding,
    temporary_nonce: [u8; 16],
) -> Result<(CommitRequest, CommitReceiver), NativeEffectFailure> {
    let decoded = CreationJournal::decode(pending).map_err(io::Error::other)?;
    if decoded.key != seal.key || decoded.state != JournalState::Pending || !control.is_absolute() {
        return Err(io::Error::other("misbound creation Pending").into());
    }
    verify_binding(&seal.key, &binding, &seal.bytes)?;
    let journal = journal_path(control, &seal.key);
    let parent = journal
        .parent()
        .ok_or_else(|| io::Error::other("missing journal parent"))?;
    let suffix: String = temporary_nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let temporary = parent.join(format!(".terrane-tmp:{suffix}"));
    let (sender, receiver) = mpsc::channel();
    Ok((
        CommitRequest {
            seal,
            control: control.to_owned(),
            pending: pending.to_vec(),
            binding,
            journal,
            temporary,
            result: sender,
        },
        CommitReceiver { result: receiver },
    ))
}

fn container_key(key: &str) -> io::Result<()> {
    // Schema validation is neutral key validation, never a creator receipt.
    let proposal = CreationJournal {
        key: key.to_owned(),
        nonce: [0; 32],
        state: JournalState::Pending,
    };
    proposal.encode().map_err(io::Error::other)?;
    if !key.starts_with("objects/pack/") {
        return Err(io::Error::other("creation seal requires a container key"));
    }
    Ok(())
}

fn journal_path(control: &Path, key: &str) -> PathBuf {
    let suffix: String = blake3::hash(key.as_bytes())
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    control.join(".terrane-creation").join(suffix)
}

fn verify_binding(key: &str, binding: &ArtifactBinding, bytes: &[u8]) -> io::Result<()> {
    let (kind, digest, size) = match binding {
        ArtifactBinding::Pack { digest, size } if key.ends_with(".pack") => {
            (IdentityKind::Pack, digest, size)
        }
        ArtifactBinding::Index { digest, size } if key.ends_with(".idx") => {
            (IdentityKind::Index, digest, size)
        }
        _ => {
            return Err(io::Error::other(
                "creation body binding has the wrong artifact kind",
            ));
        }
    };
    if u64::try_from(bytes.len()).map_err(io::Error::other)? != *size {
        return Err(io::Error::other(
            "creation body size differs from its binding",
        ));
    }
    let identity = TERRANE_V1
        .from_digest(kind, digest)
        .map_err(io::Error::other)?;
    TERRANE_V1
        .verify(&identity, bytes)
        .map_err(io::Error::other)
}

struct Projection {
    exclusions: Arc<[NativeExclusion]>,
    names: Vec<NamedFence>,
    preimages: Vec<ExactRead>,
    final_check: Option<OwnedFinalCheck>,
    directories: Option<Arc<[NativeOpenedDirectory]>>,
}

impl Projection {
    fn refresh(&self, changed: &[&Path]) -> Result<(), NativeEffectFailure> {
        if let Some(directories) = &self.directories {
            for directory in directories.iter() {
                directory.check()?;
            }
        }
        for name in &self.names {
            name.check(&self.exclusions)?;
        }
        for preimage in &self.preimages {
            if !changed.contains(&preimage.path.as_path()) {
                preimage.check()?;
            }
        }
        for name in &self.names {
            name.check(&self.exclusions)?;
        }
        if let Some(final_check) = &self.final_check {
            final_check.recheck()?;
        }
        Ok(())
    }

    fn exact(&self, path: &Path, bytes: Option<&[u8]>) -> io::Result<&ExactRead> {
        let read = self
            .preimages
            .iter()
            .find(|read| read.path == path)
            .ok_or_else(|| io::Error::other("creation operation lacks an exact preimage"))?;
        if read.expected.as_deref() != bytes {
            return Err(io::Error::other(
                "creation operation differs from its retained preimage",
            ));
        }
        Ok(read)
    }

    fn root(&self, path: &Path, owner: u32, control: bool) -> io::Result<()> {
        let expected = self
            .names
            .iter()
            .find(|name| name.path == path)
            .ok_or_else(|| io::Error::other("creation operation lacks its retained root"))?;
        let right_policy = if control {
            matches!(expected.policy, FencePolicy::PrivateControlDirectory { owner: actual } if actual == owner)
        } else {
            matches!(expected.policy, FencePolicy::NamespaceDirectory { owner: actual } if actual == owner)
        };
        if !right_policy {
            return Err(io::Error::other(
                "creation operation has the wrong retained root policy",
            ));
        }
        expected.check(&self.exclusions)
    }
}

struct Worker {
    projection: Projection,
    #[cfg(test)]
    faults: Vec<EffectFault>,
    #[cfg(all(test, feature = "tokio"))]
    gates: Vec<TestGate>,
}

impl Worker {
    fn refresh(&self, changed: &[&Path]) -> Result<(), NativeEffectFailure> {
        #[cfg(test)]
        for read in &self.projection.preimages {
            if !changed.contains(&read.path.as_path())
                && self
                    .faults
                    .contains(&EffectFault::UnavailableRead(read.path.clone()))
            {
                return Err(io::Error::other("injected creation exact read failure").into());
            }
        }
        self.projection.refresh(changed)
    }

    fn file_sync(&mut self, file: &File) -> io::Result<()> {
        #[cfg(test)]
        if self.faults.contains(&EffectFault::BeforeFileSync) {
            return Err(io::Error::other("injected creation file sync failure"));
        }
        file.sync_all()?;
        #[cfg(all(test, feature = "tokio"))]
        wait_test_gate(&mut self.gates, TestGatePhase::AfterSourceSync)?;
        #[cfg(test)]
        if self.faults.contains(&EffectFault::AfterFileSync) {
            return Err(io::Error::other(
                "injected creation failure after file sync",
            ));
        }
        Ok(())
    }

    fn directory_sync(
        &mut self,
        directory: &NativeOpenedDirectory,
        committed: bool,
    ) -> io::Result<()> {
        #[cfg(not(test))]
        let _ = committed;
        directory.check()?;
        #[cfg(all(test, feature = "tokio"))]
        wait_test_gate(&mut self.gates, TestGatePhase::BeforeDirectorySync)?;
        #[cfg(test)]
        if self.faults.contains(&EffectFault::BeforeDirectorySync)
            || self
                .faults
                .contains(&EffectFault::BeforeDirectorySyncAt(directory.path.clone()))
            || committed
                && self
                    .faults
                    .contains(&EffectFault::BeforeCommittedDirectorySyncAt(
                        directory.path.clone(),
                    ))
        {
            return Err(io::Error::other("injected creation directory sync failure"));
        }
        directory.file.sync_all()?;
        directory.check()?;
        #[cfg(all(test, feature = "tokio"))]
        wait_test_gate(&mut self.gates, TestGatePhase::AfterDirectorySync)?;
        #[cfg(test)]
        if self
            .faults
            .contains(&EffectFault::AfterDirectorySyncAt(directory.path.clone()))
            || committed
                && self
                    .faults
                    .contains(&EffectFault::AfterCommittedDirectorySyncAt(
                        directory.path.clone(),
                    ))
        {
            return Err(io::Error::other(
                "injected creation failure after directory sync",
            ));
        }
        Ok(())
    }
}

/// Identifies the three closed operations, including one ordinary retention wrapper.
pub(super) fn owns(plan: &Plan) -> bool {
    match plan {
        Plan::SealPendingCreation(_) | Plan::SealArtifact(_) | Plan::CommitCreation(_) => true,
        Plan::RetainedDirectories { operation, .. } => {
            matches!(
                operation.as_ref(),
                Plan::SealPendingCreation(_) | Plan::SealArtifact(_) | Plan::CommitCreation(_)
            )
        }
        _ => false,
    }
}

/// Completes the closed native operation while owning every original exclusion.
///
/// # Errors
/// Preserves current producer refusal and unsafe, replaced, mismatched or
/// unavailable native inputs, body verification and synchronization failures.
pub(super) fn execute(effect: NativeFsEffect) -> Result<(), NativeEffectFailure> {
    let NativeFsEffect {
        exclusions,
        names,
        preimages,
        final_check,
        plan,
        #[cfg(test)]
        faults,
        #[cfg(all(test, feature = "tokio"))]
        gates,
    } = effect;
    let (plan, directories) = match plan {
        Plan::RetainedDirectories {
            directories,
            operation,
        } => (*operation, Some(directories)),
        primitive => (primitive, None),
    };
    let worker = Worker {
        projection: Projection {
            exclusions,
            names,
            preimages,
            final_check,
            directories,
        },
        #[cfg(test)]
        faults,
        #[cfg(all(test, feature = "tokio"))]
        gates,
    };
    #[cfg(all(test, feature = "tokio"))]
    let mut worker = worker;
    #[cfg(all(test, feature = "tokio"))]
    wait_test_gate(&mut worker.gates, TestGatePhase::BeforeChecks)?;
    worker.refresh(&[])?;
    match plan {
        Plan::SealPendingCreation(request) => pending::execute(*request, worker),
        Plan::SealArtifact(request) => seal(*request, worker),
        Plan::CommitCreation(request) => commit(*request, worker),
        _ => Err(io::Error::other("incorrect creation executor dispatch").into()),
    }
}

fn checked_body(
    file: &mut File,
    path: &Path,
    stamp: MetadataStamp,
    bytes: &[u8],
    owner: u32,
) -> io::Result<()> {
    let opened = MetadataStamp::checked(&file.metadata()?)?;
    FencePolicy::Payload { owner }.validate(opened)?;
    if !opened.same_incarnation(stamp) {
        return Err(io::Error::other("sealed artifact descriptor changed"));
    }
    check_opened_name(file, path, false)?;
    file.seek(SeekFrom::Start(0))?;
    let limit = u64::try_from(bytes.len())
        .map_err(io::Error::other)?
        .checked_add(1)
        .ok_or_else(|| io::Error::other("sealed artifact length overflow"))?;
    let mut actual = Vec::new();
    (&mut *file).take(limit).read_to_end(&mut actual)?;
    if actual != bytes {
        return Err(io::Error::other("sealed artifact body changed"));
    }
    let after = MetadataStamp::checked(&file.metadata()?)?;
    if !after.same_incarnation(stamp) {
        return Err(io::Error::other(
            "sealed artifact metadata changed after verification",
        ));
    }
    check_opened_name(file, path, false)
}

fn directories_below(
    read: &ExactRead,
    root: &Path,
    owner: u32,
    control: bool,
) -> io::Result<Vec<NativeOpenedDirectory>> {
    let first = read
        .parents
        .iter()
        .position(|parent| parent.path == root)
        .ok_or_else(|| io::Error::other("creation preimage lacks its root ancestry"))?;
    let mut result = Vec::new();
    for (index, parent) in read.parents.iter().enumerate().skip(first) {
        let policy = if control {
            FencePolicy::PrivateControlDirectory { owner }
        } else {
            FencePolicy::NamespaceDirectory { owner }
        };
        policy.validate(parent.stamp)?;
        let file = open_native(&parent.path, true)?;
        let stamp = MetadataStamp::checked(&file.metadata()?)?;
        if !stamp.same_incarnation(parent.stamp) {
            return Err(io::Error::other("creation directory receipt changed"));
        }
        let parents = read.parents[..index]
            .iter()
            .map(|ancestor| ParentFence {
                path: ancestor.path.clone(),
                stamp: ancestor.stamp,
            })
            .collect();
        let receipt = NativeOpenedDirectory {
            file,
            path: parent.path.clone(),
            stamp,
            policy,
            parents,
        };
        receipt.check()?;
        result.push(receipt);
    }
    Ok(result)
}

fn seal(mut request: SealRequest, mut worker: Worker) -> Result<(), NativeEffectFailure> {
    let path = request.path;
    worker
        .projection
        .root(&request.root, request.owner, false)?;
    request.pending.recheck_installed(&worker.projection)?;
    let preimage = worker.projection.exact(&path, Some(&request.bytes))?;
    let stamp = preimage
        .metadata
        .ok_or_else(|| io::Error::other("artifact seal lacks captured metadata"))?;
    if !matches!(preimage.policy, FencePolicy::Payload { owner } if owner == request.owner)
        || preimage.identity != Some(stamp.identity)
    {
        return Err(io::Error::other("artifact seal lacks a checked payload preimage").into());
    }
    let directories = directories_below(preimage, &request.root, request.owner, false)?;
    #[cfg(all(test, feature = "tokio"))]
    wait_test_gate(&mut worker.gates, TestGatePhase::BeforeOpen)?;
    let mut file = open_native(&path, false)?;
    #[cfg(all(test, feature = "tokio"))]
    wait_test_gate(&mut worker.gates, TestGatePhase::AfterOpen)?;
    worker.refresh(&[])?;
    request.pending.recheck_installed(&worker.projection)?;
    checked_body(&mut file, &path, stamp, &request.bytes, request.owner)?;
    worker.file_sync(&file)?;
    worker.refresh(&[])?;
    request.pending.recheck_installed(&worker.projection)?;
    checked_body(&mut file, &path, stamp, &request.bytes, request.owner)?;
    // Only namespace-root and descendant directory receipts are synchronized.
    // System ancestors above the actual namespace are checked, never flushed.
    for directory in directories.iter().rev() {
        worker.directory_sync(directory, false)?;
        worker.refresh(&[])?;
        request.pending.recheck_installed(&worker.projection)?;
        checked_body(&mut file, &path, stamp, &request.bytes, request.owner)?;
    }
    let result = NativeArtifactSeal {
        file,
        path,
        root: request.root,
        key: request.key,
        bytes: request.bytes,
        stamp,
        owner: request.owner,
        directories,
        projection: worker.projection,
        pending: request.pending,
    };
    // A cancelled waiter cannot interrupt the completed worker's durability.
    // Dropping an undeliverable seal releases its holds only after this point.
    let _ = request.result.send(result);
    Ok(())
}

fn commit(mut request: CommitRequest, mut worker: Worker) -> Result<(), NativeEffectFailure> {
    let owner = request.seal.owner;
    worker.projection.root(&request.seal.root, owner, false)?;
    worker.projection.root(&request.control, owner, true)?;
    request
        .seal
        .projection
        .root(&request.control, owner, true)?;
    let decoded = CreationJournal::decode(&request.pending).map_err(io::Error::other)?;
    if decoded.key != request.seal.key
        || decoded.state != JournalState::Pending
        || request.journal != journal_path(&request.control, &decoded.key)
    {
        return Err(
            io::Error::other("creation commitment has the wrong Pending association").into(),
        );
    }
    verify_binding(&decoded.key, &request.binding, &request.seal.bytes)?;
    let pending_read = worker
        .projection
        .exact(&request.journal, Some(&request.pending))?;
    if !matches!(pending_read.policy, FencePolicy::ProtectedRecord { owner: actual } if actual == owner)
    {
        return Err(io::Error::other("creation Pending lacks protected-record policy").into());
    }
    let directories = directories_below(pending_read, &request.control, owner, true)?;
    let temporary_read = worker.projection.exact(&request.temporary, None)?;
    if !matches!(temporary_read.policy, FencePolicy::ProtectedRecord { owner: actual } if actual == owner)
        || temporary_read.identity.is_some()
        || temporary_read.metadata.is_some()
    {
        return Err(io::Error::other("creation staging lacks protected absent preimage").into());
    }
    let original_pending = request
        .seal
        .projection
        .exact(&request.journal, Some(&request.pending))?;
    if !matches!(original_pending.policy, FencePolicy::ProtectedRecord { owner: actual } if actual == owner)
        || original_pending.metadata.is_none()
    {
        return Err(
            io::Error::other("sealed creation lacks its original protected Pending").into(),
        );
    }
    request.seal.projection.refresh(&[])?;
    request.seal.pending.recheck_installed(&worker.projection)?;
    checked_body(
        &mut request.seal.file,
        &request.seal.path,
        request.seal.stamp,
        &request.seal.bytes,
        owner,
    )?;
    for directory in &request.seal.directories {
        directory.check()?;
    }

    let mut identity = Vec::with_capacity(16);
    identity.extend_from_slice(&request.seal.stamp.identity.0.to_be_bytes());
    identity.extend_from_slice(&request.seal.stamp.identity.1.to_be_bytes());
    let committed = CreationJournal {
        key: decoded.key,
        nonce: decoded.nonce,
        state: JournalState::Committed {
            binding: request.binding,
            file_identity: identity,
        },
    }
    .encode()
    .map_err(io::Error::other)?;
    let mut staged = create_staging(&request.temporary)?;
    staged.write_all(&committed)?;
    let changed = [request.temporary.as_path()];
    worker.refresh(&changed)?;
    request.seal.projection.refresh(&changed)?;
    request.seal.pending.recheck_installed(&worker.projection)?;
    check_opened_name(&staged, &request.temporary, false)?;
    FencePolicy::ProtectedRecord { owner }
        .validate(MetadataStamp::checked(&staged.metadata()?)?)?;
    let final_stamp = MetadataStamp::checked(&staged.metadata()?)?;
    checked_protected(
        &mut staged,
        &request.temporary,
        final_stamp,
        &committed,
        owner,
    )?;
    worker.file_sync(&staged)?;
    checked_protected(
        &mut staged,
        &request.temporary,
        final_stamp,
        &committed,
        owner,
    )?;
    for directory in directories.iter().rev() {
        worker.directory_sync(directory, false)?;
    }
    worker.refresh(&changed)?;
    request.seal.projection.refresh(&changed)?;
    request.seal.pending.recheck_installed(&worker.projection)?;
    checked_body(
        &mut request.seal.file,
        &request.seal.path,
        request.seal.stamp,
        &request.seal.bytes,
        owner,
    )?;
    check_opened_name(&staged, &request.temporary, false)?;
    checked_protected(
        &mut staged,
        &request.temporary,
        final_stamp,
        &committed,
        owner,
    )?;
    #[cfg(all(test, feature = "tokio"))]
    wait_test_gate(&mut worker.gates, TestGatePhase::BeforeOpen)?;
    // The staged protected descriptor is already held; this boundary precedes
    // selecting that exact descriptor under the fixed final journal name.
    #[cfg(all(test, feature = "tokio"))]
    wait_test_gate(&mut worker.gates, TestGatePhase::AfterOpen)?;
    worker.refresh(&changed)?;
    request.seal.projection.refresh(&changed)?;
    request.seal.pending.recheck_installed(&worker.projection)?;
    checked_body(
        &mut request.seal.file,
        &request.seal.path,
        request.seal.stamp,
        &request.seal.bytes,
        owner,
    )?;
    checked_protected(
        &mut staged,
        &request.temporary,
        final_stamp,
        &committed,
        owner,
    )?;
    #[cfg(test)]
    if worker.faults.contains(&EffectFault::BeforeRename) {
        return Err(io::Error::other("injected creation commitment rename failure").into());
    }
    std::fs::rename(&request.temporary, &request.journal)?;
    #[cfg(all(test, feature = "tokio"))]
    wait_test_gate(&mut worker.gates, TestGatePhase::AfterRename)?;
    // Pending has intentionally changed. Refresh every untouched input, then
    // bind the exact newly selected protected descriptor and bytes instead.
    let changed = [request.temporary.as_path(), request.journal.as_path()];
    worker.refresh(&changed)?;
    request.seal.projection.refresh(&changed)?;
    request.seal.pending.recheck_committed()?;
    absent_name(&request.temporary)?;
    checked_protected(
        &mut staged,
        &request.journal,
        final_stamp,
        &committed,
        owner,
    )?;
    checked_body(
        &mut request.seal.file,
        &request.seal.path,
        request.seal.stamp,
        &request.seal.bytes,
        owner,
    )?;
    #[cfg(test)]
    if worker.faults.contains(&EffectFault::AfterRename) {
        return Err(io::Error::other("injected creation failure after commitment rename").into());
    }
    for directory in directories.iter().rev() {
        worker.directory_sync(directory, true)?;
        worker.refresh(&changed)?;
        request.seal.projection.refresh(&changed)?;
        request.seal.pending.recheck_committed()?;
        absent_name(&request.temporary)?;
        checked_protected(
            &mut staged,
            &request.journal,
            final_stamp,
            &committed,
            owner,
        )?;
        checked_body(
            &mut request.seal.file,
            &request.seal.path,
            request.seal.stamp,
            &request.seal.bytes,
            owner,
        )?;
    }
    let _ = request.result.send(CommittedReceipt);
    Ok(())
}

fn absent_name(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::other(
            "creation staging name remained after rename",
        )),
    }
}

fn create_staging(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        // Read access is needed to verify the same staged journal descriptor;
        // the artifact seal itself retains its independent read-only descriptor.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "protected creation staging unavailable",
        ))
    }
}

fn checked_protected(
    file: &mut File,
    path: &Path,
    stamp: MetadataStamp,
    bytes: &[u8],
    owner: u32,
) -> io::Result<()> {
    FencePolicy::ProtectedRecord { owner }.validate(MetadataStamp::checked(&file.metadata()?)?)?;
    checked_body(file, path, stamp, bytes, owner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unexecuted_seal_request_never_produces_a_native_result() {
        let (sender, receiver) = mpsc::channel::<NativeArtifactSeal>();
        let receiver = SealReceiver { result: receiver };
        drop(sender);
        assert!(
            matches!(receiver.take(), Err(NativeEffectFailure::Io(error)) if error.kind() == io::ErrorKind::Unsupported)
        );
    }

    #[test]
    fn an_unexecuted_commit_never_produces_a_durable_acknowledgment() {
        let (sender, receiver) = mpsc::channel::<CommittedReceipt>();
        let receiver = CommitReceiver { result: receiver };
        drop(sender);
        assert!(
            matches!(receiver.take(), Err(NativeEffectFailure::Io(error)) if error.kind() == io::ErrorKind::Unsupported)
        );
    }
}
