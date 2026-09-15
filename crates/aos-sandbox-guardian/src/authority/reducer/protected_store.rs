//! Dormant atomic protected-store adapter for Guardian reducer checkpoints.
//!
//! The dormant owner uses one fixed root-owned directory and activates no
//! service. Its sealed backend binds an exact canonical checkpoint to a
//! monotonic store head, requires byte-exact readback, and retains an
//! outcome-unknown token instead of guessing whether an interrupted commit
//! took effect.

use aos_sandbox_core::ObjectDigest;
use rustix::fs::{
    AtFlags, FileType, FlockOperation, Mode, OFlags, flock, fstat, fsync, open, openat, renameat,
    unlinkat,
};
use sha2::{Digest as _, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use super::{
    GuardianAuthorityReducerV1, GuardianEffectPlanV1, GuardianRecoveryStoreV1, GuardianReducerError,
};

const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.guardian.protected-transaction.v1\0";
const HEAD_DOMAIN: &[u8] = b"aos.sandbox.guardian.protected-head.v1\0";
const RECEIPT_DOMAIN: &[u8] = b"aos.sandbox.guardian.protected-receipt.v1\0";
const JOURNAL_MAGIC: &[u8; 8] = b"AOSGPJ01";
const FRAME_MAGIC: &[u8; 8] = b"AOSGPC01";
const MAXIMUM_JOURNAL_BYTES: usize = 64 * 1024 * 1024;
const MAXIMUM_JOURNAL_RECORDS: usize = 4_096;
const FIXED_DIRECTORY_PATH: &str = "/var/lib/aos/guardian-reducer";
const FIXED_JOURNAL_NAME: &str = "checkpoints.journal";
const FIXED_COMPACTION_NAME: &str = ".checkpoints.journal.compacting";
const FIXED_JOURNAL_PATH: &str = "/var/lib/aos/guardian-reducer/checkpoints.journal";
const FIXED_GENESIS_PATH: &str = "/var/lib/aos/guardian-reducer/genesis.checkpoint";
const FIXED_ADMISSION_PATH: &str = "/var/lib/aos/guardian-reducer/next-admission.observation";
const FIXED_PREPARE_CURRENT_PATH: &str =
    "/var/lib/aos/guardian-reducer/prepare-current.observation";
const FIXED_FREEZE_CURRENT_PATH: &str = "/var/lib/aos/guardian-reducer/freeze-current.observation";
const FIXED_RELEASE_CURRENT_PATH: &str =
    "/var/lib/aos/guardian-reducer/release-current.observation";
const FIXED_OUTCOME_PATH: &str = "/var/lib/aos/guardian-reducer/effect-outcome.observation";
const FIXED_WORKER_DEATH_PATH: &str = "/var/lib/aos/guardian-reducer/worker-death.observation";
const FIXED_KEY_DOMAIN: &[u8] = b"aos.sandbox.guardian.fixed-protected-owner.v1\0";
const FIXED_HEAD_DOMAIN: &[u8] = b"aos.sandbox.guardian.fixed-protected-anchor.v1\0";

mod sealed {
    pub trait Sealed {}
}

/// Reports failure at the dormant Guardian protected-store boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(super) enum GuardianProtectedStoreErrorV1 {
    /// The authenticated store rejected the compare-and-swap transaction.
    #[error("Guardian protected-store transaction was rejected")]
    Rejected,
    /// The committed head, receipt, or readback bytes did not match exactly.
    #[error("Guardian protected-store readback did not match the transaction")]
    ReadbackMismatch,
    /// The reducer did not produce a canonical recoverable checkpoint.
    #[error("Guardian reducer checkpoint was not canonical")]
    InvalidCheckpoint,
    /// Protected journal I/O or canonical replay was unavailable.
    #[error("Guardian protected journal is unavailable")]
    Unavailable,
}

/// Describes one exact compare-and-swap transaction for a Guardian checkpoint.
pub(super) struct GuardianProtectedWriteV1<'a> {
    key: ObjectDigest,
    expected_generation: u64,
    expected_head: ObjectDigest,
    next_generation: u64,
    snapshot_digest: ObjectDigest,
    checkpoint_digest: ObjectDigest,
    transaction_digest: ObjectDigest,
    checkpoint: &'a [u8],
}

/// Classifies the backend result without collapsing an interrupted commit.
pub(super) enum GuardianProtectedWriteOutcomeV1 {
    /// The backend durably committed the exact transaction.
    Committed(GuardianProtectedReceiptV1),
    /// The caller lost the result after the transaction may have committed.
    OutcomeUnknown,
}

/// Carries an authenticated receipt for one atomic protected transaction.
pub(super) struct GuardianProtectedReceiptV1 {
    generation: u64,
    predecessor_head: ObjectDigest,
    current_head: ObjectDigest,
    transaction_digest: ObjectDigest,
    receipt_digest: ObjectDigest,
}

/// Carries one authenticated current record read from the protected store.
pub(super) struct GuardianProtectedReadbackV1 {
    generation: u64,
    predecessor_head: ObjectDigest,
    current_head: ObjectDigest,
    transaction_digest: ObjectDigest,
    receipt_digest: ObjectDigest,
    checkpoint: Vec<u8>,
}

/// Defines the non-implementable protected backend admitted by this adapter.
pub(super) trait GuardianProtectedBackendV1: sealed::Sealed {
    /// Atomically compares the prior head and writes the exact checkpoint.
    ///
    /// An error certifies that no write took effect. Any result lost after the
    /// commit point must be reported as [`GuardianProtectedWriteOutcomeV1::OutcomeUnknown`].
    fn commit_atomically(
        &mut self,
        write: GuardianProtectedWriteV1<'_>,
    ) -> Result<GuardianProtectedWriteOutcomeV1, GuardianProtectedStoreErrorV1>;

    /// Reads the authenticated current record for the exact logical key.
    fn read_current(
        &mut self,
        key: ObjectDigest,
    ) -> Result<GuardianProtectedReadbackV1, GuardianProtectedStoreErrorV1>;
}

/// Owns exclusive monotonic access to one Guardian protected-store row.
pub(super) struct GuardianProtectedStoreSessionV1<'a> {
    backend: &'a mut dyn GuardianProtectedBackendV1,
    key: ObjectDigest,
    generation: u64,
    head: ObjectDigest,
}

/// Proves one exact Guardian checkpoint committed and survived readback.
#[must_use]
pub(super) struct CommittedGuardianCheckpointV1 {
    store: GuardianRecoveryStoreV1,
    snapshot_digest: ObjectDigest,
    generation: u64,
    head: ObjectDigest,
    receipt_digest: ObjectDigest,
}

/// Retains all immutable inputs needed to resolve an ambiguous commit.
#[must_use]
pub(super) struct GuardianCheckpointRecoveryRequiredV1 {
    store: GuardianRecoveryStoreV1,
    key: ObjectDigest,
    expected_generation: u64,
    expected_head: ObjectDigest,
    next_generation: u64,
    snapshot_digest: ObjectDigest,
    checkpoint_digest: ObjectDigest,
    transaction_digest: ObjectDigest,
}

/// Returns either committed state or a still-owned ambiguous recovery token.
#[must_use]
pub(super) enum GuardianCheckpointCommitOutcomeV1 {
    /// Exact commit and readback succeeded.
    Committed(CommittedGuardianCheckpointV1),
    /// Commit outcome must be resolved by authenticated readback.
    RecoveryRequired(GuardianCheckpointRecoveryRequiredV1),
}

/// Resolves an ambiguous commit without discarding its recovery authority.
#[must_use]
pub(super) enum GuardianCheckpointResolutionV1 {
    /// Exact protected readback proved the transaction committed.
    Committed(CommittedGuardianCheckpointV1),
    /// Exact protected readback proved the transaction did not commit.
    NotCommitted,
    /// The commit remains contained and may be resolved again.
    RecoveryRequired {
        recovery: GuardianCheckpointRecoveryRequiredV1,
        reason: GuardianProtectedStoreErrorV1,
    },
}

/// Allows publication only after exact checkpoint commit and readback.
#[must_use]
pub(super) struct GuardianCheckpointPublicationV1 {
    snapshot_digest: ObjectDigest,
    generation: u64,
    head: ObjectDigest,
    receipt_digest: ObjectDigest,
}

/// Carries one reducer-issued Guardian effect after its ambiguity boundary.
#[must_use]
pub(super) struct GuardianEffectHandoffV1 {
    plan: GuardianEffectPlanV1,
    publication: GuardianCheckpointPublicationV1,
}

impl<'a> GuardianProtectedStoreSessionV1<'a> {
    /// Constructs a session from a child integration's authenticated store head.
    fn from_authenticated_backend(
        backend: &'a mut dyn GuardianProtectedBackendV1,
        key: ObjectDigest,
        generation: u64,
        head: ObjectDigest,
    ) -> Result<Self, GuardianProtectedStoreErrorV1> {
        if key.as_bytes() == &[0; 32] || generation == 0 || head.as_bytes() == &[0; 32] {
            return Err(GuardianProtectedStoreErrorV1::ReadbackMismatch);
        }

        Ok(Self {
            backend,
            key,
            generation,
            head,
        })
    }

    /// Commits the reducer's complete canonical checkpoint atomically.
    fn commit_reducer(
        &mut self,
        reducer: &GuardianAuthorityReducerV1,
    ) -> Result<GuardianCheckpointCommitOutcomeV1, GuardianProtectedStoreErrorV1> {
        let snapshot_digest = reducer.snapshot_digest();
        let store = GuardianRecoveryStoreV1::checkpoint(reducer.snapshot())
            .map_err(|_| GuardianProtectedStoreErrorV1::InvalidCheckpoint)?;
        let checkpoint_digest = digest(store.checkpoint_bytes());
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(GuardianProtectedStoreErrorV1::Rejected)?;
        let transaction_digest = transaction_digest(
            self.key,
            self.generation,
            self.head,
            next_generation,
            snapshot_digest,
            checkpoint_digest,
        );
        let write = GuardianProtectedWriteV1 {
            key: self.key,
            expected_generation: self.generation,
            expected_head: self.head,
            next_generation,
            snapshot_digest,
            checkpoint_digest,
            transaction_digest,
            checkpoint: store.checkpoint_bytes(),
        };

        match self.backend.commit_atomically(write)? {
            GuardianProtectedWriteOutcomeV1::Committed(receipt) => {
                let recovery = GuardianCheckpointRecoveryRequiredV1 {
                    store: store.clone(),
                    key: self.key,
                    expected_generation: self.generation,
                    expected_head: self.head,
                    next_generation,
                    snapshot_digest,
                    checkpoint_digest,
                    transaction_digest,
                };
                match self.confirm_commit(store, snapshot_digest, checkpoint_digest, receipt) {
                    Ok(committed) => Ok(GuardianCheckpointCommitOutcomeV1::Committed(committed)),
                    Err(_) => Ok(GuardianCheckpointCommitOutcomeV1::RecoveryRequired(
                        recovery,
                    )),
                }
            }
            GuardianProtectedWriteOutcomeV1::OutcomeUnknown => {
                Ok(GuardianCheckpointCommitOutcomeV1::RecoveryRequired(
                    GuardianCheckpointRecoveryRequiredV1 {
                        store,
                        key: self.key,
                        expected_generation: self.generation,
                        expected_head: self.head,
                        next_generation,
                        snapshot_digest,
                        checkpoint_digest,
                        transaction_digest,
                    },
                ))
            }
        }
    }

    fn confirm_commit(
        &mut self,
        store: GuardianRecoveryStoreV1,
        snapshot_digest: ObjectDigest,
        checkpoint_digest: ObjectDigest,
        receipt: GuardianProtectedReceiptV1,
    ) -> Result<CommittedGuardianCheckpointV1, GuardianProtectedStoreErrorV1> {
        let readback = self.backend.read_current(self.key)?;
        let expected_generation = self
            .generation
            .checked_add(1)
            .ok_or(GuardianProtectedStoreErrorV1::Rejected)?;
        validate_readback(
            self.key,
            self.generation,
            self.head,
            expected_generation,
            snapshot_digest,
            checkpoint_digest,
            store.checkpoint_bytes(),
            &receipt,
            &readback,
        )?;
        let recovered = GuardianRecoveryStoreV1::from_checkpoint_bytes(readback.checkpoint)
            .and_then(GuardianRecoveryStoreV1::recover)
            .map_err(|_| GuardianProtectedStoreErrorV1::InvalidCheckpoint)?;
        if recovered.digest != snapshot_digest {
            return Err(GuardianProtectedStoreErrorV1::InvalidCheckpoint);
        }

        self.generation = expected_generation;
        self.head = receipt.current_head;
        Ok(CommittedGuardianCheckpointV1 {
            store,
            snapshot_digest,
            generation: receipt.generation,
            head: receipt.current_head,
            receipt_digest: receipt.receipt_digest,
        })
    }

    /// Resolves an interrupted commit only by authenticated current readback.
    fn resolve_ambiguous(
        &mut self,
        recovery: GuardianCheckpointRecoveryRequiredV1,
    ) -> GuardianCheckpointResolutionV1 {
        match self.try_resolve_ambiguous(&recovery) {
            Ok(committed) => GuardianCheckpointResolutionV1::Committed(committed),
            Err(GuardianProtectedStoreErrorV1::Rejected) => {
                GuardianCheckpointResolutionV1::NotCommitted
            }
            Err(reason) => GuardianCheckpointResolutionV1::RecoveryRequired { recovery, reason },
        }
    }

    fn try_resolve_ambiguous(
        &mut self,
        recovery: &GuardianCheckpointRecoveryRequiredV1,
    ) -> Result<CommittedGuardianCheckpointV1, GuardianProtectedStoreErrorV1> {
        if recovery.key != self.key
            || recovery.expected_generation != self.generation
            || recovery.expected_head != self.head
        {
            return Err(GuardianProtectedStoreErrorV1::ReadbackMismatch);
        }
        let readback = self.backend.read_current(self.key)?;
        if readback.generation == recovery.expected_generation
            && readback.current_head == recovery.expected_head
        {
            return Err(GuardianProtectedStoreErrorV1::Rejected);
        }
        let receipt = GuardianProtectedReceiptV1 {
            generation: readback.generation,
            predecessor_head: readback.predecessor_head,
            current_head: readback.current_head,
            transaction_digest: readback.transaction_digest,
            receipt_digest: readback.receipt_digest,
        };
        validate_readback(
            recovery.key,
            recovery.expected_generation,
            recovery.expected_head,
            recovery.next_generation,
            recovery.snapshot_digest,
            recovery.checkpoint_digest,
            recovery.store.checkpoint_bytes(),
            &receipt,
            &readback,
        )?;
        if readback.transaction_digest != recovery.transaction_digest {
            return Err(GuardianProtectedStoreErrorV1::ReadbackMismatch);
        }
        let recovered = GuardianRecoveryStoreV1::from_checkpoint_bytes(readback.checkpoint.clone())
            .and_then(GuardianRecoveryStoreV1::recover)
            .map_err(|_| GuardianProtectedStoreErrorV1::InvalidCheckpoint)?;
        if recovered.digest != recovery.snapshot_digest {
            return Err(GuardianProtectedStoreErrorV1::InvalidCheckpoint);
        }

        self.generation = recovery.next_generation;
        self.head = readback.current_head;
        Ok(CommittedGuardianCheckpointV1 {
            store: recovery.store.clone(),
            snapshot_digest: recovery.snapshot_digest,
            generation: readback.generation,
            head: readback.current_head,
            receipt_digest: readback.receipt_digest,
        })
    }
}

impl CommittedGuardianCheckpointV1 {
    /// Consumes durable state to authorize a publication of this exact head.
    pub(super) fn into_publication(self) -> GuardianCheckpointPublicationV1 {
        GuardianCheckpointPublicationV1 {
            snapshot_digest: self.snapshot_digest,
            generation: self.generation,
            head: self.head,
            receipt_digest: self.receipt_digest,
        }
    }

    /// Borrows the exact canonical checkpoint retained after readback.
    pub(super) fn checkpoint_bytes(&self) -> &[u8] {
        self.store.checkpoint_bytes()
    }
}

impl GuardianCheckpointPublicationV1 {
    /// Binds a reducer-issued plan to its already durable ambiguity boundary.
    pub(super) fn into_effect_handoff(
        self,
        plan: GuardianEffectPlanV1,
    ) -> Result<GuardianEffectHandoffV1, GuardianProtectedStoreErrorV1> {
        if plan.recovery_digest() != self.snapshot_digest {
            return Err(GuardianProtectedStoreErrorV1::ReadbackMismatch);
        }
        Ok(GuardianEffectHandoffV1 {
            plan,
            publication: self,
        })
    }
}

impl GuardianEffectHandoffV1 {
    /// Returns the exact reducer-issued effect plan.
    pub(super) fn plan(&self) -> &GuardianEffectPlanV1 {
        &self.plan
    }

    /// Returns the durable protected head that preceded effect release.
    pub(super) fn protected_head(&self) -> ObjectDigest {
        self.publication.head
    }
}

/// Owns one authenticated, append-only Guardian checkpoint journal.
///
/// The type is crate-private and implements the sealed backend directly, so
/// callers cannot synthesize receipts. Initialization and reopen require an
/// already-opened file supplied by the Guardian's protected-file owner.
pub(super) struct GuardianProtectedJournalV1 {
    file: File,
    key: ObjectDigest,
    anchor_generation: u64,
    anchor_head: ObjectDigest,
    current: Option<GuardianJournalRowV1>,
    record_count: usize,
    journal_bytes: usize,
    poisoned: bool,
    fatal_swap_failure: bool,
}

#[derive(Clone)]
struct GuardianJournalRowV1 {
    key: ObjectDigest,
    expected_generation: u64,
    generation: u64,
    predecessor_head: ObjectDigest,
    current_head: ObjectDigest,
    snapshot_digest: ObjectDigest,
    checkpoint_digest: ObjectDigest,
    transaction_digest: ObjectDigest,
    receipt_digest: ObjectDigest,
    checkpoint: Vec<u8>,
}

impl GuardianProtectedJournalV1 {
    /// Initializes an empty protected journal with one exact authenticated head.
    pub(super) fn initialize(
        mut file: File,
        key: ObjectDigest,
        generation: u64,
        head: ObjectDigest,
    ) -> Result<Self, GuardianProtectedStoreErrorV1> {
        if key.as_bytes() == &[0; 32]
            || generation == 0
            || head.as_bytes() == &[0; 32]
            || file
                .metadata()
                .map_err(|_| GuardianProtectedStoreErrorV1::Unavailable)?
                .len()
                != 0
        {
            return Err(GuardianProtectedStoreErrorV1::Rejected);
        }
        flock(&file, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| GuardianProtectedStoreErrorV1::Unavailable)?;
        let header = encode_guardian_header(key, generation, head);
        file.seek(SeekFrom::Start(0))
            .and_then(|_| file.write_all(&header))
            .and_then(|_| file.sync_data())
            .map_err(|_| GuardianProtectedStoreErrorV1::Unavailable)?;
        Ok(Self {
            file,
            key,
            anchor_generation: generation,
            anchor_head: head,
            current: None,
            record_count: 0,
            journal_bytes: header.len(),
            poisoned: false,
            fatal_swap_failure: false,
        })
    }

    /// Reopens and canonically replays one bounded protected journal.
    fn reopen(
        mut file: File,
        expected_key: ObjectDigest,
    ) -> Result<Self, GuardianProtectedStoreErrorV1> {
        flock(&file, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| GuardianProtectedStoreErrorV1::Unavailable)?;
        let replay = replay_guardian_journal(&mut file, expected_key)?;
        Ok(Self {
            file,
            key: expected_key,
            anchor_generation: replay.anchor_generation,
            anchor_head: replay.anchor_head,
            current: replay.current,
            record_count: replay.record_count,
            journal_bytes: replay.journal_bytes,
            poisoned: false,
            fatal_swap_failure: false,
        })
    }

    /// Reopens the journal and reconstructs its authoritative current reducer.
    pub(super) fn reopen_recovered(
        file: File,
        expected_key: ObjectDigest,
    ) -> Result<RecoveredGuardianProtectedStateV1, GuardianProtectedStoreErrorV1> {
        Self::reopen(file, expected_key)?.into_recovered()
    }

    /// Commits the first reducer checkpoint above a newly provisioned anchor.
    pub(super) fn checkpoint_initial(
        &mut self,
        reducer: &GuardianAuthorityReducerV1,
    ) -> Result<GuardianCheckpointCommitOutcomeV1, GuardianProtectedStoreErrorV1> {
        if self.current.is_some() {
            return Err(GuardianProtectedStoreErrorV1::Rejected);
        }
        self.session()?.commit_reducer(reducer)
    }

    /// Resolves an ambiguous initial checkpoint without permitting a successor.
    pub(super) fn resolve_initial(
        &mut self,
        recovery: GuardianCheckpointRecoveryRequiredV1,
    ) -> GuardianCheckpointResolutionV1 {
        let mut session = match self.session() {
            Ok(session) => session,
            Err(reason) => {
                return GuardianCheckpointResolutionV1::RecoveryRequired { recovery, reason };
            }
        };
        session.resolve_ambiguous(recovery)
    }

    /// Consumes a journal whose current row authenticates a recoverable reducer.
    pub(super) fn into_recovered(
        self,
    ) -> Result<RecoveredGuardianProtectedStateV1, GuardianProtectedStoreErrorV1> {
        let row = self
            .current
            .as_ref()
            .ok_or(GuardianProtectedStoreErrorV1::InvalidCheckpoint)?;
        let store = GuardianRecoveryStoreV1::from_checkpoint_bytes(row.checkpoint.clone())
            .map_err(|_| GuardianProtectedStoreErrorV1::InvalidCheckpoint)?;
        let snapshot = store
            .recover()
            .map_err(|_| GuardianProtectedStoreErrorV1::InvalidCheckpoint)?;
        if snapshot.digest != row.snapshot_digest {
            return Err(GuardianProtectedStoreErrorV1::ReadbackMismatch);
        }
        let durable_snapshot_digest = row.snapshot_digest;
        let reducer = GuardianAuthorityReducerV1::recover(snapshot)
            .map_err(|_| GuardianProtectedStoreErrorV1::InvalidCheckpoint)?;

        Ok(RecoveredGuardianProtectedStateV1 {
            journal: self,
            reducer,
            durable_snapshot_digest,
        })
    }

    /// Borrows a reducer session at the exact replayed current head.
    fn session(
        &mut self,
    ) -> Result<GuardianProtectedStoreSessionV1<'_>, GuardianProtectedStoreErrorV1> {
        let key = self.key;
        let (generation, head) = self.coordinates();
        GuardianProtectedStoreSessionV1::from_authenticated_backend(self, key, generation, head)
    }

    fn coordinates(&self) -> (u64, ObjectDigest) {
        self.current
            .as_ref()
            .map_or((self.anchor_generation, self.anchor_head), |row| {
                (row.generation, row.current_head)
            })
    }

    fn compact_fixed_file(&mut self) -> Result<(), GuardianProtectedStoreErrorV1> {
        if self.fatal_swap_failure {
            return Err(GuardianProtectedStoreErrorV1::Unavailable);
        }
        self.reload()?;
        let row = self
            .current
            .clone()
            .ok_or(GuardianProtectedStoreErrorV1::InvalidCheckpoint)?;
        let directory = open(
            FIXED_DIRECTORY_PATH,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| GuardianProtectedStoreErrorV1::Unavailable)?;
        validate_guardian_fixed_directory(&directory)?;
        match unlinkat(&directory, FIXED_COMPACTION_NAME, AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(_) => return Err(GuardianProtectedStoreErrorV1::Unavailable),
        }
        let descriptor = openat(
            &directory,
            FIXED_COMPACTION_NAME,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| GuardianProtectedStoreErrorV1::Unavailable)?;
        let mut replacement = File::from(descriptor);
        let header =
            encode_guardian_header(self.key, row.expected_generation, row.predecessor_head);
        let frame = encode_guardian_frame(&row)?;
        if replacement
            .write_all(&header)
            .and_then(|_| replacement.write_all(&frame))
            .and_then(|_| replacement.sync_all())
            .is_err()
        {
            self.poisoned = true;
            return Err(GuardianProtectedStoreErrorV1::Unavailable);
        }
        flock(&replacement, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| GuardianProtectedStoreErrorV1::Unavailable)?;
        let before_swap = replay_guardian_journal(&mut replacement, self.key)?;
        if before_swap
            .current
            .as_ref()
            .map(|current| current.transaction_digest)
            != Some(row.transaction_digest)
            || before_swap.record_count != 1
        {
            return Err(GuardianProtectedStoreErrorV1::ReadbackMismatch);
        }
        renameat(
            &directory,
            FIXED_COMPACTION_NAME,
            &directory,
            FIXED_JOURNAL_NAME,
        )
        .map_err(|_| GuardianProtectedStoreErrorV1::Unavailable)?;
        self.file = replacement;
        self.anchor_generation = before_swap.anchor_generation;
        self.anchor_head = before_swap.anchor_head;
        self.current = before_swap.current;
        self.record_count = before_swap.record_count;
        self.journal_bytes = before_swap.journal_bytes;
        if fsync(&directory).is_err() {
            self.poisoned = true;
            self.fatal_swap_failure = true;
            return Err(GuardianProtectedStoreErrorV1::Unavailable);
        }
        let replay = match replay_guardian_journal(&mut self.file, self.key) {
            Ok(replay) => replay,
            Err(error) => {
                self.poisoned = true;
                self.fatal_swap_failure = true;
                return Err(error);
            }
        };
        if replay
            .current
            .as_ref()
            .map(|current| current.transaction_digest)
            != Some(row.transaction_digest)
            || replay.record_count != 1
        {
            self.poisoned = true;
            self.fatal_swap_failure = true;
            return Err(GuardianProtectedStoreErrorV1::ReadbackMismatch);
        }
        self.anchor_generation = replay.anchor_generation;
        self.anchor_head = replay.anchor_head;
        self.current = replay.current;
        self.record_count = replay.record_count;
        self.journal_bytes = replay.journal_bytes;
        self.poisoned = false;
        Ok(())
    }

    fn reload(&mut self) -> Result<(), GuardianProtectedStoreErrorV1> {
        if self.fatal_swap_failure {
            return Err(GuardianProtectedStoreErrorV1::Unavailable);
        }
        let replay = replay_guardian_journal(&mut self.file, self.key)?;
        if replay.anchor_generation != self.anchor_generation
            || replay.anchor_head != self.anchor_head
        {
            return Err(GuardianProtectedStoreErrorV1::ReadbackMismatch);
        }
        self.current = replay.current;
        self.record_count = replay.record_count;
        self.journal_bytes = replay.journal_bytes;
        self.poisoned = false;
        Ok(())
    }
}

impl sealed::Sealed for GuardianProtectedJournalV1 {}

impl GuardianProtectedBackendV1 for GuardianProtectedJournalV1 {
    fn commit_atomically(
        &mut self,
        write: GuardianProtectedWriteV1<'_>,
    ) -> Result<GuardianProtectedWriteOutcomeV1, GuardianProtectedStoreErrorV1> {
        if self.poisoned {
            return Ok(GuardianProtectedWriteOutcomeV1::OutcomeUnknown);
        }
        self.reload()?;
        let expected_transaction = transaction_digest(
            write.key,
            write.expected_generation,
            write.expected_head,
            write.next_generation,
            write.snapshot_digest,
            write.checkpoint_digest,
        );
        if write.key != self.key
            || write.expected_generation.checked_add(1) != Some(write.next_generation)
            || write.transaction_digest != expected_transaction
            || write.checkpoint.is_empty()
            || write.checkpoint.len() > super::MAXIMUM_GUARDIAN_CHECKPOINT_BYTES
            || digest(write.checkpoint) != write.checkpoint_digest
        {
            return Err(GuardianProtectedStoreErrorV1::Rejected);
        }
        if let Some(current) = &self.current {
            if current.transaction_digest == write.transaction_digest
                && current.generation == write.next_generation
                && current.predecessor_head == write.expected_head
                && current.checkpoint == write.checkpoint
            {
                return Ok(GuardianProtectedWriteOutcomeV1::Committed(
                    guardian_receipt(current),
                ));
            }
        }
        if self.coordinates() != (write.expected_generation, write.expected_head) {
            return Err(GuardianProtectedStoreErrorV1::Rejected);
        }
        let next_snapshot = recover_guardian_journal_snapshot(write.checkpoint)?;
        let predecessor_is_valid = match &self.current {
            Some(current) => {
                recover_guardian_journal_snapshot(&current.checkpoint).is_ok_and(|prior| {
                    GuardianAuthorityReducerV1::validates_journal_successor(&prior, &next_snapshot)
                })
            }
            None => true,
        };
        if next_snapshot.digest != write.snapshot_digest || !predecessor_is_valid {
            return Err(GuardianProtectedStoreErrorV1::InvalidCheckpoint);
        }

        let current_head = protected_head(
            write.expected_head,
            write.next_generation,
            write.transaction_digest,
        );
        let receipt_digest = guardian_receipt_digest(
            self.key,
            write.next_generation,
            write.expected_head,
            current_head,
            write.transaction_digest,
            write.checkpoint_digest,
        );
        let row = GuardianJournalRowV1 {
            key: self.key,
            expected_generation: write.expected_generation,
            generation: write.next_generation,
            predecessor_head: write.expected_head,
            current_head,
            snapshot_digest: write.snapshot_digest,
            checkpoint_digest: write.checkpoint_digest,
            transaction_digest: write.transaction_digest,
            receipt_digest,
            checkpoint: write.checkpoint.to_vec(),
        };
        let frame = encode_guardian_frame(&row)?;
        let next_journal_bytes = self
            .journal_bytes
            .checked_add(frame.len())
            .ok_or(GuardianProtectedStoreErrorV1::Rejected)?;
        if next_journal_bytes > MAXIMUM_JOURNAL_BYTES
            || self.record_count >= MAXIMUM_JOURNAL_RECORDS
        {
            return Err(GuardianProtectedStoreErrorV1::Rejected);
        }
        if self.file.seek(SeekFrom::End(0)).is_err() {
            return Err(GuardianProtectedStoreErrorV1::Unavailable);
        }
        if self.file.write_all(&frame).is_err() || self.file.sync_data().is_err() {
            self.poisoned = true;
            return Ok(GuardianProtectedWriteOutcomeV1::OutcomeUnknown);
        }
        self.journal_bytes = next_journal_bytes;
        self.record_count = self
            .record_count
            .checked_add(1)
            .ok_or(GuardianProtectedStoreErrorV1::Rejected)?;
        self.current = Some(row.clone());
        Ok(GuardianProtectedWriteOutcomeV1::Committed(
            guardian_receipt(&row),
        ))
    }

    fn read_current(
        &mut self,
        key: ObjectDigest,
    ) -> Result<GuardianProtectedReadbackV1, GuardianProtectedStoreErrorV1> {
        if key != self.key {
            return Err(GuardianProtectedStoreErrorV1::ReadbackMismatch);
        }
        self.reload()?;
        match &self.current {
            Some(row) => Ok(GuardianProtectedReadbackV1 {
                generation: row.generation,
                predecessor_head: row.predecessor_head,
                current_head: row.current_head,
                transaction_digest: row.transaction_digest,
                receipt_digest: row.receipt_digest,
                checkpoint: row.checkpoint.clone(),
            }),
            None => Ok(GuardianProtectedReadbackV1 {
                generation: self.anchor_generation,
                predecessor_head: self.anchor_head,
                current_head: self.anchor_head,
                transaction_digest: ObjectDigest::from_bytes([0; 32]),
                receipt_digest: ObjectDigest::from_bytes([0; 32]),
                checkpoint: Vec::new(),
            }),
        }
    }
}

struct GuardianJournalReplayV1 {
    anchor_generation: u64,
    anchor_head: ObjectDigest,
    current: Option<GuardianJournalRowV1>,
    record_count: usize,
    journal_bytes: usize,
}

/// Pairs an authenticated cold-recovered reducer with its exclusive journal.
///
/// The private fields prevent another reducer from being substituted for the
/// recovered state before a successor checkpoint is appended.
pub(super) struct RecoveredGuardianProtectedStateV1 {
    journal: GuardianProtectedJournalV1,
    reducer: GuardianAuthorityReducerV1,
    durable_snapshot_digest: ObjectDigest,
}

impl RecoveredGuardianProtectedStateV1 {
    /// Borrows the reducer reconstructed from the journal's exact current row.
    pub(super) fn reducer(&self) -> &GuardianAuthorityReducerV1 {
        &self.reducer
    }

    /// Mutably borrows the journal-owned reducer for a legitimate transition.
    pub(super) fn reducer_mut(&mut self) -> &mut GuardianAuthorityReducerV1 {
        &mut self.reducer
    }

    /// Commits the current owned reducer as the next protected checkpoint.
    pub(super) fn commit_current(
        &mut self,
    ) -> Result<GuardianCheckpointCommitOutcomeV1, GuardianProtectedStoreErrorV1> {
        if self.journal.current.as_ref().map(|row| row.snapshot_digest)
            != Some(self.durable_snapshot_digest)
        {
            return Err(GuardianProtectedStoreErrorV1::ReadbackMismatch);
        }
        let journal = &mut self.journal;
        let reducer = &self.reducer;
        let mut session = journal.session()?;
        let outcome = session.commit_reducer(reducer)?;
        if let GuardianCheckpointCommitOutcomeV1::Committed(committed) = &outcome {
            self.durable_snapshot_digest = committed.snapshot_digest;
        }
        Ok(outcome)
    }

    /// Resolves an ambiguous append against this bundle's exact journal head.
    pub(super) fn resolve_ambiguous(
        &mut self,
        recovery: GuardianCheckpointRecoveryRequiredV1,
    ) -> GuardianCheckpointResolutionV1 {
        let journal = &mut self.journal;
        let mut session = match journal.session() {
            Ok(session) => session,
            Err(reason) => {
                return GuardianCheckpointResolutionV1::RecoveryRequired { recovery, reason };
            }
        };
        let resolution = session.resolve_ambiguous(recovery);
        if let GuardianCheckpointResolutionV1::Committed(committed) = &resolution {
            self.durable_snapshot_digest = committed.snapshot_digest;
        }
        resolution
    }

    fn compact_physical_if_needed(&mut self) -> Result<(), GuardianProtectedStoreErrorV1> {
        if self.journal.record_count < MAXIMUM_JOURNAL_RECORDS / 2
            && self.journal.journal_bytes < MAXIMUM_JOURNAL_BYTES / 2
        {
            return Ok(());
        }
        self.journal.compact_fixed_file()
    }
}

/// Owns the fixed protected Guardian journal and its authenticated reducer.
///
/// The owner accepts no path, file, receipt, head, timer-policy, or reducer
/// scalar. Genesis and cold replay come only from fixed root-owned files.
pub struct DormantGuardianProtectedOwnerV1 {
    recovered: RecoveredGuardianProtectedStateV1,
}

impl DormantGuardianProtectedOwnerV1 {
    /// Opens or initializes the fixed protected Guardian reducer journal.
    ///
    /// Initialization decodes the fixed genesis checkpoint, reconstructs the
    /// complete reducer, validates its installed timer policy and currentness,
    /// commits the initial row, and resolves an ambiguous append by exact
    /// readback before returning.
    ///
    /// # Errors
    ///
    /// Returns [`DormantGuardianProtectedOwnerErrorV1`] for insecure fixed
    /// files, invalid genesis/current state, CAS conflict, or unresolved I/O.
    pub fn open_or_initialize() -> Result<Self, DormantGuardianProtectedOwnerErrorV1> {
        let key = digest(FIXED_KEY_DOMAIN);
        let anchor = digest(FIXED_HEAD_DOMAIN);
        let journal_file = open_fixed_file(FIXED_JOURNAL_PATH, true)?;
        let length = journal_file
            .metadata()
            .map_err(|_| DormantGuardianProtectedOwnerErrorV1::Unavailable)?
            .len();
        let mut journal = if length == 0 {
            GuardianProtectedJournalV1::initialize(journal_file, key, 1, anchor)?
        } else {
            GuardianProtectedJournalV1::reopen(journal_file, key)?
        };
        if journal.current.is_none() {
            let reducer = load_fixed_genesis()?;
            let outcome = journal.checkpoint_initial(&reducer)?;
            match outcome {
                GuardianCheckpointCommitOutcomeV1::Committed(_) => {}
                GuardianCheckpointCommitOutcomeV1::RecoveryRequired(recovery) => {
                    match journal.resolve_initial(recovery) {
                        GuardianCheckpointResolutionV1::Committed(_) => {}
                        GuardianCheckpointResolutionV1::NotCommitted => {
                            return Err(DormantGuardianProtectedOwnerErrorV1::NotCommitted);
                        }
                        GuardianCheckpointResolutionV1::RecoveryRequired { .. } => {
                            return Err(DormantGuardianProtectedOwnerErrorV1::RecoveryRequired);
                        }
                    }
                }
            }
        }
        let mut recovered = journal.into_recovered()?;
        recovered.compact_physical_if_needed()?;
        Ok(Self { recovered })
    }

    /// Replays and commits the exact current reducer as a successor checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`DormantGuardianProtectedOwnerErrorV1`] for stale currentness,
    /// CAS conflict, or ambiguity that exact readback cannot resolve.
    pub fn checkpoint_current(
        &mut self,
    ) -> Result<DormantGuardianProtectedCommitV1, DormantGuardianProtectedOwnerErrorV1> {
        resolve_guardian_commit(&mut self.recovered)
    }

    /// Reduces one complete fixed protected observation chain.
    ///
    /// Separate root-owned canonical carriers provide admission (including
    /// CauseEvidence), the three exact Current observations, and Outcome. The
    /// owner invokes every reducer boundary and durably checkpoints before
    /// crossing to the next boundary. It never imports caller-authored reducer
    /// state or treats a scalar as kernel, clock, or peer evidence.
    ///
    /// # Errors
    ///
    /// Returns [`DormantGuardianProtectedOwnerErrorV1`] when the carrier is
    /// insecure, malformed, stale, identity-substituted, or cannot be durably
    /// committed and resolved by exact readback.
    pub fn apply_fixed_transition(
        &mut self,
    ) -> Result<DormantGuardianProtectedCommitV1, DormantGuardianProtectedOwnerErrorV1> {
        let admission = load_fixed_guardian_admission(FIXED_ADMISSION_PATH)?;
        self.recovered
            .reducer_mut()
            .begin(admission)
            .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)?;
        let _ = resolve_guardian_commit(&mut self.recovered)?;

        let prepare_current = load_fixed_guardian_current(FIXED_PREPARE_CURRENT_PATH)?;
        let effect = self
            .recovered
            .reducer_mut()
            .prepare_effect(prepare_current)
            .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)?;
        let _ = resolve_guardian_commit(&mut self.recovered)?;

        let freeze_current = load_fixed_guardian_current(FIXED_FREEZE_CURRENT_PATH)?;
        let release = self
            .recovered
            .reducer_mut()
            .freeze_release(effect, freeze_current)
            .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)?;
        let _ = resolve_guardian_commit(&mut self.recovered)?;

        let release_current = load_fixed_guardian_current(FIXED_RELEASE_CURRENT_PATH)?;
        let _plan = self
            .recovered
            .reducer_mut()
            .release_effect(release, release_current)
            .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)?;
        let _ = resolve_guardian_commit(&mut self.recovered)?;

        let outcome = load_fixed_guardian_outcome(FIXED_OUTCOME_PATH)?;
        self.recovered
            .reducer_mut()
            .observe(outcome)
            .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)?;
        let observation_commit = resolve_guardian_commit(&mut self.recovered)?;
        match self
            .recovered
            .reducer()
            .recovery_disposition()
            .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)?
        {
            super::GuardianRecoveryDispositionV1::CommitObserved(_) => {}
            super::GuardianRecoveryDispositionV1::RevalidateReissue(_) => {
                return Ok(observation_commit);
            }
            _ => return Err(DormantGuardianProtectedOwnerErrorV1::InvalidState),
        }
        self.recovered
            .reducer_mut()
            .commit_observed()
            .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)?;
        resolve_guardian_commit(&mut self.recovered)
    }

    /// Applies a live pre-exposure timer handoff from fixed protected currentness.
    ///
    /// This path retains the move-only release token in the owner from freeze
    /// through handoff. It cannot reconstruct that token after cold reopen and
    /// therefore cannot misclassify an exposure-ambiguous recovered plan as
    /// safely unexposed. No timer or effect is activated by this method.
    ///
    /// # Errors
    ///
    /// Returns [`DormantGuardianProtectedOwnerErrorV1`] when any typed carrier
    /// is stale, the timer has not crossed, or a protected checkpoint cannot be
    /// committed and resolved exactly.
    pub fn apply_fixed_timer_handoff(
        &mut self,
    ) -> Result<DormantGuardianProtectedCommitV1, DormantGuardianProtectedOwnerErrorV1> {
        let admission = load_fixed_guardian_admission(FIXED_ADMISSION_PATH)?;
        self.recovered
            .reducer_mut()
            .begin(admission)
            .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)?;
        let _ = resolve_guardian_commit(&mut self.recovered)?;

        let prepare_current = load_fixed_guardian_current(FIXED_PREPARE_CURRENT_PATH)?;
        let effect = self
            .recovered
            .reducer_mut()
            .prepare_effect(prepare_current)
            .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)?;
        let _ = resolve_guardian_commit(&mut self.recovered)?;

        let freeze_current = load_fixed_guardian_current(FIXED_FREEZE_CURRENT_PATH)?;
        let release = self
            .recovered
            .reducer_mut()
            .freeze_release(effect, freeze_current)
            .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)?;
        let _ = resolve_guardian_commit(&mut self.recovered)?;

        let timer_current = load_fixed_guardian_current(FIXED_RELEASE_CURRENT_PATH)?;
        self.recovered
            .reducer_mut()
            .handoff_release_timer(release, timer_current)
            .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)?;
        resolve_guardian_commit(&mut self.recovered)
    }

    /// Applies exact protected admitted-worker-death evidence and checkpoints it.
    ///
    /// # Errors
    ///
    /// Returns [`DormantGuardianProtectedOwnerErrorV1`] when the fixed carrier
    /// is insecure or does not exactly supersede the journal-owned attempt.
    pub fn apply_fixed_worker_death(
        &mut self,
    ) -> Result<DormantGuardianProtectedCommitV1, DormantGuardianProtectedOwnerErrorV1> {
        let evidence = load_fixed_guardian_worker_death(FIXED_WORKER_DEATH_PATH)?;
        self.recovered
            .reducer_mut()
            .supersede_worker_death(evidence)
            .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)?;
        resolve_guardian_commit(&mut self.recovered)
    }

    /// Revalidates a cold effect-unknown attempt with fixed protected currentness.
    ///
    /// # Errors
    ///
    /// Returns [`DormantGuardianProtectedOwnerErrorV1`] when the currentness
    /// carrier is insecure, stale, or cannot be checkpointed exactly.
    pub fn revalidate_fixed_unreleased(
        &mut self,
    ) -> Result<DormantGuardianProtectedCommitV1, DormantGuardianProtectedOwnerErrorV1> {
        let current = load_fixed_guardian_current(FIXED_PREPARE_CURRENT_PATH)?;
        self.recovered
            .reducer_mut()
            .revalidate_unreleased(current)
            .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)?;
        resolve_guardian_commit(&mut self.recovered)
    }

    /// Observes and resolves a cold exposure-ambiguous Guardian attempt.
    ///
    /// # Errors
    ///
    /// Returns [`DormantGuardianProtectedOwnerErrorV1`] when the protected
    /// outcome is stale, malformed, or cannot be checkpointed exactly.
    pub fn observe_fixed_recovery(
        &mut self,
    ) -> Result<DormantGuardianProtectedCommitV1, DormantGuardianProtectedOwnerErrorV1> {
        let outcome = load_fixed_guardian_outcome(FIXED_OUTCOME_PATH)?;
        self.recovered
            .reducer_mut()
            .observe(outcome)
            .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)?;
        let observation_commit = resolve_guardian_commit(&mut self.recovered)?;
        if matches!(
            self.recovered
                .reducer()
                .recovery_disposition()
                .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)?,
            super::GuardianRecoveryDispositionV1::RevalidateReissue(_)
        ) {
            return Ok(observation_commit);
        }
        self.recovered
            .reducer_mut()
            .commit_observed()
            .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)?;
        resolve_guardian_commit(&mut self.recovered)
    }

    /// Compacts an exact receipt prefix and durably checkpoints the successor.
    ///
    /// Compaction authority is minted privately from the journal-owned current
    /// snapshot and cannot be constructed from a caller digest.
    ///
    /// # Errors
    ///
    /// Returns [`DormantGuardianProtectedOwnerErrorV1`] for a non-prefix floor,
    /// pending work, stale currentness, or unresolved protected durability.
    pub fn compact_and_checkpoint(
        &mut self,
        through_sequence: u64,
    ) -> Result<DormantGuardianProtectedCommitV1, DormantGuardianProtectedOwnerErrorV1> {
        let authority = self
            .recovered
            .reducer()
            .mint_compaction(through_sequence)
            .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)?;
        self.recovered
            .reducer_mut()
            .compact_receipts(authority)
            .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)?;
        resolve_guardian_commit(&mut self.recovered)
    }
}

/// Reports whether a fixed-owner checkpoint was committed by direct receipt or recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DormantGuardianProtectedCommitV1 {
    /// The append returned and read back its exact receipt.
    Committed,
    /// Exact recovery readback proved the ambiguous append committed.
    Recovered,
}

/// Reports fixed protected Guardian owner failures without exposing raw receipts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DormantGuardianProtectedOwnerErrorV1 {
    /// A fixed protected file was absent, insecure, or unavailable.
    #[error("fixed Guardian protected state is unavailable")]
    Unavailable,
    /// Canonical genesis or recovered reducer state was invalid.
    #[error("fixed Guardian protected state is invalid")]
    InvalidState,
    /// Exact readback proved the attempted transaction did not commit.
    #[error("Guardian protected transaction did not commit")]
    NotCommitted,
    /// Exact readback could not resolve whether the transaction committed.
    #[error("Guardian protected transaction requires cold recovery")]
    RecoveryRequired,
}

impl From<GuardianProtectedStoreErrorV1> for DormantGuardianProtectedOwnerErrorV1 {
    fn from(error: GuardianProtectedStoreErrorV1) -> Self {
        match error {
            GuardianProtectedStoreErrorV1::InvalidCheckpoint
            | GuardianProtectedStoreErrorV1::ReadbackMismatch
            | GuardianProtectedStoreErrorV1::Rejected => Self::InvalidState,
            GuardianProtectedStoreErrorV1::Unavailable => Self::Unavailable,
        }
    }
}

fn resolve_guardian_commit(
    recovered: &mut RecoveredGuardianProtectedStateV1,
) -> Result<DormantGuardianProtectedCommitV1, DormantGuardianProtectedOwnerErrorV1> {
    let resolution = match recovered.commit_current()? {
        GuardianCheckpointCommitOutcomeV1::Committed(_) => {
            Ok(DormantGuardianProtectedCommitV1::Committed)
        }
        GuardianCheckpointCommitOutcomeV1::RecoveryRequired(recovery) => {
            match recovered.resolve_ambiguous(recovery) {
                GuardianCheckpointResolutionV1::Committed(_) => {
                    Ok(DormantGuardianProtectedCommitV1::Recovered)
                }
                GuardianCheckpointResolutionV1::NotCommitted => {
                    Err(DormantGuardianProtectedOwnerErrorV1::NotCommitted)
                }
                GuardianCheckpointResolutionV1::RecoveryRequired { .. } => {
                    Err(DormantGuardianProtectedOwnerErrorV1::RecoveryRequired)
                }
            }
        }
    }?;
    recovered.compact_physical_if_needed()?;
    Ok(resolution)
}

fn load_fixed_genesis() -> Result<GuardianAuthorityReducerV1, DormantGuardianProtectedOwnerErrorV1>
{
    let reducer = load_fixed_reducer(FIXED_GENESIS_PATH)?;
    let installed = super::ProtectedGuardianTimerPolicyV1::installed();
    if !installed.valid() || reducer.timer.policy_digest != installed.digest {
        return Err(DormantGuardianProtectedOwnerErrorV1::InvalidState);
    }
    Ok(reducer)
}

fn load_fixed_reducer(
    path: &str,
) -> Result<GuardianAuthorityReducerV1, DormantGuardianProtectedOwnerErrorV1> {
    let mut file = open_fixed_file(path, false)?;
    let bytes = read_bounded_fixed_file(&mut file, super::MAXIMUM_GUARDIAN_CHECKPOINT_BYTES)?;
    recover_fixed_reducer(bytes)
}

fn read_bounded_fixed_file(
    file: &mut File,
    maximum: usize,
) -> Result<Vec<u8>, DormantGuardianProtectedOwnerErrorV1> {
    let length = usize::try_from(
        file.metadata()
            .map_err(|_| DormantGuardianProtectedOwnerErrorV1::Unavailable)?
            .len(),
    )
    .map_err(|_| DormantGuardianProtectedOwnerErrorV1::Unavailable)?;
    if length == 0 || length > maximum {
        return Err(DormantGuardianProtectedOwnerErrorV1::InvalidState);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| DormantGuardianProtectedOwnerErrorV1::Unavailable)?;
    file.read_to_end(&mut bytes)
        .map_err(|_| DormantGuardianProtectedOwnerErrorV1::Unavailable)?;
    if bytes.len() != length {
        return Err(DormantGuardianProtectedOwnerErrorV1::InvalidState);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| DormantGuardianProtectedOwnerErrorV1::Unavailable)?;
    let mut repeated = Vec::new();
    repeated
        .try_reserve_exact(length)
        .map_err(|_| DormantGuardianProtectedOwnerErrorV1::Unavailable)?;
    file.read_to_end(&mut repeated)
        .map_err(|_| DormantGuardianProtectedOwnerErrorV1::Unavailable)?;
    if repeated != bytes
        || file
            .metadata()
            .map_err(|_| DormantGuardianProtectedOwnerErrorV1::Unavailable)?
            .len()
            != length as u64
    {
        return Err(DormantGuardianProtectedOwnerErrorV1::InvalidState);
    }
    Ok(bytes)
}

fn recover_fixed_reducer(
    bytes: Vec<u8>,
) -> Result<GuardianAuthorityReducerV1, DormantGuardianProtectedOwnerErrorV1> {
    let snapshot = GuardianRecoveryStoreV1::from_checkpoint_bytes(bytes)
        .and_then(GuardianRecoveryStoreV1::recover)
        .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)?;
    let reducer = GuardianAuthorityReducerV1::recover(snapshot)
        .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)?;
    let installed = super::ProtectedGuardianTimerPolicyV1::installed();
    if !installed.valid() || reducer.timer.policy_digest != installed.digest {
        return Err(DormantGuardianProtectedOwnerErrorV1::InvalidState);
    }
    Ok(reducer)
}

fn load_fixed_guardian_admission(
    path: &str,
) -> Result<super::GuardianEffectAdmissionV1, DormantGuardianProtectedOwnerErrorV1> {
    let mut file = open_fixed_file(path, false)?;
    let bytes = read_bounded_fixed_file(&mut file, super::MAXIMUM_GUARDIAN_CHECKPOINT_BYTES)?;
    super::codec::decode_protected_admission(&bytes)
        .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)
}

fn load_fixed_guardian_current(
    path: &str,
) -> Result<super::ProtectedGuardianCurrentV1, DormantGuardianProtectedOwnerErrorV1> {
    let mut file = open_fixed_file(path, false)?;
    let bytes = read_bounded_fixed_file(&mut file, super::MAXIMUM_GUARDIAN_CHECKPOINT_BYTES)?;
    super::codec::decode_protected_current(&bytes)
        .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)
}

fn load_fixed_guardian_outcome(
    path: &str,
) -> Result<super::ProtectedGuardianOutcomeV1, DormantGuardianProtectedOwnerErrorV1> {
    let mut file = open_fixed_file(path, false)?;
    let bytes = read_bounded_fixed_file(&mut file, super::MAXIMUM_GUARDIAN_CHECKPOINT_BYTES)?;
    super::codec::decode_protected_outcome(&bytes)
        .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)
}

fn load_fixed_guardian_worker_death(
    path: &str,
) -> Result<super::ProtectedGuardianWorkerDeathSupersessionV1, DormantGuardianProtectedOwnerErrorV1>
{
    let mut file = open_fixed_file(path, false)?;
    let bytes = read_bounded_fixed_file(&mut file, super::MAXIMUM_GUARDIAN_CHECKPOINT_BYTES)?;
    super::codec::decode_protected_worker_death(&bytes)
        .map_err(|_| DormantGuardianProtectedOwnerErrorV1::InvalidState)
}

fn open_fixed_file(
    path: &str,
    writable: bool,
) -> Result<File, DormantGuardianProtectedOwnerErrorV1> {
    let name = path
        .strip_prefix(FIXED_DIRECTORY_PATH)
        .and_then(|suffix| suffix.strip_prefix('/'))
        .filter(|name| !name.is_empty() && !name.contains('/'))
        .ok_or(DormantGuardianProtectedOwnerErrorV1::Unavailable)?;
    let directory = open(
        FIXED_DIRECTORY_PATH,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| DormantGuardianProtectedOwnerErrorV1::Unavailable)?;
    validate_guardian_fixed_directory(&directory)
        .map_err(DormantGuardianProtectedOwnerErrorV1::from)?;
    let existing_flags = if writable {
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC
    } else {
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC
    };
    let descriptor = match openat(&directory, name, existing_flags, Mode::empty()) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) if writable => {
            let descriptor = openat(
                &directory,
                name,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| DormantGuardianProtectedOwnerErrorV1::Unavailable)?;
            fsync(&directory).map_err(|_| DormantGuardianProtectedOwnerErrorV1::Unavailable)?;
            descriptor
        }
        Err(_) => return Err(DormantGuardianProtectedOwnerErrorV1::Unavailable),
    };
    let metadata =
        fstat(&descriptor).map_err(|_| DormantGuardianProtectedOwnerErrorV1::Unavailable)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != 0
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o777 != 0o600
    {
        return Err(DormantGuardianProtectedOwnerErrorV1::Unavailable);
    }
    Ok(File::from(descriptor))
}

fn validate_guardian_fixed_directory(
    directory: impl std::os::fd::AsFd,
) -> Result<(), GuardianProtectedStoreErrorV1> {
    let metadata = fstat(directory).map_err(|_| GuardianProtectedStoreErrorV1::Unavailable)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != 0
        || metadata.st_mode & 0o022 != 0
    {
        return Err(GuardianProtectedStoreErrorV1::Unavailable);
    }
    Ok(())
}

fn replay_guardian_journal(
    file: &mut File,
    expected_key: ObjectDigest,
) -> Result<GuardianJournalReplayV1, GuardianProtectedStoreErrorV1> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| GuardianProtectedStoreErrorV1::Unavailable)?;
    let length = usize::try_from(
        file.metadata()
            .map_err(|_| GuardianProtectedStoreErrorV1::Unavailable)?
            .len(),
    )
    .map_err(|_| GuardianProtectedStoreErrorV1::Unavailable)?;
    if length > MAXIMUM_JOURNAL_BYTES {
        return Err(GuardianProtectedStoreErrorV1::Rejected);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| GuardianProtectedStoreErrorV1::Unavailable)?;
    file.read_to_end(&mut bytes)
        .map_err(|_| GuardianProtectedStoreErrorV1::Unavailable)?;
    if bytes.len() != length {
        return Err(GuardianProtectedStoreErrorV1::ReadbackMismatch);
    }
    let (key, anchor_generation, anchor_head, mut offset) = decode_guardian_header(&bytes)?;
    if key != expected_key {
        return Err(GuardianProtectedStoreErrorV1::ReadbackMismatch);
    }
    let mut current = None;
    let mut previous_snapshot = None;
    let mut records = 0_usize;
    while offset < bytes.len() {
        if records >= MAXIMUM_JOURNAL_RECORDS {
            return Err(GuardianProtectedStoreErrorV1::ReadbackMismatch);
        }
        if bytes.len() - offset < 12 {
            truncate_incomplete_guardian_tail(file, offset)?;
            break;
        }
        if bytes.get(offset..offset + 8) != Some(FRAME_MAGIC.as_slice()) {
            return Err(GuardianProtectedStoreErrorV1::ReadbackMismatch);
        }
        let body_length = usize::try_from(u32::from_be_bytes(
            bytes[offset + 8..offset + 12]
                .try_into()
                .map_err(|_| GuardianProtectedStoreErrorV1::ReadbackMismatch)?,
        ))
        .map_err(|_| GuardianProtectedStoreErrorV1::ReadbackMismatch)?;
        let end = offset
            .checked_add(12)
            .and_then(|value| value.checked_add(body_length))
            .ok_or(GuardianProtectedStoreErrorV1::ReadbackMismatch)?;
        if end > bytes.len() {
            truncate_incomplete_guardian_tail(file, offset)?;
            break;
        }
        let frame = bytes
            .get(offset..end)
            .ok_or(GuardianProtectedStoreErrorV1::ReadbackMismatch)?;
        let row = decode_guardian_frame(frame, expected_key)?;
        let (expected_generation, expected_head) = current.as_ref().map_or(
            (anchor_generation, anchor_head),
            |prior: &GuardianJournalRowV1| (prior.generation, prior.current_head),
        );
        if expected_generation.checked_add(1) != Some(row.generation)
            || row.predecessor_head != expected_head
        {
            return Err(GuardianProtectedStoreErrorV1::ReadbackMismatch);
        }
        let snapshot = recover_guardian_journal_snapshot(&row.checkpoint)?;
        if snapshot.digest != row.snapshot_digest
            || previous_snapshot.as_ref().is_some_and(|prior| {
                !GuardianAuthorityReducerV1::validates_journal_successor(prior, &snapshot)
            })
        {
            return Err(GuardianProtectedStoreErrorV1::InvalidCheckpoint);
        }
        records = records
            .checked_add(1)
            .ok_or(GuardianProtectedStoreErrorV1::Rejected)?;
        current = Some(row);
        previous_snapshot = Some(snapshot);
        offset = end;
    }
    Ok(GuardianJournalReplayV1 {
        anchor_generation,
        anchor_head,
        current,
        record_count: records,
        journal_bytes: offset,
    })
}

fn recover_guardian_journal_snapshot(
    checkpoint: &[u8],
) -> Result<super::GuardianRecoverySnapshotV1, GuardianProtectedStoreErrorV1> {
    let snapshot = GuardianRecoveryStoreV1::from_checkpoint_bytes(checkpoint.to_vec())
        .and_then(GuardianRecoveryStoreV1::recover)
        .map_err(|_| GuardianProtectedStoreErrorV1::InvalidCheckpoint)?;
    GuardianAuthorityReducerV1::recover(snapshot.clone())
        .map_err(|_| GuardianProtectedStoreErrorV1::InvalidCheckpoint)?;
    Ok(snapshot)
}

fn encode_guardian_header(key: ObjectDigest, generation: u64, head: ObjectDigest) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(112);
    bytes.extend_from_slice(JOURNAL_MAGIC);
    bytes.extend_from_slice(key.as_bytes());
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.extend_from_slice(head.as_bytes());
    bytes.extend_from_slice(digest(&bytes).as_bytes());
    bytes
}

fn decode_guardian_header(
    bytes: &[u8],
) -> Result<(ObjectDigest, u64, ObjectDigest, usize), GuardianProtectedStoreErrorV1> {
    const HEADER: usize = 112;
    if bytes.len() < HEADER
        || bytes.get(..8) != Some(JOURNAL_MAGIC.as_slice())
        || bytes.get(80..112) != Some(digest(&bytes[..80]).as_bytes().as_slice())
    {
        return Err(GuardianProtectedStoreErrorV1::ReadbackMismatch);
    }
    let key = ObjectDigest::from_bytes(
        bytes[8..40]
            .try_into()
            .map_err(|_| GuardianProtectedStoreErrorV1::ReadbackMismatch)?,
    );
    let generation = u64::from_be_bytes(
        bytes[40..48]
            .try_into()
            .map_err(|_| GuardianProtectedStoreErrorV1::ReadbackMismatch)?,
    );
    let head = ObjectDigest::from_bytes(
        bytes[48..80]
            .try_into()
            .map_err(|_| GuardianProtectedStoreErrorV1::ReadbackMismatch)?,
    );
    if key.as_bytes() == &[0; 32] || generation == 0 || head.as_bytes() == &[0; 32] {
        return Err(GuardianProtectedStoreErrorV1::ReadbackMismatch);
    }
    Ok((key, generation, head, HEADER))
}

fn encode_guardian_frame(
    row: &GuardianJournalRowV1,
) -> Result<Vec<u8>, GuardianProtectedStoreErrorV1> {
    let checkpoint_length =
        u32::try_from(row.checkpoint.len()).map_err(|_| GuardianProtectedStoreErrorV1::Rejected)?;
    let body_length = 276_usize
        .checked_add(row.checkpoint.len())
        .ok_or(GuardianProtectedStoreErrorV1::Rejected)?;
    let body_length =
        u32::try_from(body_length).map_err(|_| GuardianProtectedStoreErrorV1::Rejected)?;
    let mut bytes = Vec::with_capacity(12 + body_length as usize);
    bytes.extend_from_slice(FRAME_MAGIC);
    bytes.extend_from_slice(&body_length.to_be_bytes());
    bytes.extend_from_slice(&guardian_row_bytes(
        row,
        row.snapshot_digest,
        row.checkpoint_digest,
    ));
    bytes.extend_from_slice(&checkpoint_length.to_be_bytes());
    bytes.extend_from_slice(&row.checkpoint);
    bytes.extend_from_slice(digest(&bytes).as_bytes());
    Ok(bytes)
}

fn guardian_row_bytes(
    row: &GuardianJournalRowV1,
    snapshot_digest: ObjectDigest,
    checkpoint_digest: ObjectDigest,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(240);
    bytes.extend_from_slice(row.key.as_bytes());
    bytes.extend_from_slice(&row.expected_generation.to_be_bytes());
    bytes.extend_from_slice(row.predecessor_head.as_bytes());
    bytes.extend_from_slice(&row.generation.to_be_bytes());
    bytes.extend_from_slice(snapshot_digest.as_bytes());
    bytes.extend_from_slice(checkpoint_digest.as_bytes());
    bytes.extend_from_slice(row.transaction_digest.as_bytes());
    bytes.extend_from_slice(row.current_head.as_bytes());
    bytes.extend_from_slice(row.receipt_digest.as_bytes());
    bytes
}

fn decode_guardian_frame(
    frame: &[u8],
    expected_key: ObjectDigest,
) -> Result<GuardianJournalRowV1, GuardianProtectedStoreErrorV1> {
    const FRAME_PREFIX: usize = 12;
    const FIXED_BODY_WITH_DIGEST: usize = 276;
    const CHECKPOINT_LENGTH_OFFSET: usize = 252;
    const CHECKPOINT_OFFSET: usize = 256;

    if frame.len() < FRAME_PREFIX + FIXED_BODY_WITH_DIGEST
        || frame.get(..8) != Some(FRAME_MAGIC.as_slice())
    {
        return Err(GuardianProtectedStoreErrorV1::ReadbackMismatch);
    }
    let encoded_body_length = usize::try_from(read_u32(frame, 8)?)
        .map_err(|_| GuardianProtectedStoreErrorV1::ReadbackMismatch)?;
    if encoded_body_length != frame.len() - FRAME_PREFIX {
        return Err(GuardianProtectedStoreErrorV1::ReadbackMismatch);
    }
    let frame_digest_offset = frame
        .len()
        .checked_sub(32)
        .ok_or(GuardianProtectedStoreErrorV1::ReadbackMismatch)?;
    if frame.get(frame_digest_offset..)
        != Some(digest(&frame[..frame_digest_offset]).as_bytes().as_slice())
    {
        return Err(GuardianProtectedStoreErrorV1::ReadbackMismatch);
    }

    let key = read_digest(frame, 12)?;
    let expected_generation = read_u64(frame, 44)?;
    let predecessor_head = read_digest(frame, 52)?;
    let generation = read_u64(frame, 84)?;
    let snapshot_digest = read_digest(frame, 92)?;
    let checkpoint_digest = read_digest(frame, 124)?;
    let stored_transaction_digest = read_digest(frame, 156)?;
    let current_head = read_digest(frame, 188)?;
    let receipt_digest = read_digest(frame, 220)?;
    let checkpoint_length = usize::try_from(read_u32(frame, CHECKPOINT_LENGTH_OFFSET)?)
        .map_err(|_| GuardianProtectedStoreErrorV1::ReadbackMismatch)?;
    let checkpoint_end = CHECKPOINT_OFFSET
        .checked_add(checkpoint_length)
        .ok_or(GuardianProtectedStoreErrorV1::ReadbackMismatch)?;
    if checkpoint_end != frame_digest_offset
        || checkpoint_length == 0
        || checkpoint_length > super::MAXIMUM_GUARDIAN_CHECKPOINT_BYTES
    {
        return Err(GuardianProtectedStoreErrorV1::ReadbackMismatch);
    }
    let checkpoint = frame
        .get(CHECKPOINT_OFFSET..checkpoint_end)
        .ok_or(GuardianProtectedStoreErrorV1::ReadbackMismatch)?
        .to_vec();
    let store = GuardianRecoveryStoreV1::from_checkpoint_bytes(checkpoint.clone())
        .map_err(|_| GuardianProtectedStoreErrorV1::InvalidCheckpoint)?;
    let recovered = store
        .recover()
        .map_err(|_| GuardianProtectedStoreErrorV1::InvalidCheckpoint)?;

    let expected_transaction = transaction_digest(
        key,
        expected_generation,
        predecessor_head,
        generation,
        snapshot_digest,
        checkpoint_digest,
    );
    let expected_head = protected_head(predecessor_head, generation, stored_transaction_digest);
    let expected_receipt = guardian_receipt_digest(
        key,
        generation,
        predecessor_head,
        current_head,
        stored_transaction_digest,
        checkpoint_digest,
    );
    if key != expected_key
        || expected_generation.checked_add(1) != Some(generation)
        || digest(&checkpoint) != checkpoint_digest
        || recovered.digest != snapshot_digest
        || stored_transaction_digest != expected_transaction
        || current_head != expected_head
        || receipt_digest != expected_receipt
    {
        return Err(GuardianProtectedStoreErrorV1::ReadbackMismatch);
    }

    Ok(GuardianJournalRowV1 {
        key,
        expected_generation,
        generation,
        predecessor_head,
        current_head,
        snapshot_digest,
        checkpoint_digest,
        transaction_digest: stored_transaction_digest,
        receipt_digest,
        checkpoint,
    })
}

fn truncate_incomplete_guardian_tail(
    file: &mut File,
    complete_length: usize,
) -> Result<(), GuardianProtectedStoreErrorV1> {
    let complete_length =
        u64::try_from(complete_length).map_err(|_| GuardianProtectedStoreErrorV1::Unavailable)?;
    file.set_len(complete_length)
        .and_then(|_| file.sync_data())
        .map_err(|_| GuardianProtectedStoreErrorV1::Unavailable)
}

fn guardian_receipt(row: &GuardianJournalRowV1) -> GuardianProtectedReceiptV1 {
    GuardianProtectedReceiptV1 {
        generation: row.generation,
        predecessor_head: row.predecessor_head,
        current_head: row.current_head,
        transaction_digest: row.transaction_digest,
        receipt_digest: row.receipt_digest,
    }
}

fn guardian_receipt_digest(
    key: ObjectDigest,
    generation: u64,
    predecessor_head: ObjectDigest,
    current_head: ObjectDigest,
    transaction_digest: ObjectDigest,
    checkpoint_digest: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(RECEIPT_DOMAIN);
    digest.update(key.as_bytes());
    digest.update(generation.to_be_bytes());
    digest.update(predecessor_head.as_bytes());
    digest.update(current_head.as_bytes());
    digest.update(transaction_digest.as_bytes());
    digest.update(checkpoint_digest.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, GuardianProtectedStoreErrorV1> {
    let end = offset
        .checked_add(4)
        .ok_or(GuardianProtectedStoreErrorV1::ReadbackMismatch)?;
    let value = bytes
        .get(offset..end)
        .ok_or(GuardianProtectedStoreErrorV1::ReadbackMismatch)?
        .try_into()
        .map_err(|_| GuardianProtectedStoreErrorV1::ReadbackMismatch)?;
    Ok(u32::from_be_bytes(value))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, GuardianProtectedStoreErrorV1> {
    let end = offset
        .checked_add(8)
        .ok_or(GuardianProtectedStoreErrorV1::ReadbackMismatch)?;
    let value = bytes
        .get(offset..end)
        .ok_or(GuardianProtectedStoreErrorV1::ReadbackMismatch)?
        .try_into()
        .map_err(|_| GuardianProtectedStoreErrorV1::ReadbackMismatch)?;
    Ok(u64::from_be_bytes(value))
}

fn read_digest(bytes: &[u8], offset: usize) -> Result<ObjectDigest, GuardianProtectedStoreErrorV1> {
    let end = offset
        .checked_add(32)
        .ok_or(GuardianProtectedStoreErrorV1::ReadbackMismatch)?;
    let value = bytes
        .get(offset..end)
        .ok_or(GuardianProtectedStoreErrorV1::ReadbackMismatch)?
        .try_into()
        .map_err(|_| GuardianProtectedStoreErrorV1::ReadbackMismatch)?;
    Ok(ObjectDigest::from_bytes(value))
}

#[allow(clippy::too_many_arguments)]
fn validate_readback(
    key: ObjectDigest,
    expected_generation: u64,
    expected_head: ObjectDigest,
    next_generation: u64,
    snapshot_digest: ObjectDigest,
    checkpoint_digest: ObjectDigest,
    checkpoint: &[u8],
    receipt: &GuardianProtectedReceiptV1,
    readback: &GuardianProtectedReadbackV1,
) -> Result<(), GuardianProtectedStoreErrorV1> {
    let transaction = transaction_digest(
        key,
        expected_generation,
        expected_head,
        next_generation,
        snapshot_digest,
        checkpoint_digest,
    );
    let head = protected_head(expected_head, next_generation, transaction);
    let expected_receipt = guardian_receipt_digest(
        key,
        next_generation,
        expected_head,
        head,
        transaction,
        checkpoint_digest,
    );
    if receipt.generation != next_generation
        || receipt.predecessor_head != expected_head
        || receipt.current_head != head
        || receipt.transaction_digest != transaction
        || receipt.receipt_digest != expected_receipt
        || readback.generation != receipt.generation
        || readback.predecessor_head != receipt.predecessor_head
        || readback.current_head != receipt.current_head
        || readback.transaction_digest != receipt.transaction_digest
        || readback.receipt_digest != receipt.receipt_digest
        || readback.checkpoint != checkpoint
        || digest(&readback.checkpoint) != checkpoint_digest
    {
        return Err(GuardianProtectedStoreErrorV1::ReadbackMismatch);
    }
    Ok(())
}

fn transaction_digest(
    key: ObjectDigest,
    expected_generation: u64,
    expected_head: ObjectDigest,
    next_generation: u64,
    snapshot_digest: ObjectDigest,
    checkpoint_digest: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(TRANSACTION_DOMAIN);
    digest.update(key.as_bytes());
    digest.update(expected_generation.to_be_bytes());
    digest.update(expected_head.as_bytes());
    digest.update(next_generation.to_be_bytes());
    digest.update(snapshot_digest.as_bytes());
    digest.update(checkpoint_digest.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn protected_head(
    predecessor: ObjectDigest,
    generation: u64,
    transaction: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(HEAD_DOMAIN);
    digest.update(predecessor.as_bytes());
    digest.update(generation.to_be_bytes());
    digest.update(transaction.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn digest(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::digest(bytes).into())
}

impl From<GuardianReducerError> for GuardianProtectedStoreErrorV1 {
    fn from(_: GuardianReducerError) -> Self {
        Self::InvalidCheckpoint
    }
}
