//! Dormant atomic protected-store adapter for Network lifecycle checkpoints.
//!
//! This module makes durable reducer currentness a prerequisite for publication
//! and worker handoff. Its dormant owner performs only fixed protected-file
//! persistence; it activates no kernel effect, socket, route, or service.

use aos_sandbox_core::ObjectDigest;
use rustix::fs::{
    AtFlags, FileType, FlockOperation, Mode, OFlags, flock, fstat, fsync, open, openat, renameat,
    unlinkat,
};
use sha2::{Digest as _, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use super::{
    NetworkLifecycleEffectPlanV1, NetworkLifecycleRecoveryStoreV1, NetworkLifecycleReducerV1,
};

const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.network.lifecycle-store-transaction.v1\0";
const HEAD_DOMAIN: &[u8] = b"aos.sandbox.network.lifecycle-store-head.v1\0";
const RECEIPT_DOMAIN: &[u8] = b"aos.sandbox.network.lifecycle-store-receipt.v1\0";
const JOURNAL_MAGIC: &[u8; 8] = b"AOSNPJ01";
const FRAME_MAGIC: &[u8; 8] = b"AOSNPC01";
const MAXIMUM_JOURNAL_BYTES: usize = 64 * 1024 * 1024;
const MAXIMUM_JOURNAL_RECORDS: usize = 4_096;
const FIXED_DIRECTORY_PATH: &str = "/var/lib/aos/sandbox-network/broker-state";
const FIXED_JOURNAL_NAME: &str = "lifecycle-checkpoints.journal";
const FIXED_COMPACTION_NAME: &str = ".lifecycle-checkpoints.journal.compacting";
const FIXED_JOURNAL_PATH: &str =
    "/var/lib/aos/sandbox-network/broker-state/lifecycle-checkpoints.journal";
const FIXED_GENESIS_PATH: &str =
    "/var/lib/aos/sandbox-network/broker-state/lifecycle-genesis.checkpoint";
const FIXED_INTENT_PATH: &str = "/var/lib/aos/sandbox-network/broker-state/next-intent.observation";
const FIXED_PREPARE_CURRENT_PATH: &str =
    "/var/lib/aos/sandbox-network/broker-state/prepare-current.observation";
const FIXED_FREEZE_CURRENT_PATH: &str =
    "/var/lib/aos/sandbox-network/broker-state/freeze-current.observation";
const FIXED_RELEASE_CURRENT_PATH: &str =
    "/var/lib/aos/sandbox-network/broker-state/release-current.observation";
const FIXED_OBSERVATION_PATH: &str =
    "/var/lib/aos/sandbox-network/broker-state/effect-result.observation";
const FIXED_KEY_DOMAIN: &[u8] = b"aos.sandbox.network.fixed-lifecycle-owner.v1\0";
const FIXED_HEAD_DOMAIN: &[u8] = b"aos.sandbox.network.fixed-lifecycle-anchor.v1\0";

mod sealed {
    pub trait Sealed {}
}

/// Reports a fail-closed protected-store adapter rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(super) enum NetworkLifecycleProtectedStoreErrorV1 {
    /// The protected compare-and-swap transaction was rejected.
    #[error("Network lifecycle protected transaction was rejected")]
    Rejected,
    /// The authenticated receipt or exact readback did not match.
    #[error("Network lifecycle protected readback did not match")]
    ReadbackMismatch,
    /// The reducer snapshot did not form a canonical recovery checkpoint.
    #[error("Network lifecycle checkpoint was not canonical")]
    InvalidCheckpoint,
    /// Protected journal I/O or canonical replay was unavailable.
    #[error("Network lifecycle protected journal is unavailable")]
    Unavailable,
}

/// Describes one atomic compare-and-swap of a canonical lifecycle checkpoint.
pub(super) struct NetworkLifecycleProtectedWriteV1<'a> {
    key: ObjectDigest,
    expected_generation: u64,
    expected_head: ObjectDigest,
    next_generation: u64,
    snapshot_digest: ObjectDigest,
    checkpoint_digest: ObjectDigest,
    transaction_digest: ObjectDigest,
    checkpoint: &'a [u8],
}

/// Carries one singular authenticated protected-store commit receipt.
pub(super) struct NetworkLifecycleProtectedReceiptV1 {
    generation: u64,
    predecessor_head: ObjectDigest,
    current_head: ObjectDigest,
    transaction_digest: ObjectDigest,
    receipt_digest: ObjectDigest,
}

/// Carries the exact current row obtained from authenticated readback.
pub(super) struct NetworkLifecycleProtectedReadbackV1 {
    generation: u64,
    predecessor_head: ObjectDigest,
    current_head: ObjectDigest,
    transaction_digest: ObjectDigest,
    receipt_digest: ObjectDigest,
    checkpoint: Vec<u8>,
}

/// Preserves uncertainty when a commit response is lost.
pub(super) enum NetworkLifecycleProtectedWriteOutcomeV1 {
    /// The backend returned a durable receipt.
    Committed(NetworkLifecycleProtectedReceiptV1),
    /// The transaction may have committed and must be read back.
    OutcomeUnknown,
}

/// Defines the sealed backend contract for the protected-store integration.
pub(super) trait NetworkLifecycleProtectedBackendV1: sealed::Sealed {
    /// Atomically writes one exact canonical checkpoint under its prior head.
    ///
    /// An error certifies that no write took effect. Any result lost after the
    /// commit point must be reported as [`NetworkLifecycleProtectedWriteOutcomeV1::OutcomeUnknown`].
    fn commit_atomically(
        &mut self,
        write: NetworkLifecycleProtectedWriteV1<'_>,
    ) -> Result<NetworkLifecycleProtectedWriteOutcomeV1, NetworkLifecycleProtectedStoreErrorV1>;

    /// Reads the authenticated exact current row for `key`.
    fn read_current(
        &mut self,
        key: ObjectDigest,
    ) -> Result<NetworkLifecycleProtectedReadbackV1, NetworkLifecycleProtectedStoreErrorV1>;
}

/// Owns monotonic access to one exact lifecycle reducer row.
pub(super) struct NetworkLifecycleProtectedStoreSessionV1<'a> {
    backend: &'a mut dyn NetworkLifecycleProtectedBackendV1,
    key: ObjectDigest,
    generation: u64,
    head: ObjectDigest,
}

/// Proves exact checkpoint commit and byte-for-byte readback.
#[must_use]
pub(super) struct CommittedNetworkLifecycleCheckpointV1 {
    store: NetworkLifecycleRecoveryStoreV1,
    snapshot_digest: ObjectDigest,
    generation: u64,
    head: ObjectDigest,
    receipt_digest: ObjectDigest,
}

/// Retains all exact inputs when the protected commit result is ambiguous.
#[must_use]
pub(super) struct NetworkLifecycleCheckpointRecoveryRequiredV1 {
    store: NetworkLifecycleRecoveryStoreV1,
    key: ObjectDigest,
    expected_generation: u64,
    expected_head: ObjectDigest,
    next_generation: u64,
    snapshot_digest: ObjectDigest,
    checkpoint_digest: ObjectDigest,
    transaction_digest: ObjectDigest,
}

/// Returns either exact durability or a still-owned recovery token.
#[must_use]
pub(super) enum NetworkLifecycleCheckpointCommitOutcomeV1 {
    /// Commit and exact readback succeeded.
    Committed(CommittedNetworkLifecycleCheckpointV1),
    /// Authenticated readback must resolve the interrupted commit.
    RecoveryRequired(NetworkLifecycleCheckpointRecoveryRequiredV1),
}

/// Resolves an interrupted commit without dropping its recovery token.
#[must_use]
pub(super) enum NetworkLifecycleCheckpointResolutionV1 {
    /// Exact protected readback proved the transaction committed.
    Committed(CommittedNetworkLifecycleCheckpointV1),
    /// Exact protected readback proved the transaction did not commit.
    NotCommitted,
    /// The commit remains contained and may be resolved again.
    RecoveryRequired {
        recovery: NetworkLifecycleCheckpointRecoveryRequiredV1,
        reason: NetworkLifecycleProtectedStoreErrorV1,
    },
}

/// Authorizes publication of only an exact committed lifecycle head.
#[must_use]
pub(super) struct NetworkLifecycleCheckpointPublicationV1 {
    snapshot_digest: ObjectDigest,
    generation: u64,
    head: ObjectDigest,
    receipt_digest: ObjectDigest,
}

/// Carries a reducer-issued effect only after its recovery checkpoint commits.
#[must_use]
pub(super) struct NetworkLifecycleEffectHandoffV1 {
    plan: NetworkLifecycleEffectPlanV1,
    publication: NetworkLifecycleCheckpointPublicationV1,
}

impl<'a> NetworkLifecycleProtectedStoreSessionV1<'a> {
    /// Constructs a session from an authenticated protected-store head.
    fn from_authenticated_backend(
        backend: &'a mut dyn NetworkLifecycleProtectedBackendV1,
        key: ObjectDigest,
        generation: u64,
        head: ObjectDigest,
    ) -> Result<Self, NetworkLifecycleProtectedStoreErrorV1> {
        if key.as_bytes() == &[0; 32] || generation == 0 || head.as_bytes() == &[0; 32] {
            return Err(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch);
        }
        Ok(Self {
            backend,
            key,
            generation,
            head,
        })
    }

    /// Atomically commits and reads back the complete reducer checkpoint.
    fn commit_reducer(
        &mut self,
        reducer: &NetworkLifecycleReducerV1,
    ) -> Result<NetworkLifecycleCheckpointCommitOutcomeV1, NetworkLifecycleProtectedStoreErrorV1>
    {
        let snapshot_digest = reducer.snapshot_digest();
        let store = NetworkLifecycleRecoveryStoreV1::checkpoint(reducer.snapshot())
            .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::InvalidCheckpoint)?;
        let checkpoint_digest = digest(store.checkpoint_bytes());
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(NetworkLifecycleProtectedStoreErrorV1::Rejected)?;
        let transaction_digest = transaction_digest(
            self.key,
            self.generation,
            self.head,
            next_generation,
            snapshot_digest,
            checkpoint_digest,
        );
        let write = NetworkLifecycleProtectedWriteV1 {
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
            NetworkLifecycleProtectedWriteOutcomeV1::Committed(receipt) => {
                let recovery = NetworkLifecycleCheckpointRecoveryRequiredV1 {
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
                    Ok(committed) => Ok(NetworkLifecycleCheckpointCommitOutcomeV1::Committed(
                        committed,
                    )),
                    Err(_) => Ok(NetworkLifecycleCheckpointCommitOutcomeV1::RecoveryRequired(
                        recovery,
                    )),
                }
            }
            NetworkLifecycleProtectedWriteOutcomeV1::OutcomeUnknown => {
                Ok(NetworkLifecycleCheckpointCommitOutcomeV1::RecoveryRequired(
                    NetworkLifecycleCheckpointRecoveryRequiredV1 {
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
        store: NetworkLifecycleRecoveryStoreV1,
        snapshot_digest: ObjectDigest,
        checkpoint_digest: ObjectDigest,
        receipt: NetworkLifecycleProtectedReceiptV1,
    ) -> Result<CommittedNetworkLifecycleCheckpointV1, NetworkLifecycleProtectedStoreErrorV1> {
        let readback = self.backend.read_current(self.key)?;
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(NetworkLifecycleProtectedStoreErrorV1::Rejected)?;
        validate_readback(
            self.key,
            self.generation,
            self.head,
            next_generation,
            snapshot_digest,
            checkpoint_digest,
            store.checkpoint_bytes(),
            &receipt,
            &readback,
        )?;
        let recovered = NetworkLifecycleRecoveryStoreV1::from_checkpoint_bytes(readback.checkpoint)
            .and_then(NetworkLifecycleRecoveryStoreV1::recover)
            .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::InvalidCheckpoint)?;
        if recovered.digest != snapshot_digest {
            return Err(NetworkLifecycleProtectedStoreErrorV1::InvalidCheckpoint);
        }

        self.generation = next_generation;
        self.head = receipt.current_head;
        Ok(CommittedNetworkLifecycleCheckpointV1 {
            store,
            snapshot_digest,
            generation: receipt.generation,
            head: receipt.current_head,
            receipt_digest: receipt.receipt_digest,
        })
    }

    /// Resolves outcome-unknown state solely through exact current readback.
    fn resolve_ambiguous(
        &mut self,
        recovery: NetworkLifecycleCheckpointRecoveryRequiredV1,
    ) -> NetworkLifecycleCheckpointResolutionV1 {
        match self.try_resolve_ambiguous(&recovery) {
            Ok(committed) => NetworkLifecycleCheckpointResolutionV1::Committed(committed),
            Err(NetworkLifecycleProtectedStoreErrorV1::Rejected) => {
                NetworkLifecycleCheckpointResolutionV1::NotCommitted
            }
            Err(reason) => {
                NetworkLifecycleCheckpointResolutionV1::RecoveryRequired { recovery, reason }
            }
        }
    }

    fn try_resolve_ambiguous(
        &mut self,
        recovery: &NetworkLifecycleCheckpointRecoveryRequiredV1,
    ) -> Result<CommittedNetworkLifecycleCheckpointV1, NetworkLifecycleProtectedStoreErrorV1> {
        if recovery.key != self.key
            || recovery.expected_generation != self.generation
            || recovery.expected_head != self.head
        {
            return Err(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch);
        }
        let readback = self.backend.read_current(self.key)?;
        if readback.generation == recovery.expected_generation
            && readback.current_head == recovery.expected_head
        {
            return Err(NetworkLifecycleProtectedStoreErrorV1::Rejected);
        }
        let receipt = NetworkLifecycleProtectedReceiptV1 {
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
            return Err(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch);
        }
        let recovered =
            NetworkLifecycleRecoveryStoreV1::from_checkpoint_bytes(readback.checkpoint.clone())
                .and_then(NetworkLifecycleRecoveryStoreV1::recover)
                .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::InvalidCheckpoint)?;
        if recovered.digest != recovery.snapshot_digest {
            return Err(NetworkLifecycleProtectedStoreErrorV1::InvalidCheckpoint);
        }

        self.generation = recovery.next_generation;
        self.head = readback.current_head;
        Ok(CommittedNetworkLifecycleCheckpointV1 {
            store: recovery.store.clone(),
            snapshot_digest: recovery.snapshot_digest,
            generation: readback.generation,
            head: readback.current_head,
            receipt_digest: readback.receipt_digest,
        })
    }
}

impl CommittedNetworkLifecycleCheckpointV1 {
    /// Consumes durable state to authorize publication of its exact head.
    pub(super) fn into_publication(self) -> NetworkLifecycleCheckpointPublicationV1 {
        NetworkLifecycleCheckpointPublicationV1 {
            snapshot_digest: self.snapshot_digest,
            generation: self.generation,
            head: self.head,
            receipt_digest: self.receipt_digest,
        }
    }

    /// Borrows the canonical checkpoint retained after readback.
    pub(super) fn checkpoint_bytes(&self) -> &[u8] {
        self.store.checkpoint_bytes()
    }
}

impl NetworkLifecycleCheckpointPublicationV1 {
    /// Binds a reducer-issued effect to its exact durable ambiguity boundary.
    pub(super) fn into_effect_handoff(
        self,
        plan: NetworkLifecycleEffectPlanV1,
    ) -> Result<NetworkLifecycleEffectHandoffV1, NetworkLifecycleProtectedStoreErrorV1> {
        if plan.recovery_digest() != self.snapshot_digest {
            return Err(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch);
        }
        Ok(NetworkLifecycleEffectHandoffV1 {
            plan,
            publication: self,
        })
    }
}

impl NetworkLifecycleEffectHandoffV1 {
    /// Returns the exact reducer-issued effect plan.
    pub(super) fn plan(&self) -> &NetworkLifecycleEffectPlanV1 {
        &self.plan
    }

    /// Returns the durable protected head preceding worker handoff.
    pub(super) fn protected_head(&self) -> ObjectDigest {
        self.publication.head
    }
}

/// Owns one authenticated append-only Network lifecycle checkpoint journal.
///
/// The journal retains an exclusive advisory lock for its lifetime. Its sealed
/// implementation is the only code that can mint protected receipts.
pub(super) struct NetworkLifecycleProtectedJournalV1 {
    file: File,
    key: ObjectDigest,
    anchor_generation: u64,
    anchor_head: ObjectDigest,
    current: Option<NetworkLifecycleJournalRowV1>,
    record_count: usize,
    journal_bytes: usize,
    poisoned: bool,
    fatal_swap_failure: bool,
}

#[derive(Clone)]
struct NetworkLifecycleJournalRowV1 {
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

/// Pairs an authenticated cold-recovered reducer with its exclusive journal.
///
/// Private fields prevent substitution of an unrelated reducer before the
/// next protected append.
pub(super) struct RecoveredNetworkLifecycleProtectedStateV1 {
    journal: NetworkLifecycleProtectedJournalV1,
    reducer: NetworkLifecycleReducerV1,
    durable_snapshot_digest: ObjectDigest,
}

impl RecoveredNetworkLifecycleProtectedStateV1 {
    /// Borrows the reducer reconstructed from the journal's current row.
    pub(super) fn reducer(&self) -> &NetworkLifecycleReducerV1 {
        &self.reducer
    }

    /// Mutably borrows the journal-owned reducer for a legitimate transition.
    pub(super) fn reducer_mut(&mut self) -> &mut NetworkLifecycleReducerV1 {
        &mut self.reducer
    }

    /// Commits the current owned reducer as the next protected checkpoint.
    pub(super) fn commit_current(
        &mut self,
    ) -> Result<NetworkLifecycleCheckpointCommitOutcomeV1, NetworkLifecycleProtectedStoreErrorV1>
    {
        if self.journal.current.as_ref().map(|row| row.snapshot_digest)
            != Some(self.durable_snapshot_digest)
        {
            return Err(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch);
        }
        let journal = &mut self.journal;
        let reducer = &self.reducer;
        let mut session = journal.session()?;
        let outcome = session.commit_reducer(reducer)?;
        if let NetworkLifecycleCheckpointCommitOutcomeV1::Committed(committed) = &outcome {
            self.durable_snapshot_digest = committed.snapshot_digest;
        }
        Ok(outcome)
    }

    /// Resolves an ambiguous append against this bundle's exact journal head.
    pub(super) fn resolve_ambiguous(
        &mut self,
        recovery: NetworkLifecycleCheckpointRecoveryRequiredV1,
    ) -> NetworkLifecycleCheckpointResolutionV1 {
        let journal = &mut self.journal;
        let mut session = match journal.session() {
            Ok(session) => session,
            Err(reason) => {
                return NetworkLifecycleCheckpointResolutionV1::RecoveryRequired {
                    recovery,
                    reason,
                };
            }
        };
        let resolution = session.resolve_ambiguous(recovery);
        if let NetworkLifecycleCheckpointResolutionV1::Committed(committed) = &resolution {
            self.durable_snapshot_digest = committed.snapshot_digest;
        }
        resolution
    }

    fn compact_physical_if_needed(&mut self) -> Result<(), NetworkLifecycleProtectedStoreErrorV1> {
        if self.journal.record_count < MAXIMUM_JOURNAL_RECORDS / 2
            && self.journal.journal_bytes < MAXIMUM_JOURNAL_BYTES / 2
        {
            return Ok(());
        }
        self.journal.compact_fixed_file()
    }
}

/// Owns the fixed protected Network lifecycle journal and recovered reducer.
pub struct DormantNetworkLifecycleProtectedOwnerV1 {
    recovered: RecoveredNetworkLifecycleProtectedStateV1,
}

impl DormantNetworkLifecycleProtectedOwnerV1 {
    /// Opens or initializes the fixed root-owned lifecycle checkpoint journal.
    ///
    /// The initial reducer comes only from the fixed canonical genesis file;
    /// no caller path, file, journal coordinate, receipt, or reducer scalar is
    /// accepted. Ambiguous initial durability is resolved by exact readback.
    ///
    /// # Errors
    ///
    /// Returns [`DormantNetworkLifecycleOwnerErrorV1`] for insecure files,
    /// invalid replay/genesis state, conflict, or unresolved durability.
    pub fn open_or_initialize() -> Result<Self, DormantNetworkLifecycleOwnerErrorV1> {
        let key = digest(FIXED_KEY_DOMAIN);
        let anchor = digest(FIXED_HEAD_DOMAIN);
        let journal_file = open_fixed_file(FIXED_JOURNAL_PATH, true)?;
        let length = journal_file
            .metadata()
            .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::Unavailable)?
            .len();
        let mut journal = if length == 0 {
            NetworkLifecycleProtectedJournalV1::initialize(journal_file, key, 1, anchor)?
        } else {
            NetworkLifecycleProtectedJournalV1::reopen(journal_file, key)?
        };
        if journal.current.is_none() {
            let reducer = load_fixed_genesis()?;
            match journal.checkpoint_initial(&reducer)? {
                NetworkLifecycleCheckpointCommitOutcomeV1::Committed(_) => {}
                NetworkLifecycleCheckpointCommitOutcomeV1::RecoveryRequired(recovery) => {
                    match journal.resolve_initial(recovery) {
                        NetworkLifecycleCheckpointResolutionV1::Committed(_) => {}
                        NetworkLifecycleCheckpointResolutionV1::NotCommitted => {
                            return Err(DormantNetworkLifecycleOwnerErrorV1::NotCommitted);
                        }
                        NetworkLifecycleCheckpointResolutionV1::RecoveryRequired { .. } => {
                            return Err(DormantNetworkLifecycleOwnerErrorV1::RecoveryRequired);
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
    /// Returns [`DormantNetworkLifecycleOwnerErrorV1`] for stale currentness,
    /// CAS conflict, or ambiguity that exact readback cannot resolve.
    pub fn checkpoint_current(
        &mut self,
    ) -> Result<DormantNetworkLifecycleProtectedCommitV1, DormantNetworkLifecycleOwnerErrorV1> {
        resolve_network_commit(&mut self.recovered)
    }

    /// Reduces one complete fixed protected lifecycle observation chain.
    ///
    /// Root-owned typed carriers provide the Intent, three exact Current and
    /// Residual observations, and the terminal ProtectedObservation (including
    /// CleanupObservation when destroying). The owner invokes every reducer
    /// boundary and durably checkpoints before crossing to the next boundary.
    ///
    /// # Errors
    ///
    /// Returns [`DormantNetworkLifecycleOwnerErrorV1`] when the carrier is
    /// insecure, malformed, stale, identity-substituted, or cannot be durably
    /// committed and resolved by exact readback.
    pub fn apply_fixed_transition(
        &mut self,
    ) -> Result<DormantNetworkLifecycleProtectedCommitV1, DormantNetworkLifecycleOwnerErrorV1> {
        let intent = load_fixed_network_intent(FIXED_INTENT_PATH)?;
        self.recovered
            .reducer_mut()
            .begin(intent)
            .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::InvalidState)?;
        let _ = resolve_network_commit(&mut self.recovered)?;

        let prepare_current = load_fixed_network_current(FIXED_PREPARE_CURRENT_PATH)?;
        let effect = self
            .recovered
            .reducer_mut()
            .prepare_effect(prepare_current)
            .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::InvalidState)?;
        let _ = resolve_network_commit(&mut self.recovered)?;

        let freeze_current = load_fixed_network_current(FIXED_FREEZE_CURRENT_PATH)?;
        let release = self
            .recovered
            .reducer_mut()
            .freeze_release(effect, freeze_current)
            .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::InvalidState)?;
        let _ = resolve_network_commit(&mut self.recovered)?;

        let release_current = load_fixed_network_current(FIXED_RELEASE_CURRENT_PATH)?;
        let _plan = self
            .recovered
            .reducer()
            .release_effect(release, release_current)
            .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::InvalidState)?;
        let _ = resolve_network_commit(&mut self.recovered)?;

        let observation = load_fixed_network_observation(FIXED_OBSERVATION_PATH)?;
        let observed = self
            .recovered
            .reducer_mut()
            .observe(observation)
            .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::InvalidState)?;
        let observation_commit = resolve_network_commit(&mut self.recovered)?;
        if matches!(
            observed,
            super::NetworkLifecycleObserveOutcomeV1::Continue(_)
        ) {
            return Ok(observation_commit);
        }
        self.recovered
            .reducer_mut()
            .commit_observed()
            .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::InvalidState)?;
        resolve_network_commit(&mut self.recovered)
    }

    /// Revalidates a cold effect-unknown attempt with protected currentness.
    ///
    /// # Errors
    ///
    /// Returns [`DormantNetworkLifecycleOwnerErrorV1`] when the fixed carrier
    /// is insecure, stale, or cannot be checkpointed exactly.
    pub fn revalidate_fixed_unreleased(
        &mut self,
    ) -> Result<DormantNetworkLifecycleProtectedCommitV1, DormantNetworkLifecycleOwnerErrorV1> {
        let current = load_fixed_network_current(FIXED_PREPARE_CURRENT_PATH)?;
        self.recovered
            .reducer_mut()
            .revalidate_unreleased(current)
            .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::InvalidState)?;
        resolve_network_commit(&mut self.recovered)
    }

    /// Observes and resolves a cold exposure-ambiguous lifecycle attempt.
    ///
    /// # Errors
    ///
    /// Returns [`DormantNetworkLifecycleOwnerErrorV1`] when the protected
    /// observation is stale, malformed, or cannot be checkpointed exactly.
    pub fn observe_fixed_recovery(
        &mut self,
    ) -> Result<DormantNetworkLifecycleProtectedCommitV1, DormantNetworkLifecycleOwnerErrorV1> {
        let observation = load_fixed_network_observation(FIXED_OBSERVATION_PATH)?;
        let observed = self
            .recovered
            .reducer_mut()
            .observe(observation)
            .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::InvalidState)?;
        let observation_commit = resolve_network_commit(&mut self.recovered)?;
        if matches!(
            observed,
            super::NetworkLifecycleObserveOutcomeV1::Continue(_)
        ) {
            return Ok(observation_commit);
        }
        self.recovered
            .reducer_mut()
            .commit_observed()
            .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::InvalidState)?;
        resolve_network_commit(&mut self.recovered)
    }

    /// Compacts one exact receipt prefix and checkpoints the successor.
    ///
    /// The compaction capability is privately derived from the journal-owned
    /// reducer snapshot, selected floor, anchor, and complete replay index.
    ///
    /// # Errors
    ///
    /// Returns [`DormantNetworkLifecycleOwnerErrorV1`] for a non-prefix floor,
    /// pending work, stale currentness, or unresolved durability.
    pub fn compact_and_checkpoint(
        &mut self,
        through_sequence: u64,
    ) -> Result<DormantNetworkLifecycleProtectedCommitV1, DormantNetworkLifecycleOwnerErrorV1> {
        let authority = self
            .recovered
            .reducer()
            .mint_compaction(through_sequence)
            .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::InvalidState)?;
        self.recovered
            .reducer_mut()
            .compact_receipts(authority)
            .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::InvalidState)?;
        resolve_network_commit(&mut self.recovered)
    }
}

/// Reports whether a Network checkpoint committed directly or through recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DormantNetworkLifecycleProtectedCommitV1 {
    /// The append returned and read back its exact receipt.
    Committed,
    /// Exact recovery readback proved the ambiguous append committed.
    Recovered,
}

/// Reports fixed protected Network owner failures without exposing receipts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DormantNetworkLifecycleOwnerErrorV1 {
    /// A fixed protected file was absent, insecure, or unavailable.
    #[error("fixed Network lifecycle protected state is unavailable")]
    Unavailable,
    /// Canonical genesis or recovered reducer state was invalid.
    #[error("fixed Network lifecycle protected state is invalid")]
    InvalidState,
    /// Exact readback proved the attempted transaction did not commit.
    #[error("Network lifecycle protected transaction did not commit")]
    NotCommitted,
    /// Exact readback could not resolve whether the transaction committed.
    #[error("Network lifecycle protected transaction requires cold recovery")]
    RecoveryRequired,
}

impl From<NetworkLifecycleProtectedStoreErrorV1> for DormantNetworkLifecycleOwnerErrorV1 {
    fn from(error: NetworkLifecycleProtectedStoreErrorV1) -> Self {
        match error {
            NetworkLifecycleProtectedStoreErrorV1::InvalidCheckpoint
            | NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch
            | NetworkLifecycleProtectedStoreErrorV1::Rejected => Self::InvalidState,
            NetworkLifecycleProtectedStoreErrorV1::Unavailable => Self::Unavailable,
        }
    }
}

fn resolve_network_commit(
    recovered: &mut RecoveredNetworkLifecycleProtectedStateV1,
) -> Result<DormantNetworkLifecycleProtectedCommitV1, DormantNetworkLifecycleOwnerErrorV1> {
    let resolution = match recovered.commit_current()? {
        NetworkLifecycleCheckpointCommitOutcomeV1::Committed(_) => {
            Ok(DormantNetworkLifecycleProtectedCommitV1::Committed)
        }
        NetworkLifecycleCheckpointCommitOutcomeV1::RecoveryRequired(recovery) => {
            match recovered.resolve_ambiguous(recovery) {
                NetworkLifecycleCheckpointResolutionV1::Committed(_) => {
                    Ok(DormantNetworkLifecycleProtectedCommitV1::Recovered)
                }
                NetworkLifecycleCheckpointResolutionV1::NotCommitted => {
                    Err(DormantNetworkLifecycleOwnerErrorV1::NotCommitted)
                }
                NetworkLifecycleCheckpointResolutionV1::RecoveryRequired { .. } => {
                    Err(DormantNetworkLifecycleOwnerErrorV1::RecoveryRequired)
                }
            }
        }
    }?;
    recovered.compact_physical_if_needed()?;
    Ok(resolution)
}

fn load_fixed_genesis() -> Result<NetworkLifecycleReducerV1, DormantNetworkLifecycleOwnerErrorV1> {
    load_fixed_reducer(FIXED_GENESIS_PATH)
}

fn load_fixed_reducer(
    path: &str,
) -> Result<NetworkLifecycleReducerV1, DormantNetworkLifecycleOwnerErrorV1> {
    let mut file = open_fixed_file(path, false)?;
    let bytes = read_bounded_fixed_file(&mut file, super::MAXIMUM_RECOVERY_CHECKPOINT_BYTES)?;
    recover_fixed_reducer(bytes)
}

fn read_bounded_fixed_file(
    file: &mut File,
    maximum: usize,
) -> Result<Vec<u8>, DormantNetworkLifecycleOwnerErrorV1> {
    let length = usize::try_from(
        file.metadata()
            .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::Unavailable)?
            .len(),
    )
    .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::Unavailable)?;
    if length == 0 || length > maximum {
        return Err(DormantNetworkLifecycleOwnerErrorV1::InvalidState);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::Unavailable)?;
    file.read_to_end(&mut bytes)
        .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::Unavailable)?;
    if bytes.len() != length {
        return Err(DormantNetworkLifecycleOwnerErrorV1::InvalidState);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::Unavailable)?;
    let mut repeated = Vec::new();
    repeated
        .try_reserve_exact(length)
        .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::Unavailable)?;
    file.read_to_end(&mut repeated)
        .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::Unavailable)?;
    if repeated != bytes
        || file
            .metadata()
            .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::Unavailable)?
            .len()
            != length as u64
    {
        return Err(DormantNetworkLifecycleOwnerErrorV1::InvalidState);
    }
    Ok(bytes)
}

fn recover_fixed_reducer(
    bytes: Vec<u8>,
) -> Result<NetworkLifecycleReducerV1, DormantNetworkLifecycleOwnerErrorV1> {
    let snapshot = NetworkLifecycleRecoveryStoreV1::from_checkpoint_bytes(bytes)
        .and_then(NetworkLifecycleRecoveryStoreV1::recover)
        .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::InvalidState)?;
    NetworkLifecycleReducerV1::recover(snapshot)
        .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::InvalidState)
}

fn load_fixed_network_intent(
    path: &str,
) -> Result<super::NetworkLifecycleIntentV1, DormantNetworkLifecycleOwnerErrorV1> {
    let mut file = open_fixed_file(path, false)?;
    let bytes = read_bounded_fixed_file(&mut file, super::MAXIMUM_RECOVERY_CHECKPOINT_BYTES)?;
    super::codec::decode_protected_intent(&bytes)
        .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::InvalidState)
}

fn load_fixed_network_current(
    path: &str,
) -> Result<super::ProtectedNetworkLifecycleCurrentV1, DormantNetworkLifecycleOwnerErrorV1> {
    let mut file = open_fixed_file(path, false)?;
    let bytes = read_bounded_fixed_file(&mut file, super::MAXIMUM_RECOVERY_CHECKPOINT_BYTES)?;
    super::codec::decode_protected_current(&bytes)
        .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::InvalidState)
}

fn load_fixed_network_observation(
    path: &str,
) -> Result<super::ProtectedNetworkLifecycleObservationV1, DormantNetworkLifecycleOwnerErrorV1> {
    let mut file = open_fixed_file(path, false)?;
    let bytes = read_bounded_fixed_file(&mut file, super::MAXIMUM_RECOVERY_CHECKPOINT_BYTES)?;
    super::codec::decode_protected_observation(&bytes)
        .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::InvalidState)
}

fn open_fixed_file(
    path: &str,
    writable: bool,
) -> Result<File, DormantNetworkLifecycleOwnerErrorV1> {
    let name = path
        .strip_prefix(FIXED_DIRECTORY_PATH)
        .and_then(|suffix| suffix.strip_prefix('/'))
        .filter(|name| !name.is_empty() && !name.contains('/'))
        .ok_or(DormantNetworkLifecycleOwnerErrorV1::Unavailable)?;
    let directory = open(
        FIXED_DIRECTORY_PATH,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::Unavailable)?;
    validate_network_fixed_directory(&directory)
        .map_err(DormantNetworkLifecycleOwnerErrorV1::from)?;
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
            .map_err(|_| DormantNetworkLifecycleOwnerErrorV1::Unavailable)?;
            fsync(&directory).map_err(|_| DormantNetworkLifecycleOwnerErrorV1::Unavailable)?;
            descriptor
        }
        Err(_) => return Err(DormantNetworkLifecycleOwnerErrorV1::Unavailable),
    };
    let metadata =
        fstat(&descriptor).map_err(|_| DormantNetworkLifecycleOwnerErrorV1::Unavailable)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != 0
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o777 != 0o600
    {
        return Err(DormantNetworkLifecycleOwnerErrorV1::Unavailable);
    }
    Ok(File::from(descriptor))
}

fn validate_network_fixed_directory(
    directory: impl std::os::fd::AsFd,
) -> Result<(), NetworkLifecycleProtectedStoreErrorV1> {
    let metadata =
        fstat(directory).map_err(|_| NetworkLifecycleProtectedStoreErrorV1::Unavailable)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != 0
        || metadata.st_mode & 0o022 != 0
    {
        return Err(NetworkLifecycleProtectedStoreErrorV1::Unavailable);
    }
    Ok(())
}

impl NetworkLifecycleProtectedJournalV1 {
    /// Initializes an empty journal under one exact protected anchor.
    pub(super) fn initialize(
        mut file: File,
        key: ObjectDigest,
        generation: u64,
        head: ObjectDigest,
    ) -> Result<Self, NetworkLifecycleProtectedStoreErrorV1> {
        if key.as_bytes() == &[0; 32]
            || generation == 0
            || head.as_bytes() == &[0; 32]
            || file
                .metadata()
                .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::Unavailable)?
                .len()
                != 0
        {
            return Err(NetworkLifecycleProtectedStoreErrorV1::Rejected);
        }
        flock(&file, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::Unavailable)?;
        let header = encode_network_lifecycle_header(key, generation, head);
        file.seek(SeekFrom::Start(0))
            .and_then(|_| file.write_all(&header))
            .and_then(|_| file.sync_data())
            .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::Unavailable)?;
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

    fn reopen(
        mut file: File,
        expected_key: ObjectDigest,
    ) -> Result<Self, NetworkLifecycleProtectedStoreErrorV1> {
        flock(&file, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::Unavailable)?;
        let replay = replay_network_lifecycle_journal(&mut file, expected_key)?;
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
    ) -> Result<RecoveredNetworkLifecycleProtectedStateV1, NetworkLifecycleProtectedStoreErrorV1>
    {
        Self::reopen(file, expected_key)?.into_recovered()
    }

    /// Commits the first reducer checkpoint above a newly provisioned anchor.
    pub(super) fn checkpoint_initial(
        &mut self,
        reducer: &NetworkLifecycleReducerV1,
    ) -> Result<NetworkLifecycleCheckpointCommitOutcomeV1, NetworkLifecycleProtectedStoreErrorV1>
    {
        if self.current.is_some() {
            return Err(NetworkLifecycleProtectedStoreErrorV1::Rejected);
        }
        self.session()?.commit_reducer(reducer)
    }

    /// Resolves an ambiguous initial checkpoint without permitting a successor.
    pub(super) fn resolve_initial(
        &mut self,
        recovery: NetworkLifecycleCheckpointRecoveryRequiredV1,
    ) -> NetworkLifecycleCheckpointResolutionV1 {
        let mut session = match self.session() {
            Ok(session) => session,
            Err(reason) => {
                return NetworkLifecycleCheckpointResolutionV1::RecoveryRequired {
                    recovery,
                    reason,
                };
            }
        };
        session.resolve_ambiguous(recovery)
    }

    /// Consumes a journal whose current row authenticates a recoverable reducer.
    pub(super) fn into_recovered(
        self,
    ) -> Result<RecoveredNetworkLifecycleProtectedStateV1, NetworkLifecycleProtectedStoreErrorV1>
    {
        let row = self
            .current
            .as_ref()
            .ok_or(NetworkLifecycleProtectedStoreErrorV1::InvalidCheckpoint)?;
        let store = NetworkLifecycleRecoveryStoreV1::from_checkpoint_bytes(row.checkpoint.clone())
            .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::InvalidCheckpoint)?;
        let snapshot = store
            .recover()
            .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::InvalidCheckpoint)?;
        if snapshot.digest != row.snapshot_digest {
            return Err(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch);
        }
        let durable_snapshot_digest = row.snapshot_digest;
        let reducer = NetworkLifecycleReducerV1::recover(snapshot)
            .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::InvalidCheckpoint)?;

        Ok(RecoveredNetworkLifecycleProtectedStateV1 {
            journal: self,
            reducer,
            durable_snapshot_digest,
        })
    }

    fn session(
        &mut self,
    ) -> Result<NetworkLifecycleProtectedStoreSessionV1<'_>, NetworkLifecycleProtectedStoreErrorV1>
    {
        let key = self.key;
        let (generation, head) = self.coordinates();
        NetworkLifecycleProtectedStoreSessionV1::from_authenticated_backend(
            self, key, generation, head,
        )
    }

    fn coordinates(&self) -> (u64, ObjectDigest) {
        self.current
            .as_ref()
            .map_or((self.anchor_generation, self.anchor_head), |row| {
                (row.generation, row.current_head)
            })
    }

    fn compact_fixed_file(&mut self) -> Result<(), NetworkLifecycleProtectedStoreErrorV1> {
        if self.fatal_swap_failure {
            return Err(NetworkLifecycleProtectedStoreErrorV1::Unavailable);
        }
        self.reload()?;
        let row = self
            .current
            .clone()
            .ok_or(NetworkLifecycleProtectedStoreErrorV1::InvalidCheckpoint)?;
        let directory = open(
            FIXED_DIRECTORY_PATH,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::Unavailable)?;
        validate_network_fixed_directory(&directory)?;
        match unlinkat(&directory, FIXED_COMPACTION_NAME, AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(_) => return Err(NetworkLifecycleProtectedStoreErrorV1::Unavailable),
        }
        let descriptor = openat(
            &directory,
            FIXED_COMPACTION_NAME,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::Unavailable)?;
        let mut replacement = File::from(descriptor);
        let header = encode_network_lifecycle_header(
            self.key,
            row.expected_generation,
            row.predecessor_head,
        );
        let frame = encode_network_lifecycle_frame(&row)?;
        if replacement
            .write_all(&header)
            .and_then(|_| replacement.write_all(&frame))
            .and_then(|_| replacement.sync_all())
            .is_err()
        {
            self.poisoned = true;
            return Err(NetworkLifecycleProtectedStoreErrorV1::Unavailable);
        }
        flock(&replacement, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::Unavailable)?;
        let before_swap = replay_network_lifecycle_journal(&mut replacement, self.key)?;
        if before_swap
            .current
            .as_ref()
            .map(|current| current.transaction_digest)
            != Some(row.transaction_digest)
            || before_swap.record_count != 1
        {
            return Err(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch);
        }
        renameat(
            &directory,
            FIXED_COMPACTION_NAME,
            &directory,
            FIXED_JOURNAL_NAME,
        )
        .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::Unavailable)?;
        self.file = replacement;
        self.anchor_generation = before_swap.anchor_generation;
        self.anchor_head = before_swap.anchor_head;
        self.current = before_swap.current;
        self.record_count = before_swap.record_count;
        self.journal_bytes = before_swap.journal_bytes;
        if fsync(&directory).is_err() {
            self.poisoned = true;
            self.fatal_swap_failure = true;
            return Err(NetworkLifecycleProtectedStoreErrorV1::Unavailable);
        }
        let replay = match replay_network_lifecycle_journal(&mut self.file, self.key) {
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
            return Err(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch);
        }
        self.anchor_generation = replay.anchor_generation;
        self.anchor_head = replay.anchor_head;
        self.current = replay.current;
        self.record_count = replay.record_count;
        self.journal_bytes = replay.journal_bytes;
        self.poisoned = false;
        Ok(())
    }

    fn reload(&mut self) -> Result<(), NetworkLifecycleProtectedStoreErrorV1> {
        if self.fatal_swap_failure {
            return Err(NetworkLifecycleProtectedStoreErrorV1::Unavailable);
        }
        let replay = replay_network_lifecycle_journal(&mut self.file, self.key)?;
        if replay.anchor_generation != self.anchor_generation
            || replay.anchor_head != self.anchor_head
        {
            return Err(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch);
        }
        self.current = replay.current;
        self.record_count = replay.record_count;
        self.journal_bytes = replay.journal_bytes;
        self.poisoned = false;
        Ok(())
    }
}

impl sealed::Sealed for NetworkLifecycleProtectedJournalV1 {}

impl NetworkLifecycleProtectedBackendV1 for NetworkLifecycleProtectedJournalV1 {
    fn commit_atomically(
        &mut self,
        write: NetworkLifecycleProtectedWriteV1<'_>,
    ) -> Result<NetworkLifecycleProtectedWriteOutcomeV1, NetworkLifecycleProtectedStoreErrorV1>
    {
        if self.poisoned {
            return Ok(NetworkLifecycleProtectedWriteOutcomeV1::OutcomeUnknown);
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
            || write.checkpoint.len() > super::MAXIMUM_RECOVERY_CHECKPOINT_BYTES
            || digest(write.checkpoint) != write.checkpoint_digest
        {
            return Err(NetworkLifecycleProtectedStoreErrorV1::Rejected);
        }
        if let Some(current) = &self.current {
            if current.transaction_digest == write.transaction_digest
                && current.generation == write.next_generation
                && current.predecessor_head == write.expected_head
                && current.checkpoint == write.checkpoint
            {
                return Ok(NetworkLifecycleProtectedWriteOutcomeV1::Committed(
                    network_lifecycle_receipt(current),
                ));
            }
        }
        if self.coordinates() != (write.expected_generation, write.expected_head) {
            return Err(NetworkLifecycleProtectedStoreErrorV1::Rejected);
        }
        let next_snapshot = recover_network_journal_snapshot(write.checkpoint)?;
        let predecessor_is_valid = match &self.current {
            Some(current) => {
                recover_network_journal_snapshot(&current.checkpoint).is_ok_and(|prior| {
                    NetworkLifecycleReducerV1::validates_journal_successor(&prior, &next_snapshot)
                })
            }
            None => true,
        };
        if next_snapshot.digest != write.snapshot_digest || !predecessor_is_valid {
            return Err(NetworkLifecycleProtectedStoreErrorV1::InvalidCheckpoint);
        }

        let current_head = protected_head(
            write.expected_head,
            write.next_generation,
            write.transaction_digest,
        );
        let receipt_digest = network_lifecycle_receipt_digest(
            self.key,
            write.next_generation,
            write.expected_head,
            current_head,
            write.transaction_digest,
            write.checkpoint_digest,
        );
        let row = NetworkLifecycleJournalRowV1 {
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
        let frame = encode_network_lifecycle_frame(&row)?;
        let next_journal_bytes = self
            .journal_bytes
            .checked_add(frame.len())
            .ok_or(NetworkLifecycleProtectedStoreErrorV1::Rejected)?;
        if next_journal_bytes > MAXIMUM_JOURNAL_BYTES
            || self.record_count >= MAXIMUM_JOURNAL_RECORDS
        {
            return Err(NetworkLifecycleProtectedStoreErrorV1::Rejected);
        }
        if self.file.seek(SeekFrom::End(0)).is_err() {
            return Err(NetworkLifecycleProtectedStoreErrorV1::Unavailable);
        }
        if self.file.write_all(&frame).is_err() || self.file.sync_data().is_err() {
            self.poisoned = true;
            return Ok(NetworkLifecycleProtectedWriteOutcomeV1::OutcomeUnknown);
        }
        self.journal_bytes = next_journal_bytes;
        self.record_count = self
            .record_count
            .checked_add(1)
            .ok_or(NetworkLifecycleProtectedStoreErrorV1::Rejected)?;
        self.current = Some(row.clone());
        Ok(NetworkLifecycleProtectedWriteOutcomeV1::Committed(
            network_lifecycle_receipt(&row),
        ))
    }

    fn read_current(
        &mut self,
        key: ObjectDigest,
    ) -> Result<NetworkLifecycleProtectedReadbackV1, NetworkLifecycleProtectedStoreErrorV1> {
        if key != self.key {
            return Err(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch);
        }
        self.reload()?;
        match &self.current {
            Some(row) => Ok(NetworkLifecycleProtectedReadbackV1 {
                generation: row.generation,
                predecessor_head: row.predecessor_head,
                current_head: row.current_head,
                transaction_digest: row.transaction_digest,
                receipt_digest: row.receipt_digest,
                checkpoint: row.checkpoint.clone(),
            }),
            None => Ok(NetworkLifecycleProtectedReadbackV1 {
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

struct NetworkLifecycleJournalReplayV1 {
    anchor_generation: u64,
    anchor_head: ObjectDigest,
    current: Option<NetworkLifecycleJournalRowV1>,
    record_count: usize,
    journal_bytes: usize,
}

fn replay_network_lifecycle_journal(
    file: &mut File,
    expected_key: ObjectDigest,
) -> Result<NetworkLifecycleJournalReplayV1, NetworkLifecycleProtectedStoreErrorV1> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::Unavailable)?;
    let length = usize::try_from(
        file.metadata()
            .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::Unavailable)?
            .len(),
    )
    .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::Unavailable)?;
    if length > MAXIMUM_JOURNAL_BYTES {
        return Err(NetworkLifecycleProtectedStoreErrorV1::Rejected);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::Unavailable)?;
    file.read_to_end(&mut bytes)
        .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::Unavailable)?;
    if bytes.len() != length {
        return Err(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch);
    }
    let (key, anchor_generation, anchor_head, mut offset) =
        decode_network_lifecycle_header(&bytes)?;
    if key != expected_key {
        return Err(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch);
    }
    let mut current = None;
    let mut previous_snapshot = None;
    let mut records = 0_usize;
    while offset < bytes.len() {
        if records >= MAXIMUM_JOURNAL_RECORDS {
            return Err(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch);
        }
        if bytes.len() - offset < 12 {
            truncate_incomplete_network_lifecycle_tail(file, offset)?;
            break;
        }
        if bytes.get(offset..offset + 8) != Some(FRAME_MAGIC.as_slice()) {
            return Err(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch);
        }
        let body_length = usize::try_from(u32::from_be_bytes(
            bytes[offset + 8..offset + 12]
                .try_into()
                .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch)?,
        ))
        .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch)?;
        let end = offset
            .checked_add(12)
            .and_then(|value| value.checked_add(body_length))
            .ok_or(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch)?;
        if end > bytes.len() {
            truncate_incomplete_network_lifecycle_tail(file, offset)?;
            break;
        }
        let frame = bytes
            .get(offset..end)
            .ok_or(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch)?;
        let row = decode_network_lifecycle_frame(frame, expected_key)?;
        let (expected_generation, expected_head) = current.as_ref().map_or(
            (anchor_generation, anchor_head),
            |prior: &NetworkLifecycleJournalRowV1| (prior.generation, prior.current_head),
        );
        if expected_generation.checked_add(1) != Some(row.generation)
            || row.predecessor_head != expected_head
        {
            return Err(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch);
        }
        let snapshot = recover_network_journal_snapshot(&row.checkpoint)?;
        if snapshot.digest != row.snapshot_digest
            || previous_snapshot.as_ref().is_some_and(|prior| {
                !NetworkLifecycleReducerV1::validates_journal_successor(prior, &snapshot)
            })
        {
            return Err(NetworkLifecycleProtectedStoreErrorV1::InvalidCheckpoint);
        }
        records = records
            .checked_add(1)
            .ok_or(NetworkLifecycleProtectedStoreErrorV1::Rejected)?;
        current = Some(row);
        previous_snapshot = Some(snapshot);
        offset = end;
    }
    Ok(NetworkLifecycleJournalReplayV1 {
        anchor_generation,
        anchor_head,
        current,
        record_count: records,
        journal_bytes: offset,
    })
}

fn recover_network_journal_snapshot(
    checkpoint: &[u8],
) -> Result<super::NetworkLifecycleRecoverySnapshotV1, NetworkLifecycleProtectedStoreErrorV1> {
    let snapshot = NetworkLifecycleRecoveryStoreV1::from_checkpoint_bytes(checkpoint.to_vec())
        .and_then(NetworkLifecycleRecoveryStoreV1::recover)
        .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::InvalidCheckpoint)?;
    NetworkLifecycleReducerV1::recover(snapshot.clone())
        .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::InvalidCheckpoint)?;
    Ok(snapshot)
}

fn encode_network_lifecycle_header(
    key: ObjectDigest,
    generation: u64,
    head: ObjectDigest,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(112);
    bytes.extend_from_slice(JOURNAL_MAGIC);
    bytes.extend_from_slice(key.as_bytes());
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.extend_from_slice(head.as_bytes());
    bytes.extend_from_slice(digest(&bytes).as_bytes());
    bytes
}

fn decode_network_lifecycle_header(
    bytes: &[u8],
) -> Result<(ObjectDigest, u64, ObjectDigest, usize), NetworkLifecycleProtectedStoreErrorV1> {
    const HEADER: usize = 112;
    if bytes.len() < HEADER
        || bytes.get(..8) != Some(JOURNAL_MAGIC.as_slice())
        || bytes.get(80..112) != Some(digest(&bytes[..80]).as_bytes().as_slice())
    {
        return Err(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch);
    }
    let key = ObjectDigest::from_bytes(
        bytes[8..40]
            .try_into()
            .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch)?,
    );
    let generation = u64::from_be_bytes(
        bytes[40..48]
            .try_into()
            .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch)?,
    );
    let head = ObjectDigest::from_bytes(
        bytes[48..80]
            .try_into()
            .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch)?,
    );
    if key.as_bytes() == &[0; 32] || generation == 0 || head.as_bytes() == &[0; 32] {
        return Err(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch);
    }
    Ok((key, generation, head, HEADER))
}

fn encode_network_lifecycle_frame(
    row: &NetworkLifecycleJournalRowV1,
) -> Result<Vec<u8>, NetworkLifecycleProtectedStoreErrorV1> {
    let checkpoint_length = u32::try_from(row.checkpoint.len())
        .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::Rejected)?;
    let body_length = 276_usize
        .checked_add(row.checkpoint.len())
        .ok_or(NetworkLifecycleProtectedStoreErrorV1::Rejected)?;
    let body_length =
        u32::try_from(body_length).map_err(|_| NetworkLifecycleProtectedStoreErrorV1::Rejected)?;
    let mut bytes = Vec::with_capacity(12 + body_length as usize);
    bytes.extend_from_slice(FRAME_MAGIC);
    bytes.extend_from_slice(&body_length.to_be_bytes());
    bytes.extend_from_slice(&network_lifecycle_row_bytes(row));
    bytes.extend_from_slice(&checkpoint_length.to_be_bytes());
    bytes.extend_from_slice(&row.checkpoint);
    bytes.extend_from_slice(digest(&bytes).as_bytes());
    Ok(bytes)
}

fn network_lifecycle_row_bytes(row: &NetworkLifecycleJournalRowV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(240);
    bytes.extend_from_slice(row.key.as_bytes());
    bytes.extend_from_slice(&row.expected_generation.to_be_bytes());
    bytes.extend_from_slice(row.predecessor_head.as_bytes());
    bytes.extend_from_slice(&row.generation.to_be_bytes());
    bytes.extend_from_slice(row.snapshot_digest.as_bytes());
    bytes.extend_from_slice(row.checkpoint_digest.as_bytes());
    bytes.extend_from_slice(row.transaction_digest.as_bytes());
    bytes.extend_from_slice(row.current_head.as_bytes());
    bytes.extend_from_slice(row.receipt_digest.as_bytes());
    bytes
}

fn decode_network_lifecycle_frame(
    frame: &[u8],
    expected_key: ObjectDigest,
) -> Result<NetworkLifecycleJournalRowV1, NetworkLifecycleProtectedStoreErrorV1> {
    const FRAME_PREFIX: usize = 12;
    const FIXED_BODY_WITH_DIGEST: usize = 276;
    const CHECKPOINT_LENGTH_OFFSET: usize = 252;
    const CHECKPOINT_OFFSET: usize = 256;

    if frame.len() < FRAME_PREFIX + FIXED_BODY_WITH_DIGEST
        || frame.get(..8) != Some(FRAME_MAGIC.as_slice())
    {
        return Err(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch);
    }
    let encoded_body_length = usize::try_from(read_u32(frame, 8)?)
        .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch)?;
    if encoded_body_length != frame.len() - FRAME_PREFIX {
        return Err(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch);
    }
    let frame_digest_offset = frame
        .len()
        .checked_sub(32)
        .ok_or(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch)?;
    if frame.get(frame_digest_offset..)
        != Some(digest(&frame[..frame_digest_offset]).as_bytes().as_slice())
    {
        return Err(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch);
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
        .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch)?;
    let checkpoint_end = CHECKPOINT_OFFSET
        .checked_add(checkpoint_length)
        .ok_or(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch)?;
    if checkpoint_end != frame_digest_offset
        || checkpoint_length == 0
        || checkpoint_length > super::MAXIMUM_RECOVERY_CHECKPOINT_BYTES
    {
        return Err(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch);
    }
    let checkpoint = frame
        .get(CHECKPOINT_OFFSET..checkpoint_end)
        .ok_or(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch)?
        .to_vec();
    let store = NetworkLifecycleRecoveryStoreV1::from_checkpoint_bytes(checkpoint.clone())
        .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::InvalidCheckpoint)?;
    let recovered = store
        .recover()
        .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::InvalidCheckpoint)?;

    let expected_transaction = transaction_digest(
        key,
        expected_generation,
        predecessor_head,
        generation,
        snapshot_digest,
        checkpoint_digest,
    );
    let expected_head = protected_head(predecessor_head, generation, stored_transaction_digest);
    let expected_receipt = network_lifecycle_receipt_digest(
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
        return Err(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch);
    }

    Ok(NetworkLifecycleJournalRowV1 {
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

fn network_lifecycle_receipt(
    row: &NetworkLifecycleJournalRowV1,
) -> NetworkLifecycleProtectedReceiptV1 {
    NetworkLifecycleProtectedReceiptV1 {
        generation: row.generation,
        predecessor_head: row.predecessor_head,
        current_head: row.current_head,
        transaction_digest: row.transaction_digest,
        receipt_digest: row.receipt_digest,
    }
}

fn network_lifecycle_receipt_digest(
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

fn truncate_incomplete_network_lifecycle_tail(
    file: &mut File,
    complete_length: usize,
) -> Result<(), NetworkLifecycleProtectedStoreErrorV1> {
    let complete_length = u64::try_from(complete_length)
        .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::Unavailable)?;
    file.set_len(complete_length)
        .and_then(|_| file.sync_data())
        .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::Unavailable)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, NetworkLifecycleProtectedStoreErrorV1> {
    let end = offset
        .checked_add(4)
        .ok_or(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch)?;
    let value = bytes
        .get(offset..end)
        .ok_or(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch)?
        .try_into()
        .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch)?;
    Ok(u32::from_be_bytes(value))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, NetworkLifecycleProtectedStoreErrorV1> {
    let end = offset
        .checked_add(8)
        .ok_or(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch)?;
    let value = bytes
        .get(offset..end)
        .ok_or(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch)?
        .try_into()
        .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch)?;
    Ok(u64::from_be_bytes(value))
}

fn read_digest(
    bytes: &[u8],
    offset: usize,
) -> Result<ObjectDigest, NetworkLifecycleProtectedStoreErrorV1> {
    let end = offset
        .checked_add(32)
        .ok_or(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch)?;
    let value = bytes
        .get(offset..end)
        .ok_or(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch)?
        .try_into()
        .map_err(|_| NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch)?;
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
    receipt: &NetworkLifecycleProtectedReceiptV1,
    readback: &NetworkLifecycleProtectedReadbackV1,
) -> Result<(), NetworkLifecycleProtectedStoreErrorV1> {
    let transaction = transaction_digest(
        key,
        expected_generation,
        expected_head,
        next_generation,
        snapshot_digest,
        checkpoint_digest,
    );
    let head = protected_head(expected_head, next_generation, transaction);
    let expected_receipt = network_lifecycle_receipt_digest(
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
        return Err(NetworkLifecycleProtectedStoreErrorV1::ReadbackMismatch);
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
