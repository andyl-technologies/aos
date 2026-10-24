//! Same-writer original Root native admission, retained provenance and readback.
//!
//! Only exact rederived namespace40 owner edges plus their namespace46 original
//! floor pass this scope. Physical readback does not establish live Security
//! custody or Mount's actual table installation; those owners must compare the
//! same retained originals before private signing or carrier IO.

use aos_sandbox_protocol::domain_ledger::capacity_family::family::{
    CanonicalCapacityFamily, canonical_reservations,
};
use aos_sandbox_protocol::domain_ledger::capacity_family::native_held::OriginalRootCapacityRecordV5;
use aos_sandbox_protocol::domain_ledger::capacity_family::ordinary::{
    OrdinaryCapacityKindV4, OrdinaryCapacityProfileV4, OrdinaryCapacityRecordV4,
};

use crate::journal::PreflightTransactionViewV1;
use crate::journal::semantic_append::PreflightScope;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::{
    RootNativeCutKindV1, RootNativeCutV1, RootNativeHeldGraphV2, RootNativeHeldSidecarV2,
    RootNativeTransitionKindV2 as Kind, has_original_pending_closed_cut_v5,
    native_root_sidecar_key_v2, original_root_remaining_v5,
    validate_native_root_graph_v2, validate_original_root_transition_v5,
};
use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldControlKindV1, NativeHeldOwnerV1,
    frame::{PreparedNativeHeldControlV1, SignedNativeHeldControlV1},
    suffix::NativeHeldCompletionSuffixV1,
};
use sha2::{Digest as _, Sha256};

use super::{
    CommitResult, Journal, JournalError, JournalLimits, JournalRecord,
    JournalTransaction, ProtectedAuthorityScope, ProtectedJournalAuthority,
    ProtectedJournalSnapshot, RecordNamespace, RootOwnerEdge, authority_preflight_digest,
    validate_transaction,
};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

mod pending_v5;
mod root_closed_v5;
mod custody;

#[cfg(test)]
pub(super) use root_closed_v5::phase11_funded_data;

fn invalid() -> JournalError {
    aos_sandbox_ledger_replay::replay::root_original_native::invalid().into()
}

fn graph(state: &State) -> Result<RootNativeHeldGraphV2, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::graph(state)
        .map_err(JournalError::from)
}

fn require_named_funding(state: &State, limits: JournalLimits) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::require_named_funding(state, limits)
        .map_err(JournalError::from)
}

fn is_original_release_floor(family: &CanonicalCapacityFamily) -> bool {
    aos_sandbox_ledger_replay::replay::root_original_native::is_original_release_floor(family)
}

fn validate_original_release_floors(
    state: &State,
    families: &[CanonicalCapacityFamily],
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::validate_original_release_floors(
        state,
        families,
    )
        .map_err(JournalError::from)
}

fn original_release_current_puts(
    checked: &RootNativeHeldGraphV2,
    release: [u8; 32],
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::original_release_current_puts(
        checked,
        release,
    )
        .map_err(JournalError::from)
}

fn derive_original_release(
    state: &State,
    owners: &JournalTransaction,
    root: [u8; 32],
    release: [u8; 32],
    limits: JournalLimits,
) -> Result<(JournalTransaction, OrdinaryCapacityRecordV4), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::derive_original_release(
        state,
        owners,
        root,
        release,
        limits,
    )
        .map_err(JournalError::from)
}

fn validate_original_release_edge(
    state: &State,
    transaction: &JournalTransaction,
    root: [u8; 32],
    limits: JournalLimits,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::validate_original_release_edge(
        state,
        transaction,
        root,
        limits,
    )
        .map_err(JournalError::from)
}

fn derive_original_release_status(
    state: &State,
    owners: &JournalTransaction,
    root: [u8; 32],
    release: [u8; 32],
    limits: JournalLimits,
) -> Result<(JournalTransaction, OrdinaryCapacityRecordV4), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::derive_original_release_status(
        state,
        owners,
        root,
        release,
        limits,
    )
        .map_err(JournalError::from)
}

/// Shares only the closed family policy after complete canonical traversal.
///
/// # Errors
/// Rejects unsupported Source5, Mount Native3 and non-kind2/kind5 Ordinary4.
pub(super) fn require_supported_funding_families(
    families: &[CanonicalCapacityFamily],
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::require_supported_funding_families(families)
        .map_err(JournalError::from)
}

/// Rejoins unchanged native5 originals after the caller's exact ordinary reducer.
pub(super) fn preserve_local_owner(
    state: &State,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::preserve_local_owner(state, transaction)
        .map_err(JournalError::from)
}

pub(super) fn require_funded_original_owner(
    state: &State,
    checked: &RootNativeHeldGraphV2,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::require_funded_original_owner(state, checked)
        .map_err(JournalError::from)
}

/// Rejoins every selected original floor only after validating ALL families.
pub(super) fn pending(
    state: &State,
    limits: JournalLimits,
) -> Result<Vec<OriginalRootCapacityRecordV5>, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::pending(state, limits)
        .map_err(JournalError::from)
}

pub(super) fn require_generic_transaction(
    state: &State,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::require_generic_transaction(
        state,
        transaction,
    )
        .map_err(JournalError::from)
}

fn apply(state: &State, records: &[JournalRecord]) -> Result<State, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::apply(state, records)
        .map_err(JournalError::from)
}

fn require_exact_owner_puts(
    owners: &JournalTransaction,
    puts: &BTreeMap<Vec<u8>, Vec<u8>>,
    generated: Option<(&[u8], &[u8])>,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::require_exact_owner_puts(
        owners,
        puts,
        generated,
    )
        .map_err(JournalError::from)
}

fn admission(
    state: &State,
    owners: &JournalTransaction,
    prepared: PreparedNativeHeldControlV1,
    limits: JournalLimits,
) -> Result<(JournalTransaction, OriginalRootCapacityRecordV5), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::admission(state, owners, prepared, limits)
        .map_err(JournalError::from)
}

fn derive_admission(
    state: &State,
    owners: &JournalTransaction,
    prepared: PreparedNativeHeldControlV1,
    limits: JournalLimits,
) -> Result<(JournalTransaction, OriginalRootCapacityRecordV5), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::derive_admission(
        state,
        owners,
        prepared,
        limits,
    )
        .map_err(JournalError::from)
}

fn continuation(
    state: &State,
    owners: &JournalTransaction,
    attempt: [u8; 32],
    limits: JournalLimits,
) -> Result<
    (
        JournalTransaction,
        Option<OriginalRootCapacityRecordV5>,
        [u8; 32],
    ),
    JournalError,
> {
    aos_sandbox_ledger_replay::replay::root_original_native::continuation(state, owners, attempt, limits)
        .map_err(JournalError::from)
}

fn derive_continuation(
    state: &State,
    owners: &JournalTransaction,
    attempt: [u8; 32],
    limits: JournalLimits,
) -> Result<
    (
        JournalTransaction,
        Option<OriginalRootCapacityRecordV5>,
        OriginalRootCapacityRecordV5,
    ),
    JournalError,
> {
    aos_sandbox_ledger_replay::replay::root_original_native::derive_continuation(
        state,
        owners,
        attempt,
        limits,
    )
        .map_err(JournalError::from)
}

fn validate_transfer(
    transaction: &JournalTransaction,
    old: &OriginalRootCapacityRecordV5,
    next: Option<&OriginalRootCapacityRecordV5>,
    limits: JournalLimits,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::validate_transfer(
        transaction,
        old,
        next,
        limits,
    )
        .map_err(JournalError::from)
}

pub(super) fn validate_edge(
    state: &State,
    transaction: &JournalTransaction,
    attempt: [u8; 32],
    limits: JournalLimits,
) -> Result<Option<[u8; 32]>, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::validate_edge(
        state,
        transaction,
        attempt,
        limits,
    )
        .map_err(JournalError::from)
}

pub(super) fn validate_replayed_transaction(
    state: &State,
    transaction: &JournalTransaction,
    limits: JournalLimits,
    successor_sequence: u64,
) -> Result<bool, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_native::validate_replayed_transaction(
        state,
        transaction,
        limits,
        successor_sequence,
    )
        .map_err(JournalError::from)
}

/// Borrows the same fixed held writer for original Root-only native owner edges.
pub struct MountOriginalNativeJournalAuthorityV5<'journal> {
    authority: ProtectedJournalAuthority<'journal>,
}

/// Retains exact attempted bytes across every preflight/commit/readback error.
#[must_use]
pub struct PreparedOriginalRootAppendV5 {
    transaction: JournalTransaction,
    snapshot: ProtectedJournalSnapshot,
    attempt: [u8; 32],
    digest: [u8; 32],
    floor: Option<OriginalRootCapacityRecordV5>,
    preflight_complete: bool,
    failed: core::cell::Cell<bool>,
    attempted: core::cell::Cell<bool>,
    actual: Option<custody::ActualOriginalRootAppendV5>,
}

/// Binds exact original rows/floor to a physical current writer and sequence.
#[must_use]
pub struct OriginalRootProtectedReadbackV5 {
    snapshot: ProtectedJournalSnapshot,
    graph: RootNativeHeldGraphV2,
    floor: Option<OriginalRootCapacityRecordV5>,
    attempt: [u8; 32],
}

impl<'journal> MountOriginalNativeJournalAuthorityV5<'journal> {
    /// Returns the eight immutable ceilings opened by this SAME held Journal.
    ///
    /// These are configuration DATA, not currentness, residency funding or an
    /// append/signing permit. This projection performs no observation.
    #[must_use]
    pub fn configured_limits(&self) -> JournalLimits {
        self.authority.journal.native.limits_data_v1()
    }

    pub(crate) fn claim(journal: &'journal mut Journal) -> Result<Self, JournalError> {
        journal.ensure_protected_authority()?;
        let writer = Self {
            authority: ProtectedJournalAuthority {
                journal,
                namespace: RecordNamespace::MountSourceAcquisition,
                scope: ProtectedAuthorityScope::RootOriginalNativeV5,
            },
        };
        writer.require_current()?;
        writer.authority.validate_root_local_startup_replay_v4()?;
        writer.current_graph()?;
        Ok(writer)
    }

    fn require_current(&self) -> Result<(), JournalError> {
        self.authority.journal.ensure_protected_authority()?;
        self.authority.validate_held_root_owned_at(
            Path::new("/var/lib/aos/sandbox-mount"),
            "mount.journal",
        )?;
        if self.authority.scope != ProtectedAuthorityScope::RootOriginalNativeV5 {
            return Err(JournalError::Mechanical(crate::journal::MechanicalError::ForeignAuthorityNamespace));
        }
        Ok(())
    }

    /// Returns the complete checked current native graph without hot authority.
    ///
    /// # Errors
    /// Rejects stale physical names, unknown owner funding or invalid full graphs.
    pub fn current_graph(&self) -> Result<RootNativeHeldGraphV2, JournalError> {
        self.require_current()?;
        require_named_funding(self.authority.journal.native.read_view_v1().state(), self.authority.journal.native.read_view_v1().limits())?;
        pending(self.authority.journal.native.read_view_v1().state(), self.authority.journal.native.read_view_v1().limits())?;
        if self.authority.journal.native.read_view_v1().state().iter().any(|((namespace, _), value)| {
            *namespace == RecordNamespace::GlobalCapacityReservation
                && value.get(8..13) == Some(&[0, 4, 40, 10, 12])
        }) {
            for family in canonical_reservations(self.authority.journal.native.read_view_v1().state())? {
                if let CanonicalCapacityFamily::Ordinary4(floor) = family {
                    if floor.data().kind == OrdinaryCapacityKindV4::ReleaseRequest
                        && !self.authority.journal.native.read_view_v1().transaction_ids()
                            .contains(&floor.data().admission_transaction)
                    {
                        // A compacted scalar floor cannot replace actual original
                        // Release admission provenance on this selected hot route.
                        return Err(JournalError::Mechanical(crate::journal::MechanicalError::StaleAuthoritySnapshot));
                    }
                }
            }
        }
        graph(self.authority.journal.native.read_view_v1().state())
    }

    /// Returns an opaque current snapshot for this named physical scope only.
    ///
    /// # Errors
    /// Rejects unavailable physical currentness or malformed original funding.
    pub fn snapshot(&self) -> Result<ProtectedJournalSnapshot, JournalError> {
        self.current_graph()?;
        self.authority.snapshot()
    }

    /// Checks this named scope's exact physical snapshot without a generic grant.
    ///
    /// # Errors
    /// Rejects a different instance/scope/sequence or changed original state.
    pub fn validate_snapshot(
        &self,
        snapshot: &ProtectedJournalSnapshot,
    ) -> Result<(), JournalError> {
        self.current_graph()?;
        self.authority
            .validate_mount_source_acquisition_snapshot(snapshot)
    }

    /// Rechecks the retained original legacy planning token before first append.
    ///
    /// This narrow handover validates the SAME opaque instance/sequence and
    /// fixed legacy scope. It never relabels or updates a historical token.
    ///
    /// # Errors
    /// Rejects stale or nonfixed planning custody and existing original debt.
    pub fn validate_original_planning_snapshot(
        &self,
        snapshot: &ProtectedJournalSnapshot,
    ) -> Result<(), JournalError> {
        self.current_graph()?;
        if snapshot.scope != ProtectedAuthorityScope::FixedMountSourceAcquisition
            || snapshot.namespace != RecordNamespace::MountSourceAcquisition
            || !std::sync::Arc::ptr_eq(
                &snapshot.instance,
                &self.authority.journal.authority_instance,
            )
            || snapshot.sequence != self.authority.journal.snapshot_sequence()
        {
            return Err(JournalError::Mechanical(crate::journal::MechanicalError::StaleAuthoritySnapshot));
        }
        Ok(())
    }

    /// Borrows one actual current namespace40 value after full native validation.
    ///
    /// # Errors
    /// Rejects unavailable currentness or any malformed retained original floor.
    pub fn get(&self, key: &[u8]) -> Result<Option<&[u8]>, JournalError> {
        self.current_graph()?;
        self.authority.mount_source_acquisition_get(key)
    }

    /// Prepares exact original owner reservation, R/cut and its native7 floor.
    ///
    /// # Errors
    /// Rejects nonoriginal owners, changed cut/witness, fences or all-floor limits.
    pub fn prepare_admission(
        &self,
        owners: &JournalTransaction,
        prepared: PreparedNativeHeldControlV1,
    ) -> Result<PreparedOriginalRootAppendV5, JournalError> {
        let mut retained = None;
        self.prepare_admission_retaining_v5(owners, &prepared, &mut retained)?;
        retained.ok_or_else(invalid)
    }

    /// Reconstructs exact prospective companions for unsigned original DATA.
    ///
    /// This supplies no signing/append grant; original owner validation is
    /// rederived by prepare_admission before the actual coupled commit.
    ///
    /// # Errors
    /// Rejects currentness, owner graph/cut errors or exhausted frame sequence.
    pub fn prospective_original_admission_cut(&self, owners: &JournalTransaction, attempt: [u8; 32])
        -> Result<(RootNativeCutV1, aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::RootNativeReconstructedCutV1, u64), JournalError>
    {
        self.current_graph()?;
        let successor = graph(&apply(self.authority.journal.native.read_view_v1().state(), owners.records())?)?;
        let cut = RootNativeCutV1::capture(
            RootNativeCutKindV1::Admission,
            *owners.id(),
            successor.legacy(),
            attempt,
        )
        .map_err(|_| invalid())?;
        let captured = cut
            .reconstruct(successor.legacy(), attempt)
            .map_err(|_| invalid())?;
        let sequence = self
            .authority
            .journal
            .snapshot_sequence()
            .checked_add(
                u64::try_from(owners.records().len())
                    .map_err(|_| JournalError::Mechanical(crate::journal::MechanicalError::SequenceExhausted))?
                    + 4,
            )
            .ok_or(JournalError::Mechanical(crate::journal::MechanicalError::SequenceExhausted))?;
        Ok((cut, captured, sequence))
    }

    /// Prepares an exact native-only continuation under the retained originals.
    ///
    /// # Errors
    /// Rejects stutters, foreign owners, missing originals or unchanged limits.
    pub fn prepare_transition(
        &self,
        owners: &JournalTransaction,
        attempt: [u8; 32],
    ) -> Result<PreparedOriginalRootAppendV5, JournalError> {
        let mut retained = None;
        self.prepare_transition_retaining_v5(owners, attempt, &mut retained)?;
        retained.ok_or_else(invalid)
    }

    /// Parks an independently funded Release beside the same phase7 original.
    ///
    /// The returned candidate uses the existing one-shot preflight, commit and
    /// physical capture engine. It never spends or remints the original native
    /// floor and cannot authorize physical release or retirement.
    ///
    /// # Errors
    ///
    /// Retains failed candidate custody for occupied slots, changed originals,
    /// a nonfresh Release, another capacity debt or any opened ceiling failure.
    #[doc(hidden)]
    pub fn prepare_original_release_retaining_v1(
        &self,
        owners: &JournalTransaction,
        root: [u8; 32],
        release: [u8; 32],
        slot: &mut Option<PreparedOriginalRootAppendV5>,
    ) -> Result<(), JournalError> {
        custody::PreparationBoundaryV5::new(slot).run(|slot| {
            if slot.is_some() {
                return Err(invalid());
            }
            *slot = Some(self.initial_candidate_v5(owners, root));
            self.current_graph()?;
            let (transaction, _) = derive_original_release(
                self.authority.journal.native.read_view_v1().state(), owners, root, release,
                self.authority.journal.native.read_view_v1().limits(),
            )?;
            let candidate = slot.as_mut().ok_or_else(invalid)?;
            candidate.transaction = transaction;
            self.finish_preparation_v5(candidate)
        })
    }

    /// Parks the exact consumed-Pending owner edge and surviving cleanup floor.
    ///
    /// # Errors
    ///
    /// Retains a failed candidate on stale physical names, non-exact canonical
    /// owners, missing profile3 debt or any whole opened-limit/NEXT refusal.
    #[doc(hidden)]
    pub fn prepare_original_release_status_retaining_v1(
        &self,
        owners: &JournalTransaction,
        root: [u8; 32],
        release: [u8; 32],
        slot: &mut Option<PreparedOriginalRootAppendV5>,
    ) -> Result<(), JournalError> {
        custody::PreparationBoundaryV5::new(slot).run(|slot| {
            if slot.is_some() { return Err(invalid()); }
            *slot = Some(self.initial_candidate_v5(owners, root));
            self.current_graph()?;
            let (transaction, _) = derive_original_release_status(
                self.authority.journal.native.read_view_v1().state(), owners, root, release,
                self.authority.journal.native.read_view_v1().limits(),
            )?;
            let candidate = slot.as_mut().ok_or_else(invalid)?;
            candidate.transaction = transaction;
            self.finish_preparation_v5(candidate)
        })
    }

    /// Prepares exact signed Root1 storage before either original carrier send.
    ///
    /// # Errors
    /// Rejects stale physical admission/readback, a different signature input,
    /// already advanced original phase or an unfunded continuation.
    pub fn prepare_root1_store(
        &self,
        admission: &OriginalRootProtectedReadbackV5,
        signed: &SignedNativeHeldControlV1,
    ) -> Result<PreparedOriginalRootAppendV5, JournalError> {
        let mut retained = None;
        self.prepare_root1_store_retaining_v5(admission, signed, &mut retained)?;
        retained.ok_or_else(invalid)
    }

    fn original_root1_store_owners(
        &self,
        admission: &OriginalRootProtectedReadbackV5,
        signed: &SignedNativeHeldControlV1,
    ) -> Result<JournalTransaction, JournalError> {
        self.validate_readback(admission)?;
        let floor = admission.floor.as_ref().ok_or_else(invalid)?;
        let old = admission
            .graph
            .sidecars()
            .get(&admission.attempt)
            .ok_or_else(invalid)?;
        if old.suffix().phase() != 0
            || signed.kind() != NativeHeldControlKindV1::RootPrepared
            || signed.prepared() != floor.original_prepared()
        {
            return Err(invalid());
        }
        let suffix = NativeHeldCompletionSuffixV1::new(
            NativeHeldOwnerV1::Root,
            1,
            old.suffix().flight(),
            None,
            vec![signed.clone()],
        )
        .map_err(|_| invalid())?;
        let sidecar = RootNativeHeldSidecarV2::new(
            *old.original_scope(),
            old.response_transaction(),
            old.disposition().cloned(),
            old.settlement().cloned(),
            old.terminal_verifier().cloned(),
            suffix,
            old.admission_cut().clone(),
            old.disposition_cut().cloned(),
            old.no_interest_terminal().cloned(),
        )
        .map_err(|_| invalid())?;
        let mut digest = Sha256::new();
        digest.update(b"aos.sandbox.mount.original-root1-store-tx.v5\0");
        digest.update(floor.admission_transaction_id());
        digest.update(signed.to_canonical_bytes());
        let hash: [u8; 32] = digest.finalize().into();
        let mut tx = [0; 16];
        tx.copy_from_slice(&hash[..16]);
        let owners = JournalTransaction::new(
            tx,
            vec![JournalRecord::put(
                RecordNamespace::MountSourceAcquisition,
                native_root_sidecar_key_v2(admission.attempt).map_err(|_| invalid())?,
                sidecar.to_canonical_bytes().map_err(|_| invalid())?,
            )],
        )?;
        Ok(owners)
    }

    fn preflight(
        &self,
        transaction: &JournalTransaction,
        attempt: [u8; 32],
    ) -> Result<(), JournalError> {
        self.authority.journal.preflight_in_scope(
            PreflightTransactionViewV1::Ordinary(std::slice::from_ref(transaction)),
            PreflightScope {
                allow_capacity_records: true,
                root_local_edge: Some(RootOwnerEdge::OriginalNative(attempt)),
                ..PreflightScope::default()
            },
        )
    }

    /// Appends and reads back while borrowing, never consuming attempted custody.
    ///
    /// # Errors
    /// Rejects stale preflight/snapshot/bytes. Ambiguous durability or readback
    /// poisons the writer while the caller retains the same prepared container.
    pub fn commit_prepared(
        &mut self,
        prepared: &PreparedOriginalRootAppendV5,
    ) -> Result<OriginalRootProtectedReadbackV5, JournalError> {
        let mut actual = None;
        self.commit_original_input_v5(custody::OriginalAppendInputV5::borrow(prepared), &mut actual)?;
        actual.and_then(|capture| capture.complete).ok_or_else(invalid)
    }

    /// Reconstructs protected metadata for one existing original Root terminal.
    ///
    /// This permits readback after restart without a retained append container.
    /// It requires actual retained admission transaction provenance and either
    /// the current no-interest marker's cleanup transaction or a stored terminal
    /// ACK in the fully validated graph. It provides no original hot flight,
    /// positive FD or time authority, current signer, or new ACK authority.
    ///
    /// # Errors
    /// Rejects an absent or nonterminal original v2 sidecar, a remaining original
    /// floor for the attempt, missing retained transaction provenance, invalid
    /// graph/funding, or unavailable physical currentness. A compacted generation
    /// without the original transaction identities cannot supply this readback.
    pub fn terminal_readback(
        &self,
        attempt: [u8; 32],
    ) -> Result<OriginalRootProtectedReadbackV5, JournalError> {
        let checked = self.current_graph()?;
        let sidecar = checked.sidecars().get(&attempt).ok_or_else(invalid)?;
        if original_root_remaining_v5(&checked, attempt).map_err(|_| invalid())? != 0 {
            return Err(invalid());
        }

        let families = canonical_reservations(self.authority.journal.native.read_view_v1().state())?;
        if families.iter().any(|family| {
            matches!(family, CanonicalCapacityFamily::OriginalRoot5(floor)
                if floor.request().owner_id == attempt)
        }) {
            return Err(invalid());
        }

        let transactions = self.authority.journal.native.read_view_v1().transaction_ids();
        if !transactions.contains(&sidecar.admission_cut().capture_transaction()) {
            return Err(JournalError::Mechanical(crate::journal::MechanicalError::StaleAuthoritySnapshot));
        }
        if let Some(marker) = sidecar.no_interest_terminal() {
            if !transactions.contains(&marker.cleanup_transaction()) {
                return Err(JournalError::Mechanical(crate::journal::MechanicalError::StaleAuthoritySnapshot));
            }
        } else if !sidecar.suffix().controls().last().is_some_and(|control| {
            matches!(
                control.kind(),
                NativeHeldControlKindV1::RootTerminalRecorded
                    | NativeHeldControlKindV1::RootRecoveryQuery
            )
        }) {
            return Err(invalid());
        }

        let readback = OriginalRootProtectedReadbackV5 {
            snapshot: self.snapshot()?,
            graph: checked,
            floor: None,
            attempt,
        };
        self.validate_readback(&readback)?;
        Ok(readback)
    }

    /// Rechecks exact physical readback at its actual current-use boundary.
    ///
    /// # Errors
    /// Rejects stale readback, changed full graph, missing P/C or substituted floor.
    pub fn validate_readback(
        &self,
        readback: &OriginalRootProtectedReadbackV5,
    ) -> Result<(), JournalError> {
        self.validate_snapshot(&readback.snapshot)?;
        let checked = self.current_graph()?;
        if checked.canonical_records() != readback.graph.canonical_records() {
            return Err(invalid());
        }
        if let Some(floor) = &readback.floor {
            floor.validate_graph(&checked, self.authority.journal.native.read_view_v1().limits())?;
            let record = floor.to_journal_record()?;
            if self.authority.journal.get(record.namespace(), record.key()) != record.value() {
                return Err(invalid());
            }
        } else if original_root_remaining_v5(&checked, readback.attempt).map_err(|_| invalid())?
            != 0
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Checks historical origin without weakening any current V5 snapshot method.
///
/// # Errors
/// Rejects replaced instances, wrong historical scope/phase, changed original
/// rows or Root5 bytes, and malformed current Query or original metadata.
pub(super) fn require_original_root_closed_origin_v6(
    origin: &OriginalRootProtectedReadbackV5,
    journal: &Journal,
) -> Result<(), JournalError> {
    if !std::sync::Arc::ptr_eq(&origin.snapshot.instance, &journal.authority_instance)
        || origin.snapshot.namespace != RecordNamespace::MountSourceAcquisition
        || origin.snapshot.scope != ProtectedAuthorityScope::RootOriginalNativeV5
        || origin.snapshot.sequence > journal.snapshot_sequence()
    {
        return Err(JournalError::Mechanical(crate::journal::MechanicalError::StaleAuthoritySnapshot));
    }
    let floor = origin.floor.as_ref().ok_or_else(invalid)?;
    let sidecar = origin.graph.sidecars().get(&origin.attempt).ok_or_else(invalid)?;
    if floor.request().owner_id != origin.attempt
        || floor.request().future_transactions != 2
        || sidecar.suffix().phase() != 11
        || sidecar.suffix().prepared().is_some()
        || sidecar.suffix().control(NativeHeldControlKindV1::RootClosed).is_none()
        || sidecar.suffix().control(NativeHeldControlKindV1::ProviderHeld).is_some()
        || sidecar.suffix().control(NativeHeldControlKindV1::RootAccepted).is_some()
        || sidecar.settlement().is_some()
        || sidecar.terminal_verifier().is_some()
        || sidecar.no_interest_terminal().is_some()
        || !has_original_pending_closed_cut_v5(&origin.graph, sidecar).map_err(|_| invalid())?
        || original_root_remaining_v5(&origin.graph, origin.attempt).map_err(|_| invalid())? != 2
    {
        return Err(invalid());
    }
    floor.validate_graph(&origin.graph, journal.native.read_view_v1().limits())?;
    let current = graph(journal.native.read_view_v1().state())?;
    pending(journal.native.read_view_v1().state(), journal.native.read_view_v1().limits())?;
    super::root_original_inventory::pending(journal.native.read_view_v1().state(), journal.native.read_view_v1().limits())?;
    floor.validate_graph(&current, journal.native.read_view_v1().limits())?;
    let floor_record = floor.to_journal_record()?;
    let sidecar_key = native_root_sidecar_key_v2(origin.attempt).map_err(|_| invalid())?;
    if journal.get(floor_record.namespace(), floor_record.key()) != floor_record.value()
        || current.canonical_records().get(&sidecar_key)
            != origin.graph.canonical_records().get(&sidecar_key)
    {
        return Err(invalid());
    }

    let cut = sidecar.disposition_cut().ok_or_else(invalid)?;
    let captured = cut.reconstruct(origin.graph.legacy(), origin.attempt)
        .map_err(|_| invalid())?;
    let scope = origin.graph.legacy().provider_attempts.get(&origin.attempt)
        .ok_or_else(invalid)?.scope;
    let head_key = aos_sandbox_protocol::mount_source_acquisition_state::provider_head_key(
        scope.holder_authority_id, scope.provider_authority_id,
    );
    if captured.canonical_records().len() != 4 {
        return Err(invalid());
    }
    for (key, bytes) in captured.canonical_records() {
        if origin.graph.canonical_records().get(key) != Some(bytes)
            || (*key != head_key && current.canonical_records().get(key) != Some(bytes))
        {
            return Err(invalid());
        }
    }
    // Captured H/R/W remain historical. Current H has its independent complete
    // Query graph/rejoin check above, at the named writer's bracketed cut.
    Ok(())
}

impl OriginalRootProtectedReadbackV5 {
    /// Borrows actual checked current records for trusted private installation.
    #[must_use]
    pub const fn graph(&self) -> &RootNativeHeldGraphV2 {
        &self.graph
    }

    /// Borrows retained exact original provenance, never a signing grant.
    #[must_use]
    pub const fn floor(&self) -> Option<&OriginalRootCapacityRecordV5> {
        self.floor.as_ref()
    }

    /// Returns the immutable original Mount attempt identity.
    #[must_use]
    pub const fn attempt(&self) -> [u8; 32] {
        self.attempt
    }

    /// Returns the physical sequence for diagnostic comparison only.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.snapshot.sequence()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_owner_puts_match_only_exact_reducer_changes() {
        let namespace = RecordNamespace::MountSourceAcquisition;
        let owner = JournalRecord::put(namespace, b"owner".to_vec(), b"changed".to_vec());
        let owners = JournalTransaction::new([1; 16], vec![owner.clone()]).unwrap();
        let puts = BTreeMap::from([
            (b"owner".to_vec(), b"changed".to_vec()),
            (b"sidecar".to_vec(), b"generated".to_vec()),
        ]);

        assert!(require_exact_owner_puts(&owners, &puts, Some((b"sidecar", b"generated"))).is_ok());
        let redundant = JournalRecord::put(namespace, b"unchanged".to_vec(), b"same".to_vec());
        let extra = JournalTransaction::new([1; 16], vec![owner.clone(), redundant]).unwrap();
        assert!(require_exact_owner_puts(&extra, &puts, Some((b"sidecar", b"generated"))).is_err());

        let duplicate = JournalTransaction::new([1; 16], vec![owner.clone(), owner]).unwrap();
        let duplicate_puts = BTreeMap::from([(b"owner".to_vec(), b"changed".to_vec())]);
        assert!(require_exact_owner_puts(&duplicate, &duplicate_puts, None).is_err());
    }

    #[test]
    fn continuation_owner_puts_require_exact_namespace_and_put_value() {
        let puts = BTreeMap::from([(b"owner".to_vec(), b"changed".to_vec())]);
        let foreign = JournalTransaction::new(
            [1; 16],
            vec![JournalRecord::put(
                RecordNamespace::GlobalCapacityReservation,
                b"owner".to_vec(),
                b"changed".to_vec(),
            )],
        )
        .unwrap();
        assert!(require_exact_owner_puts(&foreign, &puts, None).is_err());

        let delete = JournalTransaction::new(
            [1; 16],
            vec![JournalRecord::delete(
                RecordNamespace::MountSourceAcquisition,
                b"owner".to_vec(),
            )],
        )
        .unwrap();
        assert!(require_exact_owner_puts(&delete, &puts, None).is_err());
    }
}
