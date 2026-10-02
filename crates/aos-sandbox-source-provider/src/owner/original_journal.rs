//! Same-owned Source prefix authentication and resident original append custody.
//!
//! The fixed ledger and challenge owners remain held in that order. Archived
//! durable A, captured role pins and genuinely current B authenticate the same
//! actual cuts; no archived image enters Ready or restores an original flight.
//! The private producer child uses this sole archive/prepare/readback bridge
//! for Applying, Requested, ChallengeIssued and the conditional StoragePrepared
//! readback. No SourceRoot handoff, Complete, relay or settlement is enabled.

use std::collections::BTreeMap;
use std::sync::Arc;

use aos_sandbox::{JournalTransaction, RecordNamespace};
use aos_sandbox::journal::{
    OriginalSourceProtectedReadbackV5, PreparedOriginalSourceAppendV5,
    SourceCapacityStateV5, SourceOriginalAdmissionDataV5, SourceOriginalChallengeHistoryViewV5,
    SourceOriginalNativeJournalAuthorityV5, SourceOriginalPhysicalCutV5, SourceOriginalReplayViewV5,
    SourceOriginalAppendSubjectV5,
};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    RecoveryCurrentnessQueryV1, VerifiedProviderRequestV1, VerifiedProviderRequestSequenceV1,
    SignedSourceProviderRequestV1,
    SourceProviderSigningKeyV1, StorageNativeAcquireReplyV3,
    native_held_completion::{
        NativeHeldControlKindV1 as Kind, NativeHeldOwnerV1 as Role,
        NativeHeldSectionTagV1 as Tag,
        frame::{NativeHeldSignerV1, PreparedNativeHeldControlV1, SignedNativeHeldControlV1},
        recovery::{NativeHeldRecoveryQueryV1, ProviderNativeRecoveryStateV1,
            RootNativeRecoveryAssertionV1, StorageNativeRecoveryStateV1, NativeHeldRecoveryModeV1},
        assertion::NativeHeldSettlementV1,
    },
};
use aos_sandbox_source_provider_security::{
    CurrentProviderOriginalCarrierPacketV1, CurrentProviderRequestV1, CurrentRootPreparedCarrierV1,
    ProtectedOriginalConfigurationArchiveV5, ProtectedOriginalCutReferenceV5,
    ProtectedOriginalDeploymentV5, ProtectedOriginalOriginV5, RevalidatedProviderConfigurationV1,
};
use aos_sandbox_source_provider_ledger::ledger::{
    native_completion::SourcePreRequestedColdArchiveV1,
    native_held_completion::SourceNativeHeldCompletionRecordV1,
    source_capacity::SourceCapacityOwnerEdgeKindV5,
};

use super::{FixedProviderOwnerStateV1, FixedProviderOwnerV1};
use crate::{ProviderLedgerError, ProviderLedgerLimits};
use crate::state::ProtectedProviderConfigurationV1;
use crate::recovery::original_source_capacity::authenticate_archived_complete_cut_v5;
use crate::zfs_hold_verifier::ProtectedStorageZfsHoldVerifierV1;

pub(super) mod producer;
mod selected_execution;
mod selected_archive;
mod storage_offer;
mod completion;
use producer::{OriginalProducerAppendV5, OriginalSourceProducerV5};

#[derive(Default)]
pub(super) struct OriginalJournalV5 {
    history: OriginalJournalHistoryV5,
    producer: Option<OriginalSourceProducerV5>,
}

#[derive(Default)]
struct OriginalJournalHistoryV5 {
    archive: Option<ProtectedOriginalConfigurationArchiveV5>,
    storage: Option<ProtectedStorageZfsHoldVerifierV1>,
    current_capture: Option<RevalidatedProviderConfigurationV1>,
    current: Option<ProtectedProviderConfigurationV1>,
    durable: Option<Arc<ProtectedOriginalDeploymentV5>>,
    references: Vec<ProtectedOriginalCutReferenceV5>,
    origins: BTreeMap<ObjectDigest, ProtectedOriginalOriginV5>,
    controls: ControlContextsV5,
    admissions: BTreeMap<ObjectDigest, ([u8; 16], u64)>,
    configurations: BTreeMap<ObjectDigest, Arc<ProtectedProviderConfigurationV1>>,
    projection_bytes: usize,
    // Only a genuinely parked idle Ready owner may create a CURRENT baseline.
    // Once a real Applying cut is read back, ordinary retained replay takes over.
    baseline_pending: bool,
    recovered_execution_death:
        Option<aos_sandbox_source_provider_security::DeadProviderExecutionV1>,
    failed: bool,
}

impl OriginalJournalHistoryV5 {
    fn fail_pending_baseline(&mut self) -> bool {
        if self.baseline_pending {
            self.failed = true;
        }
        self.baseline_pending
    }

    fn complete_baseline(&mut self) {
        self.baseline_pending = false;
    }
}

#[derive(Clone)]
struct ControlOriginV5 {
    eligibility: Arc<ProtectedOriginalDeploymentV5>,
    archived_configuration: Arc<ProtectedProviderConfigurationV1>,
    seconds: i64,
    session: ObjectDigest,
    query: Arc<[u8]>,
    physical: ([u8; 16], u64),
    challenge: ((u64, u64), u64, ObjectDigest),
    root_pin: Option<SourceProviderSigningKeyV1>,
    provider_pin: Option<SourceProviderSigningKeyV1>,
    native_kind: Option<Kind>,
    original_root_control: ObjectDigest,
}

#[derive(Clone, Default)]
struct ControlContextsV5 {
    frames: BTreeMap<ObjectDigest, ControlOriginV5>,
    originals: BTreeMap<ObjectDigest, ControlOriginV5>,
}

impl ControlContextsV5 {
    fn clear(&mut self) {
        self.frames.clear();
        self.originals.clear();
    }

    fn len(&self) -> usize {
        self.frames.len().saturating_add(self.originals.len())
    }

    fn get(&self, digest: &ObjectDigest) -> Option<&ControlOriginV5> {
        self.frames.get(digest)
    }

    fn contains_key(&self, digest: &ObjectDigest) -> bool {
        self.frames.contains_key(digest)
    }

    fn insert(&mut self, digest: ObjectDigest, context: ControlOriginV5) {
        self.frames.insert(digest, context);
    }
}

/// Retains an actually received packet before decoding or currentness checks.
pub(super) struct ObservedOriginalQueryV5 {
    packet: CurrentProviderOriginalCarrierPacketV1,
    session: Option<ObjectDigest>,
    failed: bool,
}

impl ObservedOriginalQueryV5 {
    fn bytes(&self) -> Result<&[u8], ProviderLedgerError> {
        match &self.packet {
            CurrentProviderOriginalCarrierPacketV1::Source(packet) => Ok(packet),
            _ => Err(ProviderLedgerError::Equivocation),
        }
    }
}

/// Keeps the original genuine pair and actual observed query caller-owned.
pub(super) struct OriginalSourceControlInputsV5 {
    root: Option<CurrentRootPreparedCarrierV1>,
    acquire: Option<CurrentProviderRequestV1>,
    query: Option<ObservedOriginalQueryV5>,
}

impl OriginalSourceControlInputsV5 {
    pub(super) fn retain(
        root: Option<CurrentRootPreparedCarrierV1>,
        acquire: Option<CurrentProviderRequestV1>,
        query: Option<ObservedOriginalQueryV5>,
    ) -> Self {
        Self { root, acquire, query }
    }
}

/// Parks every input/candidate/readback before fallible Source/Sandbox crossings.
pub(super) struct PreparedSourceOriginalV5 {
    owners: Option<JournalTransaction>,
    controls: Option<OriginalSourceControlInputsV5>,
    sandbox: Option<PreparedOriginalSourceAppendV5>,
    readback: Option<OriginalSourceProtectedReadbackV5>,
    reference: Option<ProtectedOriginalCutReferenceV5>,
    origin: Option<ProtectedOriginalOriginV5>,
    eligibility: Option<Arc<ProtectedOriginalDeploymentV5>>,
    durable: Option<Arc<ProtectedOriginalDeploymentV5>>,
    session: Option<ObjectDigest>,
    failed: bool,
    attempted: bool,
}

impl PreparedSourceOriginalV5 {
    fn park(
        owners: &mut Option<JournalTransaction>,
        controls: &mut Option<OriginalSourceControlInputsV5>,
        slot: &mut Option<Self>,
    ) -> Result<(), ProviderLedgerError> {
        if let Some(retained) = slot {
            retained.failed = true;
            return Err(ProviderLedgerError::InvalidTransition("original Source slot occupied"));
        }
        let input = owners.take().ok_or(ProviderLedgerError::Unavailable)?;
        *slot = Some(Self {
            owners: Some(input), controls: controls.take(), sandbox: None, readback: None,
            reference: None, origin: None, eligibility: None, durable: None,
            session: None, failed: false, attempted: false,
        });
        Ok(())
    }
}

// This guard borrows the actual owner throughout a Source crossing. Failure or
// unwind closes only its genuinely pending first birth, using the existing
// ingress/runtime closure; successful historical paths remain untouched.
struct FirstBirthClosureGuardV5<'owner> {
    owner: &'owner mut FixedProviderOwnerV1,
    completed: bool,
}

impl<'owner> FirstBirthClosureGuardV5<'owner> {
    fn new(owner: &'owner mut FixedProviderOwnerV1) -> Self {
        Self {
            owner,
            completed: false,
        }
    }

    fn complete_checks(&mut self) {
        self.completed = true;
    }

    fn complete_commit(&mut self) {
        // No fallible operation separates the final checks from publication.
        // Observation/prepare/preflight never clear this first-birth identity.
        if let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.owner.state.as_mut() {
            if let Some(original) = held.original.as_mut() {
                original.history.complete_baseline();
            }
        }
        self.complete_checks();
    }
}

impl Drop for FirstBirthClosureGuardV5<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.close_failed_first_birth_v5();
        }
    }
}

impl FixedProviderOwnerV1 {
    fn park_first_original_runtime_v5(&mut self) {
        if self.original_runtime.is_none()
            && matches!(self.state, Some(FixedProviderOwnerStateV1::Ready(_)))
        {
            match self.state.take() {
                Some(FixedProviderOwnerStateV1::Ready(runtime)) => {
                    self.original_runtime = Some(runtime);
                }
                other => self.state = other,
            }
        }
    }

    fn retain_first_original_runtime_v5(&mut self) -> Result<(), ProviderLedgerError> {
        if matches!(self.state, Some(FixedProviderOwnerStateV1::HeldReadOnly(_))) {
            return Ok(());
        }

        // Parking precedes even idle/pair/currentness checks. A failed conversion
        // leaves the full runtime here, never reinstalls its usable Ready state.
        self.park_first_original_runtime_v5();
        if self.state.is_some() {
            return Err(ProviderLedgerError::Unavailable);
        }

        let runtime = self.original_runtime.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?;
        runtime.original_ingress_is_idle()?;
        self.original_ingress.borrowed_pair_v5()?;
        if self.recovery_handshake.is_some()
            || self.ingress_reopen.is_some()
            || !self.pending_backend_recovery.is_empty()
            || self.priority_mount_retry_digest.is_some()
            || self.priority_mount_retry_rearm_digest.is_some()
            || self.pending_catalog_currentness.is_some()
            || self.pending_recovery_query_digest.is_some()
            || self.pending_inventory_readback_digest.is_some()
        {
            return Err(ProviderLedgerError::Unavailable);
        }

        let saved_publication = runtime.original_catalog_publication_v5();
        if saved_publication.len() != super::CANONICAL_CATALOG_PUBLICATION_BYTES {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        let publication = saved_publication.to_vec();
        let authority = super::claim_fixed_provider_authority(self.journal.as_mut())?;
        let (configuration, recovered, session) = runtime.original_ingress_parts()?;
        let current = super::configured_ledger(session, &publication)?;
        let projection = session.current_projection()?;
        self.original_ingress.require_borrowed_cut_v5(
            &authority, current.deployment_digest(), projection.session_binding(),
        )?;
        if current.deployment_digest() != configuration.deployment_digest()
            || !current.matches_authority_and_catalog(&recovered.authority, &recovered.catalog)
        {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        crate::recovery::recover(&authority, &current)?;

        // No fallible operation separates the move from its new owning slot.
        let (session, recovered_execution_death) = runtime.take_fixed_current_session()?;
        self.state = Some(FixedProviderOwnerStateV1::HeldReadOnly(Box::new(
            super::held_readonly::HeldReadOnlyV1::retain_original_v5(
                session,
                publication,
                OriginalJournalV5 {
                    history: OriginalJournalHistoryV5 {
                        baseline_pending: true,
                        recovered_execution_death,
                        ..OriginalJournalHistoryV5::default()
                    },
                    ..OriginalJournalV5::default()
                },
            ),
        )));
        Ok(())
    }

    fn close_failed_first_birth_v5(&mut self) {
        let pending = match self.state.as_mut() {
            Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) => {
                if let Some(original) = held.original.as_mut() {
                    original.history.fail_pending_baseline()
                } else {
                    false
                }
            }
            None => self.original_runtime.is_some(),
            _ => false,
        };
        if pending {
            self.original_ingress.close_original_writer_v5();
            if let Some(runtime) = self.original_runtime.as_mut() {
                runtime.poison_runtime();
            }
        }
    }

    pub(super) fn observe_original_journal_v5(
        &mut self,
    ) -> Result<super::held_readonly::FixedProviderHeldReadOnlyObservationV1, ProviderLedgerError> {
        let mut guard = FirstBirthClosureGuardV5::new(self);
        let checked = guard.owner.observe_original_journal_inner_v5();

        if checked.is_ok() {
            guard.complete_checks();
        }
        checked
    }

    fn observe_original_journal_inner_v5(
        &mut self,
    ) -> Result<super::held_readonly::FixedProviderHeldReadOnlyObservationV1, ProviderLedgerError> {
        let backend = Arc::clone(&self.backend_verifier);
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::InvalidTransition("original Source owner is not held"));
        };
        let original = &mut held.original.get_or_insert_with(OriginalJournalV5::default).history;
        if original.failed {
            return Err(ProviderLedgerError::RuntimePoisoned);
        }
        if original.archive.is_none() {
            original.archive = Some(ProtectedOriginalConfigurationArchiveV5::open_fixed()?);
        }
        if original.storage.is_none() {
            original.storage = Some(ProtectedStorageZfsHoldVerifierV1::load(backend)?);
        }
        refresh_current(original, &mut held.session, &held.publication)?;

        if original.baseline_pending {
            let projection = held.session.current_projection()?;
            let legacy = super::claim_fixed_provider_authority(self.journal.as_mut())?;
            self.original_ingress.require_borrowed_cut_v5(
                &legacy,
                original.current.as_ref().ok_or(ProviderLedgerError::Unavailable)?.deployment_digest(),
                projection.session_binding(),
            )?;
        }

        let challenges = self.hold_challenges.original_history_v5()?;
        let journal = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?;
        journal.complete_source_original_replay_v5(&challenges)?;
        let authority = journal.claim_source_original_native_v5(&challenges)?;
        let replay = authority.replayed_origins()?;
        authenticate_current_prefix(
            original, &replay, &challenges, authority.configured_limits(),
            &held.publication, &self.backend_verifier,
        )?;

        refresh_current(original, &mut held.session, &held.publication)?;
        authenticate_current_prefix(
            original, &authority.replayed_origins()?, &challenges, authority.configured_limits(),
            &held.publication, &self.backend_verifier,
        )?;
        let rows = replay.current_rows();
        Ok(super::held_readonly::FixedProviderHeldReadOnlyObservationV1 {
            owner_records: rows.keys().filter(|(namespace, _)| *namespace == RecordNamespace::SourceProviderAuthority).count(),
            held_completions: rows.values().filter(|value| value.get(8..10) == Some(&8_u16.to_be_bytes())).count(),
            capacity_floors: rows.keys().filter(|(namespace, _)| *namespace == RecordNamespace::GlobalCapacityReservation).count(),
        })
    }

    /// Retains actual zero-FD reception without making it a public native ingress.
    pub(super) fn receive_original_journal_query_v5(
        &mut self,
        slot: &mut Option<ObservedOriginalQueryV5>,
    ) -> Result<bool, ProviderLedgerError> {
        if let Some(retained) = slot {
            retained.failed = true;
            return Err(ProviderLedgerError::InvalidTransition("original query slot occupied"));
        }
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable);
        };
        let Some(packet) = held.session.receive_current_original_packet_v1()? else {
            return Ok(false);
        };
        *slot = Some(ObservedOriginalQueryV5 { packet, session: None, failed: false });
        let retained = slot.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?;
        let checked = (|| {
            let projection = held.session.current_projection()?;
            let bytes = retained.bytes()?;
            if bytes.starts_with(b"AOSSPR01") {
                let query = RecoveryCurrentnessQueryV1::from_canonical_bytes(bytes)
                    .map_err(|_| ProviderLedgerError::Equivocation)?;
                if query.session_binding() != projection.session_binding()
                    || query.authorities() != (projection.provider().authority_id(), projection.holder().authority_id())
                {
                    return Err(ProviderLedgerError::Equivocation);
                }
            } else {
                let control = SignedNativeHeldControlV1::from_canonical_bytes(bytes)
                    .map_err(|_| ProviderLedgerError::Equivocation)?;
                if control.kind() != Kind::RootRecoveryQuery {
                    return Err(ProviderLedgerError::Equivocation);
                }
            }
            retained.session = Some(projection.session_binding());
            held.session.current_projection()?;
            Ok::<_, ProviderLedgerError>(())
        })();
        if checked.is_err() {
            retained.failed = true;
        }
        checked.map(|()| true)
    }

    /// Prepares the already resident append without moving its original custody.
    pub(super) fn prepare_original_journal_append_v5(
        &mut self,
        step: OriginalProducerAppendV5,
    ) -> Result<(), ProviderLedgerError> {
        let mut guard = FirstBirthClosureGuardV5::new(self);
        let result = guard.owner.prepare_original_journal_inner_v5(step);

        if result.is_err() {
            if let Ok(retained) = guard.owner.retained_original_append_mut_v5(step) {
                retained.failed = true;
            }
        } else {
            guard.complete_checks();
        }
        result
    }

    fn retained_original_append_mut_v5(
        &mut self,
        step: OriginalProducerAppendV5,
    ) -> Result<&mut PreparedSourceOriginalV5, ProviderLedgerError> {
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable);
        };
        held.original.as_mut().and_then(|original| original.producer.as_mut())
            .ok_or(ProviderLedgerError::Unavailable)?.append_mut(step)
    }

    fn prepare_original_journal_inner_v5(
        &mut self,
        step: OriginalProducerAppendV5,
    ) -> Result<(), ProviderLedgerError> {
        let held_expiry = if step.is_original_held() { Some(self.original_held_expiry_v5()?) } else { None };
        self.retain_first_original_runtime_v5()?;
        self.observe_original_journal_v5()?;
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable);
        };
        let original = held.original.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?;
        let history = &mut original.history;
        let retained = original.producer.as_mut().ok_or(ProviderLedgerError::Unavailable)?
            .append_mut(step)?;
        let projection = held.session.current_projection()?;
        retained.session = Some(projection.session_binding());
        let challenges = self.hold_challenges.original_history_v5()?;
        let authority = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?
            .claim_source_original_native_v5(&challenges)?;
        if let Some(expiry) = held_expiry {
            self.original_ingress.borrowed_clock_v5()?.revalidate(Some(expiry))?;
        }
        authority.prepare(&mut retained.owners, &mut retained.sandbox)?;
        let prepared = retained.sandbox.as_ref().ok_or(ProviderLedgerError::RuntimePoisoned)?;
        let comparison = prepared.comparison().ok_or(ProviderLedgerError::Unavailable)?;
        if history.baseline_pending
            && !comparison.owner_edge().is_some_and(|edge| edge.kind() == SourceCapacityOwnerEdgeKindV5::Applying)
        {
            return Err(ProviderLedgerError::InvalidTransition("first original cut is not Applying"));
        }

        let durable = Arc::clone(history.durable.as_ref().ok_or(ProviderLedgerError::Unavailable)?);
        retained.durable = Some(Arc::clone(&durable));
        let archive = history.archive.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?;
        let capture = history.current_capture.as_ref().ok_or(ProviderLedgerError::RuntimePoisoned)?;
        let catalog = aos_sandbox_source_provider_security::verify_catalog_publication(capture, &held.publication)?;
        let current = history.current.as_ref().ok_or(ProviderLedgerError::RuntimePoisoned)?;
        if let Some(expiry) = held_expiry {
            self.original_ingress.borrowed_clock_v5()?.revalidate(Some(expiry))?;
        }
        let eligibility = archive.capture_deployment(
            capture,
            &catalog,
            current.deployment_digest(),
            ProviderLedgerLimits::default().deployment_digest(),
        )?;
        retained.eligibility = Some(Arc::clone(&eligibility));
        let subject = authority.archive_subject(prepared.transaction())?;
        let seconds = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
        if seconds <= 0 {
            return Err(ProviderLedgerError::Unavailable);
        }

        if comparison.owner_edge().is_some_and(|edge| edge.kind() == SourceCapacityOwnerEdgeKindV5::Applying) {
            let admission = prepared.prospective_origins().ok_or(ProviderLedgerError::Unavailable)?
                .iter().find(|origin| origin.applying_transaction().id() == prepared.transaction().id())
                .ok_or(ProviderLedgerError::Equivocation)?;
            let pair = original_pair_inputs(
                history.baseline_pending, &self.original_ingress, retained.controls.as_ref(),
            )?;
            require_original_pair(
                &mut held.session, pair.0, pair.1, admission, comparison.before(), &durable, current,
            )?;
            let storage = history.storage.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
            retained.origin = Some(archive.install_origin(
                &durable, admission, subject.transaction().1, storage.original_enrollment_v5()?,
            )?);
        }

        let query = observed_query_bytes(retained.controls.as_ref(), projection.session_binding())?;
        if let Some(expiry) = held_expiry {
            self.original_ingress.borrowed_clock_v5()?.revalidate(Some(expiry))?;
        }
        retained.reference = Some(archive.install_cut(
            &subject, &durable, &durable, retained.origin.as_ref(), &eligibility,
            seconds, &challenges, &projection, query,
        )?);

        authenticate_candidate(
            history,
            prepared,
            retained.reference.as_ref().ok_or(ProviderLedgerError::Unavailable)?,
            retained.eligibility.as_ref().ok_or(ProviderLedgerError::Unavailable)?,
            &subject,
            &challenges,
            authority.configured_limits(),
            &self.backend_verifier,
        )?;
        held.session.current_projection()?;
        if let Some(expiry) = held_expiry {
            self.original_ingress.borrowed_clock_v5()?.revalidate(Some(expiry))?;
        }
        Ok(())
    }

    /// Rechecks Source and Sandbox while the original append remains resident.
    pub(super) fn preflight_original_journal_append_v5(
        &mut self,
        step: OriginalProducerAppendV5,
    ) -> Result<(), ProviderLedgerError> {
        let mut guard = FirstBirthClosureGuardV5::new(self);
        let checked = guard.owner.preflight_original_journal_inner_v5(step);

        if checked.is_err() {
            if let Ok(retained) = guard.owner.retained_original_append_mut_v5(step) {
                retained.failed = true;
            }
        } else {
            guard.complete_checks();
        }
        checked
    }

    fn preflight_original_journal_inner_v5(
        &mut self,
        step: OriginalProducerAppendV5,
    ) -> Result<(), ProviderLedgerError> {
        let held_expiry = if step.is_original_held() { Some(self.original_held_expiry_v5()?) } else { None };
        let retained = self.retained_original_append_mut_v5(step)?;
        if retained.failed || retained.attempted {
            return Err(ProviderLedgerError::RuntimePoisoned);
        }
        self.observe_original_journal_v5()?;
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable);
        };
        let original = held.original.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let history = &mut original.history;
        let retained = original.producer.as_mut().ok_or(ProviderLedgerError::Unavailable)?
            .append_mut(step)?;
        let projection = held.session.current_projection()?;
        if retained.session != Some(projection.session_binding()) {
            return Err(ProviderLedgerError::Equivocation);
        }
        let challenges = self.hold_challenges.original_history_v5()?;
        let authority = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?
            .claim_source_original_native_v5(&challenges)?;
        let prepared = retained.sandbox.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let reference = retained.reference.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        history.archive.as_ref().ok_or(ProviderLedgerError::Unavailable)?
            .validate_references(reference, retained.origin.as_ref())?;
        let applying = prepared.prospective_origins().and_then(|origins| {
            origins.iter().find(|origin| origin.applying_transaction().id() == prepared.transaction().id())
        });
        if let Some(origin) = applying {
            let pair = original_pair_inputs(
                history.baseline_pending, &self.original_ingress, retained.controls.as_ref(),
            )?;
            require_original_pair(
                &mut held.session, pair.0, pair.1, origin,
                prepared.comparison().ok_or(ProviderLedgerError::Unavailable)?.before(),
                retained.durable.as_ref().ok_or(ProviderLedgerError::Unavailable)?,
                history.current.as_ref().ok_or(ProviderLedgerError::Unavailable)?,
            )?;
        }

        let subject = authority.archive_subject(prepared.transaction())?;
        authenticate_candidate(
            history,
            prepared,
            reference,
            retained.eligibility.as_ref().ok_or(ProviderLedgerError::Unavailable)?,
            &subject,
            &challenges,
            authority.configured_limits(),
            &self.backend_verifier,
        )?;
        if let Some(expiry) = held_expiry {
            self.original_ingress.borrowed_clock_v5()?.revalidate(Some(expiry))?;
        }
        authority.preflight(prepared)?;
        held.session.current_projection()?;
        if let Some(expiry) = held_expiry {
            self.original_ingress.borrowed_clock_v5()?.revalidate(Some(expiry))?;
        }
        Ok(())
    }

    /// Attempts one resident append and keeps actual readback before postchecks.
    pub(super) fn commit_original_journal_append_v5(
        &mut self,
        step: OriginalProducerAppendV5,
    ) -> Result<(), ProviderLedgerError> {
        let mut guard = FirstBirthClosureGuardV5::new(self);
        let checked = guard.owner.commit_original_journal_inner_v5(step);

        if checked.is_err() {
            if let Ok(retained) = guard.owner.retained_original_append_mut_v5(step) {
                retained.failed = true;
            }
        } else {
            guard.complete_commit();
        }
        checked
    }

    fn commit_original_journal_inner_v5(
        &mut self,
        step: OriginalProducerAppendV5,
    ) -> Result<(), ProviderLedgerError> {
        let held_expiry = if step.is_original_held() { Some(self.original_held_expiry_v5()?) } else { None };
        self.preflight_original_journal_append_v5(step)?;
        self.retained_original_append_mut_v5(step)?.attempted = true;
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable);
        };
        let challenges = self.hold_challenges.original_history_v5()?;
        let mut authority = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?
            .claim_source_original_native_v5(&challenges)?;
        let appended = (|| {
            let original = held.original.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
            let retained = original.producer.as_mut().ok_or(ProviderLedgerError::Unavailable)?
                .append_mut(step)?;
            if let Some(expiry) = held_expiry {
                self.original_ingress.borrowed_clock_v5()?.revalidate(Some(expiry))?;
            }
            authority.commit_prepared(
                retained.sandbox.as_mut().ok_or(ProviderLedgerError::Unavailable)?,
                &mut retained.readback,
            )?;
            authority.validate_readback(
                retained.readback.as_ref().ok_or(ProviderLedgerError::Unavailable)?,
            )?;

            let history = &mut original.history;
            refresh_current(history, &mut held.session, &held.publication)?;
            authenticate_replay(
                history, &authority.replayed_origins()?, &challenges, authority.configured_limits(),
                &self.backend_verifier,
            )?;
            history.archive.as_ref().ok_or(ProviderLedgerError::Unavailable)?.validate_references(
                retained.reference.as_ref().ok_or(ProviderLedgerError::Unavailable)?,
                retained.origin.as_ref(),
            )?;
            held.session.current_projection()?;
            if let Some(expiry) = held_expiry {
                self.original_ingress.borrowed_clock_v5()?.revalidate(Some(expiry))?;
            }
            Ok(())
        })();
        if appended.is_err() {
            authority.poison_after_owner_failure();
            if let Some(original) = held.original.as_mut() {
                original.history.failed = true;
            }
        }
        appended
    }
}

fn refresh_current(
    original: &mut OriginalJournalHistoryV5,
    session: &mut aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1,
    publication: &[u8],
) -> Result<(), ProviderLedgerError> {
    session.current_projection()?;
    original.current_capture = Some(session.revalidated_provider_configuration()?);
    let capture = original.current_capture.as_ref().ok_or(ProviderLedgerError::RuntimePoisoned)?;
    let catalog = aos_sandbox_source_provider_security::verify_catalog_publication(capture, publication)?;
    original.current = Some(ProtectedProviderConfigurationV1::from_current_capture_v5(capture, &catalog)?);
    session.current_projection()?;
    Ok(())
}

fn observed_query_bytes(
    controls: Option<&OriginalSourceControlInputsV5>,
    session: ObjectDigest,
) -> Result<&[u8], ProviderLedgerError> {
    let Some(query) = controls.and_then(|controls| controls.query.as_ref()) else {
        return Ok(&[]);
    };
    if query.failed || query.session != Some(session) {
        return Err(ProviderLedgerError::Equivocation);
    }
    query.bytes()
}

fn original_pair_inputs<'input>(
    baseline_pending: bool,
    ingress: &'input super::original_ingress::OriginalIngressV1,
    inputs: Option<&'input OriginalSourceControlInputsV5>,
) -> Result<(&'input CurrentRootPreparedCarrierV1, &'input CurrentProviderRequestV1), ProviderLedgerError> {
    if baseline_pending {
        return ingress.borrowed_pair_v5();
    }

    let inputs = inputs.ok_or(ProviderLedgerError::Unavailable)?;
    Ok((
        inputs.root.as_ref().ok_or(ProviderLedgerError::Unavailable)?,
        inputs.acquire.as_ref().ok_or(ProviderLedgerError::Unavailable)?,
    ))
}

fn require_original_pair(
    session: &mut aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1,
    root: &CurrentRootPreparedCarrierV1,
    acquire: &CurrentProviderRequestV1,
    admission: &SourceOriginalAdmissionDataV5,
    before: &SourceCapacityStateV5,
    durable: &ProtectedOriginalDeploymentV5,
    current: &ProtectedProviderConfigurationV1,
) -> Result<(), ProviderLedgerError> {
    session.revalidate_root_prepared_carrier_v1(root)?;
    let projection = session.current_projection()?;
    let VerifiedProviderRequestV1::Acquire(verified) = acquire.verified() else {
        return Err(ProviderLedgerError::Equivocation);
    };
    let expected = admission.admission_comparison().original();
    if root.control() != &admission.initial_floor().original_provenance().claims().root_prepared
        || verified.attempt().signed_request_digest() != expected.root_request_digest
        || verified.request().acquisition_id() != expected.acquisition_id
        || verified.ingress_projection().session_binding() != projection.session_binding()
        || verified.ingress_projection().provider_process_instance() != projection.provider_process_instance()
        || verified.ingress_projection().root_mount_process_instance() != projection.root_process_instance()
        || expected.session_binding != projection.session_binding()
    {
        return Err(ProviderLedgerError::Equivocation);
    }
    session.revalidate_root_prepared_carrier_v1(root)?;
    let recovered = authenticate_archived_complete_cut_v5(before, durable, current)?;
    let signed = SignedSourceProviderRequestV1::from_canonical_bytes(
        verified.attempt().canonical_signed_request(),
    ).map_err(|_| ProviderLedgerError::Equivocation)?;
    let expectation = crate::transaction::request_sequence_expectation_from_recovered_v5(
        &recovered, &signed,
    )?;
    // Requests carry zero descriptors. This refreshes actual deadline, execution,
    // trust and sequence checks without consuming the caller-retained original.
    let refreshed = session.verify_current_request(&signed, expectation, &[])?;
    let VerifiedProviderRequestV1::Acquire(refreshed) = refreshed.verified() else {
        return Err(ProviderLedgerError::Equivocation);
    };
    if !matches!(refreshed.sequence(), VerifiedProviderRequestSequenceV1::Fresh(_))
        || refreshed.request() != verified.request()
        || refreshed.attempt().signed_request_digest() != expected.root_request_digest
    {
        return Err(ProviderLedgerError::Equivocation);
    }
    Ok(())
}

fn authenticate_current_prefix(
    original: &mut OriginalJournalHistoryV5,
    replay: &SourceOriginalReplayViewV5<'_>,
    challenges: &SourceOriginalChallengeHistoryViewV5<'_>,
    limits: aos_sandbox::JournalLimits,
    publication: &[u8],
    backend: &crate::backend_verifier::ProtectedBackendVerifierV1,
) -> Result<(), ProviderLedgerError> {
    if !original.baseline_pending {
        return authenticate_replay(original, replay, challenges, limits, backend);
    }

    // This exception is a current preappend baseline, not recovery of missing
    // old cuts. Complete union validation has already refused orphan own debt.
    if !replay.cuts().is_empty()
        || !replay.origins().is_empty()
        || !original.references.is_empty()
        || !original.origins.is_empty()
    {
        return Err(ProviderLedgerError::Equivocation);
    }
    let current = original.current.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
    let archive = original.archive.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
    if original.durable.is_none() {
        let capture = original.current_capture.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let catalog = aos_sandbox_source_provider_security::verify_catalog_publication(capture, publication)?;
        original.durable = Some(archive.capture_deployment(
            capture, &catalog, current.deployment_digest(), ProviderLedgerLimits::default().deployment_digest(),
        )?);
    }
    let durable = original.durable.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
    authenticate_archived_complete_cut_v5(replay.current_rows(), durable, current)?;
    archive.revalidate()?;
    original.storage.as_ref().ok_or(ProviderLedgerError::Unavailable)?.revalidate()?;
    challenges.validate_current()?;
    Ok(())
}

fn authenticate_replay(
    original: &mut OriginalJournalHistoryV5,
    replay: &SourceOriginalReplayViewV5<'_>,
    challenges: &SourceOriginalChallengeHistoryViewV5<'_>,
    limits: aos_sandbox::JournalLimits,
    backend: &crate::backend_verifier::ProtectedBackendVerifierV1,
) -> Result<(), ProviderLedgerError> {
    if original.references.len() > replay.cuts().len() {
        return Err(ProviderLedgerError::Equivocation);
    }
    original.controls.clear();
    original.admissions.clear();
    let current = original.current.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
    let storage = original.storage.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
    let archive = original.archive.as_mut().ok_or(ProviderLedgerError::Unavailable)?;

    for (index, cut) in replay.cuts().iter().enumerate() {
        if original.references.len() == index {
            original.references.push(archive.read_cut(cut)?);
        }
        let reference = &original.references[index];
        archive.require_physical_cut(reference, cut)?;
        require_challenge_cut(reference, cut.challenge_checkpoint(), challenges)?;
        let (before_ids, after_ids) = reference.deployments();
        let before = archive.read_deployment(before_ids.0)?;
        let after = archive.read_deployment(after_ids.0)?;
        if before.identities() != before_ids || after.identities() != after_ids {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        let context = cut_context(archive, &mut original.configurations, &mut original.projection_bytes,
            reference, (*cut.transaction_id(), cut.frame_sequences().1), limits)?;

        let applying = replay.origins().iter().find(|origin| {
            origin.applying_transaction().id() == cut.transaction_id()
        });
        match (applying, reference.origin_identity()) {
            (Some(admission), Some(identity)) => {
                let acquisition = admission.admission_comparison().original().acquisition_id;
                if !original.origins.contains_key(&acquisition) {
                    original.origins.insert(acquisition, archive.read_origin(
                        identity, &after, admission, *cut.transaction_digest(),
                    )?);
                }
                let origin = original.origins.get(&acquisition).ok_or(ProviderLedgerError::Unavailable)?;
                if origin.identity() != identity {
                    return Err(ProviderLedgerError::Equivocation);
                }
                archive.validate_references(reference, Some(origin))?;
                storage.require_original_enrollment_v5(origin.storage_enrollment())?;
                original.admissions.insert(acquisition, (*cut.transaction_id(), cut.frame_sequences().1));
                register_original_context(&mut original.controls, acquisition,
                    &admission.initial_floor().original_provenance().claims().root_prepared,
                    &context, limits)?;
                register_control(&mut original.controls,
                    &admission.initial_floor().original_provenance().claims().root_prepared,
                    &context, limits)?;
                verify_control(&admission.initial_floor().original_provenance().claims().root_prepared,
                    &context, &mut original.controls, current, storage, limits, 0)?;
            }
            (None, None) => {}
            _ => return Err(ProviderLedgerError::Equivocation),
        }

        // The old reducer, exact durable head equality and ordinary signature
        // policy authenticate BOTH complete cuts under A plus current B.
        authenticate_archived_complete_cut_v5(cut.before_rows(), &before, current)?;
        authenticate_archived_complete_cut_v5(cut.after_rows(), &after, current)?;
        authenticate_native_rows(cut.after_rows(), &context, &mut original.controls,
            &original.admissions, current, storage, challenges, limits,
            &mut selected_archive::SelectedArchiveReplayV1 {
                archive: &mut *archive,
                admissions: replay.origins(),
                origins: &original.origins,
                backend,
            })?;
        original.durable = Some(after);
    }

    let durable = original.durable.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
    if replay.cuts().last().is_none_or(|cut| cut.after_rows() != replay.current_rows()) {
        return Err(ProviderLedgerError::Equivocation);
    }
    authenticate_archived_complete_cut_v5(replay.current_rows(), durable, current)?;
    archive.revalidate()?;
    storage.revalidate()?;
    challenges.validate_current()?;
    Ok(())
}

fn authenticate_candidate(
    original: &mut OriginalJournalHistoryV5,
    prepared: &PreparedOriginalSourceAppendV5,
    reference: &ProtectedOriginalCutReferenceV5,
    eligibility: &Arc<ProtectedOriginalDeploymentV5>,
    subject: &SourceOriginalAppendSubjectV5,
    challenges: &SourceOriginalChallengeHistoryViewV5<'_>,
    limits: aos_sandbox::JournalLimits,
    backend: &crate::backend_verifier::ProtectedBackendVerifierV1,
) -> Result<(), ProviderLedgerError> {
    let archive = original.archive.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
    archive.require_append_subject(reference, subject)?;
    require_challenge_cut(reference, prepared.challenge_checkpoint(), challenges)?;
    let comparison = prepared.comparison().ok_or(ProviderLedgerError::Unavailable)?;
    let durable = original.durable.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
    if reference.deployments() != (durable.identities(), durable.identities())
        || reference.eligibility_context().0 != eligibility.identities().0
    {
        return Err(ProviderLedgerError::ConfigurationMismatch);
    }
    let context = cut_context(archive, &mut original.configurations, &mut original.projection_bytes,
        reference, (subject.transaction().0, subject.frame_sequences().1), limits)?;
    let current = original.current.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
    let storage = original.storage.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
    authenticate_archived_complete_cut_v5(comparison.before(), durable, current)?;
    authenticate_archived_complete_cut_v5(comparison.after(), durable, current)?;

    // The temporary index shares archived images/query buffers; it never installs
    // a prospective carrier, origin or retirement into physical replay history.
    if original.controls.len() > limits.maximum_materialized_records {
        return Err(ProviderLedgerError::Unavailable);
    }
    let mut controls = original.controls.clone();
    let mut admissions = original.admissions.clone();
    let applying = prepared.prospective_origins().and_then(|origins| origins.iter().find(|origin| {
        origin.applying_transaction().id() == prepared.transaction().id()
    }));
    if let Some(admission) = applying {
        if reference.origin_identity().is_none() {
            return Err(ProviderLedgerError::Unavailable);
        }
        register_original_context(&mut controls,
            admission.admission_comparison().original().acquisition_id,
            &admission.initial_floor().original_provenance().claims().root_prepared,
            &context, limits)?;
        register_control(&mut controls, &admission.initial_floor().original_provenance().claims().root_prepared,
            &context, limits)?;
        verify_control(&admission.initial_floor().original_provenance().claims().root_prepared,
            &context, &mut controls, current, storage, limits, 0)?;
        admissions.insert(admission.admission_comparison().original().acquisition_id,
            (subject.transaction().0, subject.frame_sequences().1));
    } else if reference.origin_identity().is_some() {
        return Err(ProviderLedgerError::Equivocation);
    }
    authenticate_native_rows(comparison.after(), &context, &mut controls, &admissions,
        current, storage, challenges, limits,
        &mut selected_archive::SelectedArchiveReplayV1 {
            archive: &mut *archive,
            admissions: prepared.prospective_origins().unwrap_or(&[]),
            origins: &original.origins,
            backend,
        })?;
    archive.revalidate()?;
    challenges.validate_current()?;
    Ok(())
}

fn cut_context(
    archive: &mut ProtectedOriginalConfigurationArchiveV5,
    configurations: &mut BTreeMap<ObjectDigest, Arc<ProtectedProviderConfigurationV1>>,
    retained_projection_bytes: &mut usize,
    reference: &ProtectedOriginalCutReferenceV5,
    physical: ([u8; 16], u64),
    limits: aos_sandbox::JournalLimits,
) -> Result<ControlOriginV5, ProviderLedgerError> {
    let (identity, seconds) = reference.eligibility_context();
    let eligibility = archive.read_deployment(identity)?;
    let archived_configuration = match configurations.get(&identity) {
        Some(configuration) => Arc::clone(configuration),
        None => {
            // E deduplication precedes projection copies. This bounds actual
            // cloned key/history arrays plus fixed projection/publication DATA.
            let data = eligibility.public_projection();
            let additional = data.historical_public_keys().len()
                .checked_mul(std::mem::size_of::<aos_sandbox_source_provider_security::HistoricalProviderVerificationKeyV1>())
                .and_then(|bytes| data.trust_history().len()
                    .checked_mul(std::mem::size_of::<aos_sandbox_source_provider_security::ProtectedTrustHeadLinkV2>())
                    .and_then(|history| bytes.checked_add(history)))
                .and_then(|bytes| bytes.checked_add(eligibility.catalog().canonical_publication().len()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ProtectedProviderConfigurationV1>()))
                .ok_or(ProviderLedgerError::Unavailable)?;
            let next = retained_projection_bytes.checked_add(additional)
                .ok_or(ProviderLedgerError::Unavailable)?;
            if next > limits.maximum_materialized_bytes || configurations.len() >= limits.maximum_materialized_records {
                return Err(ProviderLedgerError::Unavailable);
            }
            let configuration = Arc::new(ProtectedProviderConfigurationV1::from_original_archive_v5(&eligibility)?);
            configurations.insert(identity, Arc::clone(&configuration));
            *retained_projection_bytes = next;
            configuration
        }
    };
    let (from, until) = eligibility.public_projection().validity();
    if seconds < from || seconds >= until {
        return Err(ProviderLedgerError::Unavailable);
    }
    Ok(ControlOriginV5 {
        eligibility, archived_configuration, seconds, session: reference.current_session(),
        query: Arc::from(reference.observed_query()), physical,
        challenge: reference.challenge_prefix(),
        root_pin: None, provider_pin: None, native_kind: None,
        original_root_control: ObjectDigest::from_bytes([0; 32]),
    })
}

fn require_challenge_cut(
    reference: &ProtectedOriginalCutReferenceV5,
    checkpoint: Option<usize>,
    challenges: &SourceOriginalChallengeHistoryViewV5<'_>,
) -> Result<(), ProviderLedgerError> {
    let (identity, sequence, digest) = reference.challenge_prefix();
    challenges.require_archived_prefix(identity, sequence, digest)?;
    if let Some(index) = checkpoint {
        let row = challenges.checkpoints()?.nth(index).ok_or(ProviderLedgerError::Equivocation)?;
        if row.frame_sequences().1 > sequence
            || challenges.checkpoints()?.any(|later| later.key() == row.key()
                && later.frame_sequences().1 <= sequence
                && later.frame_sequences().1 > row.frame_sequences().1)
        {
            return Err(ProviderLedgerError::Equivocation);
        }
    }
    Ok(())
}

fn context_key<'a>(
    current: &'a ProtectedProviderConfigurationV1,
    context: &ControlOriginV5,
    signer: &SourceProviderSigningKeyV1,
) -> Result<&'a [u8; 32], ProviderLedgerError> {
    let data = context.eligibility.public_projection();
    let (trust_generation, trust_digest) = data.trust_head();
    let (revocation_generation, revocation_digest) = data.revocation_head();
    let then = context.archived_configuration.historical_public_key_for(signer, context.seconds,
        trust_generation, trust_digest, revocation_generation, revocation_digest)
        .ok_or(ProviderLedgerError::Unavailable)?;
    let now = current.historical_public_key_for(signer, context.seconds,
        trust_generation, trust_digest, revocation_generation, revocation_digest)
        .ok_or(ProviderLedgerError::Unavailable)?;
    if now != then {
        return Err(ProviderLedgerError::Equivocation);
    }
    Ok(now)
}

fn register_context(
    contexts: &mut ControlContextsV5,
    digest: ObjectDigest,
    context: &ControlOriginV5,
    limits: aos_sandbox::JournalLimits,
) -> Result<(), ProviderLedgerError> {
    if contexts.contains_key(&digest) {
        return Ok(());
    }
    let count = contexts.len().checked_add(1).ok_or(ProviderLedgerError::Unavailable)?;
    if count > limits.maximum_materialized_records
        || count.checked_mul(std::mem::size_of::<ControlOriginV5>())
            .is_none_or(|bytes| bytes > limits.maximum_materialized_bytes)
    {
        return Err(ProviderLedgerError::Unavailable);
    }
    contexts.insert(digest, context.clone());
    Ok(())
}

fn register_control(
    contexts: &mut ControlContextsV5,
    control: &SignedNativeHeldControlV1,
    context: &ControlOriginV5,
    limits: aos_sandbox::JournalLimits,
) -> Result<(), ProviderLedgerError> {
    let mut pinned = context.clone();
    pinned.native_kind = Some(control.kind());
    let recovery_terminal = control.kind() == Kind::RootTerminalRecorded
        && contexts.get(&control.predecessor()).is_some_and(|parent| {
            parent.native_kind == Some(Kind::ProviderRecoveryState)
        });
    if !control.kind().is_recovery() && !recovery_terminal {
        let original = contexts.originals.get(&control.scope().provider_acquisition)
            .ok_or(ProviderLedgerError::Unavailable)?;
        pinned.root_pin = Some(original.eligibility.public_projection().root_mount_record_signer().clone());
        pinned.provider_pin = Some(original.eligibility.public_projection().provider_outcome_signer().clone());
    }
    register_context(contexts, control.digest(), &pinned, limits)
}

fn register_original_context(
    contexts: &mut ControlContextsV5,
    acquisition: ObjectDigest,
    root: &SignedNativeHeldControlV1,
    context: &ControlOriginV5,
    limits: aos_sandbox::JournalLimits,
) -> Result<(), ProviderLedgerError> {
    if contexts.originals.contains_key(&acquisition) {
        return Err(ProviderLedgerError::Equivocation);
    }
    let count = contexts.len().checked_add(1).ok_or(ProviderLedgerError::Unavailable)?;
    if count > limits.maximum_materialized_records
        || count.checked_mul(std::mem::size_of::<ControlOriginV5>())
            .is_none_or(|bytes| bytes > limits.maximum_materialized_bytes)
    {
        return Err(ProviderLedgerError::Unavailable);
    }
    let mut original = context.clone();
    original.original_root_control = root.digest();
    contexts.originals.insert(acquisition, original);
    Ok(())
}

fn authenticate_native_rows(
    rows: &SourceCapacityStateV5,
    context: &ControlOriginV5,
    contexts: &mut ControlContextsV5,
    admissions: &BTreeMap<ObjectDigest, ([u8; 16], u64)>,
    current: &ProtectedProviderConfigurationV1,
    storage: &ProtectedStorageZfsHoldVerifierV1,
    challenges: &SourceOriginalChallengeHistoryViewV5<'_>,
    limits: aos_sandbox::JournalLimits,
    selected: &mut selected_archive::SelectedArchiveReplayV1<'_>,
) -> Result<(), ProviderLedgerError> {
    for ((namespace, key), value) in rows {
        if *namespace != RecordNamespace::SourceProviderAuthority {
            continue;
        }
        if value.get(8..10) == Some(&8_u16.to_be_bytes()) {
            let held = SourceNativeHeldCompletionRecordV1::from_canonical_bytes(key, value)
                .map_err(|_| ProviderLedgerError::Equivocation)?;
            let request = held.original().canonical_request.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
            register_context(contexts, request.digest(), context, limits)?;
            let request_context = contexts.get(&request.digest()).ok_or(ProviderLedgerError::Unavailable)?;
            let original = contexts.originals.get(&held.original().acquisition_id)
                .ok_or(ProviderLedgerError::Unavailable)?;
            let provider = original.eligibility.public_projection().provider_outcome_signer().clone();
            let root = original.eligibility.public_projection().root_mount_record_signer().clone();
            request.verify(&provider, context_key(current, request_context, &provider)?,
                &root, context_key(current, original, &root)?)
                .map_err(|_| ProviderLedgerError::Equivocation)?;
            if let Some(reply) = &held.original().accepted_reply {
                verify_reply(storage, reply)?;
            }
            for control in held.suffix().controls() {
                verify_control(control, context, contexts, current, storage, limits, 0)?;
            }
            if let Some(prepared) = held.suffix().prepared() {
                let mut preparation = context.clone();
                if !prepared.kind().is_recovery() {
                    preparation.root_pin = Some(root.clone());
                    preparation.provider_pin = Some(provider.clone());
                }
                register_context(contexts, prepared.digest(), &preparation, limits)?;
                let preparation = contexts.get(&prepared.digest())
                    .ok_or(ProviderLedgerError::Unavailable)?.clone();
                require_prepared_role(prepared, &preparation, current, storage)?;
                verify_nested(prepared, &preparation, contexts, current, storage, limits, 0)?;
            }
            selected.require_held_input(&held, storage)?;
        } else if value.get(8..10) == Some(&9_u16.to_be_bytes()) {
            let cold = SourcePreRequestedColdArchiveV1::from_canonical_bytes(key, value)
                .map_err(|_| ProviderLedgerError::Equivocation)?;
            verify_cold(&cold, context, contexts, admissions, current, challenges, limits)?;
        }
    }
    Ok(())
}

fn verify_reply(
    storage: &ProtectedStorageZfsHoldVerifierV1,
    reply: &StorageNativeAcquireReplyV3,
) -> Result<(), ProviderLedgerError> {
    let verifier = storage.protocol_verifier()?;
    reply.acceptance().verify(&verifier).map_err(|_| ProviderLedgerError::Equivocation)?;
    verifier.verify_retained_signature_claim(reply.receipt())
        .map_err(|_| ProviderLedgerError::Equivocation)?;
    storage.revalidate()
}

fn require_prepared_role(
    prepared: &PreparedNativeHeldControlV1,
    context: &ControlOriginV5,
    current: &ProtectedProviderConfigurationV1,
    storage: &ProtectedStorageZfsHoldVerifierV1,
) -> Result<(), ProviderLedgerError> {
    let expected = match prepared.kind().sender() {
        Role::Root | Role::Provider => {
            let data = context.eligibility.public_projection();
            let signer = if prepared.kind().sender() == Role::Root {
                context.root_pin.as_ref().unwrap_or(data.root_mount_record_signer())
            } else {
                context.provider_pin.as_ref().unwrap_or(data.provider_outcome_signer())
            };
            context_key(current, context, signer)?;
            NativeHeldSignerV1::SourceProvider(signer.clone())
        }
        Role::Storage => NativeHeldSignerV1::Storage(storage.protocol_verifier()?.projection().0),
    };
    if prepared.signer() != &expected {
        return Err(ProviderLedgerError::Equivocation);
    }
    Ok(())
}

fn verify_control(
    control: &SignedNativeHeldControlV1,
    observed: &ControlOriginV5,
    contexts: &mut ControlContextsV5,
    current: &ProtectedProviderConfigurationV1,
    storage: &ProtectedStorageZfsHoldVerifierV1,
    limits: aos_sandbox::JournalLimits,
    depth: usize,
) -> Result<(), ProviderLedgerError> {
    if depth > 4 {
        return Err(ProviderLedgerError::Equivocation);
    }
    register_control(contexts, control, observed, limits)?;
    let context = contexts.get(&control.digest()).ok_or(ProviderLedgerError::Unavailable)?.clone();
    match control.kind().sender() {
        Role::Root | Role::Provider => {
            let data = context.eligibility.public_projection();
            let signer = if control.kind().sender() == Role::Root {
                context.root_pin.as_ref().unwrap_or(data.root_mount_record_signer())
            } else {
                context.provider_pin.as_ref().unwrap_or(data.provider_outcome_signer())
            };
            control.verify_signature_claim(&NativeHeldSignerV1::SourceProvider(signer.clone()),
                context_key(current, &context, signer)?)
                .map_err(|_| ProviderLedgerError::Equivocation)?;
        }
        Role::Storage => {
            let (signer, key) = storage.protocol_verifier()?.projection();
            control.verify_signature_claim(&NativeHeldSignerV1::Storage(signer), &key)
                .map_err(|_| ProviderLedgerError::Equivocation)?;
        }
    }
    if control.kind() == Kind::RootRecoveryQuery {
        let query = NativeHeldRecoveryQueryV1::from_canonical_bytes(
            control.section(Tag::RecoveryQuery).ok_or(ProviderLedgerError::Equivocation)?,
        ).map_err(|_| ProviderLedgerError::Equivocation)?;
        if context.query.as_ref() != control.to_canonical_bytes().as_slice()
            || query.recovery_session != context.session
        {
            return Err(ProviderLedgerError::Equivocation);
        }
    }
    if control.kind() == Kind::RootTerminalRecorded
        && contexts.get(&control.predecessor()).is_some_and(|parent| {
            parent.native_kind == Some(Kind::ProviderRecoveryState)
        })
    {
        let root = SignedNativeHeldControlV1::from_canonical_bytes(&context.query)
            .map_err(|_| ProviderLedgerError::Equivocation)?;
        if root.kind() != Kind::RootRecoveryQuery {
            return Err(ProviderLedgerError::Equivocation);
        }
        control.scope().require_root_prefix(root.scope())
            .map_err(|_| ProviderLedgerError::Equivocation)?;
        let query = NativeHeldRecoveryQueryV1::from_canonical_bytes(
            root.section(Tag::RecoveryQuery).ok_or(ProviderLedgerError::Equivocation)?,
        ).map_err(|_| ProviderLedgerError::Equivocation)?;
        let original = contexts.originals.get(&control.scope().provider_acquisition)
            .ok_or(ProviderLedgerError::Unavailable)?;
        let assertion = RootNativeRecoveryAssertionV1::from_canonical_bytes(
            root.section(Tag::RootRecoveryAssertion).ok_or(ProviderLedgerError::Equivocation)?,
        ).map_err(|_| ProviderLedgerError::Equivocation)?;
        let settlement = NativeHeldSettlementV1::from_canonical_bytes(
            control.section(Tag::Settlement).ok_or(ProviderLedgerError::Equivocation)?,
        ).map_err(|_| ProviderLedgerError::Equivocation)?;
        if query.mode != NativeHeldRecoveryModeV1::RecordRootTerminal
            || query.original_prepared != original.original_root_control
            || assertion.settlement.as_ref() != Some(&settlement)
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        verify_control(&root, &context, contexts, current, storage, limits, depth + 1)?;
    }
    verify_nested(control.prepared(), &context, contexts, current, storage, limits, depth)
}

fn verify_nested(
    prepared: &PreparedNativeHeldControlV1,
    context: &ControlOriginV5,
    contexts: &mut ControlContextsV5,
    current: &ProtectedProviderConfigurationV1,
    storage: &ProtectedStorageZfsHoldVerifierV1,
    limits: aos_sandbox::JournalLimits,
    depth: usize,
) -> Result<(), ProviderLedgerError> {
    for section in prepared.sections() {
        let mut nested = Vec::new();
        match section.tag() {
            Tag::RootPrepared | Tag::StorageHeld | Tag::RootDispositionControl | Tag::RootRecoveryControl => {
                nested.push(section.bytes());
            }
            Tag::NativeReply => {
                let reply = StorageNativeAcquireReplyV3::from_canonical_bytes(section.bytes())
                    .map_err(|_| ProviderLedgerError::Equivocation)?;
                verify_reply(storage, &reply)?;
            }
            Tag::ProviderRecoveryState => {
                let state = ProviderNativeRecoveryStateV1::from_canonical_bytes(section.bytes())
                    .map_err(|_| ProviderLedgerError::Equivocation)?;
                for bytes in [&state.fields.hot_terminal, &state.fields.child].into_iter().flatten() {
                    let child = SignedNativeHeldControlV1::from_canonical_bytes(bytes)
                        .map_err(|_| ProviderLedgerError::Equivocation)?;
                    verify_control(&child, context, contexts, current, storage, limits, depth + 1)?;
                }
            }
            Tag::StorageRecoveryState => {
                let state = StorageNativeRecoveryStateV1::from_canonical_bytes(section.bytes())
                    .map_err(|_| ProviderLedgerError::Equivocation)?;
                if let Some(bytes) = &state.fields.hot_terminal {
                    let child = SignedNativeHeldControlV1::from_canonical_bytes(bytes)
                        .map_err(|_| ProviderLedgerError::Equivocation)?;
                    verify_control(&child, context, contexts, current, storage, limits, depth + 1)?;
                }
            }
            Tag::RootRecoveryAssertion => {
                let state = RootNativeRecoveryAssertionV1::from_canonical_bytes(section.bytes())
                    .map_err(|_| ProviderLedgerError::Equivocation)?;
                if let Some(bytes) = &state.hot_archive {
                    let child = SignedNativeHeldControlV1::from_canonical_bytes(bytes)
                        .map_err(|_| ProviderLedgerError::Equivocation)?;
                    verify_control(&child, context, contexts, current, storage, limits, depth + 1)?;
                }
            }
            _ => {}
        }
        for bytes in nested {
            let child = SignedNativeHeldControlV1::from_canonical_bytes(bytes)
                .map_err(|_| ProviderLedgerError::Equivocation)?;
            verify_control(&child, context, contexts, current, storage, limits, depth + 1)?;
        }
    }
    Ok(())
}

fn verify_cold(
    cold: &SourcePreRequestedColdArchiveV1,
    observed: &ControlOriginV5,
    contexts: &mut ControlContextsV5,
    admissions: &BTreeMap<ObjectDigest, ([u8; 16], u64)>,
    current: &ProtectedProviderConfigurationV1,
    challenges: &SourceOriginalChallengeHistoryViewV5<'_>,
    limits: aos_sandbox::JournalLimits,
) -> Result<(), ProviderLedgerError> {
    let digest = exact_digest(cold.prepared().as_canonical_bytes());
    register_context(contexts, digest, observed, limits)?;
    let context = contexts.get(&digest).ok_or(ProviderLedgerError::Unavailable)?;
    let claims = cold.prepared().claims();
    if admissions.get(&claims.acquisition_id) != Some(&(claims.admission_transaction, claims.admission_sequence))
        || context.physical != (claims.first_cold_transaction, claims.first_cold_sequence)
        || (context.challenge.1, context.challenge.2) != (claims.challenge_sequence, claims.challenge_cut)
        || challenges.checkpoints()?.any(|row| row.key() == claims.challenge_absence.key())
    {
        return Err(ProviderLedgerError::Equivocation);
    }
    challenges.require_archived_prefix(context.challenge.0, context.challenge.1, context.challenge.2)?;
    let provider = context.eligibility.public_projection().provider_outcome_signer();
    if cold.prepared().signer() != provider {
        return Err(ProviderLedgerError::Equivocation);
    }
    context_key(current, context, provider)?;
    if let Some(signed) = cold.signed() {
        signed.verify(provider, context_key(current, context, provider)?)
            .map_err(|_| ProviderLedgerError::Equivocation)?;
    }
    if let Some(ack) = cold.acknowledgement() {
        let digest = exact_digest(&ack.to_canonical_bytes());
        register_context(contexts, digest, observed, limits)?;
        let context = contexts.get(&digest).ok_or(ProviderLedgerError::Unavailable)?;
        let query = RecoveryCurrentnessQueryV1::from_canonical_bytes(&context.query)
            .map_err(|_| ProviderLedgerError::Equivocation)?;
        if query.session_binding() != context.session
            || query.authorities() != (claims.provider_id, claims.holder_id)
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        let root = context.eligibility.public_projection().root_mount_record_signer();
        let key = context_key(current, context, root)?;
        ack.verify_retained_signature_claim(root, key)
            .and_then(|()| ack.verify_for_query(&query, root, key))
            .map_err(|_| ProviderLedgerError::Equivocation)?;
    }
    Ok(())
}

fn exact_digest(bytes: &[u8]) -> ObjectDigest {
    use sha2::{Digest as _, Sha256};
    ObjectDigest::from_bytes(Sha256::digest(bytes).into())
}

#[cfg(test)]
mod tests;
