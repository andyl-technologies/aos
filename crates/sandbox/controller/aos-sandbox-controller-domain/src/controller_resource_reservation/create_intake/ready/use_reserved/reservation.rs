//! Derives the exact U reserve from retained originals and complete geometry.
//!
//! Security's closed caller supplies its actual normalized request shape. The
//! same private Root owner fixes the comparison amount, while actual held
//! Journal/socket/transcript and completed B associations fix every namespace.
//! The incomplete prefix recipe is never called by this producer.

use std::error::Error;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1;
use aos_sandbox_linux::seqpacket::SeqpacketSocket;
use crate::journal::{Journal, JournalError, ProtectedJournalPreopenReplayExtentV1};
use crate::journal::broker_session_receiving::{StorageCreateUseSecurityShapeDataV1,
    StorageSessionGeometryRefusalV1, storage_create_use_receiving_demand_v1};
use crate::controller_resource_reservation::{AccountTransition, ReturnedAppend,
    ResourceReservationErrorV1, bank};
use super::super::cache_receiving::{CacheCurrentnessOriginalV1, CacheControlOriginalsV1};
use super::bank_append::{UseReservationPreparedV1, UseBankObservationOriginalsV1,
    CreateStorageUseBankOriginalsV1};
use super::receiving::UseReceivingOriginalsV1;
use super::super::*;
use sha2::{Digest as _, Sha256};

#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake) struct UseReservationOriginalsV1 {
    pub(super) entered: bool,
    pub(super) plan_funding: Option<Result<(), ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    association: Option<Result<(), super::super::client_session::ClientSessionAssociationErrorV1>>,
    before: CacheCurrentnessOriginalV1,
    before_result: Option<Result<(), ResourceReservationErrorV1>>,
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    extent: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    source_extent: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    request_shape_bytes: Option<usize>,
    recipe: Option<Result<ResourceVector, StorageSessionGeometryRefusalV1>>,
    prepared: Option<Result<UseReservationPreparedV1, ResourceReservationErrorV1>>,
    observations: UseBankObservationOriginalsV1,
    append: Option<ReturnedAppend>,
    receiving: Option<Result<UseReceivingOriginalsV1, ResourceReservationErrorV1>>,
    history: Option<Result<(), ResourceReservationErrorV1>>,
    after: CacheCurrentnessOriginalV1,
    after_result: Option<Result<(), ResourceReservationErrorV1>>,
    primary: Option<Result<(), ResourceReservationErrorV1>>,
    complete: bool,
}

impl UseReservationOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake) fn started(&self) -> bool { self.entered }

    pub(in crate::controller_resource_reservation::create_intake) fn position(&self) -> Result<super::CreateStorageWriterPositionV1, ResourceReservationErrorV1> {
        if !self.complete || self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.returned_position()
    }

    fn returned_position(&self) -> Result<super::CreateStorageWriterPositionV1, ResourceReservationErrorV1> {
        self.append.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?.require_committed()?;
        self.observations.completed_position_v1()
    }

    pub(in crate::controller_resource_reservation::create_intake) fn request_shape_bytes_v1(&self) -> Result<usize, ResourceReservationErrorV1> {
        self.position()?;
        self.request_shape_bytes.ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn split_commit_inputs_v1(&mut self)
        -> Result<(&UseReservationPreparedV1, &ReturnedAppend, usize, &mut UseReceivingOriginalsV1), ResourceReservationErrorV1> {
        self.position()?;
        let prepared = self.prepared.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let append = self.append.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let width = self.request_shape_bytes.ok_or(ResourceReservationErrorV1::Conflict)?;
        let receiving = self.receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        receiving.require_reserved_v1()?;
        Ok((prepared, append, width, receiving))
    }

    pub(super) fn returned_append_v1(&self) -> Result<&ReturnedAppend, ResourceReservationErrorV1> {
        self.position()?;
        self.append.as_ref().ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn split_root_receiving_v1(&mut self)
        -> Result<(&ReturnedAppend, &mut UseReceivingOriginalsV1), ResourceReservationErrorV1>
    {
        self.position()?;
        Ok((self.append.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?,
            self.receiving.as_mut().and_then(|r| r.as_mut().ok()).ok_or(ResourceReservationErrorV1::Conflict)?))
    }

    // Only an already-entered Root purpose uses this to run its prepaid owed
    // post after later U debt. Original reserve custody remains mandatory;
    // this never restores health or permits new primary work.
    pub(in crate::controller_resource_reservation::create_intake)
    fn split_retained_root_receiving_after_debt_v1(&mut self)
        -> Result<(&ReturnedAppend, &mut UseReceivingOriginalsV1), ResourceReservationErrorV1> {
        if !self.complete { return Err(ResourceReservationErrorV1::Conflict); }
        let append = self.append.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        append.require_committed()?;
        self.observations.completed_position_v1()?;
        Ok((append, self.receiving.as_mut().and_then(|r| r.as_mut().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?))
    }

    pub(in crate::controller_resource_reservation::create_intake) fn returned_transition_v1(&self)
        -> Result<&AccountTransition, ResourceReservationErrorV1>
    {
        self.position()?;
        self.append.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?.require_committed()
    }

    pub(in crate::controller_resource_reservation::create_intake) fn bank_members_v1(&self)
        -> Result<(&[u8; bank::ACCOUNT_HEAD_BYTES_V1], &[u8; bank::CLAIM_BYTES_V1],
            &[u8; bank::CREATE_STORAGE_USE_BINDING_BYTES_V1]), ResourceReservationErrorV1>
    {
        self.position()?;
        let append = self.append.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let transaction = append.transaction.as_ref().and_then(|r| r.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let [head, claim, binding] = transaction.records() else { return Err(ResourceReservationErrorV1::Conflict); };
        let malformed = || ResourceReservationErrorV1::Conflict;
        Ok((head.value().ok_or_else(malformed)?.try_into().map_err(|_| malformed())?,
            claim.value().ok_or_else(malformed)?.try_into().map_err(|_| malformed())?,
            binding.value().ok_or_else(malformed)?.try_into().map_err(|_| malformed())?))
    }

    pub(in crate::controller_resource_reservation::create_intake) fn receiving_mut_v1(&mut self)
        -> Result<&mut UseReceivingOriginalsV1, ResourceReservationErrorV1>
    {
        self.position()?;
        self.receiving.as_mut().and_then(|r| r.as_mut().ok()).ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn reserve_pair_receiving_once_v1(&mut self,
        demand: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.receiving_mut_v1()?.reserve_once(demand)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn require_pair_receiving_v1(&self,
        demand: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.position()?;
        let receiving = self.receiving.as_ref().and_then(|r| r.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        receiving.require_reserved_v1()?;
        receiving.charged_v1().checked_sub(demand)?;
        Ok(())
    }

    pub(in crate::controller_resource_reservation::create_intake) fn require_current_state_v1(&self,
        parent: &crate::controller_resource_reservation::ProjectPreparationReservationAttemptV1,
        state: &crate::controller_resource_reservation::State,
    ) -> Result<(), ResourceReservationErrorV1> {
        let actual = self.returned_transition_v1()?;
        let original = parent.create_storage_use_original_binding_v1()?;
        original.require_replayed(state)?;
        if bank::find_head(state, actual.after.native_fields().id)? != actual.after
            || bank::claim_bytes(state, actual.claim.native_fields().id)
                != Some(self.bank_members_v1()?.1.as_slice()) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(in crate::controller_resource_reservation::create_intake) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.plan_funding).or_else(|| error(&self.funding)).or_else(|| error(&self.association))
            .or_else(|| self.before.failure()).or_else(|| error(&self.before_result))
            .or_else(|| error(&self.metadata)).or_else(|| error(&self.extent))
            .or_else(|| error(&self.source_extent)).or_else(|| error(&self.recipe)).or_else(|| error(&self.prepared))
            .or_else(|| self.observations.primary_failure())
            .or_else(|| self.append.as_ref().and_then(ReturnedAppend::failure))
            .or_else(|| self.observations.post_failure())
            .or_else(|| error(&self.receiving))
            .or_else(|| self.receiving.as_ref().and_then(|r| r.as_ref().ok()).and_then(UseReceivingOriginalsV1::failure))
            .or_else(|| error(&self.history)).or_else(|| error(&self.primary))
            .or_else(|| self.after.failure()).or_else(|| error(&self.after_result))
    }
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Reserves U from the same completed Root turn and exact current C bank.
    ///
    /// The installed Security caller supplies its actual compiled layout and
    /// complete normalized request width. These are DATA, not receiving grants.
    /// The complete shared recipe is independently derived from original held
    /// extents and must exactly equal the authenticated Root proposal.
    ///
    /// # Errors
    /// Refuses reentry, wrong Session/B association, incomplete final geometry,
    /// changed predecessors, exhausted resources or a native/readback/post
    /// failure. Ambiguous and Reserved actual state stays resident and fenced.
    #[doc(hidden)]
    pub fn reserve_storage_use_once(&mut self, session: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, bundle_bytes: &[u8],
        request_shape_bytes: usize, private: StorageCreateUseSecurityShapeDataV1,
    ) -> Result<(), CreateStorageReadyClosedV1> {
        if self.failure().is_some() || self.original.owner.storage_use.reservation.entered {
            self.original.owner.storage_use.closed.get_or_insert(ResourceReservationErrorV1::Conflict);
            return Err(CreateStorageReadyClosedV1);
        }
        let cache_extents = match self.completed_cache_current_extents_v1() {
            Ok(value) => value,
            Err(_) => {
                self.original.owner.storage_use.closed.get_or_insert(ResourceReservationErrorV1::Conflict);
                return Err(CreateStorageReadyClosedV1);
            }
        };
        let owner = &mut *self.original.owner;
        let use_state = &mut owner.storage_use;
        let progress = &mut use_state.reservation;
        progress.entered = true;
        progress.funding = Some((|| {
            use_state.validated.position()?;
            if !matches!(progress.plan_funding, Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }
            owner.intake.require_create_history_names_peak_v1()?;
            owner.bundle.require_completed_bytes_v1(bundle_bytes)?;
            let bytes = std::mem::size_of::<UseReservationOriginalsV1>().checked_mul(2)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let dominant = ResourceVector::ZERO.with(D::MemoryBytes,
                u64::try_from(bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?);
            let backing = CacheCurrentnessOriginalV1::receiving_backing_demand_v1(2)?;
            let fixed = crate::controller_resource_reservation::create_storage_use_bank_receiving_demand_v1()?;
            // These two operation samples use clean, individually funded C
            // Producer scopes, rather than the intake's retained row archive.
            owner.intake.reserve_root_validated_capture_once(dominant.checked_add(backing)?.checked_add(fixed)?)
        })());
        if !matches!(progress.funding, Some(Ok(()))) { return Err(CreateStorageReadyClosedV1); }
        let authorization = match owner.root_exchange.borrow_use_authorization_v1() {
            Ok(value) => value,
            Err(cause) => { use_state.closed.get_or_insert(cause); return Err(CreateStorageReadyClosedV1); }
        };
        let expected = match owner.cache_capture.currentness_association_v1() {
            Ok(value) => value,
            Err(cause) => { use_state.closed.get_or_insert(cause); return Err(CreateStorageReadyClosedV1); }
        };
        progress.before_result = Some(progress.before.observe_operation_once(CacheControlOriginalsV1 {
            parent: &owner.parent, intake: &owner.intake, controller: self.original.controller,
            source: self.original.source, profile: self.original.profile,
        }, &self.cache, expected, use_state.validated.position()));
        progress.association = Some(owner.client_session.require_completed_association_v1(session, socket, transcript));
        progress.primary = Some((|| {
            if progress.before.failure().is_some() || !matches!(progress.before_result, Some(Ok(())))
                || !matches!(progress.association, Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }
            owner.bundle.require_completed_bytes_v1(bundle_bytes)?;
            let (metadata, limits) = session.held_native_receiving_metadata_v1();
            progress.metadata = Some(metadata);
            if let Some(Ok(metadata)) = progress.metadata.as_ref() {
                progress.extent = Some(crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(limits, metadata.len()));
            }
            let extent = progress.extent.as_ref().and_then(|r| r.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
            let baseline = use_state.validated.predecessor_position_v1()?;
            let controller_extent = crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
                self.original.controller.configured_limits_data_v1(), baseline.end)?;
            // Price the real original Source prefix, independently of the
            // Controller cut. Its later release cannot borrow a proxy extent.
            let source = owner.histories.source_held_data_v1(owner.intake.create_lane()?)?;
            progress.source_extent = Some(crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
                crate::source_domain::source_domain_journal_limits(), source.source_after_end));
            let source_extent = progress.source_extent.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            progress.request_shape_bytes = Some(request_shape_bytes);
            progress.recipe = Some(storage_create_use_receiving_demand_v1(extent,
                request_shape_bytes, &controller_extent, source_extent, cache_extents.extents_v1(), private));
            let amount = progress.recipe.as_ref().and_then(|r| r.as_ref().ok()).copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            if amount != authorization.body_v1()?.receiving { return Err(ResourceReservationErrorV1::Conflict); }
            let original = owner.parent.create_storage_use_original_binding_v1()?;
            let lane = owner.intake.create_lane()?;
            let ua_checksum = super::bank_append::authorization_checksum(&authorization, lane)?;
            let validated_checksum = use_state.validated.checksum_v1(lane)?;
            let digest = Sha256::new().chain_update(b"aos.sandbox.create-storage.use-claim.v1\0")
                .chain_update(original.commitment()?).chain_update(ua_checksum).chain_update(validated_checksum).finalize();
            let mut id = [0; 16];
            id.copy_from_slice(&digest[..16]);
            let claim = original.create_storage_use_claim_v1(id, amount)?;
            let binding = bank::CreateStorageUseBindingV1::new(original, ua_checksum, validated_checksum, claim)?;
            progress.prepared = Some(Ok(UseReservationPreparedV1 { recipe: Ok(amount), claim, binding }));
            let prepared = progress.prepared.as_ref().and_then(|r| r.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
            let state = self.original.controller.controller_resource_state_v1()?;
            owner.parent.require_create_continuation_state(state)?;
            let before = bank::find_head(state, prepared.claim.native_fields().account)?;
            let transition = AccountTransition::reserve_create_storage_use(before, prepared.claim,
                prepared.binding, owner.intake.create_storage_j_data_v1()?.clock);
            let original = CreateStorageUseBankOriginalsV1::reserve(&owner.parent, &owner.intake,
                &use_state.validated, &authorization, prepared, &progress.observations)?;
            progress.append = Some(ReturnedAppend::new());
            progress.append.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?
                .append_create_storage_use_into(self.original.controller, transition, original);
            progress.receiving = Some(UseReceivingOriginalsV1::from_returned_reserve_v1(
                progress.append.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?,
                self.original.controller, &mut owner.intake, self.original.profile));
            let receiving = progress.receiving.as_mut().and_then(|r| r.as_mut().ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
            let mut loan = receiving.borrow_native_history_once(&owner.parent, &owner.intake, &authorization)?;
            progress.history = Some(self.original.controller.require_controller_resource_history_for_create_storage_use_v1(&mut loan));
            if matches!(progress.history, Some(Ok(()))) { Ok(()) } else { Err(ResourceReservationErrorV1::Conflict) }
        })());
        // Both distinct observations were prepaid before either could run.
        // An ambiguous append makes the expected position unavailable; the
        // same independent post still retains all actual reached originals.
        let current = if progress.append.is_some() { progress.returned_position() } else { use_state.validated.position() };
        progress.after_result = Some(progress.after.observe_operation_once(CacheControlOriginalsV1 {
            parent: &owner.parent, intake: &owner.intake, controller: self.original.controller,
            source: self.original.source, profile: self.original.profile,
        }, &self.cache, expected, current));
        progress.complete = matches!(progress.primary, Some(Ok(())))
            && matches!(progress.after_result, Some(Ok(()))) && progress.failure().is_none();
        if progress.complete { Ok(()) } else { Err(CreateStorageReadyClosedV1) }
    }
}

fn error<T, E: Error + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref().and_then(|r| r.as_ref().err()).map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ambiguous_native_reserve_retains_its_actual_cause_before_later_post() {
        let mut actual = UseReservationOriginalsV1::default();
        let mut append = ReturnedAppend::new();
        append.native = Some(Err(JournalError::Io(std::io::Error::from_raw_os_error(5))));
        actual.append = Some(append);
        actual.after_result = Some(Err(ResourceReservationErrorV1::Conflict));

        let first = actual.failure().unwrap().downcast_ref::<JournalError>().unwrap();

        assert!(matches!(first, JournalError::Io(cause) if cause.raw_os_error() == Some(5)));
        assert!(actual.position().is_err());
        assert!(actual.returned_append_v1().is_err());
    }
}
