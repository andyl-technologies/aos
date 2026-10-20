//! Retains the actual six planning query owners on their same authorized cut.
//!
//! Each reached result has a resident destination before the next query. This
//! owner is initial planning evidence only: later pending/preaccept must observe
//! fresh originals under the real Root challenge before accepting or destroying.

use super::*;

mod lender;
mod signing;
mod preparation;
mod storage_flight;
mod apply;
mod network;
mod network_apply;
mod host_confirmation;
mod mount;
mod completion;
pub(in crate::controller_service) use lender::ControllerDeleteInitialSixPlanningLoanV2;
use aos_sandbox::ResourceReservationErrorV1;
use crate::controller_service::inventory::delete_queries::ControllerDeleteInventorySourceV2;
use aos_sandbox_broker_session_security::controller_composition::DeleteInventoryAnswerOriginalsV1;

/// Keeps all six genuine query originals, including partial failed collection.
///
/// Fields are private. No tuple, decoded cut, supplied Result or zero count can
/// construct a collection; only the actual authorized native entrances below do.
pub(in crate::controller_service) struct ControllerDeletePlanningCollectionV2<'sessions, 'cache, 'profile> {
    // This actual exclusive bundle keeps its existing MutexGuard borrowed. No
    // ordinary writer can advance any Session while initial Root verifies EOF.
    session_writers: &'sessions mut ControllerBrokerSessions,
    sessions: [Option<DeleteInventoryAnswerOriginalsV1>; 4],
    broker_models: [Option<Result<aos_sandbox::lifecycle::DeletePlanningBrokerInventoryDataV2,
        aos_sandbox::lifecycle::LifecyclePhase6ErrorV1>>; 4],
    model_admission: Option<Result<(), ResourceReservationErrorV1>>,
    broker_cuts: [Option<Result<aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchOwnerCutDataV2,
        aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError>>; 4],
    cache: Option<aos_sandbox::cache_residency::CacheDeleteInventoryOriginalV1<'cache>>,
    root: Option<ControllerDeleteLocalRootPlanningOriginalV1<'profile>>,
    cache_cut: Option<Result<aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchOwnerCutDataV2,
        CacheCutFailureV2>>,
    stages: [Option<Result<(), ResourceReservationErrorV1>>; 6],
    transfer_cut: Option<Result<aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchOwnerCutDataV2,
        TransferCutFailureV2>>,
    initial_six: Option<Result<[u8; 32],
        aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError>>,
    outer_after: Option<Result<(), ResourceReservationErrorV1>>,
    complete: bool,
    planning_lender: Option<Result<(), ResourceReservationErrorV1>>,
    fresh_sessions: [Option<DeleteInventoryAnswerOriginalsV1>; 4],
    fresh_models: [Option<Result<aos_sandbox::lifecycle::DeletePlanningBrokerInventoryDataV2,
        aos_sandbox::lifecycle::LifecyclePhase6ErrorV1>>; 4],
    fresh_model_admission: Option<Result<(), ResourceReservationErrorV1>>,
    fresh_cuts: [Option<Result<aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchOwnerCutDataV2,
        aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError>>; 4],
    fresh_stages: [Option<Result<(), ResourceReservationErrorV1>>; 6],
    fresh_entered: bool,
    fresh_closed: Option<ResourceReservationErrorV1>,
    fresh_sessions_complete: bool,
    fresh_transfer_read: Option<Result<(), ResourceReservationErrorV1>>,
    fresh_transfer_admission: Option<Result<(), ResourceReservationErrorV1>>,
    fresh_cache_cut: Option<Result<aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchOwnerCutDataV2, CacheCutFailureV2>>,
    fresh_transfer_cut: Option<Result<aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchOwnerCutDataV2, TransferCutFailureV2>>,
    resource_exchange_admission: Option<Result<(), ResourceReservationErrorV1>>,
    resource_exchange: Option<Result<(), ResourceReservationErrorV1>>,
    resource_signing: signing::ControllerDeleteResourceSigningOriginalV2,
    apply_resource_signing: signing::ControllerDeleteResourceSigningOriginalV2,
    preparatory_approval: Option<Result<(), ResourceReservationErrorV1>>,
    source_readiness: Option<Result<(), ResourceReservationErrorV1>>,
    controller_acceptance: Option<Result<(), ResourceReservationErrorV1>>,
    storage_preparation: preparation::ControllerDeleteStoragePreparationOriginalV3,
    storage_apply: apply::ControllerDeleteStorageApplyOriginalV3,
    apply_resource_exchange: Option<Result<(), ResourceReservationErrorV1>>,
    apply_approval: Option<Result<(), ResourceReservationErrorV1>>,
    network_resource_signing: signing::ControllerDeleteResourceSigningOriginalV2,
    network_resource_exchange: Option<Result<(), ResourceReservationErrorV1>>,
    network_approval: Option<Result<(), ResourceReservationErrorV1>>,
    network_apply: network_apply::ControllerDeleteNetworkApplyOriginalV4,
    host_confirmation: host_confirmation::ControllerDeleteHostConfirmationOriginalV4,
    mount_resource_signing: signing::ControllerDeleteResourceSigningOriginalV2,
    mount_resource_exchange: Option<Result<(), ResourceReservationErrorV1>>,
    mount_approval: Option<Result<(), ResourceReservationErrorV1>>,
    mount_reap: mount::ControllerDeleteMountReapOriginalV4,
    source_completion: Option<Result<
        aos_sandbox_protocol::domain_ledger::delete_root::completion::DeleteRootSourceCompletionDataV4,
        ResourceReservationErrorV1>>,
}

enum CacheCutFailureV2 {
    Admission(ResourceReservationErrorV1),
    Original(aos_sandbox::JournalError),
    Physical(aos_sandbox::cache_residency::CacheOwnerErrorV1),
    Canonical(aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError),
}

enum TransferCutFailureV2 {
    Borrow(ResourceReservationErrorV1),
    Canonical(aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningDataErrorV3),
}

impl<'sessions, 'cache, 'profile> ControllerDeletePlanningCollectionV2<'sessions, 'cache, 'profile> {
    /// Collects through the actual Runtime fields without reopening any owner.
    ///
    /// Source has already been exclusively lent by the concrete disjoint field
    /// split. Cache and local Runtime fields stay borrowed throughout the returned
    /// collection. The same exclusive four-Session bundle remains borrowed by
    /// this owner through the initial Root prefix verification and ACK; it is
    /// never returned to an unlocked globally accessible slot between phases.
    /// Each native query pays its own reached representation and IO;
    /// this initial debit additionally covers the whole resident collection.
    pub(in crate::controller_service) fn collect_authorized_once_v2(
        sessions: &'sessions mut ControllerBrokerSessions,
        cache: &'cache mut ControllerDeleteCacheRuntimeFieldsV1<'_>,
        local: &'profile ControllerDeleteLocalRuntimeFieldsV1<'_>,
        authorized: &mut ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<Self, ResourceReservationErrorV1> {
        if !std::ptr::eq(profile, local.profile.as_ref()) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let bytes = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                ControllerDeleteInventorySourceV2<'_, '_, '_, '_>>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<(), ResourceReservationErrorV1>>()
                .checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<[
                aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchOwnerCutDataV2; 6]>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<sha2::Sha256>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                ControllerDeleteInitialSixPlanningLoanV2<'_, '_>>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(48 * 3))
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        bank.reserve_delete_planning_collection_v2(authorized, controller, profile, bytes)?;
        let mut original = Self {
            session_writers: sessions,
            sessions: std::array::from_fn(|_| None),
            broker_models: std::array::from_fn(|_| None), model_admission: None,
            broker_cuts: std::array::from_fn(|_| None), cache: None, root: None, cache_cut: None,
            stages: std::array::from_fn(|_| None), transfer_cut: None, initial_six: None,
            outer_after: None, complete: false, planning_lender: None,
            fresh_sessions: std::array::from_fn(|_| None),
            fresh_models: std::array::from_fn(|_| None),
            fresh_model_admission: None, fresh_cuts: std::array::from_fn(|_| None),
            fresh_stages: std::array::from_fn(|_| None),
            fresh_entered: false, fresh_closed: None, fresh_sessions_complete: false,
            fresh_transfer_read: None, fresh_transfer_cut: None,
            fresh_transfer_admission: None, fresh_cache_cut: None,
            resource_exchange_admission: None, resource_exchange: None,
            resource_signing: Default::default(), apply_resource_signing: Default::default(),
            preparatory_approval: None, source_readiness: None, controller_acceptance: None,
            storage_preparation: Default::default(),
            storage_apply: Default::default(), apply_resource_exchange: None, apply_approval: None,
            network_resource_signing: Default::default(), network_resource_exchange: None, network_approval: None,
            network_apply: Default::default(),
            host_confirmation: Default::default(),
            mount_resource_signing: Default::default(), mount_resource_exchange: None, mount_approval: None,
            mount_reap: Default::default(),
            source_completion: None,
        };

        let collected = original.session_writers.collect_delete_planning_sessions_once_v1(
            authorized, bank, controller, profile, &mut original.sessions, &mut original.stages,
        );
        if collected.is_err() {
            original.finish_failed_outer_v2(authorized, bank, controller, profile);
        }

        original.stages[4] = Some(match cache.query_planning_once_v1(authorized, bank, controller, profile) {
            Ok(cache) => { original.cache = Some(cache); Ok(()) }
            Err(cause) => Err(cause),
        });
        if !matches!(original.stages[4], Some(Ok(()))) {
            original.finish_failed_outer_v2(authorized, bank, controller, profile);
        }

        original.stages[5] = Some(match local.query_root_planning_once_v1(authorized, bank, controller) {
            Ok(root) => { original.root = Some(root); Ok(()) }
            Err(cause) => Err(cause),
        });
        if !matches!(original.stages[5], Some(Ok(()))) {
            original.finish_failed_outer_v2(authorized, bank, controller, profile);
        }
        // The actual Root constructor retains a pure trust mismatch on its
        // whole owner. It remains negative despite six transport completions.
        if original.root.as_ref().is_some_and(|root| root.failure_v2().is_some()) {
            original.finish_failed_outer_v2(authorized, bank, controller, profile);
        }
        original.derive_broker_models_v2(authorized, bank, controller, profile);
        original.derive_cache_cut_v2(authorized, bank, controller, profile);
        original.transfer_cut = Some(match original.root.as_mut() {
            Some(root) => match root.borrow_transfer_planning_v2(local, authorized, bank, controller) {
                Ok(loan) => loan.completed_cut_data_v2().map_err(TransferCutFailureV2::Canonical),
                Err(cause) => Err(TransferCutFailureV2::Borrow(cause)),
            },
            None => Err(TransferCutFailureV2::Borrow(ResourceReservationErrorV1::Conflict)),
        });
        if !matches!(original.transfer_cut, Some(Ok(_))) {
            original.finish_failed_outer_v2(authorized, bank, controller, profile);
        }
        original.initial_six = Some(original.owner_cuts_data_v2().and_then(|cuts|
            aos_sandbox_protocol::domain_ledger::delete_root::inventory_cuts::initial_six_cut_data_v2(&cuts)));
        if !matches!(original.initial_six, Some(Ok(_))) {
            original.finish_failed_outer_v2(authorized, bank, controller, profile);
        }
        original.complete = true;
        Ok(original)
    }

    fn derive_broker_models_v2(
        &mut self,
        authorized: &mut ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) {
        let mut source = ControllerDeleteInventorySourceV2::Planning(authorized);
        let derived = derive_broker_models_from_originals_v2(
            &self.sessions, &mut self.broker_models, &mut self.broker_cuts,
            &mut self.model_admission, &mut source, bank, controller, profile,
        );
        drop(source);
        if derived.is_err() {
            self.finish_failed_outer_v2(authorized, bank, controller, profile);
        }
    }

    /// Collects fresh signed queries through this same exclusive Session bundle.
    ///
    /// The initial originals remain resident. Only the actual completed Root
    /// ACK supplies the fresh nonce/cutoff; no Session is replaced or unlocked
    /// between initial Root verification and these queries. A refusal keeps all
    /// reached answer/model/native owners on this collection for outer posts.
    /// This completes four Sessions only, never the fresh six or acceptance.
    ///
    /// # Errors
    /// Retains reentry, original association, funding, signed query or complete
    /// model refusal. The caller still owes the enclosing Pending Source post.
    pub(in crate::controller_service) fn collect_pending_sessions_once_v2<'root>(
        &mut self,
        pending: &mut aos_sandbox::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut aos_sandbox::ControllerDeletePendingRootClientOriginalV2<'root>,
        bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &'root aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
        local: &ControllerDeleteLocalRuntimeFieldsV1<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !self.complete || self.outer_after.is_some() || self.fresh_entered || self.fresh_closed.is_some() {
            self.fresh_closed.get_or_insert(ResourceReservationErrorV1::Conflict);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.fresh_entered = true;
        self.fresh_transfer_admission = Some((|| {
            let bytes = std::mem::size_of::<ControllerDeleteTransferFreshLoanV2<'_>>().checked_mul(3)
                .and_then(|n| n.checked_add(std::mem::size_of::<sha2::Sha256>().checked_mul(3)?))
                .and_then(|n| n.checked_add(aos_sandbox_protocol::domain_ledger::delete_root::
                    final_inventory::DELETE_ROOT_FRESH_TRANSFER_BYTES_V2.checked_mul(3)?))
                .and_then(|n| n.checked_add(48usize.checked_mul(3)?))
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let challenge = bank.borrow_retained_delete_pending_root_challenge_v2(pending, client, controller)?;
            bank.reserve_delete_pending_collection_v2(pending, controller, profile, &challenge, bytes)
        })());
        if !matches!(self.fresh_transfer_admission, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.fresh_transfer_read = Some(bank.receive_retained_delete_fresh_transfer_once_v2(
            pending, client, controller, profile,
        ));
        if !matches!(self.fresh_transfer_read, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.fresh_transfer_cut = Some((|| {
            let retained = &self.root.as_ref().ok_or(TransferCutFailureV2::Borrow(
                ResourceReservationErrorV1::Conflict))?.local;
            let loan = local.borrow_fresh_transfer_v2(retained, pending, client, bank, controller)
                .map_err(TransferCutFailureV2::Borrow)?;
            loan.completed_cut_data_v2().map_err(TransferCutFailureV2::Canonical)
        })());
        if !matches!(self.fresh_transfer_cut, Some(Ok(_))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let challenge = match bank.borrow_retained_delete_pending_root_challenge_v2(
            pending, client, controller,
        ) {
            Ok(challenge) => challenge,
            Err(cause) => {
                self.fresh_stages[0] = Some(Err(cause));
                return Err(ResourceReservationErrorV1::Conflict);
            }
        };
        let mut source = ControllerDeleteInventorySourceV2::Pending { pending, challenge: &challenge };
        self.session_writers.collect_delete_sessions_from_source_once_v2(
            &mut source, bank, controller, profile, &mut self.fresh_sessions,
            &mut self.fresh_stages,
        )?;
        derive_broker_models_from_originals_v2(
            &self.fresh_sessions, &mut self.fresh_models, &mut self.fresh_cuts,
            &mut self.fresh_model_admission, &mut source, bank, controller, profile,
        )?;
        self.fresh_sessions_complete = true;
        drop(source);
        self.fresh_stages[4] = Some(match bank.begin_retained_delete_pending_cache_once_v2(
            &mut self.cache, pending, controller, profile, &challenge,
        ) {
            Ok(mut query) => {
                if query.run_once_v1().is_err() {
                    // The same canonical Cache owner still holds its borrowed
                    // native originals on this failure, as in planning. Its
                    // direct outer post runs before fail-held termination.
                    let _after = query.finish_outer_source_failure_once_v1();
                    std::process::abort();
                }
                self.cache = Some(query.finish_positive_once_v1());
                Ok(())
            }
            Err(cause) => Err(cause),
        });
        if !matches!(self.fresh_stages[4], Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let mut source = ControllerDeleteInventorySourceV2::Pending { pending, challenge: &challenge };
        self.fresh_cache_cut = Some(derive_cache_cut_from_original_v2(self.cache.as_ref(),
            &mut source, bank, controller, profile));
        if !matches!(self.fresh_cache_cut, Some(Ok(_))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        drop(source);
        drop(challenge);
        // The exclusive Session guards, actual Cache and never-opened Transfer
        // stay on this same collection. Pay copied comparison carriers before
        // constructing the frame; the actual Bank client captures C itself.
        self.resource_exchange_admission = Some((|| {
            let bytes = std::mem::size_of::<[
                aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchOwnerCutDataV2; 6]>()
                .checked_mul(3).ok_or(ResourceReservationErrorV1::Conflict)?;
            let challenge = bank.borrow_retained_delete_pending_root_challenge_v2(pending, client, controller)?;
            bank.reserve_delete_pending_collection_v2(pending, controller, profile, &challenge, bytes)
        })());
        if !matches!(self.resource_exchange_admission, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.resource_exchange = Some((|| {
            if !self.fresh_sessions_complete || self.fresh_closed.is_some()
                || self.fresh_stages[..5].iter().any(|stage| !matches!(stage, Some(Ok(()))))
                || !matches!(self.fresh_transfer_read, Some(Ok(()))) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let cut = |index: usize| self.fresh_cuts[index].as_ref()
                .and_then(|r| r.as_ref().ok()).copied().ok_or(ResourceReservationErrorV1::Conflict);
            let cache = self.fresh_cache_cut.as_ref().and_then(|r| r.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            let transfer = self.fresh_transfer_cut.as_ref().and_then(|r| r.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            let (nonce, cutoff) = self.cache.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?
                .coordinates_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            bank.exchange_retained_delete_resource_draft_once_v2(pending, client, controller, profile,
                [cut(0)?, cut(1)?, cut(2)?, cut(3)?, cache, transfer], nonce, cutoff)
        })());
        if !matches!(self.resource_exchange, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        // This owner still holds all four exclusive Session writers and the
        // exact fresh packet/native/model originals used by Root's draft.
        let session = session_preimage_from_originals_v2(&self.fresh_sessions, &self.fresh_models, 2)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let model = self.fresh_models[2].as_ref().and_then(|r| r.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        self.resource_signing.sign_once_v2(bank, pending, client, controller, profile,
            local, model, session)?;
        self.preparatory_approval = Some(bank.receive_retained_delete_preparatory_approval_once_v3(
            pending, client, controller, profile));
        if !matches!(self.preparatory_approval, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.source_readiness = Some(bank.prepare_retained_delete_source_readiness_once_v3(
            pending, client, controller, profile));
        if !matches!(self.source_readiness, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.controller_acceptance = Some(bank.accept_retained_delete_controller_once_v3(
            pending, client, controller, profile));
        if !matches!(self.controller_acceptance, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.prepare_storage_catalog_once_v3(pending, client, bank, controller, profile)?;
        self.prepare_storage_apply_resources_once_v3(pending, client, bank, controller, profile, local)?;
        self.prepare_network_resources_once_v4(pending, client, bank, controller, profile, local)?;
        self.apply_network_once_v4(pending, client, bank, controller, profile)?;
        self.prepare_mount_resources_once_v4(pending, client, bank, controller, profile, local)?;
        self.reap_mount_once_v4(pending, client, bank, controller, profile)?;
        self.apply_storage_once_v3(pending, client, bank, controller, profile)?;
        self.complete_source_cleanup_once_v4(pending, client, bank, controller, profile)

    }

    fn derive_cache_cut_v2(
        &mut self,
        authorized: &mut ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) {
        let mut source = ControllerDeleteInventorySourceV2::Planning(authorized);
        self.cache_cut = Some(derive_cache_cut_from_original_v2(self.cache.as_ref(),
            &mut source, bank, controller, profile));
        drop(source);
        if !matches!(self.cache_cut, Some(Ok(_))) {
            self.finish_failed_outer_v2(authorized, bank, controller, profile);
        }
    }

    fn session_preimage_v2(&self, index: usize) -> Result<
        aos_sandbox_protocol::domain_ledger::delete_root::inventory_cuts::DeleteSessionInventoryCutDataV2<'_>,
        aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError,
    > {
        session_preimage_from_originals_v2(&self.sessions, &self.broker_models, index)
    }

    /// Borrows full canonical packet/native/model preimages from these same owners.
    ///
    /// This is initial planning DATA; fresh preaccept must use the pending Root
    /// challenge and independently verify signatures/currentness at the receiver.
    /// The actual answer/model owners remain borrowed for every returned slice.
    pub(in crate::controller_service) fn session_preimages_v2(&self) -> Result<[
        aos_sandbox_protocol::domain_ledger::delete_root::inventory_cuts::DeleteSessionInventoryCutDataV2<'_>; 4],
        ResourceReservationErrorV1,
    > {
        if !self.complete { return Err(ResourceReservationErrorV1::Conflict); }
        Ok([
            self.session_preimage_v2(0).map_err(|_| ResourceReservationErrorV1::Conflict)?,
            self.session_preimage_v2(1).map_err(|_| ResourceReservationErrorV1::Conflict)?,
            self.session_preimage_v2(2).map_err(|_| ResourceReservationErrorV1::Conflict)?,
            self.session_preimage_v2(3).map_err(|_| ResourceReservationErrorV1::Conflict)?,
        ])
    }

    fn owner_cut_data_v2(&self, index: usize) -> Option<
        aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchOwnerCutDataV2,
    > {
        let value = match index {
            0..=3 => self.broker_cuts[index].as_ref().and_then(|value| value.as_ref().ok()),
            4 => self.cache_cut.as_ref().and_then(|value| value.as_ref().ok()),
            5 => self.transfer_cut.as_ref().and_then(|value| value.as_ref().ok()),
            _ => None,
        };
        value.copied()
    }

    fn owner_cuts_data_v2(&self) -> Result<[
        aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchOwnerCutDataV2; 6],
        aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError,
    > {
        use aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError;
        Ok([
            self.owner_cut_data_v2(0).ok_or(LifecycleModelError::InvalidModel)?,
            self.owner_cut_data_v2(1).ok_or(LifecycleModelError::InvalidModel)?,
            self.owner_cut_data_v2(2).ok_or(LifecycleModelError::InvalidModel)?,
            self.owner_cut_data_v2(3).ok_or(LifecycleModelError::InvalidModel)?,
            self.owner_cut_data_v2(4).ok_or(LifecycleModelError::InvalidModel)?,
            self.owner_cut_data_v2(5).ok_or(LifecycleModelError::InvalidModel)?,
        ])
    }

    /// Returns only historical initial-planning commitments from these owners.
    ///
    /// This cannot replace fresh pending/preaccept or independent Root complete
    /// preimage verification. No caller supplies/adopts a cut into this frame.
    pub(in crate::controller_service) fn initial_six_preimage_data_v2(&self) -> Result<(
        [aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchOwnerCutDataV2; 6], [u8; 32]),
        ResourceReservationErrorV1,
    > {
        if !self.complete { return Err(ResourceReservationErrorV1::Conflict); }
        let digest = self.initial_six.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let cuts = self.owner_cuts_data_v2().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        Ok((cuts, digest))
    }

    fn finish_failed_outer_v2(
        &mut self,
        authorized: &mut ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> ! {
        self.outer_after = Some(bank.finish_delete_planning_source_failure_once_v1(
            authorized, controller, profile,
        ));
        // All prior answers, Cache/native originals and any entered Root owner
        // remain on self while the actual enclosing independent post executes.
        std::process::abort()
    }
}

fn session_preimage_from_originals_v2<'borrow>(
    sessions: &'borrow [Option<DeleteInventoryAnswerOriginalsV1>; 4],
    models: &'borrow [Option<Result<aos_sandbox::lifecycle::DeletePlanningBrokerInventoryDataV2,
        aos_sandbox::lifecycle::LifecyclePhase6ErrorV1>>; 4],
    index: usize,
) -> Result<aos_sandbox_protocol::domain_ledger::delete_root::inventory_cuts::DeleteSessionInventoryCutDataV2<'borrow>,
    aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError>
{
    use aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError;
    let answer = sessions.get(index).and_then(Option::as_ref)
        .ok_or(LifecycleModelError::InvalidModel)?;
    let model = models.get(index).and_then(Option::as_ref)
        .and_then(|model| model.as_ref().ok()).ok_or(LifecycleModelError::InvalidModel)?;
    let (count, generation, commitment) = model.complete_model_data_v2()
        .ok_or(LifecycleModelError::InvalidModel)?;
    Ok(aos_sandbox_protocol::domain_ledger::delete_root::inventory_cuts::DeleteSessionInventoryCutDataV2 {
        role: (index + 1) as u8, outcome: answer.outcome_v1(),
        kernel_boot: answer.kernel_boot_data_v2(), native: answer.native_boundary_data_v2(),
        protected: answer.protected_cut_data_v2(), inventory: (generation, commitment), count,
    })
}


// Initial and fresh callers share the same source-bound decoder, boot join and
// full native/packet/model cut recipe. Each failed Result stays in its supplied
// owning destination before another role is entered.
fn derive_broker_models_from_originals_v2(
    answers: &[Option<DeleteInventoryAnswerOriginalsV1>; 4],
    models: &mut [Option<Result<aos_sandbox::lifecycle::DeletePlanningBrokerInventoryDataV2,
        aos_sandbox::lifecycle::LifecyclePhase6ErrorV1>>; 4],
    cuts: &mut [Option<Result<aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchOwnerCutDataV2,
        aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError>>; 4],
    admission: &mut Option<Result<(), ResourceReservationErrorV1>>,
    source: &mut ControllerDeleteInventorySourceV2<'_, '_, '_, '_>,
    bank: &aos_sandbox::ControllerResourceBankOpeningV1,
    controller: &mut Journal,
    profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
) -> Result<(), ResourceReservationErrorV1> {
    *admission = Some((|| {
        let [Some(host), Some(mount), Some(storage), Some(network)] = answers.each_ref().map(Option::as_ref)
        else { return Err(ResourceReservationErrorV1::Conflict); };
        let boot = host.kernel_boot_data_v2();
        if boot == [0; 16] || [mount, storage, network].into_iter()
            .any(|answer| answer.kernel_boot_data_v2() != boot) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let demand = aos_sandbox::lifecycle::delete_planning_broker_inventory_receiving_demand_v2([
            host.outcome_v1(), mount.outcome_v1(), storage.outcome_v1(), network.outcome_v1(),
        ]).ok_or(ResourceReservationErrorV1::Conflict)?;
        let bytes = usize::try_from(demand.get(aos_sandbox_core::ResourceDimension::MemoryBytes))
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        source.reserve_model_bytes_v2(bank, controller, profile, bytes)
    })());
    if !matches!(admission, Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }
    for index in 0..4 {
        let answer = answers[index].as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        models[index] = Some(aos_sandbox::lifecycle::DeletePlanningBrokerInventoryDataV2::
            from_outcome_data_v2((index + 1) as u8, answer.outcome_v1(), answer.kernel_boot_data_v2()));
        if !matches!(models[index], Some(Ok(_))) { return Err(ResourceReservationErrorV1::Conflict); }
        cuts[index] = Some(session_preimage_from_originals_v2(answers, models, index)
            .and_then(|preimage| preimage.owner_cut_data_v2()));
        if !matches!(cuts[index], Some(Ok(_))) { return Err(ResourceReservationErrorV1::Conflict); }
    }
    Ok(())
}


fn derive_cache_cut_from_original_v2(
    cache: Option<&aos_sandbox::cache_residency::CacheDeleteInventoryOriginalV1<'_>>,
    source: &mut ControllerDeleteInventorySourceV2<'_, '_, '_, '_>,
    bank: &aos_sandbox::ControllerResourceBankOpeningV1,
    controller: &mut Journal,
    profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
) -> Result<aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchOwnerCutDataV2, CacheCutFailureV2> {
            use aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError;
            use aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::CacheJournalDataV1;
            // No duplicate row Vec is built. Pay the actual fixed five-name
            // array, borrowed row iterator, SHA, per-row pair and name encoding.
            let bytes = std::mem::size_of::<[CacheJournalDataV1; 5]>()
                .checked_add(std::mem::size_of::<std::slice::Iter<'_, aos_sandbox::lifecycle::LifecycleBootDomainEntryV1>>())
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<(
                    aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleResourceV1, [u8; 32])>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<sha2::Sha256>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::CachePhysicalDataV1>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<aos_sandbox::cache_residency::CacheOwnerLimitsV1>()))
                .and_then(|bytes| bytes.checked_add(48 + 128)).and_then(|bytes| bytes.checked_mul(3))
                .ok_or(CacheCutFailureV2::Canonical(LifecycleModelError::InvalidModel))?;
            source.reserve_model_bytes_v2(bank, controller, profile, bytes)
                .map_err(CacheCutFailureV2::Admission)?;
            let cache = cache
                .ok_or(CacheCutFailureV2::Canonical(LifecycleModelError::InvalidModel))?;
            let writers = cache.native_coordinates_v1().map_err(CacheCutFailureV2::Original)?;
            let physical = cache.physical_comparison_data_v2().map_err(CacheCutFailureV2::Physical)?;
            let (nonce, cutoff) = cache.coordinates_v1().map_err(CacheCutFailureV2::Original)?;
            let root = cache.root_v1().map_err(CacheCutFailureV2::Original)?;
            let rows = cache.entries_v1().map_err(CacheCutFailureV2::Original)?;
            aos_sandbox_protocol::domain_ledger::delete_root::inventory_cuts::cache_inventory_cut_data_v2(
                &writers, physical, nonce, cutoff, *root.as_bytes(),
                rows.iter().map(|row| (row.resource(), *row.identity().as_bytes())),
            ).map_err(CacheCutFailureV2::Canonical)

}
