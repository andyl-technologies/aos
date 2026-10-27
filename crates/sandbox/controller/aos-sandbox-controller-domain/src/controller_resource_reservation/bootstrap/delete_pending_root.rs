//! Keeps pending Delete Root projections on the Bank's actual saved Launch.
//!
//! The negative post uses the same continuously held pending Source/C17 owner.
//! It creates no new purpose, pending fence, Root challenge or disposal proof.

use super::*;

mod host_confirmation;
mod cleanup_current;
mod mount;
mod completion;
pub use completion::ControllerDeleteFinalDisposalOriginalV4;

impl ControllerResourceBankOpeningV1 {
    /// Completes the already owed Source/C17 after while failed Root stays held.
    ///
    /// This terminal failure path retains the actual post Result on the same
    /// pending original. The caller must keep the Root and Collection owners
    /// resident through this call, then fail closed without healthy reentry.
    ///
    /// # Errors
    /// Refuses missing saved Launch, repeated closure or the original native
    /// Source/C17 post failure; its owned cause remains on the pending original.
    #[doc(hidden)]
    pub fn finish_delete_pending_source_failure_once_v2(
        &self,
        pending: &mut crate::ControllerDeletePendingOriginalV2<'_, '_>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        pending
            .finish_outer_failure_once_v2(controller, launch, profile.lower_original_v1())
            .map_err(Into::into)
    }
}

/// Retains the actual original D Root socket and all native failure custody.
///
/// Only the saved-Launch Bank entrance constructs this owner. Raw frame, ACK,
/// native coordinates or comparison DATA cannot create it or its query loan.
#[doc(hidden)]
#[must_use]
pub struct ControllerDeletePendingRootClientOriginalV2<'profile> {
    inner: crate::normal_root::RootDeleteClientOriginalV1<'profile>,
}

/// Borrows the actual ACK-gated Root challenge for one genuine native query.
///
/// No public constructor, conversion or supplied result creates this loan.
/// The same Pending Source/C17 and exclusive Session collection remain held by
/// the real caller; these DATA getters supply no standalone native authority.
#[doc(hidden)]
pub struct ControllerDeletePendingRootChallengeLoanV2<'query> {
    inner: crate::normal_root::RootDeleteChallengeLoanV1<'query>,
}

impl<'query> ControllerDeletePendingRootChallengeLoanV2<'query> {
    /// Borrows the actual fresh Root query nonce after complete ACK custody.
    #[must_use]
    pub fn nonce_v2(&self) -> &[u8; 16] {
        self.inner.nonce_v1()
    }

    /// Gives the unchanged original Root/authorization-clamped query cutoff.
    #[must_use]
    pub fn cutoff_v2(&self) -> u64 {
        self.inner.cutoff_v1()
    }

    /// Borrows the actual sent version2 opening, without regenerating V1.
    #[must_use]
    pub fn open_encoding_v2(&self) -> &[u8; 208] {
        self.inner.open_encoding_v2()
    }

    /// Borrows the actual received version2 challenge from the same socket.
    #[must_use]
    pub fn challenge_encoding_v2(&self) -> &[u8; 224] {
        self.inner.challenge_encoding_v2()
    }

    pub(crate) fn actual_challenge_v2(
        &self,
    ) -> &crate::normal_root::RootDeleteChallengeLoanV1<'query> {
        &self.inner
    }
}

impl<'profile> ControllerDeletePendingRootClientOriginalV2<'profile> {
    /// Selects a retained Root or Source funding cause after a cleanup refusal.
    ///
    /// This diagnostic selector grants no query, native borrow or operation.
    #[doc(hidden)]
    #[must_use]
    pub fn host_cleanup_original_failure_is_selected_v4(
        &self,
        pending: &crate::ControllerDeletePendingOriginalV2<'_, '_>,
    ) -> bool {
        self.inner.failure().is_some()
            || self.inner.pending_intake_failure_view_v2(pending).is_some()
    }

    /// Borrows the original first native, framing or currentness cause.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.failure()
    }

    /// Lends guarded chronological native/financial diagnostics while owners live.
    #[must_use]
    pub fn failure_view_v2<'borrow, 'scope, 'original>(
        &'borrow self,
        pending: &'borrow crate::ControllerDeletePendingOriginalV2<'scope, 'original>,
    ) -> ControllerDeletePendingRootFailureViewV2<'borrow, 'profile, 'scope, 'original> {
        ControllerDeletePendingRootFailureViewV2 {
            client: self,
            pending,
        }
    }
}

/// Formats the first actual guarded error without extending an archive borrow.
#[doc(hidden)]
pub struct ControllerDeletePendingRootFailureViewV2<'borrow, 'profile, 'scope, 'original> {
    client: &'borrow ControllerDeletePendingRootClientOriginalV2<'profile>,
    pending: &'borrow crate::ControllerDeletePendingOriginalV2<'scope, 'original>,
}

impl std::fmt::Display for ControllerDeletePendingRootFailureViewV2<'_, '_, '_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(view) = self
            .client
            .inner
            .pending_intake_failure_view_v2(self.pending)
        {
            return std::fmt::Display::fmt(&view, f);
        }
        if let Some(view) = self.client.inner.current_turn_failure_view_v2() {
            return std::fmt::Display::fmt(&view, f);
        }
        if let Some(view) = self.client.inner.property_failure_view_v1() {
            return std::fmt::Debug::fmt(&view, f);
        }
        match self.client.failure_v2().or_else(|| self.pending.failure()) {
            Some(cause) => std::fmt::Display::fmt(cause, f),
            None => f.write_str("pending Delete Root failure is unavailable"),
        }
    }
}

impl std::fmt::Debug for ControllerDeletePendingRootFailureViewV2<'_, '_, '_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl ControllerResourceBankOpeningV1 {
    /// Begins the real pending Root exchange on this Bank's saved Launch.
    ///
    /// The wrapper and future short loan are paid before their construction.
    /// Entered native failures remain on the whole returned original.
    ///
    /// # Errors
    /// Refuses missing Launch, foreign/incomplete pending Source/C17 or a
    /// same-account financial refusal before native entry.
    #[doc(hidden)]
    pub fn begin_retained_delete_pending_root_client_v2<'profile>(
        &self,
        pending: &mut crate::ControllerDeletePendingOriginalV2<'_, '_>,
        controller: &mut Journal,
        profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<ControllerDeletePendingRootClientOriginalV2<'profile>, ResourceReservationErrorV1>
    {
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let bytes = std::mem::size_of::<ControllerDeletePendingRootClientOriginalV2<'_>>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<ControllerDeletePendingRootChallengeLoanV2<'_>>()
                        .checked_mul(3)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<ControllerDeletePendingRootFailureViewV2<'_, '_, '_, '_>>()
                        .checked_mul(3)?,
                )
            })
            .and_then(|bytes| bytes.checked_add(64usize.checked_mul(3)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let mut fence = pending.borrow_fence_v2()?;
        fence.reserve_preaccept_additional_v1(
            controller,
            launch,
            profile.lower_original_v1(),
            aos_sandbox_model::ResourceVector::ZERO
                .with(aos_sandbox_model::ResourceDimension::MemoryBytes, bytes),
        )?;
        let inner = crate::normal_root::RootDeleteClientOriginalV1::begin_pending_once_v1(
            &mut fence, controller, launch, profile,
        )?;
        Ok(ControllerDeletePendingRootClientOriginalV2 { inner })
    }

    /// Pays the complete initial-frame construction and lends its actual binding.
    ///
    /// The caller must hold its genuine initial-Six collection and exclusive
    /// Session writers through the later send and independently verified ACK.
    /// Only comparison digests are returned; no fresh challenge loan is lent.
    ///
    /// # Errors
    /// Refuses another profile, incomplete/failed original opening, changed
    /// Pending/C/Launch, original expiry or same-C17 financial refusal. Native
    /// and financial first causes remain on the actual client/pending owners.
    #[doc(hidden)]
    pub fn prepare_delete_initial_frame_data_v2(
        &self,
        pending: &mut crate::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut ControllerDeletePendingRootClientOriginalV2<'_>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<([u8; 32], [u8; 32]), ResourceReservationErrorV1> {
        client
            .inner
            .require_profile_v2(profile)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let mut fence = pending.borrow_fence_v2()?;
        client
            .inner
            .prepare_initial_frame_data_v2(&mut fence, controller, launch)
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    /// Sends the actual collection's preimages and receives the same-flight ACK.
    ///
    /// The caller keeps its exclusive four-Session collection resident through
    /// this call. The actual client pays its distinct native/IO/post reservoir
    /// before entry and permits no fresh loan until all afters and disposal.
    ///
    /// # Errors
    /// Retains original financial, native, framing, association, clock or owed
    /// post refusal on the client; the Pending Source outer post remains owed.
    #[doc(hidden)]
    pub fn send_retained_delete_initial_inventory_once_v2(
        &self,
        pending: &mut crate::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut ControllerDeletePendingRootClientOriginalV2<'_>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        frame: &aos_sandbox_protocol::domain_ledger::delete_root::initial_inventory::DeleteRootInitialFrameDataV3,
    ) -> Result<(), ResourceReservationErrorV1> {
        client
            .inner
            .require_profile_v2(profile)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let mut fence = pending.borrow_fence_v2()?;
        client
            .inner
            .exchange_initial_inventory_once_v2(&mut fence, controller, launch, frame)
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    /// Lends the actual ACK-gated challenge for one same-pending fresh query.
    ///
    /// The actual client rechecks the complete batch/native64/Claim/C position
    /// and immutable original horizon. No decoded ACK or DATA supplies the gate.
    ///
    /// # Errors
    /// Refuses missing/incomplete ACK, foreign Pending/C/Launch, uncertainty,
    /// expiration or unfinished local native disposal.
    #[doc(hidden)]
    pub fn borrow_retained_delete_pending_root_challenge_v2<'query>(
        &self,
        pending: &mut crate::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &'query mut ControllerDeletePendingRootClientOriginalV2<'_>,
        controller: &Journal,
    ) -> Result<ControllerDeletePendingRootChallengeLoanV2<'query>, ResourceReservationErrorV1>
    {
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let fence = pending.borrow_fence_v2()?;
        let inner = client
            .inner
            .borrow_challenge_v1(&fence, controller, launch)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        Ok(ControllerDeletePendingRootChallengeLoanV2 { inner })
    }
}


impl ControllerResourceBankOpeningV1 {
    /// Receives the fresh namespace/Ownership preimage on the original D socket.
    ///
    /// This enters one separately prepaid C17/Root read interval. Its comparison
    /// DATA becomes available only after all independent posts and actual local
    /// native disposal; the caller must rejoin its held default-local Runtime.
    ///
    /// # Errors
    /// Retains every entered native/framing/clock/financial refusal on the
    /// actual client. The same Pending Source outer after remains owed.
    #[doc(hidden)]
    pub fn receive_retained_delete_fresh_transfer_once_v2(&self,
        pending: &mut crate::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut ControllerDeletePendingRootClientOriginalV2<'_>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        client.inner.require_profile_v2(profile).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let mut fence = pending.borrow_fence_v2()?;
        client.inner.receive_fresh_transfer_once_v2(&mut fence, controller, launch)
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}

impl ControllerDeletePendingRootClientOriginalV2<'_> {
    /// Borrows complete comparison DATA from the actual completed fresh read.
    ///
    /// # Errors
    /// Refuses absent, uncertain, undisposed or failed original read custody.
    #[doc(hidden)]
    pub fn fresh_transfer_comparison_data_v2(&self)
        -> Result<&aos_sandbox_protocol::domain_ledger::delete_root::final_inventory::
            DeleteRootFreshTransferDataV2, ResourceReservationErrorV1>
    {
        self.inner.fresh_transfer_comparison_data_v2().map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}

impl ControllerResourceBankOpeningV1 {
    /// Sends fresh six/C preimages and receives the exact unsigned cleanup draft.
    ///
    /// The same saved Launch, pending Source/C17 and Root socket remain held.
    /// The full variable byte reservoir is paid after its checked header and
    /// before growth. Successful local disposal retains the passive body only;
    /// it gives neither signing authority nor public Delete acceptance.
    ///
    /// # Errors
    /// Refuses foreign or failed original custody, reentry, native uncertainty,
    /// malformed framing, expired original horizon or same-account funding.
    #[doc(hidden)]
    pub fn exchange_retained_delete_resource_draft_once_v2(&self,
        pending: &mut crate::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut ControllerDeletePendingRootClientOriginalV2<'_>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        owners: [aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchOwnerCutDataV2; 6],
        cache_nonce: [u8; 16], cache_cutoff: u64,
    ) -> Result<(), ResourceReservationErrorV1> {
        client.inner.require_profile_v2(profile).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let mut fence = pending.borrow_fence_v2()?;
        client.inner.exchange_resource_draft_once_v2(&mut fence, controller, launch,
            owners, cache_nonce, cache_cutoff).map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}

impl ControllerDeletePendingRootClientOriginalV2<'_> {
    /// Borrows draft comparison bytes after all actual read posts and disposal.
    ///
    /// This DATA cannot substitute for the later genuine current signing loan.
    ///
    /// # Errors
    /// Refuses missing, failed, incomplete or undisposed original read custody.
    #[doc(hidden)]
    pub fn resource_draft_comparison_data_v2(&self) -> Result<
        aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::DeleteRootResourceDraftDataV2<'_>,
        ResourceReservationErrorV1,
    > {
        self.inner.resource_draft_comparison_data_v2().map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}

impl ControllerResourceBankOpeningV1 {
    /// Receives the distinct apply draft on the actual completed26 cut.
    ///
    /// The accepted Controller, Source successor and native26 owners stay
    /// borrowed together; neither the response nor a decoded352 grants entry.
    ///
    /// # Errors
    /// Refuses incomplete original26 posts, changed native custody, an altered
    /// response, expired original horizons or the same C17 funding refusal.
    #[doc(hidden)]
    pub fn exchange_retained_delete_apply_resource_draft_once_v3(&self,
        pending: &mut crate::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut ControllerDeletePendingRootClientOriginalV2<'_>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        response: &aos_sandbox_api::aos::sandbox::local::v1::PrepareStorageCatalogResponse,
    ) -> Result<(), ResourceReservationErrorV1> {
        client.inner.require_profile_v2(profile).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let cut = pending.borrow_completed_preparation_cut_v3(controller)?;
        let (mut fence, accepted, preparation) = cut.into_parts_v3();
        client.inner.begin_apply_resource_exchange_once_v3(&mut fence, controller,
            launch, accepted, preparation, outcome, response)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        client.inner.exchange_apply_resource_draft_once_v3(&mut fence, controller,
            launch, accepted).map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}


/// Borrows the same live Delete original for one concrete cleanup signature.
///
/// Only the saved-Launch Bank entrance constructs this borrower. It retains the
/// actual Source fence beside the original Root client; no draft, plan, supplied
/// result or native position can construct it. Every entered attempt must finish
/// its independently prepaid posts, including a failed signer or transport.
#[doc(hidden)]
#[must_use = "finish the independently prepaid native posts on this same borrower"]
pub struct OriginalDeleteResourceSigningV2<'loan, 'journal, 'original, 'authorization, 'profile> {
    client: &'loan mut ControllerDeletePendingRootClientOriginalV2<'profile>,
    fence: crate::journal::SourceDeletePendingFenceV1<'loan, 'journal, 'original, 'authorization>,
    launch: &'loan aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchOriginalV1,
    purpose: OriginalDeleteResourceSigningPurposeV3<'loan>,
}

#[derive(Clone, Copy)]
enum OriginalDeleteResourceSigningPurposeV3<'loan> {
    Preparation,
    Apply {
        accepted: &'loan crate::journal::ControllerDeleteAdmissionOriginalV3,
        // Retain the actual completed native26 owner throughout this signer.
        _preparation: &'loan crate::DeleteStoragePreparationIoOriginalV3,
    },
}

impl ControllerDeletePendingRootClientOriginalV2<'_> {
    /// Reports whether the actual selected signing refusal belongs to its original.
    ///
    /// This diagnostic selector grants nothing. External key/completion errors
    /// remain on the Runtime owner; native/financial errors use this client's
    /// existing guarded same-pending failure view.
    #[doc(hidden)]
    #[must_use]
    pub fn resource_signing_original_failure_is_selected_v2(&self) -> bool {
        self.inner.resource_signing_original_failure_is_selected_v2()
    }
}

impl OriginalDeleteResourceSigningV2<'_, '_, '_, '_, '_> {
    /// Compares the exact Root draft with current protected C and Storage DATA.
    ///
    /// The actual fresh signed/native Storage cut must equal the completed
    /// same-D frame. The caller retains those Session originals throughout.
    ///
    /// # Errors
    /// Retains changed custody, model, lease, request, statement or clock causes
    /// on the actual client; the independent native after remains owed.
    pub fn prepare_once_v2(&mut self, controller: &Journal,
        model: &crate::lifecycle::DeletePlanningBrokerInventoryDataV2,
        session: aos_sandbox_protocol::domain_ledger::delete_root::inventory_cuts::DeleteSessionInventoryCutDataV2<'_>,
        authority: &aos_sandbox_protocol::authorization_artifact::SigningAuthority,
        scope: aos_sandbox_model::RevocationScopeId,
        verifier: &aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier,
    ) -> Result<(), ResourceReservationErrorV1> {
        match self.purpose {
            OriginalDeleteResourceSigningPurposeV3::Preparation =>
                self.client.inner.prepare_resource_signing_once_v2(&self.fence, controller,
                    self.launch, model, session, authority, scope, verifier),
            OriginalDeleteResourceSigningPurposeV3::Apply { accepted, .. } =>
                self.client.inner.prepare_apply_resource_signing_once_v3(&self.fence, controller,
                    self.launch, model, session, authority, scope, verifier, accepted),
        }.map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    /// Borrows the exact normalized preparation beside the genuine paid C17.
    ///
    /// # Errors
    /// Rejects missing or refused construction and changed actual custody.
    pub fn signing_preparation_v2(&mut self, controller: &Journal)
        -> Result<&aos_sandbox_protocol::authorization_artifact::BrokerPlanPreparation,
            ResourceReservationErrorV1> {
        match self.purpose {
            OriginalDeleteResourceSigningPurposeV3::Preparation =>
                self.client.inner.resource_signing_preparation_v2(&self.fence, controller, self.launch),
            OriginalDeleteResourceSigningPurposeV3::Apply { accepted, .. } =>
                self.client.inner.apply_resource_signing_preparation_v3(&self.fence, controller, self.launch, accepted),
        }.map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    /// Samples the separately paid final clock immediately before raw signing.
    ///
    /// # Errors
    /// Retains actual kernel, regression, original cutoff, policy or lease expiry
    /// refusal without renewing any window; all independent posts stay owed.
    pub fn final_signing_clock_once_v2(&mut self, controller: &Journal)
        -> Result<aos_sandbox_model::RawPairedClockSample, ResourceReservationErrorV1> {
        match self.purpose {
            OriginalDeleteResourceSigningPurposeV3::Preparation =>
                self.client.inner.final_resource_signing_clock_once_v2(&self.fence, controller, self.launch),
            OriginalDeleteResourceSigningPurposeV3::Apply { accepted, .. } =>
                self.client.inner.final_apply_resource_signing_clock_once_v3(&self.fence, controller, self.launch, accepted),
        }.map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    /// Parks and sends the actual completed signature for this exact draft.
    ///
    /// # Errors
    /// Retains signature association, allocation, encoding or native IO refusal.
    /// This grants no acceptance or effect and keeps the same D occupied.
    pub fn send_signed_once_v2(&mut self, controller: &Journal,
        signed: aos_sandbox_protocol::authorization_artifact::SignedBrokerPlan,
    ) -> Result<(), ResourceReservationErrorV1> {
        match self.purpose {
            OriginalDeleteResourceSigningPurposeV3::Preparation =>
                self.client.inner.send_resource_signature_once_v2(controller, &self.fence, self.launch, signed),
            OriginalDeleteResourceSigningPurposeV3::Apply { accepted, .. } =>
                self.client.inner.send_apply_resource_signature_once_v3(controller, &self.fence, self.launch, signed, accepted),
        }.map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    /// Closes the primary after an actual external signer refusal.
    ///
    /// This only denies completion. The real caller retains its typed signer
    /// error, prepared key and failed message while independent posts execute.
    pub fn refuse_signer_once_v2(&mut self) {
        self.client.inner.refuse_resource_signer_once_v2();
    }

    /// Runs every independent after and physically disposes positive scratch.
    ///
    /// # Errors
    /// Retains earlier body or native after refusal on the whole original.
    /// A positive return still grants no public acceptance or destruction.
    pub fn finish_once_v2(&mut self, controller: &mut Journal)
        -> Result<(), ResourceReservationErrorV1> {
        self.client.inner.finish_resource_signing_once_v2(controller)
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}

impl ControllerResourceBankOpeningV1 {
    /// Enters one fully prepaid concrete Delete-plan construction interval.
    ///
    /// Once native entry is reached, even a failed before is returned through
    /// the borrower so its real caller can run all independently owed posts.
    ///
    /// # Errors
    /// Refuses a different profile, incomplete same-pending draft, missing saved
    /// Launch, or the actual same-C17 funding refusal before native entry.
    #[doc(hidden)]
    pub fn begin_retained_delete_resource_signing_once_v2<'loan, 'journal, 'original, 'profile>(
        &'loan self,
        pending: &'loan mut crate::ControllerDeletePendingOriginalV2<'journal, 'original>,
        client: &'loan mut ControllerDeletePendingRootClientOriginalV2<'profile>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        authority: &aos_sandbox_protocol::authorization_artifact::SigningAuthority,
        verifier: &aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier,
    ) -> Result<OriginalDeleteResourceSigningV2<'loan, 'journal, 'original, 'journal, 'profile>,
        ResourceReservationErrorV1> {
        client.inner.require_profile_v2(profile).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let mut fence = pending.borrow_fence_v2()?;
        let loan_bytes = std::mem::size_of::<OriginalDeleteResourceSigningV2<'_, '_, '_, '_, '_>>()
            .checked_mul(3).and_then(|n| u64::try_from(n).ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
        fence.reserve_preaccept_additional_v1(controller, launch, profile.lower_original_v1(),
            aos_sandbox_model::ResourceVector::ZERO.with(aos_sandbox_model::ResourceDimension::MemoryBytes, loan_bytes))?;
        client.inner.begin_resource_signing_once_v2(&mut fence, controller, launch, authority, verifier)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        Ok(OriginalDeleteResourceSigningV2 { client, fence, launch, purpose: OriginalDeleteResourceSigningPurposeV3::Preparation })
    }

    /// Enters apply signing while the genuine completed26 owners stay borrowed.
    ///
    /// This uses the original concrete signing borrower and its independently
    /// prepaid posts. The purpose is selected only by this closed entrance.
    ///
    /// # Errors
    /// Refuses incomplete26 custody, changed profile or accepted Source/C17,
    /// missing Launch, failed apply draft or actual same-account funding.
    #[doc(hidden)]
    pub fn begin_retained_delete_apply_resource_signing_once_v3<'loan, 'journal, 'original, 'profile>(
        &'loan self,
        pending: &'loan mut crate::ControllerDeletePendingOriginalV2<'journal, 'original>,
        client: &'loan mut ControllerDeletePendingRootClientOriginalV2<'profile>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        authority: &aos_sandbox_protocol::authorization_artifact::SigningAuthority,
        verifier: &aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier,
    ) -> Result<OriginalDeleteResourceSigningV2<'loan, 'journal, 'original, 'journal, 'profile>,
        ResourceReservationErrorV1> {
        client.inner.require_resource_purpose_v4(
            aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::DeleteRootResourcePurposeDataV3::Apply7)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.begin_retained_delete_cleanup_signing_inner_v4(pending, client, controller, profile, authority, verifier)
    }

    /// Enters Network9 signing while actual26 and strict7 originals stay held.
    ///
    /// # Errors
    /// Retains changed purpose, actual Source/Controller/native custody or funding.
    #[doc(hidden)]
    pub fn begin_retained_delete_network_resource_signing_once_v4<'loan, 'journal, 'original, 'profile>(
        &'loan self,
        pending: &'loan mut crate::ControllerDeletePendingOriginalV2<'journal, 'original>,
        client: &'loan mut ControllerDeletePendingRootClientOriginalV2<'profile>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        authority: &aos_sandbox_protocol::authorization_artifact::SigningAuthority,
        verifier: &aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier,
    ) -> Result<OriginalDeleteResourceSigningV2<'loan, 'journal, 'original, 'journal, 'profile>,
        ResourceReservationErrorV1> {
        client.inner.require_resource_purpose_v4(
            aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::DeleteRootResourcePurposeDataV3::Network9)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.begin_retained_delete_cleanup_signing_inner_v4(pending, client, controller, profile, authority, verifier)
    }

    fn begin_retained_delete_cleanup_signing_inner_v4<'loan, 'journal, 'original, 'profile>(
        &'loan self,
        pending: &'loan mut crate::ControllerDeletePendingOriginalV2<'journal, 'original>,
        client: &'loan mut ControllerDeletePendingRootClientOriginalV2<'profile>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        authority: &aos_sandbox_protocol::authorization_artifact::SigningAuthority,
        verifier: &aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier,
    ) -> Result<OriginalDeleteResourceSigningV2<'loan, 'journal, 'original, 'journal, 'profile>,
        ResourceReservationErrorV1> {
        client.inner.require_profile_v2(profile).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let cut = pending.borrow_completed_preparation_cut_v3(controller)?;
        let (mut fence, accepted, preparation) = cut.into_parts_v3();
        let loan_bytes = std::mem::size_of::<OriginalDeleteResourceSigningV2<'_, '_, '_, '_, '_>>()
            .checked_mul(3).and_then(|n| u64::try_from(n).ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
        fence.reserve_preaccept_additional_v1(controller, launch, profile.lower_original_v1(),
            aos_sandbox_model::ResourceVector::ZERO.with(aos_sandbox_model::ResourceDimension::MemoryBytes, loan_bytes))?;
        client.inner.begin_apply_resource_signing_once_v3(&mut fence, controller,
            launch, authority, verifier, accepted).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        Ok(OriginalDeleteResourceSigningV2 { client, fence, launch,
            purpose: OriginalDeleteResourceSigningPurposeV3::Apply {
                accepted, _preparation: preparation,
            } })
    }
}


impl ControllerResourceBankOpeningV1 {
    /// Reads the exact concrete preparatory192 on the same live Delete socket.
    ///
    /// This does not release D or grant destructive dispatch. The actual client
    /// retains the frame only after full original/clock/native checks and local
    /// physical disposal. Public acceptance must use its later closed borrower.
    ///
    /// # Errors
    /// Retains funding, foreign custody, malformed or changed draft/signature,
    /// policy/original expiry, native IO or independently owed post refusal.
    #[doc(hidden)]
    pub fn receive_retained_delete_preparatory_approval_once_v3(&self,
        pending: &mut crate::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut ControllerDeletePendingRootClientOriginalV2<'_>, controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        client.inner.require_profile_v2(profile).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let mut fence = pending.borrow_fence_v2()?;
        client.inner.receive_preparatory_approval_once_v3(&mut fence, controller, launch)
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}

impl ControllerResourceBankOpeningV1 {
    /// Writes the finite Source readiness chain beside this Bank's actual Root client.
    ///
    /// The actual pending owner retains every plan, append result and Root
    /// interval. This does not accept the public Delete or dispatch cleanup.
    ///
    /// # Errors
    /// Refuses missing Launch, another Root profile, repeated entry, changed
    /// Source/C17 originals or a reached financial, native or semantic failure.
    #[doc(hidden)]
    pub fn prepare_retained_delete_source_readiness_once_v3(
        &self,
        pending: &mut crate::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut ControllerDeletePendingRootClientOriginalV2<'_>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        client.inner.require_profile_v2(profile)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        pending.prepare_source_readiness_once_v3(
            &mut client.inner, controller, launch, profile.lower_original_v1(),
        ).map_err(Into::into)
    }
}

impl ControllerResourceBankOpeningV1 {
    /// Receives the distinct signed7 approval beside the genuine completed26 cut.
    ///
    /// This retains the original socket, accepted Controller and Source state2
    /// fence. It lends no SDK7 request or destructive authority by itself.
    ///
    /// # Errors
    /// Refuses incomplete26 custody, purpose confusion, changed full352 or7
    /// signature, expired original horizons, native IO or any owed post.
    #[doc(hidden)]
    pub fn receive_retained_delete_apply_approval_once_v3(&self,
        pending: &mut crate::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut ControllerDeletePendingRootClientOriginalV2<'_>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        client.inner.require_profile_v2(profile).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let cut = pending.borrow_completed_preparation_cut_v3(controller)?;
        let (mut fence, accepted, _preparation) = cut.into_parts_v3();
        client.inner.receive_apply_approval_once_v3(&mut fence, controller, launch, accepted)
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}

impl ControllerResourceBankOpeningV1 {
    /// Accepts desired Delete state and records its Source cleanup debt.
    ///
    /// The same pending, Root client and C17 remain occupied for destruction.
    ///
    /// # Errors
    /// Refuses another profile, repeat entry, changed originals or any reached
    /// semantic, financial, native append, readback or independent post failure.
    #[doc(hidden)]
    pub fn accept_retained_delete_controller_once_v3(
        &self,
        pending: &mut crate::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut ControllerDeletePendingRootClientOriginalV2<'_>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        client.inner.require_profile_v2(profile).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        pending.accept_controller_once_v3(&mut client.inner, controller, launch, profile.lower_original_v1())
            .map_err(Into::into)
    }
}

impl ControllerResourceBankOpeningV1 {
    /// Returns the actual held signed26 packet bound as passive sizing DATA.
    #[doc(hidden)]
    #[must_use]
    pub fn retained_delete_preparation_request_bound_v3(&self,
        client: &ControllerDeletePendingRootClientOriginalV2<'_>,
    ) -> Option<usize> { client.inner.preparation_request_bound_v3() }

    /// Returns the actual approved7 request bound as passive sizing DATA.
    #[doc(hidden)]
    #[must_use]
    pub fn retained_delete_apply_request_bound_v3(&self,
        client: &ControllerDeletePendingRootClientOriginalV2<'_>,
    ) -> Option<usize> { client.inner.apply_request_bound_v3() }

    /// Returns the actual approved Destroy9 packet bound as passive sizing DATA.
    #[doc(hidden)]
    #[must_use]
    pub fn retained_delete_network_request_bound_v4(&self,
        client: &ControllerDeletePendingRootClientOriginalV2<'_>,
    ) -> Option<usize> { client.inner.network_request_bound_v4() }

    /// Borrows signed7 with the actual completed native26 predecessor retained.
    ///
    /// This same accepted Source/C17/Root interval remains borrowed through
    /// SDK return, every independent post and actual Session-window retirement.
    ///
    /// # Errors
    /// Refuses missing7 approval, changed or incomplete26 originals, a foreign
    /// profile, repeated entry, expired original horizons or actual funding.
    #[doc(hidden)]
    pub fn borrow_retained_delete_storage_apply_once_v3<'held, 'source, 'original, 'root>(
        &'held self, pending: &'held mut crate::ControllerDeletePendingOriginalV2<'source, 'original>,
        client: &'held mut ControllerDeletePendingRootClientOriginalV2<'root>,
        controller: &'held mut Journal,
        profile: &'held crate::normal_root::ProductionControllerNormalRootProfileV1,
        shape: crate::StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<crate::OriginalDeleteStorageApplyLoanV3<'held>, ResourceReservationErrorV1> {
        client.inner.require_profile_v2(profile).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        pending.borrow_storage_apply_once_v3(&mut client.inner, controller, launch,
            profile.lower_original_v1(), shape).map_err(Into::into)
    }

    /// Lends actual Root9 with the same accepted C/Source and fresh Network owner.
    ///
    /// The closed native interval keeps every original through SDK return,
    /// independently owed posts and actual finite Session-window retirement.
    ///
    /// # Errors
    /// Refuses another purpose/profile, incomplete26/352, changed strict9
    /// approval, stale actual Network19 cut, native or same-C17 financial failure.
    #[doc(hidden)]
    pub fn borrow_retained_delete_network_apply_once_v4<'held, 'source, 'original, 'root>(
        &'held self, pending: &'held mut crate::ControllerDeletePendingOriginalV2<'source, 'original>,
        client: &'held mut ControllerDeletePendingRootClientOriginalV2<'root>,
        controller: &'held mut Journal,
        profile: &'held crate::normal_root::ProductionControllerNormalRootProfileV1,
        inventory: aos_sandbox_protocol::domain_ledger::delete_root::inventory_cuts::DeleteSessionInventoryCutDataV2<'_>,
        shape: crate::StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<crate::OriginalDeleteNetworkApplyLoanV4<'held>, ResourceReservationErrorV1> {
        client.inner.require_profile_v2(profile).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        client.inner.require_resource_purpose_v4(
            aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::DeleteRootResourcePurposeDataV3::Network9)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        pending.borrow_network_apply_once_v4(&mut client.inner, controller, launch,
            profile.lower_original_v1(), inventory, shape).map_err(Into::into)
    }

    /// Lends signed26 only after actual C acceptance and Source ControllerCommitted.
    ///
    /// This same Source/C17/Root interval stays borrowed through SDK return,
    /// independent C/Root posts and actual finite Session-window retirement.
    ///
    /// # Errors
    /// Retains foreign profile, changed full Root Storage cut, receiving refusal,
    /// reentry or an incomplete actual native acceptance/Source successor.
    #[doc(hidden)]
    pub fn borrow_retained_delete_storage_preparation_once_v3<'held, 'source, 'original, 'root>(
        &'held self, pending: &'held mut crate::ControllerDeletePendingOriginalV2<'source, 'original>,
        client: &'held mut ControllerDeletePendingRootClientOriginalV2<'root>,
        controller: &'held mut Journal,
        profile: &'held crate::normal_root::ProductionControllerNormalRootProfileV1,
        inventory: aos_sandbox_protocol::domain_ledger::delete_root::inventory_cuts::DeleteSessionInventoryCutDataV2<'_>,
        shape: crate::StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<crate::OriginalDeleteStoragePreparationLoanV3<'held>, ResourceReservationErrorV1> {
        client.inner.require_profile_v2(profile).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        pending.borrow_storage_preparation_once_v3(&mut client.inner, controller, launch,
            profile.lower_original_v1(), inventory, shape).map_err(Into::into)
    }
}

impl ControllerResourceBankOpeningV1 {
    /// Exchanges the Network9 draft on actual completed26 and strict7 originals.
    ///
    /// # Errors
    /// Refuses changed predecessor, profile, Source/C17 or actual native/funding work.
    #[doc(hidden)]
    pub fn exchange_retained_delete_network_resource_draft_once_v4(&self,
        pending: &mut crate::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut ControllerDeletePendingRootClientOriginalV2<'_>, controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        client.inner.require_profile_v2(profile).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let cut = pending.borrow_completed_preparation_cut_v3(controller)?;
        let (mut fence, accepted, preparation) = cut.into_parts_v3();
        client.inner.begin_network_resource_exchange_once_v4(&mut fence, controller, launch, accepted, preparation)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        client.inner.exchange_apply_resource_draft_once_v3(&mut fence, controller, launch, accepted)
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    /// Receives distinct Network9 approval on the same D and native originals.
    ///
    /// # Errors
    /// Refuses another purpose, changed full predecessor, exact9 signature or any post.
    #[doc(hidden)]
    pub fn receive_retained_delete_network_approval_once_v4(&self,
        pending: &mut crate::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut ControllerDeletePendingRootClientOriginalV2<'_>, controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        client.inner.require_profile_v2(profile).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        client.inner.require_resource_purpose_v4(
            aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::DeleteRootResourcePurposeDataV3::Network9)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let cut = pending.borrow_completed_preparation_cut_v3(controller)?;
        let (mut fence, accepted, _preparation) = cut.into_parts_v3();
        client.inner.receive_apply_approval_once_v3(&mut fence, controller, launch, accepted)
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}
