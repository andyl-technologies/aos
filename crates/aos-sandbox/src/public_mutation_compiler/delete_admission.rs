//! Pays and retains one Delete authorization prefix on the genuine C17 owner.
//!
//! The fixed Bank claims its declared Delete subdivision on the same C writer,
//! profile and Launch. Entry consumes the common full-vector native operation
//! for its entire actual finite declaration before copying/decoding the request
//! or observing credentials. Reached complete requirements must fit that same
//! consumed vector before further growth or IO. Successful
//! authorization lends only the same active loan to the protected planner;
//! neither this prefix nor its completion qualifies a dependency plan/effect.

#[cfg(target_os = "linux")]
mod source;
#[cfg(target_os = "linux")]
mod planning_nonce;
#[cfg(target_os = "linux")]
pub(crate) use planning_nonce::{PlanningNonce, PlanningClockError};
#[cfg(target_os = "linux")]
pub use source::{
    ControllerDeleteCandidateOriginalV2, ControllerDeleteSourceAuthorizedScopeV1,
    ControllerDeletePendingOriginalV2, OriginalDeleteStoragePreparationLoanV3, OriginalDeleteStorageApplyLoanV3, OriginalDeleteNetworkApplyLoanV4, OriginalDeleteMountReapLoanV4,
};

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_core::{CapabilityId, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::boot::RootOriginalKernelBootIdAttemptV1;

use super::{AuthorizedPublicMutationRequestV1, PublicMutationAuthorizationErrorV1};
use crate::cli_model::authorization_adapter::{CurrentCapabilityDecisionV1,
    RetainedAuthorizationTimeFloorV1};
use crate::controller_resource_reservation::{ControllerResourceBankOpeningV1,
    ResourceReservationErrorV1};
use aos_sandbox_broker::controller_receiving::bank_launch::{
    ControllerOperationIntakeOriginalV1, ControllerOperationIntakeReceivingLoanV1,
    ControllerOperationIntakeDemandDataV1,
};
use crate::normal_root::ProductionControllerNormalRootProfileV1;
use crate::public_api_session::{PublicApiPeer, PublicApiPeerRecheckV1};
use crate::Journal;

const MAXIMUM_DELETE_ENVELOPE_BYTES: usize = 14 + 64 * 1024;

pub(crate) use super::authorization_native::PublicMutationAuthorizationNativeV1
    as DeleteAuthorizationNativeV1;

/// Owns the intrinsic Delete claim and all reached authorization originals.
///
/// Only the genuine Bank constructor below creates this private owner. It has
/// no vector/DTO constructor, detached C account or retry/reset method.
#[doc(hidden)]
pub struct ControllerDeleteAuthorizationOriginalV1 {
    // Native Drop refuses to release an active/failed original before any
    // later field can destroy its credential files or uncertainty evidence.
    native: ControllerOperationIntakeOriginalV1,
    input: Vec<u8>,
    authorization_native: DeleteAuthorizationNativeV1,
    handle: Option<Result<CapabilityId, crate::ControllerServiceError>>,
    authorization: Option<Result<AuthorizedPublicMutationRequestV1, PublicMutationAuthorizationErrorV1>>,
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    post: Option<Result<(), ResourceReservationErrorV1>>,
    attempted: bool,
    runtime_construction: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    runtime_funding_selected: bool,
}

/// Continuously borrows the actual paid C17 operation across later planning.
#[must_use]
#[doc(hidden)]
pub struct ControllerDeleteAuthorizedScopeV1<'owner> {
    native: ControllerOperationIntakeReceivingLoanV1<'owner>,
    authorization_demand: ResourceVector,
    runtime_construction: &'owner mut Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    runtime_funding_selected: &'owner mut bool,
    input: &'owner [u8],
    authorization_native: &'owner mut DeleteAuthorizationNativeV1,
    handle: &'owner Option<Result<CapabilityId, crate::ControllerServiceError>>,
    authorization: &'owner Option<Result<AuthorizedPublicMutationRequestV1, PublicMutationAuthorizationErrorV1>>,
    entry: &'owner Option<Result<(), ResourceReservationErrorV1>>,
    post: &'owner mut Option<Result<(), ResourceReservationErrorV1>>,
}

impl ControllerDeleteAuthorizationOriginalV1 {
    /// Claims only the actual image-declared C17 subdivision before construction.
    ///
    /// # Errors
    /// Refuses missing or already claimed purpose17, changed actual C/profile/
    /// Launch, arithmetic overflow or insufficient same-original capacity.
    pub fn claim_once_v1(
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<Self, ResourceReservationErrorV1> {
        let native = bank.claim_declared_delete_operation_intake_once_v1(
            controller, profile, ControllerOperationIntakeDemandDataV1::from_demand_v1(
                Self::resident_demand_v2()?,
            ),
        )?;
        Ok(Self::from_funded_intake_v2(native))
    }

    pub(crate) fn resident_demand_v2() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bytes = size_of::<Self>().checked_mul(2)
            .and_then(|n| u64::try_from(n).ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    // The genuine bank issuer supplies custody, rather than a reconstructed
    // predecessor claim or a caller-selected resource declaration.
    pub(crate) fn from_funded_intake_v2(native: ControllerOperationIntakeOriginalV1) -> Self {
        Self {
            native,
            input: Vec::new(),
            authorization_native: DeleteAuthorizationNativeV1::new(),
            handle: None,
            authorization: None,
            entry: None,
            post: None,
            attempted: false,
            runtime_construction: None,
            runtime_funding_selected: false,
        }
    }

    pub(crate) fn bind_recovered_enrollment_once_v2(
        &mut self,
        bank: &ControllerResourceBankOpeningV1,
        enrolled: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerRecoveredEnrollmentReceivingV2,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        bank.bind_recovered_operation_intake_once_v2(
            &mut self.native, enrolled, controller, profile,
        )
    }

    /// Checks placement of this actual unentered recovered Delete owner.
    ///
    /// This comparison grants no authorization, observation or native effect.
    ///
    /// # Errors
    /// Refuses prior entry, initial funding, a foreign bank or changed enrollment.
    #[doc(hidden)]
    pub fn require_unentered_recovered_runtime_placement_v2(
        &self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        use aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeFundingKindDataV2 as Kind;

        if self.attempted || self.entry.is_some()
            || self.native.funding_kind_data_v2() != Kind::RecoveredBaseline
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        bank.require_funded_operation_intake_entry_v2(&self.native, controller, profile)
    }

    /// Pays the reached authorization recipe before input/model/native growth.
    ///
    /// The returned scope also owns a failed body: its same C native post is
    /// still owed and must be completed through `finish_without_source_v1`.
    /// A positive caller keeps the scope continuously borrowed while joining
    /// the actual Source writer and protected Root dependency-plan consumer.
    ///
    /// # Errors
    /// Refuses reentry, oversized input or fixed admission before body growth.
    /// An entered body failure stays on the returned scope through owed posts.
    pub fn authorize_once_v1<'owner>(
        &'owner mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        peer: &PublicApiPeer,
        capability: CapabilityId,
        handle: &[u8],
        encoded: &[u8],
    ) -> Result<ControllerDeleteAuthorizedScopeV1<'owner>, ResourceReservationErrorV1> {
        if self.attempted {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.attempted = true;
        let demand = authorization_demand_v1(controller, peer, encoded.len())?;
        let native = bank.begin_delete_whole_declared_v1(
            &mut self.native, controller, profile,
            ControllerOperationIntakeDemandDataV1::from_demand_v1(demand),
        )?;
        self.entry = Some(bank.require_operation_intake_current_v1(&native, controller, profile));
        if matches!(self.entry, Some(Ok(()))) {
            self.input.extend_from_slice(encoded);
            self.handle = Some(crate::controller::resolve_delete_capability_handle_retaining_v1(
                controller, peer, capability, handle, &mut self.authorization_native.handle_peers,
            ));
            if matches!(self.handle, Some(Ok(_))) {
                self.authorization = Some(AuthorizedPublicMutationRequestV1::authorize_delete_retaining_v1(
                    controller, peer, capability, &self.input, &mut self.authorization_native,
                ));
            }
        }
        Ok(ControllerDeleteAuthorizedScopeV1 {
            native, authorization_demand: demand,
            runtime_construction: &mut self.runtime_construction,
            runtime_funding_selected: &mut self.runtime_funding_selected, input: &self.input,
            authorization_native: &mut self.authorization_native, handle: &self.handle,
            authorization: &self.authorization, entry: &self.entry, post: &mut self.post,
        })
    }

    /// Borrows the original entry/body cause before any separately owed post.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.entry.as_ref().and_then(|result| result.as_ref().err())
            .and_then(|_| self.native.failure())
            .or_else(|| self.entry.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.authorization_native.failure())
            .or_else(|| self.handle.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.authorization.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.runtime_construction.as_ref()?.as_ref().err()
                .and_then(|_| self.runtime_funding_selected.then(|| self.native.failure()).flatten()))
            .or_else(|| self.runtime_construction.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.native.failure())
            .or_else(|| self.post.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

/// Keeps the actual checked request and input beside the same C17 native loan.
pub(crate) struct DeleteAuthorizationBindingV1<'authorization> {
    authorization: &'authorization AuthorizedPublicMutationRequestV1,
    input: &'authorization [u8],
    demand: ResourceVector,
    decision: &'authorization CurrentCapabilityDecisionV1,
}

impl DeleteAuthorizationBindingV1<'_> {
    pub(crate) fn authorization(&self) -> &AuthorizedPublicMutationRequestV1 {
        self.authorization
    }

    pub(crate) fn input(&self) -> &[u8] {
        self.input
    }

    pub(crate) fn demand(&self) -> ResourceVector {
        self.demand
    }

    /// Commits the retained decision, exact canonical request and lease edges.
    ///
    /// Length-prefixing the complete original request makes the preimage
    /// unambiguous. The nested revision uses the sole existing canonical
    /// protected-capability decision recipe; no policy Debug or field-order
    /// dependent serialization is introduced.
    pub(crate) fn authorization_cut_data_v2(&self) -> [u8; 32] {
        let claims = self.decision.capability().claims();
        aos_sandbox_protocol::domain_ledger::delete_root::named_cuts::DeleteAuthorizationCutDataV2 {
            project: *self.authorization.project().as_bytes(),
            caller: *self.authorization.caller().as_bytes(),
            input: self.input,
            revision: *self.decision.delete_revision_data_v2().digest().as_bytes(),
            channel: *claims.channel_binding.as_bytes(),
            capability_not_before: claims.not_before,
            capability_expires: claims.expires_at,
            policy_not_before: self.decision.policy().not_before(),
            policy_expires: self.decision.policy().expires_at(),
            authorized_wall: self.decision.authorized_wall_seconds(),
        }.digest_v2()
    }


    pub(crate) fn authorization_input_data_v2(&self) -> &[u8] { self.input }

    pub(crate) fn authorization_witness_fields_v2(
        &self,
        open: aos_sandbox_protocol::domain_ledger::delete_root::transport::DeleteRootOpenDataV2,
        challenge: aos_sandbox_protocol::domain_ledger::delete_root::transport::DeleteRootChallengeDataV2,
    ) -> Result<aos_sandbox_protocol::domain_ledger::delete_root::authorization::DeleteRootAuthorizationFieldsV2,
        aos_sandbox_protocol::domain_ledger::delete_root::transport::DeleteRootWireErrorV2> {
        use aos_sandbox_protocol::domain_ledger::delete_root::{authorization::DeleteRootAuthorizationFieldsV2,
            transport::DeleteRootWireErrorV2};
        let claims = self.decision.capability().claims();
        let fields = DeleteRootAuthorizationFieldsV2 {
            open: open.digest_v2()?, challenge: challenge.digest_v2()?,
            project: *self.authorization.project().as_bytes(), caller: *self.authorization.caller().as_bytes(),
            capability: *claims.id.as_bytes(),
            input_bytes: u64::try_from(self.input.len()).map_err(|_| DeleteRootWireErrorV2::Format)?,
            channel: *claims.channel_binding.as_bytes(), capability_not_before: claims.not_before,
            capability_expires: claims.expires_at, policy_not_before: self.decision.policy().not_before(),
            policy_expires: self.decision.policy().expires_at(),
            authorized_wall: self.decision.authorized_wall_seconds(),
        };
        fields.require_exchange_v2(open, challenge)?;
        Ok(fields)
    }

    /// Projects the actual paired authorization clock and exclusive lease end.
    ///
    /// The retained decision owns both validated leases. This DATA projection
    /// neither samples a new clock nor extends either original authorization.
    pub(crate) fn authorization_horizon_v1(&self) -> (aos_sandbox_core::RawPairedClockSample, i64) {
        (self.decision.clock(), self.decision.capability().claims().expires_at
            .min(self.decision.policy().expires_at()))
    }
}

impl<'owner> ControllerDeleteAuthorizedScopeV1<'owner> {
    /// Pays the concrete Runtime's retained wrapper headers before construction.
    ///
    /// The size is passive additional debt on this same authorized original.
    /// It cannot choose a purpose, change capacity or construct a native loan.
    /// The successful complete prefix remains included in later Source demand.
    ///
    /// # Errors
    /// Refuses repeat entry, zero or overflowing size, earlier authorization
    /// failure, changed originals or insufficient same-C17 capacity. The whole
    /// reached result remains resident; the early C post is still owed.
    #[doc(hidden)]
    pub fn reserve_runtime_construction_once_v3(
        &mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        construction_bytes: usize,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.runtime_construction.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        let result = (|| {
            if construction_bytes == 0 { return Err(ResourceReservationErrorV1::Conflict); }
            let bytes = u64::try_from(construction_bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let demand = self.authorization_demand.checked_add(
                ResourceVector::ZERO.with(D::MemoryBytes, bytes))?;
            let admitted = self.require_complete_v1(bank, controller, profile,
                ControllerOperationIntakeDemandDataV1::from_demand_v1(demand));
            *self.runtime_funding_selected = admitted.is_err()
                && self.native.failure_view_v1(profile.lower_original_v1()).is_some();
            admitted?;
            Ok(demand)
        })();
        *self.runtime_construction = Some(result);
        match self.runtime_construction.as_ref().and_then(|result| result.as_ref().ok()) {
            Some(demand) => { self.authorization_demand = *demand; Ok(()) }
            None => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    /// Resolves only an actual C native marker through the same held loan.
    pub(crate) fn native_failure_view_v1<'cause>(
        &'cause self,
        profile: &'cause ProductionControllerNormalRootProfileV1,
    ) -> Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeFailureViewV1<'cause>> {
        self.native.failure_view_v1(profile.lower_original_v1())
    }

    /// Borrows the exact currently authorized Delete without reconstructing it.
    pub(crate) fn authorization_v1(&self)
        -> Option<&AuthorizedPublicMutationRequestV1>
    {
        if !matches!(self.entry, Some(Ok(()))) || !matches!(self.handle, Some(Ok(_)))
            || self.authorization_native.failure().is_some()
            || matches!(self.runtime_construction, Some(Err(_)))
        {
            return None;
        }
        self.authorization.as_ref()?.as_ref().ok()
    }

    /// Borrows the same admitted input for digest and exact-plan comparisons.
    pub(crate) fn input_v1(&self) -> &[u8] { self.input }

    /// Returns the actual admitted authorization peak as non-authorizing DATA.
    ///
    /// A later complete planner requirement must include this still-held
    /// prefix alongside its reached Source/graph/Root/transport/native owners.
    pub(crate) fn authorization_demand_v1(&self) -> ResourceVector {
        self.authorization_demand
    }

    /// Checks a complete requirement before a new planning/native frontier.
    pub(crate) fn require_complete_v1(
        &mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        complete: ControllerOperationIntakeDemandDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.authorization_v1().is_none() || self.post.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        bank.require_delete_complete_v1(&mut self.native, controller, profile, complete)
    }

    /// Lends the actual operation only while its Delete authorization is held.
    pub(crate) fn receiving_for_source_v1<'scope>(
        &'scope mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<&'scope mut ControllerOperationIntakeReceivingLoanV1<'owner>, ResourceReservationErrorV1> {
        if self.authorization_v1().is_none() || self.post.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        bank.require_operation_intake_current_v1(&self.native, controller, profile)?;
        Ok(&mut self.native)
    }

    /// Splits immutable checked input from the actual exclusive financial loan.
    ///
    /// All native credential/peer originals remain on this same authorized
    /// scope. Neither returned reference reconstructs authorization or payment.
    ///
    /// # Errors
    /// Refuses absent authorization/decision, ended posts or changed same C/profile.
    pub(crate) fn split_for_source_v1<'scope>(
        &'scope mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(DeleteAuthorizationBindingV1<'scope>,
        &'scope mut ControllerOperationIntakeReceivingLoanV1<'owner>), ResourceReservationErrorV1>
    {
        if self.authorization_v1().is_none() || self.post.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        bank.require_operation_intake_current_v1(&self.native, controller, profile)?;
        let authorization = self.authorization.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let decision = self.authorization_native.decision.as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok((DeleteAuthorizationBindingV1 {
            authorization,
            input: self.input,
            demand: self.authorization_demand,
            decision,
        }, &mut self.native))
    }

    /// Runs the independently prepaid C post after an early authorization end.
    ///
    /// This does not dispose native owners or qualify any acceptance/effect.
    /// A Source-entered caller instead finishes through that actual joint scope.
    pub fn finish_without_source_v1(
        &mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) {
        if self.post.is_some() {
            return;
        }
        *self.post = Some(bank.finish_operation_intake_native_once_v1(
            &mut self.native, controller, profile,
        ));
    }
}

// This is a conservative requirement computed from actual held C DATA and the
// actual peer. It selects no account/ceiling/authority. All namespace entries
// remain on the original C; these parser containers add no namespace-entry fee.
fn authorization_demand_v1(
    controller: &Journal,
    peer: &PublicApiPeer,
    encoded: usize,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    if encoded == 0 || encoded > MAXIMUM_DELETE_ENVELOPE_BYTES {
        return Err(ResourceReservationErrorV1::Conflict);
    }
    let invalid = || ResourceReservationErrorV1::Conflict;
    let peer_demand = peer.retained_recheck_demand_v1().ok_or_else(invalid)?;
    let mut bytes = 0usize;
    let mut rows = 0usize;
    for (_, key, value) in controller.all_records() {
        bytes = bytes.checked_add(key.len()).and_then(|n| n.checked_add(value.len()))
            .ok_or_else(invalid)?;
        rows = rows.checked_add(1).ok_or_else(invalid)?;
    }
    let request = delete_decode_bytes_v1(encoded).ok_or_else(invalid)?;
    let models = authorization_model_bytes_v1(bytes, rows).ok_or_else(invalid)?;
    let boot = RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()
        .ok_or_else(invalid)?;
    let memory = size_of::<ControllerDeleteAuthorizedScopeV1<'_>>().checked_mul(2)
        .and_then(|n| n.checked_add(size_of::<DeleteAuthorizationBindingV1<'_>>().checked_mul(3)?))
        .and_then(|n| n.checked_add(Journal::delete_semantic_scope_construction_bytes_v1()?))
        .and_then(|n| n.checked_add(source_authorized_construction_bytes_v1()?))
        .and_then(|n| n.checked_add(request))
        .and_then(|n| n.checked_add(models))
        .and_then(|n| n.checked_add(boot)).ok_or_else(invalid)?;
    Ok(peer_demand.checked_add(peer_demand)?.checked_add(peer_demand)?
        .checked_add(peer_demand)?.checked_add(ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| invalid())?)
        .with(D::OpenFiles, 1).with(D::MetadataEntries, 1))?)
}

fn source_authorized_construction_bytes_v1() -> Option<usize> {
    #[cfg(target_os = "linux")]
    {
        size_of::<ControllerDeleteSourceAuthorizedScopeV1<'_, '_>>().checked_mul(3)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

pub(crate) mod geometry;
use geometry::{delete_decode_bytes_v1, authorization_model_bytes_v1};
