//! Owns the fresh original Delete Root opening and bounded challenge stage.
//!
//! Only the actual accepted flight supplies the socket and private Root peer.
//! This stage retains comparison bytes and real native/currentness debts; it
//! cannot accept Delete, validate six owners, publish a floor, dispose its
//! lifecycle guard or substitute for the still-required terminal conjunction.

mod body;
mod planning;
pub(crate) use planning::{RootDeletePlanningChallengeOriginalV1, RootDeletePlanningReceivingV1, RootDeletePlanningDispatchOriginalV1};
mod challenge;
mod controller;
mod reader;
pub(crate) use reader::inert_reader_construction_control_bytes_v1;
mod cache;
mod graph_objects;
mod graph_comparison;
pub(crate) use graph_objects::{GraphAdmissionPhaseV2, RootDeleteGraphObjectsOriginalV2};
pub(crate) use graph_comparison::RootDeleteGraphComparisonOriginalV2;
mod initial_inventory;
mod final_inventory;
mod resource_policy;
mod cleanup_inputs;
mod resource_selection;
pub(crate) use resource_selection::RootDeleteResourceSelectionOriginalV2;
mod resource_preparation;
mod resource_draft;
mod resource_signature;
mod preparation_current;
mod cleanup_current;
mod completion_current;
mod completion_dispatch;
pub(crate) use completion_dispatch::RootDeleteDispatchOriginalV4;
pub(crate) use completion_current::{RootDeleteCompletionCurrentOriginalV4, RootDeleteCompletionPhaseV4};
mod mount_spec;
pub(crate) use mount_spec::{RootDeleteMountSpecOriginalV4, RootDeleteMountSpecPhaseV4};
pub(crate) use cleanup_current::{RootDeleteCleanupCurrentOriginalV4, RootDeleteCleanupCurrentPhaseV4};
mod apply_issuer;
pub(crate) use apply_issuer::{RootDeleteApplyIssuerPhaseV3, ApplyStageOwnerV3, RootDeleteResourceContinuationV4};
pub(crate) use preparation_current::{RootDeletePreparationCurrentPhaseV3, RootDeletePreparationCurrentOriginalV3};
mod preparatory_approval;
pub(crate) use preparatory_approval::RootDeletePreparatoryApprovalOriginalV3;
pub(crate) use resource_signature::RootDeleteResourceSignatureOriginalV2;
pub(crate) use resource_draft::RootDeleteResourceDraftOriginalV2;
pub(crate) use resource_preparation::RootDeleteResourcePreparationOriginalV2;
pub(crate) use cleanup_inputs::{CleanupInputsPhaseV2, RootDeleteCleanupInputsOriginalV2};
pub(crate) use resource_policy::RootDeleteResourcePolicyOriginalV2;
pub(crate) use final_inventory::RootDeleteFreshInventoryOriginalV2;
pub(crate) use cache::RootDeleteCacheCurrentOriginalV2;
mod source;
mod floor;
mod transfer_namespace;
pub(crate) use transfer_namespace::RootDeleteTransferNamespaceOriginalV1;
pub(crate) use floor::RootDeleteFloorOriginalV1;
pub(crate) use source::{RootDeleteSourceCurrentOriginalV1, RootDeleteSourcePredecessorPhaseV2};
pub(crate) use controller::{RootDeleteControllerCurrentOriginalV1, RootDeleteControllerAdmissionPhaseV1};
pub(crate) use challenge::RootDeleteChallengeOriginalsV1;

use aos_sandbox_broker::bounded_stream_io::DeadlineStreamDirectionV1;
use aos_sandbox_broker::bounded_stream_io::FixedDeadlineStreamIoV1;
use super::root_policy_prelude::{RootPolicyPreludeOriginalV1, RootPolicyPurposeV1,
    RootPolicyDispositionGuardV1, RootPolicyPreludeNativeOriginalV1};
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use aos_sandbox_protocol::domain_ledger::delete_root::transport::{
    DELETE_ROOT_CHALLENGE_BYTES_V2, DELETE_ROOT_OPEN_BYTES_V2,
    DeleteRootOpenDataV2, DeleteRootWireErrorV2,
};
use std::error::Error as StdError;
use std::os::unix::net::UnixStream;

#[derive(Clone, Copy)]
enum First {
    OpeningClockAfter,
    Peer,
    OpeningPermit,
    Remainder,
    Open,
    Challenge,
    Send,
    Body,
    Controller,
    Authorization,
    BrokerTrust,
    Sessions,
    Cache,
    GraphObjects,
    GraphComparison,
    InitialInventory,
    FreshAdmission,
    FreshController,
    FreshFloor,
    ResourcePolicy,
    CleanupInputs,
    ResourceSelection,
    ResourcePreparation,
    ResourceDraft,
    ResourceSignature,
    ResourcePolicyConfirmation,
    PreparatoryApproval,
    PreparationCurrent,
    ApplyIssuer,
    NetworkIssuer,
    CleanupCurrent,
    MountIssuer,
    Completion,
    Source,
    PredecessorCuts,
    Floor,
    TransferNamespace,
    ClockAfter,
    PeerAfter,
    Reentry,
}

// No positive disposal exists until the actual six-owner/floor terminal joins.
/// Retains one fresh accepted D opening before any accepting continuation.
///
/// The whole selected prelude transfers its already-armed native owner and
/// original cutoff. The listener prepays the fixed constructor before accept;
/// the typed challenge additionally pays its
/// reached variable representation and wire schedule before native work.
pub(crate) struct RootDeletePendingReceivingV1<'flight, 'listener, 'startup> {
    disposition: RootPolicyDispositionGuardV1,
    original: UnixStream,
    flight: Option<&'flight mut RootPolicyAcceptedFlightV1<'listener, 'startup>>,
    prelude: RootPolicyPreludeNativeOriginalV1,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    bytes: [u8; DELETE_ROOT_OPEN_BYTES_V2],
    opening_permit:
        Option<Result<(), crate::controller_resource_reservation::ResourceReservationErrorV1>>,
    remainder_io: FixedDeadlineStreamIoV1<{ DELETE_ROOT_OPEN_BYTES_V2 - 32 }>,
    remainder_bytes: [u8; DELETE_ROOT_OPEN_BYTES_V2 - 32],
    remainder: Option<Result<(), RootDeleteErrorV1>>,
    decoded: Option<Result<DeleteRootOpenDataV2, DeleteRootWireErrorV2>>,
    challenge: RootDeleteChallengeOriginalsV1,
    challenge_result: Option<Result<(), NormalRootStartupErrorV1>>,
    response: [u8; DELETE_ROOT_CHALLENGE_BYTES_V2],
    sent: FixedDeadlineStreamIoV1<DELETE_ROOT_CHALLENGE_BYTES_V2>,
    body: body::RootDeleteBatchReceivingV1,
    body_result: Option<Result<(), RootDeleteErrorV1>>,
    controller: RootDeleteControllerCurrentOriginalV1,
    controller_result: Option<Result<(), RootDeleteErrorV1>>,
    authorization_result: Option<Result<(), RootDeleteErrorV1>>,
    broker_trust_result: Option<Result<(), RootDeleteErrorV1>>,
    initial_sessions_result: Option<Result<(), RootDeleteErrorV1>>,
    initial_sessions_comparison: Option<Result<(), RootDeletePredecessorCutErrorV2>>,
    cache: RootDeleteCacheCurrentOriginalV2,
    cache_result: Option<Result<(), RootDeleteErrorV1>>,
    graph_objects: RootDeleteGraphObjectsOriginalV2,
    graph_objects_result: Option<Result<(), RootDeleteErrorV1>>,
    graph_comparison: RootDeleteGraphComparisonOriginalV2,
    graph_comparison_result: Option<Result<(), RootDeleteErrorV1>>,
    initial_inventory: initial_inventory::RootDeleteInitialInventoryOriginalV2,
    initial_inventory_result: Option<Result<(), RootDeleteErrorV1>>,
    fresh_inventory: Option<Box<final_inventory::RootDeleteFreshInventoryOriginalV2>>,
    fresh_admission: Option<Result<(), crate::controller_resource_reservation::ResourceReservationErrorV1>>,
    fresh_result: Option<Result<(), RootDeleteErrorV1>>,
    fresh_floor: RootDeleteFloorOriginalV1,
    fresh_floor_result: Option<Result<(), RootDeleteErrorV1>>,
    resource_policy: RootDeleteResourcePolicyOriginalV2,
    resource_policy_result: Option<Result<(), RootDeleteErrorV1>>,
    cleanup_inputs: RootDeleteCleanupInputsOriginalV2,
    cleanup_inputs_result: Option<Result<(), RootDeleteErrorV1>>,
    resource_selection: RootDeleteResourceSelectionOriginalV2,
    resource_selection_result: Option<Result<(), RootDeleteErrorV1>>,
    resource_preparation: RootDeleteResourcePreparationOriginalV2,
    resource_preparation_result: Option<Result<(), RootDeleteErrorV1>>,
    resource_draft: RootDeleteResourceDraftOriginalV2,
    resource_draft_result: Option<Result<(), RootDeleteErrorV1>>,
    resource_signature: RootDeleteResourceSignatureOriginalV2,
    resource_signature_result: Option<Result<(), RootDeleteErrorV1>>,
    resource_policy_confirmation: RootDeleteResourcePolicyOriginalV2,
    resource_policy_confirmation_result: Option<Result<(), RootDeleteErrorV1>>,
    preparatory_approval: RootDeletePreparatoryApprovalOriginalV3,
    preparatory_approval_result: Option<Result<(), RootDeleteErrorV1>>,
    preparation_current: RootDeletePreparationCurrentOriginalV3,
    preparation_current_result: Option<Result<(), RootDeleteErrorV1>>,
    apply_issuer: apply_issuer::RootDeleteApplyIssuerOriginalV3,
    apply_issuer_result: Option<Result<(), RootDeleteErrorV1>>,
    network_issuer: apply_issuer::RootDeleteApplyIssuerOriginalV3,
    network_issuer_result: Option<Result<(), RootDeleteErrorV1>>,
    cleanup_current: RootDeleteCleanupCurrentOriginalV4,
    cleanup_current_result: Option<Result<(), RootDeleteErrorV1>>,
    mount_issuer: apply_issuer::RootDeleteApplyIssuerOriginalV3,
    mount_issuer_result: Option<Result<(), RootDeleteErrorV1>>,
    completion: RootDeleteCompletionCurrentOriginalV4,
    completion_result: Option<Result<(), RootDeleteErrorV1>>,
    source: RootDeleteSourceCurrentOriginalV1,
    source_result: Option<Result<(), RootDeleteErrorV1>>,
    predecessor_cuts: Option<Result<(), RootDeletePredecessorCutErrorV2>>,
    floor: RootDeleteFloorOriginalV1,
    floor_result: Option<Result<(), RootDeleteErrorV1>>,
    transfer_namespace: RootDeleteTransferNamespaceOriginalV1,
    transfer_namespace_result: Option<Result<(), RootDeleteErrorV1>>,
    clock_after: Option<Result<(), NormalRootStartupErrorV1>>,
    peer_after: Option<Result<(), NormalRootStartupErrorV1>>,
    opening: Option<Result<(), RootDeleteErrorV1>>,
    first: Option<First>,
    closed: Option<RootDeleteErrorV1>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RootDeleteErrorV1 {
    #[error("fresh Delete Root original is unavailable")]
    Original,
    #[error("fresh Delete Root opening is unavailable")]
    Opening,
}

#[derive(Debug, thiserror::Error)]
enum RootDeletePredecessorCutErrorV2 {
    #[error(transparent)]
    Original(#[from] RootDeleteErrorV1),
    #[error("independently observed authorization, Controller or Source predecessor differs from AOSDEL02")]
    Changed,
    #[error("Root's independently observed initial four Session cuts differ from AOSDEL02")]
    SessionChanged,
}

impl<'flight, 'listener, 'startup> RootDeletePendingReceivingV1<'flight, 'listener, 'startup> {
    pub(super) fn from_prelude_v1(
        prelude: RootPolicyPreludeOriginalV1<'flight, 'listener, 'startup>,
    ) -> Self {
        if prelude.purpose_v1() != Some(RootPolicyPurposeV1::Delete) {
            std::process::abort();
        }
        let RootPolicyPreludeOriginalV1 { disposition, original, flight, native, .. } = prelude;
        Self {
            disposition,
            original,
            flight: Some(flight),
            prelude: native,
            peer: None,
            bytes: [0; DELETE_ROOT_OPEN_BYTES_V2],
            opening_permit: None,
            remainder_io: Default::default(),
            remainder_bytes: [0; DELETE_ROOT_OPEN_BYTES_V2 - 32],
            remainder: None,
            decoded: None,
            challenge: Default::default(),
            challenge_result: None,
            response: [0; DELETE_ROOT_CHALLENGE_BYTES_V2],
            sent: Default::default(),
            body: Default::default(),
            body_result: None,
            controller: Default::default(),
            controller_result: None,
            authorization_result: None,
            broker_trust_result: None,
            initial_sessions_result: None,
            initial_sessions_comparison: None,
            cache: Default::default(),
            cache_result: None,
            graph_objects: Default::default(),
            graph_objects_result: None,
            graph_comparison: Default::default(),
            graph_comparison_result: None,
            initial_inventory: Default::default(),
            initial_inventory_result: None,
            fresh_inventory: None,
            fresh_admission: None,
            fresh_result: None,
            fresh_floor: Default::default(), fresh_floor_result: None,
            resource_policy: Default::default(), resource_policy_result: None,
            cleanup_inputs: Default::default(), cleanup_inputs_result: None,
            resource_selection: Default::default(), resource_selection_result: None,
            resource_preparation: Default::default(), resource_preparation_result: None,
            resource_draft: Default::default(), resource_draft_result: None,
            resource_signature: Default::default(), resource_signature_result: None,
            resource_policy_confirmation: Default::default(), resource_policy_confirmation_result: None,
            preparatory_approval: Default::default(), preparatory_approval_result: None,
            preparation_current: Default::default(), preparation_current_result: None,
            apply_issuer: Default::default(), apply_issuer_result: None,
            network_issuer: Default::default(), network_issuer_result: None,
            cleanup_current: Default::default(), cleanup_current_result: None,
            mount_issuer: Default::default(), mount_issuer_result: None,
            completion: Default::default(), completion_result: None,
            source: Default::default(),
            source_result: None,
            predecessor_cuts: None,
            floor: Default::default(),
            floor_result: None,
            transfer_namespace: Default::default(),
            transfer_namespace_result: None,
            clock_after: None,
            peer_after: None,
            opening: None,
            first: None,
            closed: None,
        }
    }

    /// Receives only the opening and sends its fresh bounded query challenge.
    ///
    /// This successful *stage* retains every original and grants no acceptance.
    /// Only the complete future terminal producer can dispose this whole owner.
    ///
    /// # Errors
    /// Retains native, framing, same-peer, budget or original-clock refusal and
    /// completes all already-paid reached final posts before projecting it.
    pub(crate) fn receive_opening_once_v1(&mut self) -> Result<(), RootDeleteErrorV1> {
        if self.opening.is_some() || self.closed.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        let Some(flight) = self.flight.take() else {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        };
        self.disposition.entered = true;
        // Temporarily field-split the actual exclusive flight. Admission can
        // inspect this resident owner without aliasing its mutable flight field.
        self.opening = Some(self.receive_inner(flight));
        self.flight = Some(flight);
        // The whole preauthentication opening has one original deadline. Its
        // independent native post is owed even after a partial read/refusal.
        if self.prelude.finish_opening_once_v1().is_err() {
            self.first.get_or_insert(First::OpeningClockAfter);
        }
        if self.first.is_some() || !matches!(self.opening, Some(Ok(()))) {
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    fn receive_inner(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'listener, 'startup>,
    ) -> Result<(), RootDeleteErrorV1> {
        let cutoff = self.prelude.cutoff_v1().map_err(|_| RootDeleteErrorV1::Opening)?;
        self.bytes[..32].copy_from_slice(self.prelude.prefix_bytes_v1());
        self.peer = Some(flight.admit_delete_controller_peer_once_v1());
        self.require(matches!(self.peer, Some(Ok(()))), First::Peer)?;
        self.opening_permit = Some(flight.admit_delete_opening_once_v1(self));
        self.require(
            matches!(self.opening_permit, Some(Ok(()))),
            First::OpeningPermit,
        )?;
        self.remainder = Some(
            self.remainder_io
                .run_once(
                    &mut self.original,
                    &mut self.remainder_bytes,
                    cutoff,
                    DeadlineStreamDirectionV1::Read,
                )
                .map_err(|_| RootDeleteErrorV1::Opening),
        );
        self.require(matches!(self.remainder, Some(Ok(()))), First::Remainder)?;
        self.bytes[32..].copy_from_slice(&self.remainder_bytes);
        self.decoded = Some(DeleteRootOpenDataV2::decode_v2(&self.bytes));
        self.require(matches!(self.decoded, Some(Ok(_))), First::Open)?;
        let open = *self
            .decoded
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(RootDeleteErrorV1::Opening)?;
        self.challenge_result = Some(self.challenge.prepare_once_v1(flight, open));
        self.require(
            matches!(self.challenge_result, Some(Ok(()))),
            First::Challenge,
        )?;
        let query = self
            .challenge
            .source_query_v1()
            .map_err(|_| RootDeleteErrorV1::Opening)?;
        self.response = *self
            .challenge
            .challenge_bytes_v1()
            .map_err(|_| RootDeleteErrorV1::Opening)?;
        let result = self.sent.run_once(
            &mut self.original,
            &mut self.response,
            query.cutoff.min(cutoff),
            DeadlineStreamDirectionV1::Write,
        );
        self.require(result.is_ok(), First::Send)
    }

    /// Receives the same opening's complete canonical batch as comparison DATA.
    ///
    /// Each reached native chunk has distinct paid currentness bookends. This
    /// stage cannot accept D or dispose the whole lifecycle guard.
    ///
    /// # Errors
    /// Retains the first native, original, budget, subject, clock or parser
    /// failure and independently completes the already-paid whole-flight posts.
    pub(crate) fn receive_canonical_batch_once_v1(&mut self) -> Result<(), RootDeleteErrorV1> {
        if !matches!(self.opening, Some(Ok(())))
            || self.first.is_some()
            || self.body_result.is_some()
            || self.closed.is_some()
        {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        let Some(open) = self
            .decoded
            .as_ref()
            .and_then(|open| open.as_ref().ok())
            .copied()
        else {
            self.first.get_or_insert(First::Reentry);
            return Err(RootDeleteErrorV1::Original);
        };
        let Some(flight) = self.flight.take() else {
            self.first.get_or_insert(First::Reentry);
            return Err(RootDeleteErrorV1::Original);
        };
        self.body_result =
            Some(
                self.body
                    .receive_once_v1(flight, &self.original, &self.challenge, open),
            );
        self.flight = Some(flight);
        if !matches!(self.body_result, Some(Ok(()))) {
            self.first.get_or_insert(First::Body);
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    /// Independently reads and compares this flight's complete C17/current C cut.
    ///
    /// This completed stage grants no six-owner conjunction or lifecycle state.
    /// All actual reader/currentness originals remain held on this same flight.
    ///
    /// # Errors
    /// Retains strict frame, payment, native/full semantic, claim or independent
    /// post refusal and still runs the whole flight's prepaid final posts.
    pub(crate) fn verify_controller_current_once_v1(&mut self) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_some() || !matches!(self.body_result, Some(Ok(())))
            || self.controller_result.is_some() || self.closed.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        let Some(flight) = self.flight.take() else {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        };
        self.controller_result = Some(self.controller.observe_once_v1(flight, &self.original, &self.challenge));
        self.flight = Some(flight);
        if !matches!(self.controller_result, Some(Ok(()))) {
            self.first.get_or_insert(First::Controller);
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    /// Recomputes the original authorization from this Root-owned C prefix.
    ///
    /// The complete canonical request and named lease witness are comparison
    /// DATA. This stage creates no protected capability decision or lifecycle
    /// grant and cannot replace the remaining genuine six-owner conjunction.
    ///
    /// # Errors
    /// Retains frame, payment, canonical model, lease or native currentness
    /// failure and completes the whole flight's independently owed final posts.
    pub(crate) fn verify_authorization_once_v2(&mut self) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_some() || !matches!(self.controller_result, Some(Ok(())))
            || self.authorization_result.is_some() || self.closed.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        let Some(open) = self.decoded.as_ref().and_then(|open| open.as_ref().ok()).copied() else {
            self.first.get_or_insert(First::Reentry);
            return Err(RootDeleteErrorV1::Original);
        };
        let Some(flight) = self.flight.take() else {
            self.first.get_or_insert(First::Reentry);
            return Err(RootDeleteErrorV1::Original);
        };
        self.authorization_result = Some(self.controller.observe_authorization_once_v2(
            flight, &self.original, &self.challenge, open));
        self.flight = Some(flight);
        if !matches!(self.authorization_result, Some(Ok(()))) {
            self.first.get_or_insert(First::Authorization);
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    /// Captures Root's own configured broker trust before comparing six owners.
    ///
    /// # Errors
    /// Retains same-R payment, native capture, role/model or independent post
    /// failure; no Controller-supplied key or manifest can enter this stage.
    pub(crate) fn capture_broker_trust_once_v2(&mut self) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_some() || !matches!(self.authorization_result, Some(Ok(())))
            || self.broker_trust_result.is_some() || self.closed.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        let Some(flight) = self.flight.take() else { return Err(RootDeleteErrorV1::Original); };
        self.broker_trust_result = Some(self.controller.observe_broker_trust_once_v2(flight, &self.challenge));
        self.flight = Some(flight);
        if !matches!(self.broker_trust_result, Some(Ok(()))) {
            self.first.get_or_insert(First::BrokerTrust);
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    /// Verifies all four initial Session files under Root's own configured keys.
    ///
    /// Each complete packet/model/native original remains resident. This stage
    /// cannot send the initial-six ACK or lend a fresh inventory query.
    ///
    /// # Errors
    /// Retains the first payment, signature, replay or independently owed-post
    /// refusal and runs the already-armed whole-flight final checks.
    pub(crate) fn verify_initial_sessions_once_v2(&mut self) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_some() || !matches!(self.broker_trust_result, Some(Ok(())))
            || self.initial_sessions_result.is_some() || self.closed.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        let Some(flight) = self.flight.take() else {
            self.first.get_or_insert(First::Reentry);
            return Err(RootDeleteErrorV1::Original);
        };
        self.initial_sessions_result = Some(self.controller.observe_initial_sessions_once_v2(flight, &self.challenge));
        self.flight = Some(flight);
        if !matches!(self.initial_sessions_result, Some(Ok(()))) {
            self.first.get_or_insert(First::Sessions);
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        self.initial_sessions_comparison = Some((|| {
            let actual = self.controller.initial_session_cuts_v2()?;
            let expected = self.body.inventory_cuts_v2()?;
            if actual.as_slice() != &expected[..4] { return Err(RootDeletePredecessorCutErrorV2::SessionChanged); }
            Ok(())
        })());
        if !matches!(self.initial_sessions_comparison, Some(Ok(()))) {
            self.first.get_or_insert(First::Sessions);
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    /// Verifies Root's own directly queried, signed current Source pending cut.
    ///
    /// The whole signed packet, native socket and independent currentness posts
    /// stay resident. This stage alone grants no six-owner or floor acceptance.
    ///
    /// # Errors
    /// Retains original funding, native IO, own-pin signature, complete pending
    /// cut or fresh paired-clock refusal and completes all entered owed posts.
    pub(crate) fn verify_source_current_once_v1(&mut self) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_some() || !matches!(self.controller_result, Some(Ok(())))
            || !matches!(self.authorization_result, Some(Ok(())))
            || !matches!(self.broker_trust_result, Some(Ok(())))
            || self.source_result.is_some() || self.closed.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        let Some(open) = self.decoded.as_ref().and_then(|open| open.as_ref().ok()).copied() else {
            self.first.get_or_insert(First::Reentry);
            return Err(RootDeleteErrorV1::Original);
        };
        let Some(flight) = self.flight.take() else {
            self.first.get_or_insert(First::Reentry);
            return Err(RootDeleteErrorV1::Original);
        };
        self.source_result = Some(self.source.observe_once_v1(flight, &self.challenge, &mut self.controller, open));
        self.flight = Some(flight);
        if !matches!(self.source_result, Some(Ok(()))) {
            self.first.get_or_insert(First::Source);
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        self.predecessor_cuts = Some((|| {
            let saved = self.body.named_cuts_v2()?;
            let controller = self.controller.verified_named_cut_data_v2()?;
            let source = self.source.verified_source_predecessor_v2()?.source;
            let authorization = self.controller.verified_authorization_cut_data_v2()?;
            if authorization != saved.authorization || controller != saved.controller || source != saved.source {
                return Err(RootDeletePredecessorCutErrorV2::Changed);
            }
            Ok(())
        })());
        if !matches!(self.predecessor_cuts, Some(Ok(()))) {
            self.first.get_or_insert(First::PredecessorCuts);
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    /// Compares the fresh signed Source Tree with the SAME held Root floor.
    ///
    /// The actual journal, saved semantic floor/archive and original pins stay
    /// resident. No six-owner proof, new floor COMMIT or lifecycle grant follows.
    ///
    /// # Errors
    /// Retains native, full-history, exact Tree, funding or owed-post refusal.
    pub(crate) fn compare_saved_floor_once_v1(&mut self) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_some() || !matches!(self.source_result, Some(Ok(())))
            || !matches!(self.predecessor_cuts, Some(Ok(())))
            || self.floor_result.is_some() || self.closed.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        let Some(flight) = self.flight.take() else {
            self.first.get_or_insert(First::Reentry);
            return Err(RootDeleteErrorV1::Original);
        };
        self.floor_result = Some(flight.observe_delete_saved_floor_once_v1(&mut self.floor,
            &self.challenge, &self.controller, &self.source));
        self.flight = Some(flight);
        if !matches!(self.floor_result, Some(Ok(()))) {
            self.first.get_or_insert(First::Floor);
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    /// Begins exact Transfer namespace observation beside active local Ownership.
    ///
    /// The same directory and local file originals stay held through the later
    /// D continuation. This stage alone proves neither Runtime default-off nor
    /// active Ownership and cannot complete any six-owner or lifecycle gate.
    ///
    /// # Errors
    /// Retains exact namespace, funding, native or independently owed failure.
    pub(crate) fn begin_transfer_namespace_once_v1(&mut self) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_some() || !matches!(self.floor_result, Some(Ok(())))
            || self.transfer_namespace_result.is_some() || self.closed.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        let Some(flight) = self.flight.take() else {
            self.first.get_or_insert(First::Reentry);
            return Err(RootDeleteErrorV1::Original);
        };
        self.transfer_namespace_result = Some(self.transfer_namespace.begin_once_v1(flight,
            &self.challenge, &self.controller, &self.source, &self.floor));
        self.flight = Some(flight);
        if !matches!(self.transfer_namespace_result, Some(Ok(()))) {
            self.first.get_or_insert(First::TransferNamespace);
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    /// Independently compares all five Cache journals and complete physical objects.
    ///
    /// The same native/model engine serves the ordinary Root provisioning
    /// purposes; this new D entrance uses only its genuine same-R destination.
    /// This stage supplies no initial-six ACK or accepted lifecycle state.
    ///
    /// # Errors
    /// Retains actual native/model/payment/currentness failures through every
    /// prearmed independent Root, five-file and physical object after.
    pub(crate) fn verify_cache_current_once_v2(&mut self) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_some() || self.closed.is_some() || self.cache_result.is_some()
            || !matches!(self.initial_sessions_comparison, Some(Ok(())))
            || !matches!(self.source_result, Some(Ok(()))) || !matches!(self.floor_result, Some(Ok(())))
            || !matches!(self.transfer_namespace_result, Some(Ok(()))) {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        let Some(flight) = self.flight.take() else {
            self.first.get_or_insert(First::Reentry);
            return Err(RootDeleteErrorV1::Original);
        };
        self.cache_result = Some(self.cache.observe_once_v2(flight, &self.challenge, &self.controller,
            &self.source, &self.floor, &self.transfer_namespace));
        self.flight = Some(flight);
        if !matches!(self.cache_result, Some(Ok(()))) {
            self.first.get_or_insert(First::Cache);
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    /// Reconstructs and compares the complete graph from this Root's native inputs.
    ///
    /// # Errors
    /// Retains every actual file/model/selection/error and completes the same
    /// independently owed Root flight posts on any refusal. No effect is granted.
    pub(crate) fn verify_complete_graph_once_v2(&mut self) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_some() || self.closed.is_some() || self.graph_objects_result.is_some()
            || self.graph_comparison_result.is_some()
            || !self.fresh_inventory.as_ref().is_some_and(|owner| owner.inputs_complete_v2())
            || !matches!(self.fresh_floor_result, Some(Ok(()))) {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        let Some(flight) = self.flight.take() else {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        };
        self.graph_objects_result = Some((|| {
            let fresh = self.fresh_inventory.as_mut().ok_or(RootDeleteErrorV1::Original)?;
            fresh.require_inputs_complete_v2()?;
            self.graph_objects.observe_once_v2(flight, &self.challenge,
                &fresh.controller, &mut fresh.source, &fresh.cache)
        })());
        if matches!(self.graph_objects_result, Some(Ok(()))) {
            self.graph_comparison_result = Some(self.graph_comparison.observe_once_v2(flight,
                &self.graph_objects, &self.body, &self.controller));
            if !matches!(self.graph_comparison_result, Some(Ok(()))) {
                self.first.get_or_insert(First::GraphComparison);
            }
        } else {
            self.first.get_or_insert(First::GraphObjects);
        }
        self.flight = Some(flight);
        if self.first.is_some() {
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    /// Independently recomputes all initial cuts before sending their fresh ACK.
    ///
    /// The completed same-native ACK permits only fresh queries. Its peer keeps
    /// the exclusive Session writers throughout the comparison. The sole full
    /// Root graph fold runs after the late fresh six, before final approval;
    /// neither this ACK nor its bytes accept or authorize destruction.
    ///
    /// # Errors
    /// Retains frame, own-native/model, complete association, funding or owed
    /// post failure and runs the whole flight's independent final checks.
    pub(crate) fn verify_initial_inventory_once_v2(&mut self) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_some() || self.closed.is_some() || self.initial_inventory_result.is_some()
            || !matches!(self.cache_result, Some(Ok(()))) {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        let Some(open) = self.decoded.as_ref().and_then(|value| value.as_ref().ok()).copied() else {
            return Err(RootDeleteErrorV1::Original);
        };
        let Some(flight) = self.flight.take() else { return Err(RootDeleteErrorV1::Original); };
        self.initial_inventory_result = Some(self.initial_inventory.observe_once_v2(flight,
            &mut self.original, open, &self.challenge, &self.body, &self.controller,
            &self.source, &self.floor, &mut self.transfer_namespace, &self.cache));
        self.flight = Some(flight);
        if !matches!(self.initial_inventory_result, Some(Ok(()))) {
            self.first.get_or_insert(First::InitialInventory);
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    // This is an already-owed negative frontier, not a new healthy entrance.
    // Neither an opening error nor a late Root post can clear the first marker.
    pub(crate) fn finish_negative_once_v1(&mut self) {
        self.resource_policy.finish_credentials_if_owed_v2();
        if self.resource_policy.failure().is_some() {
            self.first.get_or_insert(First::ResourcePolicy);
        }
        if let Some(flight) = self.flight.as_deref_mut() {
            let _ = self.transfer_namespace.finish_if_owed_v1(flight, &self.challenge);
        }

        // Failed admission already attempted its own final pair in0168. Only
        // completed initial admission leaves this actual final debt for us.
        if matches!(self.peer, Some(Ok(()))) && self.peer_after.is_none() {
            self.peer_after = Some(match self.flight.as_deref_mut() {
                Some(flight) => flight.finish_delete_controller_peer_posts_once_v1(),
                None => Err(NormalRootStartupErrorV1::Service),
            });
            if !matches!(self.peer_after, Some(Ok(()))) {
                self.first.get_or_insert(First::PeerAfter);
            }
        }
        if self.challenge.funded_v1() && self.clock_after.is_none() {
            self.clock_after = Some(self.challenge.finish_clock_once_v1());
            if !matches!(self.clock_after, Some(Ok(()))) {
                self.first.get_or_insert(First::ClockAfter);
            }
        }
    }

    fn require(&mut self, positive: bool, stage: First) -> Result<(), RootDeleteErrorV1> {
        if positive {
            Ok(())
        } else {
            self.first.get_or_insert(stage);
            Err(RootDeleteErrorV1::Opening)
        }
    }

    pub(crate) fn opening_receiving_demand_v1(
        &self,
    ) -> Result<
        aos_sandbox_model::ResourceVector,
        crate::controller_resource_reservation::ResourceReservationErrorV1,
    > {
        use crate::controller_resource_reservation::ResourceReservationErrorV1 as Error;
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        if !self.disposition.entered
            || !matches!(self.peer, Some(Ok(())))
            || self.opening_permit.is_some()
            || self.remainder.is_some()
        {
            return Err(Error::Conflict);
        }
        // The actual listener pays the whole fixed constructor before accept;
        // its common operation already paid112 opening bytes. This exact D
        // native entrance prepays the remaining96 before reading them.
        let additional = DELETE_ROOT_OPEN_BYTES_V2
            .checked_sub(112)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(Error::EnrollmentUnavailable)?;
        Ok(ResourceVector::ZERO.with(D::NetworkBytes, additional))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        let selected = match self.first? {
            First::OpeningClockAfter => self.prelude.failure_after_v1(),
            First::Peer | First::PeerAfter => {
                self.flight.as_deref().and_then(|flight| flight.failure())
            }
            First::OpeningPermit => cause(&self.opening_permit),
            First::FreshAdmission => cause(&self.fresh_admission),
            First::CleanupInputs => self.cleanup_inputs.failure().or_else(|| cause(&self.cleanup_inputs_result)),
            First::ResourceSelection => self.resource_selection.failure().or_else(|| cause(&self.resource_selection_result)),
            First::ResourcePreparation => self.resource_preparation.failure().or_else(|| cause(&self.resource_preparation_result)),
            First::ResourceDraft => self.resource_draft.failure().or_else(|| cause(&self.resource_draft_result)),
            First::ResourceSignature => self.resource_signature.failure_with_policy_v2(&self.resource_policy)
                .or_else(|| cause(&self.resource_signature_result)),
            First::PreparationCurrent => self.preparation_current.failure().or_else(|| cause(&self.preparation_current_result)),
            First::ApplyIssuer => self.apply_issuer.failure().or_else(|| cause(&self.apply_issuer_result)),
            First::NetworkIssuer => self.network_issuer.failure().or_else(|| cause(&self.network_issuer_result)),
            First::CleanupCurrent => self.cleanup_current.failure().or_else(|| cause(&self.cleanup_current_result)),
            First::MountIssuer => self.mount_issuer.failure().or_else(|| cause(&self.mount_issuer_result)),
            First::Completion => self.completion.failure().or_else(|| cause(&self.completion_result)),
            First::PreparatoryApproval => self.preparatory_approval.failure()
                .or_else(|| cause(&self.preparatory_approval_result)),
            First::ResourcePolicyConfirmation => self.resource_policy_confirmation.failure()
                .or_else(|| cause(&self.resource_policy_confirmation_result)),
            First::ResourcePolicy => self.resource_policy.failure().or_else(|| cause(&self.resource_policy_result)),
            First::FreshFloor => self.fresh_floor.failure().or_else(|| cause(&self.fresh_floor_result)),
            First::FreshController => self.fresh_inventory.as_ref().and_then(|owner| owner.failure())
                .or_else(|| cause(&self.fresh_result)),
            First::Remainder => self
                .remainder_io
                .failure()
                .or_else(|| cause(&self.remainder)),
            First::Open => cause(&self.decoded),
            First::Challenge | First::ClockAfter => self.challenge.failure(),
            First::Send => self.sent.failure(),
            First::Body => self.body.failure().or_else(|| cause(&self.body_result)),
            First::Controller | First::Authorization | First::BrokerTrust => self.controller.failure().or_else(|| cause(&self.controller_result)),
            First::InitialInventory => {
                if self.initial_inventory.transfer_failure_selected() {
                    self.transfer_namespace.failure()
                } else { self.initial_inventory.failure() }
                .or_else(|| cause(&self.initial_inventory_result))
            },
            First::Cache => {
                let retired = self.cache.resident_retirement_failed_v2().then(||
                    self.flight.as_deref().and_then(|flight| flight.delete_cache_retirement_failure_v2()))
                    .flatten();
                retired.or_else(|| self.cache.failure()).or_else(|| cause(&self.cache_result))
            },
            First::GraphObjects => self.graph_objects.failure().or_else(|| cause(&self.graph_objects_result)),
            First::GraphComparison => self.graph_comparison.failure().or_else(|| cause(&self.graph_comparison_result)),
            First::Sessions => self.controller.failure().or_else(|| cause(&self.initial_sessions_comparison))
                .or_else(|| cause(&self.initial_sessions_result)),
            First::Source => self.source.failure().or_else(|| cause(&self.source_result)),
            First::PredecessorCuts => cause(&self.predecessor_cuts),
            First::Floor => self.floor.failure().or_else(|| cause(&self.floor_result)),
            First::TransferNamespace => self.transfer_namespace.failure().or_else(|| cause(&self.transfer_namespace_result)),
            First::Reentry => self.closed.as_ref().map(|cause| cause as _),
        };
        selected
            .or_else(|| cause(&self.opening))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub(crate) fn failure_view_v1(
        &self,
    ) -> RootDeleteFailureViewV1<'_, 'flight, 'listener, 'startup> {
        RootDeleteFailureViewV1(self)
    }
}

pub(crate) struct RootDeleteFailureViewV1<'owner, 'flight, 'listener, 'startup>(
    &'owner RootDeletePendingReceivingV1<'flight, 'listener, 'startup>,
);

impl std::fmt::Display for RootDeleteFailureViewV1<'_, '_, '_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if (matches!(self.0.first, Some(First::CleanupCurrent)) && self.0.cleanup_current.funding_failed_v4())
            || (matches!(self.0.first, Some(First::Completion)) && self.0.completion.funding_failed_v4())
            || (matches!(self.0.first, Some(First::MountIssuer)) && self.0.mount_issuer.funding_failed_v3())
            || (matches!(self.0.first, Some(First::NetworkIssuer)) && self.0.network_issuer.funding_failed_v3())
            || (matches!(self.0.first, Some(First::ApplyIssuer)) && self.0.apply_issuer.funding_failed_v3())
            || (matches!(self.0.first, Some(First::PreparationCurrent)) && self.0.preparation_current.funding_failed_v3())
            || (matches!(self.0.first, Some(First::PreparatoryApproval)) && self.0.preparatory_approval.funding_failed_v3())
            || (matches!(self.0.first, Some(First::ResourcePolicyConfirmation)) && self.0.resource_policy_confirmation.funding_failed_v2())
            || (matches!(self.0.first, Some(First::ResourceSignature)) && self.0.resource_signature.funding_failed_v2())
            || (matches!(self.0.first, Some(First::ResourceDraft)) && self.0.resource_draft.funding_failed_v2())
            || (matches!(self.0.first, Some(First::ResourcePreparation)) && self.0.resource_preparation.funding_failed_v2())
            || (matches!(self.0.first, Some(First::CleanupInputs)) && self.0.cleanup_inputs.funding_failed_v2())
            || (matches!(self.0.first, Some(First::ResourcePolicy)) && self.0.resource_policy.funding_failed_v2())
            || (matches!(self.0.first, Some(First::GraphObjects)) && self.0.graph_objects.funding_failed_v2())
            || (matches!(self.0.first, Some(First::GraphComparison)) && self.0.graph_comparison.funding_failed_v2())
            || (matches!(self.0.first, Some(First::InitialInventory)) && self.0.initial_inventory.funding_failed())
            || (matches!(self.0.first, Some(First::Cache)) && self.0.cache.funding_failed())
            || (matches!(self.0.first, Some(First::TransferNamespace))
            && self.0.transfer_namespace.financial_failure_is_selected_v1())
            || (matches!(self.0.first, Some(First::Floor))
            && self.0.floor.financial_failure_is_selected_v1())
            || (matches!(self.0.first, Some(First::Source))
            && self.0.source.financial_failure_is_selected_v1())
            || (matches!(self.0.first, Some(First::Controller | First::Authorization | First::BrokerTrust | First::Sessions))
            && self.0.controller.financial_failure_is_selected_v1())
            || (matches!(self.0.first, Some(First::Body))
            && self.0.body.financial_failure_is_selected_v1())
            || matches!(self.0.first, Some(First::OpeningPermit | First::FreshAdmission))
            || (matches!(self.0.first, Some(First::FreshFloor))
                && self.0.fresh_floor.financial_failure_is_selected_v1())
            || (matches!(self.0.first, Some(First::FreshController))
                && self.0.fresh_inventory.as_ref().is_some_and(|owner| owner.funding_failed_v2()))
            || (matches!(self.0.first, Some(First::Challenge))
                && self.0.challenge.funding_failed_v1())
        {
            if let Some(flight) = self.0.flight.as_deref() {
                if let Some(view) = flight.delete_exchange_financial_failure_view_v1() {
                    return std::fmt::Display::fmt(&view, f);
                }
            }
        }
        if matches!(self.0.first, Some(First::Peer | First::PeerAfter)) {
            if let Some(flight) = self.0.flight.as_deref() {
                if let Some(view) = flight.delete_controller_property_failure_view_v1() {
                    return std::fmt::Debug::fmt(&view, f);
                }
            }
        }
        if matches!(self.0.first, Some(First::ApplyIssuer)) {
            if let Some(view) = self.0.apply_issuer.property_failure_view_v3() {
                return std::fmt::Debug::fmt(&view, f);
            }
        }
        if matches!(self.0.first, Some(First::NetworkIssuer)) {
            if let Some(view) = self.0.network_issuer.property_failure_view_v3() {
                return std::fmt::Debug::fmt(&view, f);
            }
        }
        if matches!(self.0.first, Some(First::MountIssuer)) {
            if let Some(view) = self.0.mount_issuer.property_failure_view_v3() {
                return std::fmt::Debug::fmt(&view, f);
            }
        }
        if matches!(self.0.first, Some(First::Completion)) {
            if let Some(view) = self.0.completion.property_failure_view_v4() {
                return std::fmt::Debug::fmt(&view, f);
            }
        }
        if matches!(self.0.first, Some(First::CleanupCurrent)) {
            if let Some(view) = self.0.cleanup_current.property_failure_view_v4() {
                return std::fmt::Debug::fmt(&view, f);
            }
        }
        if matches!(self.0.first, Some(First::PreparationCurrent)) {
            if let Some(view) = self.0.preparation_current.property_failure_view_v3() {
                return std::fmt::Debug::fmt(&view, f);
            }
        }
        if matches!(self.0.first, Some(First::PreparatoryApproval)) {
            if let Some(view) = self.0.preparatory_approval.property_failure_view_v3() {
                return std::fmt::Debug::fmt(&view, f);
            }
        }
        if matches!(self.0.first, Some(First::ResourcePolicyConfirmation)) {
            if let Some(view) = self.0.resource_policy_confirmation.property_failure_view_v2() {
                return std::fmt::Debug::fmt(&view, f);
            }
        }
        if matches!(self.0.first, Some(First::ResourceSignature)) {
            if let Some(view) = self.0.resource_signature.property_failure_view_v2() {
                return std::fmt::Debug::fmt(&view, f);
            }
        }
        if matches!(self.0.first, Some(First::ResourceDraft)) {
            if let Some(view) = self.0.resource_draft.property_failure_view_v2() {
                return std::fmt::Debug::fmt(&view, f);
            }
        }
        if matches!(self.0.first, Some(First::ResourcePreparation)) {
            if let Some(view) = self.0.resource_preparation.property_failure_view_v2() {
                return std::fmt::Debug::fmt(&view, f);
            }
        }
        if matches!(self.0.first, Some(First::ResourcePolicy)) {
            if let Some(view) = self.0.resource_policy.property_failure_view_v2() {
                return std::fmt::Debug::fmt(&view, f);
            }
        }
        if matches!(self.0.first, Some(First::FreshFloor)) {
            if let Some(view) = self.0.fresh_floor.property_failure_view_v1() {
                return std::fmt::Debug::fmt(&view, f);
            }
        }
        if matches!(self.0.first, Some(First::FreshController)) {
            if let Some(view) = self.0.fresh_inventory.as_ref().and_then(|owner| owner.property_failure_view_v2()) {
                return std::fmt::Debug::fmt(&view, f);
            }
        }
        if matches!(self.0.first, Some(First::InitialInventory))
            && self.0.initial_inventory.transfer_failure_selected() {
            if let Some(view) = self.0.transfer_namespace.property_failure_view_v1() {
                return std::fmt::Debug::fmt(&view, f);
            }
        }
        if matches!(self.0.first, Some(First::InitialInventory)) {
            if let Some(view) = self.0.initial_inventory.property_failure_view() {
                return std::fmt::Debug::fmt(&view, f);
            }
        }
        if matches!(self.0.first, Some(First::GraphObjects)) {
            if let Some(view) = self.0.graph_objects.property_failure_view_v2() {
                return std::fmt::Debug::fmt(&view, f);
            }
        }
        if matches!(self.0.first, Some(First::Cache)) {
            if let Some(view) = self.0.cache.property_failure_view() { return std::fmt::Debug::fmt(&view, f); }
        }
        if matches!(self.0.first, Some(First::Body)) {
            if let Some(view) = self.0.body.property_failure_view_v1() {
                return std::fmt::Debug::fmt(&view, f);
            }
        }
        if matches!(self.0.first, Some(First::Controller | First::Authorization | First::BrokerTrust | First::Sessions)) {
            if let Some(view) = self.0.controller.property_failure_view_v1() {
                return std::fmt::Debug::fmt(&view, f);
            }
        }
        if matches!(self.0.first, Some(First::Source)) {
            if let Some(view) = self.0.source.property_failure_view_v1() {
                return std::fmt::Debug::fmt(&view, f);
            }
        }
        if matches!(self.0.first, Some(First::Floor)) {
            if let Some(view) = self.0.floor.property_failure_view_v1() {
                return std::fmt::Debug::fmt(&view, f);
            }
        }
        if matches!(self.0.first, Some(First::TransferNamespace)) {
            if let Some(view) = self.0.transfer_namespace.property_failure_view_v1() {
                return std::fmt::Debug::fmt(&view, f);
            }
        }
        match self.0.failure() {
            Some(cause) => std::fmt::Display::fmt(cause, f),
            None => f.write_str("Delete Root failure is unavailable"),
        }
    }
}

impl std::fmt::Debug for RootDeleteFailureViewV1<'_, '_, '_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

fn cause<T, E: StdError + 'static>(
    slot: &Option<Result<T, E>>,
) -> Option<&(dyn StdError + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}
