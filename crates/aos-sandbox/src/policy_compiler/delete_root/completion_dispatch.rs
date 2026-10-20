//! Moves the complete genuine Delete graph through the shared Root finisher.
//!
//! The only constructor consumes a real completed receiver, after its exact32
//! response and all owed posts. It removes the borrowed flight by moving every
//! owned field into the same receiver layout with no flight borrower. No DATA,
//! pointer cast, new socket, callback or reconstructed native owner is accepted.

use super::*;
use aos_sandbox_linux::unix_stream::RetainedUnixStream;
use std::os::fd::AsFd as _;

pub(crate) struct RootDeleteDispatchOriginalV4 {
    original: RootDeletePendingReceivingV1<'static, 'static, 'static>,
}

impl RootDeleteDispatchOriginalV4 {
    pub(crate) fn completed_confirmation_plan_v2(
        &self,
    ) -> Result<crate::normal_root::RootPolicyPositiveCompletionPlanV2, NormalRootStartupErrorV1>
    {
        self.original.require_completed_owner_v4()?;
        let acknowledgement = self
            .original
            .completion
            .acknowledgement_digest_v4()
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        let cutoff = self.original.challenge.current_cutoff_v1()?;
        Ok(
            crate::normal_root::RootPolicyPositiveCompletionPlanV2::delete_data_v2(
                acknowledgement,
                cutoff,
            ),
        )
    }

    pub(crate) fn require_same_complete_v4(
        &self,
        native: &RetainedUnixStream,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.original.require_completed_owner_v4()?;
        if self.original.flight.is_some() {
            return Err(NormalRootStartupErrorV1::Service);
        }
        native
            .require_same_endpoint_v1(self.original.original.as_fd())
            .map_err(|_| NormalRootStartupErrorV1::Service)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.original
            .failure()
            .or_else(|| self.original.prelude.failure_before_v1())
            .or_else(|| self.original.prelude.failure_after_v1())
            .or_else(|| self.original.resource_policy.failure())
            .or_else(|| self.original.transfer_namespace.failure())
            .or_else(|| self.original.challenge.failure())
            .or_else(|| self.original.completion.failure())
    }

    pub(crate) fn complete_upper_disposal_v4(mut self) {
        self.original.disposition.handed_off = true;
        drop(self);
    }
}

impl<'flight, 'listener, 'startup> RootDeletePendingReceivingV1<'flight, 'listener, 'startup> {
    fn require_completed_owner_v4(&self) -> Result<(), NormalRootStartupErrorV1> {
        if !self.disposition.entered
            || self.disposition.handed_off
            || self.first.is_some()
            || self.closed.is_some()
            || self.failure().is_some()
            || !matches!(self.opening, Some(Ok(())))
            || !matches!(self.peer, Some(Ok(())))
            || !matches!(self.completion_result, Some(Ok(())))
            || !matches!(self.peer_after, Some(Ok(())))
            || !matches!(self.clock_after, Some(Ok(())))
            || self.prelude.failure_before_v1().is_some()
            || self.prelude.failure_after_v1().is_some()
            || self.resource_policy.failure().is_some()
            || self.transfer_namespace.failure().is_some()
            || self.challenge.failure().is_some()
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.completion
            .require_completed_v4()
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        self.completion
            .acknowledgement_digest_v4()
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        Ok(())
    }

    pub(crate) fn finish_positive_once_v4(mut self) -> Result<(), NormalRootStartupErrorV1> {
        // The historical method name drains entered posts without manufacturing
        // a negative cause or ending this socket. All actual samples stay owned.
        self.finish_negative_once_v1();
        let opening_post = self.prelude.finish_opening_if_owed_v1();
        if opening_post.is_err() {
            self.first.get_or_insert(First::OpeningClockAfter);
        }
        if self.require_completed_owner_v4().is_ok() {
            let peer = match self.flight.as_deref_mut() {
                Some(flight) => flight.settle_delete_controller_peer_positive_once_v1(),
                None => Err(NormalRootStartupErrorV1::Service),
            };
            if peer.is_err() {
                self.first.get_or_insert(First::PeerAfter);
            }
        }
        let flight = match self.flight.take() {
            Some(flight) => flight,
            None => std::process::abort(),
        };
        let Self {
            disposition,
            original,
            prelude,
            peer,
            bytes,
            opening_permit,
            remainder_io,
            remainder_bytes,
            remainder,
            decoded,
            challenge,
            challenge_result,
            response,
            sent,
            body,
            body_result,
            controller,
            controller_result,
            authorization_result,
            broker_trust_result,
            initial_sessions_result,
            initial_sessions_comparison,
            cache,
            cache_result,
            graph_objects,
            graph_objects_result,
            graph_comparison,
            graph_comparison_result,
            initial_inventory,
            initial_inventory_result,
            fresh_inventory,
            fresh_admission,
            fresh_result,
            fresh_floor,
            fresh_floor_result,
            resource_policy,
            resource_policy_result,
            cleanup_inputs,
            cleanup_inputs_result,
            resource_selection,
            resource_selection_result,
            resource_preparation,
            resource_preparation_result,
            resource_draft,
            resource_draft_result,
            resource_signature,
            resource_signature_result,
            resource_policy_confirmation,
            resource_policy_confirmation_result,
            preparatory_approval,
            preparatory_approval_result,
            preparation_current,
            preparation_current_result,
            apply_issuer,
            apply_issuer_result,
            network_issuer,
            network_issuer_result,
            cleanup_current,
            cleanup_current_result,
            mount_issuer,
            mount_issuer_result,
            completion,
            completion_result,
            source,
            source_result,
            predecessor_cuts,
            floor,
            floor_result,
            transfer_namespace,
            transfer_namespace_result,
            clock_after,
            peer_after,
            opening,
            first,
            closed,
            flight: _,
        } = self;
        // Only the optional flight reference had a lifetime. Every captured
        // native/model/error field moves unchanged; no allocation or IO occurs.
        let original = RootDeletePendingReceivingV1 {
            disposition,
            original,
            prelude,
            peer,
            bytes,
            opening_permit,
            remainder_io,
            remainder_bytes,
            remainder,
            decoded,
            challenge,
            challenge_result,
            response,
            sent,
            body,
            body_result,
            controller,
            controller_result,
            authorization_result,
            broker_trust_result,
            initial_sessions_result,
            initial_sessions_comparison,
            cache,
            cache_result,
            graph_objects,
            graph_objects_result,
            graph_comparison,
            graph_comparison_result,
            initial_inventory,
            initial_inventory_result,
            fresh_inventory,
            fresh_admission,
            fresh_result,
            fresh_floor,
            fresh_floor_result,
            resource_policy,
            resource_policy_result,
            cleanup_inputs,
            cleanup_inputs_result,
            resource_selection,
            resource_selection_result,
            resource_preparation,
            resource_preparation_result,
            resource_draft,
            resource_draft_result,
            resource_signature,
            resource_signature_result,
            resource_policy_confirmation,
            resource_policy_confirmation_result,
            preparatory_approval,
            preparatory_approval_result,
            preparation_current,
            preparation_current_result,
            apply_issuer,
            apply_issuer_result,
            network_issuer,
            network_issuer_result,
            cleanup_current,
            cleanup_current_result,
            mount_issuer,
            mount_issuer_result,
            completion,
            completion_result,
            source,
            source_result,
            predecessor_cuts,
            floor,
            floor_result,
            transfer_namespace,
            transfer_namespace_result,
            clock_after,
            peer_after,
            opening,
            first,
            closed,
            flight: None,
        };
        flight.finish_delete_completion_dispatch_once_v4(RootDeleteDispatchOriginalV4 { original })
    }
}
