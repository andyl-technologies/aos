//! Lends the same resident serving pair and concrete Stop stage in place.
//!
//! Custody stays parked on the listener during every native turn, including
//! unwinding. No local take/restore owner can drop the writers before Root D.

use super::*;
use crate::normal_root::{RootPolicyAcceptedFlightV1, RootStopCleanupStageReceivingV1};
use crate::policy_compiler::{
    RootCurrentPolicyInputDataV1,
    provisioning_current::RootContinuationClockGateV1,
    stop_cleanup_root::{RootStopCleanupNativeOriginalV1, SelectionData},
};
use aos_linux_descriptors::unix_stream::RetainedUnixStream;

impl<'startup> RootPolicyAcceptedFlightV1<'_, 'startup> {
    fn stop_cleanup_native_parts_v1(
        &mut self,
    ) -> Result<
        (
            &RootPolicyServingCustodyV1,
            RootStopCleanupStageReceivingV1<'_, 'startup>,
        ),
        JournalError,
    > {
        self.stop_cleanup_cut_startup_v1()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let custody = self
            .listener
            .serving
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if !custody.ready_for_delete || custody.validation.is_err() {
            return Err(JournalError::ProtectedBoundary);
        }
        custody
            .require_same_completed_pair()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let peer = match self.purpose_peer.as_mut() {
            Some(super::super::RootAcceptedPurposePeerV1::StopCleanup(peer)) => peer,
            _ => return Err(JournalError::ProtectedBoundary),
        };
        let stage = peer
            .stage_receiving_v1()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        Ok((custody, stage))
    }

    pub(crate) fn observe_stop_cleanup_inputs_once_v1(
        &mut self,
        original: &mut RootStopCleanupNativeOriginalV1,
        stream: &RetainedUnixStream,
        policy: &RootCurrentPolicyInputDataV1<'_>,
        clock: &mut RootContinuationClockGateV1,
        selection: SelectionData,
    ) -> Result<(), JournalError> {
        let (custody, mut stage) = self.stop_cleanup_native_parts_v1()?;
        original.observe_inputs_once_v1(
            &mut stage,
            stream,
            &custody.writers,
            &custody.pins,
            policy,
            clock,
            selection,
        )
    }

    pub(crate) fn observe_stop_cleanup_final_once_v1(
        &mut self,
        original: &mut RootStopCleanupNativeOriginalV1,
        stream: &RetainedUnixStream,
        clock: &mut RootContinuationClockGateV1,
        query: ([u8; 16], [u8; 32], [u8; 32], [u8; 32], [u8; 32]),
    ) -> Result<(), JournalError> {
        let (custody, mut stage) = self.stop_cleanup_native_parts_v1()?;
        original.observe_final_once_v1(
            &mut stage,
            stream,
            &custody.writers,
            &custody.pins,
            clock,
            query,
        )
    }

    /// Drains reached actual owners without demanding a healthy new admission.
    pub(crate) fn finish_stop_cleanup_native_posts_once_v1(
        &mut self,
        original: &mut RootStopCleanupNativeOriginalV1,
        stream: &RetainedUnixStream,
        clock: &RootContinuationClockGateV1,
    ) {
        if let Some(custody) = self.listener.serving.as_ref() {
            original.finish_negative_once_v1(stream, &custody.writers, &custody.pins, clock);
        }
    }
}
