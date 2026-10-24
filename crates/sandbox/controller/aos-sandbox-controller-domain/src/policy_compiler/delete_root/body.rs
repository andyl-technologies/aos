//! Retains the sole batch parse beside the shared strict D native receiver.

pub(super) mod message;
use message::RootDeleteMessageReceivingV2;
use super::{RootDeleteChallengeOriginalsV1, RootDeleteErrorV1};
use crate::normal_root::RootPolicyAcceptedFlightV1;
use aos_sandbox_protocol::domain_ledger::delete_root::transport::{DeleteRootOpenDataV2, DeleteRootWireErrorV2};
use aos_sandbox_protocol::domain_ledger::delete_batch::{DeleteBatchCommitmentsDataV2, DeleteBatchOwnerCutDataV2};
use std::{error::Error, os::unix::net::UnixStream};

#[derive(Default)]
pub(super) struct RootDeleteBatchReceivingV1 {
    message: RootDeleteMessageReceivingV2,
    batch: Option<Result<(DeleteBatchCommitmentsDataV2, [DeleteBatchOwnerCutDataV2;6], u64), DeleteRootWireErrorV2>>,
    entered: bool,
    closed: Option<RootDeleteErrorV1>,
}

impl RootDeleteBatchReceivingV1 {
    pub(super) fn receive_once_v1(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream, challenge: &RootDeleteChallengeOriginalsV1, open: DeleteRootOpenDataV2)
        -> Result<(), RootDeleteErrorV1> {
        if self.entered || self.closed.is_some() {
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        self.entered = true;
        let length = usize::try_from(open.batch_bytes).map_err(|_| RootDeleteErrorV1::Opening)?;
        self.message.receive_once_v1(flight, original, challenge, length)?;
        self.batch = Some(open.require_batch_inventory_cuts_v2(self.message.bytes_v2()?));
        if matches!(self.batch, Some(Ok(_))) { Ok(()) } else { Err(RootDeleteErrorV1::Opening) }
    }

    pub(super) fn bytes_for_graph_comparison_v2(&self) -> Result<&[u8], RootDeleteErrorV1> {
        self.named_cuts_v2()?;
        self.message.bytes_v2()
    }

    pub(super) fn named_cuts_v2(&self) -> Result<DeleteBatchCommitmentsDataV2, RootDeleteErrorV1> {
        if self.closed.is_some() { return Err(RootDeleteErrorV1::Original); }
        self.message.bytes_v2()?;
        self.batch.as_ref().and_then(|value| value.as_ref().ok()).map(|value| value.0).ok_or(RootDeleteErrorV1::Original)
    }

    pub(super) fn inventory_cuts_v2(&self) -> Result<[DeleteBatchOwnerCutDataV2;6], RootDeleteErrorV1> {
        self.named_cuts_v2()?;
        self.batch.as_ref().and_then(|value| value.as_ref().ok()).map(|value| value.1)
            .ok_or(RootDeleteErrorV1::Original)
    }

    pub(super) fn source_predecessor_next_sequence_v2(&self) -> Result<u64, RootDeleteErrorV1> {
        self.named_cuts_v2()?;
        self.batch.as_ref().and_then(|value| value.as_ref().ok()).map(|value| value.2)
            .ok_or(RootDeleteErrorV1::Original)
    }

    pub(super) fn financial_failure_is_selected_v1(&self) -> bool { self.message.financial_failure_is_selected_v1() }
    pub(super) fn property_failure_view_v1(&self) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        self.message.property_failure_view_v1()
    }
    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.message.failure().or_else(|| self.batch.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}
