//! Prices the actual Root Apply carriers and reached cumulative traffic.

use std::mem::size_of;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use super::*;

impl RootStorageApplyClientOriginalV1 {
    pub(super) fn fixed_demand_v1(profile:&ProductionControllerNormalRootProfileV1)
        -> Result<ResourceVector,ResourceReservationErrorV1> {
        let bad=||ResourceReservationErrorV1::Conflict;
        let native=CreateStorageRootPeerReceivingOriginalsV1::provisioning_native_peak_v1(profile)
            .ok_or_else(bad)?;
        let connection=ControllerRootConnectionOriginalV1::receiving_demand_v1().ok_or_else(bad)?;
        let geometry=CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1()
            .map_err(|_|bad())?;
        let (raw_bytes,raw_files)=geometry.receive_obligations_v1();
        let clock=RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1().ok_or_else(bad)?;
        let readiness=crate::policy_compiler::RootSubjectReadinessV1::receiving_construction_bytes_v1().ok_or_else(bad)?;
        let borrowing=std::mem::size_of::<super::super::resource_stream::RootClientFundingV1<'_>>()
            .checked_add(std::mem::size_of::<super::super::resource_stream::RootReplyReceiveV1<'_>>())
            .and_then(|n|n.checked_mul(2)).ok_or_else(bad)?;
        let bytes=size_of::<Self>().checked_mul(2)
            .and_then(|n|n.checked_add(borrowing))
            .and_then(|n|n.checked_add(size_of::<OpeningV1>().checked_mul(2)?))
            .and_then(|n|n.checked_add(size_of::<RootStrictChunkOriginalV1>().checked_mul(2)?))
            .and_then(|n|n.checked_add(raw_bytes.checked_mul(2)?))
            .and_then(|n|n.checked_add(size_of::<PeerSampleV1>().checked_mul(2)?))
            .and_then(|n|n.checked_add(size_of::<current_turn::RefusalOriginalV1>().checked_mul(2)?))
            .and_then(|n|n.checked_add(clock.checked_mul(3)?))
            .and_then(|n|n.checked_add(super::diagnostics::receiving_bytes_v1()?))
            .and_then(|n|u64::try_from(n).ok())
            .and_then(|n|n.checked_add(readiness)).ok_or_else(bad)?;
        let files=raw_files.checked_add(3*RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1)
            .and_then(|n|u64::try_from(n).ok()).ok_or_else(bad)?;
        Ok(native.checked_add(connection)?.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes,bytes).with(D::OpenFiles,files).with(D::Pids,u64::try_from(CreateStorageRootPeerReceivingOriginalsV1::worker_threads_v1()).map_err(|_|bad())?))?)
    }

    // The reply and fixed opening results stay owned after native opening
    // disposal. No raw receive80 scratch/FD is charged to a later Core phase.
    pub(super) fn resident_demand_v1(&self)
        -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bad = || ResourceReservationErrorV1::Conflict;
        let connection = ControllerRootConnectionOriginalV1::receiving_demand_v1()
            .ok_or_else(bad)?;
        let bytes = size_of::<Self>().checked_mul(2)
            .and_then(|n| n.checked_add(size_of::<OpeningV1>().checked_mul(2)?))
            .and_then(|n| n.checked_add(self.state.received.bytes().len().checked_mul(2)?))
            .and_then(|n| n.checked_add(size_of::<RootStorageApplyAdmissionOriginalV1<'static>>().checked_mul(2)?))
            .and_then(|n| n.checked_add(super::diagnostics::receiving_bytes_v1()?))
            .and_then(|n| u64::try_from(n).ok()).ok_or_else(bad)?;
        // The opening's positive paired readers have already closed their
        // descriptors. Their retained fixed bytes/results are in OpeningV1.
        Ok(connection.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?)
    }

    pub(super) fn peer_traffic_v1(observations:usize)
        ->Result<ResourceVector,ResourceReservationErrorV1> {
        super::super::resource_stream::peer_traffic_v1(observations)
    }

    // Reached traffic is charged before native work. The independent whole
    // opening after was admitted at construction and is not debited again on
    // this path. Refused increments leave their original C failure resident.
    pub(super) fn charge(&mut self,loan:&mut OriginalCreateProvisioningRootLoanV1<'_, '_>,
        controller:&Journal,observations:usize,wire:usize,output:usize,
    )->Result<(),First> {
        use super::super::resource_stream::{RootClientFundingV1, RootClientLoanV1};
        RootClientFundingV1 {complete:self.complete, observations:&mut self.observations,
            wire:&mut self.wire, output:&mut self.output, received_bound:&mut self.received_bound,
            admission:&mut self.admission, funding_original:&mut self.funding_original}
            .charge(&mut RootClientLoanV1::Apply(loan),controller,observations,wire,output)
            .map_err(|_|First::Admission)
    }
}
