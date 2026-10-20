//! Lends Host argument demand from the same fixed authenticated Client writer.

use super::*;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

/// Retains one exact held metadata result and its checked passive forecast.
#[derive(Default)]
pub struct HostExecutionSessionReceivingOriginalV1 {
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    extent: Option<Result<aos_sandbox::journal::ProtectedJournalPreopenReplayExtentV1, aos_sandbox::JournalError>>,
    append: Option<Result<ResourceVector, aos_sandbox::JournalError>>,
    demand: Option<Result<ResourceVector, BrokerSessionSecurityError>>,
}

impl HostExecutionSessionReceivingOriginalV1 {
    /// Bounds this original's construction before its first metadata call.
    #[must_use]
    pub fn fixed_demand_v1() -> Option<ResourceVector> {
        Some(ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(std::mem::size_of::<Self>().checked_mul(2)?).ok()?))
    }

    /// Borrows the original native cause before its coarse checked projection.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.metadata.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _)
            .or_else(|| self.extent.as_ref()?.as_ref().err().map(|e| e as _))
            .or_else(|| self.append.as_ref()?.as_ref().err().map(|e| e as _))
            .or_else(|| self.demand.as_ref()?.as_ref().err().map(|e| e as _))
    }
}

#[derive(Clone, Copy)]
enum HostExecutionReceivingPurposeV2 {
    Argument(BrokerMethod),
    AuthorizeAndObserve,
    Output(BrokerMethod),
    HostStop,
    HostStopInventory,
}

impl ProtectedBrokerSessionOwnerV1 {
    /// Borrows original captured Host Client history DATA without new IO.
    pub(crate) fn host_execution_history_data_v1(
        &self, transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<&[u8], BrokerSessionSecurityError> {
        self.execution_history_data_inner_v2(transcript, BrokerSessionProtocolV1::Host)
    }

    pub(crate) fn storage_capture_history_data_v2(&self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<&[u8], BrokerSessionSecurityError> {
        let fixed = fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient);
        if self.journal.directory != std::path::Path::new(fixed.journal_root) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.execution_history_data_inner_v2(transcript, BrokerSessionProtocolV1::Storage)
    }

    fn execution_history_data_inner_v2(&self,
        transcript: &VerifiedBrokerSessionTranscriptV1, protocol: BrokerSessionProtocolV1,
    ) -> Result<&[u8], BrokerSessionSecurityError> {
        if transcript.protocol() != protocol
            || self.journal.endpoint.role() != BrokerSessionDurableEndpointV1::Client
            || self.journal.endpoint.protected_protocol_and_node().0 != transcript.protocol()
        { return Err(BrokerSessionSecurityError::Currentness); }
        let journal = self.journal.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        journal.ensure_healthy().map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if !journal.has_captured_append_custody_v1() { return Err(BrokerSessionSecurityError::Currentness); }
        journal.get(RecordNamespace::BrokerSessionTraffic, &protocol_key(protocol))
            .ok_or(BrokerSessionSecurityError::Currentness)
    }

    pub(crate) fn host_execution_argument_demand_v1(
        &self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        method: BrokerMethod,
        original: &mut HostExecutionSessionReceivingOriginalV1,
    ) -> Result<ResourceVector, BrokerSessionSecurityError> {
        self.host_execution_session_demand_inner_v2(
            transcript,
            original,
            HostExecutionReceivingPurposeV2::Argument(method),
        )
    }

    pub(crate) fn host_execution_authorize_observe_demand_v2(
        &self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        original: &mut HostExecutionSessionReceivingOriginalV1,
    ) -> Result<ResourceVector, BrokerSessionSecurityError> {
        self.host_execution_session_demand_inner_v2(
            transcript,
            original,
            HostExecutionReceivingPurposeV2::AuthorizeAndObserve,
        )
    }

    pub(crate) fn execution_output_demand_v1(
        &self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        method: BrokerMethod,
        original: &mut HostExecutionSessionReceivingOriginalV1,
    ) -> Result<ResourceVector, BrokerSessionSecurityError> {
        self.host_execution_session_demand_inner_v2(transcript, original, HostExecutionReceivingPurposeV2::Output(method))
    }

    pub(crate) fn host_stop_demand_v4(
        &self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        original: &mut HostExecutionSessionReceivingOriginalV1,
    ) -> Result<ResourceVector, BrokerSessionSecurityError> {
        self.host_execution_session_demand_inner_v2(
            transcript, original, HostExecutionReceivingPurposeV2::HostStop,
        )
    }

    pub(crate) fn host_stop_inventory_demand_v5(&self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        original: &mut HostExecutionSessionReceivingOriginalV1,
    ) -> Result<ResourceVector, BrokerSessionSecurityError> {
        self.host_execution_session_demand_inner_v2(transcript, original,
            HostExecutionReceivingPurposeV2::HostStopInventory)
    }

    fn host_execution_session_demand_inner_v2(
        &self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        original: &mut HostExecutionSessionReceivingOriginalV1,
        purpose: HostExecutionReceivingPurposeV2,
    ) -> Result<ResourceVector, BrokerSessionSecurityError> {
        if original.extent.is_some() || original.append.is_some() || original.demand.is_some()
            || self.journal.endpoint.role() != BrokerSessionDurableEndpointV1::Client
            || self.journal.endpoint.protected_protocol_and_node().0 != transcript.protocol()
            || match purpose {
                HostExecutionReceivingPurposeV2::Argument(method) => transcript.protocol() != BrokerSessionProtocolV1::Host
                    || !matches!(method, BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2
                        | BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2),
                HostExecutionReceivingPurposeV2::AuthorizeAndObserve
                | HostExecutionReceivingPurposeV2::HostStop
                | HostExecutionReceivingPurposeV2::HostStopInventory => transcript.protocol() != BrokerSessionProtocolV1::Host,
                HostExecutionReceivingPurposeV2::Output(method) => !matches!(method,
                    BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT
                    | BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_OUTPUT
                    | BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
                    | BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE
                    | BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1
                    | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1),
            }
        { return Err(BrokerSessionSecurityError::Currentness); }
        let journal = self.journal.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        original.extent = Some(journal.held_session_receiving_extent_v1(&mut original.metadata));
        original.demand = Some((|| {
            let extent = original.extent.as_ref().and_then(|v| v.as_ref().ok())
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            let shared = match purpose {
                HostExecutionReceivingPurposeV2::Output(method) => {
                    aos_sandbox::journal::broker_session_receiving::execution_output_client_demand_v1(extent, transcript, method)?
                }
                HostExecutionReceivingPurposeV2::Argument(method) => {
                    aos_sandbox::journal::broker_session_receiving::host_execution_argument_client_demand_v1(
                        extent, transcript, method,
                    )?
                }
                HostExecutionReceivingPurposeV2::HostStopInventory => {
                    aos_sandbox::journal::broker_session_receiving::host_stop_inventory_client_demand_v5(extent, transcript)?
                }
                HostExecutionReceivingPurposeV2::HostStop => {
                    aos_sandbox::journal::broker_session_receiving::host_stop_client_demand_v4(extent, transcript)?
                }
                HostExecutionReceivingPurposeV2::AuthorizeAndObserve => {
                    aos_sandbox::journal::broker_session_receiving::host_execution_authorize_observe_client_demand_v2(
                        extent, transcript,
                    )?
                }
            };
            original.append = Some(journal.captured_append_receiving_demand_v1(shared.get(D::StorageBytes)));
            let append = original.append.as_ref().and_then(|result| result.as_ref().ok()).copied()
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            // A selected execution turn cannot rely on the ordinary consuming
            // adapter. Its actual fixed captured recipe supplies a nonzero
            // rooted native interval; this refusal creates no owner or grant.
            if append == ResourceVector::ZERO { return Err(BrokerSessionSecurityError::Currentness); }
            let maximum = usize::try_from(transcript.negotiated_maximum_response_bytes())
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let (bytes, files) = aos_sandbox_linux::seqpacket::SeqpacketSocket::host_execution_response_receive_obligations_v1(maximum)
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            let endpoint = crate::endpoint::endpoint_revalidation_footprint_v1()
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            let process = crate::handshake::storage_process_evidence_footprint_v1()
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            // These are the SAME endpoint/current peer archive recipes used
            // by this Session. Only their real bytes/FDs are projected here;
            // old pure field/control censuses are not namespace metadata.
            let native_bytes = endpoint.inline_bytes.checked_add(endpoint.heap_bytes)
                .and_then(|n| n.checked_add(process.inline_bytes))
                .and_then(|n| n.checked_add(process.heap_bytes))
                .and_then(|n| n.checked_add(bytes))
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            let native_files = endpoint.file_descriptors.checked_add(process.file_descriptors)
                .and_then(|n| n.checked_add(files))
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            let native = ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(native_bytes).map_err(|_| BrokerSessionSecurityError::Currentness)?)
                .with(D::OpenFiles, u64::try_from(native_files).map_err(|_| BrokerSessionSecurityError::Currentness)?);
            let native = match purpose {
                HostExecutionReceivingPurposeV2::Argument(_) | HostExecutionReceivingPurposeV2::Output(_)
                | HostExecutionReceivingPurposeV2::HostStop
                | HostExecutionReceivingPurposeV2::HostStopInventory => native,
                HostExecutionReceivingPurposeV2::AuthorizeAndObserve => native.checked_add(native)
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?,
            };
            let historical_snapshot = match purpose {
                HostExecutionReceivingPurposeV2::Output(
                    BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1
                    | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1) => {
                    // The complete future native prefix dominates its one
                    // stored-history value. This is the reached prefix plus
                    // actual forecast appends, not a guessed frame multiplier.
                    let bytes = extent.native_bytes.checked_add(shared.get(D::StorageBytes))
                        .and_then(|bytes| bytes.checked_add(
                            u64::try_from(std::mem::size_of::<Vec<u8>>().checked_mul(2)?).ok()?))
                        .ok_or(BrokerSessionSecurityError::Currentness)?;
                    ResourceVector::ZERO.with(D::MemoryBytes, bytes)
                }
                _ => ResourceVector::ZERO,
            };
            shared.checked_add(native).and_then(|demand| demand.checked_add(append))
                .and_then(|demand| demand.checked_add(historical_snapshot))
                .map_err(|_| BrokerSessionSecurityError::Currentness)
        })());
        original.demand.as_ref().and_then(|v| v.as_ref().ok()).copied()
            .ok_or(BrokerSessionSecurityError::Currentness)
    }
}
