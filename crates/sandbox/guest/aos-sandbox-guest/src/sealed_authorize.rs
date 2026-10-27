//! Shares the retained sealed-spec reader between closed Authorize transports.
//!
//! The calling transport retains its complete record and remaining descriptor
//! roles. This engine owns the moved specification descriptor and mapping;
//! failed reads never escape into the cross-thread process ledger.

use std::error::Error;
use std::os::fd::OwnedFd;

use aos_sandbox_guest_protocol::{AgentOperationRequestV1, AgentProtocolError};
use aos_sandbox_linux::immutable_file::{SealedMemfdReadClosedV2, SealedMemfdReadOriginalV2};

use crate::protected_entry::ProtectedGuestAgentErrorV1;

pub(crate) struct SealedAuthorizeOriginalV1 {
    sealed: SealedMemfdReadOriginalV2,
    read: Option<Result<(), SealedMemfdReadClosedV2>>,
    reconstructed: Option<Result<(), AgentProtocolError>>,
}

impl SealedAuthorizeOriginalV1 {
    pub(crate) fn new() -> Self {
        Self {
            sealed: SealedMemfdReadOriginalV2::new(),
            read: None,
            reconstructed: None,
        }
    }

    pub(crate) fn was_entered(&self) -> bool {
        self.read.is_some()
    }

    pub(crate) fn reconstruct_once(
        &mut self,
        descriptor: OwnedFd,
        bytes: u64,
        reconstruct: impl FnOnce(&[u8]) -> Result<AgentOperationRequestV1, AgentProtocolError>,
    ) -> Result<AgentOperationRequestV1, ProtectedGuestAgentErrorV1> {
        // Constructors call this only after checking was_entered while they
        // still hold their complete received descriptor vector.
        self.read = Some(self.sealed.prepare_once(
            descriptor,
            bytes,
            aos_sandbox_guest_protocol::MAX_AGENT_SEALED_SPEC_BYTES_V1 as u64,
        ));
        if !matches!(self.read, Some(Ok(()))) {
            return Err(ProtectedGuestAgentErrorV1::CaptureRefused);
        }
        let request = self
            .sealed
            .with_bytes(|bytes, _| reconstruct(bytes))
            .map_err(|_| ProtectedGuestAgentErrorV1::CaptureRefused)?;
        match request {
            Ok(request) => {
                self.reconstructed = Some(Ok(()));
                Ok(request)
            }
            Err(cause) => {
                self.reconstructed = Some(Err(cause));
                Err(ProtectedGuestAgentErrorV1::CaptureRefused)
            }
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.sealed
            .failure()
            .or_else(|| self.read.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| {
                self.reconstructed
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
    }
}
