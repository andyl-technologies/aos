//! Host-local durability for one read-only Storage output exchange.
//!
//! The record retains the existing query and reply formats without defining
//! another wire carrier. Host authentication binds the observed bytes to the
//! original reservation, but does not establish an all-owner effect barrier.
//!
//! ```text
//! Host state: request ID, request digest, boot, assignment,
//!             AOSEOQ01 request, AOSEORQ1 reply, local authentication
//! ```

use aos_sandbox_protocol::storage_existing_output::{
    ExistingOutputRequestV1, ExistingOutputResponseV1,
};
use serde::{Deserialize, Serialize};

use super::transition::DurableExecution;
use super::{HostAction, MAXIMUM_EXECUTION_AUTHENTICATION_BYTES, RequestRecord};
use crate::{HostError, Result};

const OBSERVATION_DOMAIN: &[u8] = b"aos.sandbox.host.existing-output-observation.v1\0";

/// Retains exact query bytes under Host-local authentication for later replay.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DurableExistingOutputObservation {
    pub(super) host_request_id: [u8; 16],
    pub(super) host_request_digest: [u8; 32],
    pub(super) host_boot_id: [u8; 16],
    pub(super) assignment_digest: [u8; 32],
    pub(super) request: Vec<u8>,
    pub(super) response: Vec<u8>,
    pub(super) authentication: Vec<u8>,
}

impl DurableExistingOutputObservation {
    pub(super) fn validate_shape(&self) -> Result<()> {
        let query = ExistingOutputRequestV1::decode(&self.request)
            .map_err(|_| HostError::State("Host output observation query is invalid".to_owned()))?;
        let reply = ExistingOutputResponseV1::decode(&self.response)
            .map_err(|_| HostError::State("Host output observation reply is invalid".to_owned()))?;
        reply
            .verify_request(query)
            .map_err(|_| HostError::State("Host output observation exchange differs".to_owned()))?;
        if self.host_request_id == [0; 16]
            || self.host_request_digest == [0; 32]
            || self.host_boot_id == [0; 16]
            || self.assignment_digest == [0; 32]
            || reply.assignment_digest != self.assignment_digest
            || self.authentication.len() > MAXIMUM_EXECUTION_AUTHENTICATION_BYTES
        {
            return Err(HostError::State(
                "Host output observation binding is invalid".to_owned(),
            ));
        }
        Ok(())
    }

    pub(super) fn validate_request(&self, request: &RequestRecord) -> Result<()> {
        self.validate_shape()?;
        let DurableExecution::HostExecutionHandoff(handoff) = &request.execution else {
            return Err(HostError::State(
                "Host output observation has no execution handoff".to_owned(),
            ));
        };
        let query = ExistingOutputRequestV1::decode(&self.request)
            .map_err(|_| HostError::State("Host output query is invalid".to_owned()))?;
        if request.action != HostAction::ReserveExecutionOutput.code()
            || request.request_id != self.host_request_id
            || request.request_digest != self.host_request_digest
            || request.fence.assignment_digest != self.assignment_digest
            || handoff.execution_id != query.execution
            || handoff.operation_id != query.create
        {
            return Err(HostError::State(
                "Host output observation contradicts its reserve".to_owned(),
            ));
        }
        Ok(())
    }

    pub(super) fn payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(
            OBSERVATION_DOMAIN.len() + 16 + 32 + 16 + 32 + self.request.len() + self.response.len(),
        );
        payload.extend_from_slice(OBSERVATION_DOMAIN);
        payload.extend_from_slice(&self.host_request_id);
        payload.extend_from_slice(&self.host_request_digest);
        payload.extend_from_slice(&self.host_boot_id);
        payload.extend_from_slice(&self.assignment_digest);
        payload.extend_from_slice(&self.request);
        payload.extend_from_slice(&self.response);
        payload
    }
}
