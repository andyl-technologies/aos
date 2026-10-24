//! Protected lineage for Host-minted payload-scope handles.
//!
//! The random handle is a name for one launch-verified physical scope, not a
//! grant. Its authenticated row survives a Host process restart only while the
//! current completed Guardian lineage and fresh kernel proof still agree.

use serde::{Deserialize, Serialize};

use super::transition::{GuardianLaunchPhase, ProcessProofSnapshot, RuntimeProofSnapshot};
use super::{HostState, MAXIMUM_EXECUTION_AUTHENTICATION_BYTES, MAXIMUM_REQUESTS};
use crate::authorization::HostAuthorityV1;
use crate::worker::HostRuntimeIdentity;
use crate::{HostError, Result};

const DOMAIN: &[u8] = b"aos.sandbox.host.payload-scope-handle.v1\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DurableScopeHandle {
    pub(super) binding: ScopeHandleBindingV1,
    pub(super) authentication: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ScopeHandleBindingV1 {
    pub(super) sandbox_id: [u8; 16],
    pub(super) incarnation_id: [u8; 16],
    pub(super) source_request_id: [u8; 16],
    pub(super) unit_binding: [u8; 32],
    pub(super) guardian_invocation: [u8; 16],
    pub(super) payload_invocation: [u8; 16],
    pub(super) worker_proof: RuntimeProofSnapshot,
    pub(super) handle: [u8; 32],
}

impl ScopeHandleBindingV1 {
    fn new(
        identity: &HostRuntimeIdentity,
        lineage: &super::CompletedGuardianLineage,
        handle: [u8; 32],
    ) -> Self {
        Self {
            sandbox_id: *identity.sandbox_id(),
            incarnation_id: *identity.incarnation_id(),
            source_request_id: lineage.source_request_id,
            unit_binding: lineage.binding,
            guardian_invocation: lineage.guardian_invocation,
            payload_invocation: lineage.payload_invocation,
            worker_proof: lineage.worker_proof,
            handle,
        }
    }

    pub(super) fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(DOMAIN.len() + 296);
        bytes.extend_from_slice(DOMAIN);
        bytes.extend_from_slice(&self.sandbox_id);
        bytes.extend_from_slice(&self.incarnation_id);
        bytes.extend_from_slice(&self.source_request_id);
        bytes.extend_from_slice(&self.unit_binding);
        bytes.extend_from_slice(&self.guardian_invocation);
        bytes.extend_from_slice(&self.payload_invocation);
        bytes.extend_from_slice(&self.worker_proof.host_boot_id);
        encode_process_proof(&mut bytes, self.worker_proof.supervisor);
        encode_process_proof(&mut bytes, self.worker_proof.payload);
        bytes.extend_from_slice(&self.worker_proof.supervisor_cgroup_id.to_le_bytes());
        bytes.extend_from_slice(&self.worker_proof.payload_cgroup_id.to_le_bytes());
        bytes.extend_from_slice(&self.worker_proof.workspace_mount_id.to_le_bytes());
        bytes.extend_from_slice(&self.worker_proof.payload_root_mount_id.to_le_bytes());
        for namespace in [
            self.worker_proof.network_namespace,
            self.worker_proof.mount_namespace,
            self.worker_proof.user_namespace,
        ] {
            bytes.extend_from_slice(&namespace.device.to_le_bytes());
            bytes.extend_from_slice(&namespace.inode.to_le_bytes());
        }
        bytes.extend_from_slice(&self.handle);
        bytes
    }

    fn has_valid_shape(self) -> bool {
        self.sandbox_id != [0; 16]
            && self.incarnation_id != [0; 16]
            && self.source_request_id != [0; 16]
            && self.unit_binding != [0; 32]
            && self.guardian_invocation != [0; 16]
            && self.payload_invocation != [0; 16]
            && self.handle != [0; 32]
            && self.worker_proof.validate()
    }
}

fn encode_process_proof(bytes: &mut Vec<u8>, proof: ProcessProofSnapshot) {
    bytes.extend_from_slice(&proof.pid.to_le_bytes());
    bytes.extend_from_slice(&proof.thread_group_id.to_le_bytes());
    bytes.extend_from_slice(&proof.parent_pid.to_le_bytes());
    bytes.extend_from_slice(&proof.cgroup_id.to_le_bytes());
    bytes.extend_from_slice(&proof.start_time_ticks.to_le_bytes());
}

impl DurableScopeHandle {
    pub(super) fn source_request_id(&self) -> [u8; 16] {
        self.binding.source_request_id
    }

    pub(super) fn validate_shape(&self) -> Result<()> {
        if !self.binding.has_valid_shape()
            || self.authentication.is_empty()
            || self.authentication.len() > MAXIMUM_EXECUTION_AUTHENTICATION_BYTES
        {
            return Err(HostError::State(
                "durable Host scope handle has invalid shape".to_owned(),
            ));
        }
        Ok(())
    }
}

impl HostState {
    pub(super) fn validate_scope_handles(&self, authority: &HostAuthorityV1) -> Result<()> {
        let mut incarnations = std::collections::BTreeSet::new();
        for (request_id, record) in &self.scope_handles {
            record.validate_shape()?;
            let binding = record.binding;
            let source = self.requests.get(request_id).ok_or_else(|| {
                HostError::State("Host scope handle has no retained launch".to_owned())
            })?;
            let completed_launch =
                source
                    .execution
                    .guardian_attempt()
                    .and_then(|attempt| match attempt.phase {
                        GuardianLaunchPhase::Complete {
                            guardian_invocation,
                            payload_invocation,
                            worker_proof,
                            ..
                        } if source.receipt.is_some() => Some((
                            attempt.binding,
                            *guardian_invocation,
                            *payload_invocation,
                            *worker_proof,
                        )),
                        _ => None,
                    });
            if *request_id != binding.source_request_id
                || source.fence.sandbox_id != binding.sandbox_id
                || source.fence.incarnation_id != binding.incarnation_id
                || completed_launch
                    != Some((
                        binding.unit_binding,
                        binding.guardian_invocation,
                        binding.payload_invocation,
                        binding.worker_proof,
                    ))
                || !incarnations.insert((binding.sandbox_id, binding.incarnation_id))
                || authority.open_execution_record(request_id, &record.authentication)?
                    != binding.encode()
            {
                return Err(HostError::State(
                    "Host scope handle lineage is unauthenticated or ambiguous".to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn current_scope_handle(
        &self,
        identity: &HostRuntimeIdentity,
        lineage: &super::CompletedGuardianLineage,
    ) -> Result<Option<[u8; 32]>> {
        let Some(record) = self.scope_handles.get(&lineage.source_request_id) else {
            return Ok(None);
        };
        let expected = ScopeHandleBindingV1::new(identity, lineage, record.binding.handle);
        if record.binding != expected {
            return Err(HostError::State(
                "durable Host scope handle differs from current launch".to_owned(),
            ));
        }
        Ok(Some(record.binding.handle))
    }

    pub(crate) fn retain_scope_handle(
        &mut self,
        identity: &HostRuntimeIdentity,
        lineage: &super::CompletedGuardianLineage,
        handle: [u8; 32],
        authority: &HostAuthorityV1,
    ) -> Result<bool> {
        let binding = ScopeHandleBindingV1::new(identity, lineage, handle);
        if !binding.has_valid_shape() {
            return Err(HostError::State(
                "Host cannot retain an invalid scope handle".to_owned(),
            ));
        }
        if let Some(current) = self.scope_handles.get(&lineage.source_request_id) {
            if current.binding != binding {
                return Err(HostError::State(
                    "Host scope handle cannot be replaced".to_owned(),
                ));
            }
            return Ok(false);
        }
        if self.scope_handles.len() >= MAXIMUM_REQUESTS
            || self.scope_handles.values().any(|record| {
                (record.binding.sandbox_id == binding.sandbox_id
                    && record.binding.incarnation_id == binding.incarnation_id)
                    || record.binding.handle == binding.handle
            })
        {
            return Err(HostError::State(
                "Host scope handle lineage is full or ambiguous".to_owned(),
            ));
        }
        let authentication =
            authority.seal_execution_record(&lineage.source_request_id, &binding.encode())?;
        let record = DurableScopeHandle {
            binding,
            authentication,
        };
        record.validate_shape()?;
        self.scope_handles.insert(lineage.source_request_id, record);
        Ok(true)
    }
}
