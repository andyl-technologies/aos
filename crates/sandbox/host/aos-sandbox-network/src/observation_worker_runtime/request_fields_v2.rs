//! Shares the existing O request encoder over borrowed canonical plan DATA.
//!
//! Fixed correlation fields can remain on the actual parent owner without
//! cloning the signed plan model. The ordinary owned request delegates to the
//! identical validation and byte recipe; this adapter grants no read authority.

use super::*;

#[derive(Clone, Copy)]
pub(super) struct ObservationRequestFieldsV2 {
    pub(super) request_id: [u8; 16],
    pub(super) effect_digest: ObjectDigest,
    pub(super) kernel_plan_digest: ObjectDigest,
    pub(super) kernel_boot_id: [u8; 16],
    pub(super) namespace: NamespaceIdentity,
    pub(super) expected_state: NetworkNamespaceObservedStateV1,
}

impl ObservationRequestFieldsV2 {
    pub(super) fn validate(
        &self,
        plan: &NetworkKernelPlanV1,
    ) -> Result<(), NetworkObservationWorkerError> {
        if self.request_id == [0; 16]
            || self.effect_digest.as_bytes() == &[0; 32]
            || self.kernel_plan_digest != plan.digest()
            || self.kernel_boot_id == [0; 16]
            || self.namespace.device == 0
            || self.namespace.inode == 0
        {
            return protocol("observation request identity is invalid");
        }
        Ok(())
    }

    pub(super) fn encode(
        &self,
        plan: &NetworkKernelPlanV1,
    ) -> Result<Vec<u8>, NetworkObservationWorkerError> {
        self.validate(plan)?;
        let total = REQUEST_HEADER_BYTES
            .checked_add(plan.as_bytes().len())
            .ok_or(NetworkObservationWorkerError::Protocol(
                "observation request length overflowed",
            ))?;
        let total_u32 = u32::try_from(total).map_err(|_| {
            NetworkObservationWorkerError::Protocol("observation request is too large")
        })?;
        let plan_length = u32::try_from(plan.as_bytes().len())
            .map_err(|_| NetworkObservationWorkerError::Protocol("kernel plan is too large"))?;
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(REQUEST_MAGIC);
        bytes.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        bytes.push(REQUEST_KIND);
        bytes.push(0);
        bytes.extend_from_slice(&total_u32.to_be_bytes());
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(self.effect_digest.as_bytes());
        bytes.extend_from_slice(self.kernel_plan_digest.as_bytes());
        bytes.extend_from_slice(&self.kernel_boot_id);
        bytes.extend_from_slice(&self.namespace.device.to_be_bytes());
        bytes.extend_from_slice(&self.namespace.inode.to_be_bytes());
        bytes.push(observed_state_code(self.expected_state.kind()));
        bytes.extend_from_slice(&[0; 3]);
        let (lease_digest, lease_generation, lease_deadline) = self
            .expected_state
            .lease()
            .unwrap_or((ObjectDigest::from_bytes([0; 32]), 0, 0));
        bytes.extend_from_slice(lease_digest.as_bytes());
        bytes.extend_from_slice(&lease_generation.to_be_bytes());
        bytes.extend_from_slice(&lease_deadline.to_be_bytes());
        bytes.extend_from_slice(&plan_length.to_be_bytes());
        bytes.extend_from_slice(plan.as_bytes());
        Ok(bytes)
    }
}
