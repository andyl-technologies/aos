//! Authenticated nonmutating host capture over the owning runtime's original ledger.

use super::*;

impl NodeRuntime {
    pub(crate) fn capture_host_native(
        &self,
        activation: &WorldActivation,
        source: &RuntimeSnapshot,
        maximum_record_bytes: usize,
        maximum_native_bytes: usize,
        maximum_total_bytes: usize,
        maximum_native_objects: usize,
    ) -> Result<Vec<HostNativeCapture>, RuntimePollFailure> {
        self.validate_activation(activation)
            .map_err(RuntimePollFailure::Admission)?;
        let actual = self
            .runtime_snapshot(
                source.capture_cut,
                source.capture_ordinal,
                maximum_record_bytes,
            )
            .map_err(RuntimePollFailure::Admission)?;
        if &actual != source {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ));
        }
        let mut captures = Vec::new();
        captures
            .try_reserve_exact(self.nodes.len())
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
        let mut retained_bytes = 0usize;
        let mut retained_objects = 0usize;
        for (id, node) in &self.nodes {
            if !node.thread_affinity().permits_current_thread() {
                return Err(RuntimePollFailure::Admission(RuntimeError::ThreadAffinity));
            }
            let remaining = maximum_total_bytes
                .checked_sub(retained_bytes)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
            let capture = node
                .capture_host_continuation(activation, source, maximum_native_bytes.min(remaining))
                .map_err(RuntimePollFailure::Native)?;
            if capture.node() != id
                || capture.state.bytes.len() > maximum_native_bytes
                || capture.evidence.len() > maximum_native_objects
            {
                return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
            }
            retained_objects = retained_objects
                .checked_add(1)
                .and_then(|count| count.checked_add(capture.evidence.len()))
                .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
            retained_bytes = retained_bytes
                .checked_add(capture.state.bytes.len())
                .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
            capture
                .state
                .reference
                .verify(&capture.state.bytes)
                .map_err(|_| RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
            for evidence in &capture.evidence {
                if evidence.bytes.len() > maximum_native_bytes {
                    return Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit));
                }
                evidence
                    .reference
                    .verify(&evidence.bytes)
                    .map_err(|_| RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
                retained_bytes = retained_bytes
                    .checked_add(evidence.bytes.len())
                    .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
            }
            if retained_bytes > maximum_total_bytes || retained_objects > maximum_native_objects {
                return Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit));
            }
            captures.push(capture);
        }
        Ok(captures)
    }
}
