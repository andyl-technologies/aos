//! Authenticated original lifetime selectors for historical QueryExecution reads.
//!
//! The existing signed Authorize handoff stores a compact source under its same
//! State authentication. A historical read additionally joins the distinct
//! completed first Observe and actual native terminal marker; these bytes never
//! replace fresh Query permission or lend execution/physical completion authority.

use aos_sandbox_model::runtime_backend::EffectOperationV1;
use aos_sandbox_protocol::host_execution::{ValidatedHostExecutionApplyV1, ValidatedHostExecutionQueryV1};
use aos_sandbox_protocol::host_execution::admission_content::LifetimeSourceDataV5;
use aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2;
use aos_sandbox_protocol::storage_capture_lifetime::StorageCaptureExecutionLifetimeDataV2;
use serde::{Deserialize, Serialize};
use super::*;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HistoricalExecutionReadBindingV5 {
    version: u8,
    source_kind: u8,
    source: Vec<u8>,
    content_bytes: u64,
    content_digest: [u8; 32],
}

impl HistoricalExecutionReadBindingV5 {
    // Count the same serializer's fixed prefix without allocating source bytes.
    // A JSON byte takes at most three digits plus its comma. Eight encoded
    // planes cover both live encodings and their allocation growth; model and
    // inline source copies remain separate from those byte buffers.
    pub(crate) fn receiving_bytes_v5() -> Option<usize> {
        let width = aos_sandbox_protocol::storage_capture_grant::STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V2;
        let fixed = Self { version: u8::MAX, source_kind: u8::MAX, source: Vec::new(),
            content_bytes: u64::MAX, content_digest: [255; 32] };
        let mut count = super::transition::AuthenticationByteCountV5(0);
        serde_json::to_writer(&mut count, &fixed).ok()?;
        count.0.checked_add(width.checked_mul(4)?)?.checked_mul(8)?
            .checked_add(width.checked_mul(4)?)?
            .checked_add(std::mem::size_of::<Self>().checked_mul(4)?)?
            .checked_add(std::mem::size_of::<LifetimeSourceDataV5>().checked_mul(16)?)
    }

    pub(crate) fn from_admitted_apply_v5(apply: &ValidatedHostExecutionApplyV1)
        -> Result<Option<Self>> {
        if apply.content_version() != 5 { return Ok(None); }
        if apply.action() != EffectOperationV1::AuthorizeExecution { return Err(refused()); }
        let source = apply.admission_source_data_v5().ok_or_else(refused)?;
        let content = apply.content_fields().ok_or_else(refused)?;
        let (source_kind, source) = match source {
            LifetimeSourceDataV5::Stream(lifetime) => (1, lifetime.canonical_bytes_v2().to_vec()),
            LifetimeSourceDataV5::Capture(source) => (2, source.canonical_bytes_v2().to_vec()),
        };
        Ok(Some(Self { version: 5, source_kind, source,
            content_bytes: content.bytes(), content_digest: content.digest() }))
    }

    pub(crate) fn dynamic_bytes_v5(&self) -> usize { self.source.capacity() }

    fn source_data_v5(&self) -> Result<LifetimeSourceDataV5> {
        if self.version != 5 || self.content_bytes == 0
            || self.content_bytes > aos_sandbox_protocol::host_execution::admission_content::MAXIMUM_ADMISSION_CONTENT_BYTES_V5 as u64
            || self.content_digest == [0; 32] {
            return Err(refused());
        }
        match self.source_kind {
            1 => Ok(LifetimeSourceDataV5::Stream(StorageCaptureExecutionLifetimeDataV2::from_canonical_bytes_v2(&self.source)?)),
            2 => Ok(LifetimeSourceDataV5::Capture(StorageCaptureGrantSourceV2::from_canonical_bytes_v2(&self.source)?)),
            _ => Err(refused()),
        }
    }

    pub(crate) fn is_consistent_v5(&self, context: ExecutionContext,
        handoff: &HostExecutionHandoffRecord) -> bool {
        let Ok(source) = self.source_data_v5() else { return false; };
        let lifetime = match &source {
            LifetimeSourceDataV5::Stream(lifetime) => lifetime,
            LifetimeSourceDataV5::Capture(source) => source.lifetime_v2(),
        };
        context.action == HostAction::ApplyExecution
            && lifetime.execution_v2().as_bytes() == &handoff.execution_id
            && lifetime.original_create_operation_v2().as_bytes() == &handoff.operation_id
            && lifetime.assignment_v2().digest().as_bytes() == &context.assignment_digest
    }

    fn matches_query_v5(&self, handoff: &HostExecutionHandoffRecord,
        query: &ValidatedHostExecutionQueryV1) -> Result<bool> {
        let selector = query.monitor_v3().ok_or_else(refused)?;
        let source = self.source_data_v5()?;
        let (lifetime, digest) = match &source {
            LifetimeSourceDataV5::Stream(lifetime) => (lifetime, lifetime.digest_v2()),
            LifetimeSourceDataV5::Capture(source) => (source.lifetime_v2(), source.source_digest_v2()),
        };
        Ok(lifetime.execution_v2() == query.execution_id()
            && lifetime.original_create_operation_v2().as_bytes() == &query.operation_id()
            && lifetime.specification_digest_v2() == query.specification_digest()
            && handoff.source_commitment == *query.source_commitment().as_bytes()
            && handoff.runtime_handle == *selector.runtime_v3().as_bytes()
            && self.content_bytes == query.content_fields().bytes()
            && self.content_digest == query.content_fields().digest()
            && u32::from(self.source_kind) == selector.source_kind_v3()
            && digest == selector.source_v3())
    }
}

impl HostState {
    pub(crate) fn require_historical_execution_query_v5(&self,
        query: &ValidatedHostExecutionQueryV1, authority: &HostAuthorityV1) -> Result<()> {
        // The caller has paid the full current model/authentication census and
        // genuinely admitted its fresh read before this authenticated traversal.
        self.validate_authenticated(authority)?;
        let selector = query.monitor_v3().ok_or_else(refused)?;
        let mut original = None;
        let mut observed = None;
        for request in self.requests.values() {
            let DurableExecution::HostExecutionHandoff(handoff) = &request.execution else { continue; };
            if handoff.execution_id != *query.execution_id().as_bytes()
                || handoff.runtime_handle != *selector.runtime_v3().as_bytes()
                || handoff.source_commitment != *query.source_commitment().as_bytes()
            { continue; }
            if let Some(binding) = &handoff.historical_read_binding_v5 {
                if !binding.matches_query_v5(handoff, query)? || original.replace(request).is_some() {
                    return Err(refused());
                }
            }
            if handoff.operation_id == *selector.first_observe_v3().as_bytes() {
                if request.action != HostAction::ApplyExecution.code() || request.receipt.is_none()
                    || handoff.historical_read_binding_v5.is_some() || observed.replace(request).is_some()
                { return Err(refused()); }
            }
        }
        let original = original.ok_or_else(refused)?;
        let observed = observed.ok_or_else(refused)?;
        if original.receipt.is_none() || original.request_id == observed.request_id {
            return Err(refused());
        }
        Ok(())
    }
}

fn refused() -> HostError { HostError::Fence("historical execution binding is unavailable") }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_absent_unknown_and_cross_kind_rows_never_become_historical_proofs() {
        let binding = HistoricalExecutionReadBindingV5 { version: 5, source_kind: 1,
            source: vec![0; 424], content_bytes: 1, content_digest: [1; 32] };
        assert!(binding.source_data_v5().is_err());
        let mut changed = binding.clone();
        changed.version = 6;
        assert!(changed.source_data_v5().is_err());
        changed.version = 5;
        changed.source_kind = 2;
        assert!(changed.source_data_v5().is_err());
        assert!(serde_json::from_slice::<HistoricalExecutionReadBindingV5>(b"{} ").is_err());
    }

    #[test]
    fn source_decimal_encoder_and_copy_planes_fit_the_named_fixed_supplier() {
        for width in [0, 424, 944] {
            for byte in [0, 9, 99, 255] {
                let binding = HistoricalExecutionReadBindingV5 { version: 5, source_kind: 2,
                    source: vec![byte; width], content_bytes: u64::MAX, content_digest: [255; 32] };
                let encoded = serde_json::to_vec(&binding).unwrap();
                let co_live = binding.dynamic_bytes_v5() * 4 + encoded.capacity() * 4
                    + std::mem::size_of::<LifetimeSourceDataV5>() * 16;
                assert!(co_live <= HistoricalExecutionReadBindingV5::receiving_bytes_v5().unwrap());
            }
        }
    }
}
