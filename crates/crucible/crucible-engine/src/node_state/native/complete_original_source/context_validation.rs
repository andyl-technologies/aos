//! Prices the same retained source's final metadata and Event body validation.
//!
//! The original Host decode limits remain attached to this exact signed source.
//! This raw DATA factor scans verified body bytes without decoding an Event,
//! cloning an owner, invoking a native callback or issuing a context.

use super::*;
use crate::node_contract::{NodeRuntime, OriginalLineageRestorationLimits};
use crucible_node_format::{Event, HashRef};
use std::mem::size_of;

impl CompleteOriginalRestorationSource {
    pub(crate) fn original_installed_context_limits_data(
        &self,
    ) -> Result<OriginalLineageRestorationLimits, RuntimeError> {
        self.inner.authenticate_birth()?;
        Ok(OriginalLineageRestorationLimits {
            maximum_record_bytes: self.inner.validation_limits.maximum_record_bytes,
            lineage: self.inner.validation_limits.lineage,
        })
    }

    pub(crate) fn original_installed_context_validation_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.inner.authenticate_birth()?;
        let host_owner = self
            .inner
            .archive
            .owners()
            .iter()
            .find(|owner| owner.owner == self.inner.host.selection_data().owner.owner.id)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let host_bytes = self
            .inner
            .content
            .get(&host_owner.state)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let geometry = super::super::core_decode_credit::preflight(host_bytes, maximum)?;
        let metadata = super::super::core_decode_credit::validation_storage(
            &geometry,
            self.inner.validation_limits,
        )?;
        let record = self.original_runtime_record_data()?;
        let mut event_peak = 0usize;
        // Event contains only these closed DTO families plus its explicit
        // extension map and causal ID vector. Charge each raw container/root
        // independently, including empty objects before their typed validation.
        let typed = size_of::<Event>()
            .max(size_of::<ContentRef>())
            .max(size_of::<HashRef>())
            .max(size_of::<crucible_node_format::Endpoint>())
            .max(size_of::<Id>())
            .max(size_of::<serde_json::Value>());
        let map = NodeRuntime::capture_map_node_storage::<String, serde_json::Value>()
            .max(NodeRuntime::capture_map_node_storage::<Id, ()>());
        for input in &record.inputs {
            let Some(lineage) = &input.lineage else {
                continue;
            };
            for publication in &lineage.publications {
                let bytes = self
                    .inner
                    .content
                    .get(&publication.published)
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                if bytes.len() > self.inner.validation_limits.maximum_record_bytes {
                    return Err(RuntimeError::ResourceLimit);
                }
                let demand =
                    NodeRuntime::capture_selected_json_decode_storage(bytes, typed, map, maximum)?
                        .checked_add(size_of::<Event>())
                        .and_then(|n| {
                            n.checked_add(
                                Self::original_installed_context_validation_counter_scratch_data(),
                            )
                        })
                        .ok_or(RuntimeError::ResourceLimit)?;
                event_peak = event_peak.max(demand);
            }
        }
        let demand = metadata
            .checked_add(event_peak)
            .ok_or(RuntimeError::ResourceLimit)?;
        if demand > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(demand)
    }

    pub(crate) fn original_installed_context_validation_counter_scratch_data() -> usize {
        super::super::core_decode_credit::scanner_storage()
            + size_of::<Result<super::super::core_decode_credit::DecodeCredit, RuntimeError>>()
            + size_of::<Result<Event, crucible_node_format::ContractError>>()
            + size_of::<Result<serde_json::Value, crucible_node_format::ContractError>>()
            + size_of::<Result<(), crucible_node_format::ContractError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Option<&[u8]>>()
            + size_of::<OriginalLineageRestorationLimits>()
            + size_of::<Result<OriginalLineageRestorationLimits, RuntimeError>>()
            + size_of::<std::slice::Iter<'static, crate::node_contract::OriginalLineageInputRecord>>(
            )
            + size_of::<std::slice::Iter<'static, crate::node_contract::SavedOriginalPublication>>()
    }
}
