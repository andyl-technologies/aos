//! Captures only explicitly selected complete Runtime7 conditional model owners.
//!
//! Legacy native capture remains unchanged. Original owner grouping, current
//! binding and descriptor checks, finite credits and unchanged-cut checks are
//! required before and after every separately selected native model callback.

use super::*;

impl NodeRuntime {
    /// Captures complete Runtime7 native model journals without executing work.
    ///
    /// The canonical runtime body and actual local ledgers must agree before
    /// callbacks. Physical artifact custody and unqualified adapters refuse.
    ///
    /// # Errors
    /// Refuses changed source/target authority, unsupported native journals,
    /// missing complete owner coverage or exhausted finite capture credits.
    pub fn capture_installed_original_lineage(
        &mut self,
        graph: &crate::node_admission::AdmittedGraph,
        activation: &WorldActivation,
        source: &OriginalLineageRuntimeRecord,
        runtime_object: &crate::node_scheduling::InputPayload,
        lineage_limits: OriginalInputLineageLimits,
        limits: NativeCaptureLimits,
    ) -> Result<Vec<InstalledNativeCapture>, RuntimePollFailure> {
        self.validate_activation(activation)
            .map_err(RuntimePollFailure::Admission)?;
        if graph.world_binding_hash() != &source.source_activation.world_binding_hash
            || self
                .original_lineage_runtime_snapshot(
                    source.capture_cut,
                    source.capture_ordinal,
                    lineage_limits,
                    limits.maximum_record_bytes,
                )
                .map_err(RuntimePollFailure::Admission)?
                != *source
        {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ));
        }
        runtime_object
            .reference
            .verify(&runtime_object.bytes)
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
        let value = crucible_node_contract::canonical::parse_json(
            &runtime_object.bytes,
            limits.maximum_record_bytes,
        )
        .map_err(|_| RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
        let decoded: OriginalLineageRuntimeRecord = serde_json::from_value(value)
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
        if decoded != *source {
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        let mut captures = Vec::new();
        captures
            .try_reserve_exact(graph.ownership_policy().capture_owners.len())
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
        let mut groups = Vec::new();
        groups
            .try_reserve_exact(graph.ownership_policy().capture_owners.len())
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
        for policy in &graph.ownership_policy().capture_owners {
            let participants: Vec<_> = graph
                .node_ids()
                .filter(|node| {
                    graph.binding(node).is_some_and(|binding| {
                        binding.compatibility.capture_owner.id == policy.owner_id
                    })
                })
                .cloned()
                .collect();
            let representative = participants
                .first()
                .ok_or(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
            // The selected representative must positively attest the complete
            // shared-owner roster. Selection alone never establishes ownership.
            for participant in &participants {
                let binding = graph
                    .binding(participant)
                    .ok_or(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
                let node = self
                    .nodes
                    .get(participant)
                    .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
                if binding.compatibility.capture_owner.participant_ids != participants
                    || binding.compatibility.implementation.formats.is_empty()
                    || binding.compatibility.operating_contract.facets.is_empty()
                    || node.binding() != binding
                    || graph.descriptor(participant) != Some(node.descriptor())
                {
                    return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
                }
                if !node.thread_affinity().permits_current_thread() {
                    return Err(RuntimePollFailure::Admission(RuntimeError::ThreadAffinity));
                }
            }
            groups.push((
                policy.owner_id.clone(),
                representative.clone(),
                participants,
            ));
        }

        let mut remaining = limits;
        for (owner, representative, participants) in groups {
            // Every capture contains at least its native state object. Refuse
            // exhausted world credits before entering another native hook.
            if remaining.maximum_objects == 0 {
                return Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit));
            }
            remaining.maximum_record_bytes = remaining
                .maximum_record_bytes
                .min(remaining.maximum_total_record_bytes);
            remaining.maximum_artifact_bytes = remaining
                .maximum_artifact_bytes
                .min(remaining.maximum_total_artifact_bytes);
            let node = self
                .nodes
                .get_mut(&representative)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
            let captured = node
                .capture_original_lineage_continuation(
                    activation,
                    source,
                    runtime_object,
                    remaining,
                )
                .map_err(RuntimePollFailure::Native)?;
            if captured.owner != owner
                || captured.participants != participants
                || captured.cut != source.capture_cut
            {
                return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
            }
            if !captured.artifacts.is_empty() {
                return Err(RuntimePollFailure::Admission(
                    RuntimeError::UnsupportedFacet,
                ));
            }
            let mut bytes = 0usize;
            let mut artifacts = 0u64;
            let mut objects = 0usize;
            for participant in &participants {
                let binding = graph
                    .binding(participant)
                    .ok_or(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
                if captured.key.implementation
                    != binding.compatibility.implementation.implementation_id
                    || !binding
                        .compatibility
                        .operating_contract
                        .facets
                        .iter()
                        .any(|facet| facet.id == captured.key.profile)
                    || !binding
                        .compatibility
                        .implementation
                        .formats
                        .contains(&captured.key.schema)
                {
                    return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
                }
            }
            for object in std::iter::once(&captured.state).chain(&captured.evidence) {
                if object.bytes.len() > remaining.maximum_record_bytes {
                    return Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit));
                }
                object
                    .reference
                    .verify(&object.bytes)
                    .map_err(|_| RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
                bytes = bytes
                    .checked_add(object.bytes.len())
                    .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
                objects = objects
                    .checked_add(1)
                    .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
            }
            let mut names = std::collections::BTreeSet::new();
            for artifact in &captured.artifacts {
                if artifact.reference.length.get() > remaining.maximum_artifact_bytes
                    || !names.insert((artifact.role.clone(), artifact.name.clone()))
                {
                    return Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit));
                }
                artifact.verify().map_err(RuntimePollFailure::Native)?;
                artifacts = artifacts
                    .checked_add(artifact.reference.length.get())
                    .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
                objects = objects
                    .checked_add(1)
                    .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
            }
            remaining.maximum_total_record_bytes = remaining
                .maximum_total_record_bytes
                .checked_sub(bytes)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
            remaining.maximum_objects = remaining
                .maximum_objects
                .checked_sub(objects)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
            remaining.maximum_total_artifact_bytes = remaining
                .maximum_total_artifact_bytes
                .checked_sub(artifacts)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
            captures.push(captured);
        }
        if self
            .original_lineage_runtime_snapshot(
                source.capture_cut,
                source.capture_ordinal,
                lineage_limits,
                limits.maximum_record_bytes,
            )
            .map_err(RuntimePollFailure::Admission)?
            != *source
        {
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        Ok(captures)
    }
}
