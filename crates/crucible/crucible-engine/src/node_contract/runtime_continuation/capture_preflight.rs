//! Seals readonly allocation facts from the same four owning native capsules.
//!
//! Row values remain inert. This process-local seal retains original runtime,
//! opaque activation, collecting plan and actual boxed node occurrence identity.
//! It registers no capture attempt and performs no modeled operation.

use super::*;
use crate::node_admission::{AdmittedGraph, InstalledConformancePlan};
use crate::node_state::{CompleteOriginalOwnerCapturePreflight, NativeArchiveLimits};

/// Retains four actual owning-node preflight occurrences without serializable authority.
pub struct PreparedCompleteOriginalCapturePreflight {
    original: OriginalSchedulingSource,
    activation: WorldActivation,
    plan: Option<InstalledConformancePlan>,
    runtime_object: ContentRef,
    limits: NativeArchiveLimits,
    nodes: [usize; 4],
    owners: [CompleteOriginalOwnerCapturePreflight; 4],
    host: Option<super::capture_ticket::host_preparation::family::PreparedHostCaptureFamily>,
    host_transferred: std::cell::Cell<bool>,
}

impl PreparedCompleteOriginalCapturePreflight {
    /// Borrows source-owned allocation facts; these rows confer no permission.
    pub fn owners(&self) -> &[CompleteOriginalOwnerCapturePreflight; 4] {
        &self.owners
    }

    pub(crate) fn capture_owned_storage(&self) -> Result<usize, RuntimeError> {
        let mut total =
            crate::node_contract::NodeRuntime::capture_reference_storage(&self.runtime_object)?;
        for owner in &self.owners {
            let key = crate::node_contract::NodeRuntime::capture_native_key_storage(&owner.key)?;
            let row =
                crate::node_contract::NodeRuntime::capture_owner_geometry_storage(&owner.geometry)?;
            total = total
                .checked_add(key)
                .and_then(|bytes| bytes.checked_add(row))
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        if let Some(prepared) = self.host.as_ref() {
            total = total
                .checked_add(prepared.owned_snapshot_storage()?)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        // Activation and plan are borrowed original shared owners. Retaining
        // these handles creates no replacement snapshot or source-body bank.
        Ok(total)
    }

    pub(crate) fn authenticate_host_family17_data(
        &self,
        restored: bool,
    ) -> Result<(), RuntimeError> {
        let host = self.host.as_ref().ok_or(RuntimeError::UnsupportedFacet)?;
        host.authenticate_family_data(restored)
    }

    pub(crate) fn take_prepared_host(
        &self,
        runtime: &crate::node_contract::NodeRuntime,
        activation: &WorldActivation,
        object: &crate::node_scheduling::InputPayload,
    ) -> Result<
        super::capture_ticket::host_preparation::family::PreparedHostCaptureFamily,
        RuntimeError,
    > {
        self.authenticate_runtime(runtime, activation, object)?;
        let prepared = self
            .host
            .as_ref()
            .ok_or(RuntimeError::OutstandingObligations)?;
        prepared.authenticate_runtime(runtime)?;
        if self.host_transferred.replace(true) {
            return Err(RuntimeError::OutstandingObligations);
        }
        // Both views retain one backing. Only the attempt can consume its
        // snapshot through the original ticket; this creates no new producer.
        Ok(prepared.retained())
    }

    pub(crate) fn authenticate_runtime(
        &self,
        runtime: &crate::node_contract::NodeRuntime,
        activation: &WorldActivation,
        runtime_object: &crate::node_scheduling::InputPayload,
    ) -> Result<(), RuntimeError> {
        self.original.authenticate_runtime_authority(
            &self.activation.record().world_binding_hash,
            &runtime.authority,
        )?;
        if !Rc::ptr_eq(&self.activation.authority, &activation.authority)
            || self.activation.record() != activation.record()
            || self.runtime_object != runtime_object.reference
            || match (&self.plan, &runtime.collecting) {
                (None, None) => false,
                (Some(plan), Some(graph)) => !plan.same_original(graph.plan()),
                _ => true,
            }
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        for (index, owner) in self.owners.iter().enumerate() {
            let [participant] = owner.geometry.participants.as_slice() else {
                return Err(RuntimeError::ForeignAuthority);
            };
            let node = runtime
                .nodes
                .get(participant)
                .ok_or(RuntimeError::UnknownNode)?;
            // The address is only private occurrence data under runtime custody;
            // it is never dereferenced, serialized or exported across processes.
            let occurrence = std::ptr::from_ref(&**node) as *const () as usize;
            if occurrence != self.nodes[index] {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        Ok(())
    }
    pub(crate) fn reloan_owner(
        &self,
        runtime: &mut crate::node_contract::NodeRuntime,
        activation: &WorldActivation,
        source: &OriginalLineageRuntimeRecord,
        runtime_object: &crate::node_scheduling::InputPayload,
        index: usize,
    ) -> Result<(), super::RuntimePollFailure> {
        use super::RuntimePollFailure;
        self.authenticate_runtime(runtime, activation, runtime_object)
            .map_err(RuntimePollFailure::Admission)?;
        runtime
            .validate_all_declarations()
            .map_err(RuntimePollFailure::Admission)?;
        let expected = self
            .owners
            .get(index)
            .ok_or(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
        let [participant] = expected.geometry.participants.as_slice() else {
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        };
        let route = runtime
            .snapshots
            .get(participant)
            .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?
            .route
            .clone();
        let node = runtime
            .nodes
            .get(participant)
            .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
        let loan = if let Some(witness) = node.original_host_scheduling_owner() {
            self.host
                .as_ref()
                .ok_or(RuntimePollFailure::Admission(
                    RuntimeError::ForeignAuthority,
                ))?
                .cached_demand(
                    runtime,
                    &witness,
                    activation,
                    source,
                    runtime_object,
                    self.limits,
                )
                .map_err(|error| OperationFailure {
                    effects: EffectKnowledge::None,
                    reason: error.to_string(),
                })
        } else {
            node.preflight_complete_original_lineage_capture(
                activation,
                source,
                runtime_object,
                self.limits,
            )
        };
        let observed = match loan {
            Ok(row) => row,
            Err(error) => {
                if error.effects != EffectKnowledge::None {
                    if let Some(state) = &runtime.scheduler {
                        state.revoke();
                    }
                    runtime.contain_roster(&route);
                }
                return Err(RuntimePollFailure::Native(error));
            }
        };
        runtime
            .validate_all_declarations()
            .map_err(RuntimePollFailure::Admission)?;
        if observed.key != expected.key || observed.geometry != expected.geometry {
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        self.authenticate_runtime(runtime, activation, runtime_object)
            .map_err(RuntimePollFailure::Admission)
    }
}

impl crate::node_contract::NodeRuntime {
    pub(crate) fn preflight_complete_original_capture(
        &mut self,
        graph: &AdmittedGraph,
        activation: &WorldActivation,
        source: &OriginalLineageRuntimeRecord,
        runtime_object: &crate::node_scheduling::InputPayload,
        host_snapshot: (
            &crate::node_scheduling::SchedulingSnapshot,
            OriginalInputLineageLimits,
        ),
        limits: NativeArchiveLimits,
    ) -> Result<PreparedCompleteOriginalCapturePreflight, super::RuntimePollFailure> {
        self.preflight_complete_capture_family_data(
            graph,
            activation,
            source,
            runtime_object,
            host_snapshot,
            limits,
            None,
        )
    }

    /// Seals actual current17 owners around the separately retained Host17 producer.
    ///
    /// # Errors
    /// Refuses foreign current Scope, prepared Host or actual owner geometry.
    pub(crate) fn preflight_complete_restored_capture17_data(
        &mut self,
        graph: &AdmittedGraph,
        activation: &WorldActivation,
        source: &OriginalLineageRuntimeRecord,
        runtime_object: &crate::node_scheduling::InputPayload,
        host_snapshot: (
            &crate::node_scheduling::SchedulingSnapshot,
            OriginalInputLineageLimits,
        ),
        limits: NativeArchiveLimits,
        scope: &crate::node_contract::RestoredCollectingCaptureScope17<'_>,
        host: Rc<crate::node_contract::PreparedRestoredHost17Capture>,
    ) -> Result<PreparedCompleteOriginalCapturePreflight, super::RuntimePollFailure> {
        scope
            .authenticate_runtime_data(self)
            .map_err(super::RuntimePollFailure::Admission)?;
        host.authenticate_runtime_data(self, activation, runtime_object)
            .map_err(super::RuntimePollFailure::Admission)?;
        let result = self.preflight_complete_capture_family_data(
            graph,
            activation,
            source,
            runtime_object,
            host_snapshot,
            limits,
            Some(host),
        );
        scope
            .authenticate_runtime_data(self)
            .map_err(super::RuntimePollFailure::Admission)?;
        result
    }

    fn preflight_complete_capture_family_data(
        &mut self,
        graph: &AdmittedGraph,
        activation: &WorldActivation,
        source: &OriginalLineageRuntimeRecord,
        runtime_object: &crate::node_scheduling::InputPayload,
        host_snapshot: (
            &crate::node_scheduling::SchedulingSnapshot,
            OriginalInputLineageLimits,
        ),
        limits: NativeArchiveLimits,
        restored_host: Option<Rc<crate::node_contract::PreparedRestoredHost17Capture>>,
    ) -> Result<PreparedCompleteOriginalCapturePreflight, super::RuntimePollFailure> {
        use super::RuntimePollFailure;
        use super::capture_ticket::host_preparation::{
            OriginalHostCapturePreparation, family::PreparedHostCaptureFamily,
        };
        let (scheduling, lineage_limits) = host_snapshot;
        self.validate_activation(activation)
            .map_err(RuntimePollFailure::Admission)?;
        self.validate_all_declarations()
            .map_err(RuntimePollFailure::Admission)?;
        if graph.world_binding_hash() != &activation.record().world_binding_hash
            || source.source_activation.activation_id != activation.record().activation_id
            || source.source_activation.world_binding_hash != *graph.world_binding_hash()
            || graph.ownership_policy().capture_owners.len() != 4
            || graph.node_ids().count() != 4
        {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ));
        }
        let original = self
            .scheduling_origin()
            .map_err(RuntimePollFailure::Admission)?
            .source();
        original
            .authenticate_runtime_authority(graph.world_binding_hash(), &self.authority)
            .map_err(RuntimePollFailure::Admission)?;
        let host = match restored_host {
            Some(host) => PreparedHostCaptureFamily::Settled17(host),
            None => {
                self.precharge_original_host_capture(
                    graph,
                    source,
                    scheduling,
                    runtime_object,
                    limits.state.maximum_total_content_bytes,
                )
                .map_err(RuntimePollFailure::Admission)?;
                let host = Rc::new(
                    OriginalHostCapturePreparation::prepare(
                        self,
                        graph,
                        source,
                        runtime_object,
                        lineage_limits,
                        limits.native.maximum_record_bytes,
                        limits.state.maximum_total_content_bytes,
                    )
                    .map_err(RuntimePollFailure::Admission)?,
                );
                PreparedHostCaptureFamily::Initial15(host)
            }
        };
        host.authenticate_runtime(self)
            .map_err(RuntimePollFailure::Admission)?;
        let mut rows = [None, None, None, None];
        let mut nodes = [0; 4];
        for (index, policy) in graph.ownership_policy().capture_owners.iter().enumerate() {
            self.validate_all_declarations()
                .map_err(RuntimePollFailure::Admission)?;
            let mut participants = graph.node_ids().filter(|id| {
                graph.binding(id).is_some_and(|binding| {
                    binding.compatibility.execution_owner.id == policy.owner_id
                })
            });
            let participant = participants
                .next()
                .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
            if participants.next().is_some() {
                return Err(RuntimePollFailure::Admission(
                    RuntimeError::UnsupportedFacet,
                ));
            }
            let binding = graph
                .binding(participant)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
            let guarantee = graph
                .guarantees(participant)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
            if guarantee.capture_scope != crucible_node_format::CaptureScope::CompleteModel
                || guarantee.continuation != crucible_node_format::Continuation::Exact
                || !guarantee.durable_restart
            {
                return Err(RuntimePollFailure::Admission(
                    RuntimeError::UnsupportedFacet,
                ));
            }
            let route = self
                .snapshots
                .get(participant)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?
                .route
                .clone();
            let node = self
                .nodes
                .get(participant)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
            nodes[index] = std::ptr::from_ref(&**node) as *const () as usize;
            let loan = if let Some(witness) = node.original_host_scheduling_owner() {
                host.cached_demand(self, &witness, activation, source, runtime_object, limits)
                    .map_err(|error| OperationFailure {
                        effects: EffectKnowledge::None,
                        reason: error.to_string(),
                    })
            } else {
                node.preflight_complete_original_lineage_capture(
                    activation,
                    source,
                    runtime_object,
                    limits,
                )
            };
            let row = match loan {
                Ok(row) => row,
                Err(error) => {
                    if error.effects != EffectKnowledge::None {
                        if let Some(state) = &self.scheduler {
                            state.revoke();
                        }
                        self.contain_roster(&route);
                    }
                    return Err(RuntimePollFailure::Native(error));
                }
            };
            self.validate_all_declarations()
                .map_err(RuntimePollFailure::Admission)?;
            if row.geometry.owner != policy.owner_id
                || row.geometry.participants.as_slice() != std::slice::from_ref(participant)
                || !row
                    .key
                    .matches_selected_complete_state_profile_data(&binding.compatibility)
            {
                return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
            }
            rows[index] = Some(row);
        }
        let [Some(a), Some(b), Some(c), Some(d)] = rows else {
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        };
        Ok(PreparedCompleteOriginalCapturePreflight {
            original,
            activation: activation.clone(),
            plan: self
                .collecting
                .as_ref()
                .map(|graph| graph.plan().retained()),
            runtime_object: runtime_object.reference.clone(),
            limits,
            nodes,
            owners: [a, b, c, d],
            host: Some(host),
            host_transferred: std::cell::Cell::new(false),
        })
    }
}

#[cfg(test)]
mod tests {
    // These controls test private runtime/node occurrence identity using one
    // repeated fixture actor. The actual collector rejects that one-node graph;
    // neither these rows nor their key can qualify a four-owner native capture.
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::node_contract::NativeStateKey;
    use crate::node_state::CompleteOriginalOwnerCaptureGeometry;
    use crucible_node_format::{SchemaRef, U64, canonical};

    fn modeled_seal(
        runtime: &crate::node_contract::NodeRuntime,
        activation: &WorldActivation,
        object: &crate::node_scheduling::InputPayload,
    ) -> PreparedCompleteOriginalCapturePreflight {
        let (node_id, node) = runtime.nodes.iter().next().unwrap();
        let occurrence = std::ptr::from_ref(&**node) as *const () as usize;
        let reference = canonical::content_ref(b"model/schema", "application/json").unwrap();
        let id = Id::new("model/native-key").unwrap();
        PreparedCompleteOriginalCapturePreflight {
            original: runtime.scheduling_origin().unwrap().source(),
            activation: activation.clone(),
            plan: None,
            runtime_object: object.reference.clone(),
            limits: NativeArchiveLimits::default(),
            nodes: [occurrence; 4],
            host: None,
            host_transferred: std::cell::Cell::new(false),
            owners: std::array::from_fn(|_| CompleteOriginalOwnerCapturePreflight {
                key: NativeStateKey {
                    implementation: id.clone(),
                    profile: id.clone(),
                    schema: SchemaRef {
                        id: id.clone(),
                        version: 1,
                        definition: reference.clone(),
                        extensions: Default::default(),
                    },
                },
                geometry: CompleteOriginalOwnerCaptureGeometry {
                    owner: id.clone(),
                    participants: vec![node_id.clone()],
                    maximum_record_bytes: 1024,
                    maximum_objects: 2,
                    maximum_retained_bytes: 4096,
                    maximum_dependency_edges: 0,
                    maximum_transient_bytes: 4096,
                },
            }),
        }
    }

    fn object() -> crate::node_scheduling::InputPayload {
        let bytes = b"inert model runtime object".to_vec();
        crate::node_scheduling::InputPayload {
            reference: canonical::content_ref(&bytes, "application/json").unwrap(),
            bytes,
        }
    }

    #[test]
    fn equal_portable_world_cannot_transfer_original_preflight_occurrence() {
        let (_, runtime, activation) =
            super::super::super::tests::host_continuation_runtime_fixture();
        let (_, foreign, other_activation) =
            super::super::super::tests::host_continuation_runtime_fixture();
        let object = object();
        let seal = modeled_seal(&runtime, &activation, &object);
        seal.authenticate_runtime(&runtime, &activation, &object)
            .unwrap();
        assert_eq!(activation.record(), other_activation.record());
        assert_eq!(
            seal.authenticate_runtime(&foreign, &other_activation, &object),
            Err(RuntimeError::ForeignAuthority)
        );
    }

    #[test]
    fn changing_one_node_occurrence_or_object_ref_refuses_the_same_runtime() {
        let (_, runtime, activation) =
            super::super::super::tests::host_continuation_runtime_fixture();
        let object = object();
        let mut seal = modeled_seal(&runtime, &activation, &object);
        seal.nodes[1] ^= 1;
        assert_eq!(
            seal.authenticate_runtime(&runtime, &activation, &object),
            Err(RuntimeError::ForeignAuthority)
        );
        let seal = modeled_seal(&runtime, &activation, &object);
        let mut changed = object;
        changed.reference.length = U64::new(changed.reference.length.get() + 1);
        assert_eq!(
            seal.authenticate_runtime(&runtime, &activation, &changed),
            Err(RuntimeError::ForeignAuthority)
        );
    }
    #[test]
    fn runtime_transfer_revokes_all_preflight_views_without_reanchoring() {
        let (_, runtime, activation) =
            super::super::super::tests::host_continuation_runtime_fixture();
        let object = object();
        let seal = modeled_seal(&runtime, &activation, &object);
        seal.authenticate_runtime(&runtime, &activation, &object)
            .unwrap();

        let quarantined = runtime.into_quarantine();

        assert!(
            seal.authenticate_runtime(&quarantined.runtime, &activation, &object)
                .is_err()
        );
        assert!(
            seal.original
                .authenticate_runtime_authority(
                    &activation.record().world_binding_hash,
                    &quarantined.runtime.authority,
                )
                .is_err()
        );
    }
}
