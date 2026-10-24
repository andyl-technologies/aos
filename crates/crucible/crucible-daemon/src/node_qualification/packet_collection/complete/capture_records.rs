//! Reconstructs explicit complete-scene immutable and original-input dependency rows.
//!
//! Core records move their original vectors once. Source records are interpreted
//! by their selected typed role; measured whole-file artifacts remain byte leaves.
//! Unknown references never become leaves, and no dependency walk issues authority.

use std::{mem::size_of, rc::Rc};

use super::InstalledPacketCompleteCollectionAuthority;
use crucible_engine::{
    node_adapters::cnp::CnpSemanticSource,
    node_admission::{AdmissionEvidence, AdmittedGraph},
    node_contract::OriginalLineageRuntimeRecord,
    node_scheduling::{ExactCeiling, ExecutionPolicy, InputPayload},
    node_state::{StateError, StateErrorCode, StateLimits, admitted_graph_records},
};
use crucible_node_format::{
    CapabilityProfile, ContentRef, FacetSelection, NodeManifest, PortDescriptor, Validate,
    canonical,
};

pub(super) struct Row {
    object: InputPayload,
    dependencies: Vec<ContentRef>,
}

// The outer move projection cannot enlarge the admitted record slot layout.
const _: () =
    assert!(size_of::<Row>() <= size_of::<crucible_engine::node_state::AdmittedGraphRecord>());

struct RuntimeRow {
    reference: ContentRef,
    dependencies: Vec<ContentRef>,
}

pub(super) struct PacketCompleteCaptureRecords {
    authority: Rc<InstalledPacketCompleteCollectionAuthority>,
    core: Vec<Row>,
    runtime: Vec<RuntimeRow>,
    limits: StateLimits,
}

impl PacketCompleteCaptureRecords {
    pub(super) fn from_graph(
        authority: Rc<InstalledPacketCompleteCollectionAuthority>,
        graph: &AdmittedGraph,
        limits: StateLimits,
    ) -> Result<Self, StateError> {
        authority.current().map_err(error)?;
        let originals = admitted_graph_records(graph, limits)?;
        let mut core = Vec::new();
        core.try_reserve_exact(originals.len()).map_err(error)?;
        for original in originals {
            // No duplicate body or hidden dependency capacity survives this move.
            let (object, dependencies) = original.into_parts();
            // The factory authenticates the complete admitted graph against its
            // retained authority before this projection. Generated graph records
            // need not have been independent original source content-map entries.
            object.reference.verify(&object.bytes).map_err(error)?;
            core.push(Row {
                object,
                dependencies,
            });
        }
        authority.current().map_err(error)?;
        Ok(Self {
            authority,
            core,
            runtime: Vec::new(),
            limits,
        })
    }

    pub(super) fn content(
        &self,
        reference: &ContentRef,
        maximum: usize,
    ) -> Result<Vec<u8>, StateError> {
        self.authority.current().map_err(error)?;
        let maximum = maximum.min(self.limits.maximum_content_bytes);
        let bytes = if let Some(row) = self
            .core
            .iter()
            .find(|row| row.object.reference == *reference)
        {
            if row.object.bytes.len() > maximum {
                return Err(refused("complete core record exceeds fetch credit"));
            }
            row.object.bytes.clone()
        } else {
            self.authority.content(reference, maximum).map_err(error)?
        };
        reference.verify(&bytes).map_err(error)?;
        // Content alone cannot opt an unknown body into an empty adjacency row.
        self.dependencies(reference, &bytes, self.limits.maximum_dependency_edges)?;
        self.authority.current().map_err(error)?;
        Ok(bytes)
    }

    pub(super) fn dependencies(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        self.authority.current().map_err(error)?;
        reference.verify(bytes).map_err(error)?;
        let maximum = maximum.min(self.limits.maximum_dependency_edges);
        if let Some(row) = self
            .core
            .iter()
            .find(|row| row.object.reference == *reference)
        {
            if row.object.bytes != bytes {
                return Err(refused("complete core body changed"));
            }
            return copied(&row.dependencies, maximum);
        }
        if let Some(row) = self.runtime.iter().find(|row| &row.reference == reference) {
            // The actual runtime supplied these first-sealed full-reference rows.
            // Body verification preserves the exact original encoding; data rows
            // never authenticate an independent source or native actor.
            return copied(&row.dependencies, maximum);
        }
        let policy = self.authority.capture_graph_policy();
        for measurement in policy.measurements() {
            if reference == &measurement.host
                || reference == &measurement.peer.content
                || measurement
                    .sources
                    .iter()
                    .any(|source| &source.content == reference)
            {
                // This selected role preserves an entire measured file. Hash-like
                // text within its bytes is not another archive object namespace.
                return Ok(Vec::new());
            }
        }
        let (proof, interpretation) = policy.capture_static_references();
        if reference == interpretation {
            return Ok(Vec::new());
        }
        if reference == proof {
            let mut dependencies = Vec::new();
            push(&mut dependencies, interpretation, maximum)?;
            for measurement in policy.measurements() {
                push(&mut dependencies, &measurement.host, maximum)?;
                push(&mut dependencies, &measurement.peer.content, maximum)?;
                for source in &measurement.sources {
                    push(&mut dependencies, &source.content, maximum)?;
                }
            }
            return finished(dependencies);
        }
        let world = self.authority.world();
        if reference == &world.scenario_ref {
            // Initial graph installation compared the exact original canonical
            // requirements body and rejected unsupported scenario fields.
            return Ok(Vec::new());
        }
        if reference == &world.initialization_ref {
            let mut edges = Vec::new();
            for source in &self.authority.roster().sources {
                push(
                    &mut edges,
                    &source.installation().descriptor.initialization_ref,
                    maximum,
                )?;
            }
            push(
                &mut edges,
                &self
                    .authority
                    .host_source()
                    .selection()
                    .descriptor
                    .initialization_ref,
                maximum,
            )?;
            return finished(edges);
        }
        for source in &self.authority.roster().sources {
            let installed = source.installation();
            let compatibility = &installed.binding.compatibility;
            if reference == &installed.descriptor.model_ref
                || reference == &installed.descriptor.configuration_ref
                || reference == &installed.descriptor.initialization_ref
            {
                // Full bytes were verified above against the immutable original
                // configuration identity made by this same concrete Source.
                let mut edges = Vec::new();
                if let Some(definition) = source
                    .complete_reactive_definition_data()
                    .map_err(operation_failure)?
                {
                    for connection in &definition.connections {
                        push(&mut edges, &connection.policy, maximum)?;
                    }
                }
                return finished(edges);
            }
            if reference == &compatibility.profile_ref {
                return profile_dependencies(&installed.profile, maximum);
            }
            if reference == &compatibility.capabilities_ref {
                return capability_dependencies(&installed.capabilities, maximum);
            }
            if reference == &compatibility.guarantees_ref {
                return copied(
                    std::slice::from_ref(&installed.guarantees.limitations_ref),
                    maximum,
                );
            }
            if reference == &installed.profile.port_templates_ref {
                return port_dependencies(&installed.descriptor.ports, maximum);
            }
            if installed
                .provider
                .implementation
                .formats
                .iter()
                .any(|format| &format.definition == reference)
            {
                // Graph installation compared the exact source-authored fixed
                // schema roster and complete helper bodies. This is that closed
                // format-description role, never an arbitrary advertised schema.
                return Ok(Vec::new());
            }
        }
        let host = self.authority.host_source().selection();
        if reference == &host.descriptor.model_ref
            || host
                .binding
                .compatibility
                .implementation
                .formats
                .iter()
                .any(|format| &format.definition == reference)
        {
            // The genuine complete Host2 constructor validated these exact fixed
            // definition bodies. They contain format descriptions, not object refs.
            return Ok(Vec::new());
        }
        if reference == &host.descriptor.configuration_ref
            || reference == &host.descriptor.initialization_ref
        {
            return copied(std::slice::from_ref(&host.descriptor.model_ref), maximum);
        }
        if reference == &host.binding.compatibility.operating_contract.policy_ref {
            return execution_dependencies(&host.operating_policy, maximum);
        }
        if reference == &host.binding.compatibility.guarantees_ref {
            return copied(
                std::slice::from_ref(&host.guarantees.limitations_ref),
                maximum,
            );
        }
        if reference == &host.binding.compatibility.capabilities_ref {
            let mut edges = Vec::new();
            push(&mut edges, &host.descriptor.model_ref, maximum)?;
            push(&mut edges, &host.guarantees.limitations_ref, maximum)?;
            facet_dependencies(
                &host.binding.compatibility.operating_contract.facets,
                &mut edges,
                maximum,
            )?;
            return finished(edges);
        }
        Err(refused("unknown complete immutable content role"))
    }

    pub(super) fn bind_runtime(
        &mut self,
        runtime: &OriginalLineageRuntimeRecord,
    ) -> Result<(), StateError> {
        let (count, _) = runtime_row_demand(runtime, self.limits)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(count).map_err(error)?;
        for input in &runtime.inputs {
            let occurrences = input
                .deliveries
                .len()
                .checked_mul(3)
                .ok_or_else(|| refused("complete input direct-edge overflow"))?;
            let mut dependencies = Vec::new();
            dependencies.try_reserve_exact(occurrences).map_err(error)?;
            for delivery in &input.deliveries {
                dependencies.push(delivery.payload.clone());
                dependencies.push(delivery.provenance_ref.clone());
                dependencies.push(
                    delivery
                        .connection_policy_ref
                        .clone()
                        .ok_or_else(|| refused("complete original input policy absent"))?,
                );
            }
            dependencies.sort_unstable();
            dependencies.dedup();
            rows.push(RuntimeRow {
                reference: input.inventory.clone(),
                dependencies,
            });
            if let Some(lineage) = &input.lineage {
                for publication in &lineage.publications {
                    for row in &publication.rows {
                        rows.push(RuntimeRow {
                            reference: row.object.clone(),
                            dependencies: copied(
                                &row.dependencies,
                                self.limits.maximum_dependency_edges,
                            )?,
                        });
                    }
                }
            }
            for reference in &input.payloads {
                rows.push(RuntimeRow {
                    reference: reference.clone(),
                    dependencies: Vec::new(),
                });
            }
        }
        rows.sort_unstable_by(|a, b| a.reference.cmp(&b.reference));
        if rows.windows(2).any(|pair| {
            pair[0].reference == pair[1].reference && pair[0].dependencies != pair[1].dependencies
        }) || rows.iter().any(|row| {
            self.core.iter().any(|core| {
                core.object.reference == row.reference && core.dependencies != row.dependencies
            })
        }) {
            return Err(refused(
                "complete first-sealed direct row conflicts with original graph/input",
            ));
        }
        rows.dedup_by(|a, b| a.reference == b.reference);
        self.runtime = rows;
        Ok(())
    }

    pub(super) fn retained_bytes(&self) -> Result<usize, StateError> {
        let mut total = self
            .core
            .capacity()
            .checked_mul(size_of::<Row>())
            .ok_or_else(|| refused("complete record metadata overflow"))?;
        for row in &self.core {
            total = total
                .checked_add(row.object.bytes.capacity())
                .and_then(|sum| {
                    reference_bytes(&row.object.reference)
                        .ok()
                        .and_then(|one| sum.checked_add(one))
                })
                .and_then(|sum| {
                    row.dependencies
                        .capacity()
                        .checked_mul(size_of::<ContentRef>())
                        .and_then(|bank| sum.checked_add(bank))
                })
                .ok_or_else(|| refused("complete record storage overflow"))?;
            for reference in &row.dependencies {
                total = total
                    .checked_add(reference_bytes(reference)?)
                    .ok_or_else(|| refused("complete record references overflow"))?;
            }
        }
        total = total
            .checked_add(
                self.runtime
                    .capacity()
                    .checked_mul(size_of::<RuntimeRow>())
                    .ok_or_else(|| refused("complete runtime metadata bank overflow"))?,
            )
            .ok_or_else(|| refused("complete runtime row storage overflow"))?;
        for row in &self.runtime {
            total = total
                .checked_add(reference_bytes(&row.reference)?)
                .and_then(|sum| {
                    row.dependencies
                        .capacity()
                        .checked_mul(size_of::<ContentRef>())
                        .and_then(|bank| sum.checked_add(bank))
                })
                .ok_or_else(|| refused("complete runtime dependency bank overflow"))?;
            for reference in &row.dependencies {
                total = total
                    .checked_add(reference_bytes(reference)?)
                    .ok_or_else(|| refused("complete runtime reference storage overflow"))?;
            }
        }
        Ok(total)
    }
}

fn profile_dependencies(
    profile: &NodeManifest,
    maximum: usize,
) -> Result<Vec<ContentRef>, StateError> {
    let mut edges = Vec::new();
    for reference in [
        &profile.configuration_schema.definition,
        &profile.allowed_combinations_ref,
        &profile.port_templates_ref,
    ] {
        push(&mut edges, reference, maximum)?;
    }
    for format in &profile.state_formats {
        push(&mut edges, &format.definition, maximum)?;
    }
    facet_dependencies(&profile.operation_facets, &mut edges, maximum)?;
    finished(edges)
}

fn capability_dependencies(
    value: &CapabilityProfile,
    maximum: usize,
) -> Result<Vec<ContentRef>, StateError> {
    let mut edges = Vec::new();
    push(&mut edges, &value.devices_ref, maximum)?;
    push(&mut edges, &value.requirements_ref, maximum)?;
    facet_dependencies(&value.facets, &mut edges, maximum)?;
    finished(edges)
}

fn port_dependencies(
    ports: &[PortDescriptor],
    maximum: usize,
) -> Result<Vec<ContentRef>, StateError> {
    let mut edges = Vec::new();
    for port in ports {
        push(&mut edges, &port.configuration_ref, maximum)?;
        for lane in &port.lanes {
            push(&mut edges, &lane.payload_schema.definition, maximum)?;
        }
    }
    finished(edges)
}

fn facet_dependencies(
    facets: &[FacetSelection],
    edges: &mut Vec<ContentRef>,
    maximum: usize,
) -> Result<(), StateError> {
    for facet in facets {
        push(edges, &facet.configuration_ref, maximum)?;
        push(edges, &facet.guarantees_ref, maximum)?;
    }
    Ok(())
}

fn execution_dependencies(
    value: &ExecutionPolicy,
    maximum: usize,
) -> Result<Vec<ContentRef>, StateError> {
    let ExecutionPolicy::Exact {
        execution_proof_ref,
        boundary_settlement_ref,
        ceiling,
        ..
    } = value
    else {
        return Err(refused("complete immutable policy is not exact"));
    };
    let mut edges = Vec::new();
    push(&mut edges, execution_proof_ref, maximum)?;
    if let ExactCeiling::InputBlocked { proof_ref } = ceiling {
        push(&mut edges, proof_ref, maximum)?;
    }
    if let Some(reference) = boundary_settlement_ref {
        push(&mut edges, reference, maximum)?;
    }
    finished(edges)
}

fn push(
    edges: &mut Vec<ContentRef>,
    reference: &ContentRef,
    maximum: usize,
) -> Result<(), StateError> {
    if edges.len() >= maximum {
        return Err(refused("complete direct edge credit exhausted"));
    }
    reference.validate().map_err(error)?;
    edges.try_reserve(1).map_err(error)?;
    edges.push(reference.clone());
    Ok(())
}

fn copied(references: &[ContentRef], maximum: usize) -> Result<Vec<ContentRef>, StateError> {
    if references.len() > maximum {
        return Err(refused("complete direct row credit exhausted"));
    }
    bounded(references.to_vec(), maximum)
}

fn bounded(references: Vec<ContentRef>, maximum: usize) -> Result<Vec<ContentRef>, StateError> {
    if references.len() > maximum {
        return Err(refused("complete direct edge credit exhausted"));
    }
    finished(references)
}

fn finished(mut references: Vec<ContentRef>) -> Result<Vec<ContentRef>, StateError> {
    for reference in &references {
        reference.validate().map_err(error)?;
    }
    references.sort_unstable();
    references.dedup();
    Ok(references)
}

pub(super) fn reference_bytes(reference: &ContentRef) -> Result<usize, StateError> {
    [
        reference.hash.algorithm.capacity(),
        reference.hash.domain.capacity(),
        reference.hash.digest.capacity(),
        reference.media_type.capacity(),
    ]
    .into_iter()
    .try_fold(0usize, |sum, one| {
        sum.checked_add(one)
            .ok_or_else(|| refused("complete reference allocation overflow"))
    })
}

// StateError has no native effect field. Keep the original reason and full
// effect knowledge in its diagnostic instead of classifying a failed capture
// check as a no-effect refusal. Core retains the original capture obligations.
pub(super) fn operation_failure(
    failure: crucible_engine::node_contract::OperationFailure,
) -> StateError {
    StateError::new(
        StateErrorCode::NativeEvidence,
        "complete packet capture",
        format!("{}; native effects: {:?}", failure.reason, failure.effects),
    )
}

pub(super) fn error(error: impl std::fmt::Display) -> StateError {
    refused(error.to_string())
}

pub(super) fn refused(reason: impl Into<String>) -> StateError {
    StateError::new(
        StateErrorCode::NativeEvidence,
        "complete packet capture",
        reason,
    )
}

pub(super) fn runtime_row_demand(
    runtime: &OriginalLineageRuntimeRecord,
    limits: StateLimits,
) -> Result<(usize, usize), StateError> {
    let mut count = 0usize;
    let mut bytes = 0usize;
    let mut edges = 0usize;
    for input in &runtime.inputs {
        // A stack-three view charges each actual input edge without a temporary
        // reference Vec. The one inventory row itself is counted separately.
        charge_runtime_row(&mut count, &mut bytes, &input.inventory, limits)?;
        for delivery in &input.deliveries {
            let policy = delivery
                .connection_policy_ref
                .as_ref()
                .ok_or_else(|| refused("complete original input policy absent"))?;
            edges = edges
                .checked_add(3)
                .filter(|count| *count <= limits.maximum_dependency_edges)
                .ok_or_else(|| refused("complete input direct-edge occurrence credit exhausted"))?;
            bytes = bytes
                .checked_add(3 * size_of::<ContentRef>())
                .and_then(|sum| sum.checked_add(reference_bytes(&delivery.payload).ok()?))
                .and_then(|sum| sum.checked_add(reference_bytes(&delivery.provenance_ref).ok()?))
                .and_then(|sum| sum.checked_add(reference_bytes(policy).ok()?))
                .filter(|sum| *sum <= limits.maximum_total_content_bytes)
                .ok_or_else(|| refused("complete input projected direct-edge storage overflow"))?;
        }
        if let Some(lineage) = &input.lineage {
            for publication in &lineage.publications {
                for original in &publication.rows {
                    // The source row is already a borrowed slice; visit one edge
                    // at a time rather than collecting another reference bank.
                    charge_runtime_row(&mut count, &mut bytes, &original.object, limits)?;
                    for reference in &original.dependencies {
                        edges = edges
                            .checked_add(1)
                            .filter(|count| *count <= limits.maximum_dependency_edges)
                            .ok_or_else(|| refused("complete source adjacency credit exhausted"))?;
                        bytes = bytes
                            .checked_add(size_of::<ContentRef>())
                            .and_then(|sum| sum.checked_add(reference_bytes(reference).ok()?))
                            .filter(|sum| *sum <= limits.maximum_total_content_bytes)
                            .ok_or_else(|| {
                                refused("complete source row allocation exceeds credit")
                            })?;
                    }
                }
            }
        }
        for reference in &input.payloads {
            charge_runtime_row(&mut count, &mut bytes, reference, limits)?;
        }
    }
    Ok((count, bytes))
}

fn charge_runtime_row(
    count: &mut usize,
    bytes: &mut usize,
    reference: &ContentRef,
    limits: StateLimits,
) -> Result<(), StateError> {
    *count = count
        .checked_add(1)
        .filter(|count| *count <= limits.maximum_content_objects)
        .ok_or_else(|| refused("complete runtime row occurrence credit exhausted"))?;
    *bytes = bytes
        .checked_add(size_of::<RuntimeRow>())
        .and_then(|sum| sum.checked_add(reference_bytes(reference).ok()?))
        .filter(|sum| *sum <= limits.maximum_total_content_bytes)
        .ok_or_else(|| refused("complete runtime projected row exceeds credit"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_failure_mapping_preserves_unknown_effects_and_original_prefix_ids()
    -> Result<(), StateError> {
        use crucible_engine::node_contract::{EffectKnowledge, OperationFailure};
        use crucible_node_format::Id;

        let cases = [
            (EffectKnowledge::None, "None"),
            (EffectKnowledge::MayHaveProgressed, "MayHaveProgressed"),
            (EffectKnowledge::Unknown, "Unknown"),
            (
                EffectKnowledge::CommittedPrefix(vec![Id::new("original-prefix").map_err(error)?]),
                "original-prefix",
            ),
        ];
        for (effects, expected) in cases {
            let mapped = operation_failure(OperationFailure {
                effects,
                reason: "original failure reason".into(),
            });
            assert_eq!(mapped.code, StateErrorCode::NativeEvidence);
            assert!(mapped.reason.contains("original failure reason"));
            assert!(mapped.reason.contains(expected));
        }
        Ok(())
    }

    #[test]
    fn exact_policy_adjacency_keeps_input_blocked_and_settlement_proofs() -> Result<(), StateError>
    {
        let execution =
            canonical::content_ref(b"execution", "application/octet-stream").map_err(error)?;
        let blocked =
            canonical::content_ref(b"input barrier", "application/octet-stream").map_err(error)?;
        let settlement =
            canonical::content_ref(b"settlement", "application/octet-stream").map_err(error)?;
        let policy = ExecutionPolicy::Exact {
            schema_version: 1,
            execution_proof_ref: execution.clone(),
            ceiling: ExactCeiling::InputBlocked {
                proof_ref: blocked.clone(),
            },
            boundary_settlement_ref: Some(settlement.clone()),
        };

        let actual = execution_dependencies(&policy, 3)?;
        let mut expected = vec![execution, blocked, settlement];
        expected.sort_unstable();

        assert_eq!(actual, expected);
        assert!(execution_dependencies(&policy, 2).is_err());
        Ok(())
    }

    #[test]
    fn rejected_direct_edge_does_not_allocate_a_destination_bank() -> Result<(), StateError> {
        let reference =
            canonical::content_ref(b"original", "application/octet-stream").map_err(error)?;
        let mut edges = Vec::new();

        assert!(push(&mut edges, &reference, 0).is_err());
        assert_eq!(edges.capacity(), 0);
        assert!(edges.is_empty());
        Ok(())
    }
}
