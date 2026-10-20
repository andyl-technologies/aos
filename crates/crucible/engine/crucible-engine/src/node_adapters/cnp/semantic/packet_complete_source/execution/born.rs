//! Retains typed original creation roles and their direct content identities.
//!
//! The complete store hashes raw bytes with their full length. An exact retained
//! original reference therefore authenticates supplied body identity without a
//! redundant body copy. These rows describe inert adjacency only: the full cold
//! codecs still run before signed archive admission or any fresh installation.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError;

/// Names only the object roles created by this concrete original capture path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::node_adapters::cnp::semantic) enum OriginalBornRole {
    NativeSnapshot,
    NativeAllocationReport,
    NativeControl,
    NativeAnchor,
    NativeAfter,
    HostProtocol,
    HostExtensionRegistry,
    Semantic,
    Ancestry,
    Backend,
    Journal,
}

pub(super) struct OriginalBornObject {
    role: OriginalBornRole,
    reference: ContentRef,
    dependencies: Vec<ContentRef>,
}

impl OriginalBornObject {
    pub(super) fn reference(&self) -> &ContentRef {
        &self.reference
    }

    pub(super) fn dependencies(&self) -> &[ContentRef] {
        &self.dependencies
    }

    pub(super) fn retained_storage(&self, maximum: usize) -> Result<usize, OperationFailure> {
        self.retained_storage_with_error::<OperationFailure>(maximum)
    }

    pub(in crate::node_adapters::cnp::semantic) fn retained_storage_with_error<E: StorageError>(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        let mut bytes = retained_values::sum_with_error::<E, _>(
            [
                NodeRuntime::capture_reference_storage(&self.reference).map_err(E::runtime)?,
                self.dependencies
                    .capacity()
                    .checked_mul(size_of::<ContentRef>())
                    .ok_or_else(|| E::refused("original born adjacency slots overflow"))?,
            ],
            maximum,
        )?;
        for dependency in &self.dependencies {
            bytes = retained_values::sum_with_error::<E, _>(
                [
                    bytes,
                    NodeRuntime::capture_reference_storage(dependency).map_err(E::runtime)?,
                ],
                maximum,
            )?;
        }
        Ok(bytes)
    }
}

fn clone_dependencies<'a>(
    dependencies: impl Clone + Iterator<Item = &'a ContentRef>,
    maximum_objects: usize,
    maximum_scratch_bytes: usize,
) -> Result<Vec<ContentRef>, OperationFailure> {
    let count = dependencies.clone().try_fold(0usize, |count, _| {
        count
            .checked_add(1)
            .filter(|count| *count <= maximum_objects)
            .ok_or_else(|| refused("original born adjacency population exceeds admission"))
    })?;
    let mut requested = count
        .checked_mul(size_of::<ContentRef>())
        .ok_or_else(|| refused("original born adjacency layout overflow"))?;
    for reference in dependencies.clone() {
        requested = retained_values::sum(
            [
                requested,
                NodeRuntime::capture_reference_storage(reference).map_err(unknown)?,
            ],
            maximum_scratch_bytes,
        )?;
    }
    retained_values::sum([requested], maximum_scratch_bytes)?;

    let mut completed = Vec::new();
    completed.try_reserve_exact(count).map_err(unknown)?;
    let actual_slots = completed
        .capacity()
        .checked_mul(size_of::<ContentRef>())
        .ok_or_else(|| refused("original born adjacency actual capacity overflow"))?;
    retained_values::sum(
        [
            requested
                .checked_sub(count * size_of::<ContentRef>())
                .ok_or_else(|| refused("original born adjacency slot quote differs"))?,
            actual_slots,
        ],
        maximum_scratch_bytes,
    )?;
    completed.extend(dependencies.cloned());
    completed.sort_unstable();
    completed.dedup();
    Ok(completed)
}

impl OriginalCompleteCaptureExecution {
    pub(super) fn record_born<'a>(
        born: &mut Vec<OriginalBornObject>,
        role: OriginalBornRole,
        payload: &InputPayload,
        dependencies: impl Clone + Iterator<Item = &'a ContentRef>,
        maximum_objects: usize,
        maximum_scratch_bytes: usize,
    ) -> Result<(), OperationFailure> {
        if born.len() == born.capacity() || born.iter().any(|original| original.role == role) {
            return Err(refused(
                "original born object role is repeated or unavailable",
            ));
        }
        // ContentRef::verify creates one temporary HashRef. Its actual typed
        // string backing is quoted separately from the retained reference clone.
        let reference_storage =
            NodeRuntime::capture_reference_storage(&payload.reference).map_err(unknown)?;
        let verification_storage =
            NodeRuntime::capture_hash_storage(&payload.reference.hash).map_err(unknown)?;
        let remaining = maximum_scratch_bytes
            .checked_sub(retained_values::sum(
                [reference_storage, verification_storage],
                maximum_scratch_bytes,
            )?)
            .ok_or_else(|| refused("original born identity scratch exceeds admission"))?;
        let dependencies = clone_dependencies(dependencies, maximum_objects, remaining)?;
        payload.reference.verify(&payload.bytes).map_err(unknown)?;
        born.push(OriginalBornObject {
            role,
            reference: payload.reference.clone(),
            dependencies,
        });
        let original = born
            .last()
            .ok_or_else(|| refused("original born object was not retained"))?;
        original.retained_storage(maximum_scratch_bytes)?;
        Ok(())
    }
}

impl PacketCompleteSemanticSource {
    /// Returns direct edges only for this Source's retained original born role.
    ///
    /// The supplied full reference must equal the original private creation
    /// association, and its complete raw body must pass the existing content
    /// identity contract. Unknown objects return None. Empty edges are possible
    /// only for an explicitly registered intrinsic leaf; no JSON key scan or
    /// generic unknown-as-leaf rule is used. Cold codec validation is separate.
    ///
    /// # Errors
    /// Refuses a foreign creator, borrowed or inconsistent original custody,
    /// changed complete bytes, excessive edge count or insufficient scratch for
    /// both verification's temporary hash and the returned reference Vec.
    pub fn original_complete_capture_dependencies_data(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        maximum_objects: usize,
        maximum_scratch_bytes: usize,
    ) -> Result<Option<Vec<ContentRef>>, OperationFailure> {
        self.ensure_origin()?;
        if crate::node_adapters::cnp::CnpSemanticSource::requires_restored_capture17_scope_data(
            self,
        )
        .map_err(unknown)?
        {
            return self
                .with_original_capture17_dependency_row_data(reference, |row| {
                    let Some(dependencies) = row else {
                        return Ok(None);
                    };
                    // Unknown objects never become a leaf. Concrete rows use the
                    // same separately priced fullref/body copy path as the tests.
                    super::dependency_credit::copy_capture17_dependencies_data(
                        reference,
                        bytes,
                        dependencies,
                        maximum_objects,
                        maximum_scratch_bytes,
                    )
                    .map(Some)
                })
                .map_err(unknown);
        }
        let execution = self
            .capture_execution
            .try_borrow()
            .map_err(|_| refused("original born object custody is borrowed"))?;
        let Some(execution) = execution.as_ref() else {
            return Ok(None);
        };
        let mut matches = execution
            .born
            .iter()
            .filter(|original| &original.reference == reference);
        let Some(original) = matches.next() else {
            return Ok(None);
        };
        if matches.next().is_some() {
            return Err(refused("original born body has ambiguous creation roles"));
        }
        let verification_storage =
            NodeRuntime::capture_hash_storage(&reference.hash).map_err(unknown)?;
        let remaining = maximum_scratch_bytes
            .checked_sub(verification_storage)
            .ok_or_else(|| refused("original born identity verification exceeds scratch"))?;
        let dependencies =
            clone_dependencies(original.dependencies.iter(), maximum_objects, remaining)?;
        reference.verify(bytes).map_err(unknown)?;
        self.ensure_origin()?;
        Ok(Some(dependencies))
    }
}

/// Borrows each external object actually consumed by the common semantic codec.
///
/// Runtime7 and the host protocol are separate explicit caller context edges.
/// The full host protocol owns original native proof/ACK/Stage/Commit bytes.
/// These additional categories are fetched directly from VerifiedStateContent
/// by archive_semantics::validate and must not disappear behind Runtime7.
pub(super) fn semantic_external_content_dependencies(
    runtime: &crate::node_adapters::cnp::semantic::state::SemanticRuntimeCustody,
) -> impl Clone + Iterator<Item = &ContentRef> {
    use crate::node_adapters::cnp::semantic::state::SemanticRuntimeCustody;
    let SemanticRuntimeCustody {
        installed_restoration,
        arm_attempt: _,
        ready: _,
        prepared_owner: _,
        activate_response: _,
        observe_sequence: _,
        activation_attempt: _,
        active: _,
        inputs,
        operations,
        watermark: _,
        observation: _,
        reclaimed: _,
        credit: _,
        quarantined: _,
    } = runtime;
    installed_restoration
        .iter()
        .flat_map(|selected| selected.input_content_dependencies())
        .chain(inputs.values().flat_map(|input| {
            input
                .original
                .payloads()
                .iter()
                .map(|payload| &payload.reference)
                .chain(input.commitment.iter().flat_map(|commitment| {
                    commitment.context.iter().map(|payload| &payload.reference)
                }))
        }))
        .chain(operations.values().filter_map(|operation| {
            operation
                .retirement
                .as_ref()
                .map(|payload| &payload.reference)
        }))
}

/// Enumerates the external references consumed from the typed reference ancestry.
/// Original inline batch bytes do not create extra objects; their full inventory
/// and delivery provenance/policy references remain explicit direct dependencies.
pub(super) fn ancestry_external_content_dependencies(
    lineage: &OriginalInputLineage,
) -> impl Clone + Iterator<Item = &ContentRef> {
    [
        &lineage.source_scope().inventory,
        lineage.original().inventory(),
    ]
    .into_iter()
    .chain(lineage.original().deliveries().iter().flat_map(|delivery| {
        [&delivery.payload, &delivery.provenance_ref]
            .into_iter()
            .chain(delivery.connection_policy_ref.iter())
    }))
    .chain(
        lineage
            .original()
            .payloads()
            .iter()
            .map(|payload| &payload.reference),
    )
    .chain(lineage.publications().iter().flat_map(|publication| {
        [
            &publication.published,
            &publication.origin.observation_batch,
            &publication.origin.stop_receipt,
            &publication.origin.measurement,
            &publication.event.payload,
            &publication.event.provenance_ref,
        ]
        .into_iter()
        .chain(publication.objects.iter().map(|object| &object.reference))
        .chain(
            publication
                .rows
                .iter()
                .flat_map(|row| std::iter::once(&row.object).chain(row.dependencies.iter())),
        )
    }))
}
