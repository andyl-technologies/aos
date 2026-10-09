//! Borrows native consumption rows from one authenticated original source window.
//!
//! The rows cover the selected native relation codec only. Incoming producer
//! proofs and the preceding checksum receipt remain explicit external edges;
//! an installed runtime adopter must resolve them from original custody. A
//! missing local row never makes another producer's object a leaf.

use std::collections::BTreeSet;

use super::*;

const MAXIMUM_OBJECTS: usize = 72;
const MAXIMUM_BYTES: usize = 600 * 1024;

/// Borrows one exact original body with its selected codec's direct edges.
///
/// The body remains beneath its owning controller. This view conveys historical
/// byte and codec custody, not source qualification or current native authority.
pub struct OriginalLineageObject<'a> {
    reference: ContentRef,
    bytes: &'a [u8],
    dependencies: Vec<ContentRef>,
}

impl OriginalLineageObject<'_> {
    /// Returns the complete original typed reference, including its media role.
    pub fn reference(&self) -> &ContentRef {
        &self.reference
    }

    /// Borrows the unchanged body without allocating or acknowledging a copy.
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Returns direct selected codec edges in full-reference order.
    pub fn dependencies(&self) -> &[ContentRef] {
        &self.dependencies
    }
}

/// Borrows a finite native relation inventory and its unresolved external edges.
///
/// Its private construction starts from actual cached Realize/Input/Begin and
/// native Close agreement. It cannot be imported from serialized relation data.
/// Source adoption must still bind every external edge to authentic runtime
/// input or preceding original publication custody.
pub struct OriginalLineageEvidence<'a> {
    root: ContentRef,
    objects: Vec<OriginalLineageObject<'a>>,
    external: Vec<ContentRef>,
}

impl OriginalLineageEvidence<'_> {
    /// Returns the exact selected consumption relation root.
    pub fn root(&self) -> &ContentRef {
        &self.root
    }

    /// Borrows every locally owned native relation body and its exact row.
    pub fn objects(&self) -> &[OriginalLineageObject<'_>] {
        &self.objects
    }

    /// Returns edges which require separately authenticated original custody.
    ///
    /// Payloads, producer proofs and a preceding native receipt can legitimately
    /// share bytes under different media roles. Their full references stay
    /// distinct, and none is interpreted from its hash or JSON-shaped content.
    pub fn external_dependencies(&self) -> &[ContentRef] {
        &self.external
    }
}

impl OriginalLineageWindow<'_> {
    /// Borrows the explicit native relation inventory within declared credits.
    ///
    /// The enclosing original window has already checked actual accepted input,
    /// complete native consumption, original Ready/Close wires and preceding
    /// public ACK. This method enumerates only that selected codec. It preserves
    /// foreign dependency edges instead of scanning payloads or inventing leaves.
    ///
    /// # Errors
    /// Refuses zero or excessive credits, missing/changed original bodies,
    /// conflicting typed rows, or aggregate byte exhaustion before returning
    /// any borrowed inventory. It performs no native effects or ACK.
    pub fn native_evidence(
        &self,
        maximum_objects: usize,
        maximum_bytes: usize,
    ) -> Result<OriginalLineageEvidence<'_>, ProviderError> {
        if maximum_objects == 0
            || maximum_objects > MAXIMUM_OBJECTS
            || maximum_bytes == 0
            || maximum_bytes > MAXIMUM_BYTES
        {
            return Err(credit());
        }
        let relation = &self.relation;
        let mut rows = Vec::new();
        rows.try_reserve_exact(relation.entries.len() + 8)
            .map_err(|_| credit())?;
        rows.push((
            relation.input_batch.clone(),
            relation
                .entries
                .iter()
                .map(|entry| entry.original_event.clone())
                .collect(),
        ));
        rows.push((
            relation.native_stage.clone(),
            std::iter::once(relation.input_batch.clone())
                .chain(self.stage.entries.iter().map(|entry| entry.payload.clone()))
                .collect(),
        ));
        rows.push((
            relation.native_receipt.clone(),
            std::iter::once(relation.native_stage.clone())
                .chain(relation.previous_closed.iter().cloned())
                .collect(),
        ));
        rows.push((relation.initialize_request.clone(), Vec::new()));
        rows.push((relation.initialize_response_wire.clone(), Vec::new()));
        rows.push((relation.close_request.clone(), Vec::new()));
        rows.push((
            relation.close_response_wire.clone(),
            vec![relation.native_receipt.clone()],
        ));
        for (entry, event) in relation.entries.iter().zip(&self.input.events) {
            rows.push((
                entry.original_event.clone(),
                vec![event.payload.clone(), event.provenance_ref.clone()],
            ));
        }
        let root = self.measurement.consumption_relation.clone();
        rows.push((
            root.clone(),
            rows.iter()
                .map(|(reference, _)| reference.clone())
                .chain(relation.previous_closed.iter().cloned())
                .collect(),
        ));
        collect(self.controller, root, rows, maximum_objects, maximum_bytes)
    }
}

fn collect<'a>(
    controller: &'a ReferenceController,
    root: ContentRef,
    rows: Vec<(ContentRef, Vec<ContentRef>)>,
    maximum_objects: usize,
    maximum_bytes: usize,
) -> Result<OriginalLineageEvidence<'a>, ProviderError> {
    // Preflight original extents and row consistency before allocating the
    // returned inventory. Body storage is borrowed, never copied here.
    let mut unique = std::collections::BTreeMap::new();
    let mut total = 0usize;
    for (reference, mut dependencies) in rows {
        dependencies.sort();
        dependencies.dedup();
        if let Some(previous) = unique.get(&reference) {
            if previous != &dependencies {
                return Err(ProviderError::Conflict(
                    "original lineage dependency row changed",
                ));
            }
            continue;
        }
        let length = usize::try_from(reference.length.get()).map_err(|_| credit())?;
        total = total
            .checked_add(length)
            .filter(|total| *total <= maximum_bytes)
            .ok_or_else(credit)?;
        if unique.len() >= maximum_objects {
            return Err(credit());
        }
        unique.insert(reference, dependencies);
    }
    let local: BTreeSet<_> = unique.keys().cloned().collect();
    let external = unique
        .values()
        .flatten()
        .filter(|reference| !local.contains(*reference))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(unique.len())
        .map_err(|_| credit())?;
    for (reference, dependencies) in unique {
        let bytes = controller.content(&reference)?;
        reference.verify(bytes)?;
        objects.push(OriginalLineageObject {
            reference,
            bytes,
            dependencies,
        });
    }
    Ok(OriginalLineageEvidence {
        root,
        objects,
        external: external.into_iter().collect(),
    })
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("original lineage evidence inventory credit")
}
