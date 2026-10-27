//! Retains exact current role adjacency and the genuine imported Index3 body.
//!
//! References inside an intrinsic native/Controller dictionary remain contained.
//! External edges come only from the defining cold consumers and the original
//! signed Index3 inventory. No JSON key scan or unknown-object leaf is used.

#[path = "born/capacities.rs"]
mod capacities;

use super::super::super::{
    ancestry::OriginalRestoredCaptureAncestry17Data, construction_quote::sum, encoding_extent,
    logical::OriginalSourceRestoredSettled17Read, materialization_storage::reference_backing,
};
use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::{
    PacketCompleteCaptureDependencyLookupData, PacketCompleteCaptureDependencyStorageData,
    retained_values::value_storage_with_error,
};
use crate::node_state::{CompleteOriginalRestorationSource, NativeArchiveRecord};
use std::io::{self, Write};

const INDEX_MEDIA: &str = "application/vnd.crucible.native-signed-index-body.v3+json";
const ROWS: usize = OUTPUT_COUNT + 1;
const INDEX_ROW: usize = OUTPUT_COUNT;

/// Prices the concrete role bank, imported Index3 and independent returned rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CaptureBornStorage {
    pub(crate) index_encoded: usize,
    pub(crate) retained: usize,
    pub(crate) transient: usize,
    pub(crate) scratch: usize,
    source_rows: usize,
    returned_rows: usize,
    lookup: usize,
    count: usize,
    imported: (usize, usize, usize, usize, usize, usize, usize, usize),
}

impl CaptureBornStorage {
    /// Quotes actual typed original custody before any Index or adjacency copy.
    ///
    /// # Errors
    /// Refuses foreign custody, missing inherited bodies, unsupported Index3,
    /// malformed reference geometry or any independent requested-layout ceiling.
    pub(crate) fn quote_data(
        source: &PacketCompleteSemanticSource,
        ancestry: &OriginalRestoredCaptureAncestry17Data<'_>,
        inherited: Option<&OriginalSourceRestoredSettled17Read>,
        archive: &CompleteOriginalRestorationSource,
        original_runtime_reference_bytes: usize,
        maximum: usize,
    ) -> Result<Self, RuntimeError> {
        source.authenticate_original_capture17_parent_archive_data(archive)?;
        let original = archive.archive();
        let geometry = original
            .complete_original_index_identity_construction_data(maximum, maximum)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let body = original
            .complete_original_index_body17_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let index_encoded = encoding_extent::canonical_encoded_extent_data(&body, maximum)?;
        let own_references = sum(&media_types().map(reference_backing), maximum)?;
        // Parent fields retain arbitrary valid media. Repeating the exact seven
        // borrowed reference bank conservatively covers the four custody-backed
        // parent roles in two rows and the scope's parent-manifest edge.
        let parent = ancestry.owned_requested_storage_data(maximum)?;
        let prior = match inherited {
            Some(prior) => {
                if archive.content().get(prior.reference_data()).is_none()
                    || archive.content().get(prior.node_reference_data()).is_none()
                {
                    return Err(RuntimeError::InvalidReceipt);
                }
                sum(
                    &[
                        NodeRuntime::capture_reference_storage(prior.reference_data())?,
                        NodeRuntime::capture_reference_storage(prior.node_reference_data())?,
                    ],
                    maximum,
                )?
            }
            None => 0,
        };
        let generated_edge_strings = sum(
            &[
                // semantic: Node, Controller, proof; prefix: checkpoint;
                // Journal: objects9, prefix, proof. Longest valid media is bounded
                // by the defining ContentRef grammar, with no placeholder object.
                15usize
                    .checked_mul(84 + 128)
                    .ok_or(RuntimeError::ResourceLimit)?,
                parent.checked_mul(3).ok_or(RuntimeError::ResourceLimit)?,
                original_runtime_reference_bytes,
                prior,
            ],
            maximum,
        )?;
        let ordinary_count = 25usize
            .checked_add(if inherited.is_some() { 2 } else { 0 })
            .ok_or(RuntimeError::ResourceLimit)?;
        let mut index_edges = 0usize;
        let mut index_strings = 0usize;
        for reference in original
            .complete_original_index_dependencies17_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?
        {
            index_edges = index_edges
                .checked_add(1)
                .ok_or(RuntimeError::ResourceLimit)?;
            index_strings = sum(
                &[
                    index_strings,
                    NodeRuntime::capture_reference_storage(reference)?,
                ],
                maximum,
            )?;
        }
        let edge_backing = sum(
            &[
                generated_edge_strings,
                index_strings,
                ordinary_count
                    .checked_add(index_edges)
                    .and_then(|n| n.checked_mul(size_of::<ContentRef>()))
                    .ok_or(RuntimeError::ResourceLimit)?,
            ],
            maximum,
        )?;
        let source_rows = sum(&[own_references, geometry.0, edge_backing], maximum)?;
        let mut returned_rows = edge_backing;
        let mut lookup = edge_backing
            .checked_add(84)
            .ok_or(RuntimeError::ResourceLimit)?;
        let mut count = index_edges.max(15);
        let index_adjacency = sum(
            &[
                index_strings,
                index_edges
                    .checked_mul(size_of::<ContentRef>())
                    .ok_or(RuntimeError::ResourceLimit)?,
            ],
            maximum,
        )?;
        let mut imported = (
            1usize,
            index_encoded,
            geometry.0,
            index_edges,
            index_adjacency,
            index_encoded,
            index_adjacency,
            index_adjacency
                .checked_add(84)
                .ok_or(RuntimeError::ResourceLimit)?,
        );
        // Forwarding an imported row clones its actual signed adjacency, not
        // an inferred dependency list. These returned Core rows are independent
        // of the retained original archive and the Source's new born bank.
        for (reference, dependencies) in original
            .complete_original_index_rows17_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?
        {
            let data = PacketCompleteCaptureDependencyLookupData::from_borrowed_capture17_data(
                reference,
                dependencies,
                usize::MAX,
            )?;
            returned_rows = sum(&[returned_rows, data.returned_row_bytes()], maximum)?;
            lookup = lookup.max(
                data.requested_bytes()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            );
            count = count.max(dependencies.len());
            let bytes = archive
                .content()
                .get(reference)
                .ok_or(RuntimeError::InvalidReceipt)?;
            imported.0 = imported
                .0
                .checked_add(1)
                .ok_or(RuntimeError::ResourceLimit)?;
            imported.1 = imported
                .1
                .checked_add(bytes.len())
                .ok_or(RuntimeError::ResourceLimit)?;
            imported.2 = imported
                .2
                .checked_add(NodeRuntime::capture_reference_storage(reference)?)
                .ok_or(RuntimeError::ResourceLimit)?;
            imported.3 = imported
                .3
                .checked_add(dependencies.len())
                .ok_or(RuntimeError::ResourceLimit)?;
            imported.4 = imported
                .4
                .checked_add(data.returned_row_bytes())
                .ok_or(RuntimeError::ResourceLimit)?;
            imported.5 = imported.5.max(bytes.len());
            imported.6 = imported.6.max(data.returned_row_bytes());
            imported.7 = imported.7.max(
                data.requested_bytes()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            );
        }
        // geometry.1 covers the actual Index DOM and canonical buffer. Keeping
        // it on R and independently on T accounts their retained bank plus the
        // serializer's work; it never reuses the Host identity output credit.
        let retained = sum(&[source_rows, geometry.0, geometry.1], maximum)?;
        let scratch = CaptureBornOwner::counter_scratch_data();
        let transient = geometry.1;
        sum(&[retained, transient, scratch], maximum)?;
        source.authenticate_original_capture17_parent_archive_data(archive)?;
        Ok(Self {
            index_encoded,
            retained,
            transient,
            scratch,
            source_rows,
            returned_rows,
            lookup,
            count,
            imported,
        })
    }

    /// Returns the independent row-copy geometry without native permission.
    pub(crate) fn dependency_storage_data(&self) -> PacketCompleteCaptureDependencyStorageData {
        PacketCompleteCaptureDependencyStorageData::from_capture17_data(
            self.source_rows,
            self.returned_rows,
            self.lookup,
            self.count,
        )
    }

    /// Returns the original closure geometry already derived under quote credit.
    pub(crate) const fn imported_closure_storage_data(
        &self,
    ) -> (usize, usize, usize, usize, usize, usize, usize, usize) {
        self.imported
    }

    #[cfg(test)]
    pub(crate) fn data_test_index_bound(index_encoded: usize) -> Self {
        Self {
            index_encoded,
            retained: 0,
            transient: 0,
            scratch: 0,
            source_rows: 0,
            returned_rows: 0,
            lookup: 0,
            count: 0,
            imported: (0, 0, 0, 0, 0, 0, 0, 0),
        }
    }
}

struct BornRow {
    started: bool,
    completed: bool,
    reference: Option<ContentRef>,
    dependencies: Vec<ContentRef>,
}

impl BornRow {
    const fn empty() -> Self {
        Self {
            started: false,
            completed: false,
            reference: None,
            dependencies: Vec::new(),
        }
    }

    fn retain_data<'a>(
        &mut self,
        reference: &ContentRef,
        dependencies: impl Clone + Iterator<Item = &'a ContentRef>,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        if self.started {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.started = true;
        reference
            .validate()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        self.reference = Some(reference.clone());
        let count = dependencies.clone().try_fold(0usize, |n, _| {
            n.checked_add(1).ok_or(RuntimeError::ResourceLimit)
        })?;
        let mut prospective = count
            .checked_mul(size_of::<ContentRef>())
            .ok_or(RuntimeError::ResourceLimit)?;
        for dependency in dependencies.clone() {
            prospective = sum(
                &[
                    prospective,
                    NodeRuntime::capture_reference_storage(dependency)?,
                ],
                maximum,
            )?;
        }
        sum(&[prospective], maximum)?;
        self.dependencies
            .try_reserve_exact(count)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if self.dependencies.capacity() > count {
            return Err(RuntimeError::ResourceLimit);
        }
        for dependency in dependencies {
            dependency
                .validate()
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            self.dependencies.push(dependency.clone());
            self.retained_storage_data(maximum)?;
        }
        self.dependencies.sort_unstable();
        self.dependencies.dedup();
        self.retained_storage_data(maximum)?;
        self.completed = true;
        Ok(())
    }

    fn retained_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let Self {
            started: _,
            completed: _,
            reference,
            dependencies,
        } = self;
        let mut total = dependencies
            .capacity()
            .checked_mul(size_of::<ContentRef>())
            .ok_or(RuntimeError::ResourceLimit)?;
        if let Some(reference) = reference {
            total = sum(
                &[total, NodeRuntime::capture_reference_storage(reference)?],
                maximum,
            )?;
        }
        for dependency in dependencies {
            total = sum(
                &[total, NodeRuntime::capture_reference_storage(dependency)?],
                maximum,
            )?;
        }
        Ok(total)
    }
}

/// Keeps partial Index encoding and all concrete born rows in actual Source custody.
pub(super) struct CaptureBornOwner {
    index_started: bool,
    index_completed: bool,
    index_dom: Option<serde_json::Value>,
    index_reference: Option<ContentRef>,
    index_bytes: Vec<u8>,
    index_output: PayloadCopy,
    rows: [BornRow; ROWS],
}

impl CaptureBornOwner {
    pub(super) fn empty() -> Self {
        Self {
            index_started: false,
            index_completed: false,
            index_dom: None,
            index_reference: None,
            index_bytes: Vec::new(),
            index_output: PayloadCopy::empty(),
            rows: std::array::from_fn(|_| BornRow::empty()),
        }
    }

    pub(super) fn retained_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let Self {
            index_started: _,
            index_completed: _,
            index_dom,
            index_reference,
            index_bytes,
            index_output,
            rows,
        } = self;
        let dom = index_dom.as_ref().map_or(Ok(0), |value| {
            value_storage_with_error::<RuntimeError>(value, 0, maximum)
        })?;
        let reference = index_reference
            .as_ref()
            .map_or(Ok(0), NodeRuntime::capture_reference_storage)?;
        let mut total = sum(
            &[
                dom,
                reference,
                index_bytes.capacity(),
                index_output.retained_storage_data(maximum)?,
            ],
            maximum,
        )?;
        for row in rows {
            total = sum(&[total, row.retained_storage_data(maximum)?], maximum)?;
        }
        Ok(total)
    }

    pub(super) fn prepare_data(
        &mut self,
        completion: &OriginalSourceRestoredCaptureCompletion<'_>,
        source: &PacketCompleteSemanticSource,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        if self.index_started {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.index_started = true;
        source.authenticate_original_capture17_parent_archive_data(completion.archive)?;
        let ancestry = completion.ancestry;
        let original = completion.archive.archive();
        let content = completion.archive.content();
        let parent = [
            &ancestry.parent_archive_index,
            &ancestry.parent_manifest,
            &ancestry.first_semantic,
            &ancestry.first_journal,
        ];
        // The three non-Index signed parent bodies are already retained by the same
        // actual ticket/source; the Index itself is encoded from that archive's
        // private typed owner below. Matching arbitrary fullrefs cannot qualify.
        if original.artifact() != &ancestry.parent_manifest {
            return Err(RuntimeError::ForeignAuthority);
        }
        for reference in &parent[1..] {
            if content.get(reference).is_none() {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
        if let Some(prior) = completion.inherited {
            if content.get(prior.reference_data()).is_none()
                || content.get(prior.node_reference_data()).is_none()
                || prior.reference_data() != &ancestry.first_semantic
            {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
        let value = original
            .complete_original_index_body17_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        self.index_dom =
            Some(serde_json::to_value(value).map_err(|_| RuntimeError::InvalidReceipt)?);
        self.retained_storage_data(maximum)?;
        let bound = completion.row.materialization.born.index_encoded;
        self.index_bytes
            .try_reserve_exact(bound)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if self.index_bytes.capacity() > bound {
            return Err(RuntimeError::ResourceLimit);
        }
        self.retained_storage_data(maximum)?;
        let mut writer = IndexWriter {
            bytes: &mut self.index_bytes,
            maximum: bound,
        };
        canonical::canonical_json_to_writer(
            self.index_dom
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            &mut writer,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        self.index_reference = Some(
            canonical::content_ref(&self.index_bytes, INDEX_MEDIA)
                .map_err(|_| RuntimeError::InvalidReceipt)?,
        );
        if self.index_reference.as_ref() != Some(&ancestry.parent_archive_index) {
            return Err(RuntimeError::InvalidReceipt);
        }
        self.retained_storage_data(maximum)?;
        self.index_completed = true;
        self.index_output.copy_data(
            self.index_reference
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            &self.index_bytes,
            INDEX_MEDIA,
            bound,
        )?;
        self.retained_storage_data(maximum)?;

        let payloads = completion.materialization_payloads_data()?;
        for index in [0, 1, 2, 3, 4, 5] {
            // Native graphs and Controller dictionaries own their literal bytes;
            // none of their contained references triggers an external fetch.
            self.rows[index].retain_data(payloads[index].0, std::iter::empty(), maximum)?;
        }
        let prior_node = completion
            .inherited
            .map(|prior| prior.node_reference_data());
        self.rows[7].retain_data(payloads[7].0, prior_node.into_iter(), maximum)?;
        let scope = &completion.sdk.request_data().scope;
        self.rows[8].retain_data(
            payloads[8].0,
            [&ancestry.parent_manifest, &scope.source_runtime].into_iter(),
            maximum,
        )?;
        let checkpoint = &completion
            .finalization
            .objects
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .coordinator_checkpoint;
        self.rows[9].retain_data(payloads[9].0, std::iter::once(checkpoint), maximum)?;
        let prior_source = completion.inherited.map(|prior| prior.reference_data());
        self.rows[6].retain_data(
            payloads[6].0,
            [payloads[7].0, payloads[5].0, payloads[8].0]
                .into_iter()
                .chain(parent)
                .chain(prior_source),
            maximum,
        )?;
        let objects = completion
            .finalization
            .objects
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        self.rows[10].retain_data(
            payloads[10].0,
            [
                &objects.snapshot,
                &objects.before,
                &objects.control,
                &objects.anchor,
                &objects.after,
                &objects.host_protocol,
                &objects.semantic,
                &objects.runtime_object,
                &objects.coordinator_checkpoint,
                payloads[9].0,
                payloads[8].0,
            ]
            .into_iter()
            .chain(parent),
            maximum,
        )?;
        self.rows[INDEX_ROW].retain_data(
            self.index_reference
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            original
                .complete_original_index_dependencies17_data()
                .map_err(|_| RuntimeError::InvalidReceipt)?,
            maximum,
        )?;
        self.retained_storage_data(maximum)?;
        Ok(())
    }

    pub(super) fn take_index_payload_data(
        &mut self,
    ) -> Option<crate::node_scheduling::InputPayload> {
        if !self.index_completed || self.rows.iter().any(|row| !row.completed) {
            return None;
        }
        self.index_output.take_data()
    }

    pub(super) fn restore_index_payload_data(
        &mut self,
        payload: Option<crate::node_scheduling::InputPayload>,
    ) {
        self.index_output.restore_data(payload);
    }

    fn find_data(&self, reference: &ContentRef) -> Result<Option<&[ContentRef]>, RuntimeError> {
        if !self.index_completed || self.rows.iter().any(|row| !row.completed) {
            return Err(RuntimeError::OutstandingObligations);
        }
        let mut found = None;
        for row in &self.rows {
            if row.reference.as_ref() == Some(reference) {
                if found.is_some() {
                    return Err(RuntimeError::InvalidReceipt);
                }
                found = Some(row.dependencies.as_slice());
            }
        }
        Ok(found)
    }

    pub(super) fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<BornRow>()
            + size_of::<CaptureBornStorage>()
            + size_of::<[BornRow; ROWS]>()
            + size_of::<[&ContentRef; 15]>()
            + size_of::<IndexWriter<'static>>()
            + size_of::<serde_json::Value>()
            + size_of::<Result<serde_json::Value, serde_json::Error>>()
            + size_of::<Result<(), crucible_node_format::ContractError>>()
            + size_of::<std::slice::Iter<'static, BornRow>>()
            + size_of::<std::slice::Iter<'static, ContentRef>>()
            + size_of::<std::array::IntoIter<&ContentRef, 11>>()
            + size_of::<std::array::IntoIter<&ContentRef, 4>>()
            + size_of::<std::array::IntoIter<&ContentRef, 3>>()
            + size_of::<Option<crate::node_scheduling::InputPayload>>()
            + NativeArchiveRecord::complete_original_index_identity_counter_scratch_data()
            + NativeArchiveRecord::complete_original_index_body17_counter_scratch_data()
            + PacketCompleteSemanticSource::original_capture17_imported_closure_counter_scratch_data(
            )
    }
}

struct IndexWriter<'a> {
    bytes: &'a mut Vec<u8>,
    maximum: usize,
}

impl Write for IndexWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|n| *n <= self.maximum && *n <= self.bytes.capacity())
            .ok_or(io::ErrorKind::OutOfMemory)?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_intrinsic_leaf_keeps_exact_identity_and_cannot_retry() {
        let reference =
            canonical::content_ref(b"actual intrinsic role", "application/json").unwrap();
        let mut row = BornRow::empty();
        row.retain_data(&reference, std::iter::empty(), 4096)
            .unwrap();

        assert!(row.completed);
        assert_eq!(row.reference.as_ref(), Some(&reference));
        assert!(row.dependencies.is_empty());
        assert!(
            row.retain_data(&reference, std::iter::empty(), 4096)
                .is_err()
        );
    }

    #[test]
    fn duplicate_edges_are_deduplicated_after_their_reserved_slots_are_retained() {
        let reference = canonical::content_ref(b"actual output", "application/json").unwrap();
        let dependency = canonical::content_ref(b"signed dependency", "application/json").unwrap();
        let mut row = BornRow::empty();
        row.retain_data(&reference, [&dependency, &dependency].into_iter(), 4096)
            .unwrap();

        assert_eq!(
            row.dependencies.as_slice(),
            std::slice::from_ref(&dependency)
        );
        assert_eq!(row.dependencies.capacity(), 2);
        assert!(row.retained_storage_data(4096).unwrap() >= 2 * size_of::<ContentRef>());
    }

    #[test]
    fn refused_adjacency_retains_the_original_identity_and_cannot_retry() {
        let reference = canonical::content_ref(b"retained output", "application/json").unwrap();
        let dependency =
            canonical::content_ref(b"retained dependency", "application/json").unwrap();
        let mut row = BornRow::empty();

        assert!(
            row.retain_data(&reference, [&dependency].into_iter(), 0)
                .is_err()
        );
        assert!(row.started);
        assert!(!row.completed);
        assert_eq!(row.reference.as_ref(), Some(&reference));
        assert!(
            row.retain_data(&reference, std::iter::empty(), 4096)
                .is_err()
        );
    }
}

#[path = "born/source.rs"]
mod source;
