//! Retains the actual mutable physical graph across later preparation failure.
//!
//! Canonicalization uses the existing validation and JSON engines. Its owning
//! destination retains reached graph/byte results; it creates no writer grant.

use super::*;
use crate::state::encoding::StateEncodingContextV1;

#[derive(Clone, Copy)]
enum CanonicalFailure {
    Normalization,
    Metadata,
    Persistent,
    Bytes,
    Bound,
    Binding,
}

/// Keeps bytes ahead of their source DTO in reverse-local destruction order.
pub(super) struct CanonicalStateOriginalV1 {
    bytes: Option<Result<Vec<u8>, StorageStateError>>,
    persistent: Option<Result<PhysicalStateWireV1, StorageStateError>>,
    normalization: Option<Result<(), StorageStateError>>,
    metadata: Option<Result<(), StorageStateError>>,
    bound: Option<Result<(), StorageStateError>>,
    binding: Option<Result<CatalogBindingV1, StorageStateError>>,
    first: Option<CanonicalFailure>,
}

impl CanonicalStateOriginalV1 {
    pub(super) const fn new() -> Self {
        Self {
            bytes: None,
            persistent: None,
            normalization: None,
            metadata: None,
            bound: None,
            binding: None,
            first: None,
        }
    }

    pub(super) fn run(
        &mut self,
        wire: &mut PhysicalStateWire,
        metadata: &BTreeMap<(String, u64), SnapshotMetadataWireV1>,
        receiving: Option<&mut StateEncodingContextV1<'_, '_, '_>>,
    ) -> Result<(), StorageStateError> {
        if self.normalization.is_some() {
            return Err(StorageStateError::Receiving);
        }
        let selected = receiving.is_some();
        self.first = Some(CanonicalFailure::Normalization);
        self.normalization = Some(normalize_and_validate(wire));
        if !matches!(self.normalization, Some(Ok(()))) {
            return Err(StorageStateError::Receiving);
        }

        self.first = Some(CanonicalFailure::Metadata);
        self.metadata = Some(validate_snapshot_metadata_set(wire, metadata));
        if !matches!(self.metadata, Some(Ok(()))) {
            return Err(StorageStateError::Receiving);
        }

        self.first = Some(CanonicalFailure::Persistent);
        self.persistent = Some(persistent_wire(wire, metadata));
        let Some(Ok(persistent)) = self.persistent.as_ref() else {
            return Err(StorageStateError::Receiving);
        };
        self.first = Some(CanonicalFailure::Bytes);
        let encoded = crate::state::encoding::encode_json_v1(persistent, receiving);
        if !selected {
            // The old borrowed serialization temporary ended before checking
            // its Result and before the completed bytes local was constructed.
            drop(self.persistent.take());
        }
        self.bytes = Some(encoded.map_err(|cause| match cause {
                StorageStateError::Receiving => StorageStateError::Receiving,
                _ => StorageStateError::CorruptRecord,
            }));
        let Some(Ok(bytes)) = self.bytes.as_ref() else {
            return Err(StorageStateError::Receiving);
        };

        self.first = Some(CanonicalFailure::Bound);
        self.bound = Some(if bytes.len() > MAXIMUM_STATE_BYTES {
            Err(StorageStateError::InvalidValue)
        } else {
            Ok(())
        });
        if !matches!(self.bound, Some(Ok(()))) {
            return Err(StorageStateError::Receiving);
        }
        let mut hash = Sha256::new();
        hash.update(STATE_DIGEST_DOMAIN);
        hash.update(bytes);
        let digest = ObjectDigest::from_bytes(hash.finalize().into());
        self.first = Some(CanonicalFailure::Binding);
        self.binding = Some(CatalogBindingV1::from_publisher(wire.generation, digest)
            .map_err(|_| StorageStateError::InvalidValue));
        if !matches!(self.binding, Some(Ok(_))) {
            return Err(StorageStateError::Receiving);
        }
        self.first = None;
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&StorageStateError> {
        match self.first? {
            CanonicalFailure::Normalization => self.normalization.as_ref()?.as_ref().err(),
            CanonicalFailure::Metadata => self.metadata.as_ref()?.as_ref().err(),
            CanonicalFailure::Persistent => self.persistent.as_ref()?.as_ref().err(),
            CanonicalFailure::Bytes => self.bytes.as_ref()?.as_ref().err(),
            CanonicalFailure::Bound => self.bound.as_ref()?.as_ref().err(),
            CanonicalFailure::Binding => self.binding.as_ref()?.as_ref().err(),
        }
    }

    pub(super) fn take_failure(&mut self) -> Option<StorageStateError> {
        match self.first? {
            CanonicalFailure::Normalization => self.normalization.take()?.err(),
            CanonicalFailure::Metadata => self.metadata.take()?.err(),
            CanonicalFailure::Persistent => self.persistent.take()?.err(),
            CanonicalFailure::Bytes => self.bytes.take()?.err(),
            CanonicalFailure::Bound => self.bound.take()?.err(),
            CanonicalFailure::Binding => self.binding.take()?.err(),
        }
    }

    pub(super) fn take_positive(&mut self) -> (Vec<u8>, CatalogBindingV1) {
        if self.first.is_some() {
            std::process::abort();
        }
        let Some(Ok(bytes)) = self.bytes.take() else {
            std::process::abort();
        };
        let Some(Ok(binding)) = self.binding.take() else {
            std::process::abort();
        };
        (bytes, binding)
    }
}

#[derive(Clone, Copy)]
enum ApplicationFailure {
    Admission,
    Members,
    Canonical,
}

/// Holds the actual wire before its first member can reject it.
///
/// The enclosing real State model/slot debit precedes construction. Persistent
/// DTOs and reached canonical bytes are separately paid by the same codec.
pub(super) struct AtomicPhysicalApplicationOriginalV1 {
    canonical: CanonicalStateOriginalV1,
    metadata: Option<BTreeMap<(String, u64), SnapshotMetadataWireV1>>,
    wire: Option<PhysicalStateWire>,
    admission: Option<Result<(u64, CatalogBindingV1), StorageStateError>>,
    members: Option<Result<(), StorageStateError>>,
    first: Option<ApplicationFailure>,
    entered: bool,
    completed: bool,
}

impl AtomicPhysicalApplicationOriginalV1 {
    pub(super) const fn new() -> Self {
        Self {
            canonical: CanonicalStateOriginalV1::new(),
            metadata: None,
            wire: None,
            admission: None,
            members: None,
            first: None,
            entered: false,
            completed: false,
        }
    }

    pub(super) fn failure(&self) -> Option<&StorageStateError> {
        match self.first? {
            ApplicationFailure::Admission => self.admission.as_ref()?.as_ref().err(),
            ApplicationFailure::Members => self.members.as_ref()?.as_ref().err(),
            ApplicationFailure::Canonical => self.canonical.failure(),
        }
    }

    pub(super) fn actual_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure().map(|cause| cause as &dyn std::error::Error)
    }

    // This is an inert destination routine. The only production caller is
    // apply below, after the same genuine codec has paid its actual shape.
    fn prepare_members(
        &mut self,
        source: &PhysicalCatalogState,
        program: &crate::DormantAtomicDatasetSnapshotV1,
        member_guids: &[u64],
    ) -> Result<(), StorageStateError> {
        if self.entered {
            return Err(StorageStateError::Receiving);
        }
        self.entered = true;
        self.first = Some(ApplicationFailure::Admission);
        self.admission = Some(atomic_group_successor(source, program, member_guids));
        let Some(Ok((next_generation, resolution))) = self.admission.as_ref() else {
            return Err(StorageStateError::Receiving);
        };
        let (next_generation, resolution) = (*next_generation, *resolution);
        self.wire = Some(source.wire.clone());
        let Some(wire) = self.wire.as_mut() else {
            std::process::abort();
        };
        self.first = Some(ApplicationFailure::Members);
        self.members = Some(apply_atomic_group_members(wire, program, member_guids));
        if !matches!(self.members, Some(Ok(()))) {
            return Err(StorageStateError::Receiving);
        }
        wire.generation = next_generation;
        wire.predecessor_state = Some(source.binding.into());
        wire.resolution = Some(resolution.into());
        self.metadata = Some(source.snapshot_metadata.clone());
        Ok(())
    }

    pub(super) fn apply(
        &mut self,
        source: &PhysicalCatalogState,
        program: &crate::DormantAtomicDatasetSnapshotV1,
        member_guids: &[u64],
        receiving: &mut StateEncodingContextV1<'_, '_, '_>,
    ) -> Result<PhysicalCatalogState, StorageStateError> {
        self.prepare_members(source, program, member_guids)?;
        let Some(wire) = self.wire.as_mut() else {
            std::process::abort();
        };
        let Some(metadata) = self.metadata.as_ref() else {
            std::process::abort();
        };
        self.first = Some(ApplicationFailure::Canonical);
        self.canonical.run(wire, metadata, Some(receiving))?;
        let (bytes, binding) = self.canonical.take_positive();
        let Some(wire) = self.wire.take() else {
            std::process::abort();
        };
        let Some(snapshot_metadata) = self.metadata.take() else {
            std::process::abort();
        };
        self.completed = true;
        self.first = None;
        Ok(PhysicalCatalogState { wire, snapshot_metadata, bytes, binding })
    }
}

// Conservative application/canonical parent fields, owned successor
// tuple2/binding2 and canonical binding2 remain distinct nested carriers.
pub(crate) const PHYSICAL_APPLICATION_OWNED_CELLS: usize = 8 + 8 + 5 + 2 + 2 + 2;

// Core operands4/locals6; application operands5/locals8; shared member
// operands3/items2; successor operands3/locals2; prepare operands4/locals3;
// reached shape operands2/locals13. These are separate from owned fields.
pub(crate) const PHYSICAL_APPLICATION_CALL_CELLS: usize =
    4 + 6 + 5 + 8 + 3 + 2 + 3 + 2 + 4 + 3 + 2 + 13
        + 13 // Normalizer entry/collector/closure/result operands and locals.
        + 8; // Shared source-shape operand and seven local/iteration carriers.

/// Prices actual application, persistent and transition graphs before allocation.
///
/// The existing wire-table supplier describes this SAME held state. Group
/// members add only their actual snapshot rows/names; encoded bytes are later
/// paid from the shared serializer's reached wire count.
pub(super) fn application_shape_v1(
    source: &PhysicalCatalogState,
    program: &crate::DormantAtomicDatasetSnapshotV1,
) -> Result<(usize, usize), aos_sandbox_model::AccountingError> {
    use aos_sandbox_model::{AccountingError, ResourceDimension};
    let memory_error = || AccountingError::ArithmeticOverflow {
        dimension: ResourceDimension::MemoryBytes,
    };
    let metadata_error = || AccountingError::ArithmeticOverflow {
        dimension: ResourceDimension::MetadataEntries,
    };
    let (mut bytes, mut cells) = retained_source_shape(source)?;
    let normalization_bytes =
        super::validation::atomic_uniqueness_bytes_v1(&source.wire, program)?;
    bytes = bytes.checked_add(normalization_bytes).ok_or_else(memory_error)?;
    for member in program.members() {
        let names = member.source_name().len().checked_add(member.destination_name().len())
            .ok_or_else(memory_error)?;
        let row = std::mem::size_of::<SnapshotWireV1>().checked_add(names)
            .and_then(|row| row.checked_mul(3)).ok_or_else(memory_error)?;
        bytes = bytes.checked_add(row).ok_or_else(memory_error)?;
        // This member adds one snapshot name in each of the three reached
        // graph representations, irrespective of the row's Rust field count.
        cells = cells.checked_add(3).ok_or_else(metadata_error)?;
    }

    // The same transition producer immediately clones the completed state
    // and member GUIDs before its next encoder call. This third graph and
    // second metadata map are paid here, before either model can be cloned.
    let guids = program.member_count().max(4).checked_mul(std::mem::size_of::<u64>())
        .ok_or_else(memory_error)?;
    bytes = bytes.checked_add(guids).ok_or_else(memory_error)?;
    // The GUID vector and transition/header carriers create no map or
    // catalog name. Their full allocation and carrier bytes remain below.
    // These are the actual additional fixed call/hash work carriers. Both
    // child owners are also included here so the shape stands independently
    // of their earlier enclosing slot debit; no unrelated pool credit is used.
    let fixed_work = std::mem::size_of::<Sha256>()
        + std::mem::size_of::<ObjectDigest>()
        + std::mem::size_of::<super::wire_custody::CatalogWireGeometryV1>()
        + std::mem::size_of::<AtomicPhysicalApplicationOriginalV1>()
        + std::mem::size_of::<CanonicalStateOriginalV1>()
        + 2 * std::mem::size_of::<PhysicalCatalogState>()
        + std::mem::size_of::<TransitionPayload>()
        + PHYSICAL_APPLICATION_CALL_CELLS * std::mem::size_of::<(usize, usize)>();
    bytes = bytes.checked_add(fixed_work).ok_or_else(memory_error)?;
    Ok((bytes, cells))
}

/// Prices actual held source graph/map clones for both fixed mutation families.
pub(super) fn retained_source_shape(
    source: &PhysicalCatalogState,
) -> Result<(usize, usize), aos_sandbox_model::AccountingError> {
    use aos_sandbox_model::{AccountingError, ResourceDimension};
    let memory_error = || AccountingError::ArithmeticOverflow {
        dimension: ResourceDimension::MemoryBytes,
    };
    let metadata_error = || AccountingError::ArithmeticOverflow {
        dimension: ResourceDimension::MetadataEntries,
    };
    let source_shape = super::wire_custody::persistent_geometry(source)?;
    let mut bytes = source_shape.memory.checked_mul(3).ok_or_else(memory_error)?;
    // The application wire, canonical persistent DTO and transition state
    // each own the catalog rows. Only the application/result and transition
    // states own a separate snapshot-metadata index: the persistent DTO embeds
    // that record in its existing snapshot row instead of making a third map.
    let metadata_entries = source.snapshot_metadata.len();
    let catalog_rows = source_shape.metadata.checked_sub(metadata_entries)
        .ok_or_else(metadata_error)?;
    let cells = catalog_rows.checked_mul(3)
        .zip(metadata_entries.checked_mul(2))
        .and_then(|(rows, maps)| rows.checked_add(maps))
        .ok_or_else(metadata_error)?;
    // Clone retains no empty root (pinned alloc BTreeMap::clone). Every
    // nonempty node has at least one logical entry, so the actual entry count
    // bounds cloned nodes. The shared source-derived bound includes alignment,
    // eleven key/value slots, parent header and twelve internal child links.
    let map_bytes = aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1::<
        (String, u64), SnapshotMetadataWireV1,
    >(source.snapshot_metadata.len()).ok_or_else(memory_error)?;
    bytes = map_bytes.checked_mul(2).and_then(|map| bytes.checked_add(map))
        .ok_or_else(memory_error)?;
    // BTreeMap headers, node slots, parent/index/length fields and child
    // edges are byte representations, not additional namespace entries.
    for ((name, _), _) in &source.snapshot_metadata {
        bytes = name.len().checked_mul(2).and_then(|names| bytes.checked_add(names))
            .ok_or_else(memory_error)?;
    }
    Ok((bytes, cells))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> PhysicalCatalogState {
        let catalog = super::super::tests::catalog(7, "tank/aos/project/work");
        PhysicalCatalogState::bootstrap(6, std::slice::from_ref(&catalog)).unwrap()
    }

    #[test]
    fn source_namespace_counts_rows_without_empty_map_headers() {
        let source = source();
        assert_eq!(source.wire.roots.len(), 1);
        assert_eq!(source.wire.datasets.len(), 1);
        assert!(source.snapshot_metadata.is_empty());

        let (_, entries) = retained_source_shape(&source).unwrap();

        // Actual application, canonical DTO and transition each retain these
        // two named rows; an empty metadata map contributes no entry.
        assert_eq!(entries, 6);
    }

    #[test]
    fn rejected_member_keeps_the_actual_cloned_graph_and_original_cause() {
        let source = source();
        let program = crate::lifecycle_atomic_snapshot::atomic_snapshot_program_for_catalog_test(
            source.binding.generation(), source.binding.digest(), source.binding.digest(),
            "tank/aos/project/missing", 15,
        );
        let mut original = AtomicPhysicalApplicationOriginalV1::new();

        assert!(original.prepare_members(&source, &program, &[81]).is_err());
        let wire = original.wire.as_ref().unwrap();
        let pointer = wire.roots[0].dataset_prefix.as_ptr();
        let error = original.failure().unwrap() as *const StorageStateError;
        assert!(matches!(original.failure(), Some(StorageStateError::InvalidTransition)));
        assert_eq!(wire.snapshots, source.wire.snapshots);
        assert!(original.metadata.is_none());

        assert!(original.prepare_members(&source, &program, &[82]).is_err());

        assert_eq!(original.wire.as_ref().unwrap().roots[0].dataset_prefix.as_ptr(), pointer);
        assert!(std::ptr::eq(original.failure().unwrap(), error));
        assert!(!original.completed);
        assert!(matches!(source.apply_atomic_snapshot_group(&program, &[81]),
            Err(StorageStateError::InvalidTransition)));
    }

    #[test]
    fn canonical_state_bytes_and_binding_keep_the_ordinary_recipe() {
        let source = source();
        let mut wire = source.wire.clone();
        let persistent = persistent_wire(&wire, &source.snapshot_metadata).unwrap();
        let expected = serde_json::to_vec(&persistent).unwrap();
        let mut hash = Sha256::new();
        hash.update(STATE_DIGEST_DOMAIN);
        hash.update(&expected);
        let expected_binding = CatalogBindingV1::from_publisher(
            wire.generation, ObjectDigest::from_bytes(hash.finalize().into()),
        ).unwrap();
        let mut original = CanonicalStateOriginalV1::new();

        original.run(&mut wire, &source.snapshot_metadata, None).unwrap();
        let (bytes, binding) = original.take_positive();

        assert_eq!(bytes, expected);
        assert_eq!(binding, expected_binding);
        assert!(original.persistent.is_none());
        assert!(original.failure().is_none());
    }
}
