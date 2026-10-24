//! Retains the actual singular catalog graph across later preparation failure.
//!
//! The ordinary wrapper and genuine selected consumer use one ordered mutation
//! and canonicalization schedule. This owning model confers no writer grant.

use super::*;
use super::physical_preparation::CanonicalStateOriginalV1;
use crate::state::encoding::StateEncodingContextV1;

#[derive(Clone, Copy)]
enum Failure {
    Admission,
    Ingest,
    Effect,
    Metadata,
    Generation,
    Canonical,
}

/// Selects the existing ordinary recipe or the dedicated Capture row effect.
///
/// Capture creates no workspace initialization or ancestor aggregate. Its
/// privileged producer must separately own the genuine signed admission and
/// observed create; this pure catalog fold supplies neither authority.
enum ApplicationRecipeV3<'a> {
    Ordinary(&'a ResolvedCatalogCommitmentV1),
    Capture {
        requirement: &'a execution_capture::CaptureDatasetRequirementV1,
        resolution: CatalogBindingV1,
    },
}

impl ApplicationRecipeV3<'_> {
    fn generation(&self) -> u64 { self.binding().generation() }

    fn binding(&self) -> CatalogBindingV1 {
        match self {
            Self::Ordinary(catalog) => catalog.binding(),
            Self::Capture { resolution, .. } => *resolution,
        }
    }

    fn current_format(&self) -> bool {
        match self {
            Self::Ordinary(catalog) => catalog.format_version() == FORMAT_VERSION,
            Self::Capture { .. } => true,
        }
    }

    fn ordinary_plan(&self) -> Option<&CatalogPlanV1> {
        match self {
            Self::Ordinary(catalog) => Some(catalog.plan()),
            Self::Capture { .. } => None,
        }
    }

    fn ingest(&self, wire: &mut PhysicalStateWire, operation_id: [u8; 16])
        -> Result<(), StorageStateError>
    {
        match self {
            Self::Ordinary(catalog) => ingest_plan_inputs(wire, catalog.plan(), false),
            Self::Capture { requirement, .. } => {
                validate_capture_inputs_v3(wire, operation_id, requirement)
            }
        }
    }

    fn apply_postcondition(&self, wire: &mut PhysicalStateWire,
        operation_id: [u8; 16], object_guid: Option<u64>) -> Result<(), StorageStateError>
    {
        match self {
            Self::Ordinary(catalog) =>
                apply_postcondition(wire, operation_id, catalog.plan(), object_guid),
            Self::Capture { requirement, .. } => {
                let guid = object_guid.filter(|guid| *guid != 0)
                    .ok_or(StorageStateError::InvalidValue)?;
                insert_created_dataset(wire, operation_id, requirement.dataset_name(),
                    guid, requirement.root(), requirement.planned_dataset().domains(),
                    requirement.space_policy(), None)
            }
        }
    }
}

pub(super) fn validate_capture_inputs_v3(
    wire: &mut PhysicalStateWire,
    operation: [u8; 16],
    requirement: &execution_capture::CaptureDatasetRequirementV1,
) -> Result<(), StorageStateError> {
    if requirement.storage_create_operation().as_bytes() != &operation {
        return Err(StorageStateError::AuthorityLinkMismatch);
    }
    ensure_root(wire, requirement.root(), false)?;
    require_available_name(wire, requirement.dataset_name())
}

/// Drops canonical bytes before the metadata/wire that produced them.
pub(crate) struct CatalogPhysicalApplicationOriginalV1 {
    canonical: CanonicalStateOriginalV1,
    metadata_key: Option<(String, u64)>,
    metadata_insert: Option<Option<SnapshotMetadataWireV1>>,
    metadata_remove: Option<Option<SnapshotMetadataWireV1>>,
    new_metadata: Option<SnapshotMetadataWireV1>,
    metadata: Option<BTreeMap<(String, u64), SnapshotMetadataWireV1>>,
    wire: Option<PhysicalStateWire>,
    admission: Option<Result<(), StorageStateError>>,
    ingest: Option<Result<(), StorageStateError>>,
    effect: Option<Result<(), StorageStateError>>,
    supplement: Option<Result<(), StorageStateError>>,
    generation: Option<Result<u64, StorageStateError>>,
    first: Option<Failure>,
    entered: bool,
    completed: bool,
}

impl CatalogPhysicalApplicationOriginalV1 {
    pub(crate) const fn new() -> Self {
        Self {
            canonical: CanonicalStateOriginalV1::new(),
            metadata_key: None,
            metadata_insert: None,
            metadata_remove: None,
            new_metadata: None,
            metadata: None,
            wire: None,
            admission: None,
            ingest: None,
            effect: None,
            supplement: None,
            generation: None,
            first: None,
            entered: false,
            completed: false,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let state = match self.first? {
            Failure::Admission => self.admission.as_ref()?.as_ref().err(),
            Failure::Ingest => self.ingest.as_ref()?.as_ref().err(),
            Failure::Effect => self.effect.as_ref()?.as_ref().err(),
            Failure::Metadata => self.supplement.as_ref()?.as_ref().err(),
            Failure::Generation => self.generation.as_ref()?.as_ref().err(),
            Failure::Canonical => self.canonical.failure(),
        };
        state.map(|cause| cause as &dyn std::error::Error)
    }

    pub(super) fn take_failure(&mut self) -> Option<StorageStateError> {
        match self.first? {
            Failure::Admission => self.admission.take()?.err(),
            Failure::Ingest => self.ingest.take()?.err(),
            Failure::Effect => self.effect.take()?.err(),
            Failure::Metadata => self.supplement.take()?.err(),
            Failure::Generation => self.generation.take()?.err(),
            Failure::Canonical => self.canonical.take_failure(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn apply(
        &mut self,
        source: &PhysicalCatalogState,
        operation_id: [u8; 16],
        catalog: &ResolvedCatalogCommitmentV1,
        object_guid: Option<u64>,
        snapshot_metadata: Option<CheckedSnapshotMetadataRecordV1>,
        receiving: Option<&mut StateEncodingContextV1<'_, '_, '_>>,
    ) -> Result<PhysicalCatalogState, StorageStateError> {
        self.apply_recipe_v3(
            source, operation_id, ApplicationRecipeV3::Ordinary(catalog),
            object_guid, snapshot_metadata, receiving,
        )
    }

    pub(super) fn apply_capture_v3(
        &mut self,
        source: &PhysicalCatalogState,
        operation_id: [u8; 16],
        requirement: &execution_capture::CaptureDatasetRequirementV1,
        resolution: CatalogBindingV1,
        object_guid: u64,
        receiving: Option<&mut StateEncodingContextV1<'_, '_, '_>>,
    ) -> Result<PhysicalCatalogState, StorageStateError> {
        self.apply_recipe_v3(
            source, operation_id,
            ApplicationRecipeV3::Capture { requirement, resolution },
            Some(object_guid), None, receiving,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_recipe_v3(
        &mut self,
        source: &PhysicalCatalogState,
        operation_id: [u8; 16],
        recipe: ApplicationRecipeV3<'_>,
        object_guid: Option<u64>,
        snapshot_metadata: Option<CheckedSnapshotMetadataRecordV1>,
        receiving: Option<&mut StateEncodingContextV1<'_, '_, '_>>,
    ) -> Result<PhysicalCatalogState, StorageStateError> {
        if self.entered {
            return Err(StorageStateError::Receiving);
        }
        self.entered = true;
        let selected = receiving.is_some();
        self.first = Some(Failure::Admission);
        self.admission = Some(if source.binding.generation().checked_add(1)
            != Some(recipe.generation())
            || !recipe.current_format()
        {
            Err(StorageStateError::InvalidTransition)
        } else {
            Ok(())
        });
        if !matches!(self.admission, Some(Ok(()))) {
            return Err(StorageStateError::Receiving);
        }
        self.wire = Some(source.wire.clone());
        let Some(wire) = self.wire.as_mut() else {
            std::process::abort();
        };
        wire.version = FORMAT_VERSION;
        self.metadata = Some(source.snapshot_metadata.clone());
        let Some(metadata) = self.metadata.as_mut() else {
            std::process::abort();
        };

        self.first = Some(Failure::Ingest);
        self.ingest = Some(recipe.ingest(wire, operation_id));
        if !matches!(self.ingest, Some(Ok(()))) {
            return Err(StorageStateError::Receiving);
        }
        self.first = Some(Failure::Effect);
        self.effect = Some(recipe.apply_postcondition(wire, operation_id, object_guid));
        if !matches!(self.effect, Some(Ok(()))) {
            return Err(StorageStateError::Receiving);
        }

        self.first = Some(Failure::Metadata);
        self.supplement = Some(match (recipe.ordinary_plan(), snapshot_metadata) {
            (Some(CatalogPlanV1::Snapshot { destination, .. }), Some(record)) => {
                match object_guid {
                    Some(guid) => validate_snapshot_metadata_record(
                        record, operation_id, guid, destination.dataset().guid(),
                        Some(destination.dataset().storage_handle()),
                    ),
                    None => Err(StorageStateError::InvalidValue),
                }
            }
            (Some(CatalogPlanV1::Snapshot { .. }), None) | (_, Some(_)) =>
                Err(StorageStateError::InvalidValue),
            _ => Ok(()),
        });
        if !matches!(self.supplement, Some(Ok(()))) {
            return Err(StorageStateError::Receiving);
        }
        if let (Some(CatalogPlanV1::Snapshot { destination, .. }), Some(record), Some(guid)) =
            (recipe.ordinary_plan(), snapshot_metadata, object_guid)
        {
            self.new_metadata = Some(snapshot_metadata_wire(record));
            self.metadata_key = Some((destination.name().to_owned(), guid));
            let Some(value) = self.new_metadata.take() else {
                std::process::abort();
            };
            let replaced = if selected {
                let Some(key) = self.metadata_key.as_ref() else {
                    std::process::abort();
                };
                if let Some(previous) = metadata.get_mut(key) {
                    // Keep both the old actual value and the incoming key on
                    // rejection; insert would discard the latter internally.
                    Some(std::mem::replace(previous, value))
                } else {
                    let Some(key) = self.metadata_key.take() else {
                        std::process::abort();
                    };
                    metadata.insert(key, value)
                }
            } else {
                let Some(key) = self.metadata_key.take() else {
                    std::process::abort();
                };
                metadata.insert(key, value)
            };
            self.metadata_insert = Some(replaced);
            let replaced = matches!(self.metadata_insert, Some(Some(_)));
            if !selected {
                // The old insert(...).is_some() consumed the actual replaced
                // value before returning the semantic transition error.
                drop(self.metadata_insert.take());
            }
            if replaced {
                self.supplement = Some(Err(StorageStateError::InvalidTransition));
                return Err(StorageStateError::Receiving);
            }
        }
        if let Some(CatalogPlanV1::DestroySnapshot { snapshot }) = recipe.ordinary_plan() {
            self.metadata_key = Some((snapshot.name().to_owned(), snapshot.guid()));
            let Some(key) = self.metadata_key.as_ref() else {
                std::process::abort();
            };
            self.metadata_remove = Some(metadata.remove(key));
            if !selected {
                drop(self.metadata_remove.take());
                drop(self.metadata_key.take());
            }
        }
        self.first = Some(Failure::Generation);
        self.generation = Some(
            recipe.generation().checked_add(1).ok_or(StorageStateError::InvalidValue),
        );
        let Some(Ok(generation)) = self.generation.as_ref() else {
            return Err(StorageStateError::Receiving);
        };
        wire.generation = *generation;
        wire.predecessor_state = Some(source.binding.into());
        wire.resolution = Some(recipe.binding().into());
        self.first = Some(Failure::Canonical);
        self.canonical.run(wire, metadata, receiving)?;
        let (bytes, binding) = self.canonical.take_positive();
        let Some(wire) = self.wire.take() else {
            std::process::abort();
        };
        let Some(snapshot_metadata) = self.metadata.take() else {
            std::process::abort();
        };
        self.completed = true;
        self.first = None;
        Ok(PhysicalCatalogState {
            wire,
            snapshot_metadata,
            bytes,
            binding,
        })
    }
}

// Fixed reached call frames: application7 operands/15 locals; ingestion4/1;
// root4/5, dataset4/1, root-comparison3/3, snapshot3/1, hold5/4;
// postcondition5/8, owned/borrowed insertion8/8, each removal4/2;
// aggregate2/1, dataset lookup3/1; plan admission3/1, root slot1/2,
// allocation diagnostic1/1; shape2/18. Canonical4/6, normalization13
// and shared source-shape8 are the same actual nested engine frames.
pub(crate) const SINGULAR_APPLICATION_CALL_CELLS: usize =
    7 + 15 + 4 + 1 + 4 + 5 + 4 + 1 + 3 + 3 + 3 + 1 + 5 + 4
        + 5 + 8 + 8 + 8 + 4 + 2 + 4 + 2 + 2 + 1 + 3 + 1
        + 3 + 1 + 1 + 2 + 1 + 1 + 2 + 18 + 4 + 6 + 13 + 8;

/// Prices only the source graphs and new rows of the actual typed catalog.
pub(super) fn shape(
    source: &PhysicalCatalogState,
    catalog: &ResolvedCatalogCommitmentV1,
) -> Result<(usize, usize), aos_sandbox_model::AccountingError> {
    use aos_sandbox_model::{AccountingError, ResourceDimension};
    let memory_error = || AccountingError::ArithmeticOverflow {
        dimension: ResourceDimension::MemoryBytes,
    };
    let metadata_error = || AccountingError::ArithmeticOverflow {
        dimension: ResourceDimension::MetadataEntries,
    };
    let (mut bytes, mut cells) = super::physical_preparation::retained_source_shape(source)?;
    let normalization_bytes =
        super::validation::catalog_uniqueness_bytes_v1(&source.wire, catalog)?;
    bytes = bytes.checked_add(normalization_bytes).ok_or_else(memory_error)?;
    let (row_bytes, row_entries, roots, expected_hold, lookup_name, new_metadata) =
        match catalog.plan() {
            CatalogPlanV1::CreateWorkspace { destination, ancestor, .. } => {
                let names = destination.name().len()
                    .checked_add(destination.root().pool().len())
                    .and_then(|n| n.checked_add(destination.root().dataset_prefix().len()))
                    .ok_or_else(memory_error)?;
                (
                    std::mem::size_of::<DatasetWire>()
                        .checked_add(names).ok_or_else(memory_error)?,
                    1_usize,
                    [Some(destination.root()), Some(ancestor.dataset().root()), None],
                    None,
                    None,
                    false,
                )
            }
            CatalogPlanV1::Clone { source, destination, ancestor, .. } => {
                let names = destination.name().len()
                    .checked_add(destination.root().pool().len())
                    .and_then(|n| n.checked_add(destination.root().dataset_prefix().len()))
                    .and_then(|n| n.checked_add(source.name().len()))
                    .ok_or_else(memory_error)?;
                (
                    std::mem::size_of::<DatasetWire>()
                        .checked_add(names).ok_or_else(memory_error)?,
                    1,
                    [
                        Some(destination.root()),
                        Some(source.dataset().root()),
                        Some(ancestor.dataset().root()),
                    ],
                    Some(source.name()),
                    None,
                    false,
                )
            }
            CatalogPlanV1::Snapshot { source, destination } => {
                let names = source.name().len().checked_add(destination.name().len())
                    .ok_or_else(memory_error)?;
                (
                    std::mem::size_of::<SnapshotWireV1>()
                        .checked_add(names).ok_or_else(memory_error)?,
                    1,
                    [Some(source.root()), Some(source.root()), None],
                    None,
                    Some(destination.name()),
                    true,
                )
            }
            CatalogPlanV1::HoldSnapshot { snapshot, .. } => (
                std::mem::size_of::<HoldWire>().checked_add(snapshot.name().len())
                    .ok_or_else(memory_error)?,
                1,
                [Some(snapshot.dataset().root()), Some(snapshot.dataset().root()), None],
                None,
                None,
                false,
            ),
            CatalogPlanV1::ReleaseHold { snapshot, .. } => (
                0,
                0,
                [Some(snapshot.dataset().root()), Some(snapshot.dataset().root()), None],
                Some(snapshot.name()),
                None,
                false,
            ),
            CatalogPlanV1::SetQuota { dataset, ancestor, .. } => (
                0,
                0,
                [Some(dataset.root()), Some(dataset.root()), Some(ancestor.dataset().root())],
                None,
                None,
                false,
            ),
            CatalogPlanV1::DestroyDataset { dataset } => (
                std::mem::size_of::<TombstoneWire>().checked_add(dataset.name().len())
                    .ok_or_else(memory_error)?,
                1,
                [Some(dataset.root()), Some(dataset.root()), None],
                None,
                None,
                false,
            ),
            CatalogPlanV1::DestroySnapshot { snapshot } => (
                std::mem::size_of::<TombstoneWire>().checked_add(snapshot.name().len())
                    .ok_or_else(memory_error)?,
                1,
                [Some(snapshot.dataset().root()), Some(snapshot.dataset().root()), None],
                None,
                Some(snapshot.name()),
                false,
            ),
        };
    bytes = row_bytes.checked_mul(3).and_then(|rows| bytes.checked_add(rows))
        .ok_or_else(memory_error)?;
    cells = row_entries.checked_mul(3).and_then(|rows| cells.checked_add(rows))
        .ok_or_else(metadata_error)?;
    // These input-comparison/lookup operands allocate bytes but create no
    // catalog row or resident index entry (ingestion uses allow_seed=false).
    for root in roots.into_iter().flatten() {
        let names = root.pool().len().checked_add(root.dataset_prefix().len())
            .ok_or_else(memory_error)?;
        bytes = names.checked_add(std::mem::size_of::<RootWire>())
            .and_then(|expected| bytes.checked_add(expected)).ok_or_else(memory_error)?;
    }
    if let Some(name) = expected_hold {
        bytes = name.len().checked_add(std::mem::size_of::<HoldWire>())
            .and_then(|expected| bytes.checked_add(expected)).ok_or_else(memory_error)?;
    }
    if let CatalogPlanV1::Clone { source, .. } = catalog.plan() {
        bytes = bytes.checked_add(std::mem::size_of::<OriginWire>())
            .and_then(|n| n.checked_add(source.name().len())).ok_or_else(memory_error)?;
    }
    if let Some(name) = lookup_name {
        bytes = name.len().checked_mul(2).and_then(|keys| bytes.checked_add(keys))
            .ok_or_else(memory_error)?;
    }
    if new_metadata {
        let node = aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1::<
            (String, u64), SnapshotMetadataWireV1,
        >(1).ok_or_else(memory_error)?;
        bytes = node.checked_mul(2).and_then(|nodes| bytes.checked_add(nodes))
            .and_then(|bytes| bytes.checked_add(3 * 384)).ok_or_else(memory_error)?;
        // Two real metadata maps receive this key. The persistent DTO
        // embeds its record in the already-counted new snapshot row.
        cells = cells.checked_add(2).ok_or_else(metadata_error)?;
    }
    let fixed = std::mem::size_of::<CatalogPhysicalApplicationOriginalV1>()
        + std::mem::size_of::<CanonicalStateOriginalV1>()
        + std::mem::size_of::<TransitionPayload>()
        + 3 * std::mem::size_of::<CheckedSnapshotMetadataRecordV1>()
        + std::mem::size_of::<Sha256>() + std::mem::size_of::<ObjectDigest>()
        + SINGULAR_APPLICATION_CALL_CELLS * std::mem::size_of::<(usize, usize)>();
    bytes = bytes.checked_add(fixed).ok_or_else(memory_error)?;
    Ok((bytes, cells))
}

/// Prices the exact dedicated-row branch before its common application grows.
pub(super) fn capture_shape_v3(
    source: &PhysicalCatalogState,
    requirement: &execution_capture::CaptureDatasetRequirementV1,
) -> Result<(usize, usize), aos_sandbox_model::AccountingError> {
    use aos_sandbox_model::{AccountingError, ResourceDimension as D};
    let overflow = || AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
    let (bytes, entries) = super::physical_preparation::retained_source_shape(source)?;
    let row = std::mem::size_of::<DatasetWire>()
        .checked_add(requirement.dataset_name().len())
        .and_then(|bytes| bytes.checked_add(requirement.root().pool().len()))
        .and_then(|bytes| bytes.checked_add(requirement.root().dataset_prefix().len()))
        .ok_or_else(overflow)?;
    let comparison = std::mem::size_of::<RootWire>()
        .checked_add(requirement.root().pool().len())
        .and_then(|bytes| bytes.checked_add(requirement.root().dataset_prefix().len()))
        .ok_or_else(overflow)?;
    let fixed = std::mem::size_of::<CatalogPhysicalApplicationOriginalV1>()
        + std::mem::size_of::<CanonicalStateOriginalV1>()
        + std::mem::size_of::<TransitionPayload>()
        + 3 * std::mem::size_of::<CheckedSnapshotMetadataRecordV1>()
        + std::mem::size_of::<Sha256>() + std::mem::size_of::<ObjectDigest>()
        + SINGULAR_APPLICATION_CALL_CELLS * std::mem::size_of::<(usize, usize)>();
    let bytes = row.checked_mul(3).and_then(|rows| bytes.checked_add(rows))
        .and_then(|bytes| bytes.checked_add(comparison))
        .and_then(|bytes| bytes.checked_add(fixed))
        .and_then(|bytes| bytes.checked_add(super::validation::capture_uniqueness_bytes_v3(&source.wire).ok()?))
        .ok_or_else(overflow)?;
    let entries = entries.checked_add(3).ok_or(AccountingError::ArithmeticOverflow {
        dimension: D::MetadataEntries,
    })?;
    Ok((bytes, entries))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_namespace_adds_one_dataset_per_reached_graph() {
        let catalog = super::super::tests::catalog(7, "tank/aos/project/work");
        let source = PhysicalCatalogState::bootstrap(6, std::slice::from_ref(&catalog)).unwrap();
        assert_eq!(source.wire.roots.len(), 1);
        assert_eq!(source.wire.datasets.len(), 1);

        let (_, entries) = shape(&source, &catalog).unwrap();

        // The existing root/ancestor plus one new dataset appear in the
        // application, canonical persistent DTO and transition state.
        assert_eq!(entries, 9);
    }

    #[test]
    fn shared_input_check_preserves_error_and_original_graph() {
        let catalog = super::super::tests::catalog(7, "tank/aos/project/work");
        let source = PhysicalCatalogState::bootstrap(6, std::slice::from_ref(&catalog)).unwrap();
        let dataset = match catalog.plan() {
            CatalogPlanV1::CreateWorkspace { ancestor, .. } => ancestor.dataset(),
            _ => unreachable!(),
        };
        let mut candidate = source.wire.clone();
        candidate.datasets[0].guid += 1;
        let before = serde_json::to_vec(&candidate).unwrap();
        let original = serde_json::to_vec(&source.wire).unwrap();

        assert!(matches!(ensure_dataset(&mut candidate, dataset, false),
            Err(StorageStateError::InvalidTransition)));

        assert_eq!(serde_json::to_vec(&candidate).unwrap(), before);
        assert_eq!(serde_json::to_vec(&source.wire).unwrap(), original);
    }

    #[test]
    fn shared_removal_keeps_tombstone_and_source_unchanged() {
        let catalog = super::super::tests::catalog(7, "tank/aos/project/work");
        let source = PhysicalCatalogState::bootstrap(6, std::slice::from_ref(&catalog)).unwrap();
        let dataset = match catalog.plan() {
            CatalogPlanV1::CreateWorkspace { ancestor, .. } => ancestor.dataset(),
            _ => unreachable!(),
        };
        let mut candidate = source.wire.clone();
        let original = serde_json::to_vec(&source.wire).unwrap();
        let operation = [91; 16];

        remove_dataset(&mut candidate, operation, dataset).unwrap();

        assert!(candidate.datasets.iter().all(|row| row.name != dataset.name()));
        assert!(candidate.tombstones.iter().any(|row|
            row.name == dataset.name() && row.guid == dataset.guid()
                && row.retired_by == operation));
        assert_eq!(serde_json::to_vec(&source.wire).unwrap(), original);
        assert!(matches!(remove_dataset(&mut candidate, operation, dataset),
            Err(StorageStateError::InvalidTransition)));
    }
}
