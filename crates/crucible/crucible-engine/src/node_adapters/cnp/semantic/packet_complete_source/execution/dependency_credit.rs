//! Quotes the fixed original producer's dependency metadata before effects.
//!
//! Actual retained input/ancestry/backend references and the closed generated
//! role roster determine these requested-layout bounds. They are data. A real
//! whole admission must bind the same prepared runtime before using the bounds.

use super::born::{ancestry_external_content_dependencies, semantic_external_content_dependencies};
use super::*;

/// Reports distinct future original dependency-metadata obligations.
///
/// The source-private prepared plan binds this data to one actual Runtime7 body.
/// It grants no scratch allowance, ticket, Capture or archive permission.
#[derive(Clone, Copy, Debug)]
pub struct PacketCompleteCaptureDependencyStorageData {
    source_born_growth: usize,
    returned_row_growth: usize,
    maximum_lookup_scratch: usize,
    maximum_dependency_count: usize,
}

impl PacketCompleteCaptureDependencyStorageData {
    /// Returns future dynamic backing retained by the original Source rows.
    pub fn source_born_growth(&self) -> usize {
        self.source_born_growth
    }

    /// Returns all separately retained row vectors/reference clones returned to Core.
    pub fn returned_row_growth(&self) -> usize {
        self.returned_row_growth
    }

    /// Returns one lookup's complete returned vector plus temporary verification hash.
    pub fn maximum_lookup_scratch(&self) -> usize {
        self.maximum_lookup_scratch
    }

    /// Returns the maximum occurrence count in any prospective dependency row.
    ///
    /// Repeated references are counted before the producer sorts and deduplicates.
    pub fn maximum_dependency_count(&self) -> usize {
        self.maximum_dependency_count
    }
}

/// Reports one already born row's prospective copy and verification storage.
#[derive(Clone, Copy, Debug)]
pub struct PacketCompleteCaptureDependencyLookupData {
    returned_row_bytes: usize,
    verification_bytes: usize,
}

impl PacketCompleteCaptureDependencyLookupData {
    /// Returns the separate returned dependency Vec and cloned fullref backing.
    pub fn returned_row_bytes(&self) -> usize {
        self.returned_row_bytes
    }

    /// Returns the temporary actual hash backing used by full-body verification.
    pub fn verification_bytes(&self) -> usize {
        self.verification_bytes
    }

    /// Returns their checked simultaneous requested-layout sum as data.
    ///
    /// # Errors
    /// Refuses arithmetic overflow. A result is not an admission or authority.
    pub fn requested_bytes(&self) -> Result<usize, OperationFailure> {
        retained_values::sum(
            [self.returned_row_bytes, self.verification_bytes],
            usize::MAX,
        )
    }
}

pub(super) struct OriginalDependencyPlan {
    pub(super) runtime: ContentRef,
    data: PacketCompleteCaptureDependencyStorageData,
}

// canonical::content_ref requests exactly these three hash Strings. ContentRef
// validation requires this algorithm/domain and a 64-byte hexadecimal digest.
// The numeric length is an inline U64; no placeholder body or hash is allocated.
fn generated_hash_bytes() -> usize {
    "blake3-256".len() + "cnp.blob.v1".len() + 64
}

fn generated_reference_bytes(role: born::OriginalBornRole) -> usize {
    use born::OriginalBornRole::*;
    let media = match role {
        // These refs arrive through the original native result. Their complete
        // validated ContentRef grammar bounds printable media at 128 bytes;
        // this is a prospective metadata-copy bound, not a native heap report.
        NativeSnapshot | NativeControl | NativeAnchor | NativeAfter => {
            return generated_hash_bytes() + 128;
        }
        NativeAllocationReport => crucible_node_transport::reference_packet::service::capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA,
        HostProtocol => "application/vnd.source-owned.packet-host-protocol.v11+json",
        HostExtensionRegistry => registry_capture::HOST_REGISTRY_MEDIA,
        Semantic => "application/vnd.source-owned.packet-semantic-custody.v5+json",
        Ancestry => "application/vnd.source-owned.packet-original-ancestry.v12+json",
        // The explicit v15/v16/v17 media have the same closed encoded extent.
        Backend => return generated_hash_bytes()
            + BACKEND_MEDIA.len().max(STARTUP_BACKEND_MEDIA.len()).max(INVOCATION_BACKEND_MEDIA.len()),
        Journal => "application/vnd.source-owned.packet-native-settled-journal.v12+json",
    };
    generated_hash_bytes() + media.len()
}

struct RowQuote {
    bytes: usize,
    count: usize,
    maximum: usize,
}

impl RowQuote {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: 0,
            count: 0,
            maximum,
        }
    }

    fn add_bytes(&mut self, bytes: usize) -> Result<(), OperationFailure> {
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| refused("original dependency count overflow"))?;
        self.bytes =
            retained_values::sum([self.bytes, size_of::<ContentRef>(), bytes], self.maximum)?;
        Ok(())
    }

    fn existing(&mut self, reference: &ContentRef) -> Result<(), OperationFailure> {
        // Charging the actual source String capacities is conservative for a
        // clone, which requests their initialized lengths. No alias is refunded.
        self.add_bytes(NodeRuntime::capture_reference_storage(reference).map_err(unknown)?)
    }

    fn generated(&mut self, role: born::OriginalBornRole) -> Result<(), OperationFailure> {
        self.add_bytes(generated_reference_bytes(role))
    }
}

struct PlanQuote {
    rows: usize,
    data: PacketCompleteCaptureDependencyStorageData,
    maximum: usize,
}

impl PlanQuote {
    fn new(maximum: usize) -> Self {
        Self {
            rows: 0,
            data: PacketCompleteCaptureDependencyStorageData {
                source_born_growth: 0,
                returned_row_growth: 0,
                maximum_lookup_scratch: 0,
                maximum_dependency_count: 0,
            },
            maximum,
        }
    }

    fn finish_row(
        &mut self,
        role: born::OriginalBornRole,
        row: RowQuote,
    ) -> Result<(), OperationFailure> {
        self.rows = self
            .rows
            .checked_add(1)
            .ok_or_else(|| refused("original dependency row count overflow"))?;
        self.data.source_born_growth = retained_values::sum(
            [
                self.data.source_born_growth,
                generated_reference_bytes(role),
                row.bytes,
            ],
            self.maximum,
        )?;
        self.data.returned_row_growth =
            retained_values::sum([self.data.returned_row_growth, row.bytes], self.maximum)?;
        let scratch = retained_values::sum([row.bytes, generated_hash_bytes()], self.maximum)?;
        self.data.maximum_lookup_scratch = self.data.maximum_lookup_scratch.max(scratch);
        self.data.maximum_dependency_count = self.data.maximum_dependency_count.max(row.count);
        Ok(())
    }
}

impl PacketCompleteSemanticSource {
    pub(super) fn prepare_original_dependency_plan(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        runtime_object: &InputPayload,
        execution: &mut OriginalCompleteCaptureExecution,
        maximum: usize,
    ) -> Result<(), OperationFailure> {
        if let Some(plan) = &execution.dependency_plan {
            if plan.runtime != runtime_object.reference {
                return Err(refused(
                    "original dependency plan has another Runtime7 body",
                ));
            }
            // This invocation may have a narrower remaining whole window than
            // the one that prepared the plan. Its runtime clone is already in
            // retained_storage, so reuse admits only the still-future backing.
            retained_values::sum(
                [
                    execution.retained_storage(maximum)?,
                    plan.data.source_born_growth,
                    plan.data.returned_row_growth,
                    plan.data.maximum_lookup_scratch,
                ],
                maximum,
            )?;
            return Ok(());
        }
        self.authenticate_witness_scope(scope)?;
        let runtime = scope
            .native
            .runtime
            .as_ref()
            .ok_or_else(|| refused("original dependency plan has no semantic custody"))?;
        let lineages = self.original_reference_ancestry_lineages(scope)?;
        use born::OriginalBornRole::*;
        let mut plan = PlanQuote::new(maximum);
        plan.quote_native_rows(execution.allocation_selected)?;
        if execution.allocation_selected {
            // The independent Report InputPayload fullref is constructed in
            // addition to the born-row reference and its returned Core clones.
            plan.data.source_born_growth = retained_values::sum(
                [
                    plan.data.source_born_growth,
                    generated_reference_bytes(NativeAllocationReport),
                ],
                maximum,
            )?;
            plan.data.maximum_lookup_scratch = plan.data.maximum_lookup_scratch.max(
                allocation_report::allocation_reference_phase_storage_for_class_data(
                    self.selected_complete_native_snapshot_class()?,
                    maximum,
                )?,
            );
        }
        let mut semantic = RowQuote::new(maximum);
        semantic.existing(&runtime_object.reference)?;
        semantic.generated(HostProtocol)?;
        for reference in semantic_external_content_dependencies(runtime) {
            semantic.existing(reference)?;
        }
        plan.finish_row(Semantic, semantic)?;
        let mut ancestry = RowQuote::new(maximum);
        for lineage in lineages.iter().flat_map(|lineages| lineages.iter()) {
            for reference in ancestry_external_content_dependencies(lineage) {
                ancestry.existing(reference)?;
            }
        }
        plan.finish_row(Ancestry, ancestry)?;
        let installed = &self.installation().binding.compatibility.implementation;
        let mut backend = RowQuote::new(maximum);
        for reference in installed
            .artifacts
            .iter()
            .map(|artifact| &artifact.content)
            .chain(installed.formats.iter().map(|schema| &schema.definition))
            .chain(installed.model_definitions.iter())
        {
            backend.existing(reference)?;
        }
        plan.finish_row(Backend, backend)?;
        let mut journal = RowQuote::new(maximum);
        journal.existing(&runtime_object.reference)?;
        for role in [
            Backend,
            Semantic,
            Ancestry,
            NativeSnapshot,
            NativeControl,
            NativeAnchor,
            NativeAfter,
            HostProtocol,
            HostExtensionRegistry,
        ] {
            journal.generated(role)?;
        }
        plan.finish_row(Journal, journal)?;
        if plan.rows != execution.born_roles() {
            return Err(refused("original dependency role roster differs"));
        }
        retained_values::sum(
            [
                execution.retained_storage(maximum)?,
                NodeRuntime::capture_reference_storage(&runtime_object.reference)
                    .map_err(unknown)?,
                plan.data.source_born_growth,
                plan.data.returned_row_growth,
                plan.data.maximum_lookup_scratch,
            ],
            maximum,
        )?;
        execution.dependency_plan = Some(OriginalDependencyPlan {
            runtime: runtime_object.reference.clone(),
            data: plan.data,
        });
        self.authenticate_witness_scope(scope)
    }

    /// Borrows the actual prepared plan's named metadata obligations as data.
    ///
    /// The trusted factory separately conjoins same-source Core preflight and a
    /// genuine whole allocation admission. This getter neither creates nor
    /// authenticates an allowance from the returned byte counts.
    ///
    /// # Errors
    /// Refuses a foreign creator, missing/busy original plan or another Runtime7.
    pub fn original_complete_capture_dependency_preflight_data(
        &self,
        runtime: &ContentRef,
    ) -> Result<PacketCompleteCaptureDependencyStorageData, OperationFailure> {
        self.ensure_origin()?;
        let slot = self
            .capture_execution
            .try_borrow()
            .map_err(|_| refused("original dependency plan is borrowed"))?;
        let plan = slot
            .as_ref()
            .and_then(|original| original.dependency_plan.as_ref())
            .filter(|plan| &plan.runtime == runtime)
            .ok_or_else(|| refused("original dependency plan is absent or has another Runtime7"))?;
        Ok(plan.data)
    }

    /// Quotes one already born lookup before its returned row is allocated.
    ///
    /// This origin-only data read uses the exact retained private row. Unknown
    /// references return None. A real admitted scratch window remains required.
    ///
    /// # Errors
    /// Refuses a foreign creator, borrowed/ambiguous row, excessive edge count,
    /// or checked requested-layout overflow.
    pub fn original_complete_capture_dependency_lookup_data(
        &self,
        reference: &ContentRef,
        maximum_objects: usize,
    ) -> Result<Option<PacketCompleteCaptureDependencyLookupData>, OperationFailure> {
        self.ensure_origin()?;
        if crate::node_adapters::cnp::CnpSemanticSource::requires_restored_capture17_scope_data(
            self,
        )
        .map_err(unknown)?
        {
            return self
                .with_original_capture17_dependency_row_data(reference, |row| {
                    row.map(|dependencies| {
                        PacketCompleteCaptureDependencyLookupData::from_borrowed_capture17_data(
                            reference,
                            dependencies,
                            maximum_objects,
                        )
                    })
                    .transpose()
                })
                .map_err(unknown);
        }
        let slot = self
            .capture_execution
            .try_borrow()
            .map_err(|_| refused("original dependency row is borrowed"))?;
        let Some(original) = slot.as_ref() else {
            return Ok(None);
        };
        let mut matches = original
            .born
            .iter()
            .filter(|row| row.reference() == reference);
        let Some(row) = matches.next() else {
            return Ok(None);
        };
        if matches.next().is_some() {
            return Err(refused("original dependency row is ambiguous"));
        }
        row.lookup_storage_data(maximum_objects).map(Some)
    }
}

impl born::OriginalBornObject {
    pub(super) fn lookup_storage_data(
        &self,
        maximum_objects: usize,
    ) -> Result<PacketCompleteCaptureDependencyLookupData, OperationFailure> {
        let dependencies = self.dependencies();
        if dependencies.len() > maximum_objects {
            return Err(refused("original dependency edge count exceeds admission"));
        }
        let mut returned_row_bytes = dependencies
            .len()
            .checked_mul(size_of::<ContentRef>())
            .ok_or_else(|| refused("original dependency row slots overflow"))?;
        for reference in dependencies {
            returned_row_bytes = retained_values::sum(
                [
                    returned_row_bytes,
                    NodeRuntime::capture_reference_storage(reference).map_err(unknown)?,
                ],
                usize::MAX,
            )?;
        }
        Ok(PacketCompleteCaptureDependencyLookupData {
            returned_row_bytes,
            verification_bytes: NodeRuntime::capture_hash_storage(&self.reference().hash)
                .map_err(unknown)?,
        })
    }
}

impl OriginalCompleteCaptureExecution {
    /// Rechecks actual born owners against their same-runtime prospective plan.
    /// No body or dependency is moved until this complete comparison succeeds.
    pub(super) fn authenticate_original_dependency_storage(
        &self,
        runtime: &ContentRef,
        maximum_objects: usize,
        maximum: usize,
    ) -> Result<(), OperationFailure> {
        let plan = self
            .dependency_plan
            .as_ref()
            .filter(|plan| &plan.runtime == runtime)
            .ok_or_else(|| refused("original dependency storage plan has another Runtime7"))?;
        if self.born.len() != self.born_roles() {
            return Err(refused(
                "original dependency storage has an incomplete born roster",
            ));
        }
        let mut source_bytes = 0usize;
        let mut returned_bytes = 0usize;
        for row in &self.born {
            let lookup = row.lookup_storage_data(maximum_objects)?;
            source_bytes =
                retained_values::sum([source_bytes, row.retained_storage(maximum)?], maximum)?;
            returned_bytes =
                retained_values::sum([returned_bytes, lookup.returned_row_bytes], maximum)?;
            if row.dependencies().len() > plan.data.maximum_dependency_count
                || lookup.requested_bytes()? > plan.data.maximum_lookup_scratch
            {
                return Err(refused(
                    "original born lookup exceeds its prepared dependency plan",
                ));
            }
        }
        if source_bytes > plan.data.source_born_growth
            || returned_bytes > plan.data.returned_row_growth
        {
            return Err(refused(
                "original born storage exceeds its prepared dependency plan",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prospective_quote_covers_duplicate_slots_and_actual_fullref_backing() -> Result<(), String> {
        // Repeated direct edges disappear after dedup, but their reserved slots
        // remain owned. The pre-effect quote must retain that simultaneous cost.
        let media = "x".repeat(128);
        let reference = canonical::content_ref(b"actual generated dependency", &media)
            .map_err(|error| format!("{error:?}"))?;
        let payload = InputPayload {
            reference: canonical::content_ref(b"actual native snapshot", &media)
                .map_err(|error| format!("{error:?}"))?,
            bytes: b"actual native snapshot".to_vec(),
        };
        let mut proposed = PlanQuote::new(usize::MAX);
        let mut row = RowQuote::new(usize::MAX);
        row.generated(born::OriginalBornRole::NativeControl)
            .map_err(|error| format!("{error:?}"))?;
        row.generated(born::OriginalBornRole::NativeControl)
            .map_err(|error| format!("{error:?}"))?;
        proposed
            .finish_row(born::OriginalBornRole::NativeSnapshot, row)
            .map_err(|error| format!("{error:?}"))?;

        let mut actual = Vec::new();
        actual
            .try_reserve_exact(1)
            .map_err(|error| format!("{error:?}"))?;
        OriginalCompleteCaptureExecution::record_born(
            &mut actual,
            born::OriginalBornRole::NativeSnapshot,
            &payload,
            [&reference, &reference].into_iter(),
            2,
            usize::MAX,
        )
        .map_err(|error| format!("{error:?}"))?;
        let actual = actual.first().ok_or("actual born row absent")?;
        let lookup = actual
            .lookup_storage_data(1)
            .map_err(|error| format!("{error:?}"))?;

        assert_eq!(actual.dependencies().len(), 1);
        assert_eq!(proposed.data.maximum_dependency_count(), 2);
        assert!(
            actual
                .retained_storage(usize::MAX)
                .map_err(|error| format!("{error:?}"))?
                <= proposed.data.source_born_growth()
        );
        assert!(lookup.returned_row_bytes() <= proposed.data.returned_row_growth());
        assert!(
            lookup
                .requested_bytes()
                .map_err(|error| format!("{error:?}"))?
                <= proposed.data.maximum_lookup_scratch()
        );
        assert!(actual.lookup_storage_data(0).is_err());
        Ok(())
    }
}

impl PlanQuote {
    fn quote_native_rows(&mut self, allocation_selected: bool) -> Result<(), OperationFailure> {
        use born::OriginalBornRole::*;
        for (role, dependency) in [
            (NativeSnapshot, NativeControl),
            (NativeControl, Backend),
            (NativeAnchor, NativeControl),
        ] {
            let mut row = RowQuote::new(self.maximum);
            row.generated(dependency)?;
            if role == NativeSnapshot && allocation_selected {
                row.generated(NativeAllocationReport)?;
            }
            self.finish_row(role, row)?;
        }
        for role in [NativeAfter, HostProtocol, HostExtensionRegistry] {
            self.finish_row(role, RowQuote::new(self.maximum))?;
        }
        if allocation_selected {
            self.finish_row(NativeAllocationReport, RowQuote::new(self.maximum))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod selected_report_tests {
    use super::*;

    #[test]
    fn original_snapshot_dependency_quote_includes_report_edge_and_intrinsic_leaf() {
        let mut ordinary = PlanQuote::new(usize::MAX);
        ordinary.quote_native_rows(false).unwrap();
        let mut selected = PlanQuote::new(usize::MAX);
        selected.quote_native_rows(true).unwrap();
        assert_eq!(ordinary.rows, 6);
        assert_eq!(selected.rows, 7);
        assert_eq!(ordinary.data.maximum_dependency_count, 1);
        assert_eq!(selected.data.maximum_dependency_count, 2);
        assert!(selected.data.source_born_growth > ordinary.data.source_born_growth);
        assert!(selected.data.returned_row_growth > ordinary.data.returned_row_growth);
        assert!(selected.data.maximum_lookup_scratch > ordinary.data.maximum_lookup_scratch);
        let mut short = PlanQuote::new(selected.data.source_born_growth - 1);
        assert!(short.quote_native_rows(true).is_err());
    }
}

impl OriginalDependencyPlan {
    pub(super) fn maximum_lookup_scratch_data(&self) -> usize {
        self.data.maximum_lookup_scratch
    }
}

impl PacketCompleteCaptureDependencyLookupData {
    /// Prices one concrete already-owned row and its independent verification.
    ///
    /// # Errors
    /// Refuses excessive edge population or checked requested-layout overflow.
    pub(crate) fn from_borrowed_capture17_data(
        reference: &ContentRef,
        dependencies: &[ContentRef],
        maximum_objects: usize,
    ) -> Result<Self, RuntimeError> {
        if dependencies.len() > maximum_objects {
            return Err(RuntimeError::ResourceLimit);
        }
        let mut returned_row_bytes = dependencies
            .len()
            .checked_mul(size_of::<ContentRef>())
            .ok_or(RuntimeError::ResourceLimit)?;
        for dependency in dependencies {
            returned_row_bytes = returned_row_bytes
                .checked_add(NodeRuntime::capture_reference_storage(dependency)?)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        Ok(Self {
            returned_row_bytes,
            verification_bytes: NodeRuntime::capture_hash_storage(&reference.hash)?,
        })
    }
}

impl PacketCompleteCaptureDependencyStorageData {
    /// Carries a defining finite Capture17 row quote without granting admission.
    pub(crate) const fn from_capture17_data(
        source_born_growth: usize,
        returned_row_growth: usize,
        maximum_lookup_scratch: usize,
        maximum_dependency_count: usize,
    ) -> Self {
        Self {
            source_born_growth,
            returned_row_growth,
            maximum_lookup_scratch,
            maximum_dependency_count,
        }
    }
}

/// Copies one concrete row inside its independently admitted return/hash window.
///
/// # Errors
/// Refuses short row/hash credit, a different supplied body or allocation excess.
pub(super) fn copy_capture17_dependencies_data(
    reference: &ContentRef,
    bytes: &[u8],
    dependencies: &[ContentRef],
    maximum_objects: usize,
    maximum_scratch_bytes: usize,
) -> Result<Vec<ContentRef>, RuntimeError> {
    let quote = PacketCompleteCaptureDependencyLookupData::from_borrowed_capture17_data(
        reference,
        dependencies,
        maximum_objects,
    )?;
    if quote
        .requested_bytes()
        .map_err(|_| RuntimeError::ResourceLimit)?
        > maximum_scratch_bytes
    {
        return Err(RuntimeError::ResourceLimit);
    }

    let mut copied = Vec::new();
    copied
        .try_reserve_exact(dependencies.len())
        .map_err(|_| RuntimeError::ResourceLimit)?;
    if copied.capacity() > dependencies.len() {
        return Err(RuntimeError::ResourceLimit);
    }
    copied.extend(dependencies.iter().cloned());
    reference
        .verify(bytes)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    Ok(copied)
}

#[cfg(test)]
mod capture17_lookup_tests {
    use super::*;
    use crucible_node_format::canonical;

    #[test]
    fn concrete_lookup_prices_full_reference_backing_and_independent_hash_window() {
        let output = canonical::content_ref(b"actual retained output", "application/json").unwrap();
        let dependency =
            canonical::content_ref(b"actual imported dependency", "application/json").unwrap();
        let mut other_media = dependency.clone();
        other_media.media_type = "application/vnd.example.longer-imported-body+json".into();
        let dependencies = [dependency.clone(), other_media.clone()];

        let lookup = PacketCompleteCaptureDependencyLookupData::from_borrowed_capture17_data(
            &output,
            &dependencies,
            2,
        )
        .unwrap();
        let cloned = dependencies.to_vec();
        let actual = cloned.capacity() * size_of::<ContentRef>()
            + cloned
                .iter()
                .map(|reference| NodeRuntime::capture_reference_storage(reference).unwrap())
                .sum::<usize>();

        assert!(lookup.returned_row_bytes() >= actual);
        assert_eq!(
            lookup.verification_bytes,
            NodeRuntime::capture_hash_storage(&output.hash).unwrap()
        );
        assert!(lookup.requested_bytes().unwrap() > lookup.returned_row_bytes());
        assert!(
            PacketCompleteCaptureDependencyLookupData::from_borrowed_capture17_data(
                &output,
                &dependencies,
                1,
            )
            .is_err()
        );
        assert_ne!(dependencies[0], dependencies[1]);
    }
    #[test]
    fn actual_row_copy_requires_exact_hash_and_full_independent_lookup_credit() {
        let bytes = b"actual body accepted by the defining content contract";
        let output = canonical::content_ref(bytes, "application/json").unwrap();
        let dependency =
            canonical::content_ref(b"actual signed dependency", "application/json").unwrap();
        let dependencies = [dependency];
        let quote = PacketCompleteCaptureDependencyLookupData::from_borrowed_capture17_data(
            &output,
            &dependencies,
            1,
        )
        .unwrap()
        .requested_bytes()
        .unwrap();

        let copied =
            copy_capture17_dependencies_data(&output, bytes, &dependencies, 1, quote).unwrap();

        assert_eq!(copied.as_slice(), dependencies);
        assert!(
            copy_capture17_dependencies_data(&output, bytes, &dependencies, 1, quote - 1).is_err()
        );
        assert!(
            copy_capture17_dependencies_data(&output, b"substituted body", &dependencies, 1, quote)
                .is_err()
        );
    }
}
