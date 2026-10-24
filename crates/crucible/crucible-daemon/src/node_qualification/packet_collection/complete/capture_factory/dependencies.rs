//! Joins original Source born-row demand to Core's late whole-storage check.
//!
//! Early factory/cache admission runs before an encoded Runtime7 exists. This
//! separate callback runs after owning preflight, and Core checks its named sum
//! before issuing a ticket. The fixed inline scope retains data association;
//! it cannot manufacture a Source row, ticket or historical leaf acceptance.

use super::*;
use crucible_engine::node_adapters::cnp::{
    PacketCompleteCaptureDependencyLookupData, PacketCompleteCaptureDependencyStorageData,
};
use crucible_engine::node_contract::{
    HostCaptureDependencyLookupData, HostCaptureDependencyStorageData,
};
use crucible_engine::node_state::{
    CompleteOriginalCaptureDependencyStorage, ORIGINAL_LINEAGE_RUNTIME_MEDIA,
};

#[derive(Clone, Copy, PartialEq, Eq)]
struct OriginalRuntimeIdentity {
    length: U64,
    digest: [u8; 64],
}

impl OriginalRuntimeIdentity {
    fn from_original(reference: &ContentRef) -> Result<Self, StateError> {
        if reference.hash.algorithm != "blake3-256"
            || reference.hash.domain != "cnp.blob.v1"
            || reference.media_type != ORIGINAL_LINEAGE_RUNTIME_MEDIA
            || reference.length.get() == 0
            || !reference
                .hash
                .digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(refused(
                "complete dependency scope is not original Runtime7",
            ));
        }
        Ok(Self {
            length: reference.length,
            digest: reference
                .hash
                .digest
                .as_bytes()
                .try_into()
                .map_err(|_| refused("complete dependency runtime digest extent"))?,
        })
    }
}

#[derive(Clone, Copy)]
struct OriginalSourceDependencyBound {
    born: usize,
    returned: usize,
    lookup: usize,
    count: usize,
}

impl From<PacketCompleteCaptureDependencyStorageData> for OriginalSourceDependencyBound {
    fn from(data: PacketCompleteCaptureDependencyStorageData) -> Self {
        Self {
            born: data.source_born_growth(),
            returned: data.returned_row_growth(),
            lookup: data.maximum_lookup_scratch(),
            count: data.maximum_dependency_count(),
        }
    }
}

impl From<HostCaptureDependencyStorageData> for OriginalSourceDependencyBound {
    fn from(data: HostCaptureDependencyStorageData) -> Self {
        Self {
            born: data.source_born_growth(),
            returned: data.returned_row_growth(),
            lookup: data.maximum_lookup_scratch(),
            count: data.maximum_dependency_count(),
        }
    }
}

impl OriginalSourceDependencyBound {
    fn authenticate_narrowing(&self, observed: Self) -> Result<(), StateError> {
        if observed.born > self.born
            || observed.returned > self.returned
            || observed.lookup > self.lookup
            || observed.count > self.count
        {
            return Err(refused("complete Source dependency plan widened"));
        }
        Ok(())
    }
}

// All fields are fixed inline data already included in the actual factory Rc
// payload. Runtime identity uses its closed public hash fields, with no String
// clone, body copy, native pointer or constructed replacement ContentRef.
pub(super) struct OriginalDependencyStorageScope {
    runtime: OriginalRuntimeIdentity,
    sources: [OriginalSourceDependencyBound; 3],
    host: OriginalSourceDependencyBound,
}

/// Counts known inline quote/lookup values before the late callback runs.
///
/// Early factory admission includes this term while no Source plan exists.
/// Recursive callbacks/compiler frames and allocator residency remain separate;
/// this reports actual compiled value layouts, not a measured stack bound.
pub(super) fn requested_scratch_bytes() -> usize {
    super::host17::selection_counter_scratch_data()
        + super::super::records::host_capture17_counter_scratch_data()
        + size_of::<OriginalDependencyStorageScope>()
        + size_of::<OriginalRuntimeIdentity>()
        + size_of::<[PacketCompleteCaptureDependencyStorageData; 3]>()
        + size_of::<[Option<PacketCompleteCaptureDependencyLookupData>; 3]>()
        + size_of::<HostCaptureDependencyStorageData>()
        + size_of::<Option<HostCaptureDependencyLookupData>>()
        + size_of::<CompleteOriginalCaptureDependencyStorage>()
        + size_of::<Option<Vec<ContentRef>>>()
}

impl OriginalDependencyStorageScope {
    fn requested_data(&self) -> Result<CompleteOriginalCaptureDependencyStorage, StateError> {
        let mut born = 0usize;
        let mut returned = 0usize;
        let mut lookup = 0usize;
        for source in self.sources.iter().chain(std::iter::once(&self.host)) {
            born = born
                .checked_add(source.born)
                .ok_or_else(|| refused("complete Source born storage overflow"))?;
            returned = returned
                .checked_add(source.returned)
                .ok_or_else(|| refused("complete returned dependency storage overflow"))?;
            // Lookups are synchronous. All returned rows remain retained,
            // whereas at most one verification/copy scratch window is active.
            lookup = lookup.max(source.lookup);
        }
        let data = CompleteOriginalCaptureDependencyStorage {
            source_born_growth_bytes: born,
            returned_row_growth_bytes: returned,
            maximum_lookup_scratch_bytes: lookup,
        };
        data.peak()?;
        Ok(data)
    }
}

fn retain_narrowed_scope(
    original: &mut Option<OriginalDependencyStorageScope>,
    observed: OriginalDependencyStorageScope,
) -> Result<(), StateError> {
    if let Some(admitted) = original.as_ref() {
        if admitted.runtime != observed.runtime {
            return Err(refused(
                "complete dependency callback changed original Runtime7",
            ));
        }
        for (admitted, actual) in admitted.sources.iter().zip(observed.sources) {
            admitted.authenticate_narrowing(actual)?;
        }
        admitted.host.authenticate_narrowing(observed.host)?;
    }
    // Keep exactly the data returned to Core by this successful query. A later
    // lookup cannot spend a former wider scope after a narrower requery. Every
    // field is inline, and replacement performs no allocation or owner clone.
    *original = Some(observed);
    Ok(())
}

impl PacketCompleteCaptureFactory {
    pub(super) fn original_dependency_storage(
        &self,
        graph: &AdmittedGraph,
        runtime: &OriginalLineageRuntimeRecord,
        scheduling: &SchedulingSnapshot,
        runtime_object: &crucible_engine::node_scheduling::InputPayload,
        limits: NativeArchiveLimits,
    ) -> Result<CompleteOriginalCaptureDependencyStorage, StateError> {
        self.authenticate_live(graph, runtime, scheduling)?;
        let identity = OriginalRuntimeIdentity::from_original(&runtime_object.reference)?;
        if runtime_object.reference.length.get() != runtime_object.bytes.len() as u64 {
            return Err(refused(
                "complete dependency original Runtime7 length differs",
            ));
        }
        let sources = &self.authority.roster().sources;
        let [first, second, third] = sources;
        // Each query requires an existing private plan prepared by that SAME
        // Source from its real Core scope and this exact runtime fullref.
        // There is no zero/default plan for an unsupported source or phase.
        let observed = OriginalDependencyStorageScope {
            runtime: identity,
            sources: [
                first
                    .original_complete_capture_dependency_preflight_data(&runtime_object.reference)
                    .map_err(operation_failure)?
                    .into(),
                second
                    .original_complete_capture_dependency_preflight_data(&runtime_object.reference)
                    .map_err(operation_failure)?
                    .into(),
                third
                    .original_complete_capture_dependency_preflight_data(&runtime_object.reference)
                    .map_err(operation_failure)?
                    .into(),
            ],
            host: self
                .host_capture_dependency_preflight_data(&runtime_object.reference)?
                .into(),
        };
        if observed
            .sources
            .iter()
            .chain(std::iter::once(&observed.host))
            .any(|source| source.count > limits.state.maximum_dependency_edges)
        {
            return Err(refused("complete dependency plan exceeds edge credit"));
        }
        let data = observed.requested_data()?;
        let peak = data.peak()?;
        if peak > limits.state.maximum_total_content_bytes
            || peak > limits.native.maximum_total_record_bytes
        {
            return Err(refused(
                "complete dependency plan exceeds whole capture credit",
            ));
        }
        self.authenticate_live(graph, runtime, scheduling)?;
        let mut original = self.dependency_storage.try_borrow_mut().map_err(error)?;
        retain_narrowed_scope(&mut original, observed)?;
        Ok(data)
    }

    pub(super) fn original_born_dependencies(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        maximum_objects: usize,
    ) -> Result<Option<Vec<ContentRef>>, StateError> {
        self.authenticate_storage_origin()?;
        let maximum_objects = maximum_objects.min(self.limits.state.maximum_dependency_edges);
        let sources = &self.authority.roster().sources;
        let mut lookups = [None; 3];
        // Quote every matching actual producer before allocating a returned
        // row. Equal immutable backend bytes may genuinely be born under more
        // than one original Source; all their dependency rows must agree.
        for (source, lookup) in sources.iter().zip(&mut lookups) {
            *lookup = source
                .original_complete_capture_dependency_lookup_data(reference, maximum_objects)
                .map_err(operation_failure)?;
        }
        let host_lookup = self.host_capture_dependency_lookup_data(reference, maximum_objects)?;
        if host_lookup.is_none() && lookups.iter().all(Option::is_none) {
            return Ok(None);
        }
        let original = self.dependency_storage.try_borrow().map_err(error)?;
        let original = original
            .as_ref()
            .ok_or_else(|| refused("complete born dependencies have no late storage scope"))?;
        for (lookup, bound) in lookups.iter().zip(&original.sources) {
            if let Some(lookup) = lookup {
                let requested = lookup.requested_bytes().map_err(operation_failure)?;
                if requested > bound.lookup || lookup.returned_row_bytes() > bound.returned {
                    return Err(refused(
                        "complete born dependency lookup exceeds original storage",
                    ));
                }
            }
        }
        if let Some(lookup) = &host_lookup {
            let requested = lookup.requested_bytes().map_err(error)?;
            if requested > original.host.lookup
                || lookup.returned_row_bytes() > original.host.returned
            {
                return Err(refused(
                    "complete Host2 dependency lookup exceeds original storage",
                ));
            }
        }
        let mut result = None;
        for ((source, lookup), bound) in sources.iter().zip(lookups).zip(&original.sources) {
            if lookup.is_none() {
                continue;
            }
            // Full supplied-body verification and actual row cloning occur
            // inside this prequoted window. Existing comparison rows fit the
            // separately summed returned-row retention; only one verification
            // window is active. Cold acceptance remains a later mandatory gate.
            let row = source
                .original_complete_capture_dependencies_data(
                    reference,
                    bytes,
                    maximum_objects.min(bound.count),
                    bound.lookup,
                )
                .map_err(operation_failure)?
                .ok_or_else(|| refused("complete original born dependency row disappeared"))?;
            if let Some(original) = result.as_ref() {
                if original != &row {
                    return Err(refused(
                        "complete original producers disagree on dependencies",
                    ));
                }
            } else {
                result = Some(row);
            }
        }
        if host_lookup.is_some() {
            let row = self
                .host_capture_dependencies_data(
                    reference,
                    bytes,
                    maximum_objects.min(original.host.count),
                    original.host.lookup,
                )?
                .ok_or_else(|| refused("complete original Host2 dependency row disappeared"))?;
            if let Some(original) = result.as_ref() {
                if original != &row {
                    return Err(refused(
                        "complete Host2 and native producers disagree on dependencies",
                    ));
                }
            } else {
                result = Some(row);
            }
        }
        self.authenticate_storage_origin()?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These inert reports exercise the caller's arithmetic and association
    // checks; they cannot construct a Source plan or a native Capture ticket.
    fn bound() -> OriginalSourceDependencyBound {
        OriginalSourceDependencyBound {
            born: 11,
            returned: 17,
            lookup: 23,
            count: 5,
        }
    }

    #[test]
    fn runtime_scope_preserves_exact_digest_length_and_fixed_fullref_role() -> Result<(), StateError>
    {
        let original = crucible_node_format::canonical::content_ref(
            b"original-runtime",
            ORIGINAL_LINEAGE_RUNTIME_MEDIA,
        )
        .map_err(error)?;
        let identity = OriginalRuntimeIdentity::from_original(&original)?;
        assert_eq!(identity.length, original.length);
        assert_eq!(identity.digest.as_slice(), original.hash.digest.as_bytes());

        let mut changed = original.clone();
        changed.length = U64::new(original.length.get() + 1);
        assert!(identity != OriginalRuntimeIdentity::from_original(&changed)?);
        changed = original.clone();
        changed.hash.digest.replace_range(
            ..1,
            if original.hash.digest.starts_with('0') {
                "1"
            } else {
                "0"
            },
        );
        assert!(identity != OriginalRuntimeIdentity::from_original(&changed)?);
        changed = original.clone();
        changed.media_type.push_str(";foreign");
        assert!(OriginalRuntimeIdentity::from_original(&changed).is_err());
        changed = original.clone();
        changed.hash.domain.push_str(";foreign");
        assert!(OriginalRuntimeIdentity::from_original(&changed).is_err());
        changed = original;
        changed.hash.algorithm.push_str(";foreign");
        assert!(OriginalRuntimeIdentity::from_original(&changed).is_err());
        Ok(())
    }

    #[test]
    fn dependency_requery_refuses_each_widened_owner_term() -> Result<(), StateError> {
        let admitted = bound();
        admitted.authenticate_narrowing(admitted)?;
        admitted.authenticate_narrowing(OriginalSourceDependencyBound {
            born: 0,
            returned: 0,
            lookup: 0,
            count: 0,
        })?;
        for changed in [
            OriginalSourceDependencyBound {
                born: admitted.born + 1,
                ..admitted
            },
            OriginalSourceDependencyBound {
                returned: admitted.returned + 1,
                ..admitted
            },
            OriginalSourceDependencyBound {
                lookup: admitted.lookup + 1,
                ..admitted
            },
            OriginalSourceDependencyBound {
                count: admitted.count + 1,
                ..admitted
            },
        ] {
            assert!(admitted.authenticate_narrowing(changed).is_err());
        }
        Ok(())
    }

    #[test]
    fn four_owner_storage_sums_all_returned_rows_and_one_lookup_peak() -> Result<(), StateError> {
        let mut scope = OriginalDependencyStorageScope {
            runtime: OriginalRuntimeIdentity {
                length: U64::new(1),
                digest: [b'0'; 64],
            },
            sources: [bound(); 3],
            host: OriginalSourceDependencyBound {
                born: 31,
                returned: 37,
                lookup: 41,
                count: 2,
            },
        };
        let data = scope.requested_data()?;
        assert_eq!(data.source_born_growth_bytes, 3 * 11 + 31);
        assert_eq!(data.returned_row_growth_bytes, 3 * 17 + 37);
        assert_eq!(data.maximum_lookup_scratch_bytes, 41);
        assert_eq!(data.peak()?, 3 * (11 + 17) + 31 + 37 + 41);

        scope.host.lookup = 1;
        assert_eq!(scope.requested_data()?.maximum_lookup_scratch_bytes, 23);
        scope.host.born = usize::MAX;
        assert!(scope.requested_data().is_err());
        Ok(())
    }

    #[test]
    fn successful_requery_replaces_scope_and_failed_widening_keeps_it() -> Result<(), StateError> {
        fn scope(value: usize) -> OriginalDependencyStorageScope {
            let bound = OriginalSourceDependencyBound {
                born: value,
                returned: value,
                lookup: value,
                count: value,
            };
            OriginalDependencyStorageScope {
                runtime: OriginalRuntimeIdentity {
                    length: U64::new(1),
                    digest: [b'0'; 64],
                },
                sources: [bound; 3],
                host: bound,
            }
        }
        let mut original = None;
        retain_narrowed_scope(&mut original, scope(17))?;
        retain_narrowed_scope(&mut original, scope(11))?;
        let actual = original
            .as_ref()
            .ok_or_else(|| refused("test scope absent"))?
            .requested_data()?;
        assert_eq!(actual.source_born_growth_bytes, 4 * 11);
        assert_eq!(actual.returned_row_growth_bytes, 4 * 11);
        assert_eq!(actual.maximum_lookup_scratch_bytes, 11);

        assert!(retain_narrowed_scope(&mut original, scope(12)).is_err());
        let actual = original
            .as_ref()
            .ok_or_else(|| refused("test scope lost"))?
            .requested_data()?;
        assert_eq!(actual.source_born_growth_bytes, 4 * 11);
        assert_eq!(actual.maximum_lookup_scratch_bytes, 11);
        let mut foreign = scope(0);
        foreign.runtime.length = U64::new(2);
        assert!(retain_narrowed_scope(&mut original, foreign).is_err());
        assert_eq!(
            original
                .as_ref()
                .ok_or_else(|| refused("test scope lost"))?
                .runtime
                .length,
            U64::new(1)
        );
        Ok(())
    }
}
