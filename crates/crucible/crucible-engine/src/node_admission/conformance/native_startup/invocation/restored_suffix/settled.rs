//! Admits an independent native17 reserve before any new carrier allocation.
//!
//! The old native/private/Host/suffix conjunction remains whole. A genuine
//! registered holder lends each actual ticket's import geometry. The new member
//! retains that non-Clone quote before Source construction and can publish only
//! the new wire family. Numeric equality never issues an action or Capture grant.

use super::*;
use crucible_node_transport::reference_packet::service::native_startup::{
    PacketNativeSettledConstructionStorageData, PacketRestoredSettledNativeCarrierData,
    PacketRestoredSettledNativeExistingRowsData, PacketRestoredSettledNativeStorageData,
    authenticate_original_native_settled_final_rows_data,
    original_native_settled_carrier_counter_scratch_data,
    original_native_settled_construction_storage_data,
    original_restored_settled_native_storage_counter_scratch_data,
};

struct SettledRows {
    storage: PacketRestoredSettledNativeStorageData,
    construction: PacketNativeSettledConstructionStorageData,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct QuoteIdentity {
    carrier: PacketRestoredSettledNativeCarrierData,
    retained: usize,
    transient: usize,
    scratch: usize,
}

impl QuoteIdentity {
    fn from_quote(row: &PacketRestoredSettledNativeStorageData) -> Self {
        Self {
            carrier: *row.carrier_data(),
            retained: row.retained_requested_bytes_data(),
            transient: row.transient_requested_bytes_data(),
            scratch: row.counter_scratch_bytes_data(),
        }
    }
}

/// Retains the admitted original conjunction and independent three native17 rows.
#[must_use = "retain the genuine admission and all failed Source members through cleanup"]
pub struct CompleteOriginalRestoredSettledStartupAdmission<'a> {
    original: CompleteOriginalRestoredSuffixStartupAdmission<'a>,
    rows: [Option<SettledRows>; 3],
    existing_rows: [PacketRestoredSettledNativeExistingRowsData; 3],
    identities: [QuoteIdentity; 3],
    requested_peak: usize,
}

pub(crate) struct OriginalRestoredSettledStartupMember {
    rows: SettledRows,
    wire_attempted: Cell<bool>,
    wire_completed: Cell<bool>,
}

impl InstalledConformancePlan {
    /// Names every defining Core/Source/Provider fixed view before the callback.
    ///
    /// # Errors
    /// Refuses checked layout overflow; it observes no live or imported owner.
    pub fn original_restored_settled_startup_counter_scratch_data() -> Result<usize, RuntimeError> {
        let terms = [
            Self::original_restored_suffix_startup_counter_scratch_data()?,
            original_restored_settled_native_storage_counter_scratch_data(),
            original_native_settled_carrier_counter_scratch_data(),
            PacketCompleteSemanticSource::original_restored_settled_startup_counter_scratch_data()?,
            size_of::<CompleteOriginalRestoredSettledStartupAdmission<'static>>(),
            size_of::<OriginalRestoredSettledStartupMember>(),
            size_of::<Option<OriginalRestoredSettledStartupMember>>(),
            size_of::<SettledRows>(),
            size_of::<Option<SettledRows>>(),
            size_of::<[Option<SettledRows>; 3]>(),
            size_of::<QuoteIdentity>(),
            size_of::<[QuoteIdentity; 3]>(),
            size_of::<[PacketRestoredSettledNativeStorageData; 3]>(),
            size_of::<Result<[PacketRestoredSettledNativeStorageData; 3], RuntimeError>>(),
            size_of::<PacketNativeSettledConstructionStorageData>(),
            size_of::<
                Result<
                    PacketNativeSettledConstructionStorageData,
                    crucible_node_transport::ProviderError,
                >,
            >(),
            size_of::<PacketRestoredSettledNativeCarrierData>(),
            size_of::<&PacketRestoredSettledNativeCarrierData>(),
            size_of::<Result<CompleteOriginalRestoredSettledStartupAdmission<'static>, RuntimeError>>(
            ),
            size_of::<Result<OriginalNativeStartupMember, RuntimeError>>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<Result<u64, crucible_node_transport::ProviderError>>(),
            size_of::<Result<usize, RuntimeError>>(),
            size_of::<Result<U64, RuntimeError>>(),
            size_of::<Result<U64, std::num::TryFromIntError>>(),
            size_of::<Result<u64, std::num::TryFromIntError>>(),
            size_of::<Option<usize>>(),
            size_of::<Cell<bool>>(),
            size_of::<&Cell<bool>>(),
            size_of::<std::array::IntoIter<PacketRestoredSettledNativeStorageData, 3>>(),
            size_of::<
                std::iter::Enumerate<
                    std::array::IntoIter<PacketRestoredSettledNativeStorageData, 3>,
                >,
            >(),
            size_of::<(usize, PacketRestoredSettledNativeStorageData)>(),
            size_of::<[usize; 4]>(),
            size_of::<[usize; 8]>(),
            size_of::<std::ops::Range<usize>>(),
            size_of::<&[usize]>(),
            size_of::<std::slice::Iter<'static, usize>>(),
            size_of::<&usize>(),
            size_of::<&mut PacketNativeStartupAllocationRow>(),
            size_of::<&OriginalRestoredSuffixStartupMember>(),
            size_of::<Option<&OriginalRestoredSuffixStartupMember>>(),
            size_of::<Result<&OriginalRestoredSuffixStartupMember, RuntimeError>>(),
            size_of::<Option<&OriginalRestoredSettledStartupMember>>(),
            size_of::<Result<&OriginalRestoredSettledStartupMember, RuntimeError>>(),
            size_of::<&OriginalRestoredSettledStartupMember>(),
            size_of::<&PacketRestoredSettledNativeStorageData>(),
            size_of::<[&PacketRestoredSettledNativeStorageData; 3]>(),
            size_of::<std::array::IntoIter<&PacketRestoredSettledNativeStorageData, 3>>(),
            size_of::<std::slice::Iter<'static, PacketRestoredSettledNativeStorageData>>(),
            size_of::<
                std::iter::Enumerate<
                    std::slice::Iter<'static, PacketRestoredSettledNativeStorageData>,
                >,
            >(),
            size_of::<(usize, &PacketRestoredSettledNativeStorageData)>(),
            size_of::<Option<(usize, &PacketRestoredSettledNativeStorageData)>>(),
            size_of::<Option<&mut Option<SettledRows>>>(),
            size_of::<Result<SettledRows, RuntimeError>>(),
            size_of::<PacketRestoredSettledNativeExistingRowsData>(),
            size_of::<[PacketRestoredSettledNativeExistingRowsData; 3]>(),
            size_of::<&[PacketRestoredSettledNativeExistingRowsData; 3]>(),
            size_of::<&PacketRestoredSettledNativeExistingRowsData>(),
            size_of::<std::ops::Range<usize>>(),
            size_of::<Option<PacketNativeStartupAllocationRow>>(),
        ];
        let headers = std::mem::size_of_val(&terms)
            .checked_add(size_of::<std::slice::Iter<'static, usize>>())
            .ok_or(RuntimeError::ResourceLimit)?;
        add(headers, sum(&terms, usize::MAX)?, usize::MAX)
    }

    /// Independently admits actual imported native17 demand for all three Sources.
    ///
    /// No old row is subtracted or reused. The retained holder's scenario count
    /// is checked by the defining producer and remains one global allowance.
    ///
    /// # Errors
    /// Refuses unselected/foreign holders, changed inputs, repeated members,
    /// unsupported demand or any unchanged complete policy overrun.
    pub fn reserve_original_restored_settled_startup<'a>(
        &'a self,
        sources: &'a [Rc<PacketCompleteSemanticSource>; 3],
        launches: &'a [PacketNative5SourceLaunch; 3],
        canonical: &'a [Vec<u8>; 3],
    ) -> Result<CompleteOriginalRestoredSettledStartupAdmission<'a>, RuntimeError> {
        let mut original =
            self.reserve_original_restored_suffix_startup(sources, launches, canonical)?;
        let fixed = Self::original_restored_settled_startup_counter_scratch_data()?;
        if fixed
            > original
                .original
                .baseline
                .policy
                .declared_observer_scratch_bytes
        {
            return Err(RuntimeError::ResourceLimit);
        }
        for source in sources {
            if !source.is_original_restored_settled_capture_declaration_data()? {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        // Freeze the actual admitted old rows before adding the independent new17
        // axes. The suffix reservation is already a subcomponent of native_birth.
        let existing_rows =
            std::array::from_fn(|index| PacketRestoredSettledNativeExistingRowsData {
                native_birth: original.original.baseline.quotes[index].rows.native_birth,
                restore_prepare: original.original.baseline.quotes[index]
                    .rows
                    .restore_prepare,
                suffix: original.rows[index].reservation.reservation_data(),
            });
        let quoted = self.0.authority.original_restored_settled_startup_data(
            &self.evidence(),
            &original.original.baseline.scope,
            &existing_rows,
        )?;
        let identities = quoted.each_ref().map(QuoteIdentity::from_quote);
        let maximum = original.original.baseline.policy.maximum_requested_bytes;
        let mut requested = original.requested_peak;
        let mut rows = [None, None, None];
        for (index, storage) in quoted.into_iter().enumerate() {
            let reservation = original.rows[index].reservation.reservation_data();
            let construction = original_native_settled_construction_storage_data(
                &original.original.purposes[index],
                &canonical[index],
                &reservation,
                &existing_rows[index],
                storage.carrier_data(),
                maximum,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
            let native_retained = add(
                storage.retained_requested_bytes_data(),
                construction.native_retained_requested_bytes(),
                maximum,
            )?;
            let native_transient = add(
                storage.transient_requested_bytes_data(),
                construction.native_transient_requested_bytes(),
                maximum,
            )?;
            let native_scratch = add(
                storage.counter_scratch_bytes_data(),
                original_native_settled_carrier_counter_scratch_data(),
                maximum,
            )?;
            let quote = &mut original.original.baseline.quotes[index];
            add_settled_row(
                &mut quote.rows.private_bootstrap,
                construction.private_retained_requested_bytes(),
                construction.private_transient_requested_bytes(),
                original_native_settled_carrier_counter_scratch_data(),
                maximum,
            )?;
            add_settled_row(
                &mut quote.rows.native_birth,
                native_retained,
                native_transient,
                native_scratch,
                maximum,
            )?;
            authenticate_original_native_settled_final_rows_data(
                &existing_rows[index],
                &storage,
                &construction,
                &quote.rows.native_birth,
                &quote.rows.restore_prepare,
            )
            .map_err(|_| RuntimeError::ForeignAuthority)?;
            if let Some(overlap) = quote.rows.retained_overlap {
                quote.rows.retained_overlap = Some(
                    overlap
                        .with_additional_retained_requested_bytes_data(
                            construction.private_retained_requested_bytes(),
                            native_retained,
                        )
                        .map_err(|_| RuntimeError::ResourceLimit)?,
                );
            }
            let headers =
                PacketCompleteSemanticSource::original_restored_settled_wire_header_storage_data();
            requested = add(
                requested,
                sum(
                    &[
                        native_retained,
                        native_transient,
                        native_scratch,
                        construction.private_retained_requested_bytes(),
                        construction.private_transient_requested_bytes(),
                        original_native_settled_carrier_counter_scratch_data(),
                        construction.source_finalization_requested_bytes(),
                        headers,
                    ],
                    maximum,
                )?,
                maximum,
            )?;
            quote.finalization_bytes = add(
                quote.finalization_bytes,
                add(
                    construction.source_finalization_requested_bytes(),
                    headers,
                    maximum,
                )?,
                maximum,
            )?;
            quote.wire_requested_bytes = add(
                quote.wire_requested_bytes,
                add(construction.wire_growth_requested_bytes(), headers, maximum)?,
                maximum,
            )?;
            rows[index] = Some(SettledRows {
                storage,
                construction,
            });
        }
        let result = CompleteOriginalRestoredSettledStartupAdmission {
            original,
            rows,
            existing_rows,
            identities,
            requested_peak: requested,
        };
        result.authenticate_current()?;
        Ok(result)
    }
}

fn add_settled_row(
    row: &mut PacketNativeStartupAllocationRow,
    retained: usize,
    transient: usize,
    scratch: usize,
    maximum: usize,
) -> Result<(), RuntimeError> {
    let updated = PacketNativeStartupAllocationRow {
        retained_requested_bytes: quantity(add(
            extent(row.retained_requested_bytes.get())?,
            retained,
            maximum,
        )?)?,
        maximum_simultaneous_transient_bytes: quantity(add(
            extent(row.maximum_simultaneous_transient_bytes.get())?,
            transient,
            maximum,
        )?)?,
        declared_counter_scratch_bytes: quantity(add(
            extent(row.declared_counter_scratch_bytes.get())?,
            scratch,
            maximum,
        )?)?,
    };
    updated
        .requested_peak_data()
        .map_err(|_| RuntimeError::ResourceLimit)?;
    *row = updated;
    Ok(())
}

impl CompleteOriginalRestoredSettledStartupAdmission<'_> {
    /// Returns the complete independently added startup conjunction as DATA.
    pub const fn requested_peak_data(&self) -> usize {
        self.requested_peak
    }

    /// Rechecks the same actual holder, import geometry, launch and complete axes.
    ///
    /// # Errors
    /// Refuses changed actual provenance/rows, even when numeric totals match.
    pub fn authenticate_current(&self) -> Result<(), RuntimeError> {
        self.original.authenticate_current()?;
        let scope = &self.original.original.baseline.scope;
        let actual = scope
            .plan
            .0
            .authority
            .original_restored_settled_startup_data(
                &scope.plan.evidence(),
                scope,
                &self.existing_rows,
            )?;
        for (index, row) in actual.iter().enumerate() {
            if QuoteIdentity::from_quote(row) != self.identities[index]
                || !scope.sources[index].is_original_restored_settled_capture_declaration_data()?
            {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        self.original.original.baseline.origin()
    }

    /// Installs a consumed native17 member before any fallible Source bank work.
    ///
    /// # Errors
    /// Refuses changed/repeated members. Once spent, the Source retains partial
    /// finalization; no failed construction renews reservation or occurrence.
    pub fn finalize_original_source(&mut self, index: usize) -> Result<(), RuntimeError> {
        let phase = self
            .original
            .original
            .baseline
            .begin_host_finalization(index)?;
        self.authenticate_current()?;
        let rows = self
            .rows
            .get_mut(index)
            .and_then(Option::take)
            .ok_or(RuntimeError::DuplicateOperation)?;
        let mut member = self.original.original.take_original_member(index)?;
        let source = &self.original.original.baseline.scope.sources[index];
        member.launch_digest = self.original.original.construction[index]
            .launch_identity_data()
            .raw_digest;
        member.maximum_boot_bytes =
            self.original.original.construction[index].maximum_private_boot_body_bytes();
        member.suffix = Some(OriginalRestoredSuffixStartupMember {
            process: self.original.original.baseline.process,
            thread: self.original.original.baseline.thread,
            source: Rc::downgrade(source),
            plan: self.original.original.baseline.scope.plan.downgrade(),
            rows: self.original.rows[index],
            wire_attempted: Cell::new(false),
            wire_completed: Cell::new(false),
            settled: Some(OriginalRestoredSettledStartupMember {
                rows,
                wire_attempted: Cell::new(false),
                wire_completed: Cell::new(false),
            }),
        });
        source.finalize_original_restored_settled_startup_birth(
            member,
            &self.original.original.baseline.scope.launches[index],
            &self.original.original.purposes[index],
        )?;
        self.authenticate_current()?;
        source.complete_original_native_invocation_birth()?;
        self.authenticate_current()?;
        phase.finish()
    }
}

impl OriginalRestoredSuffixStartupMember {
    pub(crate) fn settled_data(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<Option<&OriginalRestoredSettledStartupMember>, RuntimeError> {
        self.authenticate_source_data(source)?;
        Ok(self.settled.as_ref())
    }
}

impl OriginalRestoredSettledStartupMember {
    pub(crate) fn storage_data(&self) -> &PacketRestoredSettledNativeStorageData {
        &self.rows.storage
    }

    pub(crate) fn existing_rows_data(&self) -> &PacketRestoredSettledNativeExistingRowsData {
        self.rows.storage.existing_rows_data()
    }

    pub(crate) fn carrier_data(&self) -> &PacketRestoredSettledNativeCarrierData {
        self.rows.storage.carrier_data()
    }

    pub(crate) fn launch_identity_data(&self) -> PacketNativeSuffixLaunchIdentityData {
        self.rows.construction.launch_identity_data()
    }

    pub(crate) fn begin_wire_data(&self) -> Result<(), RuntimeError> {
        if self.wire_attempted.replace(true) {
            return Err(RuntimeError::DuplicateOperation);
        }
        Ok(())
    }

    pub(crate) fn authenticate_wire_in_progress_data(&self) -> Result<(), RuntimeError> {
        if !self.wire_attempted.get() || self.wire_completed.get() {
            return Err(RuntimeError::DuplicateOperation);
        }
        Ok(())
    }

    pub(crate) fn complete_wire_data(&self) -> Result<(), RuntimeError> {
        self.authenticate_wire_in_progress_data()?;
        self.wire_completed.set(true);
        Ok(())
    }

    pub(crate) fn authenticate_completed_wire_data(&self) -> Result<(), RuntimeError> {
        if !self.wire_attempted.get() || !self.wire_completed.get() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        Ok(())
    }
}

struct History17<'a>(&'a OriginalRestoredSettledStartupMember);

impl OriginalRestoredSettledStartupMember {
    // Only the enclosing same-Source suffix origin check lends this inert view.
    pub(super) fn borrowed_history17_data(&self) -> impl serde::Serialize + '_ {
        History17(self)
    }

    pub(super) fn history17_counter_scratch_data() -> usize {
        size_of::<History17<'static>>()
            + size_of::<&Self>()
            + size_of::<&SettledRows>()
            + size_of::<&PacketRestoredSettledNativeStorageData>()
            + PacketNativeSettledConstructionStorageData::settled17_history_counter_scratch_data()
            + size_of::<(bool, bool)>() * 2
            + size_of::<usize>()
    }
}

impl serde::Serialize for History17<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeStruct};
        let OriginalRestoredSettledStartupMember {
            rows,
            wire_attempted,
            wire_completed,
        } = self.0;
        let SettledRows {
            storage,
            construction,
        } = rows;
        let observed = (wire_attempted.get(), wire_completed.get());
        let mut state = serializer.serialize_struct("HistoricalSettledStartupMember17", 4)?;
        state.serialize_field("storage", storage)?;
        state.serialize_field(
            "construction",
            &construction.borrowed_settled17_history_data(),
        )?;
        state.serialize_field("wire_attempted", &observed.0)?;
        state.serialize_field("wire_completed", &observed.1)?;
        let result = state.end()?;
        if observed != (wire_attempted.get(), wire_completed.get()) {
            return Err(S::Error::custom(RuntimeError::ForeignAuthority));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_new_axis_never_partially_replaces_an_original_row() {
        let original = PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(11),
            maximum_simultaneous_transient_bytes: U64::new(17),
            declared_counter_scratch_bytes: U64::new(23),
        };
        for (retained, transient, scratch, maximum) in [
            (31, 0, 0, 41),
            (0, 41, 0, 57),
            (0, 0, 43, 65),
            (usize::MAX, 0, 0, usize::MAX),
        ] {
            let mut actual = original;
            assert!(add_settled_row(&mut actual, retained, transient, scratch, maximum).is_err());
            assert_eq!(actual, original);
        }
    }
}

impl OriginalRestoredSettledStartupMember {
    /// Checks the defining inline SDK quote without borrowing a native owner.
    ///
    /// # Errors
    /// Refuses a changed SDK quote that would require out-of-line capacity rows.
    pub(super) fn record_retained_capacity_data(
        &self,
        census: &mut crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            rows,
            wire_attempted,
            wire_completed,
        } = self;
        let SettledRows {
            storage,
            construction,
        } = rows;

        fn fixed_cell<T: Copy>(_: &Cell<T>) {}

        fixed_cell(wire_attempted);
        fixed_cell(wire_completed);
        census.observe_inline_data(construction);
        if storage.retained_metadata_data() != Default::default() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        Ok(())
    }
}

impl OriginalRestoredSettledStartupMember {
    /// Names actual non-Copy inline quote and default-fact return controls.
    pub(super) fn retained_capacity_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&SettledRows>()
            + size_of::<Option<&Self>>()
            + size_of::<&PacketRestoredSettledNativeStorageData>()
            + size_of::<&PacketNativeSettledConstructionStorageData>()
            + PacketRestoredSettledNativeStorageData::retained_metadata_counter_scratch_data()
            + size_of::<crucible_node_transport::retained_metadata::RetainedProtocolMetadataFacts>()
    }
}
