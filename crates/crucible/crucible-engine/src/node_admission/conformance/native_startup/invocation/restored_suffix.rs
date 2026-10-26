//! Admits a finite restored suffix beneath the genuine registered startup holder.
//!
//! Each ticket-derived row is independently added to the original three-owner
//! startup and Host sum. This owner can prepare the distinct startup carrier;
//! it grants no Endpoint action, input, execution or advanced Capture right.

use super::*;
use crucible_node_format::U64;
use crucible_node_transport::reference_packet::service::native_startup::{
    PacketNativeRestoredSuffixStartupStorageData, PacketNativeSuffixConstructionStorageData,
    PacketNativeSuffixLaunchIdentityData, PacketRestoredSuffixReservationData,
    original_native_restored_suffix_startup_counter_scratch_data,
    original_native_suffix_construction_storage_data, original_native_suffix_counter_scratch_data,
};
use std::cell::Cell;

/// Retains all original startup admissions and their independent suffix rows.
///
/// The registered authority supplies the same tickets and installed scenario
/// allowance. No constructor, cloning or decoding can substitute for that loan.
#[must_use = "retain the startup owner and failed Source members until cleanup"]
pub struct CompleteOriginalRestoredSuffixStartupAdmission<'a> {
    original: CompleteOriginalNativeInvocationAdmission<'a>,
    rows: [OriginalRestoredSuffixStartupRows; 3],
    requested_peak: usize,
}

#[derive(Clone, Copy)]
struct OriginalRestoredSuffixStartupRows {
    reservation: PacketNativeRestoredSuffixStartupStorageData,
    construction: PacketNativeSuffixConstructionStorageData,
}

/// Retains a consumed same-Source reservation through partial carrier writes.
///
/// This nonserializable owner is installed inside the existing native member
/// before Source construction. Its numeric rows issue no live action rights.
pub(crate) struct OriginalRestoredSuffixStartupMember {
    process: u32,
    thread: ThreadId,
    source: std::rc::Weak<PacketCompleteSemanticSource>,
    plan: WeakInstalledConformancePlan,
    rows: OriginalRestoredSuffixStartupRows,
    wire_attempted: Cell<bool>,
    // Host publication only: native receipt and post-Observe proof are separate.
    wire_completed: Cell<bool>,
    settled: Option<settled::OriginalRestoredSettledStartupMember>,
}

impl InstalledConformancePlan {
    /// Names all fixed Core, Source and Provider suffix construction views.
    ///
    /// # Errors
    /// Refuses checked layout overflow before the registered ticket callback.
    pub fn original_restored_suffix_startup_counter_scratch_data() -> Result<usize, RuntimeError> {
        let terms: [usize; 42] = [
            Self::original_native_invocation_counter_scratch_data()?,
            original_native_restored_suffix_startup_counter_scratch_data(),
            original_native_suffix_counter_scratch_data(),
            PacketCompleteSemanticSource::original_restored_suffix_startup_counter_scratch_data()?,
            size_of::<CompleteOriginalRestoredSuffixStartupAdmission<'static>>(),
            size_of::<OriginalRestoredSuffixStartupMember>(),
            size_of::<Cell<bool>>(),
            size_of::<&Cell<bool>>(),
            size_of::<Option<OriginalRestoredSuffixStartupMember>>(),
            size_of::<[OriginalRestoredSuffixStartupRows; 3]>(),
            size_of::<[Option<OriginalRestoredSuffixStartupRows>; 3]>(),
            3 * size_of::<Option<OriginalRestoredSuffixStartupRows>>(),
            2 * size_of::<[PacketNativeRestoredSuffixStartupStorageData; 3]>(),
            size_of::<Result<[PacketNativeRestoredSuffixStartupStorageData; 3], RuntimeError>>(),
            size_of::<PacketNativeSuffixConstructionStorageData>(),
            size_of::<
                Result<
                    PacketNativeSuffixConstructionStorageData,
                    crucible_node_transport::ProviderError,
                >,
            >(),
            size_of::<PacketRestoredSuffixReservationData>(),
            size_of::<Result<u64, crucible_node_transport::ProviderError>>(),
            size_of::<Result<(), crucible_node_transport::ProviderError>>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<Result<usize, RuntimeError>>(),
            size_of::<&mut PacketNativeStartupAllocationRow>(),
            size_of::<[usize; 7]>(),
            size_of::<[usize; 42]>(),
            size_of::<std::array::IntoIter<usize, 42>>(),
            size_of::<std::ops::Range<usize>>(),
            size_of::<usize>(),
            size_of::<Option<usize>>(),
            size_of::<Result<CompleteOriginalRestoredSuffixStartupAdmission<'static>, RuntimeError>>(
            ),
            size_of::<OriginalRestoredSuffixStartupRows>(),
            size_of::<(
                Option<OriginalRestoredSuffixStartupRows>,
                Option<OriginalRestoredSuffixStartupRows>,
                Option<OriginalRestoredSuffixStartupRows>,
            )>(),
            size_of::<&[usize]>(),
            size_of::<std::slice::Iter<'static, usize>>(),
            size_of::<&usize>(),
            size_of::<Result<U64, RuntimeError>>(),
            size_of::<Result<U64, std::num::TryFromIntError>>(),
            size_of::<Result<u64, std::num::TryFromIntError>>(),
            size_of::<PacketNativeStartupAllocationRow>(),
            size_of::<std::slice::Iter<'static, Rc<PacketCompleteSemanticSource>>>(),
            size_of::<&Rc<PacketCompleteSemanticSource>>(),
            size_of::<OriginalNativeStartupMember>(),
            size_of::<Result<OriginalNativeStartupMember, RuntimeError>>(),
        ];
        sum(&terms, usize::MAX)
    }

    /// Admits the actual finite scenario suffix before any carrier serialization.
    ///
    /// Existing native, private, Host, policy and three-owner terms remain in
    /// full. Each new ingress/action row and carrier phase is added separately.
    /// Future actual actions must still debit their independent current demand
    /// and obey the single global scenario allowance; this reserves no action.
    ///
    /// # Errors
    /// Refuses missing declarations or ticket geometry, a foreign registered
    /// holder, changed launch/row/currentness, or any complete policy overrun.
    pub fn reserve_original_restored_suffix_startup<'a>(
        &'a self,
        sources: &'a [Rc<PacketCompleteSemanticSource>; 3],
        launches: &'a [PacketNative5SourceLaunch; 3],
        canonical_launches: &'a [Vec<u8>; 3],
    ) -> Result<CompleteOriginalRestoredSuffixStartupAdmission<'a>, RuntimeError> {
        let mut original =
            self.reserve_original_native_invocation(sources, launches, canonical_launches)?;
        let fixed = Self::original_restored_suffix_startup_counter_scratch_data()?;
        let baseline = &mut original.baseline;
        if fixed > baseline.policy.declared_observer_scratch_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        for source in sources {
            if !source.is_original_restored_suffix_declaration_data()? {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        let quoted = self
            .0
            .authority
            .original_restored_suffix_startup_data(&self.evidence(), &baseline.scope)?;
        let maximum = baseline.policy.maximum_requested_bytes;
        let mut requested = original.requested_peak;
        let mut rows = [None, None, None];
        for index in 0..3 {
            if original.purposes[index].is_original_execution_data() {
                return Err(RuntimeError::ForeignAuthority);
            }
            let reservation = quoted[index].reservation_data();
            let construction = original_native_suffix_construction_storage_data(
                &original.purposes[index],
                &canonical_launches[index],
                &reservation,
                maximum,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
            let quote = &mut baseline.quotes[index];
            add_carrier_row(
                &mut quote.rows.private_bootstrap,
                construction.private_retained_requested_bytes(),
                construction.private_transient_requested_bytes(),
                maximum,
            )?;
            add_carrier_row(
                &mut quote.rows.native_birth,
                construction.native_retained_requested_bytes(),
                construction.native_transient_requested_bytes(),
                maximum,
            )?;
            if let Some(overlap) = quote.rows.retained_overlap {
                quote.rows.retained_overlap = Some(
                    overlap
                        .with_additional_retained_requested_bytes_data(
                            construction.private_retained_requested_bytes(),
                            construction.native_retained_requested_bytes(),
                        )
                        .map_err(|_| RuntimeError::ResourceLimit)?,
                );
            }
            let source_headers =
                PacketCompleteSemanticSource::original_restored_suffix_wire_header_storage_data();
            let terms = [
                construction.private_retained_requested_bytes(),
                construction.private_transient_requested_bytes(),
                construction.native_retained_requested_bytes(),
                construction.native_transient_requested_bytes(),
                2 * original_native_suffix_counter_scratch_data(),
                construction.source_finalization_requested_bytes(),
                source_headers,
            ];
            requested = add(requested, sum(&terms, maximum)?, maximum)?;
            requested = add(requested, quoted[index].requested_bytes_data(), maximum)?;
            quote.finalization_bytes = add(
                quote.finalization_bytes,
                add(
                    construction.source_finalization_requested_bytes(),
                    source_headers,
                    maximum,
                )?,
                maximum,
            )?;
            quote.wire_requested_bytes = add(
                quote.wire_requested_bytes,
                add(
                    construction.wire_growth_requested_bytes(),
                    source_headers,
                    maximum,
                )?,
                maximum,
            )?;
            rows[index] = Some(OriginalRestoredSuffixStartupRows {
                reservation: quoted[index],
                construction,
            });
        }
        let [a, b, c] = rows;
        let admission = CompleteOriginalRestoredSuffixStartupAdmission {
            original,
            rows: [
                a.ok_or(RuntimeError::OwnerUnavailable)?,
                b.ok_or(RuntimeError::OwnerUnavailable)?,
                c.ok_or(RuntimeError::OwnerUnavailable)?,
            ],
            requested_peak: requested,
        };
        admission.authenticate_current()?;
        Ok(admission)
    }
}

fn add_carrier_row(
    row: &mut PacketNativeStartupAllocationRow,
    retained: usize,
    transient: usize,
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
            original_native_suffix_counter_scratch_data(),
            maximum,
        )?)?,
    };
    updated
        .requested_peak_data()
        .map_err(|_| RuntimeError::ResourceLimit)?;
    *row = updated;
    Ok(())
}

fn quantity(value: usize) -> Result<U64, RuntimeError> {
    u64::try_from(value)
        .map(U64::new)
        .map_err(|_| RuntimeError::ResourceLimit)
}

impl CompleteOriginalRestoredSuffixStartupAdmission<'_> {
    /// Returns the full independently admitted conjunction as DATA.
    pub const fn requested_peak_data(&self) -> usize {
        self.requested_peak
    }

    /// Reauthenticates the same original holder, tickets and exact cached inputs.
    ///
    /// # Errors
    /// Refuses changed scenario, source/launch, cached geometry or live ownership.
    pub fn authenticate_current(&self) -> Result<(), RuntimeError> {
        self.original.authenticate_current()?;
        let scope = &self.original.baseline.scope;
        let actual = scope
            .plan
            .0
            .authority
            .original_restored_suffix_startup_data(&scope.plan.evidence(), scope)?;
        for index in 0..3 {
            if !scope.sources[index].is_original_restored_suffix_declaration_data()? {
                return Err(RuntimeError::ForeignAuthority);
            }
            self.rows[index]
                .reservation
                .authenticate_same_quote_data(&actual[index])
                .map_err(|_| RuntimeError::ForeignAuthority)?;
        }
        self.original.baseline.origin()
    }

    /// Consumes a real member before constructing its distinct startup carrier.
    ///
    /// # Errors
    /// Refuses repeated or changed members. The original admission and Source
    /// retain every spent member and partial allocation after error or unwind.
    pub fn finalize_original_source(&mut self, index: usize) -> Result<(), RuntimeError> {
        let phase = self.original.baseline.begin_host_finalization(index)?;
        self.authenticate_current()?;
        let mut member = self.original.take_original_member(index)?;
        let source = &self.original.baseline.scope.sources[index];
        member.launch_digest = self.original.construction[index]
            .launch_identity_data()
            .raw_digest;
        member.maximum_boot_bytes =
            self.original.construction[index].maximum_private_boot_body_bytes();
        member.suffix = Some(OriginalRestoredSuffixStartupMember {
            process: self.original.baseline.process,
            thread: self.original.baseline.thread,
            source: Rc::downgrade(source),
            plan: self.original.baseline.scope.plan.downgrade(),
            rows: self.rows[index],
            wire_attempted: Cell::new(false),
            wire_completed: Cell::new(false),
            settled: None,
        });
        source.finalize_original_restored_suffix_startup_birth(
            member,
            &self.original.baseline.scope.launches[index],
            &self.original.purposes[index],
        )?;
        self.authenticate_current()?;
        source.complete_original_native_invocation_birth()?;
        self.authenticate_current()?;
        phase.finish()
    }
}

impl OriginalRestoredSuffixStartupMember {
    pub(crate) fn authenticate_source_data(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        if self.process != std::process::id()
            || !std::ptr::eq(self.source.as_ptr(), source)
            || self.plan.0.strong_count() == 0
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        Ok(())
    }

    pub(crate) fn reservation_data(&self) -> PacketRestoredSuffixReservationData {
        self.rows.reservation.reservation_data()
    }

    /// Lends the same immutable cached geometry after actual host publication.
    ///
    /// # Errors
    /// Refuses another Source or an attempted-only/failed startup16 write.
    pub(crate) fn observation_startup_data(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<PacketNativeRestoredSuffixStartupStorageData, RuntimeError> {
        self.authenticate_completed_wire_data(source)?;
        Ok(self.rows.reservation)
    }

    pub(crate) fn launch_identity_data(&self) -> PacketNativeSuffixLaunchIdentityData {
        self.rows.construction.launch_identity_data()
    }

    pub(crate) fn authenticate_wire_in_progress_data(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        self.authenticate_source_data(source)?;
        if self.settled.is_some() || !self.wire_attempted.get() || self.wire_completed.get() {
            return Err(RuntimeError::DuplicateOperation);
        }
        Ok(())
    }

    // Only the Source16 writer calls this after every bank and its final
    // currentness check succeed. It proves host wire publication, not native
    // receipt, cached-input authentication or first-Observe completion.
    pub(crate) fn complete_wire_data(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        self.authenticate_wire_in_progress_data(source)?;
        self.wire_completed.set(true);
        Ok(())
    }

    pub(crate) fn authenticate_completed_wire_data(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        self.authenticate_source_data(source)?;
        if let Some(settled) = &self.settled {
            return settled.authenticate_completed_wire_data();
        }
        if !self.wire_attempted.get() || !self.wire_completed.get() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        Ok(())
    }

    pub(crate) fn begin_wire_data(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        self.authenticate_source_data(source)?;
        if self.settled.is_some() || self.wire_attempted.replace(true) {
            return Err(RuntimeError::DuplicateOperation);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> PacketNativeStartupAllocationRow {
        PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(11),
            maximum_simultaneous_transient_bytes: U64::new(17),
            declared_counter_scratch_bytes: U64::new(23),
        }
    }

    #[test]
    fn actual_carrier_helper_adds_each_independent_axis_without_old_credit() {
        let mut actual = row();
        add_carrier_row(&mut actual, 31, 41, usize::MAX).unwrap();
        assert_eq!(actual.retained_requested_bytes.get(), 42);
        assert_eq!(actual.maximum_simultaneous_transient_bytes.get(), 58);
        assert_eq!(
            actual.declared_counter_scratch_bytes.get(),
            23 + u64::try_from(original_native_suffix_counter_scratch_data()).unwrap()
        );
        assert_eq!(
            actual.requested_peak_data().unwrap(),
            123 + u64::try_from(original_native_suffix_counter_scratch_data()).unwrap()
        );
    }

    #[test]
    fn actual_carrier_helper_refuses_each_short_axis_before_row_replacement() {
        let baseline = row();
        for (retained, transient, maximum) in [
            (31, 41, 41),
            (0, 41, 57),
            (0, 0, original_native_suffix_counter_scratch_data() + 22),
        ] {
            let mut actual = baseline;
            assert!(add_carrier_row(&mut actual, retained, transient, maximum).is_err());
            assert_eq!(actual, baseline);
        }
    }
}

#[path = "restored_suffix/settled17.rs"]
mod settled17;

#[path = "restored_suffix/settled.rs"]
mod settled;

pub use settled::CompleteOriginalRestoredSettledStartupAdmission;
pub(crate) use settled::OriginalRestoredSettledStartupMember;

impl OriginalRestoredSuffixStartupMember {
    /// Records the original restored member's weak owners and nested inline rows.
    ///
    /// # Errors
    /// Refuses unsupported SDK backing, exhausted rows or unavailable physical
    /// backing. Neither spent suffix counts nor settled completion is renewed.
    pub(crate) fn record_retained_capacity_data(
        &self,
        census: &mut crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            process,
            thread,
            source,
            plan,
            rows,
            wire_attempted,
            wire_completed,
            settled,
        } = self;
        let OriginalRestoredSuffixStartupRows {
            reservation,
            construction,
        } = rows;

        fn fixed_cell<T: Copy>(_: &Cell<T>) {}

        census.observe_inline_data(process);
        census.observe_inline_data(thread);
        census.observe_inline_data(reservation);
        census.observe_inline_data(construction);
        fixed_cell(wire_attempted);
        fixed_cell(wire_completed);
        plan.record_retained_capacity_data(census)?;
        census.observe_weak_allocation_data(source)?;
        if let Some(settled) = settled {
            settled.record_retained_capacity_data(census)?;
        }
        Ok(())
    }
}

impl OriginalRestoredSuffixStartupMember {
    /// Names actual optional suffix/settled row and fixed-cell borrowed views.
    pub(crate) fn retained_capacity_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&OriginalRestoredSuffixStartupRows>()
            + size_of::<Option<&Self>>()
            + size_of::<&Cell<bool>>()
            + size_of::<&PacketNativeRestoredSuffixStartupStorageData>()
            + size_of::<&PacketNativeSuffixConstructionStorageData>()
            + settled::OriginalRestoredSettledStartupMember::retained_capacity_counter_scratch_data(
            )
    }
}
