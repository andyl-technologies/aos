//! Derives invocation provenance through the same registered pre-Child holder.
//!
//! The public purpose projection is DATA. This nonconstructible Core owner is
//! issued only after the installed startup policy, complete retained roster and
//! actual authority callback agree. It cannot expose or replace its baseline
//! admission, and cannot itself launch a Child or perform native work.

use super::*;
use crucible_node_provider::reference_packet::service::native_startup::{
    PacketNativeInvocationConstructionStorageData, PacketNativeInvocationPurposeData,
    original_native_invocation_construction_storage_data,
    original_native_invocation_counter_scratch_data,
    original_native_invocation_ingress_storage_data,
};

/// Retains the same admitted roster and its source-derived invocation identities.
///
/// No constructor, Clone, decoder or caller-selected purpose exists. The
/// registered authority derives each identity from its real private holder.
#[must_use = "retain the invocation and its original baseline admission on refusal"]
pub struct CompleteOriginalNativeInvocationAdmission<'a> {
    baseline: CompleteOriginalNativeStartupAdmission<'a>,
    purposes: [PacketNativeInvocationPurposeData; 3],
    construction: [PacketNativeInvocationConstructionStorageData; 3],
    requested_peak: usize,
}

impl InstalledConformancePlan {
    /// Names fixed Core and provider views before the purpose callback.
    ///
    /// # Errors
    /// Refuses checked layout arithmetic overflow.
    pub fn original_native_invocation_counter_scratch_data() -> Result<usize, RuntimeError> {
        sum(
            &[
                Self::original_native_startup_counter_scratch_data()?,
                size_of::<CompleteOriginalNativeInvocationAdmission<'_>>(),
                4 * size_of::<[PacketNativeInvocationPurposeData; 3]>(),
                // Pending rows, their destructured Options and the converted
                // result array can coexist with the final admission header.
                size_of::<[Option<PacketNativeInvocationConstructionStorageData>; 3]>(),
                3 * size_of::<Option<PacketNativeInvocationConstructionStorageData>>(),
                size_of::<[PacketNativeInvocationConstructionStorageData; 3]>(),
                size_of::<Result<
                    PacketNativeInvocationConstructionStorageData,
                    crucible_node_provider::ProviderError,
                >>(),
                size_of::<Result<PacketNativeInvocationConstructionStorageData, RuntimeError>>(),
                size_of::<Result<Option<PacketNativeStartupAllocationRow>, RuntimeError>>(),
                size_of::<Result<u64, std::num::TryFromIntError>>(),
                original_native_invocation_counter_scratch_data(),
                PacketCompleteSemanticSource::original_native_invocation_source_counter_scratch_data()?,
            ],
            usize::MAX,
        )
    }

    /// Derives native invocation identities beneath the same installed startup action.
    ///
    /// The caller supplies only original owner arrays. The registered holder,
    /// rather than an enum, selects original execution or a ticketed restoration
    /// target. This action does not finalize new private wire bodies or admit
    /// Query, Prepare, restoration installation, Capture or activation.
    ///
    /// # Errors
    /// Refuses unsupported authority, expired/repeated owners, missing fixed
    /// credit, foreign ticket/source/target or any additional aggregate overrun.
    pub fn reserve_original_native_invocation<'a>(
        &'a self,
        sources: &'a [Rc<PacketCompleteSemanticSource>; 3],
        launches: &'a [PacketNative5SourceLaunch; 3],
        encoded_launches: &'a [Vec<u8>; 3],
    ) -> Result<CompleteOriginalNativeInvocationAdmission<'a>, RuntimeError> {
        let baseline = self.reserve_original_native_startup(sources, launches, encoded_launches)?;
        let fixed = Self::original_native_invocation_counter_scratch_data()?;
        if fixed > baseline.policy.declared_observer_scratch_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        // The callback copies only bounded inline DATA. Every archive, ticket,
        // Source and target owner remains retained in the registered holder.
        let purposes = self
            .0
            .authority
            .original_native_invocation_data(&self.evidence(), &baseline.scope)?;
        for (purpose, launch) in purposes.iter().zip(launches) {
            purpose
                .authenticate_target_data(launch)
                .map_err(|_| RuntimeError::ForeignAuthority)?;
        }
        // The actual baseline remains charged; every new private/native/Source
        // owner is admitted independently before an invocation member is spent.
        let mut baseline = baseline;
        let mut requested_peak = baseline.requested_peak;
        let mut construction = [None, None, None];
        for index in 0..3 {
            let data = original_native_invocation_construction_storage_data(
                &purposes[index],
                &encoded_launches[index],
                baseline.quotes[index].maximum_boot_bytes,
                baseline.policy.maximum_requested_bytes,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
            let add_row = |row: &mut PacketNativeStartupAllocationRow,
                           retained: usize,
                           transient: usize|
             -> Result<(), RuntimeError> {
                let value = |n| {
                    u64::try_from(n)
                        .map(crucible_node_contract::U64::new)
                        .map_err(|_| RuntimeError::ResourceLimit)
                };
                row.retained_requested_bytes = value(add(
                    extent(row.retained_requested_bytes.get())?,
                    retained,
                    baseline.policy.maximum_requested_bytes,
                )?)?;
                row.maximum_simultaneous_transient_bytes = value(add(
                    extent(row.maximum_simultaneous_transient_bytes.get())?,
                    transient,
                    baseline.policy.maximum_requested_bytes,
                )?)?;
                row.declared_counter_scratch_bytes = value(add(
                    extent(row.declared_counter_scratch_bytes.get())?,
                    original_native_invocation_counter_scratch_data(),
                    baseline.policy.maximum_requested_bytes,
                )?)?;
                Ok(())
            };
            let before = baseline.quotes[index]
                .native_and_publication_peak(baseline.policy.maximum_requested_bytes)?;
            // This independent future owner exists only for a genuine fresh
            // purpose derived above by this same registered-holder callback.
            // It is admitted before any member/source finalization or Child.
            let ingress = original_native_invocation_ingress_storage_data(
                &launches[index],
                &purposes[index],
                baseline.policy.maximum_requested_bytes,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
            let ingress_retained = if let Some(ingress) = ingress {
                let row = &mut baseline.quotes[index].rows.native_birth;
                row.retained_requested_bytes = crucible_node_contract::U64::new(
                    u64::try_from(add(
                        extent(row.retained_requested_bytes.get())?,
                        extent(ingress.retained_requested_bytes.get())?,
                        baseline.policy.maximum_requested_bytes,
                    )?)
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                );
                row.maximum_simultaneous_transient_bytes = crucible_node_contract::U64::new(
                    row.maximum_simultaneous_transient_bytes
                        .get()
                        .max(ingress.maximum_simultaneous_transient_bytes.get()),
                );
                row.declared_counter_scratch_bytes = crucible_node_contract::U64::new(
                    row.declared_counter_scratch_bytes
                        .get()
                        .max(ingress.declared_counter_scratch_bytes.get()),
                );
                extent(ingress.retained_requested_bytes.get())?
            } else {
                0
            };
            add_row(
                &mut baseline.quotes[index].rows.private_bootstrap,
                data.private_retained_requested_bytes(),
                data.private_transient_requested_bytes(),
            )?;
            add_row(
                &mut baseline.quotes[index].rows.native_birth,
                data.native_retained_requested_bytes(),
                data.native_transient_requested_bytes(),
            )?;
            if let Some(row) = baseline.quotes[index].rows.restore_prepare.as_mut() {
                let counter = crucible_node_provider::reference_packet::service::PacketNativePrepareStartupStorageData::original_invocation_counter_scratch_data();
                row.declared_counter_scratch_bytes = crucible_node_contract::U64::new(
                    u64::try_from(counter)
                        .map_err(|_| RuntimeError::ResourceLimit)?
                        .max(row.declared_counter_scratch_bytes.get()),
                );
            }
            if let Some(overlap) = baseline.quotes[index].rows.retained_overlap {
                baseline.quotes[index].rows.retained_overlap = Some(
                    overlap
                        .with_additional_retained_requested_bytes_data(
                            data.private_retained_requested_bytes(),
                            add(
                                data.native_retained_requested_bytes(),
                                ingress_retained,
                                baseline.policy.maximum_requested_bytes,
                            )?,
                        )
                        .map_err(|_| RuntimeError::ResourceLimit)?,
                );
            }
            let after = baseline.quotes[index]
                .native_and_publication_peak(baseline.policy.maximum_requested_bytes)?;
            requested_peak = add(
                requested_peak,
                after
                    .checked_sub(before)
                    .ok_or(RuntimeError::ResourceLimit)?,
                baseline.policy.maximum_requested_bytes,
            )?;
            requested_peak = add(
                requested_peak,
                data.source_finalization_requested_bytes(),
                baseline.policy.maximum_requested_bytes,
            )?;
            baseline.quotes[index].finalization_bytes = add(
                baseline.quotes[index].finalization_bytes,
                data.source_finalization_requested_bytes(),
                baseline.policy.maximum_requested_bytes,
            )?;
            baseline.quotes[index].wire_requested_bytes = add(
                baseline.quotes[index].wire_requested_bytes,
                data.wire_growth_requested_bytes(),
                baseline.policy.maximum_requested_bytes,
            )?;
            construction[index] = Some(data);
        }
        let [a, b, c] = construction;
        let admitted = CompleteOriginalNativeInvocationAdmission {
            baseline,
            purposes,
            construction: [
                a.ok_or(RuntimeError::OwnerUnavailable)?,
                b.ok_or(RuntimeError::OwnerUnavailable)?,
                c.ok_or(RuntimeError::OwnerUnavailable)?,
            ],
            requested_peak,
        };
        admitted.authenticate_current()?;
        Ok(admitted)
    }
}

impl CompleteOriginalNativeInvocationAdmission<'_> {
    /// Reports the admitted requested-storage conjunction as DATA.
    pub const fn requested_peak_data(&self) -> usize {
        self.requested_peak
    }

    /// Rechecks the same registered holder and all original invocation fields.
    ///
    /// # Errors
    /// Refuses changed policy, source/target/ticket identity or original currency.
    pub fn authenticate_current(&self) -> Result<(), RuntimeError> {
        self.baseline.recheck()?;
        let actual = self
            .baseline
            .scope
            .plan
            .0
            .authority
            .original_native_invocation_data(
                &self.baseline.scope.plan.evidence(),
                &self.baseline.scope,
            )?;
        if actual != self.purposes {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.baseline.origin()
    }
}

impl CompleteOriginalNativeInvocationAdmission<'_> {
    /// Spends one real member before Source writes its invocation-bound private birth.
    ///
    /// # Errors
    /// Refuses repeated/foreign members, changed purpose/target, additional
    /// resource demand or failed Source construction. The same member and partial
    /// Source owners stay retained after the first fallible allocating phase.
    pub fn finalize_original_source(&mut self, index: usize) -> Result<(), RuntimeError> {
        let phase = self.baseline.begin_host_finalization(index)?;
        self.authenticate_current()?;
        let mut member = self.take_original_member(index)?;
        let source = &self.baseline.scope.sources[index];
        let identity = self.construction[index].launch_identity_data();
        member.launch_digest = identity.raw_digest;
        member.maximum_boot_bytes = self.construction[index].maximum_private_boot_body_bytes();
        source.finalize_original_native_invocation_birth(
            member,
            &self.baseline.scope.launches[index],
            &self.purposes[index],
        )?;
        self.authenticate_current()?;
        source.complete_original_native_invocation_birth()?;
        self.authenticate_current()?;
        phase.finish()
    }

    fn take_original_member(
        &mut self,
        index: usize,
    ) -> Result<OriginalNativeStartupMember, RuntimeError> {
        self.baseline.origin()?;
        if index >= 3 || self.baseline.spent[index] {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.baseline.recheck()?;
        let source = &self.baseline.scope.sources[index];
        let quote = &self.baseline.quotes[index];
        let actual = source.original_native_startup_quote_data(
            &self.baseline.scope.launches[index],
            &self.baseline.scope.encoded_launches[index],
            self.baseline.policy.maximum_requested_bytes,
        )?;
        for (allowed, observed) in [
            (
                Some(quote.rows.private_bootstrap),
                Some(actual.rows.private_bootstrap),
            ),
            (
                Some(quote.rows.native_birth),
                Some(actual.rows.native_birth),
            ),
            (quote.rows.restore_prepare, actual.rows.restore_prepare),
        ] {
            match (allowed, observed) {
                (Some(allowed), Some(observed)) => allowed
                    .authenticate_actual_data(&observed)
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                (None, None) => {}
                _ => return Err(RuntimeError::ForeignAuthority),
            }
        }
        quote.authenticate_publication_data(&actual)?;
        if actual.launch_digest != quote.launch_digest
            || actual.maximum_boot_bytes > quote.maximum_boot_bytes
            || actual.finalization_bytes > quote.finalization_bytes
            || actual.wire_requested_bytes > quote.wire_requested_bytes
            || actual.publication_bytes > quote.publication_bytes
            || actual.source_capture_backend_bytes != quote.source_capture_backend_bytes
            || actual.source_capture_execution_bytes > quote.source_capture_execution_bytes
            || actual.source_capture_execution_scratch > quote.source_capture_execution_scratch
        {
            return Err(RuntimeError::ResourceLimit);
        }
        // The same actual baseline occurrence is consumed before its member is
        // moved to Source. No public numeric/purpose DATA can reach this constructor.
        self.baseline.spent[index] = true;
        Ok(OriginalNativeStartupMember {
            host_finalization: Rc::clone(
                self.baseline
                    .host_finalization
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
            ),
            host_finalization_index: index,
            edition: NativeStartupMemberEdition::Invocation15,
            process: self.baseline.process,
            thread: self.baseline.thread,
            source: Rc::downgrade(source),
            plan: self.baseline.scope.plan.downgrade(),
            rows: quote.rows,
            suffix: None,
            finalization_bytes: quote.finalization_bytes,
            source_capture_backend_bytes: quote.source_capture_backend_bytes,
            source_capture_execution_bytes: quote.source_capture_execution_bytes,
            source_capture_execution_scratch: quote.source_capture_execution_scratch,
            wire_requested_bytes: quote.wire_requested_bytes,
            host_launch_requested_bytes: self
                .baseline
                .storage
                .prospective_host_launch_requested_bytes[index],
            launch_digest: quote.launch_digest,
            maximum_boot_bytes: quote.maximum_boot_bytes,
        })
    }
}

impl OriginalNativeStartupMember {
    // This local identity comparison invokes no authority callback while the
    // caller holds the actual Source birth loan. The encompassing installed
    // window separately authenticates runtime/activation/current kernel state.
    pub(crate) fn authenticate_original_invocation_target_plan_data(
        &self,
        source: &PacketCompleteSemanticSource,
        plan: &InstalledConformancePlan,
    ) -> Result<(), RuntimeError> {
        self.authenticate_original_invocation_source_identity_data(source)?;
        if self.plan.0.as_ptr() != Rc::as_ptr(&plan.0) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

impl OriginalNativeStartupMember {
    pub(crate) fn authenticate_original_invocation_source_identity_data(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        if !std::ptr::eq(self.source.as_ptr(), source) || self.plan.0.strong_count() == 0 {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

#[path = "invocation/restored_suffix.rs"]
mod restored_suffix;

pub use restored_suffix::CompleteOriginalRestoredSuffixStartupAdmission;
pub(crate) use restored_suffix::OriginalRestoredSuffixStartupMember;

pub use restored_suffix::CompleteOriginalRestoredSettledStartupAdmission;
pub(crate) use restored_suffix::OriginalRestoredSettledStartupMember;
