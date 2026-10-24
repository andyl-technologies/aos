//! Admits the same original native baseline before private parsing or Child birth.
//!
//! The installed resource action observes its actual holder and fixed Source
//! roster, then admits separately compiled private-bootstrap, native-birth and
//! optional pre-MAC Prepare phases. Report and HOST query actions remain separate.
//! No row, serialized body or numeric limit can construct a member.

use std::{
    mem::size_of,
    rc::{Rc, Weak},
    thread::ThreadId,
};

use crucible_node_transport::reference_packet::service::{
    PacketNative5SourceLaunch, native_startup::PacketNativeStartupAllocationRow,
};

use super::{InstalledConformancePlan, WeakInstalledConformancePlan};
use crate::{node_adapters::cnp::PacketCompleteSemanticSource, node_contract::RuntimeError};
use crucible_node_transport::reference_packet::service::report_startup::PacketNativeReportStartupAllocationRow;

mod host_finalization;
pub(crate) use host_finalization::{
    OriginalHostFinalizationBarrier, OriginalHostFinalizationSource,
};

/// Borrows the actual original policy roster and both retained launch views.
///
/// Core constructs this scope. The policy compares each reference against its
/// registered holder; byte equality cannot replace the original association.
pub struct OriginalNativeStartupScope<'a> {
    plan: &'a InstalledConformancePlan,
    sources: &'a [Rc<PacketCompleteSemanticSource>; 3],
    launches: &'a [PacketNative5SourceLaunch; 3],
    encoded_launches: &'a [Vec<u8>; 3],
}

impl OriginalNativeStartupScope<'_> {
    /// Borrows the same actual installed plan.
    pub fn plan(&self) -> &InstalledConformancePlan {
        self.plan
    }

    /// Borrows the fixed actual producer, relay and sink Sources.
    pub fn sources(&self) -> &[Rc<PacketCompleteSemanticSource>; 3] {
        self.sources
    }

    /// Borrows their typed launches without constructing or serializing a DTO.
    pub fn launches(&self) -> &[PacketNative5SourceLaunch; 3] {
        self.launches
    }

    /// Borrows the independent encodings retained from the same installation.
    pub fn encoded_launches(&self) -> &[Vec<u8>; 3] {
        self.encoded_launches
    }

    /// Compares the exact plan allocation without a live callback.
    pub fn is_original_plan(&self, plan: &InstalledConformancePlan) -> bool {
        Rc::ptr_eq(&self.plan.0, &plan.0)
    }

    /// Compares the retained policy object without reauthentication work.
    pub fn is_original_authority(
        &self,
        authority: &dyn super::ConformanceAdmissionAuthority,
    ) -> bool {
        self.plan.has_authority(authority)
    }
}

/// Carries the installed baseline resource action and its observer allowance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalNativeStartupPolicy {
    /// Bounds the complete actual holder, Sources and all new native owners.
    pub maximum_requested_bytes: usize,
    /// Precredits actual concrete holder and source/compiled-producer observers.
    pub declared_observer_scratch_bytes: usize,
}

/// Separates actual registered host owners from the independently observed Sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalNativeStartupStorage {
    /// Counts all actual holder, code, policy, plan, Host and receiver roots.
    pub retained_holder_bytes: usize,
    /// Bounds its entire simultaneous additional observation/construction phase.
    pub maximum_simultaneous_transient_bytes: usize,
    /// Precharges each original launch's full retained, transient and scratch row.
    pub prospective_host_launch_requested_bytes: [usize; 3],
}

/// Borrows the same private member's policy and Source without a live callback.
pub struct OriginalNativeStartupMemberScope<'a> {
    plan: &'a InstalledConformancePlan,
    source: &'a PacketCompleteSemanticSource,
}

impl OriginalNativeStartupMemberScope<'_> {
    /// Borrows the actual installed plan.
    pub fn plan(&self) -> &InstalledConformancePlan {
        self.plan
    }

    /// Borrows the original Source allocation.
    pub fn source(&self) -> &PacketCompleteSemanticSource {
        self.source
    }

    /// Compares the exact plan without renewing it.
    pub fn is_original_plan(&self, plan: &InstalledConformancePlan) -> bool {
        Rc::ptr_eq(&self.plan.0, &plan.0)
    }

    /// Compares the actual authority before its raw same-holder callback.
    pub fn is_original_authority(
        &self,
        authority: &dyn super::ConformanceAdmissionAuthority,
    ) -> bool {
        self.plan.has_authority(authority)
    }
}

// This fixed primitive projection owns no schema String or body before credit.
// The actual Binding14 allocation object is constructed only after consumption.
#[derive(Clone, Copy)]
pub(crate) struct NativeStartupRows {
    pub(crate) private_bootstrap: PacketNativeStartupAllocationRow,
    pub(crate) native_birth: PacketNativeStartupAllocationRow,
    pub(crate) restore_prepare: Option<PacketNativeStartupAllocationRow>,
    // Non-wire same-input intersection; absent facts retain the full sum.
    pub(crate) retained_overlap: Option<crucible_node_transport::reference_packet::service::native_startup::PacketNativeBirthRetainedOverlapData>,
    // Same-source selected preflight producer only; original broad report
    // admission remains retained and independently authenticated in Source.
    pub(crate) initial_report_rows: Option<super::report_startup::StartupRows>,
}

impl NativeStartupRows {
    // Bootstrap returns before Endpoint dispatch. Admit, Prepare and report
    // publication are separate synchronous calls on that same Endpoint; their
    // temporary banks end before the next phase. Every lasting or failed owner
    // remains in retained. Independent Sources still have separately summed peaks.
    fn peak_with_publication(
        self,
        publication: super::report_startup::StartupRows,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let native_retained = match self.retained_overlap {
            Some(overlap) => overlap
                .additional_native_retained_requested_bytes_data(
                    extent(self.private_bootstrap.retained_requested_bytes.get())?,
                    extent(self.native_birth.retained_requested_bytes.get())?,
                )
                .map_err(|_| RuntimeError::ForeignAuthority)?,
            None => extent(self.native_birth.retained_requested_bytes.get())?,
        };
        self.peak_with_native_retained(publication, native_retained, maximum)
    }

    // SDK admission retains the original full native R sum: its existing
    // outstanding commitment did not use the native intersection proof. Only
    // sequential native/report temporary phases are shared, exactly as at the
    // native admission boundary. SDK/Hello work remains independently additive.
    pub(crate) fn outstanding_peak_with_publication(
        self,
        publication: super::report_startup::StartupRows,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.peak_with_native_retained(
            publication,
            extent(self.native_birth.retained_requested_bytes.get())?,
            maximum,
        )
    }

    pub(crate) fn publication_phase_counter_scratch_data() -> usize {
        2 * size_of::<Self>()
            + 2 * size_of::<super::report_startup::StartupRows>()
            + size_of::<[(Option<PacketNativeStartupAllocationRow>, Option<usize>); 3]>()
            + size_of::<
                std::array::IntoIter<(Option<PacketNativeStartupAllocationRow>, Option<usize>), 3>,
            >()
            + size_of::<[Option<PacketNativeReportStartupAllocationRow>; 2]>()
            + size_of::<std::array::IntoIter<Option<PacketNativeReportStartupAllocationRow>, 2>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<usize, crucible_node_transport::ProviderError>>()
            + size_of::<Result<u64, crucible_node_transport::ProviderError>>()
            + size_of::<Result<u64, RuntimeError>>()
            + size_of::<Result<usize, std::num::TryFromIntError>>()
            + size_of::<&PacketNativeStartupAllocationRow>()
            + size_of::<&PacketNativeReportStartupAllocationRow>()
            + size_of::<Option<usize>>()
            + size_of::<usize>()
    }

    fn peak_with_native_retained(
        self,
        publication: super::report_startup::StartupRows,
        native_retained: usize,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let mut retained = 0;
        let mut phase = 0;
        for (row, retained_override) in [
            (Some(self.private_bootstrap), None),
            (Some(self.native_birth), Some(native_retained)),
            (self.restore_prepare, None),
        ] {
            let Some(row) = row else {
                continue;
            };
            row.requested_peak_data()
                .map_err(|_| RuntimeError::ResourceLimit)?;
            retained = add(
                retained,
                retained_override.unwrap_or(extent(row.retained_requested_bytes.get())?),
                maximum,
            )?;
            phase = phase.max(add(
                extent(row.maximum_simultaneous_transient_bytes.get())?,
                extent(row.declared_counter_scratch_bytes.get())?,
                maximum,
            )?);
        }
        for row in [
            publication.original_observe12,
            publication.fresh_completed_admit13,
        ]
        .into_iter()
        .flatten()
        {
            row.requested_peak_data()
                .map_err(|_| RuntimeError::ResourceLimit)?;
            retained = add(retained, extent(row.retained_growth_bytes.get())?, maximum)?;
            phase = phase.max(add(
                extent(row.maximum_simultaneous_transient_bytes.get())?,
                extent(row.declared_counter_scratch_bytes.get())?,
                maximum,
            )?);
        }
        add(retained, phase, maximum)
    }
}

pub(crate) struct OriginalNativeStartupQuote {
    pub(crate) rows: NativeStartupRows,
    pub(crate) finalization_bytes: usize,
    // Source-owned pre-Child output-bank construction is a distinct host term.
    // It is never serialized into the native private/bootstrap/Prepare rows.
    pub(crate) source_capture_backend_bytes: usize,
    pub(crate) source_capture_execution_bytes: usize,
    pub(crate) source_capture_execution_scratch: usize,
    pub(crate) wire_requested_bytes: usize,
    pub(crate) publication_bytes: usize,
    // Keep actual separately authenticated axes; an equal total cannot justify
    // moving transient credit into retained owners at the later recheck.
    pub(crate) publication_rows: super::report_startup::StartupRows,
    pub(crate) launch_digest: [u8; 32],
    pub(crate) maximum_boot_bytes: usize,
}

impl OriginalNativeStartupQuote {
    fn native_and_publication_peak(&self, maximum: usize) -> Result<usize, RuntimeError> {
        self.rows
            .peak_with_publication(self.publication_rows, maximum)
    }

    fn authenticate_publication_data(&self, actual: &Self) -> Result<(), RuntimeError> {
        for (allowed, observed) in [
            (
                self.publication_rows.original_observe12,
                actual.publication_rows.original_observe12,
            ),
            (
                self.publication_rows.fresh_completed_admit13,
                actual.publication_rows.fresh_completed_admit13,
            ),
        ] {
            match (allowed, observed) {
                (Some(allowed), Some(observed)) => allowed
                    .authenticate_actual_data(&observed)
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                (None, None) => {}
                _ => return Err(RuntimeError::ForeignAuthority),
            }
        }
        Ok(())
    }
}

// This is host-only actual-call provenance, never serialized or inferred from
// row magnitudes. Each quote/finalization uses the same admitted producer.
#[derive(Clone, Copy)]
enum NativeStartupQuoteKind {
    Broad,
    Preflight,
}

impl NativeStartupQuoteKind {
    fn quote(
        self,
        source: &Rc<PacketCompleteSemanticSource>,
        launch: &PacketNative5SourceLaunch,
        encoded: &[u8],
        maximum: usize,
    ) -> Result<OriginalNativeStartupQuote, RuntimeError> {
        match self {
            Self::Broad => source.original_native_startup_quote_data(launch, encoded, maximum),
            Self::Preflight => {
                source.original_native_preflight_startup_quote_data(launch, encoded, maximum)
            }
        }
    }
}

/// Retains Core's original once-consumed baseline allocation admission.
///
/// No constructor, Clone or serialization exists. It authorizes only the
/// separately named allocation phases; post-Hello MAC, semantic, activation,
/// Capture and whole restoration rights remain independent.
pub struct CompleteOriginalNativeStartupAdmission<'a> {
    scope: OriginalNativeStartupScope<'a>,
    quote_kind: NativeStartupQuoteKind,
    process: u32,
    thread: ThreadId,
    policy: OriginalNativeStartupPolicy,
    storage: OriginalNativeStartupStorage,
    quotes: [OriginalNativeStartupQuote; 3],
    source_bytes: [usize; 3],
    spent: [bool; 3],
    requested_peak: usize,
    host_finalization: Option<Rc<OriginalHostFinalizationBarrier>>,
}

impl InstalledConformancePlan {
    /// Quotes the actual fixed Core and Source baseline-observation layouts.
    ///
    /// # Errors
    /// Refuses checked layout arithmetic overflow.
    pub fn original_native_startup_counter_scratch_data() -> Result<usize, RuntimeError> {
        let terms: [usize; 29] = [
            size_of::<[usize; 20]>(),
            size_of::<&[usize]>(),
            size_of::<std::slice::Iter<'static, usize>>(),
            size_of::<Result<usize, RuntimeError>>(),
            size_of::<CompleteOriginalNativeStartupAdmission<'_>>(),
            size_of::<NativeStartupQuoteKind>(),
            size_of::<(Option<super::report_startup::StartupRows>, Option<super::report_startup::StartupRows>)>(),
            size_of::<Option<super::report_startup::StartupRows>>(),
            size_of::<std::array::IntoIter<(Option<PacketNativeStartupAllocationRow>, Option<usize>), 3>>(),
            size_of::<[(Option<PacketNativeStartupAllocationRow>, Option<usize>); 3]>(),
            size_of::<Option<usize>>(),
            size_of::<Result<usize, crucible_node_transport::ProviderError>>(),
            size_of::<OriginalNativeStartupScope<'_>>(),
            size_of::<OriginalNativeStartupMemberScope<'_>>(),
            size_of::<[OriginalNativeStartupQuote; 3]>(),
            size_of::<[Option<OriginalNativeStartupQuote>; 3]>(),
            crate::node_adapters::cnp::CnpSemanticLaunchReservation::unlaunched_storage_counter_scratch_data(),
            PacketCompleteSemanticSource::original_native_startup_counter_scratch_data()?,
            OriginalHostFinalizationBarrier::counter_scratch_data(),
            PacketCompleteSemanticSource::original_native_host_barrier_slot_scratch_data(),
            size_of::<[usize; 29]>(),
            size_of::<[Option<PacketNativeReportStartupAllocationRow>; 2]>(),
            size_of::<std::array::IntoIter<Option<PacketNativeReportStartupAllocationRow>, 2>>(),
            size_of::<[(Option<PacketNativeReportStartupAllocationRow>, Option<PacketNativeReportStartupAllocationRow>); 2]>(),
            size_of::<std::array::IntoIter<(Option<PacketNativeReportStartupAllocationRow>, Option<PacketNativeReportStartupAllocationRow>), 2>>(),
            2 * size_of::<&OriginalNativeStartupQuote>(),
            2 * size_of::<&PacketNativeReportStartupAllocationRow>(),
            size_of::<super::report_startup::StartupRows>(),
            size_of::<Result<OriginalNativeStartupQuote, RuntimeError>>(),
        ];
        sum(&terms, usize::MAX)
    }

    /// Admits native baseline allocations on the same actual pre-Child roster.
    ///
    /// All three real compiled quotes must be complete. Missing private-parser,
    /// native-birth or selected Prepare phases refuse before a member exists.
    /// The holder retains the returned admission throughout finalization.
    ///
    /// # Errors
    /// Refuses unsupported policy, foreign/spent owners, unknown actual backing,
    /// incomplete compiled phases or any checked aggregate storage overrun.
    pub fn reserve_original_native_startup<'a>(
        &'a self,
        sources: &'a [Rc<PacketCompleteSemanticSource>; 3],
        launches: &'a [PacketNative5SourceLaunch; 3],
        encoded_launches: &'a [Vec<u8>; 3],
    ) -> Result<CompleteOriginalNativeStartupAdmission<'a>, RuntimeError> {
        self.reserve_original_native_startup_with_quote(
            sources,
            launches,
            encoded_launches,
            NativeStartupQuoteKind::Broad,
        )
    }

    /// Admits original14 startup with the current native's restrictive raw gates.
    ///
    /// The original authority still authenticates every holder/Source and sums
    /// all three independent rows. No serialized row chooses this producer.
    ///
    /// # Errors
    /// Refuses the same foreign, incomplete, changed or over-budget original
    /// owners as the broad admission; this grants no syntax or native rights.
    pub fn reserve_original_native_preflight_startup<'a>(
        &'a self,
        sources: &'a [Rc<PacketCompleteSemanticSource>; 3],
        launches: &'a [PacketNative5SourceLaunch; 3],
        encoded_launches: &'a [Vec<u8>; 3],
    ) -> Result<CompleteOriginalNativeStartupAdmission<'a>, RuntimeError> {
        self.reserve_original_native_startup_with_quote(
            sources,
            launches,
            encoded_launches,
            NativeStartupQuoteKind::Preflight,
        )
    }

    fn reserve_original_native_startup_with_quote<'a>(
        &'a self,
        sources: &'a [Rc<PacketCompleteSemanticSource>; 3],
        launches: &'a [PacketNative5SourceLaunch; 3],
        encoded_launches: &'a [Vec<u8>; 3],
        quote_kind: NativeStartupQuoteKind,
    ) -> Result<CompleteOriginalNativeStartupAdmission<'a>, RuntimeError> {
        let scope = OriginalNativeStartupScope {
            plan: self,
            sources,
            launches,
            encoded_launches,
        };
        let policy = self
            .0
            .authority
            .original_native_startup_policy(&self.evidence(), &scope)?;
        let fixed = Self::original_native_startup_counter_scratch_data()?;
        if fixed > policy.declared_observer_scratch_bytes
            || policy.declared_observer_scratch_bytes > policy.maximum_requested_bytes
            || policy.maximum_requested_bytes == 0
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let storage = self.0.authority.authenticate_original_native_startup(
            &self.evidence(),
            &scope,
            &policy,
        )?;
        let mut source_bytes = [0; 3];
        if storage.prospective_host_launch_requested_bytes.contains(&0) {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let mut observed = sum(
            &storage.prospective_host_launch_requested_bytes,
            policy.maximum_requested_bytes,
        )?;
        observed = add(
            observed,
            storage.retained_holder_bytes,
            policy.maximum_requested_bytes,
        )?;
        // This same allocation remains owned by Core and each issued member.
        // Source links are weak; the complete shared allocation is charged once.
        observed = add(
            observed,
            OriginalHostFinalizationBarrier::allocation_requested_bytes(),
            policy.maximum_requested_bytes,
        )?;
        let mut pending = [None, None, None];
        for index in 0..3 {
            if (0..index).any(|previous| Rc::ptr_eq(&sources[previous], &sources[index])) {
                return Err(RuntimeError::ForeignAuthority);
            }
            source_bytes[index] = sources[index]
                .original_complete_report_startup_retained_storage_precredit_data(
                    policy.maximum_requested_bytes,
                )?;
            observed = add(
                observed,
                source_bytes[index],
                policy.maximum_requested_bytes,
            )?;
            let quote = quote_kind.quote(
                &sources[index],
                &launches[index],
                &encoded_launches[index],
                policy.maximum_requested_bytes,
            )?;
            observed = add(
                observed,
                quote.native_and_publication_peak(policy.maximum_requested_bytes)?,
                policy.maximum_requested_bytes,
            )?;
            observed = add(
                observed,
                quote.finalization_bytes,
                policy.maximum_requested_bytes,
            )?;
            pending[index] = Some(quote);
        }
        observed = add(
            observed,
            add(
                policy.declared_observer_scratch_bytes,
                storage.maximum_simultaneous_transient_bytes,
                policy.maximum_requested_bytes,
            )?,
            policy.maximum_requested_bytes,
        )?;
        let [a, b, c] = pending;
        let mut admission = CompleteOriginalNativeStartupAdmission {
            scope,
            quote_kind,
            process: std::process::id(),
            thread: std::thread::current().id(),
            policy,
            storage,
            quotes: [
                a.ok_or(RuntimeError::OwnerUnavailable)?,
                b.ok_or(RuntimeError::OwnerUnavailable)?,
                c.ok_or(RuntimeError::OwnerUnavailable)?,
            ],
            source_bytes,
            spent: [false; 3],
            requested_peak: observed,
            host_finalization: None,
        };
        admission.recheck()?;
        // Acquire and validate all original birth loans before allocating the
        // gate. Holding all three excludes callbacks/reentry during attachment.
        // Every assignment below is infallible, so no alias is left unguarded.
        let slots = PacketCompleteSemanticSource::original_native_host_barrier_slots(sources)?;
        let barrier = Rc::new(OriginalHostFinalizationBarrier::new(self, sources));
        slots.attach(&barrier);
        admission.host_finalization = Some(barrier);
        Ok(admission)
    }
}

impl CompleteOriginalNativeStartupAdmission<'_> {
    /// Returns the actual admitted requested-storage conjunction as data.
    pub fn requested_peak_data(&self) -> usize {
        self.requested_peak
    }

    /// Consumes one original member before Source changes its private birth.
    ///
    /// # Errors
    /// Refuses a foreign/repeated member, changed holder or widened owner. A
    /// failed finalization stays spent and retains its same partial Source owner.
    pub fn finalize_original_source(&mut self, index: usize) -> Result<(), RuntimeError> {
        let phase = self.begin_host_finalization(index)?;
        self.origin()?;
        if index >= 3 || self.spent[index] {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.recheck()?;
        let source = &self.scope.sources[index];
        let quote = &self.quotes[index];
        let actual = self.quote_kind.quote(
            source,
            &self.scope.launches[index],
            &self.scope.encoded_launches[index],
            self.policy.maximum_requested_bytes,
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
        match (
            quote.rows.initial_report_rows,
            actual.rows.initial_report_rows,
        ) {
            (Some(allowed), Some(observed))
                if allowed.original_observe12 == observed.original_observe12
                    && allowed.fresh_completed_admit13 == observed.fresh_completed_admit13 => {}
            (None, None) => {}
            _ => return Err(RuntimeError::ForeignAuthority),
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
        self.spent[index] = true;
        let member = OriginalNativeStartupMember {
            host_finalization: Rc::clone(
                self.host_finalization
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
            ),
            host_finalization_index: index,
            edition: NativeStartupMemberEdition::Startup14,
            process: self.process,
            thread: self.thread,
            source: Rc::downgrade(source),
            plan: self.scope.plan.downgrade(),
            rows: quote.rows,
            suffix: None,
            finalization_bytes: quote.finalization_bytes,
            source_capture_backend_bytes: quote.source_capture_backend_bytes,
            source_capture_execution_bytes: quote.source_capture_execution_bytes,
            source_capture_execution_scratch: quote.source_capture_execution_scratch,
            wire_requested_bytes: quote.wire_requested_bytes,
            host_launch_requested_bytes: self.storage.prospective_host_launch_requested_bytes
                [index],
            launch_digest: quote.launch_digest,
            maximum_boot_bytes: quote.maximum_boot_bytes,
        };
        source.finalize_original_native_startup_birth(member, &self.scope.launches[index])?;
        self.recheck()?;
        source.complete_original_native_startup_birth()?;
        self.origin()?;
        // Complete the original post-fences before the final member can open
        // the shared roster barrier through any retained Source alias.
        self.recheck()?;
        phase.finish()
    }

    fn begin_host_finalization(
        &self,
        index: usize,
    ) -> Result<host_finalization::OriginalHostFinalizationLease, RuntimeError> {
        let barrier = self
            .host_finalization
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let source = self.scope.sources.get(index).ok_or_else(|| {
            barrier.abandon();
            RuntimeError::DuplicateOperation
        })?;
        barrier.begin(index, self.scope.plan, source)
    }

    fn origin(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        Ok(())
    }

    fn recheck(&self) -> Result<(), RuntimeError> {
        self.origin()?;
        let authority = &self.scope.plan.0.authority;
        if authority.original_native_startup_policy(&self.scope.plan.evidence(), &self.scope)?
            != self.policy
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let actual = authority.authenticate_original_native_startup(
            &self.scope.plan.evidence(),
            &self.scope,
            &self.policy,
        )?;
        if actual.retained_holder_bytes > self.storage.retained_holder_bytes
            || actual.maximum_simultaneous_transient_bytes
                > self.storage.maximum_simultaneous_transient_bytes
            || actual.prospective_host_launch_requested_bytes
                != self.storage.prospective_host_launch_requested_bytes
        {
            return Err(RuntimeError::ResourceLimit);
        }
        for index in 0..3 {
            let actual = self.scope.sources[index]
                .original_complete_report_startup_retained_storage_precredit_data(
                    self.policy.maximum_requested_bytes,
                )?;
            let allowed = add(
                self.source_bytes[index],
                if self.spent[index] {
                    self.quotes[index].finalization_bytes
                } else {
                    0
                },
                self.policy.maximum_requested_bytes,
            )?;
            if actual > allowed {
                return Err(RuntimeError::ResourceLimit);
            }
        }
        self.origin()
    }
}

impl Drop for CompleteOriginalNativeStartupAdmission<'_> {
    fn drop(&mut self) {
        if let Some(barrier) = &self.host_finalization {
            barrier.abandon();
        }
    }
}

// Issued only by the two genuine once-spent member constructors. Neither a
// decoded Source body nor the absence of a partial body can choose an edition.
#[derive(Clone, Copy)]
enum NativeStartupMemberEdition {
    Startup14,
    Invocation15,
}

pub(crate) struct OriginalNativeStartupMember {
    host_finalization: Rc<OriginalHostFinalizationBarrier>,
    host_finalization_index: usize,
    edition: NativeStartupMemberEdition,
    process: u32,
    thread: ThreadId,
    source: Weak<PacketCompleteSemanticSource>,
    plan: WeakInstalledConformancePlan,
    pub(crate) rows: NativeStartupRows,
    pub(crate) suffix: Option<OriginalRestoredSuffixStartupMember>,
    pub(crate) finalization_bytes: usize,
    // Source-owned pre-Child output-bank construction is a distinct host term.
    // It is never serialized into the native private/bootstrap/Prepare rows.
    pub(crate) source_capture_backend_bytes: usize,
    pub(crate) source_capture_execution_bytes: usize,
    pub(crate) source_capture_execution_scratch: usize,
    pub(crate) wire_requested_bytes: usize,
    pub(crate) host_launch_requested_bytes: usize,
    pub(crate) launch_digest: [u8; 32],
    pub(crate) maximum_boot_bytes: usize,
}

impl OriginalNativeStartupMember {
    /// Retains installed member authentication beneath the shared boot barrier.
    ///
    /// # Errors
    /// Refuses a foreign/spent member or incomplete, aborted or abandoned roster.
    pub(crate) fn authenticate_boot_ready(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        self.host_finalization
            .authenticate_ready(self.host_finalization_index, source)?;
        self.authenticate(source)?;
        self.host_finalization
            .authenticate_ready(self.host_finalization_index, source)
    }

    pub(crate) fn requires_original_invocation_data(&self) -> Result<bool, RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        Ok(matches!(
            self.edition,
            NativeStartupMemberEdition::Invocation15
        ))
    }

    pub(crate) fn retained_shared_storage_data(&self) -> Result<usize, RuntimeError> {
        // This actual Source walker names the shared gate it keeps alive.
        // Prospective finalization precredits the same conservative term for
        // every member, in addition to the complete roster's upfront charge.
        self.plan
            .retained_allocation_bytes()
            .checked_add(
                crate::node_contract::NodeRuntime::capture_shared_allocation_storage::<
                    PacketCompleteSemanticSource,
                >(),
            )
            .and_then(|bytes| {
                bytes.checked_add(Self::host_finalization_allocation_requested_data())
            })
            .ok_or(RuntimeError::ResourceLimit)
    }

    /// Counts the same gate allocation retained through an installed member.
    pub(crate) fn host_finalization_allocation_requested_data() -> usize {
        OriginalHostFinalizationBarrier::allocation_requested_bytes()
    }

    pub(crate) fn authenticate(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        if !std::ptr::eq(self.source.as_ptr(), source) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let plan = self
            .plan
            .0
            .upgrade()
            .map(InstalledConformancePlan)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let scope = OriginalNativeStartupMemberScope {
            plan: &plan,
            source,
        };
        plan.0
            .authority
            .authenticate_original_native_startup_member(&plan.evidence(), &scope)
    }
}

fn extent(value: u64) -> Result<usize, RuntimeError> {
    usize::try_from(value).map_err(|_| RuntimeError::ResourceLimit)
}

fn add(a: usize, b: usize, maximum: usize) -> Result<usize, RuntimeError> {
    a.checked_add(b)
        .filter(|n| *n <= maximum)
        .ok_or(RuntimeError::ResourceLimit)
}

fn sum(values: &[usize], maximum: usize) -> Result<usize, RuntimeError> {
    values
        .iter()
        .try_fold(0, |total, value| add(total, *value, maximum))
}

mod invocation;
pub(crate) use invocation::OriginalRestoredSuffixStartupMember;
pub use invocation::{
    CompleteOriginalNativeInvocationAdmission, CompleteOriginalRestoredSuffixStartupAdmission,
};

#[cfg(test)]
mod retained_overlap_tests {
    use super::*;

    #[test]
    fn missing_joint_metadata_keeps_full_retained_sum_and_original_phase_bound() {
        let row = |retained, transient, scratch| PacketNativeStartupAllocationRow {
            retained_requested_bytes: crucible_node_format::U64::new(retained),
            maximum_simultaneous_transient_bytes: crucible_node_format::U64::new(transient),
            declared_counter_scratch_bytes: crucible_node_format::U64::new(scratch),
        };
        let rows = NativeStartupRows {
            private_bootstrap: row(10, 3, 2),
            native_birth: row(20, 6, 2),
            restore_prepare: Some(row(5, 2, 1)),
            retained_overlap: None,
            initial_report_rows: None,
        };
        let publication = super::super::report_startup::StartupRows {
            original_observe12: None,
            fresh_completed_admit13: None,
        };
        assert_eq!(rows.peak_with_publication(publication, 43).unwrap(), 43);
        assert!(rows.peak_with_publication(publication, 42).is_err());
        assert_eq!(rows.private_bootstrap.retained_requested_bytes.get(), 10);
        assert_eq!(rows.native_birth.retained_requested_bytes.get(), 20);
    }
}

mod settled17;

pub use invocation::CompleteOriginalRestoredSettledStartupAdmission;
pub(crate) use invocation::OriginalRestoredSettledStartupMember;

// Import18 has its own member and installed-authority hooks. Legacy members
// never select this path from their edition or serialized allocation rows.
mod import18;
pub use import18::{
    CompleteOriginalNativeImport18StartupAdmission, OriginalNativeImport18StartupMemberScope,
    OriginalNativeImport18StartupScope,
};
pub(crate) use import18::{
    OriginalNativeImport18StartupMember, OriginalNativeImport18StartupQuote,
};
