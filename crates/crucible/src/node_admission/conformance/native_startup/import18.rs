//! Admits only the original Source-owned import18 startup allocation phases.
//!
//! The installed authority observes the same three Sources and launch owners.
//! A complete opaque producer recipe and independent baseline quote precede
//! admission. No decoded announcement or legacy startup member enters this path.

use super::*;
use crucible_node_provider::reference_packet::service::complete_restore::import18::{
    PacketNativeImport18InitialFundingData, PacketNativeImport18PrebirthRecipeData,
};

/// Borrows the exact installed import18 roster and its retained launch owners.
pub struct OriginalNativeImport18StartupScope<'a> {
    plan: &'a InstalledConformancePlan,
    sources: &'a [Rc<PacketCompleteSemanticSource>; 3],
    launches: &'a [PacketNative5SourceLaunch; 3],
    encoded_launches: &'a [Vec<u8>; 3],
}

impl OriginalNativeImport18StartupScope<'_> {
    /// Borrows the original installed plan.
    pub fn plan(&self) -> &InstalledConformancePlan {
        self.plan
    }

    /// Borrows the actual three Source allocations.
    pub fn sources(&self) -> &[Rc<PacketCompleteSemanticSource>; 3] {
        self.sources
    }

    /// Borrows their retained typed launches.
    pub fn launches(&self) -> &[PacketNative5SourceLaunch; 3] {
        self.launches
    }

    /// Borrows their separately retained original encodings.
    pub fn encoded_launches(&self) -> &[Vec<u8>; 3] {
        self.encoded_launches
    }

    /// Compares the actual installed plan allocation without callbacks.
    pub fn is_original_plan(&self, plan: &InstalledConformancePlan) -> bool {
        Rc::ptr_eq(&self.plan.0, &plan.0)
    }

    /// Compares the installed authority allocation without granting work.
    pub fn is_original_authority(
        &self,
        authority: &dyn super::super::ConformanceAdmissionAuthority,
    ) -> bool {
        self.plan.has_authority(authority)
    }
}

/// Borrows the genuine Source and temporarily upgraded original plan.
pub struct OriginalNativeImport18StartupMemberScope<'a> {
    plan: &'a InstalledConformancePlan,
    source: &'a PacketCompleteSemanticSource,
}

impl OriginalNativeImport18StartupMemberScope<'_> {
    /// Borrows the same installed plan for this callback only.
    pub fn plan(&self) -> &InstalledConformancePlan {
        self.plan
    }

    /// Borrows the actual original Source allocation.
    pub fn source(&self) -> &PacketCompleteSemanticSource {
        self.source
    }

    /// Compares the actual installed plan allocation.
    pub fn is_original_plan(&self, plan: &InstalledConformancePlan) -> bool {
        Rc::ptr_eq(&self.plan.0, &plan.0)
    }

    /// Compares the installed authority allocation.
    pub fn is_original_authority(
        &self,
        authority: &dyn super::super::ConformanceAdmissionAuthority,
    ) -> bool {
        self.plan.has_authority(authority)
    }
}

/// Receives only a genuine complete Source producer output, never wire DATA.
pub(crate) struct OriginalNativeImport18StartupQuote {
    pub(crate) recipe: PacketNativeImport18PrebirthRecipeData,
    pub(crate) initial: PacketNativeImport18InitialFundingData,
    pub(crate) baseline: OriginalNativeStartupQuote,
    pub(crate) host: [usize; 3],
    pub(crate) wire_body_maximum: [usize; 3],
    pub(crate) launch_digest: [u8; 32],
}

impl OriginalNativeImport18StartupQuote {
    fn requested_peak(&self, maximum: usize) -> Result<usize, RuntimeError> {
        self.initial
            .row_data()
            .requested_peak_data()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let escrow = self.recipe.escrow_storage_data();
        let initial = [
            self.initial.row_data().retained_requested_bytes,
            self.initial.row_data().maximum_simultaneous_transient_bytes,
            self.initial.row_data().declared_counter_scratch_bytes,
        ];
        for (actual, allowed) in initial.iter().zip(&escrow) {
            if actual.get() > allowed.get() {
                return Err(RuntimeError::ResourceLimit);
            }
        }
        if self.wire_body_maximum.contains(&0)
            || sum(&self.wire_body_maximum, maximum)? > self.host[0]
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let mut peak = self.baseline.native_and_publication_peak(maximum)?;
        for bytes in [
            self.baseline.finalization_bytes,
            self.baseline.source_capture_backend_bytes,
            self.baseline.source_capture_execution_bytes,
            self.baseline.source_capture_execution_scratch,
            self.baseline.wire_requested_bytes,
            self.baseline.publication_bytes,
        ] {
            peak = add(peak, bytes, maximum)?;
        }
        // The initial row is a subpartition, not a second grant. Count the
        // single original recipe escrow once, separately from baseline and host.
        for bytes in escrow {
            peak = add(peak, extent(bytes.get())?, maximum)?;
        }
        for bytes in self.host {
            peak = add(peak, bytes, maximum)?;
        }
        Ok(peak)
    }

    fn authenticate_actual(&self, actual: &Self, maximum: usize) -> Result<(), RuntimeError> {
        actual.requested_peak(maximum)?;
        if self.recipe.identity_data() != actual.recipe.identity_data()
            || self.launch_digest != actual.launch_digest
            || self.baseline.launch_digest != actual.baseline.launch_digest
            || self.baseline.rows.retained_overlap.is_some()
                != actual.baseline.rows.retained_overlap.is_some()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.initial
            .row_data()
            .authenticate_actual_data(actual.initial.row_data())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        for (allowed, observed) in self.host.iter().zip(actual.host) {
            if observed > *allowed {
                return Err(RuntimeError::ResourceLimit);
            }
        }
        for (allowed, observed) in self.wire_body_maximum.iter().zip(actual.wire_body_maximum) {
            if observed > *allowed {
                return Err(RuntimeError::ResourceLimit);
            }
        }
        for (allowed, observed) in [
            (
                Some(self.baseline.rows.private_bootstrap),
                Some(actual.baseline.rows.private_bootstrap),
            ),
            (
                Some(self.baseline.rows.native_birth),
                Some(actual.baseline.rows.native_birth),
            ),
            (
                self.baseline.rows.restore_prepare,
                actual.baseline.rows.restore_prepare,
            ),
        ] {
            match (allowed, observed) {
                (Some(a), Some(b)) => a
                    .authenticate_actual_data(&b)
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                (None, None) => {}
                _ => return Err(RuntimeError::ForeignAuthority),
            }
        }
        match (
            self.baseline.rows.initial_report_rows,
            actual.baseline.rows.initial_report_rows,
        ) {
            (Some(a), Some(b))
                if a.original_observe12 == b.original_observe12
                    && a.fresh_completed_admit13 == b.fresh_completed_admit13 => {}
            (None, None) => {}
            _ => return Err(RuntimeError::ForeignAuthority),
        }
        self.baseline
            .authenticate_publication_data(&actual.baseline)?;
        for (allowed, observed) in [
            (
                self.baseline.finalization_bytes,
                actual.baseline.finalization_bytes,
            ),
            (
                self.baseline.source_capture_backend_bytes,
                actual.baseline.source_capture_backend_bytes,
            ),
            (
                self.baseline.source_capture_execution_bytes,
                actual.baseline.source_capture_execution_bytes,
            ),
            (
                self.baseline.source_capture_execution_scratch,
                actual.baseline.source_capture_execution_scratch,
            ),
            (
                self.baseline.wire_requested_bytes,
                actual.baseline.wire_requested_bytes,
            ),
            (
                self.baseline.publication_bytes,
                actual.baseline.publication_bytes,
            ),
            (
                self.baseline.maximum_boot_bytes,
                actual.baseline.maximum_boot_bytes,
            ),
            (
                self.baseline.native_and_publication_peak(maximum)?,
                actual.baseline.native_and_publication_peak(maximum)?,
            ),
        ] {
            if observed > allowed {
                return Err(RuntimeError::ResourceLimit);
            }
        }
        Ok(())
    }
}

/// Keeps the once-issued import18 members beneath a shared allocation barrier.
pub struct CompleteOriginalNativeImport18StartupAdmission<'a> {
    scope: OriginalNativeImport18StartupScope<'a>,
    process: u32,
    thread: ThreadId,
    policy: OriginalNativeStartupPolicy,
    storage: OriginalNativeStartupStorage,
    quotes: [OriginalNativeImport18StartupQuote; 3],
    source_bytes: [usize; 3],
    quote_prewalk: [(usize, usize); 3],
    spent: [bool; 3],
    pending_member: Option<OriginalNativeImport18StartupMember>,
    failed: bool,
    requested_peak: usize,
    barrier: Option<Rc<OriginalHostFinalizationBarrier>>,
}

impl InstalledConformancePlan {
    /// Names the actual fixed admission, quote, member and callback views.
    ///
    /// # Errors
    /// Refuses checked counter arithmetic overflow.
    pub fn original_native_import18_startup_counter_scratch_data() -> Result<usize, RuntimeError> {
        let terms = [
            size_of::<CompleteOriginalNativeImport18StartupAdmission<'_>>(),
            size_of::<OriginalNativeImport18StartupScope<'_>>(),
            size_of::<OriginalNativeImport18StartupMemberScope<'_>>(),
            size_of::<[OriginalNativeImport18StartupQuote; 3]>(),
            size_of::<[Option<OriginalNativeImport18StartupQuote>; 3]>(),
            size_of::<OriginalNativeImport18StartupMember>(),
            size_of::<[usize; 3]>(),
            size_of::<[bool; 3]>(),
            size_of::<[(usize, usize); 3]>(),
            size_of::<std::array::IntoIter<(usize, usize), 3>>(),
            size_of::<(usize, usize)>(),
            size_of::<[usize; 6]>(),
            size_of::<[(usize, usize); 8]>(),
            size_of::<std::array::IntoIter<(usize, usize), 8>>(),
            size_of::<std::slice::Iter<'static, usize>>(),
            size_of::<std::array::IntoIter<usize, 3>>(),
            size_of::<std::array::IntoIter<usize, 6>>(),
            size_of::<std::array::IntoIter<crucible_node_contract::U64, 3>>(),
            size_of::<Result<OriginalNativeImport18StartupQuote, RuntimeError>>(),
            size_of::<Result<CompleteOriginalNativeImport18StartupAdmission<'_>, RuntimeError>>(),
            size_of::<Result<usize, RuntimeError>>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<OriginalNativeStartupPolicy>(),
            size_of::<OriginalNativeStartupStorage>(),
            size_of::<InstalledConformancePlan>(),
            size_of::<Option<InstalledConformancePlan>>(),
            size_of::<Rc<OriginalHostFinalizationBarrier>>(),
            OriginalHostFinalizationBarrier::counter_scratch_data(),
            PacketCompleteSemanticSource::original_native_host_barrier_slot_scratch_data(),
            PacketCompleteSemanticSource::original_native_import18_startup_counter_scratch_data()?,
            super::NativeStartupRows::publication_phase_counter_scratch_data(),
            size_of::<
                [(
                    Option<PacketNativeStartupAllocationRow>,
                    Option<PacketNativeStartupAllocationRow>,
                ); 3],
            >(),
            size_of::<
                std::array::IntoIter<
                    (
                        Option<PacketNativeStartupAllocationRow>,
                        Option<PacketNativeStartupAllocationRow>,
                    ),
                    3,
                >,
            >(),
            size_of::<
                std::iter::Zip<
                    std::slice::Iter<'static, crucible_node_contract::U64>,
                    std::slice::Iter<'static, crucible_node_contract::U64>,
                >,
            >(),
            size_of::<
                std::iter::Zip<std::slice::Iter<'static, usize>, std::array::IntoIter<usize, 3>>,
            >(),
            size_of::<(&usize, usize)>(),
            size_of::<(&crucible_node_contract::U64, &crucible_node_contract::U64)>(),
            size_of::<[crucible_node_contract::U64; 3]>(),
            // Concrete index/previous/max/observed/peak/bytes/growth and
            // allowed/actual/fixed arithmetic views across the closed methods.
            size_of::<[usize; 10]>(),
            size_of::<&OriginalNativeImport18StartupQuote>(),
            size_of::<&OriginalNativeStartupQuote>(),
            size_of::<&OriginalNativeImport18StartupMember>(),
            size_of::<&mut Option<OriginalNativeImport18StartupMember>>(),
            size_of::<Option<&OriginalNativeImport18StartupMember>>(),
            size_of::<Result<&OriginalNativeImport18StartupMember, RuntimeError>>(),
            size_of::<&PacketCompleteSemanticSource>(),
            size_of::<&Rc<PacketCompleteSemanticSource>>(),
            size_of::<Option<&Rc<PacketCompleteSemanticSource>>>(),
            size_of::<&InstalledConformancePlan>(),
            size_of::<&PacketNative5SourceLaunch>(),
            size_of::<&Vec<u8>>(),
            size_of::<&[u8]>(),
            size_of::<&OriginalNativeStartupPolicy>(),
            size_of::<&OriginalNativeStartupStorage>(),
            size_of::<Result<usize, crucible_node_provider::ProviderError>>(),
            size_of::<Result<(), crucible_node_provider::ProviderError>>(),
            size_of::<Option<PacketNativeStartupAllocationRow>>(),
            size_of::<std::ops::Range<usize>>(),
            OriginalNativeImport18StartupMember::authentication_counter_scratch_data(),
        ];
        add(
            sum(&terms, usize::MAX)?,
            std::mem::size_of_val(&terms),
            usize::MAX,
        )
    }

    /// Admits real complete import18 producer quotes for the same installed roster.
    ///
    /// # Errors
    /// Refuses unsupported installed policy, foreign Sources, incomplete recipe
    /// producers, changed whole-holder observations, or any exceeded row.
    pub fn reserve_original_native_import18_startup<'a>(
        &'a self,
        sources: &'a [Rc<PacketCompleteSemanticSource>; 3],
        launches: &'a [PacketNative5SourceLaunch; 3],
        encoded_launches: &'a [Vec<u8>; 3],
    ) -> Result<CompleteOriginalNativeImport18StartupAdmission<'a>, RuntimeError> {
        let scope = OriginalNativeImport18StartupScope {
            plan: self,
            sources,
            launches,
            encoded_launches,
        };
        let policy = self
            .0
            .authority
            .original_native_import18_startup_policy(&self.evidence(), &scope)?;
        if policy.maximum_requested_bytes == 0
            || Self::original_native_import18_startup_counter_scratch_data()?
                > policy.declared_observer_scratch_bytes
            || policy.declared_observer_scratch_bytes > policy.maximum_requested_bytes
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let storage = self
            .0
            .authority
            .authenticate_original_native_import18_startup(&self.evidence(), &scope, &policy)?;
        if storage.prospective_host_launch_requested_bytes.contains(&0) {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let max = policy.maximum_requested_bytes;
        let mut observed = sum(&storage.prospective_host_launch_requested_bytes, max)?;
        observed = add(observed, storage.retained_holder_bytes, max)?;
        observed = add(
            observed,
            OriginalHostFinalizationBarrier::allocation_requested_bytes(),
            max,
        )?;
        let mut pending = [None, None, None];
        let mut source_bytes = [0; 3];
        let mut quote_prewalk = [(0, 0); 3];
        for index in 0..3 {
            if (0..index).any(|previous| Rc::ptr_eq(&sources[index], &sources[previous])) {
                return Err(RuntimeError::ForeignAuthority);
            }
            source_bytes[index] = sources[index]
                .original_complete_report_startup_retained_storage_precredit_data(max)?;
            observed = add(observed, source_bytes[index], max)?;
            // This prewalk invokes only prepaid fixed metadata/scanner controls.
            // Its actual formatter/constructor T is admitted before any source
            // quote can enter a serializer, including the unchanged baseline.
            quote_prewalk[index] = sources[index]
                .original_native_import18_startup_quote_prewalk_data(&launches[index], max)?;
        }
        let mut quote_peak = add(observed, policy.declared_observer_scratch_bytes, max)?;
        quote_peak = add(
            quote_peak,
            storage.maximum_simultaneous_transient_bytes,
            max,
        )?;
        for (transient, scratch) in quote_prewalk {
            quote_peak = add(add(quote_peak, transient, max)?, scratch, max)?;
        }
        for index in 0..3 {
            let quote = sources[index].original_native_import18_startup_quote_data(
                &launches[index],
                &encoded_launches[index],
                max,
            )?;
            if quote.host[1] > quote_prewalk[index].0 || quote.host[2] > quote_prewalk[index].1 {
                return Err(RuntimeError::ResourceLimit);
            }
            observed = add(observed, quote.requested_peak(max)?, max)?;
            pending[index] = Some(quote);
        }
        observed = add(
            observed,
            add(
                policy.declared_observer_scratch_bytes,
                storage.maximum_simultaneous_transient_bytes,
                max,
            )?,
            max,
        )?;
        let [a, b, c] = pending;
        let mut owner = CompleteOriginalNativeImport18StartupAdmission {
            scope,
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
            quote_prewalk,
            spent: [false; 3],
            pending_member: None,
            failed: false,
            requested_peak: observed,
            barrier: None,
        };
        owner.recheck()?;
        let slots = PacketCompleteSemanticSource::original_native_host_barrier_slots(sources)?;
        let barrier = Rc::new(OriginalHostFinalizationBarrier::new(self, sources));
        slots.attach(&barrier);
        owner.barrier = Some(barrier);
        Ok(owner)
    }
}

impl CompleteOriginalNativeImport18StartupAdmission<'_> {
    /// Reports the actually admitted whole requested-storage conjunction.
    pub fn requested_peak_data(&self) -> usize {
        self.requested_peak
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
        if authority
            .original_native_import18_startup_policy(&self.scope.plan.evidence(), &self.scope)?
            != self.policy
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let actual = authority.authenticate_original_native_import18_startup(
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
            let growth = if self.spent[index] {
                add(
                    self.quotes[index].baseline.finalization_bytes,
                    self.quotes[index].host[0],
                    self.policy.maximum_requested_bytes,
                )?
            } else {
                0
            };
            let allowed = add(
                self.source_bytes[index],
                growth,
                self.policy.maximum_requested_bytes,
            )?;
            if actual > allowed {
                return Err(RuntimeError::ResourceLimit);
            }
        }
        self.origin()
    }
}

impl Drop for CompleteOriginalNativeImport18StartupAdmission<'_> {
    fn drop(&mut self) {
        if let Some(barrier) = &self.barrier {
            barrier.abandon();
        }
    }
}

/// Retains only the distinct import18 allocation member in its original Source.
pub(crate) struct OriginalNativeImport18StartupMember {
    process: u32,
    thread: ThreadId,
    source: Weak<PacketCompleteSemanticSource>,
    plan: WeakInstalledConformancePlan,
    barrier: Rc<OriginalHostFinalizationBarrier>,
    index: usize,
    quote: OriginalNativeImport18StartupQuote,
    pub(crate) host_launch_requested_bytes: usize,
}

impl OriginalNativeImport18StartupMember {
    fn origin(&self, source: &PacketCompleteSemanticSource) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        if !std::ptr::eq(self.source.as_ptr(), source) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Names this member's own same-owner and authority callback views.
    ///
    /// The authority's actual observer work remains separately preadmitted.
    pub(crate) fn authentication_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&PacketCompleteSemanticSource>()
            + size_of::<InstalledConformancePlan>()
            + size_of::<Option<InstalledConformancePlan>>()
            + size_of::<OriginalNativeImport18StartupMemberScope<'_>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<[usize; 3]>()
            + size_of::<usize>()
            + size_of::<ThreadId>()
            + size_of::<u32>()
            + OriginalHostFinalizationSource::authentication_scratch_data()
    }

    /// Authenticates the actual installed import18 member without native effects.
    ///
    /// # Errors
    /// Refuses a foreign Source, process, thread, expired plan or revoked member.
    pub(crate) fn authenticate(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        self.origin(source)?;
        let plan = self
            .plan
            .0
            .upgrade()
            .map(InstalledConformancePlan)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let scope = OriginalNativeImport18StartupMemberScope {
            plan: &plan,
            source,
        };
        plan.0
            .authority
            .authenticate_original_native_import18_startup_member(&plan.evidence(), &scope)?;
        self.origin(source)
    }

    /// Requires the same fully finalized nonaborted three-Source allocation gate.
    ///
    /// # Errors
    /// Refuses a foreign, incomplete, abandoned or aborted original roster.
    pub(crate) fn authenticate_boot_ready(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        self.barrier.authenticate_ready(self.index, source)?;
        self.authenticate(source)?;
        self.barrier.authenticate_ready(self.index, source)
    }

    pub(crate) fn recipe_data(&self) -> &PacketNativeImport18PrebirthRecipeData {
        &self.quote.recipe
    }
    pub(crate) fn initial_data(&self) -> PacketNativeStartupAllocationRow {
        *self.quote.initial.row_data()
    }
    pub(crate) fn initial_funding_data(&self) -> &PacketNativeImport18InitialFundingData {
        &self.quote.initial
    }
    pub(crate) fn baseline_data(&self) -> &OriginalNativeStartupQuote {
        &self.quote.baseline
    }
    pub(crate) fn host_storage_data(&self) -> [usize; 3] {
        self.quote.host
    }
    pub(crate) fn wire_body_maximum_data(&self) -> [usize; 3] {
        self.quote.wire_body_maximum
    }
    pub(crate) fn launch_digest_data(&self) -> [u8; 32] {
        self.quote.launch_digest
    }

    /// Names this genuine barrier allocation without issuing an admission.
    pub(crate) fn host_finalization_allocation_requested_data() -> usize {
        OriginalHostFinalizationBarrier::allocation_requested_bytes()
    }

    /// Counts true weak-allocation and shared gate retention without equality credit.
    ///
    /// # Errors
    /// Refuses checked retained backing arithmetic overflow.
    pub(crate) fn retained_shared_storage_data(&self) -> Result<usize, RuntimeError> {
        self.plan
            .retained_allocation_bytes()
            .checked_add(
                crate::node_contract::NodeRuntime::capture_shared_allocation_storage::<
                    PacketCompleteSemanticSource,
                >(),
            )
            .and_then(|n| {
                n.checked_add(OriginalHostFinalizationBarrier::allocation_requested_bytes())
            })
            .ok_or(RuntimeError::ResourceLimit)
    }
}
