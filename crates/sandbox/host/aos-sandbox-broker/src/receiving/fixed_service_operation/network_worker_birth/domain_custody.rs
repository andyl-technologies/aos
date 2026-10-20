//! Retains the issued P worker's existing domain custody interval.
//!
//! The protected binder persists and reads back namespace custody before any
//! effect frame. Its exclusive reservation lends the same parent loan only
//! during that synchronous binder. Both independently paid Source bookends
//! stay on this birth owner, including through a caught domain unwind.

use super::*;

#[derive(Clone, Copy)]
enum First { Order, Before, Clock, Body, After }

pub(super) struct DomainCustodyOriginalV2 {
    entered: bool,
    before: Option<FixedServiceCurrentnessSampleV1<FixedServiceOperationClosedV4>>,
    before_result: Option<Result<(), FixedServiceOperationClosedV4>>,
    clock: Option<Result<RawPairedClockSample, FixedServiceOperationClosedV4>>,
    body: Option<Result<(), FixedServiceOperationClosedV4>>,
    after: Option<FixedServiceCurrentnessSampleV1<FixedServiceOperationClosedV4>>,
    after_entered: bool,
    after_result: Option<Result<(), FixedServiceOperationClosedV4>>,
    first: Option<First>,
}

impl DomainCustodyOriginalV2 {
    pub(super) const fn new() -> Self {
        Self { entered: false, before: None, before_result: None,
            clock: None, body: None, after: None, after_entered: false,
            after_result: None, first: None }
    }

    pub(super) fn dynamic_demand() -> Result<ResourceVector, AccountingError> {
        // Resident fields are covered by the containing birth original. Only
        // the actual P reservation enters these two native sample recipes.
        let sample = FixedServiceCurrentnessSampleV1::<FixedServiceOperationClosedV4>::dynamic_demand()?;
        sample.checked_add(sample)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Before => self.before.as_ref()?.failure(),
            First::After => self.after.as_ref()?.failure(),
            First::Clock | First::Body | First::Order => None,
        }.or(Some(&FixedServiceOperationClosedV4))
    }

    pub(super) fn parent_failure_is_selected(&self) -> bool {
        matches!(self.first, Some(First::Clock))
    }
}

// This concrete guard owns no new permission. It completes only the after
// already priced by this actual reservation, even when the domain unwinds.
struct SourceAfterV2<'held, 'financial> {
    loan: &'held mut FixedServiceOperationLoanV4<'financial>,
    original: &'held mut DomainCustodyOriginalV2,
}

impl SourceAfterV2<'_, '_> {
    fn observe_after(&mut self) {
        if self.original.after_entered {
            return;
        }
        self.original.after_entered = true;
        let earlier = self.original.first;
        self.original.first.get_or_insert(First::After);
        let Some(after) = self.original.after.as_mut() else {
            self.original.first.get_or_insert(First::After);
            return;
        };
        self.original.after_result = Some(observe(self.loan.common, after));
        if matches!(self.original.after_result, Some(Ok(()))) {
            self.original.first = earlier;
        }
    }
}

impl Drop for SourceAfterV2<'_, '_> {
    fn drop(&mut self) {
        self.observe_after();
        if self.original.first.is_some() {
            self.loan.common.operation_closed = true;
            self.loan.operation.fail(Failure::Body);
        }
    }
}

impl<'held, 'financial> NetworkWorkerBirthReservationV2<'held, 'financial> {
    /// Lends the same parent loan once to the existing domain custody binder.
    ///
    /// The callback synchronously persists and reads back the actual target
    /// namespace before any worker effect frame. It retains its original
    /// Journal/store result and first cause on the caller owner before returning
    /// this closed marker. No loan borrow can escape, and no new Source,
    /// account, signed admission or deadline is constructed here.
    ///
    /// Both Source observations are priced before this P reservation's
    /// PREBIRTH. Its independently owed after runs when the clock or callback
    /// refuses or unwinds. The actual domain error stays on the caller owner;
    /// this original owns the native Source results and selected marker.
    ///
    /// # Errors
    /// Refuses another purpose, incomplete native birth/ARM, repeated entry,
    /// native Source observations, parent clock or domain custody failure.
    pub fn with_parent_domain_custody_once_v2(
        &mut self,
        body: impl FnOnce(&mut FixedServiceOperationLoanV4<'financial>)
            -> Result<(), FixedServiceOperationClosedV4>,
    ) -> Result<(), FixedServiceOperationClosedV4> {
        let original = &mut self.original.domain_custody;
        if original.entered || self.original.first.is_some()
            || !matches!(self.original.purpose, Some(NetworkWorkerBirthPurposeV2::Preparation))
            || self.original.birth.as_ref().and_then(|birth| birth.completed_packet_data()).is_none()
            || self.original.armed.is_none() {
            original.first.get_or_insert(First::Order);
            self.original.first.get_or_insert(super::First::DomainCustody);
            return Err(self.loan.refuse_network_worker_birth_v2(Failure::Order));
        }
        original.entered = true;
        original.before = Some(Default::default());
        original.after = Some(Default::default());
        let mut scope = SourceAfterV2 { loan: &mut *self.loan, original };
        scope.original.first = Some(First::Before);
        if let Some(before) = scope.original.before.as_mut() {
            scope.original.before_result = Some(observe(scope.loan.common, before));
        }
        if !matches!(scope.original.before_result, Some(Ok(()))) {
            scope.original.first = Some(First::Before);
        } else {
            scope.original.first = Some(First::Clock);
            scope.original.clock = Some(scope.loan.observe_network_worker_effect_clock_v4());
            if !matches!(scope.original.clock, Some(Ok(_))) {
                scope.original.first = Some(First::Clock);
            } else {
                // An unwind must leave this entered body closed before its
                // owed after can select a different, later native failure.
                scope.original.first = Some(First::Body);
                scope.original.body = Some(body(&mut *scope.loan));
                if matches!(scope.original.body, Some(Ok(()))) {
                    scope.original.first = None;
                }
            }
        }
        scope.observe_after();
        let failed = scope.original.first.is_some();
        drop(scope);
        if failed {
            self.original.first.get_or_insert(super::First::DomainCustody);
            Err(self.loan.refuse_network_worker_birth_v2(Failure::Body))
        } else {
            Ok(())
        }
    }
}
