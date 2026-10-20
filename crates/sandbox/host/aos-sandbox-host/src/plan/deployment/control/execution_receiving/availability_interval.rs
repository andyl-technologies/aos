//! Retains actual authenticated subintervals on the once-consumed Prepare19.
//!
//! The Host capsule owns the closed semantic program and native writers. This
//! module adds no grant or receiver factory: each request extends the same
//! complete liability before allocating its original observation destinations.

use super::*;

pub(in crate::plan::deployment::control) struct AvailabilityIntervalsV2 {
    authenticated: bool,
    requests: Vec<Request>,
    allocation: Option<Result<(), std::collections::TryReserveError>>,
    current: Option<Request>,
    native_positive: bool,
    prepared: Option<Request>,
    accept: Option<Request>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(id: u8) -> Request {
        Request {
            id: [id; 16],
            session: [4; 32],
            signed: [id; 32],
        }
    }

    fn retained_original() -> HostExecutionReceivingV2 {
        let mut original = HostExecutionReceivingV2::from_reserved_subdivisions(
            ResourceVector::new([40_000; 22]),
            ExecutionReceivingProfileV2 {
                prepare: [10_000; 22],
                accept: [10_000; 22],
                launch: [10_000; 22],
                boot_preparation: None,
            },
            ResourceVector::ZERO,
        )
        .unwrap();
        original.begin(Phase::Prepare, request(1)).unwrap();
        original
            .require_complete(
                Phase::Prepare,
                request(1),
                ResourceVector::ZERO
                    .with(D::MemoryBytes, 100)
                    .with(D::NetworkBytes, 7),
            )
            .unwrap();
        original.mark_availability_original_v2(request(1)).unwrap();
        original
            .finish_native_positive(Phase::Prepare, request(1))
            .unwrap();
        original
            .retain_authenticated_availability_v2(request(1))
            .unwrap();
        original
    }

    #[test]
    fn authenticated_intervals_keep_same_consumed_operation_peak_and_traffic() {
        let mut original = retained_original();
        let charged = original.ledger.charged();
        let operation = original.flights[0].operation.as_ref().unwrap() as *const _;

        for (id, traffic) in [(2, 12), (3, 19)] {
            original
                .begin_availability_interval_v2(
                    request(1),
                    request(id),
                    ResourceVector::ZERO
                        .with(D::MemoryBytes, 80)
                        .with(D::NetworkBytes, traffic),
                )
                .unwrap();
            original
                .finish_availability_native_v2(request(1), request(id))
                .unwrap();
            original
                .finish_availability_authenticated_v2(request(1), request(id))
                .unwrap();

            let flight = &original.flights[0];
            assert!(std::ptr::eq(flight.operation.as_ref().unwrap(), operation));
            assert!(flight.operation.as_ref().unwrap().is_consumed_current());
            assert!(flight.request == Some(request(1)));
            assert_eq!(flight.reached.get(D::MemoryBytes), 100);
            assert_eq!(flight.current.get(D::MemoryBytes), 100);
            assert_eq!(flight.reached.get(D::NetworkBytes), traffic);
            assert_eq!(original.ledger.charged(), charged);
        }

        assert!(
            original
                .begin_availability_interval_v2(request(1), request(2), ResourceVector::ZERO)
                .is_err()
        );
        assert!(original.mark_availability_original_v2(request(1)).is_err());
        assert!(original.begin(Phase::Accept, request(4)).is_err());
        assert!(
            original.flights[0]
                .operation
                .as_ref()
                .unwrap()
                .is_consumed_current()
        );
        assert_eq!(original.ledger.charged(), charged);
    }

    #[test]
    fn accept_keeps_exact_consumed_prepare_and_requires_authenticated_preparation() {
        let mut original = retained_original();
        let charged = original.ledger.charged();
        let prepare = original.flights[0].operation.as_ref().unwrap() as *const _;
        let reached = original.flights[0].reached;
        let current = original.flights[0].current;
        assert!(
            original
                .begin_accept_with_retained_availability_v2(
                    request(1),
                    request(2),
                    request(3),
                    ResourceVector::ZERO
                )
                .is_err()
        );
        assert!(original.flights[1].operation.is_none());

        original
            .begin_availability_interval_v2(request(1), request(2), reached)
            .unwrap();
        original
            .finish_availability_native_v2(request(1), request(2))
            .unwrap();
        original
            .retain_authenticated_availability_preparation_v2(request(1), request(2))
            .unwrap();
        original
            .begin_accept_with_retained_availability_v2(
                request(1),
                request(2),
                request(3),
                ResourceVector::ZERO.with(D::MemoryBytes, 200),
            )
            .unwrap();

        assert!(std::ptr::eq(
            original.flights[0].operation.as_ref().unwrap(),
            prepare
        ));
        assert!(
            original.flights[0]
                .operation
                .as_ref()
                .unwrap()
                .is_consumed_current()
        );
        assert_eq!(original.flights[0].reached, reached);
        assert_eq!(original.flights[0].current, current);
        assert!(original.retained_prepare_for_accept_v2(request(3)).unwrap() == Some(request(1)));
        assert!(original.retained_prepare_for_accept_v2(request(4)).is_err());
        assert_eq!(original.ledger.charged(), charged);
        assert!(
            original
                .retire_after_disposal(Phase::Prepare, request(1))
                .is_err()
        );
        assert!(
            original
                .retire_after_disposal(Phase::Accept, request(3))
                .is_err()
        );

        assert!(
            original
                .require_complete(
                    Phase::Accept,
                    request(3),
                    ResourceVector::ZERO.with(D::MemoryBytes, 10_001)
                )
                .is_err()
        );
        let first = original.failure().unwrap() as *const dyn std::error::Error;
        assert!(
            original
                .require_owed_post(Phase::Accept, request(3))
                .is_ok()
        );
        assert!(
            original
                .require_complete(Phase::Accept, request(3), ResourceVector::ZERO)
                .is_err()
        );
        assert!(std::ptr::eq(original.failure().unwrap(), first));
        assert!(std::ptr::eq(
            original.flights[0].operation.as_ref().unwrap(),
            prepare
        ));
        assert_eq!(original.flights[0].reached, reached);
        assert_eq!(original.ledger.charged(), charged);
    }

    #[test]
    fn overdraw_keeps_actual_first_error_and_independently_owed_post() {
        let mut original = retained_original();
        let charged = original.ledger.charged();
        original
            .begin_availability_interval_v2(
                request(1),
                request(2),
                ResourceVector::ZERO.with(D::NetworkBytes, 12),
            )
            .unwrap();

        assert!(
            original
                .require_availability_interval_v2(
                    request(1),
                    request(2),
                    ResourceVector::ZERO.with(D::NetworkBytes, 10_001)
                )
                .is_err()
        );
        let first = original.failure().unwrap() as *const dyn std::error::Error;
        assert!(
            original
                .failure()
                .unwrap()
                .downcast_ref::<AccountingError>()
                .is_some()
        );
        assert!(
            original
                .require_availability_interval_v2(request(1), request(2), ResourceVector::ZERO)
                .is_err()
        );

        assert!(std::ptr::eq(original.failure().unwrap(), first));
        assert!(
            original
                .require_availability_owed_v2(request(1), request(2))
                .is_ok()
        );
        assert!(
            original
                .finish_availability_native_v2(request(1), request(2))
                .is_err()
        );
        assert!(
            original
                .finish_availability_authenticated_v2(request(1), request(2))
                .is_err()
        );
        assert_eq!(original.flights[0].reached.get(D::NetworkBytes), 12);
        assert!(
            original.flights[0]
                .operation
                .as_ref()
                .unwrap()
                .is_consumed_current()
        );
        assert_eq!(original.ledger.charged(), charged);
    }

    #[test]
    fn terminal_no_apply_ends_only_descriptor_liability_after_exact_authenticated_ack() {
        let mut original = retained_original();
        let charged = original.ledger.charged();
        original.begin_availability_interval_v2(request(1), request(2),
            ResourceVector::ZERO.with(D::MemoryBytes, 80)
                .with(D::NetworkBytes, 12).with(D::OpenFiles, 5)).unwrap();
        original.finish_availability_native_v2(request(1), request(2)).unwrap();

        assert!(original.require_no_apply_terminal_disposal_v2(request(1), request(2)).is_err());
        original.finish_availability_authenticated_v2(request(1), request(2)).unwrap();
        assert!(original.require_no_apply_terminal_disposal_v2(request(1), request(3)).is_err());
        let reached = original.flights[0].reached;
        let current = original.flights[0].current;
        original.complete_no_apply_terminal_disposal_v2(request(1), request(2)).unwrap();

        assert_eq!(original.flights[0].reached, reached);
        assert_eq!(original.flights[0].current, current.with(D::OpenFiles, 0));
        assert_eq!(original.ledger.charged(), charged);
        assert!(original.flights[0].operation.is_none());
        assert!(original.flights[0].availability_interval.is_none());
        assert!(original.require_no_apply_terminal_disposal_v2(request(1), request(2)).is_err());
    }
}

impl HostExecutionReceivingV2 {
    pub(in crate::plan::deployment::control) fn require_no_apply_terminal_disposal_v2(
        &self, prepare: Request, ack: Request,
    ) -> Result<(), Closed> {
        let before = &self.flights[Phase::Prepare.index()];
        let intervals = before.availability_interval.as_ref().ok_or(Closed)?;
        if self.closed || self.active != Some(Phase::Prepare) || self.prepared.is_some()
            || before.request != Some(prepare) || !before.native_positive
            || !before.operation.as_ref().is_some_and(|operation| operation.is_consumed_current())
            || !matches!(before.representation, Some(Ok(_)))
            || !intervals.authenticated || intervals.current.is_some()
            || !intervals.native_positive || intervals.prepared.is_some() || intervals.accept.is_some()
            || intervals.requests.last() != Some(&ack)
            || ack.session != prepare.session
            || self.flights[Phase::Accept.index()].operation.is_some()
        { return Err(Closed); }
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn complete_no_apply_terminal_disposal_v2(
        &mut self, prepare: Request, ack: Request,
    ) -> Result<(), Closed> {
        self.require_no_apply_terminal_disposal_v2(prepare, ack)?;
        let before = &mut self.flights[Phase::Prepare.index()];
        before.operation.take().ok_or(Closed)?.complete_after_disposal();
        // The same permanent account keeps every reached peak and spent byte.
        before.current = before.current.with(D::OpenFiles, 0);
        before.worker_current_files = 0;
        before.request = None;
        before.native_positive = false;
        before.representation = None;
        before.availability_interval = None;
        self.active = None;
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn retain_authenticated_availability_preparation_v2(
        &mut self,
        original: Request,
        preparation: Request,
    ) -> Result<(), Closed> {
        self.require_availability_owed_v2(original, preparation)?;
        let intervals = self.flights[Phase::Prepare.index()]
            .availability_interval
            .as_ref()
            .ok_or(Closed)?;
        if self.closed
            || !intervals.native_positive
            || intervals.prepared.is_some()
            || intervals.accept.is_some()
            || preparation.session != original.session
        {
            return Err(Closed);
        }
        self.finish_availability_authenticated_v2(original, preparation)?;
        self.flights[Phase::Prepare.index()]
            .availability_interval
            .as_mut()
            .ok_or(Closed)?
            .prepared = Some(preparation);
        self.prepared = Some(preparation);
        Ok(())
    }

    // The same HostService ledger already reserved both complete declarations.
    // Enter20 without releasing19's still-owned four writers or native prefix.
    pub(in crate::plan::deployment::control) fn begin_accept_with_retained_availability_v2(
        &mut self,
        original: Request,
        preparation: Request,
        accept: Request,
        actual: ResourceVector,
    ) -> Result<(), Closed> {
        let before = &self.flights[Phase::Prepare.index()];
        let intervals = before.availability_interval.as_ref().ok_or(Closed)?;
        if self.closed
            || self.active != Some(Phase::Prepare)
            || self.prepared != Some(preparation)
            || before.request != Some(original)
            || !before.native_positive
            || !before
                .operation
                .as_ref()
                .is_some_and(|operation| operation.is_consumed_current())
            || !matches!(before.representation, Some(Ok(_)))
            || !intervals.authenticated
            || intervals.current.is_some()
            || intervals.prepared != Some(preparation)
            || intervals.accept.is_some()
            || accept.id == [0; 16]
            || accept.signed == [0; 32]
            || accept.session != original.session
            || preparation.session != original.session
            || accept.id == original.id
            || intervals
                .requests
                .iter()
                .any(|request| request.id == accept.id)
        {
            return Err(Closed);
        }
        let next = &mut self.flights[Phase::Accept.index()];
        if next
            .begin_consumed_v2(accept)
            .and_then(|()| next.require_amount_v2(actual))
            .is_err()
        {
            self.closed = true;
            return Err(Closed);
        }
        self.flights[Phase::Prepare.index()]
            .availability_interval
            .as_mut()
            .ok_or(Closed)?
            .accept = Some(accept);
        self.active = Some(Phase::Accept);
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn require_retained_availability_accept_v2(
        &self,
        accept: Request,
    ) -> Result<(), Closed> {
        let before = &self.flights[Phase::Prepare.index()];
        let Some(intervals) = &before.availability_interval else {
            return Ok(());
        };
        let original = before.request.ok_or(Closed)?;
        if intervals.accept != Some(accept)
            || intervals.current.is_some()
            || !intervals.authenticated
            || intervals.prepared.is_none()
            || intervals.prepared != self.prepared
            || !before.native_positive
            || !matches!(before.representation, Some(Ok(_)))
            || !before
                .operation
                .as_ref()
                .is_some_and(|operation| operation.is_consumed_current())
            || original.session != accept.session
        {
            return Err(Closed);
        }
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn retained_prepare_for_accept_v2(
        &self,
        accept: Request,
    ) -> Result<Option<Request>, Closed> {
        self.require_retained_availability_accept_v2(accept)?;
        let before = &self.flights[Phase::Prepare.index()];
        Ok(before.availability_interval.as_ref().and(before.request))
    }

    pub(in crate::plan::deployment::control) fn mark_availability_original_v2(
        &mut self,
        original: Request,
    ) -> Result<(), Closed> {
        let slot = &mut self.flights[Phase::Prepare.index()];
        if self.closed
            || self.active != Some(Phase::Prepare)
            || slot.request != Some(original)
            || slot.availability_interval.is_some()
            || slot.native_positive
            || !slot
                .operation
                .as_ref()
                .is_some_and(|operation| operation.is_consumed_current())
        {
            return Err(Closed);
        }
        slot.availability_interval = Some(AvailabilityIntervalsV2 {
            authenticated: false,
            requests: Vec::new(),
            allocation: None,
            current: None,
            native_positive: false,
            prepared: None,
            accept: None,
        });
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn is_availability_original_v2(
        &self,
        original: Request,
    ) -> bool {
        let slot = &self.flights[Phase::Prepare.index()];
        slot.request == Some(original) && slot.availability_interval.is_some()
    }

    pub(in crate::plan::deployment::control) fn retain_authenticated_availability_v2(
        &mut self,
        original: Request,
    ) -> Result<(), Closed> {
        let slot = &mut self.flights[Phase::Prepare.index()];
        if self.closed
            || self.active != Some(Phase::Prepare)
            || slot.request != Some(original)
            || !slot.native_positive
            || slot.availability_interval.is_none()
            || !slot
                .operation
                .as_ref()
                .is_some_and(|operation| operation.is_consumed_current())
        {
            return Err(Closed);
        }
        let intervals = slot.availability_interval.as_mut().ok_or(Closed)?;
        if intervals.authenticated {
            return Err(Closed);
        }
        intervals.authenticated = true;
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn availability_history_demand_v2(
        &self,
        original: Request,
    ) -> Result<ResourceVector, Closed> {
        let slot = &self.flights[Phase::Prepare.index()];
        let intervals = slot.availability_interval.as_ref().ok_or(Closed)?;
        if slot.request != Some(original) || !intervals.authenticated || intervals.current.is_some()
        {
            return Err(Closed);
        }
        let bytes = intervals
            .requests
            .len()
            .checked_add(1)
            .and_then(|length| length.checked_mul(std::mem::size_of::<Request>()))
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(Closed)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    pub(super) fn availability_allocation_failure_v2(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        self.flights[Phase::Prepare.index()]
            .availability_interval
            .as_ref()?
            .allocation
            .as_ref()?
            .as_ref()
            .err()
            .map(|cause| cause as _)
    }

    pub(in crate::plan::deployment::control) fn begin_availability_interval_v2(
        &mut self,
        original: Request,
        request: Request,
        actual: ResourceVector,
    ) -> Result<(), Closed> {
        let slot = &mut self.flights[Phase::Prepare.index()];
        let intervals = slot.availability_interval.as_ref().ok_or(Closed)?;
        if self.closed
            || self.active != Some(Phase::Prepare)
            || slot.request != Some(original)
            || !slot.native_positive
            || !intervals.authenticated
            || intervals.current.is_some()
            || intervals.allocation.as_ref().is_some_and(Result::is_err)
            || request.id == [0; 16]
            || request.session == [0; 32]
            || request.signed == [0; 32]
            || request.id == original.id
            || intervals
                .requests
                .iter()
                .any(|prior| prior.id == request.id)
            || !slot
                .operation
                .as_ref()
                .is_some_and(|operation| operation.is_consumed_current())
            || slot.representation.as_ref().is_some_and(Result::is_err)
        {
            return Err(Closed);
        }
        if slot.require_amount_v2(actual).is_err() {
            self.closed = true;
            return Err(Closed);
        }

        let intervals = slot.availability_interval.as_mut().ok_or(Closed)?;
        intervals.allocation = Some(intervals.requests.try_reserve_exact(1));
        if !matches!(intervals.allocation, Some(Ok(()))) {
            self.closed = true;
            return Err(Closed);
        }
        intervals.requests.push(request);
        intervals.current = Some(request);
        intervals.native_positive = false;
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn require_availability_interval_v2(
        &mut self,
        original: Request,
        request: Request,
        actual: ResourceVector,
    ) -> Result<(), Closed> {
        self.require_availability_owed_v2(original, request)?;
        let slot = &mut self.flights[Phase::Prepare.index()];
        if self.closed
            || slot.representation.as_ref().is_some_and(Result::is_err)
            || slot
                .availability_interval
                .as_ref()
                .is_none_or(|intervals| intervals.native_positive)
        {
            return Err(Closed);
        }
        if slot.require_amount_v2(actual).is_err() {
            self.closed = true;
            return Err(Closed);
        }
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn require_availability_owed_v2(
        &self,
        original: Request,
        request: Request,
    ) -> Result<(), Closed> {
        let slot = &self.flights[Phase::Prepare.index()];
        if self.active != Some(Phase::Prepare)
            || slot.request != Some(original)
            || !slot
                .operation
                .as_ref()
                .is_some_and(|operation| operation.is_consumed_current())
            || !slot
                .availability_interval
                .as_ref()
                .is_some_and(|intervals| {
                    intervals.authenticated && intervals.current == Some(request)
                })
        {
            return Err(Closed);
        }
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn finish_availability_native_v2(
        &mut self,
        original: Request,
        request: Request,
    ) -> Result<(), Closed> {
        self.require_availability_owed_v2(original, request)?;
        let intervals = self.flights[Phase::Prepare.index()]
            .availability_interval
            .as_mut()
            .ok_or(Closed)?;
        if self.closed || intervals.native_positive {
            return Err(Closed);
        }
        intervals.native_positive = true;
        Ok(())
    }

    pub(in crate::plan::deployment::control) fn finish_availability_authenticated_v2(
        &mut self,
        original: Request,
        request: Request,
    ) -> Result<(), Closed> {
        self.require_availability_owed_v2(original, request)?;
        let intervals = self.flights[Phase::Prepare.index()]
            .availability_interval
            .as_mut()
            .ok_or(Closed)?;
        if self.closed || !intervals.native_positive {
            return Err(Closed);
        }
        intervals.current = None;
        Ok(())
    }
}
