//! Lends the issued worker's same parent clocks to its retained transport.
//!
//! These ports neither export the loan nor adopt a source. Positive transport
//! uses the original9/63 worker lane; disabling cleanup uses only its already
//! prearmed destinations, including after a financial or body refusal.

use super::*;
use aos_sandbox_linux::seqpacket::NetworkWorkerNativeCutoffV4;

impl NetworkWorkerBirthReservationV2<'_, '_> {
    /// Borrows native bootstrap affinity DATA from this same issued programme.
    ///
    /// The native PREPARED producer already bound these coordinates to the
    /// paid PREBIRTH. This snapshot grants no Source, birth admission, current
    /// lease or effect; each later native and signed check remains mandatory.
    #[must_use]
    pub fn child_operation_binding_data_v2(
        &self,
    ) -> Option<crate::receiving::NetworkChildOperationBindingDataV2> {
        if self.original.first.is_some() || !self.original.prebirth_ready {
            return None;
        }
        self.operation_binding_data()
    }

    /// Borrows original coordinates solely for issued negative disposition.
    ///
    /// A fully bound native donation must already exist. This DATA borrow can
    /// correlate its negative/ACK after primary poison; it grants no Source,
    /// ARM, currentness, positive completion or renewed deadline.
    #[must_use]
    pub fn issued_child_operation_binding_data_v2(
        &self,
    ) -> Option<crate::receiving::NetworkChildOperationBindingDataV2> {
        birth::BirthOriginalV2::issued_original(&self.original.birth, &self.original.owed_birth)?;
        self.operation_binding_data()
    }

    fn operation_binding_data(&self) -> Option<crate::receiving::NetworkChildOperationBindingDataV2> {
        let prepared = self.original.prepared.completed_payload_data()?;
        let request = &self.original.prebirth;
        Some(crate::receiving::NetworkChildOperationBindingDataV2 {
            purpose: request[10],
            boot: request[16..32].try_into().ok()?,
            source_invocation: request[32..48].try_into().ok()?,
            worker_invocation: prepared[96..112].try_into().ok()?,
            prebirth_digest: prepared[64..96].try_into().ok()?,
            request_id: request[80..96].try_into().ok()?,
            effect_digest: request[96..128].try_into().ok()?,
            operation_ordinal: u64::from_be_bytes(request[128..136].try_into().ok()?),
            native_limits: self.original.selected_native_limits_data_v2(self.original.purpose?)?,
            source_probe_count: u64::from_be_bytes(request[136..144].try_into().ok()?),
        })
    }

    /// Borrows the same parent's original selected native or financial cause.
    ///
    /// This diagnostic borrow preserves ownership on the actual loan. It
    /// exports neither the mutable loan nor a replacement account or source.
    #[must_use]
    pub fn parent_worker_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.loan.failure()
    }

    /// Samples this issued worker's existing paid parent effect frontier.
    ///
    /// # Errors
    /// Preserves wrong-purpose, original Source, financial and clock refusals.
    pub fn observe_parent_worker_clock_v2(
        &mut self,
    ) -> Result<RawPairedClockSample, FixedServiceOperationClosedV4> {
        self.loan.observe_network_worker_effect_clock_v4()
    }

    /// Borrows the same original BOOTTIME and signed WALL transport ceilings.
    ///
    /// This comparison DATA samples no clock, renews no deadline and admits no
    /// worker effect. The caller still owes its separate paid native frontier.
    ///
    /// # Errors
    /// Refuses another purpose, incomplete parent entry or a failed interval.
    pub fn parent_worker_cutoff_data_v2(
        &mut self,
    ) -> Result<NetworkWorkerNativeCutoffV4, FixedServiceOperationClosedV4> {
        self.loan.require_network_worker_current_v4()?;
        let (baseline, deadline) = self.loan.operation.clock.retained_interval_data_v4()?;
        let wall = self.loan.operation.clock.retained_wall_ceiling_data_v4()?;
        Ok(NetworkWorkerNativeCutoffV4::new(
            baseline.boottime_nanoseconds(),
            baseline.wall_seconds(),
            deadline,
            wall,
        ))
    }

    /// Prearms the actual operation's one shared P/O disabling-cleanup scope.
    ///
    /// The caller retains this scope across both genuine worker reservations;
    /// its second child cannot manufacture another prearm or additional slots.
    ///
    /// # Errors
    /// Preserves wrong purpose, incomplete entry, repeated prearm and poison.
    pub fn prearm_parent_worker_cleanup_once_v2(
        &mut self,
    ) -> Result<NetworkWorkerCleanupClockScopeV4, FixedServiceOperationClosedV4> {
        self.loan.prearm_network_worker_cleanup_once_v4()
    }

    /// Samples an already-owed disabling frontier on the same original parent.
    ///
    /// Financial and body failures cannot suppress that prearmed destination.
    /// The original deadline, native clock failure and two-slot bound still
    /// apply. This grants no positive worker, refund or subsequent admission.
    ///
    /// # Errors
    /// Preserves foreign scope, exhausted slot, completed owner or clock error.
    pub fn observe_owed_parent_worker_cleanup_clock_v2(
        &mut self,
        scope: &mut NetworkWorkerCleanupClockScopeV4,
    ) -> Result<RawPairedClockSample, FixedServiceOperationClosedV4> {
        self.loan.observe_owed_network_worker_cleanup_clock_v4(scope)
    }
}

impl<'held, 'financial> NetworkWorkerBirthReservationV2<'held, 'financial> {
    /// Lends issued native cleanup pins beside their same prearmed parent loan.
    ///
    /// The scoped callback enters the existing retained quiescence recipe. It
    /// parks its complete native result and independently owed observations on
    /// the caller's original before projecting this marker. The reservation
    /// retains all PIDFD, cgroup and events custody throughout the call; no
    /// descriptor duplication, source construction or loan escape is possible.
    ///
    /// Positive parent capability is fenced before entry, including on unwind.
    /// This borrow grants only the already issued child's negative disposition.
    /// The separate terminal send still requires actual death and Empty/Retired.
    ///
    /// # Errors
    /// Refuses absent issued native custody, a foreign or exhausted prearm,
    /// repeated entry, native clock posts, or the retained cleanup refusal.
    pub fn with_issued_birth_cleanup_once_v2(
        &mut self,
        scope: &mut NetworkWorkerCleanupClockScopeV4,
        body: impl FnOnce(
            &aos_linux_descriptors::pidfd::PidFd,
            &aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
            &aos_sandbox_linux::cgroup::CgroupPopulationMonitor,
            &mut FixedServiceOperationLoanV4<'financial>,
            &mut NetworkWorkerCleanupClockScopeV4,
        ) -> Result<(), FixedServiceOperationClosedV4>,
    ) -> Result<(), FixedServiceOperationClosedV4> {
        let operation = &self.loan.operation;
        let same_scope = scope.operation_address == std::ptr::from_ref(&**operation).addr()
            && Some(scope.operation_ordinal) == operation.operation_ordinal
            && scope.operation_ordinal == self.loan.common.operation_ordinal
            && Some(scope.invocation) == operation.invocation
            && operation.invocation == self.loan.common.enrollment.map(|value| value.recipient_invocation)
            && operation.worker_cleanup_prearmed && scope.used == 0
            && operation.armed && !operation.finished && self.loan.common.operation_active
            && matches!(operation.purpose, Some(Purpose::NetworkPrepare | Purpose::NetworkDestroy));
        let pins = birth::BirthOriginalV2::issued_original(&self.original.birth, &self.original.owed_birth).and_then(|birth| {
            birth.issued_packet_data()?;
            birth.retained_native_data()
        });
        if self.original.cleanup_entered || !same_scope || pins.is_none() {
            self.original.first.get_or_insert(First::Cleanup);
            return Err(self.loan.refuse_network_worker_birth_v2(Failure::Order));
        }
        let Some((process, anchor, monitor)) = pins else {
            return Err(self.loan.refuse_network_worker_birth_v2(Failure::Order));
        };

        self.original.cleanup_entered = true;
        let earlier = self.original.first;
        self.original.first.get_or_insert(First::Cleanup);
        self.loan.common.operation_closed = true;
        self.loan.operation.fail(Failure::Body);
        // This single issued disposition consumes the already prearmed finite
        // programme, whose shared native engine permits at most two writes.
        scope.used = 2;
        let boot = self.original.prebirth[16..32].try_into()
            .map_err(|_| FixedServiceOperationClosedV4)?;
        self.original.issued_cleanup = Some(issued_cleanup::IssuedCleanupOriginalV2::new(boot));
        let Some(cleanup) = self.original.issued_cleanup.as_mut() else {
            return Err(FixedServiceOperationClosedV4);
        };
        let mut after = issued_cleanup::CleanupAfterV2(cleanup);
        after.0.observe_before();
        // A native clock refusal is retained, but cannot suppress containment
        // of this already-issued exact child. No positive clock is restored.
        self.original.cleanup_result = Some(body(process, anchor, monitor, &mut *self.loan, scope));
        after.0.observe_after();
        let clock_failed = after.0.failure().is_some();
        drop(after);
        if matches!(self.original.cleanup_result, Some(Ok(()))) && !clock_failed {
            self.original.first = earlier;
            Ok(())
        } else {
            Err(FixedServiceOperationClosedV4)
        }
    }

    /// Borrows the independently retained issued-cleanup native clock cause.
    ///
    /// The ordinary getter continues to select the earlier primary cause.
    #[must_use]
    pub fn issued_cleanup_clock_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.original.issued_cleanup.as_ref()?.failure()
    }
}
