//! Consumes three declared Host execution purposes under the same original.
//!
//! The parent constructs this private owner only from its actual admitted
//! immutable profile and genuine fixed Parent/native/PID1 joins. The selected
//! image binds Prepare/Accept to its existing purposes19/20 and declares the
//! Launch subdivision inside that same HostService account. All three are
//! subtracted from its committed service baseline. A request selects only its
//! named slot in this one ledger, never an amount,
//! account or replacement budget. Each complete flight vector is once-consumed
//! before native/codec construction. Its permanently held declaration permits
//! slot reuse only after whole authenticated completion and positive disposal;
//! failed, pending or ambiguous operations remain resident and cannot reuse.

pub(super) mod monitor_interval;
pub(super) mod query_interval;
pub(super) mod availability_interval;
mod terminal_stage;
mod physical_fit;
pub(super) mod resident_stop;
mod terminal_inventory;
mod cleanup_flight;
pub(in crate::plan::deployment::control) use cleanup_flight::ControlCleanupPurposeV1;
pub(crate) use cleanup_flight::HostControlCleanupTokenV1;
mod catalogpub;
pub(super) mod stop_containment;

use aos_sandbox_broker::receiving::ComponentReceivingOwnedOperationV1;
use aos_sandbox_core::component_receiving::ComponentServiceReceivingLedgerV1;
use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExecutionReceivingProfileV2 {
    prepare: [u64; 22],
    accept: [u64; 22],
    // This image-bound partition comes out of the existing Host baseline.
    // It creates no extra HostService or top-level Bank claim.
    launch: [u64; 22],
    // The normal prelisten producer remains inside this same prepaid whole.
    boot_preparation: Option<[u64; 22]>,
}

impl ExecutionReceivingProfileV2 {
    pub(super) const fn prepare_vector(self) -> ResourceVector {
        ResourceVector::new(self.prepare)
    }

    pub(super) const fn accept_vector(self) -> ResourceVector {
        ResourceVector::new(self.accept)
    }

    pub(super) const fn launch_vector(self) -> ResourceVector {
        ResourceVector::new(self.launch)
    }

    pub(super) const fn boot_preparation_vector_v1(self) -> Option<ResourceVector> {
        match self.boot_preparation {
            Some(amount) => Some(ResourceVector::new(amount)),
            None => None,
        }
    }

    pub(super) fn require_subdivision(self, service: ResourceVector) -> Result<(), Closed> {
        let prepare = ResourceVector::new(self.prepare);
        let accept = ResourceVector::new(self.accept);
        if self.boot_preparation_vector_v1().is_some_and(|amount|
            [D::CpuMicrosPerPeriod, D::MemoryBytes, D::Pids, D::OpenFiles].into_iter()
                .any(|dimension| amount.get(dimension) == 0)
                || amount.get(D::ConcurrentOperations) != 1)
        {
            return Err(Closed);
        }
        let combined = prepare.checked_add(accept)
            .and_then(|amount| amount.checked_add(self.launch_vector()))
            .and_then(|amount| amount.checked_add(self.boot_preparation_vector_v1().unwrap_or(ResourceVector::ZERO)))
            .map_err(|_| Closed)?;
        let complement = service.checked_sub(combined).map_err(|_| Closed)?;
        for amount in [prepare, accept, self.launch_vector()] {
            if amount.get(D::MemoryBytes) == 0 || amount.get(D::OpenFiles) == 0
                || amount.get(D::ConcurrentOperations) == 0
            {
                return Err(Closed);
            }
        }
        if complement.get(D::Pids) == 0 || complement.get(D::MemoryBytes) == 0
            || complement.get(D::OpenFiles) == 0
        {
            return Err(Closed);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Phase {
    Prepare,
    Accept,
    Launch,
}

impl Phase {
    pub(super) const fn index(self) -> usize {
        match self {
            Self::Prepare => 0,
            Self::Accept => 1,
            Self::Launch => 2,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Request {
    pub(crate) id: [u8; 16],
    pub(crate) session: [u8; 32],
    pub(crate) signed: [u8; 32],
}

// Two real authenticated mutations follow Accept on this same consumed
// purpose20: sealed Authorize and its first Observe. Their Session responses
// each complete separately; neither can remint the enclosing operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AcceptedContinuationV2 { Authorize, Observe }

impl AcceptedContinuationV2 {
    pub(super) const fn index(self) -> usize {
        match self { Self::Authorize => 0, Self::Observe => 1 }
    }
}

struct ContinuationFlightV2 {
    request: Option<Request>,
    native_positive: bool,
    authenticated_positive: bool,
}

impl ContinuationFlightV2 {
    fn new() -> Self {
        Self { request: None, native_positive: false, authenticated_positive: false }
    }
}

struct Flight {
    capacity: ResourceVector,
    operation: Option<ComponentReceivingOwnedOperationV1>,
    request: Option<Request>,
    reached: ResourceVector,
    // Reached remains the historical peak. Only actual closed disposal can
    // reduce this current native liability while retaining the same operation.
    current: ResourceVector,
    worker_current_files: u64,
    worker_compensation_files: Option<u64>,
    traffic_before_operation: ResourceVector,
    operation_requirement: ResourceVector,
    resident_stop: Option<resident_stop::ResidentStopFlightV4>,
    representation: Option<Result<ResourceVector, AccountingError>>,
    native_positive: bool,
    authenticated_accept: bool,
    continuations: [ContinuationFlightV2; 2],
    active_continuation: Option<AcceptedContinuationV2>,
    capture_negative: Option<CaptureNegativeFlightV3>,
    monitor_interval: Option<monitor_interval::ExecutionMonitorFlightV5>,
    query_interval: Option<query_interval::ExecutionQueryFlightV3>,
    availability_interval: Option<availability_interval::AvailabilityIntervalsV2>,
}

impl Flight {
    fn begin_consumed_v2(&mut self, request: Request) -> Result<(), Closed> {
        if self.request.is_some() || self.operation.is_some() { return Err(Closed); }
        self.traffic_before_operation = aos_sandbox_core::component_receiving::operation_traffic_demand_v1(self.reached);
        self.operation_requirement = ResourceVector::ZERO;
        self.request = Some(request);
        self.operation = Some(ComponentReceivingOwnedOperationV1::preflight(self.capacity, self.capacity));
        self.operation.as_mut().ok_or(Closed)?.consume_once().map_err(|_| Closed)
    }

    fn new(capacity: ResourceVector) -> Self {
        Self {
            capacity,
            operation: None,
            request: None,
            reached: ResourceVector::ZERO,
            current: ResourceVector::ZERO,
            worker_current_files: 0,
            worker_compensation_files: None,
            traffic_before_operation: ResourceVector::ZERO,
            operation_requirement: ResourceVector::ZERO,
            resident_stop: None,
            representation: None,
            native_positive: false,
            authenticated_accept: false,
            continuations: std::array::from_fn(|_| ContinuationFlightV2::new()),
            active_continuation: None, capture_negative: None, monitor_interval: None, query_interval: None,
            availability_interval: None,
        }
    }

    // All subintervals use this same bound. The original operation stays
    // consumed, the native peak never decreases, and cumulative traffic is
    // charged against its existing declaration before any subsequent growth.
    fn require_amount_v2(&mut self, actual: ResourceVector) -> Result<(), Closed> {
        let requirement = self.operation_requirement.componentwise_max(actual);
        let reached = {
            use aos_sandbox_core::component_receiving::{
                operation_traffic_demand_v1, without_operation_traffic_v1,
            };
            without_operation_traffic_v1(self.reached)
                .componentwise_max(without_operation_traffic_v1(requirement))
                .checked_add(self.traffic_before_operation
                    .checked_add(operation_traffic_demand_v1(requirement)).map_err(|_| Closed)?)
                .map_err(|_| Closed)?
        };
        self.representation = Some(self.capacity.checked_sub(reached));
        if !matches!(self.representation, Some(Ok(_))) { return Err(Closed); }
        self.reached = reached;
        self.operation_requirement = requirement;
        self.current = self.current.componentwise_max(actual);
        Ok(())
    }

    fn enter_worker_files_v4(
        &mut self,
        phase: &crate::worker::launch::HostLaunchWorkerPhaseV4,
    ) -> Result<(), Closed> {
        let worker_files = u64::try_from(phase.current_native_files_v4()).map_err(|_| Closed)?;
        let current_files = self.current.get(D::OpenFiles)
            .checked_sub(self.worker_current_files)
            .and_then(|base| base.checked_add(worker_files)).ok_or(Closed)?;
        let current = self.current.with(D::OpenFiles, current_files);
        let reached = self.reached.componentwise_max(current);
        self.representation = Some(self.capacity.checked_sub(reached));
        if !matches!(self.representation, Some(Ok(_))) {
            return Err(Closed);
        }

        // The worker alone constructs phases after its actual predecessor
        // disposal gates. Only its native FD term changes here. Every previous
        // peak, other dimension, and consumed operation remains in this flight.
        if phase.compensation_prearm_v1() {
            self.worker_compensation_files = Some(worker_files);
        }
        self.worker_current_files = worker_files;
        self.current = current;
        self.reached = reached;
        Ok(())
    }

}

// This is the same Launch flight's prearmed retained-disposition liability.
// Neither its token nor its demand may authorize a positive execution action.
struct CaptureNegativeFlightV3 {
    identity: std::sync::Arc<()>,
    source: aos_sandbox_core::ObjectDigest,
    execution: aos_sandbox_core::ExecutionId,
    accept: Request,
    requirement: ResourceVector,
    entry: CaptureNegativeEntryV3,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CaptureNegativeEntryV3 { Armed, Entered }

pub(super) struct CaptureNegativeReservationV3 {
    identity: std::sync::Arc<()>,
    pub(super) source: aos_sandbox_core::ObjectDigest,
    pub(super) execution: aos_sandbox_core::ExecutionId,
    launch: Request,
    accept: Request,
}

impl CaptureNegativeReservationV3 {
    pub(in crate::plan::deployment::control) fn launch_for_stop_v4(&self) -> Request { self.launch }

    pub(in crate::plan::deployment::control) fn accept_for_stop_v4(&self) -> Request { self.accept }
}

pub(super) struct HostExecutionReceivingV2 {
    ledger: ComponentServiceReceivingLedgerV1,
    reservation: Result<(), Closed>,
    baseline_capacity: ResourceVector,
    baseline_requirement: Option<Result<ResourceVector, AccountingError>>,
    flights: [Flight; 3],
    control_capacity: ResourceVector,
    control_operation: Option<ComponentReceivingOwnedOperationV1>,
    control_requirement: Option<Result<ResourceVector, AccountingError>>,
    // Armed only by the real Phase0 constructor, never from a supplied budget.
    physical_baseline: Option<crate::Result<ResourceVector>>,
    physical_requirement: Option<Result<ResourceVector, AccountingError>>,
    stop_containment: Option<stop_containment::StopContainmentFlightV4>,
    stop_admission: Option<stop_containment::StopAdmissionFlightV4>,
    cleanup: Option<cleanup_flight::ControlCleanupFlightV1>,
    execution_admitted: bool,
    active: Option<Phase>,
    prepared: Option<Request>,
    closed: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("Host execution receiving is closed")]
pub(super) struct Closed;

impl HostExecutionReceivingV2 {
    // Fixed Parent delivery prearms bounded bootstrap receiving only. No
    // execution can enter until the SAME owner passes its complete native joins.
    pub(super) fn from_capture_prelude_v2(original: &super::HostComponentControlStartupV2)
        -> Result<Self, Closed>
    {
        if !original.has_capture_prelude_v2() {
            return Err(Closed);
        }
        let profile = original.profile.as_ref().ok_or(Closed)?;
        let receiving = profile.host_execution_receiving.ok_or(Closed)?;
        let mut owner = Self::from_reserved_subdivisions(
            ResourceVector::new(profile.host_service), receiving,
            ResourceVector::new(profile.host_control),
        )?;
        owner.execution_admitted = false;
        Ok(owner)
    }

    pub(super) fn require_complete_original(original: &super::HostComponentControlStartupV2)
        -> Result<(), Closed>
    {
        if !original.capture_attempted || !original.admission_attempted
            || original.used != 2 || !original.armed || original.admitted
            || original.transferred || original.first.is_some()
            || !original.attempts[1].action.as_ref().is_some_and(Result::is_ok)
        {
            return Err(Closed);
        }
        original.profile.as_ref().and_then(|profile| profile.host_execution_receiving)
            .ok_or(Closed)?;
        // Both actual pair calls were reached only after the real PID1
        // producer/recipient readbacks. Their native originals remain here;
        // this is not the public consuming pair-comparison adapter.
        for slot in 0..2 {
            if !original.attempts[1].pair[slot].as_ref().is_some_and(Result::is_ok)
                || !original.attempts[1].pair_originals[slot].as_ref()
                    .is_some_and(|pair| pair.failure().is_none() && pair.policy_commitment().is_some())
            {
                return Err(Closed);
            }
        }
        Ok(())
    }

    pub(super) fn consume_control_once(&mut self, actual: ResourceVector) -> Result<(), Closed> {
        if self.closed || self.reservation.is_err() || self.control_operation.is_some() || self.execution_admitted {
            self.closed = true;
            return Err(Closed);
        }
        self.control_requirement = Some(self.control_capacity.checked_sub(actual));
        if !matches!(self.control_requirement, Some(Ok(_))) {
            self.closed = true;
            return Err(Closed);
        }
        // The complete finite Control vector is consumed once. The smaller
        // representation requirement is a separate check, never new currency.
        self.control_operation = Some(ComponentReceivingOwnedOperationV1::preflight(
            self.control_capacity, self.control_capacity,
        ));
        if self.control_operation.as_mut().ok_or(Closed)?.consume_once().is_err() {
            self.closed = true;
            return Err(Closed);
        }
        Ok(())
    }

    pub(super) fn extend_control_representation_v2(&mut self, additional: ResourceVector) -> Result<(), Closed> {
        if !self.control_was_consumed() || self.execution_admitted {
            self.closed = true;
            return Err(Closed);
        }
        self.account_control_preparation_v5(additional)
    }

    pub(super) fn has_consumed_control_v2(&self) -> bool {
        self.control_operation.as_ref().is_some_and(|operation| operation.is_consumed_current())
    }

    pub(super) fn control_was_consumed(&self) -> bool {
        !self.closed && self.control_operation.as_ref()
            .is_some_and(|operation| operation.is_consumed_current())
            && matches!(self.control_requirement, Some(Ok(_)))
    }

    pub(super) fn admit_execution_once(&mut self) -> Result<(), Closed> {
        if self.closed || self.execution_admitted
            || !self.control_operation.as_ref().is_some_and(|operation| operation.is_consumed_current())
            || !matches!(self.control_requirement, Some(Ok(_)))
        {
            self.closed = true;
            return Err(Closed);
        }
        self.execution_admitted = true;
        Ok(())
    }

    fn from_reserved_subdivisions(service: ResourceVector, profile: ExecutionReceivingProfileV2,
        control: ResourceVector)
        -> Result<Self, Closed>
    {
        profile.require_subdivision(service)?;
        let prepare = ResourceVector::new(profile.prepare);
        let accept = ResourceVector::new(profile.accept);
        let launch = profile.launch_vector();
        let boot_preparation = profile.boot_preparation_vector_v1().unwrap_or(ResourceVector::ZERO);
        let complement = service.checked_sub(prepare.checked_add(accept)
            .and_then(|amount| amount.checked_add(launch))
            .and_then(|amount| amount.checked_add(boot_preparation)).map_err(|_| Closed)?)
            .map_err(|_| Closed)?;
        let ceiling = service.checked_add(control).map_err(|_| Closed)?;
        let mut ledger = ComponentServiceReceivingLedgerV1::new(ceiling);
        let reservation = (|| {
            ledger.reserve(complement).map_err(|_| Closed)?;
            ledger.reserve(prepare).map_err(|_| Closed)?;
            ledger.reserve(accept).map_err(|_| Closed)?;
            ledger.reserve(launch).map_err(|_| Closed)?;
            ledger.reserve(boot_preparation).map_err(|_| Closed)?;
            ledger.reserve(control).map_err(|_| Closed)
        })();
        Ok(Self {
            ledger,
            reservation,
            baseline_capacity: complement,
            baseline_requirement: None,
            flights: [Flight::new(prepare), Flight::new(accept), Flight::new(launch)],
            control_capacity: control,
            control_operation: None,
            control_requirement: None,
            physical_baseline: None,
            physical_requirement: None,
            stop_containment: None, stop_admission: None, cleanup: None,
            execution_admitted: true,
            active: None,
            prepared: None,
            closed: false,
        })
    }

    // The selected startup calls this before loading/constructing its actual
    // permanent Host model. Launch cannot borrow the unmeasured remainder.
    pub(super) fn require_baseline_before_growth_v2(&mut self, actual: ResourceVector)
        -> Result<(), Closed>
    {
        if self.closed || self.reservation.is_err() || self.baseline_requirement.is_some() {
            self.closed = true;
            return Err(Closed);
        }
        self.baseline_requirement = Some(self.baseline_capacity.checked_sub(actual));
        if !matches!(self.baseline_requirement, Some(Ok(_))) {
            self.closed = true;
            return Err(Closed);
        }
        Ok(())
    }

    // A later state-read entry borrows only the original positive check. It
    // cannot replace the once baseline Result or reserve another remainder.
    pub(super) fn require_prepaid_baseline_v2(&self) -> Result<(), Closed> {
        if self.closed || self.reservation.is_err()
            || !matches!(self.baseline_requirement, Some(Ok(_)))
        {
            return Err(Closed);
        }
        Ok(())
    }

    pub(super) fn begin(&mut self, phase: Phase, request: Request) -> Result<(), Closed> {
        if self.cleanup.is_some() {
            return Err(Closed);
        }
        if self.closed || !self.execution_admitted || self.reservation.is_err() || self.active.is_some()
            || request.id == [0; 16] || request.session == [0; 32] || request.signed == [0; 32]
            || self.flights[phase.index()].request.is_some()
        {
            self.closed = true;
            return Err(Closed);
        }
        if phase == Phase::Launch
            && !matches!(self.baseline_requirement, Some(Ok(_)))
        {
            self.closed = true;
            return Err(Closed);
        }
        if (phase == Phase::Prepare && self.prepared.is_some())
            || (phase == Phase::Accept && self.prepared.is_none_or(|before| {
                before.id == request.id || before.session != request.session
            }))
        {
            self.closed = true;
            return Err(Closed);
        }
        let slot = &mut self.flights[phase.index()];
        // A distinct positive operation may reuse physically disposed native
        // destinations, but its traffic always adds to the same original debt.
        if slot.begin_consumed_v2(request).is_err() {
            self.closed = true;
            return Err(Closed);
        }
        self.active = Some(phase);
        Ok(())
    }

    // The amount is a requirement from this exact native/semantic owner, not
    // an imported grant. The complete capacity was already consumed at begin.
    pub(super) fn require_complete(&mut self, phase: Phase, request: Request,
        actual: ResourceVector) -> Result<(), Closed>
    {
        if self.closed || self.active != Some(phase) { self.closed = true; return Err(Closed); }
        if phase == Phase::Accept { self.require_retained_availability_accept_v2(request)?; }
        let slot = &mut self.flights[phase.index()];
        if slot.request != Some(request) || slot.native_positive
            || !slot.operation.as_ref().is_some_and(|operation| operation.is_consumed_current())
            || slot.representation.as_ref().is_some_and(Result::is_err)
        {
            self.closed = true;
            return Err(Closed);
        }
        if slot.require_amount_v2(actual).is_err() { self.closed = true; return Err(Closed); }
        Ok(())
    }

    /// Retains the actual compiler disposal without lowering the reached peak.
    ///
    /// # Errors
    /// Refuses a closed, different, or completed Launch or a stale proof.
    pub(super) fn retain_compilation_disposal_v2(
        &mut self,
        request: Request,
        disposed: &crate::plan::HostLaunchCompilationDisposedV2,
    ) -> Result<(), Closed> {
        let slot = &mut self.flights[Phase::Launch.index()];
        if self.closed || self.active != Some(Phase::Launch)
            || slot.request != Some(request) || slot.native_positive
            || !matches!(slot.representation, Some(Ok(_)))
            || !slot.operation.as_ref().is_some_and(|operation| operation.is_consumed_current())
            || !disposed.matches_v2((request.id, request.session, request.signed), slot.current)
        {
            self.closed = true;
            return Err(Closed);
        }
        // Only the closed actual compiler-disposal producer can lower this
        // current native liability. The prior peak and consumed operation stay.
        slot.current = disposed.current_demand_v2();
        Ok(())
    }

    /// Checks one actual worker phase against the same consumed Launch.
    ///
    /// # Errors
    /// Refuses another original, an unhealthy flight, or an unaffordable phase.
    /// Any already entered native prefix remains charged on refusal.
    pub(super) fn enter_launch_worker_phase_v4(
        &mut self,
        request: Request,
        phase: &crate::worker::launch::HostLaunchWorkerPhaseV4,
    ) -> Result<(), Closed> {
        let slot = &mut self.flights[Phase::Launch.index()];
        if self.closed || self.active != Some(Phase::Launch)
            || slot.request != Some(request) || slot.native_positive
            || phase.request_identity_v4() != (request.id, request.session, request.signed)
            || !matches!(slot.representation, Some(Ok(_)))
            || !slot.operation.as_ref().is_some_and(|operation| operation.is_consumed_current())
        {
            self.closed = true;
            return Err(Closed);
        }
        if slot.enter_worker_files_v4(phase).is_err() {
            self.closed = true;
            return Err(Closed);
        }
        Ok(())
    }

    // No new comparison/debit occurs here: only the previously successful
    // same-flight prearm can fund this purpose-closed negative suffix.
    pub(super) fn require_launch_compensation_phase_v1(
        &self,
        request: Request,
        phase: &crate::worker::launch::HostLaunchWorkerPhaseV4,
    ) -> Result<(), Closed> {
        self.require_owed_post(Phase::Launch, request)?;
        let slot = &self.flights[Phase::Launch.index()];
        if slot.native_positive || slot.authenticated_accept || phase.compensation_prearm_v1()
            || phase.request_identity_v4() != (request.id, request.session, request.signed)
            || !slot.worker_compensation_files.is_some_and(|paid|
                u64::try_from(phase.current_native_files_v4()).is_ok_and(|actual| actual <= paid))
        {
            return Err(Closed);
        }
        Ok(())
    }

    // The actual parent invokes this only after primary/native and independent
    // posts. The consumed operation remains resident until its real carriers
    // are disposed. This comparison alone releases no receiving obligation.
    pub(super) fn finish_native_positive(&mut self, phase: Phase, request: Request) -> Result<(), Closed> {
        if phase == Phase::Accept { self.require_retained_availability_accept_v2(request)?; }
        if self.closed || self.active != Some(phase) { self.closed = true; return Err(Closed); }
        let slot = &mut self.flights[phase.index()];
        if slot.request != Some(request) || slot.native_positive
            || !matches!(slot.representation, Some(Ok(_)))
        { self.closed = true; return Err(Closed); }
        if !slot.operation.as_ref().is_some_and(|operation| operation.is_consumed_current()) {
            self.closed = true;
            return Err(Closed);
        }
        slot.native_positive = true;
        Ok(())
    }

    // Called only after the SAME whole authenticated interval and its native
    // capsule have completed and disposed. The permanent declaration stays
    // charged; only its bounded positive destination becomes available again.
    pub(super) fn retire_after_disposal(&mut self, phase: Phase, request: Request) -> Result<(), Closed> {
        if matches!(phase, Phase::Prepare | Phase::Accept)
            && self.flights[Phase::Prepare.index()].availability_interval.is_some()
        {
            // Only the whole terminal Stage disposer may end either operation
            // while the retained availability prefix owns those same writers.
            return Err(Closed);
        }
        if phase == Phase::Launch {
            // A launch reply is not terminal runtime/Agent/Capture disposal.
            self.closed = true;
            return Err(Closed);
        }
        if phase == Phase::Accept
            && self.flights[Phase::Launch.index()].capture_negative.is_some()
        {
            // A first Observe cannot retire the financial operation containing
            // an independently prearmed physical Capture lifetime.
            return Err(Closed);
        }
        let slot = &mut self.flights[phase.index()];
        if self.closed || self.active != Some(phase)
            || slot.request != Some(request) || !slot.native_positive
            || (phase == Phase::Accept && slot.authenticated_accept
                && (!slot.continuations[1].authenticated_positive
                    || slot.active_continuation.is_some())) {
            self.closed = true;
            return Err(Closed);
        }
        let operation = slot.operation.take().ok_or(Closed)?;
        operation.complete_after_disposal();
        slot.request = None;
        // The same reservation retains every historical highwater and spent
        // traffic amount. Only the actual disposed current liability ends.
        slot.current = ResourceVector::ZERO;
        slot.worker_current_files = 0;
        slot.worker_compensation_files = None;
        slot.representation = None;
        slot.native_positive = false;
        slot.authenticated_accept = false;
        slot.continuations = std::array::from_fn(|_| ContinuationFlightV2::new());
        slot.active_continuation = None;
        self.active = None;
        self.prepared = match phase {
            Phase::Prepare => Some(request),
            Phase::Accept => None,
            Phase::Launch => self.prepared,
        };
        Ok(())
    }

    // The live channel outlives its launch reply. After actual Sent and
    // scratch disposal, retain the consumed operation in its distinct paid
    // slot while releasing only the temporary exclusive phase borrow.
    pub(super) fn require_pending_launch_v2(&self, request: Request)
        -> Result<(), Closed>
    {
        let slot = &self.flights[Phase::Launch.index()];
        if self.closed || self.active != Some(Phase::Launch)
            || slot.request != Some(request) || !slot.native_positive
            || !slot.operation.as_ref().is_some_and(|operation| operation.is_consumed_current())
            || !matches!(slot.representation, Some(Ok(_)))
        {
            return Err(Closed);
        }
        Ok(())
    }

    pub(super) fn retain_authenticated_launch_v2(&mut self, request: Request) -> Result<(), Closed> {
        self.require_pending_launch_v2(request)?;
        self.active = None;
        Ok(())
    }

    // The only producer follows the actual whole acquisition disposal at
    // authenticated Sent. Its survivor roster cannot erase any historical
    // requirement or traffic and cannot create a new consumed operation.
    pub(super) fn retain_authenticated_launch_native_v4(
        &mut self,
        request: Request,
        disposed: &crate::broker::HostLaunchResidentNativeV4,
    ) -> Result<(), Closed> {
        self.require_pending_launch_v2(request)?;
        let files = u64::try_from(disposed.current_native_files_v4()).map_err(|_| Closed)?;
        let slot = &self.flights[Phase::Launch.index()];
        if disposed.request_identity_v4() != (request.id, request.session, request.signed)
            || files > slot.current.get(D::OpenFiles)
        {
            self.closed = true;
            return Err(Closed);
        }
        self.retain_authenticated_launch_v2(request)?;
        let slot = &mut self.flights[Phase::Launch.index()];
        slot.current = slot.current.with(D::OpenFiles, files);
        slot.worker_current_files = 0;
        slot.worker_compensation_files = None;
        Ok(())
    }

    pub(super) fn require_launch_resident_v2(&self, request: Request) -> Result<(), Closed> {
        let slot = &self.flights[Phase::Launch.index()];
        if self.closed || self.active == Some(Phase::Launch)
            || slot.request != Some(request) || !slot.native_positive
            || !slot.operation.as_ref().is_some_and(|operation| operation.is_consumed_current())
            || !matches!(slot.representation, Some(Ok(_)))
        {
            return Err(Closed);
        }
        Ok(())
    }

    // Invoked only by the sealed SAME request's real CAS/readback/Sent caller.
    // It advances ownership; no operation or representation is released.
    pub(super) fn retain_authenticated_accept_v2(&mut self, request: Request) -> Result<(), Closed> {
        self.require_owed_post(Phase::Accept, request)?;
        let slot = &mut self.flights[Phase::Accept.index()];
        if self.closed || self.active != Some(Phase::Accept)
            || slot.request != Some(request) || !slot.native_positive
            || slot.authenticated_accept
            || !slot.operation.as_ref().is_some_and(|op| op.is_consumed_current())
        { self.closed = true; return Err(Closed); }
        slot.authenticated_accept = true;
        Ok(())
    }

    pub(super) fn begin_accepted_continuation_v2(
        &mut self, stage: AcceptedContinuationV2, original: Request,
        request: Request, actual: ResourceVector,
    ) -> Result<(), Closed> {
        self.require_owed_post(Phase::Accept, original)?;
        let slot = &mut self.flights[Phase::Accept.index()];
        if self.closed || self.active != Some(Phase::Accept)
            || slot.request != Some(original) || !slot.native_positive
            || !slot.authenticated_accept || slot.active_continuation.is_some()
            || request.session != original.session || request.id == original.id
            || request.id == [0; 16] || request.signed == [0; 32]
            || slot.continuations.iter().any(|prior| prior.request.is_some_and(|p| p.id == request.id))
            || !slot.operation.as_ref().is_some_and(|op| op.is_consumed_current())
            || (stage == AcceptedContinuationV2::Observe
                && !slot.continuations[0].authenticated_positive)
            || slot.continuations[stage.index()].request.is_some()
        { self.closed = true; return Err(Closed); }
        slot.continuations[stage.index()].request = Some(request);
        slot.active_continuation = Some(stage);
        let reached = slot.reached.componentwise_max(actual);
        slot.representation = Some(slot.capacity.checked_sub(reached));
        if !matches!(slot.representation, Some(Ok(_))) {
            self.closed = true;
            return Err(Closed);
        }
        slot.reached = reached;
        slot.current = slot.current.componentwise_max(actual);
        Ok(())
    }

    // Later materialization checks stay on the already-consumed Accept slot.
    // Native-positive Accept is not a reason to reject its real continuation,
    // and no smaller request can lower the previously reached liability.
    pub(super) fn require_accepted_continuation_v2(
        &mut self, stage: AcceptedContinuationV2, request: Request, actual: ResourceVector,
    ) -> Result<(), Closed> {
        let original = self.flights[Phase::Accept.index()].request.ok_or(Closed)?;
        self.require_owed_post(Phase::Accept, original)?;
        let slot = &mut self.flights[Phase::Accept.index()];
        if self.closed || self.active != Some(Phase::Accept)
            || slot.active_continuation != Some(stage)
            || slot.continuations[stage.index()].request != Some(request)
            || slot.continuations[stage.index()].native_positive
            || !slot.operation.as_ref().is_some_and(|operation| operation.is_consumed_current())
            || slot.representation.as_ref().is_some_and(Result::is_err)
        {
            self.closed = true;
            return Err(Closed);
        }
        let reached = slot.reached.componentwise_max(actual);
        slot.representation = Some(slot.capacity.checked_sub(reached));
        if !matches!(slot.representation, Some(Ok(_))) {
            self.closed = true;
            return Err(Closed);
        }
        slot.reached = reached;
        slot.current = slot.current.componentwise_max(actual);
        Ok(())
    }

    pub(super) fn finish_accepted_continuation_native_v2(
        &mut self, stage: AcceptedContinuationV2, request: Request,
    ) -> Result<(), Closed> {
        self.require_retained_availability_accept_v2(
            self.flights[Phase::Accept.index()].request.ok_or(Closed)?)?;
        let slot = &mut self.flights[Phase::Accept.index()];
        let current = &mut slot.continuations[stage.index()];
        if self.closed || self.active != Some(Phase::Accept)
            || slot.active_continuation != Some(stage) || current.request != Some(request)
            || current.native_positive || !slot.authenticated_accept
            || !matches!(slot.representation, Some(Ok(_)))
        { self.closed = true; return Err(Closed); }
        current.native_positive = true;
        Ok(())
    }

    pub(super) fn finish_accepted_continuation_authenticated_v2(
        &mut self, stage: AcceptedContinuationV2, request: Request,
    ) -> Result<(), Closed> {
        self.require_retained_availability_accept_v2(
            self.flights[Phase::Accept.index()].request.ok_or(Closed)?)?;
        let slot = &mut self.flights[Phase::Accept.index()];
        let current = &mut slot.continuations[stage.index()];
        if self.closed || self.active != Some(Phase::Accept)
            || slot.active_continuation != Some(stage) || current.request != Some(request)
            || !current.native_positive || current.authenticated_positive
        { self.closed = true; return Err(Closed); }
        current.authenticated_positive = true;
        slot.active_continuation = None;
        Ok(())
    }

    pub(super) fn prearm_capture_negative_v3(
        &mut self, launch: Request, accept: Request,
        source: aos_sandbox_core::ObjectDigest, execution: aos_sandbox_core::ExecutionId,
        requirement: ResourceVector,
    ) -> Result<CaptureNegativeReservationV3, Closed> {
        self.require_retained_availability_accept_v2(accept)?;
        self.require_launch_resident_v2(launch)?;
        let accepted = &self.flights[Phase::Accept.index()];
        if self.closed || self.active != Some(Phase::Accept)
            || accepted.request != Some(accept) || !accepted.authenticated_accept
            || accepted.active_continuation != Some(AcceptedContinuationV2::Authorize)
            || !accepted.operation.as_ref().is_some_and(|operation| operation.is_consumed_current())
        {
            return Err(Closed);
        }
        let launch_slot = &mut self.flights[Phase::Launch.index()];
        if launch_slot.capture_negative.is_some()
            || source.as_bytes() == &[0; 32] || execution.as_bytes() == &[0; 16]
            || requirement.get(D::MemoryBytes) == 0
        {
            return Err(Closed);
        }
        // Extend the SAME consumed full22 liability before allocating or
        // arming the actual retained disposition. A hold-only disposition needs
        // no new FDs: the same already-paid native owners remain occupied.
        // No prior amount is reset,
        // no scalar is credited and no replacement operation is consumed.
        let reached = launch_slot.reached.checked_add(requirement);
        launch_slot.representation = Some(reached.and_then(|complete|
            launch_slot.capacity.checked_sub(complete)));
        if !matches!(launch_slot.representation, Some(Ok(_))) {
            self.closed = true;
            return Err(Closed);
        }
        launch_slot.reached = launch_slot.capacity.checked_sub(
            *launch_slot.representation.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(Closed)?).map_err(|_| Closed)?;
        launch_slot.current = launch_slot.current.checked_add(requirement).map_err(|_| Closed)?;
        // This tiny same-original identity is part of the admitted control
        // footprint. It cannot be reconstructed from matching request DATA.
        let identity = std::sync::Arc::new(());
        launch_slot.capture_negative = Some(CaptureNegativeFlightV3 {
            identity: std::sync::Arc::clone(&identity),
            source, execution, accept, requirement, entry: CaptureNegativeEntryV3::Armed,
        });
        Ok(CaptureNegativeReservationV3 { identity, source, execution, launch, accept })
    }

    pub(super) fn enter_capture_negative_v3(
        &mut self, reservation: &CaptureNegativeReservationV3,
    ) -> Result<(), Closed> {
        self.require_capture_negative_owed_v3(reservation)?;
        let current = self.flights[Phase::Launch.index()].capture_negative.as_mut().ok_or(Closed)?;
        if current.entry != CaptureNegativeEntryV3::Armed { return Err(Closed); }
        current.entry = CaptureNegativeEntryV3::Entered;
        Ok(())
    }

    pub(super) fn require_capture_negative_owed_v3(
        &self, reservation: &CaptureNegativeReservationV3,
    ) -> Result<(), Closed> {
        self.require_retained_availability_accept_v2(reservation.accept)?;
        let launch = &self.flights[Phase::Launch.index()];
        let accepted = &self.flights[Phase::Accept.index()];
        let current = launch.capture_negative.as_ref().ok_or(Closed)?;
        // The already paid retained disposition remains independently owed
        // after a financial/currentness poison. This cannot admit another
        // primary, THAW, grant, operation, source deadline or native owner.
        if !std::sync::Arc::ptr_eq(&current.identity, &reservation.identity)
            || current.source != reservation.source || current.execution != reservation.execution
            || launch.request != Some(reservation.launch) || current.accept != reservation.accept
            || accepted.request != Some(reservation.accept)
            || !launch.operation.as_ref().is_some_and(|operation| operation.is_consumed_current())
            || !accepted.operation.as_ref().is_some_and(|operation| operation.is_consumed_current())
            || current.requirement.get(D::MemoryBytes) == 0
        {
            return Err(Closed);
        }
        Ok(())
    }

    pub(super) fn require_capture_after_observe_v3(
        &self, launch: Request, accept: Request, observe: Request,
    ) -> Result<(), Closed> {
        self.require_retained_availability_accept_v2(accept)?;
        self.require_launch_resident_v2(launch)?;
        let slot = &self.flights[Phase::Accept.index()];
        let first = &slot.continuations[AcceptedContinuationV2::Authorize.index()];
        let current = &slot.continuations[AcceptedContinuationV2::Observe.index()];
        if self.closed || self.active != Some(Phase::Accept)
            || slot.request != Some(accept) || !slot.native_positive
            || !slot.authenticated_accept || slot.active_continuation.is_some()
            || !first.native_positive || !first.authenticated_positive
            || current.request != Some(observe) || !current.native_positive
            || !current.authenticated_positive || observe.session != accept.session
            || !matches!(slot.representation, Some(Ok(_)))
            || !slot.operation.as_ref().is_some_and(|operation| operation.is_consumed_current())
        {
            return Err(Closed);
        }
        Ok(())
    }

    pub(super) fn require_authenticated_authorize_v2(&self, request: Request) -> Result<(), Closed> {
        self.require_authenticated_continuation_v5(AcceptedContinuationV2::Authorize, request)
    }

    pub(super) fn require_authenticated_continuation_v5(
        &self, stage: AcceptedContinuationV2, request: Request,
    ) -> Result<(), Closed> {
        self.require_retained_availability_accept_v2(
            self.flights[Phase::Accept.index()].request.ok_or(Closed)?)?;
        let slot = &self.flights[Phase::Accept.index()];
        let current = &slot.continuations[stage.index()];
        if self.closed || self.active != Some(Phase::Accept) || !slot.authenticated_accept
            || slot.active_continuation.is_some() || current.request != Some(request)
            || !current.native_positive || !current.authenticated_positive
            || !slot.operation.as_ref().is_some_and(|operation| operation.is_consumed_current())
        {
            return Err(Closed);
        }
        Ok(())
    }

    // An entered failed primary still owes its independently prepaid post.
    // This borrows the actual consumed slot, including after closure; it never
    // authorizes another primary or consumes a replacement operation.
    pub(super) fn require_owed_post(&self, phase: Phase, request: Request) -> Result<(), Closed> {
        if phase == Phase::Accept { self.require_retained_availability_accept_v2(request)?; }
        let slot = &self.flights[phase.index()];
        if self.active != Some(phase) || slot.request != Some(request)
            || !slot.operation.as_ref().is_some_and(|operation| operation.is_consumed_current())
        {
            return Err(Closed);
        }
        Ok(())
    }

    pub(super) fn remaining_launch_capacity_v2(
        &self,
        request: Request,
        complete: ResourceVector,
    ) -> Result<ResourceVector, Closed> {
        self.require_owed_post(Phase::Launch, request)?;
        let slot = &self.flights[Phase::Launch.index()];
        if self.closed || self.reservation.is_err() || slot.native_positive
            || !matches!(slot.representation, Some(Ok(_)))
            || slot.current != complete
        {
            return Err(Closed);
        }
        slot.capacity.checked_sub(complete).map_err(|_| Closed)
    }

    pub(super) fn remaining_accepted_capacity_v1(
        &self,
        original: Request,
        request: Request,
        complete: ResourceVector,
    ) -> Result<ResourceVector, Closed> {
        self.require_owed_post(Phase::Accept, original)?;
        let slot = &self.flights[Phase::Accept.index()];
        if self.closed || self.reservation.is_err()
            || slot.active_continuation != Some(AcceptedContinuationV2::Authorize)
            || slot.continuations[0].request != Some(request)
            || !matches!(slot.representation, Some(Ok(_)))
        {
            return Err(Closed);
        }
        slot.capacity.checked_sub(slot.reached.componentwise_max(complete)).map_err(|_| Closed)
    }

    pub(super) fn close(&mut self) {
        self.closed = true;
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.ledger.failure().map(|error| error as _)
            .or_else(|| self.baseline_requirement.as_ref()?.as_ref().err().map(|error| error as _))
            .or_else(|| self.control_operation.as_ref()?.failure().map(|error| error as _))
            .or_else(|| self.control_requirement.as_ref()?.as_ref().err().map(|error| error as _))
            .or_else(|| self.physical_baseline.as_ref()?.as_ref().err().map(|error| error as _))
            .or_else(|| self.physical_requirement.as_ref()?.as_ref().err().map(|error| error as _))
            .or_else(|| self.flights.iter().find_map(|slot| {
                slot.operation.as_ref().and_then(|operation| operation.failure())
                    .map(|error| error as _)
                    .or_else(|| slot.representation.as_ref()?.as_ref().err().map(|error| error as _))
            }))
            .or_else(|| self.availability_allocation_failure_v2())
            .or_else(|| (self.closed || self.reservation.is_err()).then_some(&Closed as _))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn capture_original() -> HostExecutionReceivingV2 {
        let profile = ExecutionReceivingProfileV2 {
            launch: [32; 22], prepare: [32; 22], accept: [32; 22], boot_preparation: None,
        };
        let mut original = HostExecutionReceivingV2::from_reserved_subdivisions(
            ResourceVector::new([128; 22]), profile, ResourceVector::ZERO,
        ).unwrap();
        original.require_baseline_before_growth_v2(ResourceVector::ZERO).unwrap();
        let launch = request(7, 2);
        original.begin(Phase::Launch, launch).unwrap();
        original.require_complete(Phase::Launch, launch, capture_invoice(2)).unwrap();
        original.finish_native_positive(Phase::Launch, launch).unwrap();
        original.retain_authenticated_launch_v2(launch).unwrap();
        let prepare = request(8, 3);
        original.begin(Phase::Prepare, prepare).unwrap();
        original.require_complete(Phase::Prepare, prepare, capture_invoice(2)).unwrap();
        original.finish_native_positive(Phase::Prepare, prepare).unwrap();
        original.retire_after_disposal(Phase::Prepare, prepare).unwrap();
        let accept = request(9, 3);
        original.begin(Phase::Accept, accept).unwrap();
        original.require_complete(Phase::Accept, accept, capture_invoice(4)).unwrap();
        original.finish_native_positive(Phase::Accept, accept).unwrap();
        original.retain_authenticated_accept_v2(accept).unwrap();
        original.begin_accepted_continuation_v2(AcceptedContinuationV2::Authorize,
            accept, request(10, 3), capture_invoice(4)).unwrap();
        original
    }

    fn capture_invoice(amount: u64) -> ResourceVector {
        ResourceVector::ZERO.with(D::MemoryBytes, amount).with(D::OpenFiles, amount)
            .with(D::NetworkBytes, amount).with(D::LogBytes, amount)
    }

    #[test]
    fn capture_negative_adds_to_same_launch_and_survives_poison_once() {
        let mut original = capture_original();
        let charged = original.ledger.charged();
        let reservation = original.prearm_capture_negative_v3(
            request(7, 2), request(9, 3),
            aos_sandbox_core::ObjectDigest::from_bytes([12; 32]),
            aos_sandbox_core::ExecutionId::from_bytes([13; 16]), capture_invoice(5)).unwrap();

        assert_eq!(original.ledger.charged(), charged);
        assert_eq!(original.flights[Phase::Launch.index()].reached, capture_invoice(7));
        original.close();
        assert!(original.begin(Phase::Prepare, request(11, 3)).is_err());
        original.require_capture_negative_owed_v3(&reservation).unwrap();
        original.enter_capture_negative_v3(&reservation).unwrap();
        assert!(original.enter_capture_negative_v3(&reservation).is_err());
        for phase in [Phase::Launch, Phase::Accept] {
            assert!(original.flights[phase.index()].operation.as_ref()
                .is_some_and(|operation| operation.is_consumed_current()));
        }
    }

    #[test]
    fn retained_disposition_admits_no_new_fds_without_releasing_existing_liability() {
        let mut original = capture_original();
        let charged = original.ledger.charged();
        let reached = original.flights[Phase::Launch.index()].reached;
        let retained = ResourceVector::ZERO.with(D::MemoryBytes, 5);

        let reservation = original.prearm_capture_negative_v3(
            request(7, 2), request(9, 3),
            aos_sandbox_core::ObjectDigest::from_bytes([12; 32]),
            aos_sandbox_core::ExecutionId::from_bytes([13; 16]), retained).unwrap();

        assert_eq!(original.ledger.charged(), charged);
        assert_eq!(original.flights[Phase::Launch.index()].reached,
            reached.checked_add(retained).unwrap());
        assert_eq!(original.flights[Phase::Launch.index()].reached.get(D::OpenFiles),
            reached.get(D::OpenFiles));
        original.close();
        original.require_capture_negative_owed_v3(&reservation).unwrap();
        assert!(original.flights[Phase::Accept.index()].operation.as_ref()
            .is_some_and(|operation| operation.is_consumed_current()));
    }

    #[test]
    fn capture_negative_rejects_another_original_with_identical_request_data() {
        let mut first = capture_original();
        let reservation = first.prearm_capture_negative_v3(
            request(7, 2), request(9, 3),
            aos_sandbox_core::ObjectDigest::from_bytes([12; 32]),
            aos_sandbox_core::ExecutionId::from_bytes([13; 16]), capture_invoice(5)).unwrap();
        let mut second = capture_original();
        second.prearm_capture_negative_v3(
            request(7, 2), request(9, 3),
            aos_sandbox_core::ObjectDigest::from_bytes([12; 32]),
            aos_sandbox_core::ExecutionId::from_bytes([13; 16]), capture_invoice(5)).unwrap();

        assert!(second.require_capture_negative_owed_v3(&reservation).is_err());
        assert!(second.enter_capture_negative_v3(&reservation).is_err());
        first.enter_capture_negative_v3(&reservation).unwrap();
    }

    #[test]
    fn capture_negative_refusal_keeps_actual_capacity_cause_and_no_token() {
        let mut original = capture_original();
        let charged = original.ledger.charged();

        assert!(original.prearm_capture_negative_v3(
            request(7, 2), request(9, 3),
            aos_sandbox_core::ObjectDigest::from_bytes([12; 32]),
            aos_sandbox_core::ExecutionId::from_bytes([13; 16]), capture_invoice(31)).is_err());

        assert_eq!(original.ledger.charged(), charged);
        assert!(original.flights[Phase::Launch.index()].capture_negative.is_none());
        assert!(matches!(original.flights[Phase::Launch.index()].representation, Some(Err(_))));
        assert!(original.failure().unwrap().downcast_ref::<AccountingError>().is_some());
        assert!(original.flights[Phase::Launch.index()].operation.as_ref()
            .is_some_and(|operation| operation.is_consumed_current()));
    }

    fn profile() -> ExecutionReceivingProfileV2 {
        ExecutionReceivingProfileV2 { launch: [1; 22], prepare: [1; 22], accept: [1; 22], boot_preparation: None }
    }

    fn request(id: u8, session: u8) -> Request {
        Request { id: [id; 16], session: [session; 32], signed: [id; 32] }
    }

    #[test]
    fn boot_preparation_stays_reserved_inside_the_same_whole_service() {
        let boot = ResourceVector::ZERO
            .with(D::CpuMicrosPerPeriod, 1)
            .with(D::MemoryBytes, 2)
            .with(D::Pids, 1)
            .with(D::OpenFiles, 2)
            .with(D::ConcurrentOperations, 1);
        let mut declaration = profile();
        declaration.boot_preparation = Some(D::ALL.map(|dimension| boot.get(dimension)));
        let service = ResourceVector::new([4; 22]).checked_add(boot).unwrap();
        let mut original = HostExecutionReceivingV2::from_reserved_subdivisions(
            service, declaration, ResourceVector::ZERO,
        ).unwrap();

        assert_eq!(original.baseline_capacity, ResourceVector::new([1; 22]));
        assert_eq!(original.ledger.charged(), service);
        original.require_baseline_before_growth_v2(ResourceVector::new([1; 22])).unwrap();
        original.begin(Phase::Launch, request(7, 2)).unwrap();

        assert_eq!(original.ledger.charged(), service);
        assert_eq!(original.flights.len(), 3);
    }

    #[test]
    fn host_baseline_cannot_borrow_the_retained_boot_reservation() {
        let boot = ResourceVector::new([1; 22]);
        let mut declaration = profile();
        declaration.boot_preparation = Some(D::ALL.map(|dimension| boot.get(dimension)));
        let service = ResourceVector::new([5; 22]);
        let mut original = HostExecutionReceivingV2::from_reserved_subdivisions(
            service, declaration, ResourceVector::ZERO,
        ).unwrap();

        let baseline_with_boot_memory = ResourceVector::new([1; 22])
            .with(D::MemoryBytes, 2);
        assert!(original.require_baseline_before_growth_v2(baseline_with_boot_memory).is_err());
        assert_eq!(original.ledger.charged(), service);
        assert!(original.begin(Phase::Launch, request(7, 2)).is_err());
    }

    #[test]
    fn launch_partition_keeps_the_same_whole_and_requires_paid_baseline() {
        let mut original = HostExecutionReceivingV2::from_reserved_subdivisions(
            ResourceVector::new([4; 22]), profile(), ResourceVector::ZERO,
        ).unwrap();
        assert_eq!(original.ledger.charged(), ResourceVector::new([4; 22]));
        assert_eq!(original.baseline_capacity, ResourceVector::new([1; 22]));
        original.require_baseline_before_growth_v2(ResourceVector::new([1; 22])).unwrap();
        original.begin(Phase::Launch, request(7, 2)).unwrap();
        assert_eq!(original.ledger.charged(), ResourceVector::new([4; 22]));
        assert!(original.require_owed_post(Phase::Launch, request(7, 2)).is_ok());
        assert!(original.begin(Phase::Prepare, request(8, 2)).is_err());
        assert!(original.require_owed_post(Phase::Launch, request(7, 2)).is_ok());
    }

    #[test]
    fn authenticated_launch_keeps_its_paid_residency_during_later_arguments() {
        let mut original = HostExecutionReceivingV2::from_reserved_subdivisions(
            ResourceVector::new([4; 22]), profile(), ResourceVector::ZERO,
        ).unwrap();
        original.require_baseline_before_growth_v2(ResourceVector::new([1; 22])).unwrap();
        let launch = request(7, 2);
        original.begin(Phase::Launch, launch).unwrap();
        original.require_complete(Phase::Launch, launch, ResourceVector::new([1; 22])).unwrap();
        original.finish_native_positive(Phase::Launch, launch).unwrap();
        original.retain_authenticated_launch_v2(launch).unwrap();
        assert!(original.require_launch_resident_v2(launch).is_ok());
        assert!(original.flights[Phase::Launch.index()].operation.as_ref()
            .is_some_and(|operation| operation.is_consumed_current()));
        original.begin(Phase::Prepare, request(8, 2)).unwrap();
        assert!(original.require_launch_resident_v2(launch).is_ok());
        assert_eq!(original.ledger.charged(), ResourceVector::new([4; 22]));
    }

    #[test]
    fn launch_cannot_take_an_unmeasured_or_overdrawn_baseline() {
        let mut missing = HostExecutionReceivingV2::from_reserved_subdivisions(
            ResourceVector::new([4; 22]), profile(), ResourceVector::ZERO,
        ).unwrap();
        assert!(missing.begin(Phase::Launch, request(7, 2)).is_err());
        for dimension in D::ALL {
            let mut original = HostExecutionReceivingV2::from_reserved_subdivisions(
                ResourceVector::new([4; 22]), profile(), ResourceVector::ZERO,
            ).unwrap();
            assert!(original.require_baseline_before_growth_v2(
                ResourceVector::ZERO.with(dimension, 2),
            ).is_err());
            assert!(original.begin(Phase::Launch, request(7, 2)).is_err());
            assert_eq!(original.ledger.charged(), ResourceVector::new([4; 22]));
        }
    }

    #[test]
    fn each_actual_dimension_is_checked_inside_the_once_consumed_slot() {
        for dimension in D::ALL {
            let mut original = HostExecutionReceivingV2::from_reserved_subdivisions(ResourceVector::new([4; 22]), profile(), ResourceVector::ZERO).unwrap();
            let before = original.ledger.charged();
            let request = request(1, 2);
            original.begin(Phase::Prepare, request).unwrap();

            let excessive = ResourceVector::ZERO.with(dimension, 2);
            assert!(original.require_complete(Phase::Prepare, request, excessive).is_err());
            let first = original.failure().unwrap() as *const dyn std::error::Error;
            assert!(original.require_complete(Phase::Prepare, request, ResourceVector::ZERO).is_err());

            assert!(std::ptr::eq(original.failure().unwrap(), first));
            assert_eq!(original.ledger.charged(), before);
            assert!(original.require_owed_post(Phase::Prepare, request).is_ok());
            assert!(original.begin(Phase::Accept, self::request(3, 2)).is_err());
        }
    }

    #[test]
    fn accept_requires_positive_preparation_on_the_same_actual_session() {
        let mut original = HostExecutionReceivingV2::from_reserved_subdivisions(ResourceVector::new([4; 22]), profile(), ResourceVector::ZERO).unwrap();
        let preparation = request(1, 2);
        original.begin(Phase::Prepare, preparation).unwrap();
        original.require_complete(Phase::Prepare, preparation, ResourceVector::new([1; 22])).unwrap();
        original.finish_native_positive(Phase::Prepare, preparation).unwrap();

        assert!(original.flights[0].operation.as_ref().unwrap().is_consumed_current());
        assert!(original.begin(Phase::Accept, request(3, 4)).is_err());
        assert!(original.begin(Phase::Accept, request(3, 2)).is_err());
    }

    fn complete_positive(original: &mut HostExecutionReceivingV2, phase: Phase, request: Request) {
        original.begin(phase, request).unwrap();
        original.require_complete(phase, request, ResourceVector::new([1; 22])).unwrap();
        original.finish_native_positive(phase, request).unwrap();
        assert!(original.flights[phase.index()].operation.as_ref().unwrap().is_consumed_current());
        assert_eq!(original.active, Some(phase));
        // The actual caller supplies whole authenticated completion and native
        // disposal before entering this private positive boundary.
        original.retire_after_disposal(phase, request).unwrap();
    }

    #[test]
    fn same_original_serves_two_positive_intervals_without_new_origin_or_refund() {
        use std::sync::{Arc, Mutex};
        let original = Arc::new(Mutex::new(HostExecutionReceivingV2::from_reserved_subdivisions(
            ResourceVector::new([8; 22]), ExecutionReceivingProfileV2 {
                prepare: [2; 22], accept: [2; 22], launch: [2; 22], boot_preparation: None,
            }, ResourceVector::ZERO,
        ).unwrap()));
        let same = Arc::clone(&original);
        let charged = original.lock().unwrap().ledger.charged();

        for first in [1, 3] {
            let mut held = same.lock().unwrap();
            complete_positive(&mut held, Phase::Prepare, request(first, 9));
            complete_positive(&mut held, Phase::Accept, request(first + 1, 9));

            assert_eq!(held.ledger.charged(), charged);
            assert!(held.flights.iter().all(|slot| slot.operation.is_none()));
            assert!(held.prepared.is_none());
            assert!(!held.closed);
        }
        assert!(Arc::ptr_eq(&original, &same));
        let held = original.lock().unwrap();
        for phase in [Phase::Prepare, Phase::Accept] {
            let reached = held.flights[phase.index()].reached;
            assert_eq!(reached.get(D::NetworkBytes), 2);
            assert_eq!(reached.get(D::OutputBytes), 2);
            assert_eq!(reached.get(D::MemoryBytes), 1);
            assert_eq!(held.flights[phase.index()].current, ResourceVector::ZERO);
        }
    }

    #[test]
    fn a_distinct_prepare_cannot_reuse_spent_traffic_after_positive_disposal() {
        let mut original = HostExecutionReceivingV2::from_reserved_subdivisions(
            ResourceVector::new([4; 22]), profile(), ResourceVector::ZERO,
        ).unwrap();
        complete_positive(&mut original, Phase::Prepare, request(1, 9));
        complete_positive(&mut original, Phase::Accept, request(2, 9));
        let charged = original.ledger.charged();
        let next = request(3, 9);

        original.begin(Phase::Prepare, next).unwrap();
        assert!(original.require_complete(Phase::Prepare, next,
            ResourceVector::ZERO.with(D::NetworkBytes, 1)).is_err());

        assert_eq!(original.ledger.charged(), charged);
        assert_eq!(original.flights[Phase::Prepare.index()].reached.get(D::NetworkBytes), 1);
        assert!(original.flights[Phase::Prepare.index()].operation.as_ref().unwrap().is_consumed_current());
        assert!(original.require_owed_post(Phase::Prepare, next).is_ok());
    }

    #[test]
    fn failure_after_first_positive_interval_keeps_same_negative_slot_spent() {
        let mut original = HostExecutionReceivingV2::from_reserved_subdivisions(
            ResourceVector::new([4; 22]), profile(), ResourceVector::ZERO,
        ).unwrap();
        complete_positive(&mut original, Phase::Prepare, request(1, 9));
        complete_positive(&mut original, Phase::Accept, request(2, 9));
        let charged = original.ledger.charged();
        let failed = request(3, 9);

        original.begin(Phase::Prepare, failed).unwrap();
        assert!(original.require_complete(Phase::Prepare, failed,
            ResourceVector::ZERO.with(D::NetworkBytes, 2)).is_err());
        let first = original.failure().unwrap() as *const dyn std::error::Error;
        assert!(original.require_owed_post(Phase::Prepare, failed).is_ok());
        assert!(original.retire_after_disposal(Phase::Prepare, failed).is_err());
        assert!(original.begin(Phase::Prepare, request(4, 9)).is_err());

        assert!(std::ptr::eq(first, original.failure().unwrap()));
        assert_eq!(original.ledger.charged(), charged);
        assert!(original.flights[0].operation.as_ref().unwrap().is_consumed_current());
    }

    #[test]
    fn failed_control_precharge_retains_the_original_dimension_error() {
        let capacity = ResourceVector::new([2; 22]);
        let mut original = HostExecutionReceivingV2::from_reserved_subdivisions(
            ResourceVector::new([4; 22]), profile(), capacity,
        ).unwrap();
        original.execution_admitted = false;
        let charged = original.ledger.charged();

        assert!(original.consume_control_once(ResourceVector::ZERO.with(D::MemoryBytes, 3)).is_err());
        let first = original.failure().unwrap() as *const dyn std::error::Error;

        assert!(original.failure().unwrap().downcast_ref::<AccountingError>().is_some());
        assert!(original.control_operation.is_none());
        assert!(!original.control_was_consumed());
        assert!(original.begin(Phase::Prepare, request(1, 2)).is_err());
        assert!(std::ptr::eq(original.failure().unwrap(), first));
        assert_eq!(original.ledger.charged(), charged);
    }

    #[test]
    fn control_preparation_cannot_itself_unseal_an_execution_receiver() {
        let capacity = ResourceVector::new([2; 22]);
        let mut original = HostExecutionReceivingV2::from_reserved_subdivisions(
            ResourceVector::new([4; 22]), profile(), capacity,
        ).unwrap();
        original.execution_admitted = false;

        original.consume_control_once(ResourceVector::ZERO.with(D::MemoryBytes, 1)).unwrap();

        assert!(original.control_was_consumed());
        assert!(!original.execution_admitted);
        assert!(original.begin(Phase::Prepare, request(1, 2)).is_err());
        assert!(original.control_operation.as_ref().unwrap().is_consumed_current());
    }

    fn retained_accept() -> (HostExecutionReceivingV2, Request) {
        let mut owner = HostExecutionReceivingV2::from_reserved_subdivisions(
            ResourceVector::new([4; 22]), profile(), ResourceVector::ZERO,
        ).unwrap();
        complete_positive(&mut owner, Phase::Prepare, request(1, 9));
        let accept = request(2, 9);
        owner.begin(Phase::Accept, accept).unwrap();
        owner.require_complete(Phase::Accept, accept, ResourceVector::new([1; 22])).unwrap();
        owner.finish_native_positive(Phase::Accept, accept).unwrap();
        owner.retain_authenticated_accept_v2(accept).unwrap();
        (owner, accept)
    }

    #[test]
    fn real_authorize_then_observe_stays_on_same_consumed_accept() {
        let (mut owner, accept) = retained_accept();
        let charged = owner.ledger.charged();
        for (stage, current) in [(AcceptedContinuationV2::Authorize, request(3, 9)),
            (AcceptedContinuationV2::Observe, request(4, 9))] {
            owner.begin_accepted_continuation_v2(stage, accept, current,
                ResourceVector::new([1; 22])).unwrap();
            owner.require_accepted_continuation_v2(stage, current, ResourceVector::ZERO).unwrap();
            assert_eq!(owner.flights[1].reached, ResourceVector::new([1; 22]));
            assert!(owner.flights[1].operation.as_ref().unwrap().is_consumed_current());
            assert_eq!(owner.ledger.charged(), charged);
            assert!(owner.require_authenticated_continuation_v5(stage, current).is_err());
            owner.finish_accepted_continuation_native_v2(stage, current).unwrap();
            assert!(owner.require_authenticated_continuation_v5(stage, current).is_err());
            owner.finish_accepted_continuation_authenticated_v2(stage, current).unwrap();
            owner.require_authenticated_continuation_v5(stage, current).unwrap();
            assert!(owner.require_authenticated_continuation_v5(stage, request(99, 9)).is_err());
            assert_eq!(owner.ledger.charged(), charged);
            assert!(owner.flights[1].operation.as_ref().unwrap().is_consumed_current());
        }
        owner.retire_after_disposal(Phase::Accept, accept).unwrap();
        assert!(owner.flights[1].operation.is_none());
        assert_eq!(owner.ledger.charged(), charged);
    }

    #[test]
    fn observe_requires_authenticated_authorize_not_only_native_completion() {
        let (mut owner, accept) = retained_accept();
        let authorize = request(3, 9);
        owner.begin_accepted_continuation_v2(AcceptedContinuationV2::Authorize,
            accept, authorize, ResourceVector::new([1; 22])).unwrap();
        owner.finish_accepted_continuation_native_v2(AcceptedContinuationV2::Authorize, authorize).unwrap();
        assert!(owner.begin_accepted_continuation_v2(AcceptedContinuationV2::Observe,
            accept, request(4, 9), ResourceVector::ZERO).is_err());
        assert!(owner.require_owed_post(Phase::Accept, accept).is_ok());
        assert!(owner.flights[1].operation.as_ref().unwrap().is_consumed_current());
    }

    #[test]
    fn continuation_refusal_never_reopens_or_refunds_original_accept() {
        for foreign in [request(3, 8), request(2, 9)] {
            let (mut owner, accept) = retained_accept();
            let charged = owner.ledger.charged();
            assert!(owner.begin_accepted_continuation_v2(AcceptedContinuationV2::Authorize,
                accept, foreign, ResourceVector::ZERO).is_err());
            assert!(owner.begin_accepted_continuation_v2(AcceptedContinuationV2::Authorize,
                accept, request(4, 9), ResourceVector::ZERO).is_err());
            assert!(owner.require_owed_post(Phase::Accept, accept).is_ok());
            assert_eq!(owner.ledger.charged(), charged);
        }
    }


    fn monitor_original() -> HostExecutionReceivingV2 {
        let mut original = capture_original();
        original.prearm_capture_negative_v3(request(7, 2), request(9, 3),
            aos_sandbox_core::ObjectDigest::from_bytes([12; 32]),
            aos_sandbox_core::ExecutionId::from_bytes([13; 16]), capture_invoice(5)).unwrap();
        original.finish_accepted_continuation_native_v2(AcceptedContinuationV2::Authorize,
            request(10, 3)).unwrap();
        original.finish_accepted_continuation_authenticated_v2(AcceptedContinuationV2::Authorize,
            request(10, 3)).unwrap();
        original.begin_accepted_continuation_v2(AcceptedContinuationV2::Observe,
            request(9, 3), request(11, 3), capture_invoice(4)).unwrap();
        original.finish_accepted_continuation_native_v2(AcceptedContinuationV2::Observe,
            request(11, 3)).unwrap();
        original.finish_accepted_continuation_authenticated_v2(AcceptedContinuationV2::Observe,
            request(11, 3)).unwrap();
        original
    }

    #[test]
    fn monitor_prepays_before_sequence_and_preserves_debt_after_refusal() {
        let mut original = monitor_original();
        let charged = original.ledger.charged();
        let prior = original.flights[Phase::Launch.index()].reached;
        let reservation = original.prepare_execution_monitor_v5(
            request(7, 2), request(9, 3), request(11, 3),
            aos_sandbox_core::ObjectDigest::from_bytes([12; 32]),
            aos_sandbox_core::ExecutionId::from_bytes([13; 16]), capture_invoice(3)).unwrap();

        assert_eq!(original.ledger.charged(), charged);
        assert_eq!(original.flights[Phase::Launch.index()].reached.get(D::NetworkBytes),
            prior.get(D::NetworkBytes) + 3);
        assert!(original.require_execution_monitor_owed_v5(request(9, 3), 3).is_err());
        original.bind_execution_monitor_sequence_v5(&reservation, 3, capture_invoice(2)).unwrap();
        original.require_execution_monitor_complete_v5(request(9, 3), 3, capture_invoice(3)).unwrap();
        assert_eq!(original.flights[Phase::Launch.index()].reached.get(D::NetworkBytes),
            prior.get(D::NetworkBytes) + 3);

        original.close();
        original.require_execution_monitor_owed_v5(request(9, 3), 3).unwrap();
        assert!(original.prepare_execution_monitor_v5(
            request(7, 2), request(9, 3), request(11, 3),
            aos_sandbox_core::ObjectDigest::from_bytes([12; 32]),
            aos_sandbox_core::ExecutionId::from_bytes([13; 16]), capture_invoice(1)).is_err());
        assert_eq!(original.ledger.charged(), charged);
        for phase in [Phase::Launch, Phase::Accept] {
            assert!(original.flights[phase.index()].operation.as_ref()
                .is_some_and(|operation| operation.is_consumed_current()));
        }
    }

    #[test]
    fn monitor_rejects_identical_data_from_another_actual_original() {
        let mut first = monitor_original();
        let mut second = monitor_original();
        let source = aos_sandbox_core::ObjectDigest::from_bytes([12; 32]);
        let execution = aos_sandbox_core::ExecutionId::from_bytes([13; 16]);
        let reservation = first.prepare_execution_monitor_v5(request(7, 2), request(9, 3),
            request(11, 3), source, execution, capture_invoice(3)).unwrap();
        second.prepare_execution_monitor_v5(request(7, 2), request(9, 3),
            request(11, 3), source, execution, capture_invoice(3)).unwrap();

        assert!(second.bind_execution_monitor_sequence_v5(&reservation, 3, capture_invoice(2)).is_err());
        first.bind_execution_monitor_sequence_v5(&reservation, 3, capture_invoice(2)).unwrap();
        assert!(first.bind_execution_monitor_sequence_v5(&reservation, 4, capture_invoice(2)).is_err());
        assert!(first.prepare_execution_monitor_v5(request(7, 2), request(9, 3), request(11, 3),
            source, execution, capture_invoice(1)).is_err());
    }


    #[test]
    fn terminal_stage_disposal_preserves_launch_debt_and_exact_accept_operation() {
        let mut original = monitor_original();
        let charged = original.ledger.charged();
        let launch_reached = original.flights[Phase::Launch.index()].reached;
        let accept_reached = original.flights[Phase::Accept.index()].reached;

        assert!(original.require_terminal_stage_disposal_v3(
            request(7, 2), request(99, 3), request(11, 3), None).is_err());
        original.require_terminal_stage_disposal_v3(
            request(7, 2), request(9, 3), request(11, 3), None).unwrap();
        original.complete_terminal_stage_disposal_v3(
            request(7, 2), request(9, 3), request(11, 3), None).unwrap();

        assert_eq!(original.ledger.charged(), charged);
        assert_eq!(original.flights[Phase::Launch.index()].reached, launch_reached);
        assert_eq!(original.flights[Phase::Accept.index()].reached, accept_reached);
        assert!(original.flights[Phase::Launch.index()].operation.as_ref()
            .is_some_and(|operation| operation.is_consumed_current()));
        assert!(original.flights[Phase::Accept.index()].operation.is_none());
        assert!(original.flights[Phase::Launch.index()].capture_negative.is_none());
        assert!(original.active.is_none());
        assert!(original.complete_terminal_stage_disposal_v3(
            request(7, 2), request(9, 3), request(11, 3), None).is_err());
    }

    #[test]
    fn terminal_stage_disposal_refuses_entered_negative_and_keeps_original() {
        let mut original = monitor_original();
        let charged = original.ledger.charged();
        original.flights[Phase::Launch.index()].capture_negative.as_mut().unwrap().entry
            = CaptureNegativeEntryV3::Entered;

        assert!(original.require_terminal_stage_disposal_v3(
            request(7, 2), request(9, 3), request(11, 3), None).is_err());
        assert!(original.complete_terminal_stage_disposal_v3(
            request(7, 2), request(9, 3), request(11, 3), None).is_err());

        assert_eq!(original.ledger.charged(), charged);
        assert!(original.flights[Phase::Launch.index()].capture_negative.is_some());
        assert!(original.flights[Phase::Accept.index()].operation.as_ref()
            .is_some_and(|operation| operation.is_consumed_current()));
    }

}

#[cfg(test)]
mod permanent_baseline_tests {
    use super::*;

    #[test]
    fn permanent_native_files_must_fit_before_snapshot_or_launch() {
        let baseline = super::super::component_baseline_receiving_demand_v2().unwrap();
        let snapshot = crate::state::HostStateReadAttemptV2::receiving_demand_v2().unwrap();
        assert_eq!(baseline.get(D::OpenFiles), snapshot.get(D::OpenFiles) + 3 + 2 + 1);

        // Only private accounting DATA is constructed. Native fixed delivery
        // and its completed admission remain mandatory in the actual caller.
        let flight = snapshot.with(D::ConcurrentOperations, 1);
        let profile = ExecutionReceivingProfileV2 {
            prepare: D::ALL.map(|dimension| flight.get(dimension)),
            accept: D::ALL.map(|dimension| flight.get(dimension)),
            launch: D::ALL.map(|dimension| flight.get(dimension)),
            boot_preparation: None,
        };
        let subdivisions = flight.checked_add(flight).unwrap().checked_add(flight).unwrap();
        let omitted = baseline.with(D::OpenFiles, snapshot.get(D::OpenFiles));
        let mut short = HostExecutionReceivingV2::from_reserved_subdivisions(
            omitted.checked_add(subdivisions).unwrap(), profile, ResourceVector::ZERO,
        ).unwrap();
        assert!(short.require_prepaid_baseline_v2().is_err());
        assert!(short.require_baseline_before_growth_v2(baseline).is_err());
        let first = short.failure().unwrap() as *const dyn std::error::Error;
        assert!(short.require_prepaid_baseline_v2().is_err());
        assert!(short.require_baseline_before_growth_v2(baseline).is_err());
        assert!(std::ptr::eq(first, short.failure().unwrap() as *const dyn std::error::Error));

        let mut sufficient = HostExecutionReceivingV2::from_reserved_subdivisions(
            baseline.checked_add(subdivisions).unwrap(), profile, ResourceVector::ZERO,
        ).unwrap();
        sufficient.require_baseline_before_growth_v2(baseline).unwrap();
        sufficient.require_prepaid_baseline_v2().unwrap();
        assert!(sufficient.require_baseline_before_growth_v2(baseline).is_err());
    }
}
