//! Retains Controller B's actual selected profile comparison scopes.
//!
//! The initial scope spans profile admission and its exact original recipient
//! join. Later scopes use the same original C and prepaid complete peak. Only
//! complete local/control/semantic success and clean native Ended dispose an
//! archive before another scope starts. No caller vector constructs payment.

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use crate::controller_receiving::{
    ControllerReceivingOriginalV1, ControllerReceivingErrorV1,
};
use crate::controller_receiving::original::{ControllerControlScopeV1, ControllerConstructionPostV1};
use super::{ControllerSelfProfileOriginalV1, ControllerProfileErrorV1};
use super::local_currentness::ControllerProfileLocalCurrentnessOriginalV1;
use super::observer as service;
use crate::controller_receiving::operation_intake::OperationIntakePurposeV1;

const MATERIALIZED_BYTES: usize = 64 * 1024;
// Each named post observes producer twice; each producer owns two local
// recheck bookends and one independent local post: six retained snapshots.
const MAXIMUM_LOCALS: usize = 6;
const CONSTRUCTION_LANES: usize = 3;
const CONSTRUCTION_ROWS: usize = 4 * CONSTRUCTION_LANES;

#[derive(Clone, Copy)]
pub(super) enum ScopeKind {
    Initial,
    Recheck,
    Producer,
    Peer,
    CacheInitialization,
    SourceInitialization,
    PublisherReadonly,
    RuntimeStartup,
    SourceCredentials,
    PublicCredentials,
    SourceConstructionPost,
    ControllerConstructionPost,
}

impl ScopeKind {
    fn rows(self) -> usize {
        match self {
            Self::Initial => 4,
            Self::Recheck => 1,
            Self::Producer => 2,
            Self::Peer | Self::CacheInitialization | Self::SourceInitialization | Self::PublisherReadonly | Self::SourceConstructionPost | Self::ControllerConstructionPost
            | Self::SourceCredentials | Self::PublicCredentials => 4,
            Self::RuntimeStartup => 5,
        }
    }
}

/// Shares only the actual original receiving owner with its admitted profile.
pub(in crate::controller_receiving) struct ControllerBaselineProfileV1 {
    original: Arc<ControllerReceivingOriginalV1>,
    state: Mutex<ProfileState>,
    source_post: Mutex<ProfileState>,
    controller_post: Mutex<ProfileState>,
    post_dispatch: Mutex<Option<(std::thread::ThreadId, ControllerConstructionPostV1)>>,
    receiving_dispatch: Mutex<Option<std::thread::ThreadId>>,
    operation_dispatch: Mutex<Option<(std::thread::ThreadId, OperationIntakePurposeV1, usize)>>,
    operation_scopes: [OnceLock<OperationProfilePoolV1>; 2],
    provisioning_scopes: OnceLock<Box<provisioning::ProvisioningProfilePoolV1>>,
    provisioning_dispatch: Mutex<Option<(std::thread::ThreadId, usize)>>,
}

// The unshipped D receiver has four separate recurring destinations; X keeps
// its exact original four. This private choice follows the genuine purpose.
enum OperationProfilePoolV1 {
    Delete(Box<[Mutex<ProfileState>; 8]>),
    Execution(Box<[Mutex<ProfileState>; 4]>),
}

impl OperationProfilePoolV1 {
    fn get(&self, slot: usize) -> Option<&Mutex<ProfileState>> {
        match self { Self::Delete(values) => values.get(slot), Self::Execution(values) => values.get(slot) }
    }

    fn iter_mut(&mut self) -> std::slice::IterMut<'_, Mutex<ProfileState>> {
        match self { Self::Delete(values) => values.iter_mut(), Self::Execution(values) => values.iter_mut() }
    }
}

struct ProfileState {
    scope: Option<ProfileScope>,
    failed_entry: Option<ControllerReceivingErrorV1>,
    files: usize,
    initial_completed: bool,
}

impl ProfileState {
    const fn new() -> Self {
        Self { scope: None, failed_entry: None, files: 0, initial_completed: false }
    }
}

#[derive(Clone, Copy)]
enum FirstFailure {
    Local(usize),
    Comparison(usize),
    Completion,
    Canonical(usize),
    Property(usize),
}

struct ProfileScope {
    control: ControllerControlScopeV1,
    archive: Option<service::FirstGlobalPropertyArchive>,
    preparation: Option<Result<(), ControllerProfileErrorV1>>,
    local: [Option<ControllerProfileLocalCurrentnessOriginalV1>; MAXIMUM_LOCALS],
    next_local: usize,
    // A named post has two producers: each can retain its failed read,
    // semantic recheck and producer projection before the independent post.
    comparisons: [Option<Result<(), ControllerProfileErrorV1>>; MAXIMUM_LOCALS],
    next_comparison: usize,
    first_failure: Option<FirstFailure>,
    construction_before: Option<Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1>>,
    construction_after: Option<Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1>>,
    canonical: [Option<std::io::Result<std::path::PathBuf>>; MAXIMUM_LOCALS],
    canonical_binding: [Option<Result<(), ControllerProfileErrorV1>>; MAXIMUM_LOCALS],
    next_canonical: usize,
    completion: Option<Result<(), ControllerProfileErrorV1>>,
    control_post: Option<Result<(), ControllerReceivingErrorV1>>,
    recipient: Option<Result<(), ControllerReceivingErrorV1>>,
    settlement: Option<Result<(), ControllerProfileErrorV1>>,
    thread: std::thread::ThreadId,
    kind: ScopeKind,
}

// The guard keeps the actual parked cause borrowed from its sole owner.
// Only this private view may traverse native details. Admission publishes the
// fixed phase and legacy classification, retaining the SAME owner Arc.
pub(in crate::controller_receiving) struct BaselineFailureView<'owner> {
    state: MutexGuard<'owner, ProfileState>,
}

impl BaselineFailureView<'_> {
    pub(in crate::controller_receiving) fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.state.failed_entry.as_ref()
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.state.scope.as_ref().and_then(ProfileScope::failure))
    }

    pub(in crate::controller_receiving) fn phase(&self) -> &'static str {
        if self.state.failed_entry.is_some() {
            return "baseline-entry";
        }
        self.state.scope.as_ref().and_then(ProfileScope::failure_phase)
            .unwrap_or("baseline-unavailable")
    }

    pub(super) fn property_failure(
        &self,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        let scope = self.state.scope.as_ref()?;
        if self.state.failed_entry.is_some() || scope.control.before_failure().is_some() {
            return None;
        }
        // A later independent property error cannot replace an earlier local
        // or semantic cause. This guard follows only the selected actual stage.
        if retained_error(&scope.preparation).is_none()
            && !matches!(scope.first_failure, Some(FirstFailure::Property(_)))
            && !(scope.first_failure.is_none() && retained_error(&scope.settlement).is_some())
        {
            return None;
        }
        scope.archive.as_ref()?.failure_view()
    }

    pub(super) fn classification(&self) -> ControllerProfileErrorV1 {
        if self.state.failed_entry.is_some() {
            return ControllerProfileErrorV1::Service;
        }
        self.state.scope.as_ref().map_or(ControllerProfileErrorV1::Service,
            ProfileScope::failure_classification)
    }
}

impl ControllerBaselineProfileV1 {
    pub(in crate::controller_receiving) fn original(&self) -> &Arc<ControllerReceivingOriginalV1> {
        &self.original
    }

    pub(in crate::controller_receiving) fn is_receiving_scope_current(&self) -> Result<bool, ControllerProfileErrorV1> {
        Ok(self.receiving_dispatch.try_lock().map_err(|_| ControllerProfileErrorV1::Service)?
            .is_some_and(|thread| thread == std::thread::current().id()))
    }

    // Dispatch is scheduling state, never a payer/currentness witness. The
    // only callers first enter their own genuine original-funded operation.
    fn enter_receiving_dispatch(&self) -> Result<(), ControllerProfileErrorV1> {
        let mut dispatch = self.receiving_dispatch.try_lock()
            .map_err(|_| ControllerProfileErrorV1::Service)?;
        if dispatch.is_some() {
            return Err(ControllerProfileErrorV1::Service);
        }
        *dispatch = Some(std::thread::current().id());
        Ok(())
    }

    fn leave_receiving_dispatch(&self) {
        match self.receiving_dispatch.try_lock() {
            Ok(mut dispatch) => *dispatch = None,
            Err(_) => std::process::abort(),
        }
    }

    pub(in crate::controller_receiving) fn run_publisher_producer(
        &self,
        original: &Arc<ControllerReceivingOriginalV1>,
        compare: impl FnOnce() -> Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1>,
    ) -> Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1> {
        if !Arc::ptr_eq(&self.original, original) || self.is_nested()? {
            return Err(ControllerProfileErrorV1::Service);
        }
        original.require_publisher_operation()
            .map_err(|_| ControllerProfileErrorV1::Service)?;
        self.enter_receiving_dispatch()?;
        // The sole closed caller has already consumed its actual Publisher
        // loan. This enters the ordinary shared Producer scope before reads,
        // with its real control/local/semantic/Ended outcomes and positive drop.
        let result = compare();
        self.leave_receiving_dispatch();
        result
    }

    pub(in crate::controller_receiving) fn run_operation_intake_producer_v1(
        &self,
        original: &Arc<ControllerReceivingOriginalV1>,
        purpose: OperationIntakePurposeV1,
        slot: usize,
        compare: impl FnOnce() -> Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1>,
    ) -> Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1> {
        if !Arc::ptr_eq(&self.original, original) || slot >= purpose.profile_pool_slots() {
            return Err(ControllerProfileErrorV1::Service);
        }
        {
            let mut dispatch = self.operation_dispatch.try_lock().map_err(|_| ControllerProfileErrorV1::Service)?;
            if dispatch.is_some() { return Err(ControllerProfileErrorV1::Service); }
            *dispatch = Some((std::thread::current().id(), purpose, slot));
        }
        // The actual private purpose owner consumed its whole flight before
        // this dispatch. The same ordinary Producer engine retains all native
        // local/property/control Results in a distinct preallocated destination.
        let entered = self.enter_receiving_dispatch();
        let returned = match entered {
            Ok(()) => {
                let returned = self.run_producer(compare);
                self.leave_receiving_dispatch();
                returned
            }
            Err(cause) => Err(cause),
        };
        match self.operation_dispatch.try_lock() {
            Ok(mut dispatch) => *dispatch = None,
            Err(_) => std::process::abort(),
        }
        returned
    }

    pub(in crate::controller_receiving) fn operation_intake_pool_resident_demand_v1(
        purpose: OperationIntakePurposeV1,
    ) -> Result<ResourceVector, ControllerReceivingErrorV1> {
        // One retained heap body plus two conservative construction/move
        // destinations. The embedded OnceLock/Box header is already in Self.
        let body = match purpose {
            OperationIntakePurposeV1::Delete => std::mem::size_of::<[Mutex<ProfileState>; 8]>(),
            OperationIntakePurposeV1::Execution => std::mem::size_of::<[Mutex<ProfileState>; 4]>(),
            OperationIntakePurposeV1::LifecycleStop => return Err(ControllerReceivingErrorV1::Conflict),
        };
        let bytes = body.checked_mul(3)
            .ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
        let bytes = u64::try_from(bytes)
            .map_err(|_| ControllerReceivingErrorV1::EnrollmentUnavailable)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    pub(in crate::controller_receiving) fn prepare_operation_intake_pool_once_v1(
        &self,
        original: &Arc<ControllerReceivingOriginalV1>,
        purpose: OperationIntakePurposeV1,
    ) -> Result<(), ControllerProfileErrorV1> {
        if !Arc::ptr_eq(&self.original, original) {
            return Err(ControllerProfileErrorV1::Service);
        }
        original.operation_intakes.try_lock()
            .map_err(|_| ControllerProfileErrorV1::Service)?
            .slot(purpose).require_claimed_idle()
            .map_err(|_| ControllerProfileErrorV1::Service)?;

        if purpose == OperationIntakePurposeV1::LifecycleStop {
            return Err(ControllerProfileErrorV1::Service);
        }
        let pool = &self.operation_scopes[purpose.index()];
        if pool.get().is_some() {
            return Err(ControllerProfileErrorV1::Service);
        }
        // The SAME actual purpose has admitted this entire permanent body and
        // its construction before allocation. No property/native IO runs here.
        let scopes = match purpose {
            OperationIntakePurposeV1::Delete => OperationProfilePoolV1::Delete(
                Box::new(std::array::from_fn(|_| Mutex::new(ProfileState::new())))),
            OperationIntakePurposeV1::Execution => OperationProfilePoolV1::Execution(
                Box::new(std::array::from_fn(|_| Mutex::new(ProfileState::new())))),
            OperationIntakePurposeV1::LifecycleStop => return Err(ControllerProfileErrorV1::Service),
        };
        pool.set(scopes).map_err(|_| ControllerProfileErrorV1::Service)
    }

    pub(in crate::controller_receiving) fn operation_intake_failure_view_v1(
        &self, purpose: OperationIntakePurposeV1, slot: usize,
    ) -> Option<BaselineFailureView<'_>> {
        let state = self.operation_scopes.get(purpose.index())?.get()?.get(slot)?.try_lock().ok()?;
        let view = BaselineFailureView { state };
        if view.cause().is_some() { Some(view) } else { None }
    }

    pub(in crate::controller_receiving) fn operation_intake_demand_v1(&self)
        -> Result<ResourceVector, ControllerReceivingErrorV1>
    {
        let files = self.state.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?.files;
        let producer = Self::scope_demand(ScopeKind::Producer, files)?;
        let mut complete = ResourceVector::ZERO;
        for _ in 0..4 { complete = complete.checked_add(producer)?; }
        Ok(complete)
    }

    // Uses the exact recipe selected by begin_scope(Producer). This only lends
    // its cost DATA; the existing scope still performs actual same-C admission.
    pub(in crate::controller_receiving) fn create_storage_producer_demand_v1(
        &self,
    ) -> Result<ResourceVector, ControllerReceivingErrorV1> {
        let state = self.state.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        Self::scope_demand(ScopeKind::Producer, state.files)
    }

    // The native Producer recipe contributes traffic only through these same
    // fixed observer rows. File/pin counts change resident/native cost, not wire.
    pub(in crate::controller_receiving) fn create_storage_producer_traffic_bound_v1(
        producer_calls: usize,
    ) -> Option<(u64, u64)> {
        let row = super::fixed_property_observer_demand_v1(MATERIALIZED_BYTES).ok()?;
        let rows = u64::try_from(ScopeKind::Producer.rows()).ok()?
            .checked_mul(u64::try_from(producer_calls).ok()?)?;
        Some((row.get(D::NetworkBytes).checked_mul(rows)?,
            row.get(D::LogBytes).checked_mul(rows)?))
    }

    pub(in crate::controller_receiving) fn run_create_storage_producer(
        &self,
        compare: impl FnOnce() -> Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1>,
    ) -> Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1> {
        if self.is_nested()? {
            return Err(ControllerProfileErrorV1::Service);
        }
        // The sole profile caller first proves its exact live J/held-Cache
        // association. Dispatch only selects this original's shared B receiver.
        self.enter_receiving_dispatch()?;
        let result = compare();
        self.leave_receiving_dispatch();
        result
    }

    pub(in crate::controller_receiving) fn run_runtime_startup(
        &self,
        original: &Arc<ControllerReceivingOriginalV1>,
        compare: impl FnOnce() -> Result<(), ControllerProfileErrorV1>,
    ) -> Result<(), ControllerProfileErrorV1> {
        if !Arc::ptr_eq(&self.original, original) || self.is_nested()? {
            return Err(ControllerProfileErrorV1::Service);
        }
        {
            let state = self.state.try_lock().map_err(|_| ControllerProfileErrorV1::Service)?;
            if !state.initial_completed || state.failed_entry.is_some() || state.scope.is_some() {
                return Err(ControllerProfileErrorV1::Service);
            }
        }
        self.run(ScopeKind::RuntimeStartup, compare)
    }

    pub(super) fn begin_startup_credential_receiving(
        &self,
        original: &Arc<ControllerReceivingOriginalV1>,
        purpose: crate::controller_receiving::startup_envelope::CredentialPurposeV1,
    ) -> Result<(), ControllerProfileErrorV1> {
        if !Arc::ptr_eq(&self.original, original) || self.is_nested()? {
            return Err(ControllerProfileErrorV1::Service);
        }
        // Preserve the old credential entry order. Only this private fixed
        // receiver can retain the dispatch/scope across its actual native body.
        self.enter_receiving_dispatch()?;
        if let Err(cause) = self.begin_scope(credential_kind(purpose)) {
            let _post = self.finish(Err(cause), None);
            self.leave_receiving_dispatch();
            return Err(ControllerProfileErrorV1::Service);
        }
        Ok(())
    }

    pub(super) fn finish_startup_credential_receiving(
        &self,
        original: &Arc<ControllerReceivingOriginalV1>,
        purpose: crate::controller_receiving::startup_envelope::CredentialPurposeV1,
        comparison: Result<(), ControllerProfileErrorV1>,
    ) -> Result<(), ControllerProfileErrorV1> {
        if !Arc::ptr_eq(&self.original, original) {
            return Err(ControllerProfileErrorV1::Service);
        }
        {
            let state = self.current_state()?.try_lock()
                .map_err(|_| ControllerProfileErrorV1::Service)?;
            let scope = state.scope.as_ref().ok_or(ControllerProfileErrorV1::Service)?;
            if scope.thread != std::thread::current().id()
                || !same_credential_kind(scope.kind, purpose)
                || scope.completion.is_some()
            {
                return Err(ControllerProfileErrorV1::Service);
            }
        }
        // The comparison is derived only by this subtree's real native
        // before/after receiver; it is never an upper body Result or callback.
        let result = self.finish(comparison, None);
        self.leave_receiving_dispatch();
        result
    }

    pub(super) fn begin_construction_receiving(
        &self,
        profile: &ControllerSelfProfileOriginalV1,
        original: &Arc<ControllerReceivingOriginalV1>,
        purpose: crate::controller_receiving::construction::ControllerProfileConstructionPurposeV1,
    ) -> Result<(), ControllerProfileErrorV1> {
        if !Arc::ptr_eq(&self.original, original) || self.is_nested()? {
            return Err(ControllerProfileErrorV1::Service);
        }
        let kind = construction_kind(purpose);
        self.begin_scope(kind)?;
        self.enter_receiving_dispatch()?;

        // The entire actual role body remains between these producer rows.
        // Only its typed loan can later invoke the matching after observation.
        let before = profile.require_resource_producer();
        let mut state = self.current_state()?.try_lock()
            .map_err(|_| ControllerProfileErrorV1::Service)?;
        let scope = state.scope.as_mut().ok_or(ControllerProfileErrorV1::Service)?;
        scope.construction_before = Some(before);
        match scope.construction_before {
            Some(Ok(_)) => Ok(()),
            _ => Err(ControllerProfileErrorV1::Service),
        }
    }

    pub(super) fn finish_construction_receiving(
        &self,
        profile: &ControllerSelfProfileOriginalV1,
        original: &Arc<ControllerReceivingOriginalV1>,
        purpose: crate::controller_receiving::construction::ControllerProfileConstructionPurposeV1,
    ) -> Result<(), ControllerProfileErrorV1> {
        if !Arc::ptr_eq(&self.original, original) {
            return Err(ControllerProfileErrorV1::Service);
        }
        {
            let state = self.current_state()?.try_lock()
                .map_err(|_| ControllerProfileErrorV1::Service)?;
            let scope = state.scope.as_ref().ok_or(ControllerProfileErrorV1::Service)?;
            if scope.thread != std::thread::current().id()
                || !same_construction_kind(scope.kind, purpose)
                || scope.completion.is_some()
                || scope.construction_after.is_some()
            {
                return Err(ControllerProfileErrorV1::Service);
            }
        }

        // This post is driven by the actual typed interval. No upper body
        // Result or caller-supplied success flag selects its disposition.
        let after = profile.require_resource_producer();
        let (comparison, recipient) = {
            let mut state = self.current_state()?.try_lock()
                .map_err(|_| ControllerProfileErrorV1::Service)?;
            let scope = state.scope.as_mut().ok_or(ControllerProfileErrorV1::Service)?;
            scope.construction_after = Some(after);
            match (&scope.construction_before, &scope.construction_after) {
                (Some(Ok(before)), Some(Ok(after))) if before == after => (Ok(()), Some(*after)),
                _ => (Err(ControllerProfileErrorV1::Service), None),
            }
        };
        let returned = self.finish(comparison, recipient);
        self.leave_receiving_dispatch();
        returned
    }

    pub(in crate::controller_receiving) fn run_cache_initialization(
        &self,
        compare: impl FnOnce() -> Result<(), ControllerProfileErrorV1>,
    ) -> Result<(), ControllerProfileErrorV1> {
        // Only the selected initializer calls this private unit-returning
        // port. Its actual B receive is independent of prior P/I/Q archives;
        // ordinary profile calls cannot fall through or rearm those children.
        if self.is_nested()? {
            return Err(ControllerProfileErrorV1::Service);
        }
        if let Err(cause) = self.begin_scope(ScopeKind::CacheInitialization) {
            let _post = self.finish(Err(cause), None);
            return Err(ControllerProfileErrorV1::Service);
        }
        if self.enter_receiving_dispatch().is_err() {
            return self.finish(Err(ControllerProfileErrorV1::Service), None);
        }
        let result = compare();
        let completed = self.finish(result, None);
        // A negative scope remains closed/resident. Clearing dispatch is no
        // refund or child fallback; only complete positive finish disposes it.
        self.leave_receiving_dispatch();
        completed
    }

    pub(super) fn failure_view(&self) -> Option<BaselineFailureView<'_>> {
        let view = BaselineFailureView { state: self.state.try_lock().ok()? };
        if view.cause().is_some() { Some(view) } else { None }
    }

    pub(super) fn begin_initial(
        original: Arc<ControllerReceivingOriginalV1>,
    ) -> Self {
        Self {
            original,
            state: Mutex::new(ProfileState::new()),
            source_post: Mutex::new(ProfileState::new()),
            controller_post: Mutex::new(ProfileState::new()),
            post_dispatch: Mutex::new(None),
            receiving_dispatch: Mutex::new(None),
            operation_dispatch: Mutex::new(None),
            operation_scopes: std::array::from_fn(|_| OnceLock::new()),
            provisioning_scopes: OnceLock::new(),
            provisioning_dispatch: Mutex::new(None),
        }
    }

    pub(super) fn prepare_initial_once(&self) -> Result<(), ControllerProfileErrorV1> {
        self.begin_scope(ScopeKind::Initial)
    }

    pub(super) fn startup_pool_bounds(&self) -> Result<(ResourceVector, ResourceVector, ResourceVector), ControllerReceivingErrorV1> {
        let state = self.state.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if !state.initial_completed || state.failed_entry.is_some()
            || state.scope.as_ref().is_none_or(|scope| !matches!(scope.kind, ScopeKind::RuntimeStartup))
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok((Self::fixed_demand(4, state.files, false)?,
            Self::scope_demand(ScopeKind::SourceCredentials, state.files)?,
            Self::construction_demand(state.files)?))
    }

    pub(super) fn startup_envelope_requested_counts_v1(
        runtime_files: usize,
        shape: crate::controller_receiving::shapes::ControllerRuntimeStartupShapeV1,
        credentials: crate::controller_receiving::shapes::ControllerRuntimeCredentialShapeV1,
    ) -> Result<crate::controller_receiving::shapes::ControllerRuntimeRequestedCountsV1, ControllerReceivingErrorV1> {
        use aos_sandbox_model::component_receiving::complete_bound_delta_v1;
        use crate::controller_receiving::startup_envelope::ControllerStartupEnvelopeV1;

        if runtime_files > super::schema::MAXIMUM_RUNTIME_FILES {
            return Err(ControllerReceivingErrorV1::EnrollmentUnavailable);
        }
        let files = runtime_files.checked_add(4)
            .ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
        let profile = Self::fixed_demand(4, files, false)?;
        let construction = Self::construction_demand(files)?;
        let envelope = ControllerStartupEnvelopeV1::new(
            profile, Self::scope_demand(ScopeKind::SourceCredentials, files)?, construction,
            credentials.source_proof_files.ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?,
            credentials.public_tls_demand()?,
            if shape.publisher {
                crate::controller_receiving::publisher_schedule::operation_demand()?
            } else { ResourceVector::ZERO },
            shape.public_listener, shape.publisher,
        )?;
        // The pre-envelope Runtime scope is already permanently charged in
        // the SAME row; preserve it even if a future producer changes a bound.
        let startup = Self::scope_demand(ScopeKind::RuntimeStartup, files)?;
        let peak = complete_bound_delta_v1(startup, envelope.peak())?.0;
        let total = shape.fixed_demand()?.checked_add(credentials.resident_credential_demand()?)?
            .checked_add(peak)?;
        Ok(crate::controller_receiving::shapes::ControllerRuntimeRequestedCountsV1::from_demand(total))
    }

    pub(super) fn requested_counts_v1(
        runtime_files: usize,
    ) -> Result<super::ControllerProfileRequestedCountsV1, ControllerReceivingErrorV1> {
        use aos_sandbox_model::component_receiving::complete_bound_delta_v1;
        use crate::controller_receiving::shapes::ControllerRuntimeRequestedCountsV1 as Counts;

        if runtime_files > super::schema::MAXIMUM_RUNTIME_FILES {
            return Err(ControllerReceivingErrorV1::EnrollmentUnavailable);
        }
        // The actual retained admission's pins! recipe uses these same four:
        // PID1, canonical policy, source policy and effective matrix.
        let files = runtime_files.checked_add(4)
            .ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
        let startup = Self::scope_demand(ScopeKind::RuntimeStartup, files)?;
        let construction = Self::construction_demand(files)?;
        let (complete, _) = complete_bound_delta_v1(startup, construction)?;
        Ok(super::ControllerProfileRequestedCountsV1 {
            pin_files: files,
            runtime_startup: Counts::from_demand(startup),
            construction: Counts::from_demand(construction),
            complete: Counts::from_demand(complete),
        })
    }

    // Each Producer performs a nested Recheck before its second PID1 row.
    // A failed local primitive retains at most four Files: earlier positive
    // policy/subject/status/membership primitives have already retired their
    // actual Files. A failed first native row owns its seven-FD bound, while
    // both independent local posts can retain four each: fifteen. A failed
    // second row coexists with the earlier successful row's conservative two
    // retained slots and one local post: thirteen. Three local-only failures
    // use twelve. Fifteen therefore bounds this exact two-row producer.
    // Recheck needs at most seven native +four owed-local Files: eleven.
    // The successful-row two-slot term is deliberately conservative: the e0
    // worker destroys its Runtime and retires the actual socket before return.
    fn scope_demand(kind: ScopeKind, files: usize) -> Result<ResourceVector, ControllerReceivingErrorV1> {
        let receive_local_files = match kind {
            ScopeKind::Producer => 15,
            ScopeKind::Recheck => 11,
            ScopeKind::SourceInitialization | ScopeKind::CacheInitialization | ScopeKind::PublisherReadonly => 2 * 15,
            ScopeKind::SourceCredentials | ScopeKind::PublicCredentials
                | ScopeKind::SourceConstructionPost | ScopeKind::ControllerConstructionPost => 2 * 15,
            ScopeKind::RuntimeStartup => 2 * 15 + 7,
            _ => return Self::fixed_demand(kind.rows(), files, false),
        };
        Self::demand_with_receive_files(kind.rows(), files,
            matches!(kind, ScopeKind::RuntimeStartup), receive_local_files)
    }

    fn construction_demand(files: usize) -> Result<ResourceVector, ControllerReceivingErrorV1> {
        // The continuous two-producer primary interval and both independent
        // two-producer posts can coexist on failure. Keep all twelve actual
        // raw/model/traffic rows and six producer negative peaks.
        Self::demand_with_receive_files(CONSTRUCTION_ROWS, files, false, 6 * 15)
    }

    fn demand_with_receive_files(
        rows: usize,
        files: usize,
        runtime_pids: bool,
        receive_local_files: usize,
    ) -> Result<ResourceVector, ControllerReceivingErrorV1> {
        let unavailable = || ControllerReceivingErrorV1::EnrollmentUnavailable;
        let local_slots = MAXIMUM_LOCALS.checked_mul(if rows == CONSTRUCTION_ROWS {
            CONSTRUCTION_LANES
        } else { 1 }).ok_or_else(unavailable)?;
        let previous = rows.checked_mul(7).and_then(|drivers| drivers.checked_add(local_slots.checked_mul(4)?))
            .and_then(|count| u64::try_from(count).ok()).ok_or_else(unavailable)?;
        let retained = u64::try_from(receive_local_files).map_err(|_| unavailable())?;
        Self::fixed_demand(rows, files, runtime_pids)?
            .checked_sub(ResourceVector::ZERO.with(D::OpenFiles, previous))?
            .checked_add(ResourceVector::ZERO.with(D::OpenFiles, retained)).map_err(Into::into)
    }

    fn fixed_demand(
        rows: usize,
        files: usize,
        runtime_pids: bool,
    ) -> Result<ResourceVector, ControllerReceivingErrorV1> {
        let capacity = || ControllerReceivingErrorV1::EnrollmentUnavailable;
        let schema = super::schema::bounded_profile_representation_bytes_v1()
            .ok_or_else(capacity)?;
        // Initial admission can retain two immutable profile read buffers, the
        // selected executable-map reader and fixed status/fragment readers.
        // Every file digest/SELinux comparator streams fixed-size chunks.
        let local = ControllerSelfProfileOriginalV1::local_currentness_demand_for_pin_count_v1(files)
            .ok_or_else(capacity)?;
        // This is the COMPLETE selected-profile owner: the same retained
        // schema, pins and three inline scope slots (included in size_of Self)
        // coexist with these buffers and every observer row. Initial admission
        // has disposed its old archive/locals before the construction peak.
        // Primary, Source-post and Controller-post retained local buffers may
        // coexist after a failure. Those three concrete lanes are paid once.
        let local_slots = MAXIMUM_LOCALS.checked_mul(if rows == CONSTRUCTION_ROWS {
            CONSTRUCTION_LANES
        } else { 1 }).ok_or_else(capacity)?;
        let memory = schema.checked_add(2 * 1024 * 1024)
            .and_then(|bytes| bytes.checked_add(4 * 256 * 1024))

            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ProfileScope>()))
            .ok_or_else(capacity)?;
        // Fixed simultaneous Files outside local/worker rows: original policy
        // and enrollment (2), launch (1), original enrollment boot reader (1),
        // before/after control boot readers (2), measured profile/fragment/Nix
        // delivery (3), pidfd (1), and the initial fixed cgroup capture (6).
        // The selected admission actually retires successful subject/policy
        // Files before later acquisition; negative attempts stop that schedule.
        let mut demand = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| capacity())?)
            .with(D::OpenFiles, u64::try_from(files.checked_add(16).ok_or_else(capacity)?)
                .map_err(|_| capacity())?)
            // One selected caller and one sequential joined observer worker.
            .with(D::Pids, 2);
        // Every actual local owner has authoritative lower native geometry.
        // This includes all six retained failure destinations per named lane.
        for _ in 0..local_slots {
            demand = demand.checked_add(local)?;
        }
        // Shared worker geometry prices each actual row's Entry/Original.
        // Its archive container and actual Vec backing remain this owner.
        let archive_bytes = service::FirstGlobalPropertyArchive::inline_bytes_v1()
            .checked_add(rows.checked_mul(service::FirstGlobalPropertyArchive::entry_bytes_v1()).ok_or_else(capacity)?)
            .and_then(|bytes| bytes.checked_add(7 * 4096
                * if rows == CONSTRUCTION_ROWS { CONSTRUCTION_LANES } else { 1 }))
            .ok_or_else(capacity)?;
        demand = demand.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(archive_bytes).map_err(|_| capacity())?))?;
        let observer = super::fixed_property_observer_demand_v1(MATERIALIZED_BYTES)
            .map_err(|_| capacity())?;
        for _ in 0..rows {
            demand = demand.checked_add(observer)?;
        }
        if runtime_pids {
            use aos_sandbox_linux::cgroup::PidsLimitReadbackV1 as Pids;
            let bytes = Pids::dominant_requested_bytes_v1().ok_or_else(capacity)?;
            demand = demand.checked_add(ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| capacity())?)
                .with(D::OpenFiles, u64::try_from(Pids::MAXIMUM_RETAINED_FILES_V1)
                    .map_err(|_| capacity())?))?;
        }
        Ok(demand)
    }

    // Native-only complete owner growth before actual pin File acquisition.
    pub(super) fn require_pin_count(&self, files: usize) -> Result<(), ControllerProfileErrorV1> {
        let mut state = self.state.try_lock().map_err(|_| ControllerProfileErrorV1::Service)?;
        if state.failed_entry.is_some() || state.initial_completed
            || state.scope.as_ref().is_none_or(|scope| !matches!(scope.kind, ScopeKind::Initial))
        {
            return Err(ControllerProfileErrorV1::Service);
        }
        let demand = match Self::fixed_demand(ScopeKind::Initial.rows(), files, false) {
            Ok(demand) => demand,
            Err(cause) => {
                state.failed_entry = Some(cause);
                return Err(ControllerProfileErrorV1::Service);
            }
        };
        if let Err(cause) = self.original.raise_profile_complete(demand) {
            state.failed_entry = Some(cause);
            return Err(ControllerProfileErrorV1::Service);
        }
        state.files = files;
        Ok(())
    }

    fn current_state(&self) -> Result<&Mutex<ProfileState>, ControllerProfileErrorV1> {
        let provisioning = self.provisioning_dispatch.try_lock().map_err(|_| ControllerProfileErrorV1::Service)?;
        if let Some((thread, slot)) = *provisioning {
            if thread != std::thread::current().id() { return Err(ControllerProfileErrorV1::Service); }
            return self.provisioning_scopes.get().and_then(|pool| pool.states.get(slot))
                .ok_or(ControllerProfileErrorV1::Service);
        }
        drop(provisioning);
        let operation = self.operation_dispatch.try_lock().map_err(|_| ControllerProfileErrorV1::Service)?;
        if let Some((thread, purpose, slot)) = *operation {
            if thread != std::thread::current().id() || slot >= purpose.profile_pool_slots() {
                return Err(ControllerProfileErrorV1::Service);
            }
            return self.operation_scopes[purpose.index()].get()
                .and_then(|scopes| scopes.get(slot)).ok_or(ControllerProfileErrorV1::Service);
        }
        let dispatch = self.post_dispatch.try_lock().map_err(|_| ControllerProfileErrorV1::Service)?;
        match *dispatch {
            Some((thread, _)) if thread != std::thread::current().id() => Err(ControllerProfileErrorV1::Service),
            Some((_, ControllerConstructionPostV1::SourceConstruction)) => Ok(&self.source_post),
            Some((_, ControllerConstructionPostV1::ControllerConstruction)) => Ok(&self.controller_post),
            None => Ok(&self.state),
        }
    }

    pub(super) fn reserve_construction_posts_once(
        &self,
        original: &Arc<ControllerReceivingOriginalV1>,
    ) -> Result<(), ControllerProfileErrorV1> {
        if !Arc::ptr_eq(&self.original, original) {
            return Err(ControllerProfileErrorV1::Service);
        }
        let mut state = self.state.try_lock().map_err(|_| ControllerProfileErrorV1::Service)?;
        if state.scope.is_some() || state.failed_entry.is_some() || !state.initial_completed {
            return Err(ControllerProfileErrorV1::Service);
        }
        let demand = Self::construction_demand(state.files);
        let returned = demand.and_then(|demand| self.original.reserve_construction_posts_once(demand));
        if let Err(cause) = returned {
            state.failed_entry = Some(cause);
            return Err(ControllerProfileErrorV1::Service);
        }
        self.source_post.try_lock().map_err(|_| ControllerProfileErrorV1::Service)?.files = state.files;
        self.controller_post.try_lock().map_err(|_| ControllerProfileErrorV1::Service)?.files = state.files;
        Ok(())
    }

    pub(super) fn run_construction_post(
        &self,
        purpose: ControllerConstructionPostV1,
        compare: impl FnOnce() -> Result<(), ControllerProfileErrorV1>,
    ) -> Result<(), ControllerProfileErrorV1> {
        {
            let mut dispatch = self.post_dispatch.try_lock().map_err(|_| ControllerProfileErrorV1::Service)?;
            if dispatch.is_some() {
                return Err(ControllerProfileErrorV1::Service);
            }
            *dispatch = Some((std::thread::current().id(), purpose));
        }
        let kind = match purpose {
            ControllerConstructionPostV1::SourceConstruction => ScopeKind::SourceConstructionPost,
            ControllerConstructionPostV1::ControllerConstruction => ScopeKind::ControllerConstructionPost,
        };
        let returned = self.run(kind, compare);
        // Removing dispatch never reopens the permanently spent named lane.
        *self.post_dispatch.try_lock().map_err(|_| ControllerProfileErrorV1::Service)? = None;
        returned
    }

    fn begin_scope(&self, kind: ScopeKind) -> Result<(), ControllerProfileErrorV1> {
        let mut state = self.current_state()?.try_lock().map_err(|_| ControllerProfileErrorV1::Service)?;
        if state.scope.is_some() || state.failed_entry.is_some() {
            return Err(ControllerProfileErrorV1::Service);
        }
        let operation = *self.operation_dispatch.try_lock().map_err(|_| ControllerProfileErrorV1::Service)?;
        let provisioning = *self.provisioning_dispatch.try_lock()
            .map_err(|_| ControllerProfileErrorV1::Service)?;
        let entered = if let Some((thread, slot)) = provisioning {
            if thread != std::thread::current().id() || !matches!(kind, ScopeKind::Producer) {
                Err(ControllerReceivingErrorV1::Conflict)
            } else {
                self.take_provisioning_control_v1(slot)
            }
        } else {
            match operation {
                Some((thread, purpose, slot)) if thread == std::thread::current().id()
                    && matches!(kind, ScopeKind::Producer) => self.original.begin_operation_intake_profile_v1(purpose, slot),
                Some(_) => Err(ControllerReceivingErrorV1::Conflict),
                None => match kind {
                ScopeKind::SourceConstructionPost => self.original.begin_construction_post(ControllerConstructionPostV1::SourceConstruction),
                ScopeKind::ControllerConstructionPost => self.original.begin_construction_post(ControllerConstructionPostV1::ControllerConstruction),
                _ => Self::scope_demand(kind, state.files)
                    .and_then(|demand| self.original.begin_profile_scope(demand)),
                },
            }
        };
        let control = match entered {
            Ok(control) => control,
            Err(cause) => {
                state.failed_entry = Some(cause);
                return Err(ControllerProfileErrorV1::Service);
            }
        };
        state.scope = Some(ProfileScope {
            control,
            archive: None,
            preparation: None,
            local: [const { None }; MAXIMUM_LOCALS],
            next_local: 0,
            comparisons: [const { None }; MAXIMUM_LOCALS],
            next_comparison: 0,
            first_failure: None,
            construction_before: None,
            construction_after: None,
            canonical: [const { None }; MAXIMUM_LOCALS],
            canonical_binding: [const { None }; MAXIMUM_LOCALS],
            next_canonical: 0,
            completion: None,
            control_post: None,
            recipient: None,
            settlement: None,
            thread: std::thread::current().id(),
            kind,
        });
        let scope = state.scope.as_mut().ok_or(ControllerProfileErrorV1::Service)?;
        scope.control.require_before().map_err(|_| ControllerProfileErrorV1::Service)?;
        // All dynamic receiver fields follow the original ledger admission.
        scope.archive = Some(service::FirstGlobalPropertyArchive::with_materialization_limit(
            kind.rows(), MATERIALIZED_BYTES,
        ));
        scope.preparation = Some(scope.archive.as_mut()
            .ok_or(ControllerProfileErrorV1::Service)?.prepare_once().map_err(|_| ControllerProfileErrorV1::Service));
        positive(&scope.preparation)
    }

    fn is_nested(&self) -> Result<bool, ControllerProfileErrorV1> {
        let state = self.current_state()?.try_lock().map_err(|_| ControllerProfileErrorV1::Service)?;
        if state.failed_entry.is_some() {
            return Err(ControllerProfileErrorV1::Service);
        }
        match state.scope.as_ref() {
            Some(scope) if scope.thread == std::thread::current().id()
                && scope.completion.is_none() => Ok(true),
            Some(_) => Err(ControllerProfileErrorV1::Service),
            None => Ok(false),
        }
    }

    pub(super) fn read(
        &self,
        unit: &'static str,
        pid: u32,
        properties: &'static [&'static str],
    ) -> Result<service::PropertyPairV1, ControllerProfileErrorV1> {
        let mut state = self.current_state()?.try_lock().map_err(|_| ControllerProfileErrorV1::Service)?;
        let scope = state.scope.as_mut().ok_or(ControllerProfileErrorV1::Service)?;
        if scope.thread != std::thread::current().id() || scope.completion.is_some() {
            return Err(ControllerProfileErrorV1::Service);
        }
        let archive = scope.archive.as_mut().ok_or(ControllerProfileErrorV1::Service)?;
        let observed = if unit == service::CONTROLLER_UNIT && pid == std::process::id()
            && properties == service::SERVICE_PROPERTIES
        {
            service::read_controller_startup_with_archive(archive)
        } else if unit == service::CONTROLLER_UNIT && pid == std::process::id()
            && properties == service::RESOURCE_SERVICE_PROPERTIES
        {
            service::read_controller_resource_with_archive(archive)
        } else if matches!(scope.kind, ScopeKind::RuntimeStartup)
            && unit == service::CONTROLLER_UNIT && pid == std::process::id()
            && properties == service::RUNTIME_TASK_PROPERTIES
        {
            archive.read(unit, pid, properties, service::UNIT_PROPERTIES)
                .map(|(service, unit)| (super::property_values::PropertyValuesV1::retained_owned(service), super::property_values::PropertyValuesV1::retained_owned(unit)))
                .map_err(|_| ControllerProfileErrorV1::Service)
        } else if matches!(scope.kind, ScopeKind::Peer)
            && unit == super::schema::UNIT && pid != 0
            && properties == service::PEER_PROPERTIES
        {
            archive.read(unit, pid, properties, service::UNIT_PROPERTIES)
                .map(|(service, unit)| (super::property_values::PropertyValuesV1::retained_owned(service), super::property_values::PropertyValuesV1::retained_owned(unit)))
                .map_err(|_| ControllerProfileErrorV1::Service)
        } else {
            Err(ControllerProfileErrorV1::Service)
        };
        match observed {
            Ok(values) => Ok(values),
            Err(cause) => {
                let index = scope.next_comparison;
                let first = scope.first_failure.is_none();
                let _retained = scope.retain_comparison(Err(cause));
                if first {
                    scope.first_failure = Some(FirstFailure::Property(index));
                }
                Err(ControllerProfileErrorV1::Service)
            }
        }
    }

    pub(super) fn canonicalize_observation(
        &self,
        observed: super::delivery::ServiceObservationV1,
    ) -> Result<super::delivery::ServiceObservationV1, ControllerProfileErrorV1> {
        let mut state = self.current_state()?.try_lock()
            .map_err(|_| ControllerProfileErrorV1::Service)?;
        let scope = state.scope.as_mut().ok_or(ControllerProfileErrorV1::Service)?;
        if scope.thread != std::thread::current().id()
            || scope.completion.is_some()
            || scope.next_canonical >= scope.canonical.len()
        {
            return Err(ControllerProfileErrorV1::Service);
        }
        let index = scope.next_canonical;
        scope.next_canonical += 1;
        let result = canonicalize_into(
            observed, &mut scope.canonical[index], &mut scope.canonical_binding[index],
        );
        if result.is_err() && scope.first_failure.is_none() {
            scope.first_failure = Some(FirstFailure::Canonical(index));
        }
        result
    }

    // Parks the actual semantic error before independent local/native posts.
    // The two callers return only unit or Copy recipient DATA, never originals.
    pub(in crate::controller_receiving) fn retain_comparison(
        &self,
        result: Result<(), ControllerProfileErrorV1>,
    ) -> Result<(), ControllerProfileErrorV1> {
        let mut state = self.current_state()?.try_lock().map_err(|_| ControllerProfileErrorV1::Service)?;
        let scope = state.scope.as_mut().ok_or(ControllerProfileErrorV1::Service)?;
        scope.retain_comparison(result)
    }

    pub(super) fn capture_local(
        &self,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerProfileErrorV1> {
        let mut state = self.current_state()?.try_lock().map_err(|_| ControllerProfileErrorV1::Service)?;
        let scope = state.scope.as_mut().ok_or(ControllerProfileErrorV1::Service)?;
        if scope.thread != std::thread::current().id() || scope.next_local >= MAXIMUM_LOCALS {
            return Err(ControllerProfileErrorV1::Service);
        }
        let slot = scope.next_local;
        scope.next_local += 1;
        scope.local[slot] = Some(ControllerProfileLocalCurrentnessOriginalV1::new());
        let local = scope.local[slot].as_mut().ok_or(ControllerProfileErrorV1::Service)?;
        let _returned = profile.observe_local_currentness_retaining_v1(local);
        let returned = positive(&local.local.completion);
        if returned.is_err() && scope.first_failure.is_none() {
            scope.first_failure = Some(FirstFailure::Local(slot));
        }
        returned
    }

    pub(super) fn run(
        &self,
        kind: ScopeKind,
        compare: impl FnOnce() -> Result<(), ControllerProfileErrorV1>,
    ) -> Result<(), ControllerProfileErrorV1> {
        if self.is_nested()? {
            return compare();
        }
        if let Err(cause) = self.begin_scope(kind) {
            let _post = self.finish(Err(cause), None);
            return Err(ControllerProfileErrorV1::Service);
        }
        match compare() {
            Ok(()) => self.finish(Ok(()), None),
            Err(cause) => {
                self.finish(Err(cause), None)?;
                Err(ControllerProfileErrorV1::Service)
            }
        }
    }

    pub(super) fn run_peer<'profile>(
        &self,
        compare: impl FnOnce() -> Result<super::ControllerStartupRootPeerV1<'profile>, ControllerProfileErrorV1>,
    ) -> Result<super::ControllerStartupRootPeerV1<'profile>, ControllerProfileErrorV1> {
        // Only recheck_stream is nested inside peer construction. A second
        // owning peer construction cannot borrow another scope's disposition.
        if self.is_nested()? {
            return Err(ControllerProfileErrorV1::Service);
        }
        if let Err(cause) = self.begin_scope(ScopeKind::Peer) {
            let _post = self.finish(Err(cause), None);
            return Err(ControllerProfileErrorV1::Service);
        }
        match compare() {
            Ok(peer) => match self.finish(Ok(()), None) {
                Ok(()) => Ok(peer),
                Err(_) => {
                    // The successful returned cgroup/fragment originals must
                    // remain resident if a later control or Ended post fails.
                    // Abort does not unwind or release this actual peer.
                    let _original = &peer;
                    std::process::abort();
                }
            },
            Err(cause) => {
                self.finish(Err(cause), None)?;
                Err(ControllerProfileErrorV1::Service)
            }
        }
    }

    pub(super) fn run_producer(
        &self,
        compare: impl FnOnce() -> Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1>,
    ) -> Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1> {
        if self.is_nested()? {
            return compare();
        }
        if let Err(cause) = self.begin_scope(ScopeKind::Producer) {
            let _post = self.finish(Err(cause), None);
            return Err(ControllerProfileErrorV1::Service);
        }
        match compare() {
            Ok(pair) => {
                self.finish(Ok(()), Some(pair))?;
                Ok(pair)
            }
            Err(cause) => {
                self.finish(Err(cause), None)?;
                Err(ControllerProfileErrorV1::Service)
            }
        }
    }

    pub(super) fn refuse_initial(&self) {
        // No new receiver is constructed. A previously funded control scope
        // still receives its independent original-file post after refusal.
        let _post = self.finish(Err(ControllerProfileErrorV1::Profile), None);
    }

    pub(super) fn finish_initial(
        &self,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerProfileErrorV1> {
        let result = profile.require_resource_producer();
        let (result, recipient) = match result {
            Ok((invocation, producer)) => (Ok(()), Some((invocation, producer))),
            Err(cause) => (Err(cause), None),
        };
        self.finish(result, recipient)?;
        self.current_state()?.try_lock().map_err(|_| ControllerProfileErrorV1::Service)?.initial_completed = true;
        Ok(())
    }

    fn finish(
        &self,
        result: Result<(), ControllerProfileErrorV1>,
        recipient: Option<([u8; 16], [u8; 16])>,
    ) -> Result<(), ControllerProfileErrorV1> {
        let mut state = self.current_state()?.try_lock().map_err(|_| ControllerProfileErrorV1::Service)?;
        let scope = state.scope.as_mut().ok_or(ControllerProfileErrorV1::Service)?;
        if scope.thread != std::thread::current().id() || scope.completion.is_some() {
            return Err(ControllerProfileErrorV1::Service);
        }
        if result.is_err() && scope.first_failure.is_none() {
            scope.first_failure = Some(FirstFailure::Completion);
        }
        scope.completion = Some(result);
        // The real original negative post is independent of semantic failure.
        scope.control_post = Some(scope.control.finish_once());
        if let Some((invocation, producer)) = recipient {
            scope.recipient = Some(scope.control.require_recipient(invocation, producer));
        }
        if scope.failure().is_some()
            || !matches!(scope.completion, Some(Ok(_)))
            || !matches!(scope.control_post, Some(Ok(())))
            || matches!(scope.recipient, Some(Err(_)))
            || matches!(scope.kind, ScopeKind::Initial | ScopeKind::Producer
                | ScopeKind::SourceInitialization | ScopeKind::CacheInitialization | ScopeKind::PublisherReadonly)
                && !matches!(scope.recipient, Some(Ok(())))
            || scope.local.iter().flatten().any(|local| !matches!(local.local.completion, Some(Ok(()))))
        {
            return Err(ControllerProfileErrorV1::Service);
        }
        scope.settlement = Some(scope.archive.as_mut()
            .ok_or(ControllerProfileErrorV1::Service)?.settle_positive_once().map_err(|_| ControllerProfileErrorV1::Service));
        positive(&scope.settlement)?;
        if scope.control.uses_operation_intake_v1() {
            let prepared = scope.control.prepare_operation_intake_disposal_v1()
                .map_err(|_| ControllerProfileErrorV1::Service)?;
            drop(scope.archive.take());
            for local in &mut scope.local { drop(local.take()); }
            prepared.complete_after_disposal_v1();
        } else {
            // Ordinary disposal keeps its existing ordering and funding route.
            drop(scope.archive.take());
            for local in &mut scope.local { drop(local.take()); }
            scope.control.retire_positive_once().map_err(|_| ControllerProfileErrorV1::Service)?;
        }
        drop(state.scope.take());
        Ok(())
    }
}

impl ProfileScope {
    fn retain_comparison(
        &mut self,
        result: Result<(), ControllerProfileErrorV1>,
    ) -> Result<(), ControllerProfileErrorV1> {
        // Successful DATA has no cause to retain. Failed comparisons are kept
        // individually, including independent posts after an earlier failure.
        if result.is_ok() {
            return Ok(());
        }
        if self.next_comparison >= self.comparisons.len() {
            // Preserve the consuming error on this stack through termination.
            let _original = &result;
            std::process::abort();
        }
        let index = self.next_comparison;
        self.next_comparison += 1;
        self.comparisons[index] = Some(result);
        if self.first_failure.is_none() {
            self.first_failure = Some(FirstFailure::Comparison(index));
        }
        Err(ControllerProfileErrorV1::Service)
    }

    fn failure_phase(&self) -> Option<&'static str> {
        self.failure()?;
        if self.control.before_failure().is_some() {
            return Some("baseline-control-before");
        }
        if retained_error(&self.preparation).is_some() {
            return Some("baseline-receiver-preparation");
        }
        match self.first_failure {
            Some(FirstFailure::Local(_)) => return Some("baseline-local-currentness"),
            Some(FirstFailure::Comparison(_)) => return Some("baseline-comparison"),
            Some(FirstFailure::Completion) => return Some("baseline-semantic-completion"),
            Some(FirstFailure::Canonical(_)) => return Some("baseline-fragment-canonicalization"),
            Some(FirstFailure::Property(_)) => return Some("baseline-property-flight"),
            None => {}
        }
        if self.control.failure().is_some() || retained_error(&self.control_post).is_some() {
            Some("baseline-control-after")
        } else if retained_error(&self.recipient).is_some() {
            Some("baseline-recipient")
        } else {
            Some("baseline-settlement")
        }
    }

    fn failure_classification(&self) -> ControllerProfileErrorV1 {
        // Local positive()/positive_ref() already return Service. This bridge
        // preserves that classification; it does not invent a richer mapping.
        if self.control.before_failure().is_some() {
            return ControllerProfileErrorV1::Service;
        }
        if let Some(Err(cause)) = &self.preparation {
            return legacy_classification(cause);
        }
        let receiver = match self.first_failure {
            Some(FirstFailure::Local(index)) => self.local[index].as_ref()
                .and_then(|local| local.local.completion.as_ref()).and_then(|result| result.as_ref().err()),
            Some(FirstFailure::Comparison(index) | FirstFailure::Property(index)) => self.comparisons[index].as_ref()
                .and_then(|result| result.as_ref().err()),
            Some(FirstFailure::Completion) => self.completion.as_ref()
                .and_then(|result| result.as_ref().err()),
            Some(FirstFailure::Canonical(_)) => return ControllerProfileErrorV1::Service,
            None => None,
        };
        if let Some(cause) = receiver {
            return legacy_classification(cause);
        }
        if self.control.failure().is_some() || retained_error(&self.control_post).is_some()
            || retained_error(&self.recipient).is_some()
        {
            return ControllerProfileErrorV1::Service;
        }
        self.settlement.as_ref().and_then(|result| result.as_ref().err())
            .map_or(ControllerProfileErrorV1::Service, legacy_classification)
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Before equality/process binding predates every receiver and post.
        // The chronological marker then preserves semantic failure ahead of
        // an independently required later local/native comparison failure.
        self.control.before_failure()
            .or_else(|| retained_error(&self.preparation))
            .or_else(|| match self.first_failure {
                Some(FirstFailure::Local(index)) => self.local[index].as_ref()
                    .and_then(ControllerProfileLocalCurrentnessOriginalV1::failure),
                Some(FirstFailure::Comparison(index) | FirstFailure::Property(index)) => retained_error(&self.comparisons[index]),
                Some(FirstFailure::Completion) => retained_error(&self.completion),
                Some(FirstFailure::Canonical(index)) => canonical_failure(
                    &self.canonical[index], &self.canonical_binding[index],
                ),
                None => None,
            })
            .or_else(|| self.control.failure())
            .or_else(|| retained_error(&self.control_post))
            .or_else(|| retained_error(&self.recipient))
            .or_else(|| retained_error(&self.settlement))
    }
}

impl Drop for ControllerBaselineProfileV1 {
    fn drop(&mut self) {
        let abandoned = [&mut self.state, &mut self.source_post, &mut self.controller_post]
            .into_iter().any(|state| state.get_mut().map_or(true, |state| {
                state.failed_entry.is_some() || state.scope.is_some()
            }));
        let operation_unfinished = self.operation_scopes.iter_mut().any(|pool| {
            pool.get_mut().is_some_and(|scopes| scopes.iter_mut().any(|state| {
                state.get_mut().map_or(true, |state| state.failed_entry.is_some() || state.scope.is_some())
            }))
        });
        if abandoned || operation_unfinished {
            std::process::abort();
        }
    }
}

// Canonicalize may succeed while UTF8/store-path comparison still refuses.
// Park that actual semantic error before returning a stopping projection; the
// same indexed cause must precede every independently owed later native post.
fn canonicalize_into(
    observed: super::delivery::ServiceObservationV1,
    canonical: &mut Option<std::io::Result<std::path::PathBuf>>,
    binding: &mut Option<Result<(), ControllerProfileErrorV1>>,
) -> Result<super::delivery::ServiceObservationV1, ControllerProfileErrorV1> {
    match super::delivery::immutable_observation_into(observed, canonical) {
        Ok(observed) => {
            *binding = Some(Ok(()));
            Ok(observed)
        }
        Err(cause) => {
            *binding = Some(Err(cause));
            Err(ControllerProfileErrorV1::Service)
        }
    }
}

fn canonical_failure<'original>(
    canonical: &'original Option<std::io::Result<std::path::PathBuf>>,
    binding: &'original Option<Result<(), ControllerProfileErrorV1>>,
) -> Option<&'original (dyn std::error::Error + 'static)> {
    retained_error(canonical).or_else(|| retained_error(binding))
}

fn positive<T, E>(result: &Option<Result<T, E>>) -> Result<(), ControllerProfileErrorV1> {
    positive_ref(result.as_ref()).map(|_| ())
}

fn positive_ref<T, E>(result: Option<&Result<T, E>>) -> Result<&T, ControllerProfileErrorV1> {
    result.and_then(|result| result.as_ref().ok()).ok_or(ControllerProfileErrorV1::Service)
}

fn retained_error<T, E: std::error::Error + 'static>(
    result: &Option<Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    result.as_ref().and_then(|result| result.as_ref().err())
        .map(|cause| cause as &(dyn std::error::Error + 'static))
}

// Selected admission's public chain retains its original privacy boundary.
// Additional owning startup variants remain private behind Service as well.
fn legacy_classification(cause: &ControllerProfileErrorV1) -> ControllerProfileErrorV1 {
    match cause {
        ControllerProfileErrorV1::Activation => ControllerProfileErrorV1::Activation,
        ControllerProfileErrorV1::Profile => ControllerProfileErrorV1::Profile,
        ControllerProfileErrorV1::Image => ControllerProfileErrorV1::Image,
        ControllerProfileErrorV1::Confinement => ControllerProfileErrorV1::Confinement,
        _ => ControllerProfileErrorV1::Service,
    }
}


fn construction_kind(
    purpose: crate::controller_receiving::construction::ControllerProfileConstructionPurposeV1,
) -> ScopeKind {
    use crate::controller_receiving::construction::ControllerProfileConstructionPurposeV1 as Purpose;
    match purpose {
        Purpose::Source => ScopeKind::SourceInitialization,
        Purpose::Cache => ScopeKind::CacheInitialization,
        Purpose::PublisherReadonly => ScopeKind::PublisherReadonly,
    }
}

fn same_construction_kind(
    kind: ScopeKind,
    purpose: crate::controller_receiving::construction::ControllerProfileConstructionPurposeV1,
) -> bool {
    matches!((kind, construction_kind(purpose)),
        (ScopeKind::SourceInitialization, ScopeKind::SourceInitialization)
        | (ScopeKind::CacheInitialization, ScopeKind::CacheInitialization)
        | (ScopeKind::PublisherReadonly, ScopeKind::PublisherReadonly))
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    #[test]
    fn failed_entry_without_scope_borrows_actual_cause_and_reports_service() {
        let mut state = ProfileState::new();
        let native = aos_sandbox_model::ResourceVector::ZERO.checked_sub(
            aos_sandbox_model::ResourceVector::ZERO.with(D::MemoryBytes, 1),
        ).unwrap_err();
        state.failed_entry = Some(ControllerReceivingErrorV1::Accounting(native));
        let state = Mutex::new(state);
        let view = BaselineFailureView { state: state.lock().unwrap() };

        assert_eq!(view.phase(), "baseline-entry");
        assert!(matches!(view.classification(), ControllerProfileErrorV1::Service));
        let cause = view.cause().unwrap();
        let original = view.state.failed_entry.as_ref().unwrap();
        assert!(std::ptr::eq(cause.downcast_ref::<ControllerReceivingErrorV1>().unwrap(), original));

        let ControllerReceivingErrorV1::Accounting(native) = original else {
            panic!("the retained entry must own its original Core refusal");
        };
        let ControllerReceivingErrorV1::Accounting(borrowed_native) =
            cause.downcast_ref::<ControllerReceivingErrorV1>().unwrap() else {
                panic!("the diagnostic must borrow the actual accounting refusal");
            };
        assert!(std::ptr::eq(borrowed_native, native));
        assert_eq!(cause.to_string(), native.to_string());
        // A transparent wrapper delegates source(), rather than inserting the
        // wrapped error as an additional source-chain node.
        assert!(std::error::Error::source(native).is_none());
        assert!(std::error::Error::source(cause).is_none());
    }
}

#[cfg(test)]
mod native_geometry_tests {
    use super::*;

    #[test]
    fn native_phase_recipe_changes_only_descriptors_and_keeps_generic_scopes() {
        let files = 9;
        for kind in [ScopeKind::Initial, ScopeKind::Peer] {
            assert_eq!(ControllerBaselineProfileV1::scope_demand(kind, files).unwrap(),
                ControllerBaselineProfileV1::fixed_demand(kind.rows(), files, false).unwrap());
        }
        for kind in [ScopeKind::Producer, ScopeKind::Recheck, ScopeKind::RuntimeStartup,
            ScopeKind::SourceInitialization, ScopeKind::CacheInitialization, ScopeKind::PublisherReadonly,
            ScopeKind::SourceCredentials, ScopeKind::PublicCredentials,
            ScopeKind::SourceConstructionPost, ScopeKind::ControllerConstructionPost]
        {
            let legacy = ControllerBaselineProfileV1::fixed_demand(kind.rows(), files,
                matches!(kind, ScopeKind::RuntimeStartup)).unwrap();
            let actual = ControllerBaselineProfileV1::scope_demand(kind, files).unwrap();
            for dimension in D::ALL {
                if dimension != D::OpenFiles {
                    assert_eq!(actual.get(dimension), legacy.get(dimension));
                }
            }
            assert!(legacy.checked_sub(actual).is_ok());
        }
        let legacy = ControllerBaselineProfileV1::fixed_demand(CONSTRUCTION_ROWS, files, false).unwrap();
        let actual = ControllerBaselineProfileV1::construction_demand(files).unwrap();
        for dimension in D::ALL {
            if dimension != D::OpenFiles {
                assert_eq!(actual.get(dimension), legacy.get(dimension));
            }
        }
        assert_eq!(legacy.get(D::OpenFiles) - actual.get(D::OpenFiles), 66);
    }
}

#[cfg(test)]
mod canonical_cause_tests {
    use super::*;
    use super::super::delivery::ServiceObservationV1;

    #[test]
    fn successful_native_canonicalization_preserves_earlier_store_refusal() {
        let directory = tempfile::tempdir().unwrap();
        let mut canonical = None;
        let mut binding = None;

        assert!(canonicalize_into(ServiceObservationV1 {
            fragment: directory.path().to_path_buf(),
            invocation: [1; 16],
        }, &mut canonical, &mut binding).is_err());
        assert!(matches!(canonical, Some(Ok(_))));
        let original = binding.as_ref().unwrap().as_ref().unwrap_err();
        let cause = canonical_failure(&canonical, &binding).unwrap()
            .downcast_ref::<ControllerProfileErrorV1>().unwrap();

        assert!(std::ptr::eq(original, cause));
    }

    #[test]
    fn canonical_native_failure_precedes_its_stopping_semantic_projection() {
        let directory = tempfile::tempdir().unwrap();
        let mut canonical = None;
        let mut binding = None;

        assert!(canonicalize_into(ServiceObservationV1 {
            fragment: directory.path().join("absent"),
            invocation: [1; 16],
        }, &mut canonical, &mut binding).is_err());
        let original = canonical.as_ref().unwrap().as_ref().unwrap_err();
        let cause = canonical_failure(&canonical, &binding).unwrap()
            .downcast_ref::<std::io::Error>().unwrap();

        assert!(std::ptr::eq(original, cause));
        assert!(matches!(binding, Some(Err(_))));
    }
}

fn credential_kind(purpose: crate::controller_receiving::startup_envelope::CredentialPurposeV1) -> ScopeKind {
    match purpose {
        crate::controller_receiving::startup_envelope::CredentialPurposeV1::SourceGenesis => ScopeKind::SourceCredentials,
        crate::controller_receiving::startup_envelope::CredentialPurposeV1::PublicTls => ScopeKind::PublicCredentials,
    }
}

fn same_credential_kind(kind: ScopeKind, purpose: crate::controller_receiving::startup_envelope::CredentialPurposeV1) -> bool {
    matches!((kind, purpose),
        (ScopeKind::SourceCredentials, crate::controller_receiving::startup_envelope::CredentialPurposeV1::SourceGenesis)
        | (ScopeKind::PublicCredentials, crate::controller_receiving::startup_envelope::CredentialPurposeV1::PublicTls))
}

#[cfg(test)]
mod create_storage_producer_traffic_tests {
    use super::*;

    #[test]
    fn fixed_bound_matches_the_actual_complete_producer_recipe_for_all_pin_counts() {
        for files in [0, 1, 4, 32] {
            let actual = ControllerBaselineProfileV1::scope_demand(ScopeKind::Producer, files).unwrap();
            for calls in [0, 1, 2, 17] {
                let (wire, logs) = ControllerBaselineProfileV1::create_storage_producer_traffic_bound_v1(calls).unwrap();
                assert_eq!(wire, actual.get(D::NetworkBytes) * calls as u64);
                assert_eq!(logs, actual.get(D::LogBytes) * calls as u64);
            }
        }
        #[cfg(target_pointer_width = "64")]
        assert!(ControllerBaselineProfileV1::create_storage_producer_traffic_bound_v1(usize::MAX).is_none());
    }
}

pub(in crate::controller_receiving) mod provisioning;
