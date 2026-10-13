//! Retains one paid ordinary capture operation across native borrow and physical end.
//!
//! The inline holder belongs to the admitted controller allocation. A callback
//! borrows the operation already entered by the outer caller; refusal never moves
//! it to a stack pointer or lets its source/page exclusion disappear.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::super::engine::OrdinaryPagingCustody;
use super::*;
use crate::ram_fingerprint::FingerprintBaseline;
use crate::runtime::FingerprintBorrowContext;

#[derive(Default)]
pub(super) struct FingerprintState {
    issued: u64,
    live: Option<FingerprintCapture>,
    refusal: Option<ObservationOperationError>,
    api: Option<crate::runtime::FingerprintApi>,
}

impl FingerprintState {
    pub(super) fn configured() -> Result<Self, RamError> {
        let api = crate::runtime::FingerprintApi::resolve().map_err(|status| RamError::Native {
            operation: "resolve fingerprint source return SDK",
            status,
        })?;
        Ok(Self {
            api: Some(api),
            ..Self::default()
        })
    }
}

struct FingerprintCapture {
    identity: u64,
    operation: LiveOperation,
    baseline: FingerprintBaseline,
    paging: Option<OrdinaryPagingCustody>,
    loan: Option<usize>,
    native_capture: Option<(u64, u64, u32)>,
    native_capture_closed: bool,
    returned: bool,
    rearm_attempted: bool,
    post_attempted: bool,
    page_units: AtomicU64,
    observation_only: bool,
    expected_mode: Option<bool>,
    first_failure: Option<RamError>,
    original_failure: Option<ObservationOperationError>,
}

/// Keeps the actual controller owner until the outer caller's physical return.
pub(crate) struct FingerprintCall {
    controller: Arc<LivePagerController>,
    identity: u64,
}

fn enter_with_controller(
    controller: Arc<LivePagerController>,
    baseline: FingerprintBaseline,
) -> Result<FingerprintCall, RamError> {
    let mut holder = controller
        .fingerprint
        .try_lock()
        .map_err(|_| RamError::Invariant("ordinary fingerprint holder busy"))?;
    if holder.live.is_some() {
        return Err(RamError::Invariant(
            "ordinary fingerprint owner still retained",
        ));
    }
    holder.issued = holder
        .issued
        .checked_add(1)
        .ok_or("ordinary fingerprint identity exhausted")?;
    let operation = controller
        .begin_inline::<true>(SourceOperationClass::FingerprintUpdate)
        .map_err(|_| RamError::Invariant("ordinary fingerprint admission refused"))?;
    let identity = holder.issued;
    holder.live = Some(FingerprintCapture {
        identity,
        operation,
        baseline,
        paging: None,
        loan: None,
        native_capture: None,
        native_capture_closed: false,
        returned: false,
        rearm_attempted: false,
        post_attempted: false,
        page_units: AtomicU64::new(0),
        observation_only: false,
        expected_mode: None,
        first_failure: None,
        original_failure: None,
    });
    drop(holder);
    Ok(FingerprintCall {
        controller,
        identity,
    })
}

impl FingerprintCall {
    /// Checks that active capture mode preserved the authentic pre-entry context.
    ///
    /// # Errors
    /// Refuses a different operation or native invocation mode.
    pub(crate) fn check_observed_mode(&self, observation_only: bool) -> Result<(), RamError> {
        let holder = self
            .controller
            .fingerprint
            .try_lock()
            .map_err(|_| "fingerprint mode post busy")?;
        let capture = holder
            .live
            .as_ref()
            .filter(|capture| capture.identity == self.identity)
            .ok_or("fingerprint mode post operation changed")?;
        if capture.observation_only != observation_only {
            return Err(RamError::Invariant(
                "fingerprint native invocation mode changed",
            ));
        }
        Ok(())
    }

    /// Lends a rejection-only close receipt to this actual native capture caller.
    pub(crate) fn close_notice(&self) -> FingerprintCloseNotice {
        FingerprintCloseNotice {
            controller: self.controller.clone(),
            identity: self.identity,
        }
    }

    /// Reports authenticated hash/tree batches under the same shrinking Original.
    ///
    /// # Errors
    /// Refuses stale, exhausted or terminal operation authority.
    pub(crate) fn completed_units(&self, completed: u64) -> Result<(), RamError> {
        let mut holder = self
            .controller
            .fingerprint
            .try_lock()
            .map_err(|_| "fingerprint progress holder busy")?;
        let capture = holder
            .live
            .as_mut()
            .filter(|capture| capture.identity == self.identity)
            .ok_or("fingerprint progress operation changed")?;
        let prior = capture
            .page_units
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |units| {
                units.checked_add(completed).filter(|_| completed != 0)
            })
            .map_err(|_| RamError::Invariant("fingerprint completed units exhausted"))?;
        if let Err(error) = capture
            .operation
            .progress_for_observation(prior + completed)
        {
            retain_original_failure(capture, error);
            return Err(RamError::Invariant(
                "fingerprint progress Original failure retained",
            ));
        }
        Ok(())
    }

    /// Retains the actual successful native begin before the first mode query.
    ///
    /// # Errors
    /// Refuses a different caller or an already retained native capture.
    pub(crate) fn bind_capture(
        &mut self,
        generation: u64,
        topology: u64,
        regions: u32,
    ) -> Result<(), RamError> {
        let mut holder = self
            .controller
            .fingerprint
            .try_lock()
            .map_err(|_| "fingerprint capture holder busy")?;
        let capture = holder
            .live
            .as_mut()
            .filter(|capture| capture.identity == self.identity)
            .ok_or("fingerprint capture operation changed")?;
        if generation == 0 || topology == 0 || regions == 0 || capture.native_capture.is_some() {
            return Err(RamError::Invariant(
                "ordinary native capture binding changed",
            ));
        }
        capture.native_capture = Some((generation, topology, regions));
        capture.native_capture_closed = false;
        Ok(())
    }

    /// Records the native factual mode without constructing operation authority.
    ///
    /// # Errors
    /// Refuses a changed actual holder or a borrowed ACK loan in noACK mode.
    pub(crate) fn set_observation_mode(&mut self, observation_only: bool) -> Result<(), RamError> {
        let mut holder = self
            .controller
            .fingerprint
            .try_lock()
            .map_err(|_| "fingerprint mode holder busy")?;
        let capture = holder
            .live
            .as_mut()
            .filter(|capture| capture.identity == self.identity)
            .ok_or("fingerprint mode operation changed")?;
        if observation_only && capture.loan.is_some() {
            return Err(RamError::Invariant(
                "noACK observation borrowed retirement authority",
            ));
        }
        if capture
            .expected_mode
            .is_some_and(|expected| expected != observation_only)
        {
            return Err(RamError::Invariant(
                "fingerprint actual invocation mode changed before capture",
            ));
        }
        capture.observation_only = observation_only;
        Ok(())
    }

    /// Posts the actual CPU logical observation before native validation closes it.
    ///
    /// # Errors
    /// Preserves its Original refusal. Main captures post through their registered
    /// callback before ACK, so this method performs no second completion there.
    pub(crate) fn post_observation_only(&mut self) -> Result<(), RamError> {
        let mut holder = self
            .controller
            .fingerprint
            .try_lock()
            .map_err(|_| "fingerprint post holder busy")?;
        let capture = holder
            .live
            .as_mut()
            .filter(|capture| capture.identity == self.identity)
            .ok_or("fingerprint post operation changed")?;
        if !capture.observation_only {
            return Ok(());
        }
        if capture.post_attempted {
            return Err(RamError::Invariant(
                "fingerprint observation already posted",
            ));
        }
        capture.post_attempted = true;
        if let Err(error) = capture.operation.complete_observation() {
            retain_original_failure(capture, error);
            return Err(RamError::Invariant(
                "fingerprint Original post failure retained",
            ));
        }
        Ok(())
    }

    /// Checks the retained Original before any native capture effect.
    ///
    /// # Errors
    /// Refuses changed, expired or canceled original operation authority.
    pub(crate) fn check_before_begin(&self) -> Result<(), RamError> {
        let mut holder = self
            .controller
            .fingerprint
            .try_lock()
            .map_err(|_| "fingerprint holder busy")?;
        let capture = holder
            .live
            .as_mut()
            .filter(|capture| capture.identity == self.identity)
            .ok_or("fingerprint actual operation changed")?;
        if let Err(error) = capture.operation.wait_slice_for_observation() {
            retain_original_failure(capture, error);
            return Err(RamError::Invariant(
                "fingerprint original pre refusal retained",
            ));
        }
        Ok(())
    }

    /// Accepts only the independently posted operation and actual native return.
    ///
    /// # Errors
    /// Preserves missing completion, physical uncertainty or the first failure.
    pub(crate) fn finish(&mut self) -> Result<(), RamError> {
        let holder = self
            .controller
            .fingerprint
            .try_lock()
            .map_err(|_| "fingerprint finish holder busy")?;
        let capture = holder
            .live
            .as_ref()
            .filter(|capture| capture.identity == self.identity)
            .ok_or("fingerprint finish actual operation changed")?;
        if !(capture.returned || (capture.observation_only && capture.native_capture_closed))
            || !capture.post_attempted
            || capture.operation.terminal.load(Ordering::Acquire) != 1
        {
            return Err(RamError::Invariant(
                "fingerprint lacks actual post and native return",
            ));
        }
        if capture.first_failure.is_some() {
            return Err(RamError::Invariant(
                "fingerprint first failure remains retained",
            ));
        }
        Ok(())
    }

    /// Reports local borrower disposition without claiming native readiness.
    pub(crate) fn physically_returned(&self) -> bool {
        self.controller
            .fingerprint
            .try_lock()
            .ok()
            .is_some_and(|holder| {
                holder.live.as_ref().is_some_and(|capture| {
                    capture.identity == self.identity
                        && (capture.returned
                            || (capture.loan.is_none()
                                && (capture.native_capture.is_none()
                                    || capture.native_capture_closed)))
                })
            })
    }
}

impl Drop for FingerprintCall {
    fn drop(&mut self) {
        if let Ok(mut holder) = self.controller.fingerprint.try_lock() {
            if holder.live.as_ref().is_some_and(|capture| {
                capture.identity == self.identity
                    && (capture.returned
                        || (capture.loan.is_none()
                            && (capture.native_capture.is_none() || capture.native_capture_closed)))
            }) {
                if let Some(mut retired) = holder.live.take() {
                    if holder.refusal.is_none() {
                        holder.refusal = retired.original_failure.take();
                    }
                }
            }
        }
        // A real nonnull native borrower keeps the operation and any partially
        // returned paging gate in the stable paid holder. Drop is no end proof.
    }
}

fn callback_controller(id: u64, userdata: *mut c_void) -> Result<Arc<LivePagerController>, i32> {
    let controller = controller()
        .map_err(|_| -libc::EBUSY)?
        .ok_or(-libc::ENODEV)?;
    let actor = controller.actor.try_lock().map_err(|_| -libc::EBUSY)?;
    if !actor.matches_runtime(id, userdata) {
        return Err(-libc::ESTALE);
    }
    drop(actor);
    Ok(controller)
}

/// Lends the already-entered operation before fallible keeper admission.
pub(crate) fn borrow_fingerprint(
    context: &FingerprintBorrowContext,
    id: u64,
    userdata: *mut c_void,
    output: *mut *mut c_void,
) -> i32 {
    let controller = match callback_controller(id, userdata) {
        Ok(controller) => controller,
        Err(status) => return status,
    };
    let baseline = {
        let Ok(mut holder) = controller.fingerprint.try_lock() else {
            return -libc::EBUSY;
        };
        let Some(capture) = holder.live.as_mut() else {
            return -libc::ENOKEY;
        };
        if capture.loan.is_some() || capture.returned {
            return -libc::EBUSY;
        }
        capture.loan = Some(context.key());
        // SAFETY: only the genuine registered native invocation lends this
        // output. Publish the already-born stable operation owner before any
        // fallible range, page-service or supervision cut can refuse admission.
        unsafe {
            output.write(Arc::as_ptr(&controller).cast_mut().cast());
        }
        capture.baseline.clone()
    };
    // All native identity/range observations occur with holder/State/Slot guards
    // released. These copied baseline keys discriminate, but never mint a loan.
    if let Err(error) = context.validate_baseline(&baseline) {
        return retain_borrow_refusal(&controller, context, error);
    }
    let owner = match current_owner() {
        Ok(Some(owner)) => owner,
        Ok(None) => {
            return retain_borrow_refusal(
                &controller,
                context,
                RamError::Invariant("fingerprint paging owner absent"),
            );
        }
        Err(error) => return retain_borrow_refusal(&controller, context, error),
    };
    if Arc::as_ptr(&owner.operations).cast::<()>() != Arc::as_ptr(&controller).cast::<()>() {
        return retain_borrow_refusal(
            &controller,
            context,
            RamError::Invariant("fingerprint actual controller allocation changed"),
        );
    }
    let Ok(mut holder) = controller.fingerprint.try_lock() else {
        return -libc::EBUSY;
    };
    let Some(capture) = holder
        .live
        .as_mut()
        .filter(|capture| capture.loan == Some(context.key()) && !capture.returned)
    else {
        return -libc::ESTALE;
    };
    if capture.paging.is_none() {
        match OrdinaryPagingCustody::retain(owner, capture.identity, context) {
            Ok(paging) => capture.paging = Some(paging),
            Err(error) => {
                capture.first_failure = Some(error);
                return -libc::EIO;
            }
        }
    }
    let result = capture
        .paging
        .as_mut()
        .ok_or(RamError::Invariant("fingerprint custody absent"))
        .and_then(|paging| paging.settle(&capture.operation));
    match result {
        Ok(()) => 0,
        Err(error) => {
            capture.first_failure = Some(error);
            -libc::EIO
        }
    }
}

fn retain_borrow_refusal(
    controller: &LivePagerController,
    context: &FingerprintBorrowContext,
    error: RamError,
) -> i32 {
    let status = match &error {
        RamError::Native { status, .. } if *status < 0 => *status,
        _ => -libc::EIO,
    };
    if let Ok(mut holder) = controller.fingerprint.try_lock() {
        if let Some(capture) = holder
            .live
            .as_mut()
            .filter(|capture| capture.loan == Some(context.key()))
        {
            if capture.first_failure.is_none() {
                capture.first_failure = Some(error);
            }
        }
    }
    status
}

fn matches_capture(capture: &FingerprintCapture, context: &FingerprintBorrowContext) -> bool {
    capture.loan == Some(context.key())
        && !capture.returned
        && match capture.native_capture {
            Some((generation, topology, regions)) => {
                context.status.operation_capture_generation == generation
                    && context.status.topology_generation == topology
                    && context.status.region_count == regions
            }
            None => context.status.operation_capture_generation == 0,
        }
}

/// Rearms only the same genuine borrower and actual acknowledged page gate.
pub(crate) fn rearm_fingerprint(
    context: &FingerprintBorrowContext,
    id: u64,
    userdata: *mut c_void,
    owner: *mut c_void,
) -> i32 {
    let controller = match callback_controller(id, userdata) {
        Ok(controller) => controller,
        Err(status) => return status,
    };
    if owner != Arc::as_ptr(&controller).cast_mut().cast() {
        return -libc::ESTALE;
    }
    let Ok(mut holder) = controller.fingerprint.try_lock() else {
        return -libc::EBUSY;
    };
    let Some(capture) = holder
        .live
        .as_mut()
        .filter(|capture| matches_capture(capture, context))
    else {
        return -libc::ESTALE;
    };
    if capture.rearm_attempted {
        return -libc::EALREADY;
    }
    capture.rearm_attempted = true;
    let result = capture
        .paging
        .as_ref()
        .ok_or(RamError::Invariant("fingerprint page custody absent"))
        .and_then(|paging| paging.rearm(context.status.topology_generation, &capture.operation));
    match result {
        Ok(()) => 0,
        Err(error) => {
            if capture.first_failure.is_none() {
                capture.first_failure = Some(error);
            }
            -libc::EIO
        }
    }
}

/// Independently posts the same entered Original before fingerprint ACK.
pub(crate) fn check_fingerprint(
    context: &FingerprintBorrowContext,
    id: u64,
    userdata: *mut c_void,
    owner: *mut c_void,
) -> i32 {
    let controller = match callback_controller(id, userdata) {
        Ok(controller) => controller,
        Err(status) => return status,
    };
    if owner != Arc::as_ptr(&controller).cast_mut().cast() {
        return -libc::ESTALE;
    }
    let Ok(mut holder) = controller.fingerprint.try_lock() else {
        return -libc::EBUSY;
    };
    let Some(capture) = holder
        .live
        .as_mut()
        .filter(|capture| matches_capture(capture, context))
    else {
        return -libc::ESTALE;
    };
    if capture.post_attempted {
        return -libc::EALREADY;
    }
    post_actual_operation(capture, context.status.operation_capture_generation != 0)
}

fn post_actual_operation(capture: &mut FingerprintCapture, actual_capture: bool) -> i32 {
    let result = if actual_capture {
        capture.post_attempted = true;
        capture.operation.complete_observation()
    } else {
        capture.operation.wait_slice_for_observation().map(|_| ())
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            retain_original_failure(capture, error);
            if capture.first_failure.is_none() {
                capture.first_failure = Some(RamError::Invariant(
                    "fingerprint Original post refusal retained",
                ));
            }
            -libc::EIO
        }
    }
}

/// Returns physical borrower custody without a new semantic observation.
pub(crate) fn end_fingerprint(
    context: &FingerprintBorrowContext,
    id: u64,
    userdata: *mut c_void,
    owner: *mut *mut c_void,
) -> i32 {
    let controller = match callback_controller(id, userdata) {
        Ok(controller) => controller,
        Err(status) => return status,
    };
    // SAFETY: native lends the exact retained owner holder for physical return.
    let supplied = unsafe { owner.read() };
    if supplied != Arc::as_ptr(&controller).cast_mut().cast() {
        return -libc::ESTALE;
    }
    let Ok(mut holder) = controller.fingerprint.try_lock() else {
        return -libc::EBUSY;
    };
    let Some(capture) = holder
        .live
        .as_mut()
        .filter(|capture| capture.loan == Some(context.key()) && !capture.returned)
    else {
        return -libc::ESTALE;
    };
    if let Some(paging) = capture.paging.as_mut() {
        if paging.return_identity().is_err() {
            return -libc::EBUSY;
        }
    }
    capture.returned = true;
    // SAFETY: physical exclusion actually returned; immediately consume the SAME
    // native holder before any subsequent semantic result can refuse observation.
    unsafe {
        owner.write(std::ptr::null_mut());
    }
    0
}

/// Lends one page exchange the same outer clock and cumulative progress counter.
struct FingerprintPageExchange<'a> {
    operation: &'a LiveOperation,
    units: &'a AtomicU64,
    completed: AtomicBool,
}

impl SourceOperation for FingerprintPageExchange<'_> {
    fn wait_slice(&self) -> io::Result<Duration> {
        self.wait_slice_for_observation()
            .map_err(ObservationOperationError::into_io)
    }

    fn wait_slice_for_observation(&self) -> Result<Duration, ObservationOperationError> {
        if self.completed.load(Ordering::Acquire) {
            return Err(ObservationOperationError::Static {
                kind: io::ErrorKind::Other,
                message: "fingerprint page exchange already completed",
            });
        }
        self.operation.wait_slice_for_observation()
    }

    fn complete(&self) -> io::Result<()> {
        self.complete_observation()
            .map_err(ObservationOperationError::into_io)
    }

    fn complete_observation(&self) -> Result<(), ObservationOperationError> {
        self.wait_slice_for_observation()?;
        if self.completed.swap(true, Ordering::AcqRel) {
            return Err(ObservationOperationError::Static {
                kind: io::ErrorKind::Other,
                message: "fingerprint page exchange completed twice",
            });
        }
        let prior = self
            .units
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |units| {
                units.checked_add(1)
            })
            .map_err(|_| ObservationOperationError::Static {
                kind: io::ErrorKind::Other,
                message: "fingerprint completed units exhausted",
            })?;
        self.operation.progress_for_observation(prior + 1)
    }
}

pub(super) fn with_outer_exchange(
    controller: &LivePagerController,
    exchange: &mut dyn FnMut(&dyn SourceOperation),
) -> Result<bool, ObservationOperationError> {
    let holder =
        controller
            .fingerprint
            .try_lock()
            .map_err(|_| ObservationOperationError::Static {
                kind: io::ErrorKind::WouldBlock,
                message: "fingerprint operation holder busy",
            })?;
    let Some(capture) = holder.live.as_ref() else {
        return Ok(false);
    };
    capture.operation.wait_slice_for_observation()?;
    let page = FingerprintPageExchange {
        operation: &capture.operation,
        units: &capture.page_units,
        completed: AtomicBool::new(false),
    };
    // Source/spill transport receives only this synchronous borrow. The holder
    // cannot be returned by a native end callback until the exchange has ended.
    exchange(&page);
    Ok(true)
}

fn retain_original_failure(capture: &mut FingerprintCapture, error: ObservationOperationError) {
    if let Ok(state) = capture.operation.state.lock() {
        if let Some(owner) = state.owner.as_ref() {
            owner.retain_observation_failure(error);
            return;
        }
    }
    if capture.original_failure.is_none() {
        capture.original_failure = Some(error);
    }
}

/// Retains the actual controller operation across a synchronous native close.
///
/// The notice cannot read RAM or acquire a loan. Only the typed capture caller
/// records successful physical close after its genuine native call returns.
pub(crate) struct FingerprintCloseNotice {
    controller: Arc<LivePagerController>,
    identity: u64,
}

impl FingerprintCloseNotice {
    /// Records the typed caller's successful close without lending read authority.
    ///
    /// # Errors
    /// Refuses a different retained operation or native capture generation.
    pub(crate) fn record_closed(&self, generation: u64) -> Result<(), RamError> {
        let mut holder = self
            .controller
            .fingerprint
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let capture = holder
            .live
            .as_mut()
            .filter(|capture| {
                capture.identity == self.identity
                    && capture
                        .native_capture
                        .is_some_and(|(actual, _, _)| actual == generation)
            })
            .ok_or("fingerprint close actual capture changed")?;
        capture.native_capture_closed = true;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn fixture_fingerprint(
    baseline: FingerprintBaseline,
) -> Result<FingerprintCall, RamError> {
    enter_with_controller(Arc::new(super::tests::controller()), baseline)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline() -> FingerprintBaseline {
        crate::ram_fingerprint::ordinary_fixture_baseline()
    }

    #[test]
    fn completed_page_exchanges_preserve_the_live_outer_operation() {
        let controller = Arc::new(super::super::tests::controller());
        let call = enter_with_controller(controller.clone(), baseline()).unwrap();

        for _ in 0..2 {
            assert!(
                with_outer_exchange(&controller, &mut |page| {
                    page.wait_slice_for_observation().unwrap();
                    page.complete_observation().unwrap();
                    assert!(page.complete_observation().is_err());
                })
                .unwrap()
            );
        }

        let holder = controller.fingerprint.lock().unwrap();
        let capture = holder.live.as_ref().unwrap();
        assert_eq!(capture.operation.terminal.load(Ordering::Acquire), 0);
        assert_eq!(capture.page_units.load(Ordering::Acquire), 2);
        assert_eq!(
            capture.operation.progress.lock().unwrap().completed_units,
            2
        );
        capture.operation.wait_slice_for_observation().unwrap();
        drop(holder);
        drop(call);
    }

    #[test]
    fn cancellation_after_birth_retains_the_same_inline_original_until_return() {
        let controller = Arc::new(super::super::tests::controller());
        let call = enter_with_controller(controller.clone(), baseline()).unwrap();
        controller.canceled.store(true, Ordering::Release);

        assert!(call.check_before_begin().is_err());
        let holder = controller.fingerprint.lock().unwrap();
        let capture = holder.live.as_ref().unwrap();
        assert_eq!(capture.identity, call.identity);
        assert!(capture.loan.is_none());
        assert!(matches!(
            capture.operation.wait_slice_for_observation(),
            Err(ObservationOperationError::Static {
                kind: io::ErrorKind::Interrupted,
                ..
            })
        ));
        drop(holder);

        drop(call);
        assert!(controller.fingerprint.lock().unwrap().live.is_none());
    }

    #[test]
    fn native_post_cut_retains_the_actual_typed_original_refusal() {
        let controller = Arc::new(super::super::tests::controller());
        let call = enter_with_controller(controller.clone(), baseline()).unwrap();
        controller.canceled.store(true, Ordering::Release);
        let mut holder = controller.fingerprint.lock().unwrap();
        let capture = holder.live.as_mut().unwrap();

        assert_eq!(post_actual_operation(capture, true), -libc::EIO);
        assert!(capture.post_attempted);
        assert!(matches!(
            capture.original_failure.as_ref(),
            Some(ObservationOperationError::Static {
                kind: io::ErrorKind::Interrupted,
                ..
            })
        ));
        assert!(capture.first_failure.is_some());
        drop(holder);

        drop(call);
        assert!(matches!(
            controller.fingerprint.lock().unwrap().refusal.as_ref(),
            Some(ObservationOperationError::Static {
                kind: io::ErrorKind::Interrupted,
                ..
            })
        ));
    }

    #[test]
    fn a_terminal_outer_operation_cannot_lend_a_new_page_exchange() {
        let controller = Arc::new(super::super::tests::controller());
        let call = enter_with_controller(controller.clone(), baseline()).unwrap();
        controller
            .fingerprint
            .lock()
            .unwrap()
            .live
            .as_ref()
            .unwrap()
            .operation
            .complete_observation()
            .unwrap();

        let mut invoked = false;
        assert!(with_outer_exchange(&controller, &mut |_| invoked = true).is_err());
        assert!(!invoked);
        assert_eq!(
            controller
                .fingerprint
                .lock()
                .unwrap()
                .live
                .as_ref()
                .unwrap()
                .page_units
                .load(Ordering::Acquire),
            0
        );
        drop(call);
    }
}

/// Authenticated pre-admission facts; they cannot construct an operation or loan.
pub(crate) struct FingerprintEntry {
    controller: Arc<LivePagerController>,
    pub(crate) observation_only: bool,
    returned_identity: Option<u64>,
    return_failure: Option<RamError>,
}

/// Resolves actual old Source custody before any new operation/cache work.
///
/// # Errors
/// Preserves native context/return refusal and any mismatching retained owner.
pub(crate) fn prepare_fingerprint_entry() -> Result<FingerprintEntry, RamError> {
    let controller = controller()?.ok_or("fingerprint source controller absent")?;
    let id = controller
        .actor
        .try_lock()
        .map_err(|_| "fingerprint source binding busy")?
        .source_plugin_id();
    let api = controller
        .fingerprint
        .try_lock()
        .map_err(|_| "fingerprint source SDK busy")?
        .api
        .ok_or("fingerprint source SDK absent")?;
    let observation_only = api.observation_context(id)?;
    if observation_only {
        return Ok(FingerprintEntry {
            controller,
            observation_only,
            returned_identity: None,
            return_failure: None,
        });
    }
    let Some(mut old) = api.old_borrow(id)? else {
        if controller
            .fingerprint
            .try_lock()
            .map_err(|_| "fingerprint old holder busy")?
            .live
            .is_some()
        {
            return Err(RamError::Invariant(
                "native absence disagrees with retained fingerprint holder",
            ));
        }
        return Ok(FingerprintEntry {
            controller,
            observation_only,
            returned_identity: None,
            return_failure: None,
        });
    };
    let identity = {
        let holder = controller
            .fingerprint
            .try_lock()
            .map_err(|_| "fingerprint old owner busy")?;
        let capture = holder
            .live
            .as_ref()
            .filter(|capture| {
                capture.loan == Some(old.key())
                    && !capture.returned
                    && capture.native_capture.map_or(
                        old.status.operation_capture_generation == 0,
                        |(generation, _, _)| generation == old.status.operation_capture_generation,
                    )
            })
            .ok_or("fingerprint old Source borrower disagrees")?;
        capture.identity
    };
    // Native end may call the real module closer; no Rust guard spans this call.
    let result = old.return_old();
    let mut holder = controller
        .fingerprint
        .try_lock()
        .map_err(|_| "fingerprint old physical journal busy")?;
    let capture = holder
        .live
        .as_ref()
        .filter(|capture| capture.identity == identity)
        .ok_or("fingerprint physical return actual owner changed")?;
    if !old.consumed() || !capture.returned {
        return Err(result.err().unwrap_or(RamError::Invariant(
            "fingerprint physical return remains uncertain",
        )));
    }
    if let Some(mut retired) = holder.live.take() {
        if holder.refusal.is_none() {
            holder.refusal = retired.original_failure.take();
        }
    }
    drop(holder);
    // Consumption returns only this borrower, never checkpoint Root/observer
    // custody. Fresh admission performs its own real registry/State checks.
    Ok(FingerprintEntry {
        controller,
        observation_only,
        returned_identity: Some(identity),
        return_failure: result.err(),
    })
}

impl FingerprintEntry {
    pub(crate) fn returned_old_cache(&self) -> bool {
        self.returned_identity.is_some()
    }

    pub(crate) fn take_return_failure(&mut self) -> Option<RamError> {
        self.return_failure.take()
    }

    /// Enters a fresh operation only after the actual old holder has returned.
    ///
    /// # Errors
    /// Refuses current policy/Root/registry admission or a new retained holder.
    pub(crate) fn enter(self, baseline: FingerprintBaseline) -> Result<FingerprintCall, RamError> {
        let call = enter_with_controller(self.controller, baseline)?;
        {
            let mut holder = call
                .controller
                .fingerprint
                .try_lock()
                .map_err(|_| "fingerprint entry mode holder busy")?;
            let capture = holder
                .live
                .as_mut()
                .filter(|capture| capture.identity == call.identity)
                .ok_or("fingerprint entry actual operation changed")?;
            capture.expected_mode = Some(self.observation_only);
        }
        Ok(call)
    }
}
