//! Retains genuine Main resident or paging custody outside its borrowed observer.
//!
//! Native phase one issues the Source view; phase two checks that same live
//! Original. Page exclusion and the durable view return only at physical end.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;
use crate::runtime::FingerprintBorrowContext;

mod placement;
use placement::PhysicalCustody;

pub(super) struct Custody {
    pub(super) loan: usize,
    physical: PhysicalCustody,
    rearm_attempted: bool,
    checked: bool,
    failure: Option<RamError>,
}

/// Restores actual funded custody on error or unwinding, without native calls.
struct Work<'a> {
    owner: &'a Owner,
    custody: Option<Custody>,
}

impl Drop for Work<'_> {
    fn drop(&mut self) {
        let mut state = self
            .owner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.retirement = self.custody.take();
        state.retirement_busy = false;
    }
}

impl Owner {
    fn retirement_work(&self, context: &FingerprintBorrowContext) -> Result<Work<'_>, c_int> {
        let mut state = self.state.try_lock().map_err(|_| -libc::EBUSY)?;
        if state.capture.as_ref().is_some_and(|capture| {
            capture.capture_generation != context.status.operation_capture_generation
                || capture.topology_generation != context.status.topology_generation
                || capture.region_count != context.status.region_count
        }) {
            return Err(-libc::ESTALE);
        }
        if state.retirement_busy
            || state.reads.is_retained()
            || !state
                .retirement
                .as_ref()
                .is_some_and(|custody| custody.loan == context.key())
        {
            return Err(-libc::ESTALE);
        }
        let custody = state.retirement.take();
        state.retirement_busy = true;
        Ok(Work {
            owner: self,
            custody,
        })
    }

    fn retirement_sample(&self, loan: usize) -> Result<Evidence, ObservationOperationError> {
        let selector = self.selector()?;
        let mut observed = Evidence::default();
        let result = (self.apis.retirement_observe)(
            self.plugin_id,
            loan as *mut crate::runtime::FingerprintLoan,
            selector as *mut Operation,
            &mut observed,
        );
        if result != 0 {
            return Err(ObservationOperationError::Io(
                std::io::Error::from_raw_os_error(if result < 0 {
                    result.saturating_neg()
                } else {
                    libc::EPROTO
                }),
            ));
        }
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| refusal("retirement Original observation busy"))?;
        if state.selector.load(Ordering::Acquire) as usize != selector
            || !valid_evidence(&observed, state.evidence.as_ref())
        {
            return Err(refusal("retirement Original changed"));
        }
        state.evidence = Some(observed);
        Ok(observed)
    }
}

/// Queries the genuine registered phase, never completing or issuing its clock.
struct LiveOriginal<'a> {
    owner: &'a Owner,
    loan: usize,
}

impl SourceOperation for LiveOriginal<'_> {
    fn wait_slice(&self) -> std::io::Result<Duration> {
        self.wait_slice_for_observation()
            .map_err(ObservationOperationError::into_io)
    }

    fn wait_slice_for_observation(&self) -> Result<Duration, ObservationOperationError> {
        self.owner
            .retirement_sample(self.loan)
            .map(|observed| Duration::from_nanos(observed.bounded_ns))
    }

    fn complete(&self) -> std::io::Result<()> {
        self.complete_observation()
            .map_err(ObservationOperationError::into_io)
    }

    fn complete_observation(&self) -> Result<(), ObservationOperationError> {
        Err(refusal(
            "native Source alone posts the whole fingerprint Original",
        ))
    }
}

fn signed(error: RamError) -> c_int {
    match error {
        RamError::Native { status, .. } if status < 0 => status,
        _ => -libc::EIO,
    }
}

/// Retains the issued Source view and actual realization before observer entry.
pub(crate) fn borrow(
    context: &FingerprintBorrowContext,
    id: u64,
    userdata: *mut c_void,
    output: *mut *mut c_void,
) -> c_int {
    let owner = match registered_owner(id, userdata) {
        Ok(owner) => owner,
        Err(status) => return status,
    };
    if let Err(error) = owner.synchronize() {
        return signed(error);
    }
    let physical = match PhysicalCustody::retain(owner.placement, context, id, userdata) {
        Ok(physical) => physical,
        Err(error) => return signed(error),
    };
    let mut state = match owner.state.try_lock() {
        Ok(state) => state,
        Err(_) => return -libc::EBUSY,
    };
    if state.retirement.is_some()
        || state.retirement_busy
        || state.reads.is_retained()
        || !state.selector.load(Ordering::Acquire).is_null()
    {
        return -libc::EBUSY;
    }
    state.retirement = Some(Custody {
        loan: context.key(),
        physical,
        rearm_attempted: false,
        checked: false,
        failure: None,
    });
    // SAFETY: the native registered invocation lends this output. Publish the
    // real prepaid runtime owner before Source view admission can fail.
    unsafe {
        output.write(std::ptr::from_ref(owner).cast_mut().cast());
    }
    state.evidence = None;
    state.capture = None;
    state.return_status = None;
    let result = (owner.apis.retirement_borrow)(
        id,
        context.key() as *mut crate::runtime::FingerprintLoan,
        state.selector.get_mut(),
    );
    owner.active.store(
        !state.selector.load(Ordering::Acquire).is_null(),
        Ordering::Release,
    );

    drop(state);
    if result != 0 {
        return if result < 0 { result } else { -libc::EPROTO };
    }
    let mut work = match owner.retirement_work(context) {
        Ok(work) => work,
        Err(status) => return status,
    };
    let operation = LiveOriginal {
        owner,
        loan: context.key(),
    };
    let custody = match work.custody.as_mut() {
        Some(custody) => custody,
        None => return -libc::ESTALE,
    };
    let evidence = match owner.retirement_sample(context.key()) {
        Ok(evidence) => evidence,
        Err(error) => {
            // No producing class has been projected yet. Preserve the actual
            // cause in the paid custody; neither an update nor a new clock is
            // invented merely to label this failed query.
            custody.failure = Some(RamError::from(error.into_io()));
            return -libc::EIO;
        }
    };
    let class = match evidence.class {
        4 => crate::paged_ram::source::SourceOperationClass::FingerprintInitialization,
        5 => crate::paged_ram::source::SourceOperationClass::FingerprintUpdate,
        _ => return -libc::EPROTO,
    };
    if let Err(error) = custody.physical.bind_original(evidence.serial, class) {
        custody.failure = Some(error);
        return -libc::EPROTO;
    }
    match custody.physical.settle(&operation) {
        Ok(()) => 0,
        Err(error) => {
            let status = match &error {
                RamError::Native { status, .. } if *status < 0 => *status,
                _ => -libc::EIO,
            };
            custody.failure = Some(error);
            status
        }
    }
}

/// Rearms actual page work or checks the genuine resident Source Original.
pub(crate) fn rearm(
    context: &FingerprintBorrowContext,
    id: u64,
    userdata: *mut c_void,
    supplied: *mut c_void,
) -> c_int {
    let owner = match registered_owner(id, userdata) {
        Ok(owner) => owner,
        Err(status) => return status,
    };
    if supplied != std::ptr::from_ref(owner).cast_mut().cast() {
        return -libc::ESTALE;
    }
    let mut work = match owner.retirement_work(context) {
        Ok(work) => work,
        Err(status) => return status,
    };
    let operation = LiveOriginal {
        owner,
        loan: context.key(),
    };
    let custody = match work.custody.as_mut() {
        Some(custody) => custody,
        None => return -libc::ESTALE,
    };
    if custody.rearm_attempted {
        return -libc::EALREADY;
    }
    custody.rearm_attempted = true;
    match custody
        .physical
        .rearm(context.status.topology_generation, &operation)
    {
        Ok(()) => 0,
        Err(error) => {
            let status = match &error {
                RamError::Native { status, .. } if *status < 0 => *status,
                _ => -libc::EIO,
            };
            custody.failure.get_or_insert(error);
            status
        }
    }
}

/// Checks live Source authority before its native independent post.
pub(crate) fn check(
    context: &FingerprintBorrowContext,
    id: u64,
    userdata: *mut c_void,
    supplied: *mut c_void,
) -> c_int {
    let owner = match registered_owner(id, userdata) {
        Ok(owner) => owner,
        Err(status) => return status,
    };
    if supplied != std::ptr::from_ref(owner).cast_mut().cast() {
        return -libc::ESTALE;
    }
    let mut work = match owner.retirement_work(context) {
        Ok(work) => work,
        Err(status) => return status,
    };
    let custody = match work.custody.as_mut() {
        Some(custody) => custody,
        None => return -libc::ESTALE,
    };
    if custody.checked {
        return -libc::EALREADY;
    }
    custody.checked = true;
    match owner.retirement_sample(context.key()) {
        Ok(_) => 0,
        Err(error) => {
            custody
                .failure
                .get_or_insert(RamError::from(error.into_io()));
            -libc::EIO
        }
    }
}

/// Returns actual physical custody and saved view without renewing its clock.
pub(crate) fn end(
    context: &FingerprintBorrowContext,
    id: u64,
    userdata: *mut c_void,
    supplied: *mut *mut c_void,
) -> c_int {
    let owner = match registered_owner(id, userdata) {
        Ok(owner) => owner,
        Err(status) => return status,
    };
    // SAFETY: native lends the same saved opaque owner field for physical end.
    if unsafe { supplied.read() } != std::ptr::from_ref(owner).cast_mut().cast() {
        return -libc::ESTALE;
    }
    let mut work = match owner.retirement_work(context) {
        Ok(work) => work,
        Err(status) => return status,
    };
    let custody = match work.custody.as_mut() {
        Some(custody) => custody,
        None => return -libc::ESTALE,
    };
    if custody.physical.return_identity().is_err() {
        return -libc::EBUSY;
    }
    let returned = if owner.is_active() {
        owner.return_view()
    } else {
        Ok(())
    };
    let state = match owner.state.try_lock() {
        Ok(state) => state,
        Err(_) => return -libc::EBUSY,
    };
    let consumed = state.selector.load(Ordering::Acquire).is_null();
    drop(state);
    if consumed {
        work.custody = None;
        // SAFETY: exact pager and Source fields physically returned. Consume
        // the native owner immediately, independently of signed end status.
        unsafe {
            supplied.write(std::ptr::null_mut());
        }
    }
    match returned {
        Ok(()) => 0,
        Err(error) => signed(error),
    }
}
