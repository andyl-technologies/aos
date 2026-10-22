//! Borrows the Source operation already entered by the native root caller.
//!
//! The stable observer lane retains the actual native selector before any
//! fallible projection. Nested backing exchanges query that same Original;
//! their completion neither advances native progress nor ends the operation.
//! Only the native successful-read witness can advance its progress allowance.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

mod read;
pub(crate) use read::with_read_exchange;

mod publication;
pub(crate) use publication::synchronize;
pub(super) use publication::synchronize_root;
mod retirement;
use crate::paged_ram::source::{ObservationOperationError, SourceOperation};
pub(crate) use retirement::{
    borrow as borrow_retirement, check as check_retirement, end as end_retirement,
    rearm as rearm_retirement,
};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::time::Duration;

#[repr(C)]
pub(super) struct Operation {
    _private: [u8; 0],
}

/// Keeps the opaque final-publication type in the matched native SDK.
#[repr(C)]
struct Publication {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Evidence {
    capability: [u8; 32],
    origin_ns: u64,
    serial: u64,
    start_ns: u64,
    progress_ns: u64,
    bounded_ns: u64,
    class: u32,
}

type Borrow = extern "C" fn(u64, *mut *mut Operation) -> c_int;
type Observe = extern "C" fn(*mut Operation, *mut Evidence) -> c_int;
type Return = extern "C" fn(*mut *mut Operation) -> c_int;
type Begin =
    extern "C" fn(u64, *mut Operation, u32, *mut CaptureHeader, *mut *mut Publication) -> c_int;
type Restart = extern "C" fn(u64, *mut Operation, u32, *mut CaptureHeader) -> c_int;
type ViewReturn = extern "C" fn(u64, *mut Operation, *mut c_void) -> c_int;
type Register = extern "C" fn(
    u64,
    Option<ViewReturn>,
    *mut c_void,
    *mut *mut Operation,
    *mut *mut Publication,
) -> c_int;
type RetirementBorrow =
    extern "C" fn(u64, *mut crate::runtime::FingerprintLoan, *mut *mut Operation) -> c_int;
type RetirementObserve = extern "C" fn(
    u64,
    *mut crate::runtime::FingerprintLoan,
    *mut Operation,
    *mut Evidence,
) -> c_int;

/// Keeps an unpublished immutable view under the same paid runtime lane.
struct StagedView {
    evidence: Evidence,
    capture: CaptureHeader,
    scope: Scope,
    view: Option<CachedView>,
}

/// Retains the literal Source and logical-capture entry points.
#[derive(Clone, Copy)]
pub(super) struct Apis {
    borrow: Borrow,
    observe: Observe,
    return_view: Return,
    begin: Begin,
    restart: Restart,
    register: Register,
    publication_observe: publication::Observe,
    publication_return: publication::Return,
    retirement_borrow: RetirementBorrow,
    retirement_observe: RetirementObserve,
}

impl Apis {
    pub(super) fn resolve() -> Result<Self, RamError> {
        // SAFETY: these exported symbols have the exact opaque pointer and
        // repr(C) layouts in the independently retained native Source SDK.
        unsafe {
            Ok(Self {
                borrow: std::mem::transmute::<*mut c_void, Borrow>(symbol(
                    b"qemu_plugin_crucible_fingerprint_operation_borrow_v1\0",
                )?),
                observe: std::mem::transmute::<*mut c_void, Observe>(symbol(
                    b"qemu_plugin_crucible_fingerprint_operation_observe_v1\0",
                )?),
                return_view: std::mem::transmute::<*mut c_void, Return>(symbol(
                    b"qemu_plugin_crucible_fingerprint_operation_borrow_end_v1\0",
                )?),
                begin: std::mem::transmute::<*mut c_void, Begin>(symbol(
                    b"qemu_plugin_crucible_ram_logical_capture_begin_v3\0",
                )?),
                restart: std::mem::transmute::<*mut c_void, Restart>(symbol(
                    b"qemu_plugin_crucible_ram_logical_capture_restart_v1\0",
                )?),
                register: std::mem::transmute::<*mut c_void, Register>(symbol(
                    b"qemu_plugin_crucible_register_fingerprint_owner_v1\0",
                )?),
                publication_observe: std::mem::transmute::<*mut c_void, publication::Observe>(
                    symbol(b"qemu_plugin_crucible_fingerprint_publication_observe_v1\0")?,
                ),
                publication_return: std::mem::transmute::<*mut c_void, publication::Return>(
                    symbol(b"qemu_plugin_crucible_fingerprint_publication_return_v1\0")?,
                ),
                retirement_borrow: std::mem::transmute::<*mut c_void, RetirementBorrow>(symbol(
                    b"qemu_plugin_crucible_fingerprint_retirement_operation_borrow_v1\0",
                )?),
                retirement_observe: std::mem::transmute::<*mut c_void, RetirementObserve>(symbol(
                    b"qemu_plugin_crucible_fingerprint_retirement_operation_observe_v1\0",
                )?),
            })
        }
    }
}

#[derive(Default)]
struct State {
    selector: AtomicPtr<Operation>,
    publication: AtomicPtr<Publication>,
    staged: Option<StagedView>,
    evidence: Option<Evidence>,
    capture: Option<CaptureHeader>,
    return_status: Option<c_int>,
    retirement: Option<retirement::Custody>,
    retirement_busy: bool,
    settled: Option<publication::Status>,
    returned_publication: Option<publication::Returned>,
    pending_facts: Option<publication::Identity>,
    reads: read::Custody,
}

/// Selects the registered realization without granting capture authority.
///
/// Native validates the selected Source/runtime registrar and its actual
/// writer/inventory loan before invoking any module borrower.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FingerprintPlacement {
    /// Retains the actual installed controller, service and page-state gate.
    Paging,
    /// Uses genuine native nonpaging inventory and writer custody.
    Resident,
}

/// Keeps one paid module view without owning or issuing the Source clock.
pub(crate) struct Owner {
    plugin_id: u64,
    runtime_userdata: usize,
    owner_process: u32,
    placement: FingerprintPlacement,
    fingerprint: crate::runtime::FingerprintApi,
    apis: Apis,
    state: Mutex<State>,
    active: AtomicBool,
}

impl Owner {
    /// Initializes the inline paid owner before its stable fields are enrolled.
    ///
    /// # Errors
    /// Refuses absent runtime identity or unavailable matching native exports.
    pub(crate) fn prepare(
        plugin_id: u64,
        runtime_userdata: *mut c_void,
        placement: FingerprintPlacement,
    ) -> Result<Self, RamError> {
        if runtime_userdata.is_null() {
            return Err(RamError::Invariant("Original runtime userdata absent"));
        }
        let apis = Apis::resolve()?;
        let fingerprint = crate::runtime::FingerprintApi::resolve(placement).map_err(|status| {
            RamError::Native {
                operation: "resolve fingerprint retirement",
                status,
            }
        })?;
        Ok(Self {
            plugin_id,
            runtime_userdata: runtime_userdata as usize,
            owner_process: std::process::id(),
            placement,
            fingerprint,
            apis,
            state: Mutex::new(State::default()),
            active: AtomicBool::new(false),
        })
    }

    /// Enrolls the genuine stable fields after Root observer registration.
    pub(super) fn enroll(&self) -> Result<(), RamError> {
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| "Original enrollment busy")?;
        let State {
            selector,
            publication,
            ..
        } = &mut *state;
        let result = (self.apis.register)(
            self.plugin_id,
            Some(return_old_view),
            self.runtime_userdata as *mut c_void,
            selector.get_mut(),
            publication.get_mut(),
        );
        status(result, "register prepaid fingerprint owner")?;
        drop(state);
        self.fingerprint
            .register(self.plugin_id, self.runtime_userdata as *mut c_void)
            .map_err(|status| RamError::Native {
                operation: "register fingerprint retirement",
                status,
            })
    }

    /// Borrows only the actual operation entered before this observer callback.
    pub(super) fn borrow(&self, scope: Scope) -> Result<Call<'_>, RamError> {
        let mut state = self.state.try_lock().map_err(|_| "Original owner busy")?;
        if state.staged.is_some()
            || state.capture.is_some()
            || !state.publication.load(Ordering::Acquire).is_null()
            || state.retirement_busy
            || state.reads.is_retained()
        {
            return Err(RamError::Invariant("Original publication still retained"));
        }
        if let Some(custody) = state.retirement.as_ref() {
            let loan = custody.loan;
            if state.selector.load(Ordering::Acquire).is_null() || !self.is_active() {
                return Err(RamError::Invariant("fingerprint custody lost its Original"));
            }
            drop(state);
            let call = Call {
                owner: self,
                return_owner: ViewOwner::Retirement(loan),
                scope,
            };
            call.sample().map_err(ObservationOperationError::into_io)?;
            return Ok(call);
        }
        if !state.selector.load(Ordering::Acquire).is_null() || self.is_active() {
            return Err(RamError::Invariant("Original module view still retained"));
        }
        // The native Source writes directly into this prepaid runtime member.
        // Every plain/atomic access is serialized by this same mutex. Native
        // records the durable member address and invokes no callback here.
        let result = (self.apis.borrow)(self.plugin_id, state.selector.get_mut());
        let selector = state.selector.load(Ordering::Acquire);
        state.evidence = None;
        state.capture = None;
        state.return_status = None;
        self.active.store(!selector.is_null(), Ordering::Release);
        drop(state);
        if result != 0 {
            return Err(RamError::Native {
                operation: "borrow native fingerprint Original",
                status: result,
            });
        }
        if selector.is_null() {
            return Err(RamError::Invariant("Source returned no actual Original"));
        }
        let call = Call {
            owner: self,
            return_owner: ViewOwner::Observer,
            scope,
        };
        call.sample().map_err(ObservationOperationError::into_io)?;
        Ok(call)
    }

    pub(super) fn has_retained_work(&self) -> bool {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        self.is_active()
            || state.reads.is_retained()
            || state.staged.is_some()
            || state.capture.is_some()
            || state.retirement.is_some()
            || state.retirement_busy
            || !state.publication.load(Ordering::Acquire).is_null()
    }

    pub(super) fn staged_root(
        &self,
        scope: Scope,
        previous: Option<&CachedView>,
    ) -> Result<(RamRootDigest, u64), RamError> {
        let state = self.state.try_lock().map_err(|_| "logical stage busy")?;
        let staged = state.staged.as_ref().ok_or("logical view was not staged")?;
        let view = staged
            .view
            .as_ref()
            .or(previous)
            .ok_or("logical staged baseline absent")?;
        let index = SCOPES
            .iter()
            .position(|candidate| *candidate == scope)
            .ok_or("logical scope absent")?;
        Ok((view.roots[index], view.logical_bytes[index]))
    }

    pub(super) fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    fn selector(&self) -> Result<usize, ObservationOperationError> {
        let state = self
            .state
            .try_lock()
            .map_err(|_| refusal("Original owner busy"))?;
        if !self.is_active() || state.selector.load(Ordering::Acquire).is_null() {
            return Err(refusal("native fingerprint Original is not borrowed"));
        }
        Ok(state.selector.load(Ordering::Acquire) as usize)
    }

    fn sample(&self) -> Result<Evidence, ObservationOperationError> {
        let selector = self.selector()?;
        let mut evidence = Evidence::default();
        // No observer/State/Slot guard crosses a native Source observation.
        let result = (self.apis.observe)(selector as *mut Operation, &mut evidence);
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
            .map_err(|_| refusal("Original observation busy"))?;
        if state.selector.load(Ordering::Acquire) as usize != selector
            || !valid_evidence(&evidence, state.evidence.as_ref())
        {
            return Err(refusal("native fingerprint Original observation changed"));
        }
        state.evidence = Some(evidence);
        Ok(evidence)
    }

    /// Returns only the module view, independently of Original post and end.
    fn return_view(&self) -> Result<(), RamError> {
        let selector = self
            .selector()
            .map_err(ObservationOperationError::into_io)?;
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.selector.load(Ordering::Acquire) as usize != selector {
            return Err(RamError::Invariant("Original return selector changed"));
        }
        if state.reads.is_retained() {
            return Err(RamError::Invariant(
                "Original backing read is still retained",
            ));
        }
        // This callback-free identity return mutates the actual saved holder.
        // It queries no Original and invokes no module/State/Slot callbacks.
        let result = (self.apis.return_view)(state.selector.get_mut());
        let pointer = state.selector.load(Ordering::Acquire);
        state.return_status = Some(result);
        self.active.store(!pointer.is_null(), Ordering::Release);
        if result != 0 {
            return Err(RamError::Native {
                operation: "return native fingerprint Original view",
                status: result,
            });
        }
        if !pointer.is_null() {
            return Err(RamError::Invariant("Original view return retained custody"));
        }
        Ok(())
    }
}

fn valid_evidence(current: &Evidence, previous: Option<&Evidence>) -> bool {
    current.serial != 0
        && matches!(current.class, 4 | 5)
        && current.bounded_ns != 0
        && current.bounded_ns <= i64::MAX as u64
        && current.progress_ns >= current.start_ns
        && previous.is_none_or(|previous| {
            current.capability == previous.capability
                && current.origin_ns == previous.origin_ns
                && current.serial == previous.serial
                && current.start_ns == previous.start_ns
                && current.class == previous.class
                && current.progress_ns >= previous.progress_ns
        })
}

fn refusal(message: &'static str) -> ObservationOperationError {
    ObservationOperationError::Static {
        kind: std::io::ErrorKind::Other,
        message,
    }
}

/// Borrows the stable Source lane during the genuine synchronous observer.
enum ViewOwner {
    Observer,
    Retirement(usize),
}

pub(super) struct Call<'a> {
    owner: &'a Owner,
    return_owner: ViewOwner,
    scope: Scope,
}

impl Call<'_> {
    fn sample(&self) -> Result<Evidence, ObservationOperationError> {
        self.owner.sample()
    }

    pub(super) fn require_full(&self) -> Result<bool, RamError> {
        self.sample()
            .map(|evidence| evidence.class == 4)
            .map_err(ObservationOperationError::into_io)
            .map_err(Into::into)
    }

    pub(super) fn begin(&self, full: bool, restart: bool) -> Result<CaptureHeader, RamError> {
        let selector = self
            .owner
            .selector()
            .map_err(ObservationOperationError::into_io)?;
        self.sample().map_err(ObservationOperationError::into_io)?;
        let mut header = CaptureHeader::default();
        let mut state = self
            .owner
            .state
            .try_lock()
            .map_err(|_| "Original capture busy")?;
        if state.selector.load(Ordering::Acquire) as usize != selector {
            return Err(RamError::Invariant("Original capture owner changed"));
        }
        // Both entry points are callback-free. Begin writes its real loan into
        // the saved field before projecting a signed/header refusal.
        let result = if restart {
            (self.owner.apis.restart)(
                self.owner.plugin_id,
                selector as *mut Operation,
                u32::from(full),
                &mut header,
            )
        } else {
            (self.owner.apis.begin)(
                self.owner.plugin_id,
                selector as *mut Operation,
                u32::from(full),
                &mut header,
                state.publication.get_mut(),
            )
        };
        // Keep any born output before validating it or interpreting a refusal.
        // Returning the Original view alone cannot prove this capture settled;
        // only its eventual native publication journal permits cache reuse.
        if header.capture_generation != 0 {
            state.capture = Some(header);
        }
        let facts = publication::capture_facts(self.owner, &mut state);
        drop(state);
        status(result, "begin native logical RAM capture")?;
        facts?;
        Ok(header)
    }

    pub(super) fn retain_stage(
        &self,
        capture: CaptureHeader,
        view: Option<CachedView>,
    ) -> Result<(), RamError> {
        let evidence = self.sample().map_err(ObservationOperationError::into_io)?;
        let mut state = self
            .owner
            .state
            .try_lock()
            .map_err(|_| "logical staging owner busy")?;
        let actual = state
            .capture
            .as_ref()
            .ok_or("native logical capture absent")?;
        if state.staged.is_some()
            || actual.capture_generation != capture.capture_generation
            || actual.topology_generation != capture.topology_generation
            || actual.region_count != capture.region_count
        {
            return Err(RamError::Invariant("logical stage capture changed"));
        }
        state.staged = Some(StagedView {
            evidence,
            capture,
            scope: self.scope,
            view,
        });
        Ok(())
    }

    pub(super) fn check(&self) -> Result<(), RamError> {
        self.sample()
            .map(|_| ())
            .map_err(ObservationOperationError::into_io)
            .map_err(Into::into)
    }

    pub(super) fn finish(&self) -> Result<(), RamError> {
        let first = self.check();
        match self.return_owner {
            ViewOwner::Observer => first.and(self.owner.return_view()),
            ViewOwner::Retirement(loan) => {
                let state = self
                    .owner
                    .state
                    .try_lock()
                    .map_err(|_| "retirement view busy")?;
                if !state
                    .retirement
                    .as_ref()
                    .is_some_and(|custody| custody.loan == loan)
                {
                    return Err(RamError::Invariant("observer retirement custody changed"));
                }
                first
            }
        }
    }
}

impl Drop for Call<'_> {
    fn drop(&mut self) {
        if matches!(self.return_owner, ViewOwner::Observer) && self.owner.is_active() {
            // Expiry and panic do not prevent identity-only physical return.
            // Refusal retains the saved selector and paid lane for Main cleanup.
            let _ = self.owner.return_view();
        }
    }
}

/// Borrows only the narrow member of the process-retained runtime allocation.
#[derive(Clone, Copy)]
pub(crate) struct OwnerRef {
    address: usize,
}

impl OwnerRef {
    /// Constructs the narrow observer view after the genuine runtime birth.
    ///
    /// # Safety
    /// The caller must retain the actual prepaid pinned runtime containing this
    /// member for the process lifetime, including registration error and panic.
    /// The member must never be moved, replaced or dropped after this call.
    pub(crate) unsafe fn from_retained_runtime(owner: &Owner) -> Self {
        Self {
            address: std::ptr::from_ref(owner) as usize,
        }
    }

    pub(super) fn owner(self) -> &'static Owner {
        // SAFETY: the sole constructor requires actual prepaid pinned runtime
        // retention. This accesses only the separate mutex/atomic component,
        // never the concurrently-used whole runtime or its mutable installer.
        unsafe { &*(self.address as *const Owner) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> Evidence {
        Evidence {
            capability: [3; 32],
            origin_ns: 10,
            serial: 7,
            start_ns: 20,
            progress_ns: 30,
            bounded_ns: 500_000,
            class: 4,
        }
    }

    #[test]
    fn logical_restart_cannot_change_original_identity_or_class() {
        let original = evidence();
        for changed in [
            Evidence {
                capability: [4; 32],
                ..original
            },
            Evidence {
                origin_ns: 11,
                ..original
            },
            Evidence {
                serial: 8,
                ..original
            },
            Evidence {
                start_ns: 21,
                ..original
            },
            Evidence {
                class: 5,
                ..original
            },
        ] {
            assert!(!valid_evidence(&changed, Some(&original)));
        }
    }

    #[test]
    fn cumulative_progress_cannot_move_before_its_previous_cut() {
        let original = evidence();
        let regressed = Evidence {
            progress_ns: 29,
            ..original
        };
        assert!(!valid_evidence(&regressed, Some(&original)));

        let renewed_progress = Evidence {
            progress_ns: 31,
            bounded_ns: 1,
            ..original
        };
        assert!(valid_evidence(&renewed_progress, Some(&original)));
    }

    #[test]
    fn invalid_finite_slice_or_unissued_class_refuses_projection() {
        let original = evidence();
        for changed in [
            Evidence {
                bounded_ns: 0,
                ..original
            },
            Evidence {
                bounded_ns: i64::MAX as u64 + 1,
                ..original
            },
            Evidence {
                serial: 0,
                ..original
            },
            Evidence {
                class: 0,
                ..original
            },
            Evidence {
                class: 6,
                ..original
            },
            Evidence {
                progress_ns: 19,
                ..original
            },
        ] {
            assert!(!valid_evidence(&changed, None));
        }
    }
}

extern "C" fn return_old_view(id: u64, operation: *mut Operation, userdata: *mut c_void) -> c_int {
    std::panic::catch_unwind(|| {
        let owner = match registered_owner(id, userdata) {
            Ok(owner) => owner,
            Err(status) => return status,
        };
        let state = match owner.state.try_lock() {
            Ok(state) => state,
            Err(_) => return -libc::EBUSY,
        };
        if state.selector.load(Ordering::Acquire) != operation
            || operation.is_null()
            || state.retirement.is_some()
            || state.retirement_busy
        {
            return -libc::ESTALE;
        }
        drop(state);
        match owner.return_view() {
            Ok(()) => 0,
            Err(RamError::Native { status, .. }) if status < 0 => status,
            Err(_) => -libc::EIO,
        }
    })
    .unwrap_or(-libc::EIO)
}

fn registered_owner(id: u64, userdata: *mut c_void) -> Result<&'static Owner, c_int> {
    let owner = OBSERVER
        .get()
        .and_then(|observer| observer.original)
        .ok_or(-libc::ENODEV)?
        .owner();
    if owner.plugin_id != id
        || owner.owner_process != std::process::id()
        || owner.runtime_userdata != userdata as usize
        || userdata.is_null()
    {
        return Err(-libc::ESTALE);
    }
    Ok(owner)
}

/// Returns only the narrow API enrolled by the same retained Runtime owner.
///
/// # Errors
/// Refuses a foreign process, installer or actual userdata allocation. The
/// returned table issues no loan; its native observer authenticates invocation.
pub(crate) fn retirement_api(
    id: u64,
    userdata: *mut c_void,
) -> Result<crate::runtime::FingerprintApi, c_int> {
    Ok(registered_owner(id, userdata)?.fingerprint)
}

/// Returns only the producing class previously observed from a real Source view.
///
/// # Errors
/// Refuses an active view without factual class evidence or changed ownership.
/// This getter grants no time, read, progress or operation authority.
pub(crate) fn borrowed_original_class()
-> Result<Option<crate::paged_ram::source::SourceOperationClass>, RamError> {
    use crate::paged_ram::source::SourceOperationClass;
    let Some(owner) = OBSERVER.get().and_then(|observer| observer.original) else {
        return Ok(None);
    };
    let owner = owner.owner();
    let state = owner
        .state
        .try_lock()
        .map_err(|_| "Original classification busy")?;
    if !owner.is_active() {
        return Ok(None);
    }
    if state.selector.load(Ordering::Acquire).is_null() {
        return Err(RamError::Invariant("Original classification lost view"));
    }
    match state.evidence.as_ref().map(|evidence| evidence.class) {
        Some(4) => Ok(Some(SourceOperationClass::FingerprintInitialization)),
        Some(5) => Ok(Some(SourceOperationClass::FingerprintUpdate)),
        _ => Err(RamError::Invariant("Original producing class absent")),
    }
}
