//! Read-only native verification after the original RR constructor returns.
//!
//! The 144-byte getter and by-value 88-byte response are process-private GPL
//! ABIs. A fresh source getter precedes Arc/TLS access. Matching retained engine
//! identities describes construction; it grants no setter, HOLD or Ready loan.

use super::*;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NativePreparationReturn {
    pub(super) version: u32,
    pub(super) size: u32,
    pub(super) phase: u32,
    pub(super) cpu_index: u32,
    pub(super) plugin_id: u64,
    pub(super) process: u64,
    pub(super) actual_tid: u64,
    pub(super) loader_tid: u64,
    pub(super) deadline_ns: u64,
    pub(super) callback: usize,
    pub(super) userdata: *mut c_void,
    pub(super) constructor: *const c_void,
    pub(super) cpu: *const c_void,
    pub(super) permit: *const c_void,
    pub(super) engine: *mut c_void,
    pub(super) setter_mask: u32,
    pub(super) reserved: u32,
    pub(super) setup_digest: [u8; 32],
}

impl Default for NativePreparationReturn {
    fn default() -> Self {
        Self {
            version: 1,
            size: 144,
            phase: 0,
            cpu_index: 0,
            plugin_id: 0,
            process: 0,
            actual_tid: 0,
            loader_tid: 0,
            deadline_ns: 0,
            callback: 0,
            userdata: std::ptr::null_mut(),
            constructor: std::ptr::null(),
            cpu: std::ptr::null(),
            permit: std::ptr::null(),
            engine: std::ptr::null_mut(),
            setter_mask: 0,
            reserved: 0,
            setup_digest: [0; 32],
        }
    }
}

impl NativePreparationReturn {
    fn birth(self) -> NativePreparation {
        NativePreparation {
            version: self.version,
            size: 128,
            phase: 1,
            cpu_index: self.cpu_index,
            plugin_id: self.plugin_id,
            process: self.process,
            actual_tid: self.actual_tid,
            loader_tid: self.loader_tid,
            deadline_ns: self.deadline_ns,
            callback: self.callback,
            userdata: self.userdata,
            constructor: self.constructor,
            cpu: self.cpu,
            permit: self.permit,
            setup_digest: self.setup_digest,
        }
    }
}

pub(super) type ReadPreparationReturn = extern "C" fn(*mut NativePreparationReturn) -> c_int;

/// Describes the original RR engine through the source's revoked verification window.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparationObservation {
    /// Names this private ABI edition.
    pub version: u32,
    /// Reports the complete native ABI extent.
    pub size: u32,
    /// Contains zero on a matching observation or a negative refusal errno.
    pub status: i32,
    /// Names the original CPU0 during post-return verification.
    pub cpu_index: u32,
    /// Names the original process authenticated by the source getter.
    pub process: u64,
    /// Names the retained original loader thread.
    pub loader_tid: u64,
    /// Names the original RR thread on which the engine remains retained.
    pub actual_tid: u64,
    /// Reports the four actual callback births previously accepted by this owner.
    pub observed_mask: u32,
    /// Reports completed Rust calls matching all five native setter families.
    pub family_mask: u32,
    /// Correlates the same retained complete sealed constructor descriptor.
    pub setup_digest: [u8; 32],
    /// Remains zero in this edition.
    pub reserved: u64,
}

impl PreparationObservation {
    fn refused(status: c_int) -> Self {
        Self {
            version: 1,
            size: 88,
            status,
            cpu_index: 0,
            process: 0,
            loader_tid: 0,
            actual_tid: 0,
            observed_mask: 0,
            family_mask: 0,
            setup_digest: [0; 32],
            reserved: 0,
        }
    }
}

const _: () = {
    assert!(std::mem::size_of::<NativePreparationReturn>() == 144);
    assert!(std::mem::offset_of!(NativePreparationReturn, engine) == 96);
    assert!(std::mem::offset_of!(NativePreparationReturn, setter_mask) == 104);
    assert!(std::mem::offset_of!(NativePreparationReturn, reserved) == 108);
    assert!(std::mem::offset_of!(NativePreparationReturn, setup_digest) == 112);
    assert!(std::mem::size_of::<PreparationObservation>() == 88);
    assert!(std::mem::offset_of!(PreparationObservation, observed_mask) == 40);
    assert!(std::mem::offset_of!(PreparationObservation, family_mask) == 44);
    assert!(std::mem::offset_of!(PreparationObservation, setup_digest) == 48);
    assert!(std::mem::offset_of!(PreparationObservation, reserved) == 80);
};

pub(super) fn capture(apis: &PreparationApis) -> Result<NativePreparationReturn, c_int> {
    let mut tuple = NativePreparationReturn::default();
    let status = (apis.read_return)(&mut tuple);
    if status != 0 {
        return Err(if status < 0 { status } else { -libc::EPROTO });
    }
    let now = super::super::monotonic_ns().map_err(|_| -libc::ESTALE)?;
    if tuple.version != 1
        || tuple.size != 144
        || tuple.phase != 2
        || tuple.cpu_index != 0
        || tuple.process != u64::from(std::process::id())
        || tuple.actual_tid != current_tid()?
        || tuple.loader_tid == 0
        || tuple.plugin_id == 0
        || tuple.callback != prepare_on_rr as *const () as usize
        || tuple.userdata.is_null()
        || tuple.constructor.is_null()
        || tuple.cpu.is_null()
        || tuple.permit.is_null()
        || tuple.engine.is_null()
        || tuple.setter_mask != 31
        || tuple.reserved != 0
        || now >= tuple.deadline_ns
    {
        return Err(-libc::ESTALE);
    }
    Ok(tuple)
}

fn observe(
    original: &Arc<SharedCallbackCustody>,
    tuple: NativePreparationReturn,
    userdata: *mut c_void,
) -> Result<PreparationObservation, c_int> {
    if tuple.userdata != userdata
        || userdata != Arc::as_ptr(original).cast_mut().cast()
        || !tuple_matches(&tuple.birth(), original)
        || !original.preparation_attempted.load(Ordering::Acquire)
    {
        return Err(-libc::ESTALE);
    }

    ENGINE
        .try_with(|cell| {
            let slot = cell.try_borrow().map_err(|_| -libc::EBUSY)?;
            let engine = slot.as_ref().ok_or(-libc::ESTALE)?;
            // Only a retained Box supplies the comparison address. No supplied
            // native/userdata address is ever dereferenced by this observer.
            let retained_pointer = std::ptr::from_ref(engine.as_ref()).cast_mut().cast();
            if tuple.engine != retained_pointer
                || !Arc::ptr_eq(&engine._original, original)
                || engine._birth != tuple.birth()
                || !engine.native_visible
                || engine.registered_families != 31
            {
                return Err(-libc::ESTALE);
            }
            Ok(PreparationObservation {
                version: 1,
                size: 88,
                status: 0,
                cpu_index: tuple.cpu_index,
                process: tuple.process,
                loader_tid: tuple.loader_tid,
                actual_tid: tuple.actual_tid,
                observed_mask: u32::from(original.observed_vcpus.load(Ordering::Acquire)),
                family_mask: engine.registered_families,
                setup_digest: tuple.setup_digest,
                reserved: 0,
            })
        })
        .map_err(|_| -libc::ESTALE)?
}

/// Reports the retained RR engine inside the original native post-return observer.
///
/// A fresh source getter authenticates the read-only verification window before
/// accessing Rust custody. Failed observations fence scalar callback admission;
/// they never acquire mapping/journal guards or reopen native permissions.
#[unsafe(no_mangle)]
pub extern "C" fn crucible_qemu_plugin_preparation_observation_v1(
    userdata: *mut c_void,
) -> PreparationObservation {
    if !callback_process_current() {
        return PreparationObservation::refused(-libc::ESTALE);
    }
    let captured = APIS.get().ok_or(-libc::ESTALE).and_then(capture);
    let Some(original) = super::super::ORIGINAL_CALLBACK.get() else {
        return PreparationObservation::refused(-libc::ESTALE);
    };
    let result = captured.and_then(|tuple| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            observe(original, tuple, userdata)
        }))
        .map_err(|_| -libc::EFAULT)?
    });
    match result {
        Ok(observation) => observation,
        Err(status) => {
            original.refuse_callback();
            PreparationObservation::refused(status)
        }
    }
}

#[cfg(test)]
pub(super) fn compare_retained_for_test(
    original: &Arc<SharedCallbackCustody>,
    tuple: NativePreparationReturn,
    userdata: *mut c_void,
) -> Result<PreparationObservation, c_int> {
    observe(original, tuple, userdata)
}
