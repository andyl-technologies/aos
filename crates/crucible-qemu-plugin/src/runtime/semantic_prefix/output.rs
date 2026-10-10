//! Original reply-backed reservations for the output-disabled prefix subset.
//!
//! Source supplies an authenticated pending-cut bound. Each stable slot joins
//! that cut to the actual pre-dequeue reply credit; no modeled FIFO publication
//! is available in this dispatcher. Finish keeps the slot and credit retained.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::ffi::{c_int, c_void};
use std::sync::TryLockError;

#[cfg(not(test))]
use super::PrefixPolicy;
use super::{SemanticPrefixOwner, SourcePrefixEffectCut, SourcePrefixRootSeal};
use crate::native_node_control::administrative_inbox::NativeAdministrativeInboxError;
use crucible_protocol::node_control::NativeCommandError;

#[derive(Default)]
#[repr(C)]
pub(super) struct NativeBound {
    version: u32,
    size: u32,
    sequence: u64,
    cut_id: u64,
    canonical_bytes: u32,
    modeled_records: u32,
}

pub(super) type QueryBound = extern "C" fn(
    *const SourcePrefixRootSeal,
    *mut c_void,
    *const SourcePrefixEffectCut,
    *mut NativeBound,
) -> c_int;

/// Joins one native cut to stable, preallocated original reply custody.
#[derive(Default)]
pub(super) struct Reservation {
    root: usize,
    epoch: usize,
    cut: usize,
    sequence: u64,
    pub(super) cut_id: u64,
    cursor: u64,
    canonical_bytes: u32,
    pub(super) finished: bool,
    request_index: Option<usize>,
}

/// Supplies the exact copied process-life output reservation callbacks.
#[repr(C)]
pub(super) struct Operations {
    version: u32,
    size: u32,
    reserve: Reserve,
    validate_reserved: Validate,
    finish: Validate,
    userdata: *mut c_void,
}

/// Registers copied reservation callbacks for the exact installed prefix owner.
///
/// # Safety
/// Source copies the three function pointers and process-life userdata before
/// publication. Its calls retain known root/epoch/cut objects and synchronous
/// output storage; foreign reservation addresses are never dereferenced.
#[cfg(not(test))]
pub(super) type RegisterOutput = extern "C" fn(*const PrefixPolicy, *const Operations) -> c_int;

impl Operations {
    pub(super) fn original(userdata: *mut c_void) -> Self {
        Self {
            version: 1,
            size: 40,
            reserve,
            validate_reserved,
            finish,
            userdata,
        }
    }
}

pub(super) fn allocate(capacity: u32) -> Result<Box<[Reservation]>, NativeCommandError> {
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(capacity as usize)
        .map_err(|_| NativeCommandError::Invalid("prefix reservation allocation failed"))?;
    slots.resize_with(capacity as usize, Reservation::default);
    Ok(slots.into_boxed_slice())
}

impl SemanticPrefixOwner {
    fn reserve_output(
        &self,
        root: *const SourcePrefixRootSeal,
        epoch: *mut c_void,
        cut: *const SourcePrefixEffectCut,
    ) -> Result<*mut c_void, c_int> {
        let runtime = self.runtime()?;
        if runtime.setup.mapped_region().header().shutdown_requested()
            || crate::native_node_control::registered_owner()
                .is_none_or(|owner| owner.semantic_administration_failed())
        {
            return Err(-libc::ECANCELED);
        }
        if root.is_null() || epoch.is_null() || cut.is_null() {
            return Err(-libc::EINVAL);
        }
        // The native getter requires its exact pending cut and sealed installed
        // roster. A caller count or an observed empty FIFO cannot create a bound.
        let mut bound = NativeBound::default();
        let result = (self.api.query_output_bound)(root, epoch, cut, &mut bound);
        if result != 0 {
            return Err(result);
        }
        if bound.version != 1
            || bound.size != 32
            || bound.sequence == 0
            || bound.cut_id == 0
            || bound.modeled_records != 0
            || !matches!(bound.canonical_bytes, 256 | 320)
        {
            return Err(-libc::ESTALE);
        }
        let mut state = self.state.try_lock().map_err(lock_error)?;
        let actual_epoch = std::ptr::from_mut(state.epoch.as_mut()).cast::<c_void>();
        if state.failed || !state.acquired || state.root != root as usize || actual_epoch != epoch {
            return Err(-libc::ESTALE);
        }
        let original = state.command.as_ref().ok_or(-libc::EAGAIN)?;
        if original.compute.command.sequence.get() != bound.sequence {
            return Err(-libc::ESTALE);
        }
        let request_index = match bound.canonical_bytes {
            256 => {
                if original.result.is_some() {
                    return Err(-libc::ESTALE);
                }
                None
            }
            320 => Some(
                state
                    .requests
                    .iter()
                    .position(|request| {
                        matches!(
                            request.frame,
                            crucible_protocol::node_control::NativeFrame::ContinuePrefix(_)
                        ) && request.reply.is_none()
                            && (request.cut_id.is_none() || request.cut_id == Some(bound.cut_id))
                    })
                    .ok_or(-libc::ESTALE)?,
            ),
            _ => return Err(-libc::ESTALE),
        };
        let (cursor, credit) = if let Some(index) = request_index {
            let request = &state.requests[index];
            (request.cursor, request.credit.as_ref())
        } else {
            (original.cursor, original.credit.as_ref())
        };
        self.original_actor()?
            .validate_unpublished_credit(credit.ok_or(-libc::ESTALE)?)
            .map_err(credit_error)?;
        let index = state
            .output
            .iter()
            .position(|slot| slot.cut == cut as usize)
            .or_else(|| state.output.iter().position(|slot| slot.cut == 0))
            .ok_or(-libc::ENOSPC)?;
        let slot = &mut state.output[index];
        if slot.cut != 0 {
            if !slot.matches(root, epoch, cut)
                || slot.sequence != bound.sequence
                || slot.cut_id != bound.cut_id
                || slot.cursor != cursor
                || slot.canonical_bytes != bound.canonical_bytes
                || slot.request_index != request_index
                || slot.finished
            {
                return Err(-libc::ESTALE);
            }
        } else {
            *slot = Reservation {
                root: root as usize,
                epoch: epoch as usize,
                cut: cut as usize,
                sequence: bound.sequence,
                cut_id: bound.cut_id,
                cursor,
                canonical_bytes: bound.canonical_bytes,
                finished: false,
                request_index,
            };
        }
        let address = std::ptr::from_mut(slot).cast();
        if let Some(index) = request_index {
            state.requests[index].cut_id = Some(bound.cut_id);
            state.requests[index].cut_handle = cut as usize;
        }
        Ok(address)
    }

    fn validate_output(
        &self,
        root: *const SourcePrefixRootSeal,
        epoch: *mut c_void,
        cut: *const SourcePrefixEffectCut,
        reservation: *mut c_void,
        finish_original: bool,
    ) -> Result<(), c_int> {
        let runtime = self.runtime()?;
        if runtime.setup.mapped_region().header().shutdown_requested()
            || crate::native_node_control::registered_owner()
                .is_none_or(|owner| owner.semantic_administration_failed())
        {
            return Err(-libc::ECANCELED);
        }
        let mut state = self.state.try_lock().map_err(lock_error)?;
        if state.failed
            || !state.acquired
            || state.root != root as usize
            || std::ptr::from_mut(state.epoch.as_mut()).cast::<c_void>() != epoch
        {
            return Err(-libc::ESTALE);
        }
        // Identity comparison precedes every slot access; opaque foreign
        // addresses cannot name an adopted reservation or a Rust allocation.
        let index = state
            .output
            .iter()
            .position(|slot| std::ptr::from_ref(slot).cast_mut().cast::<c_void>() == reservation)
            .ok_or(-libc::ESTALE)?;
        let slot = &state.output[index];
        if !slot.matches(root, epoch, cut) {
            return Err(-libc::ESTALE);
        }
        let original = state.command.as_ref().ok_or(-libc::ESTALE)?;
        if slot.sequence != original.compute.command.sequence.get() {
            return Err(-libc::ESTALE);
        }
        let credit = if let Some(request_index) = slot.request_index {
            let request = state.requests.get(request_index).ok_or(-libc::ESTALE)?;
            if request.cursor != slot.cursor
                || request.cut_id != Some(slot.cut_id)
                || request.cut_handle != cut as usize
            {
                return Err(-libc::ESTALE);
            }
            request.credit.as_ref()
        } else {
            if slot.cursor != original.cursor || original.cut_id.is_some_and(|id| id != slot.cut_id)
            {
                return Err(-libc::ESTALE);
            }
            original.credit.as_ref()
        };
        self.original_actor()?
            .validate_unpublished_credit(credit.ok_or(-libc::ESTALE)?)
            .map_err(credit_error)?;
        if finish_original {
            state.output[index].finished = true;
        }
        Ok(())
    }

    pub(super) fn original_actor(
        &self,
    ) -> Result<
        &'static std::sync::Arc<
            crate::native_node_control::administrative_inbox::NativeAdministrativeInbox,
        >,
        c_int,
    > {
        crate::native_node_control::registered_owner()
            .and_then(|owner| owner.original_administrative_actor())
            .ok_or(-libc::ESTALE)
    }
}

impl Reservation {
    pub(super) fn matches(
        &self,
        root: *const SourcePrefixRootSeal,
        epoch: *mut c_void,
        cut: *const SourcePrefixEffectCut,
    ) -> bool {
        self.cut != 0
            && self.root == root as usize
            && self.epoch == epoch as usize
            && self.cut == cut as usize
    }
}

fn lock_error<T>(error: TryLockError<T>) -> c_int {
    match error {
        TryLockError::WouldBlock => -libc::EAGAIN,
        TryLockError::Poisoned(_) => -libc::EOWNERDEAD,
    }
}

fn credit_error(error: NativeAdministrativeInboxError) -> c_int {
    match error {
        NativeAdministrativeInboxError::Busy => -libc::EAGAIN,
        _ => -libc::ESTALE,
    }
}

/// Reserves actual original reply credit without granting effect admission.
///
/// # Safety
/// Source retains its known root/epoch/cut and the installed process-life
/// userdata. Output is aligned writable storage disjoint from owner custody.
/// The callback clears it before every refusal and never dereferences handles.
type Reserve = unsafe extern "C" fn(
    root: *const SourcePrefixRootSeal,
    epoch: *mut c_void,
    cut: *const SourcePrefixEffectCut,
    output: *mut *mut c_void,
    userdata: *mut c_void,
) -> c_int;

/// Revalidates or finishes the same original reservation without releasing credit.
///
/// # Safety
/// Source retains the exact installed userdata and known source objects for
/// the call. Reservation addresses are looked up in the owner's stable slots
/// before access; a caller address is never adopted or dereferenced.
type Validate = unsafe extern "C" fn(
    root: *const SourcePrefixRootSeal,
    epoch: *mut c_void,
    cut: *const SourcePrefixEffectCut,
    reservation: *mut c_void,
    userdata: *mut c_void,
) -> c_int;

/// Copies only a source-authenticated original reservation to native output.
///
/// # Safety
/// The copied installed tuple supplies process-life userdata and writable
/// output storage. Source handles are known to native code and never dereferenced.
unsafe extern "C" fn reserve(
    root: *const SourcePrefixRootSeal,
    epoch: *mut c_void,
    cut: *const SourcePrefixEffectCut,
    output: *mut *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    if output.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: The installed native callback supplies aligned writable output.
    unsafe {
        output.write(std::ptr::null_mut());
    }
    if userdata.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: Source retains the exact registered process-life owner allocation.
    let owner = unsafe { &*userdata.cast::<SemanticPrefixOwner>() };
    match owner.reserve_output(root, epoch, cut) {
        Ok(original) => {
            // SAFETY: The same output remains writable; the slot is process-life.
            unsafe {
                output.write(original);
            }
            0
        }
        Err(error) => error,
    }
}

/// Validates the actual original reservation without consuming its credit.
///
/// # Safety
/// Source retains registered userdata and the original root/epoch/cut. Foreign
/// reservation addresses are compared before access and never dereferenced.
unsafe extern "C" fn validate_reserved(
    root: *const SourcePrefixRootSeal,
    epoch: *mut c_void,
    cut: *const SourcePrefixEffectCut,
    reservation: *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    if userdata.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: Source retains the exact installed process-life owner allocation.
    let owner = unsafe { &*userdata.cast::<SemanticPrefixOwner>() };
    owner
        .validate_output(root, epoch, cut, reservation, false)
        .map_or_else(|e| e, |()| 0)
}

/// Finishes the native cut while preserving actual reply bytes and obligations.
///
/// # Safety
/// Source retains the same registered tuple and original handles through end.
/// Finish may mark only an already known retained slot; it releases no custody.
unsafe extern "C" fn finish(
    root: *const SourcePrefixRootSeal,
    epoch: *mut c_void,
    cut: *const SourcePrefixEffectCut,
    reservation: *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    if userdata.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: Source retains the exact installed process-life owner allocation.
    let owner = unsafe { &*userdata.cast::<SemanticPrefixOwner>() };
    owner
        .validate_output(root, epoch, cut, reservation, true)
        .map_or_else(|e| e, |()| 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    #[test]
    fn source_output_bound_and_copied_operation_tuple_match_native_layouts() {
        assert_eq!(size_of::<NativeBound>(), 32);
        assert_eq!(offset_of!(NativeBound, sequence), 8);
        assert_eq!(offset_of!(NativeBound, cut_id), 16);
        assert_eq!(offset_of!(NativeBound, canonical_bytes), 24);
        assert_eq!(offset_of!(NativeBound, modeled_records), 28);
        assert_eq!(size_of::<Operations>(), 40);
        assert_eq!(offset_of!(Operations, reserve), 8);
        assert_eq!(offset_of!(Operations, validate_reserved), 16);
        assert_eq!(offset_of!(Operations, finish), 24);
        assert_eq!(offset_of!(Operations, userdata), 32);
    }

    #[test]
    fn missing_owner_zeros_reservation_output_and_never_adopts_foreign_handles() {
        let operations = Operations::original(std::ptr::null_mut());
        let mut output = std::ptr::dangling_mut::<c_void>();

        // SAFETY: Output is aligned writable storage. Null userdata must be
        // rejected before any opaque handle or Rust owner is dereferenced.
        let result = unsafe {
            (operations.reserve)(
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                &mut output,
                operations.userdata,
            )
        };

        assert_eq!(result, -libc::EINVAL);
        assert!(output.is_null());
        // SAFETY: Both calls reject missing userdata before reservation access.
        unsafe {
            assert_eq!(
                (operations.validate_reserved)(
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::dangling_mut(),
                    operations.userdata
                ),
                -libc::EINVAL
            );
            assert_eq!(
                (operations.finish)(
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::dangling_mut(),
                    operations.userdata
                ),
                -libc::EINVAL
            );
        }
    }
}
