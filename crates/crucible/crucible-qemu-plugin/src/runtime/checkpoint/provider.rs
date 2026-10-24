//! Retains installed paging allocations under an authenticated native request.
//!
//! Acquisition lends one inline Slot in the same pinned runtime. PREPARE then
//! uses its existing controller/service owner; copied request fields supply no
//! page or execution proof. Finalization runs after RELEASE on Main, and end
//! returns this keeper only after the actual State journal or a genuine native
//! no-root disposition. No callback runs from a State-held native observer end.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::ffi::c_void;
use std::sync::atomic::Ordering;

use super::{Invocation, OwnedCallbackRuntimeState, RetiredCallback, Slot};
use crate::paged_ram::controller::retain_pager_owner;

#[repr(C)]
struct Request {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Default)]
struct RequestStatus {
    schema_version: u32,
    struct_size: u32,
    request_generation: u64,
    native_transaction_generation: u64,
    connection_epoch: u64,
    process_generation: u64,
    cancellation_device: u64,
    cancellation_inode: u64,
    cancellation_event_id: u64,
    cancellation_fd: i32,
    reserved: u32,
    original: *const u8,
    original_bytes: usize,
    arm_request_digest: *const u8,
    arm_request_digest_bytes: usize,
    first_status: i32,
    post_status: i32,
}

type Acquire = extern "C" fn(u64, *mut Request, *mut c_void, *mut *mut c_void) -> i32;
type Return = extern "C" fn(u64, *mut Request, *mut c_void, *mut c_void) -> i32;
type Register =
    extern "C" fn(u64, Option<Acquire>, Option<Return>, Option<Return>, *mut c_void) -> i32;
type RegisterFinalize = extern "C" fn(u64, Option<Return>, *mut c_void) -> i32;
type Observe = extern "C" fn(u64, *mut Request, *mut RequestStatus) -> i32;

#[derive(Clone, Copy)]
pub(super) struct ProviderApi {
    register: Register,
    register_finalize: RegisterFinalize,
    observe: Observe,
}

impl ProviderApi {
    /// Resolves every matched registrar and identity observer before publication.
    ///
    /// # Errors
    /// Refuses any missing function from the literal process-private SDK.
    pub(super) fn resolve() -> Result<Self, i32> {
        macro_rules! resolve {
            ($name:literal, $signature:ty) => {{
                // SAFETY: the fixed symbol names refer to the literal matched
                // process-private SDK. Resolution itself issues no request loan.
                let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, $name.as_ptr()) };
                if address.is_null() {
                    return Err(-libc::ENOSYS);
                }
                // SAFETY: the non-null symbol has this exact SDK declaration.
                unsafe { std::mem::transmute::<*mut c_void, $signature>(address) }
            }};
        }
        Ok(Self {
            register: resolve!(
                c"qemu_plugin_crucible_register_checkpoint_provider_v1",
                Register
            ),
            register_finalize: resolve!(
                c"qemu_plugin_crucible_register_checkpoint_finalize_v1",
                RegisterFinalize
            ),
            observe: resolve!(
                c"qemu_plugin_crucible_checkpoint_request_observe_v2",
                Observe
            ),
        })
    }

    /// Registers against the already retained pager userdata before actor birth.
    ///
    /// # Errors
    /// Preserves genuine registrar refusal while keeping userdata retained.
    pub(super) fn register(self, plugin_id: u64, userdata: *mut c_void) -> Result<(), i32> {
        let status = (self.register)(plugin_id, Some(acquire), Some(check), Some(end), userdata);
        if status != 0 {
            return Err(status);
        }
        let status = (self.register_finalize)(plugin_id, Some(finalize), userdata);
        if status == 0 { Ok(()) } else { Err(status) }
    }

    fn binding(self, plugin_id: u64, request: *mut Request) -> Result<ProviderBinding, i32> {
        let mut output = RequestStatus::default();
        let status = (self.observe)(plugin_id, request, &mut output);
        if status != 0 {
            return Err(status);
        }
        if output.schema_version != 2
            || output.struct_size as usize != std::mem::size_of::<RequestStatus>()
            || output.request_generation == 0
            || output.native_transaction_generation == 0
            || output.connection_epoch == 0
            || output.process_generation == 0
            || output.cancellation_fd < 0
            || output.reserved != 0
            || output.original.is_null()
            || output.original_bytes != 80
            || output.arm_request_digest.is_null()
            || output.arm_request_digest_bytes != 32
            || output.first_status > 0
            || output.post_status > 0
        {
            return Err(-libc::EPROTO);
        }
        // SAFETY: the successful identity-only native observer lends exactly
        // these complete fixed arrays throughout this registered invocation.
        // No pointer or descriptor escapes; native retains close/read custody.
        let (original, digest) = unsafe {
            (
                *output.original.cast::<[u8; 80]>(),
                *output.arm_request_digest.cast::<[u8; 32]>(),
            )
        };
        Ok(ProviderBinding {
            request: request as usize,
            request_generation: output.request_generation,
            transaction: output.native_transaction_generation,
            connection_epoch: output.connection_epoch,
            process_generation: output.process_generation,
            cancellation_device: output.cancellation_device,
            cancellation_inode: output.cancellation_inode,
            cancellation_event_id: output.cancellation_event_id,
            cancellation_fd: output.cancellation_fd,
            original,
            digest,
        })
    }
}

/// Records the nominal borrowed request together with the actual inline keeper.
/// Equality checks reject foreign calls; they never construct native authority.
#[derive(PartialEq, Eq)]
pub(super) struct ProviderBinding {
    request: usize,
    request_generation: u64,
    transaction: u64,
    connection_epoch: u64,
    process_generation: u64,
    cancellation_device: u64,
    cancellation_inode: u64,
    cancellation_event_id: u64,
    cancellation_fd: i32,
    original: [u8; 80],
    digest: [u8; 32],
}

impl ProviderBinding {
    pub(super) fn matches_reader(&self, read: &super::reader::HeldReaderIdentity) -> bool {
        self.request_generation == read.request_generation
            && self.transaction == read.transaction
            && self.process_generation == read.process_generation
            && self.connection_epoch == read.connection_epoch
            && self.original == read.original
    }

    pub(super) fn matches_invocation(&self, call: &Invocation) -> bool {
        self.transaction == call.native_transaction_generation
            && self.process_generation == call.process_generation
            && self.cancellation_device == call.cancellation_device
            && self.cancellation_inode == call.cancellation_inode
            && self.cancellation_event_id == call.cancellation_event_id
            && self.cancellation_fd == call.cancellation_fd
    }
}

fn with_runtime(
    plugin_id: u64,
    request: *mut Request,
    userdata: *mut c_void,
    callback: impl FnOnce(&OwnedCallbackRuntimeState, ProviderBinding) -> i32,
) -> i32 {
    if userdata.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: only the genuine native registrar invokes these private callbacks;
    // its retained userdata is the same pinned allocation for this whole call.
    // The scoped closure returns only a status and cannot extend this borrow.
    let runtime = unsafe { &*userdata.cast::<OwnedCallbackRuntimeState>() };
    if runtime.plugin_id != Some(plugin_id) || runtime.owner_process != std::process::id() {
        return -libc::ESTALE;
    }
    match observed_binding(runtime, plugin_id, request) {
        Ok(binding) => callback(runtime, binding),
        Err(status) => status,
    }
}

fn observed_binding(
    runtime: &OwnedCallbackRuntimeState,
    plugin_id: u64,
    request: *mut Request,
) -> Result<ProviderBinding, i32> {
    if request.is_null() {
        return Err(-libc::EINVAL);
    }
    let binding = runtime
        .checkpoint_api
        .ok_or(-libc::ENOSYS)?
        .provider
        .binding(plugin_id, request)?;
    if binding.process_generation != runtime.process_generation {
        return Err(-libc::ESTALE);
    }
    Ok(binding)
}

fn matches_owner(slot: &Slot, owner: *mut c_void, binding: &ProviderBinding) -> bool {
    owner == std::ptr::from_ref(slot).cast_mut().cast()
        && slot.provider.as_ref() == Some(binding)
        && slot.owner.is_some()
}

extern "C" fn acquire(
    plugin_id: u64,
    request: *mut Request,
    userdata: *mut c_void,
    output: *mut *mut c_void,
) -> i32 {
    if output.is_null() {
        return -libc::EINVAL;
    }
    with_runtime(plugin_id, request, userdata, |runtime, binding| {
        let Ok(mut slot) = runtime.checkpoint.try_lock() else {
            return -libc::EBUSY;
        };
        if slot.provider.is_some()
            || slot.owner.is_some()
            || slot.root.is_some()
            || slot.binding.is_some()
        {
            return -libc::EBUSY;
        }
        if slot
            .retired
            .as_ref()
            .is_some_and(|retired| retired.transaction >= binding.transaction)
        {
            return -libc::ESTALE;
        }
        let Some(issued) = slot.issued_owner.checked_add(1) else {
            return -libc::EOVERFLOW;
        };
        let owner = match retain_pager_owner(binding.transaction) {
            Ok(owner) => owner,
            Err(cause) => return slot.refuse(cause),
        };
        slot.provider = Some(binding);
        slot.owner = Some(owner);
        slot.issued_owner = issued;
        runtime
            .checkpoint_owner_retained
            .store(true, Ordering::Release);
        // SAFETY: native lends this writable output for this call. It retains the
        // returned real inline Slot; its address cannot move within pinned runtime.
        unsafe { output.write(std::ptr::from_mut(&mut *slot).cast()) };
        0
    })
}

extern "C" fn check(
    plugin_id: u64,
    request: *mut Request,
    owner: *mut c_void,
    userdata: *mut c_void,
) -> i32 {
    with_runtime(plugin_id, request, userdata, |runtime, binding| {
        let Ok(mut slot) = runtime.checkpoint.try_lock() else {
            return -libc::EBUSY;
        };
        if !matches_owner(&slot, owner, &binding) {
            return -libc::ESTALE;
        }
        if slot.first_status != 0 {
            return slot.first_status;
        }
        match slot.owner.as_ref().map(|owner| owner.check_retained()) {
            Some(Ok(())) => 0,
            Some(Err(cause)) => slot.refuse(cause),
            None => -libc::ESTALE,
        }
    })
}

extern "C" fn finalize(
    plugin_id: u64,
    request: *mut Request,
    owner: *mut c_void,
    userdata: *mut c_void,
) -> i32 {
    with_runtime(plugin_id, request, userdata, |runtime, binding| {
        let Ok(slot) = runtime.checkpoint.try_lock() else {
            return -libc::EBUSY;
        };
        if !matches_owner(&slot, owner, &binding) || slot.root.is_some() {
            return -libc::ESTALE;
        }
        match slot.owner.as_ref().map(|owner| owner.finalize_retirement()) {
            Some(Ok(true)) => {
                match crate::ram_fingerprint::retire_held_cache(|read| binding.matches_reader(read))
                {
                    Ok(()) => 0,
                    Err(_) => -libc::EBUSY,
                }
            }
            Some(Ok(false)) => -libc::EINPROGRESS,
            Some(Err(crate::ram_error::RamError::Native { status, .. })) if status != 0 => status,
            _ => -libc::EBUSY,
        }
    })
}

extern "C" fn end(
    plugin_id: u64,
    request: *mut Request,
    owner: *mut c_void,
    userdata: *mut c_void,
) -> i32 {
    with_runtime(plugin_id, request, userdata, |runtime, binding| {
        let Ok(mut slot) = runtime.checkpoint.try_lock() else {
            return -libc::EBUSY;
        };
        if !matches_owner(&slot, owner, &binding) || slot.root.is_some() {
            return -libc::ESTALE;
        }
        if slot.binding.is_some() {
            if let Err(status) = slot.retire_completed_owner() {
                return status;
            }
        } else {
            match slot
                .owner
                .as_ref()
                .map(|owner| owner.unprepared_returnable())
            {
                Some(Ok(true)) => {}
                _ => return -libc::EBUSY,
            }
            slot.retired = Some(RetiredCallback {
                transaction: binding.transaction,
                first_status: slot.first_status,
                post_status: slot.post_status,
            });
            slot.owner.take();
            slot.failure = None;
            slot.first_status = 0;
            slot.post_status = 0;
        }
        slot.provider.take();
        0
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Coordinates exercise refusal checks only; these fixtures issue no native
    // request, installed service, stopped proof or provider lease.
    fn binding() -> ProviderBinding {
        ProviderBinding {
            request: 1,
            request_generation: 2,
            transaction: 3,
            connection_epoch: 4,
            process_generation: 5,
            cancellation_device: 6,
            cancellation_inode: 7,
            cancellation_event_id: 8,
            cancellation_fd: 9,
            original: [10; 80],
            digest: [11; 32],
        }
    }

    fn invocation() -> Invocation {
        Invocation {
            schema_version: 2,
            struct_size: std::mem::size_of::<Invocation>() as u32,
            action: 1,
            disposition: 0,
            native_transaction_generation: 3,
            process_generation: 5,
            arena_generation: 1,
            topology_generation: 1,
            cancellation_device: 6,
            cancellation_inode: 7,
            cancellation_event_id: 8,
            cancellation_fd: 9,
            reserved: 0,
        }
    }

    #[test]
    fn foreign_pager_transaction_process_or_event_refuses_same_keeper_binding() {
        let binding = binding();
        for field in 0..6 {
            let mut call = invocation();
            match field {
                0 => call.native_transaction_generation += 1,
                1 => call.process_generation += 1,
                2 => call.cancellation_device += 1,
                3 => call.cancellation_inode += 1,
                4 => call.cancellation_event_id += 1,
                5 => call.cancellation_fd += 1,
                _ => unreachable!(),
            }

            assert!(!binding.matches_invocation(&call));
        }
    }

    #[test]
    fn request_digest_and_original_remain_part_of_the_retained_binding() {
        let original = binding();
        for field in 0..5 {
            let mut foreign = binding();
            match field {
                0 => foreign.request += 1,
                1 => foreign.request_generation += 1,
                2 => foreign.connection_epoch += 1,
                3 => foreign.original[0] ^= 1,
                4 => foreign.digest[0] ^= 1,
                _ => unreachable!(),
            }

            assert!(original != foreign);
        }
    }

    #[test]
    fn equal_coordinates_and_slot_address_cannot_replace_actual_keeper_owner() {
        let slot = Slot {
            provider: Some(binding()),
            ..Slot::default()
        };
        let address = std::ptr::from_ref(&slot).cast_mut().cast();

        assert!(!matches_owner(&slot, address, &binding()));
        assert!(slot.owner.is_none());
        assert!(slot.root.is_none());
    }
}
