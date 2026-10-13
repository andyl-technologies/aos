//! Registers checkpoint callbacks against the actual pinned runtime allocation.
//!
//! Active original checks precede owner admission. Preparation retains the real
//! pager before requesting policy, accepted-work and fault-worker holds. Pending
//! observations retain the genuine native root and whole service/page owners.
//! Callback return and native restoration leave policy admission closed until
//! same-thread observers establish final physical cleanup and root acknowledgment.

// SPDX-License-Identifier: GPL-2.0-or-later

mod provider;
pub(crate) mod reader;
mod root;

pub(crate) use root::{LocalDisposition, NativeMailbox, NativeRoot, RootStage};

use std::ffi::c_void;
use std::pin::Pin;
use std::sync::atomic::Ordering;

use super::OwnedCallbackRuntimeState;
use crate::paged_ram::controller::CheckpointPagerOwner;
use crate::ram_error::RamError;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct Invocation {
    schema_version: u32,
    struct_size: u32,
    action: u32,
    disposition: u32,
    native_transaction_generation: u64,
    process_generation: u64,
    arena_generation: u64,
    topology_generation: u64,
    cancellation_device: u64,
    cancellation_inode: u64,
    cancellation_event_id: u64,
    cancellation_fd: i32,
    reserved: u32,
}

impl Invocation {
    fn owner_identity(mut self) -> Self {
        self.action = 0;
        self.disposition = 0;
        self
    }
}

#[repr(C)]
struct Status {
    schema_version: u32,
    struct_size: u32,
    action: u32,
    state: u32,
    native_transaction_generation: u64,
    plugin_owner_generation: u64,
    process_generation: u64,
    arena_generation: u64,
    topology_generation: u64,
    first_status: i32,
    post_status: i32,
}

type Callback = extern "C" fn(u64, *const Invocation, *mut Status, *mut c_void) -> i32;
type Register =
    extern "C" fn(u64, Option<Callback>, Option<Callback>, Option<Callback>, *mut c_void) -> i32;
type Check = extern "C" fn(u64) -> i32;

/// Stores only resolved process-private functions from the matched native SDK.
#[derive(Clone, Copy)]
pub(super) struct NativeApi {
    register: Register,
    check: Check,
    root: root::RootApi,
    provider: provider::ProviderApi,
    reader: reader::ReaderApi,
}

/// Keeps an entered owner and its first refusal in the pinned runtime allocation.
#[derive(Default)]
pub(super) struct Slot {
    binding: Option<Invocation>,
    provider: Option<provider::ProviderBinding>,
    owner: Option<CheckpointPagerOwner>,
    root: Option<NativeRoot>,
    issued_owner: u64,
    failure: Option<RamError>,
    first_status: i32,
    post_status: i32,
    retired: Option<RetiredCallback>,
}

/// Preserves the last disposed transaction's signed facts after owner release.
struct RetiredCallback {
    transaction: u64,
    first_status: i32,
    post_status: i32,
}

impl Slot {
    fn retired_status(&self, transaction: u64) -> Option<i32> {
        let retired = self
            .retired
            .as_ref()
            .filter(|retired| retired.transaction == transaction)?;
        Some(if retired.first_status != 0 {
            retired.first_status
        } else if retired.post_status != 0 {
            retired.post_status
        } else {
            -libc::ESTALE
        })
    }

    fn retire_completed_owner(&mut self) -> Result<(), i32> {
        let Some(owner) = self.owner.as_ref() else {
            return Err(-libc::ESTALE);
        };
        if self.root.is_some() {
            return Err(-libc::ESTALE);
        }
        if !owner.retirement_completed().map_err(|_| -libc::EBUSY)? {
            return Err(-libc::ESTALE);
        }
        let binding = self.binding.as_ref().ok_or(-libc::ESTALE)?;
        self.retired = Some(RetiredCallback {
            transaction: binding.native_transaction_generation,
            first_status: self.first_status,
            post_status: self.post_status,
        });
        self.owner.take();
        self.binding = None;
        self.failure = None;
        self.first_status = 0;
        self.post_status = 0;
        Ok(())
    }

    fn refuse(&mut self, cause: RamError) -> i32 {
        if self.failure.is_none() {
            self.first_status = match &cause {
                RamError::Native { status, .. } if *status != 0 => *status,
                _ => -libc::EPERM,
            };
            self.failure = Some(cause);
        }
        self.first_status
    }
}

/// Registers callbacks while permanently retaining the same userdata allocation.
///
/// # Errors
/// Refuses an incomplete matched SDK or preserves the actual registrar status.
/// Missing registration leaves checkpoint capture unavailable without a fallback.
pub(super) fn register(
    plugin_id: u64,
    runtime: Pin<&mut OwnedCallbackRuntimeState>,
) -> Result<(), i32> {
    // SAFETY: the static symbol name is valid for dlsym. No function pointer is
    // called before non-null resolution against the literal process-private ABI.
    let register = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"qemu_plugin_crucible_register_checkpoint_pager_v1".as_ptr(),
        )
    };
    if register.is_null() {
        return Ok(());
    }
    // SAFETY: the resolved check belongs to the same literal native SDK and may
    // only authenticate the currently active synchronous checkpoint invocation.
    let check = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"qemu_plugin_crucible_checkpoint_original_check_v1".as_ptr(),
        )
    };
    if check.is_null() {
        return Err(-libc::ENOSYS);
    }
    let root = root::RootApi::resolve()?;
    let provider = provider::ProviderApi::resolve()?;
    let reader = reader::ReaderApi::resolve()?;
    // SAFETY: both non-null symbols have exactly the native declarations bound
    // by the checkpoint receiving disposition SDK. No public process protocol
    // carries these functions or their userdata.
    let api = unsafe {
        NativeApi {
            register: std::mem::transmute::<*mut c_void, Register>(register),
            check: std::mem::transmute::<*mut c_void, Check>(check),
            root,
            provider,
            reader,
        }
    };
    // SAFETY: these inline assignments do not move the pinned allocation; the
    // installing owner has not yet published or executed these callbacks.
    let state = unsafe { runtime.get_unchecked_mut() };
    if state.owner_process != std::process::id()
        || state.plugin_id.is_some_and(|current| current != plugin_id)
    {
        return Err(-libc::ESTALE);
    }
    state.plugin_id = Some(plugin_id);
    state.checkpoint_api = Some(api);
    // Native may retain the pointer even if registration returns a refusal.
    state
        .checkpoint_registration_retained
        .store(true, Ordering::Release);
    let result = (api.register)(
        plugin_id,
        Some(callback),
        Some(callback),
        Some(callback),
        std::ptr::from_mut(state).cast(),
    );
    if result != 0 {
        return Err(result);
    }
    api.provider
        .register(plugin_id, std::ptr::from_mut(state).cast())?;
    api.reader
        .register(plugin_id, std::ptr::from_mut(state).cast())
}

extern "C" fn callback(
    plugin_id: u64,
    invocation: *const Invocation,
    output: *mut Status,
    userdata: *mut c_void,
) -> i32 {
    if invocation.is_null() || output.is_null() || userdata.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: the genuine native registrar retains this pinned allocation and
    // fixed invocation/output objects for the whole synchronous callback. The
    // native active original check below refuses foreign or returned invocations
    // before any capture effect; coordinates alone never construct an owner.
    let (runtime, call) = unsafe { (&*userdata.cast::<OwnedCallbackRuntimeState>(), *invocation) };
    let Some(api) = runtime.checkpoint_api else {
        return -libc::ENOSYS;
    };
    let initial = (api.check)(plugin_id);
    if initial != 0 && call.action != 3 {
        return initial;
    }
    if call.schema_version != 2
        || call.struct_size as usize != std::mem::size_of::<Invocation>()
        || !(1..=3).contains(&call.action)
        || (call.action != 3 && call.disposition != 0)
        || (call.action == 3 && !(1..=3).contains(&call.disposition))
        || call.native_transaction_generation == 0
        || call.process_generation != runtime.process_generation
        || runtime.plugin_id != Some(plugin_id)
        || runtime.owner_process != std::process::id()
        || call.reserved != 0
    {
        return -libc::EPROTO;
    }
    let Ok(mut slot) = runtime.checkpoint.try_lock() else {
        return -libc::EBUSY;
    };
    if let Some(status) = slot.retired_status(call.native_transaction_generation) {
        return status;
    }
    let Some(provider) = slot.provider.as_ref() else {
        return -libc::ENOKEY;
    };
    if !provider.matches_invocation(&call)
        || slot
            .binding
            .is_some_and(|binding| binding != call.owner_identity())
        || slot.owner.is_none()
    {
        return -libc::ESTALE;
    }
    if slot.failure.is_some() && call.action != 3 {
        slot.post_status = (api.check)(plugin_id);
        return slot.first_status;
    }
    if slot.binding.is_none() {
        if call.action != 1 {
            return -libc::EPERM;
        }
        let root = match api
            .root
            .acquire(plugin_id, userdata, call.native_transaction_generation)
        {
            Ok(root) => root,
            Err(cause) => return slot.refuse(cause),
        };
        // The provider already retains the whole service. Keep the native root
        // before attaching that same owner to the actual State cut.
        slot.root = Some(root);
        slot.binding = Some(call.owner_identity());
        let Slot { owner, root, .. } = &mut *slot;
        if let Some(Err(cause)) = owner.as_mut().map(|owner| owner.install_native_root(root)) {
            return slot.refuse(cause);
        }
    }
    let work = match slot.owner.as_mut() {
        Some(owner) if call.action == 1 => {
            owner.request().and_then(|()| owner.worker_acknowledged())
        }
        Some(owner) if call.action == 2 => owner.worker_acknowledged(),
        Some(owner) => owner.return_native_callback().map(|()| false),
        None => Err(RamError::Invariant(
            "checkpoint retained pager owner absent",
        )),
    };
    let post = (api.check)(plugin_id);
    slot.post_status = post;
    let settled = match work {
        Ok(settled) => settled,
        Err(cause) => return slot.refuse(cause),
    };
    if post != 0 {
        return slot.refuse(RamError::Native {
            operation: "checkpoint original postcut",
            status: post,
        });
    }
    let observed = Status {
        schema_version: 2,
        struct_size: std::mem::size_of::<Status>() as u32,
        action: call.action,
        // This reports the actual worker/page cut. Native reader enrollment
        // and final physical retirement remain independently required.
        state: if settled { 2 } else { 1 },
        native_transaction_generation: call.native_transaction_generation,
        plugin_owner_generation: slot.issued_owner,
        process_generation: call.process_generation,
        arena_generation: call.arena_generation,
        topology_generation: call.topology_generation,
        first_status: 0,
        post_status: 0,
    };
    // SAFETY: genuine native dispatch lends this writable fixed status object
    // until callback return. All negative paths above leave it unchanged.
    unsafe { output.write(observed) };
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disposed_transaction_reentry_keeps_its_first_and_independent_post() {
        let slot = Slot {
            retired: Some(RetiredCallback {
                transaction: 41,
                first_status: -libc::ECANCELED,
                post_status: -libc::ETIMEDOUT,
            }),
            ..Slot::default()
        };

        assert_eq!(slot.retired_status(41), Some(-libc::ECANCELED));
        assert_eq!(slot.retired_status(42), None);
        assert_eq!(slot.retired.as_ref().unwrap().post_status, -libc::ETIMEDOUT);
    }

    #[test]
    fn disposed_transaction_reentry_reports_post_when_no_first_refusal_exists() {
        let slot = Slot {
            retired: Some(RetiredCallback {
                transaction: 41,
                first_status: 0,
                post_status: -libc::ETIMEDOUT,
            }),
            ..Slot::default()
        };

        assert_eq!(slot.retired_status(41), Some(-libc::ETIMEDOUT));
    }

    #[test]
    fn successfully_disposed_transaction_cannot_reenter_from_the_same_generation() {
        let slot = Slot {
            retired: Some(RetiredCallback {
                transaction: 41,
                first_status: 0,
                post_status: 0,
            }),
            ..Slot::default()
        };

        assert_eq!(slot.retired_status(41), Some(-libc::ESTALE));
    }

    #[test]
    fn missing_physical_owner_cannot_erase_a_saved_callback_refusal() {
        let mut slot = Slot::default();
        slot.refuse(RamError::Native {
            operation: "checkpoint original postcut",
            status: -libc::ECANCELED,
        });
        slot.post_status = -libc::ETIMEDOUT;

        assert_eq!(slot.retire_completed_owner(), Err(-libc::ESTALE));

        assert!(slot.retired.is_none());
        assert!(slot.failure.is_some());
        assert_eq!(slot.first_status, -libc::ECANCELED);
        assert_eq!(slot.post_status, -libc::ETIMEDOUT);
    }

    #[test]
    fn original_refusal_keeps_its_exact_status_after_a_later_failure() {
        let mut slot = Slot::default();

        assert_eq!(
            slot.refuse(RamError::Native {
                operation: "checkpoint original postcut",
                status: -libc::ECANCELED,
            }),
            -libc::ECANCELED,
        );
        slot.post_status = -libc::ETIMEDOUT;
        assert_eq!(
            slot.refuse(RamError::Invariant("later custody refusal")),
            -libc::ECANCELED,
        );

        assert!(matches!(
            slot.failure,
            Some(RamError::Native {
                status,
                ..
            }) if status == -libc::ECANCELED,
        ));
        assert_eq!(slot.post_status, -libc::ETIMEDOUT);
        assert!(slot.owner.is_none());
    }
}
