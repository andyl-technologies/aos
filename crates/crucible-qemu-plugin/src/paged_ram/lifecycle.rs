//! Installs native RAM metadata admission and coherent resident fork handoff.
//!
//! The immutable root observer is composed with the existing native lifecycle
//! fence. Cold mappings additionally require the live pager authority owner;
//! this resident handoff never advertises or substitutes that ownership.

use crate::ram_error::RamError;
use std::os::raw::{c_int, c_void};
use std::sync::OnceLock;

use crate::PluginArgs;

type RequestAccess = extern "C" fn() -> c_int;
type SetBudget = extern "C" fn(u64) -> c_int;
type RebindCapture = extern "C" fn() -> c_int;
type LifecycleCallback = extern "C" fn(u32, u64, *mut c_void) -> c_int;
type RegisterLifecycle = extern "C" fn(u64, Option<LifecycleCallback>, *mut c_void) -> c_int;

static NATIVE: OnceLock<NativeLifecycle> = OnceLock::new();

#[derive(Clone, Copy)]
struct NativeLifecycle {
    request: RequestAccess,
    budget: SetBudget,
    rebind: RebindCapture,
    register: RegisterLifecycle,
}

impl NativeLifecycle {
    fn resolve() -> Result<Self, RamError> {
        // SAFETY: these symbols are the matching GPL-private native declarations.
        // Callback pointers stay inside this process and no Apache ABI is exposed.
        unsafe {
            Ok(Self {
                request: std::mem::transmute::<*mut c_void, RequestAccess>(symbol(
                    b"qemu_plugin_crucible_ram_paging_request_v1\0",
                )?),
                budget: std::mem::transmute::<*mut c_void, SetBudget>(symbol(
                    b"qemu_plugin_crucible_ram_set_metadata_budget_v1\0",
                )?),
                rebind: std::mem::transmute::<*mut c_void, RebindCapture>(symbol(
                    b"qemu_plugin_crucible_ram_capture_rebind_v1\0",
                )?),
                register: std::mem::transmute::<*mut c_void, RegisterLifecycle>(symbol(
                    b"qemu_plugin_crucible_register_ram_lifecycle\0",
                )?),
            })
        }
    }
}

/// Installs the actual native allowance and resident lifecycle owner.
///
/// # Errors
/// Returns an error for missing admission, unavailable native APIs, duplicate
/// installation, or rejected registration. Managed cold mappings require their
/// separately qualified manager before this function can accept its endpoint.
pub(crate) fn install(args: &PluginArgs, plugin_id: u64) -> Result<(), RamError> {
    #[cfg(feature = "kernel-swap-measurement")]
    super::research_resident::install(args)?;

    let budget = args.ram_metadata_budget().ok_or(RamError::Invariant(
        "RAM metadata allowance was not admitted",
    ))?;
    let native = NativeLifecycle::resolve()?;
    let status = (native.request)();
    if status != 0 {
        return Err(RamError::Native {
            operation: "audited native RAM access admission rejected",
            status,
        });
    }
    let status = (native.budget)(budget);
    if status != 0 {
        return Err(RamError::Native {
            operation: "native RAM metadata admission rejected",
            status,
        });
    }
    super::controller::install(args)?;
    if args.ram_control().is_some() {
        super::fork::install(plugin_id)?;
    }
    NATIVE
        .set(native)
        .map_err(|_| RamError::Invariant("RAM lifecycle owner is already installed"))?;
    let context = NATIVE.get().ok_or(RamError::Invariant(
        "RAM lifecycle owner publication failed",
    ))? as *const NativeLifecycle as *mut c_void;
    let status = (native.register)(plugin_id, Some(lifecycle), context);
    if status != 0 {
        return Err(RamError::Native {
            operation: "native RAM lifecycle registration rejected",
            status,
        });
    }
    Ok(())
}

extern "C" fn lifecycle(operation: u32, generation: u64, _opaque: *mut c_void) -> c_int {
    if generation == 0 {
        return -libc::EINVAL;
    }
    #[cfg(feature = "kernel-swap-measurement")]
    if super::research_resident::selected() {
        return super::research_resident::refuse_transition();
    }

    let result = match operation {
        1 => super::controller::prepare_fork()
            .and_then(|()| crate::ram_fingerprint::prepare_fork())
            .and_then(|()| super::fork::capture_parent(generation)),
        2 => super::controller::final_seal().and_then(|()| crate::ram_fingerprint::final_seal()),
        3 => super::fork::resume_parent()
            .and_then(|()| crate::ram_fingerprint::resume_parent())
            .and_then(|()| super::controller::resume_parent()),
        4 => {
            let Some(native) = NATIVE.get() else {
                return -libc::ENOSYS;
            };
            let status = (native.rebind)();
            if status != 0 {
                return status;
            }
            super::fork::rebind_child(generation)
                .and_then(|()| crate::ram_fingerprint::rebind_child())
        }
        5 => super::fork::resume_parent()
            .and_then(|()| crate::ram_fingerprint::abort_fork())
            .and_then(|()| super::controller::resume_parent()),
        _ => return -libc::EINVAL,
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            crate::ram_diagnostics::emit(crate::ram_diagnostics::RamDiagnostic::LifecycleFailed(
                &error,
            ));
            -libc::EIO
        }
    }
}

pub(super) fn symbol(name: &'static [u8]) -> Result<*mut c_void, RamError> {
    // SAFETY: every caller supplies a static NUL-terminated symbol name. The
    // handle selects the current QEMU process and no loaded-library owner escapes.
    let pointer = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr().cast()) };
    if pointer.is_null() {
        return Err(RamError::MissingSymbol(name));
    }
    Ok(pointer)
}
