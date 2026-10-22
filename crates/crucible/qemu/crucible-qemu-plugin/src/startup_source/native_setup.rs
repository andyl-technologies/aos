//! Borrows the selected preinit frame and roles from their sole native owner.
//!
//! The actual installing module/id authenticates this private ABI. Native owns
//! the accepted carrier and aliases until process retirement. The Rust keeper
//! retains their exact views across Hello, mapping and runtime installation;
//! it never receives the already-consumed frame again or acquires alias ownership.
// SPDX-License-Identifier: GPL-2.0-only

use std::ffi::{CStr, c_void};
use std::os::fd::BorrowedFd;

use super::{InstallerStartupSource, SetupDescriptor, StartupSourceError, resolve_api};

mod publisher;

#[repr(C)]
struct NativeBorrow {
    schema_version: u32,
    struct_size: u32,
    control_fd: i32,
    reserved: u32,
    frame: *const u8,
    frame_bytes: usize,
    descriptors: *const i32,
    descriptor_count: usize,
}

type Borrow = extern "C" fn(u64, *mut NativeBorrow) -> i32;

/// Keeps the exact selected frame and authenticated process-lifetime role views.
pub(crate) struct NativeSetupBorrow {
    frame: [u8; 61],
    control: BorrowedFd<'static>,
    roles: [Option<BorrowedFd<'static>>; 6],
    publisher: Option<publisher::PublisherBorrow>,
}

impl NativeSetupBorrow {
    #[cfg(test)]
    pub(super) fn from_model(
        frame: &[u8; 61],
        control: i32,
        roles: &[i32; 5],
    ) -> Result<Self, StartupSourceError> {
        validate_output(&NativeBorrow {
            schema_version: 3,
            struct_size: size_of::<NativeBorrow>() as u32,
            control_fd: control,
            reserved: 0,
            frame: frame.as_ptr(),
            frame_bytes: frame.len(),
            descriptors: roles.as_ptr(),
            descriptor_count: roles.len(),
        })
    }

    pub(crate) fn frame(&self) -> &[u8; 61] {
        &self.frame
    }

    pub(crate) fn control(&self) -> BorrowedFd<'static> {
        self.control
    }

    pub(crate) fn role(&self, index: usize) -> Result<SetupDescriptor, StartupSourceError> {
        self.roles
            .get(index)
            .copied()
            .flatten()
            .map(SetupDescriptor::Native)
            .ok_or(StartupSourceError::Ownership {
                reason: "native setup role is absent",
            })
    }

    pub(crate) fn publisher_setup(
        &self,
    ) -> Result<
        Option<crucible_qemu_protocol::publisher_subscription::PublisherSetup>,
        StartupSourceError,
    > {
        self.publisher
            .as_ref()
            .map(publisher::PublisherBorrow::setup)
            .transpose()
    }

    fn begin_publisher_transfer(&self) -> Result<(), StartupSourceError> {
        self.publisher
            .as_ref()
            .ok_or(StartupSourceError::Ownership {
                reason: "native publisher service is absent",
            })?
            .begin_runtime_transfer()
    }

    pub(crate) fn has_publisher(&self) -> bool {
        self.publisher.is_some()
    }

    pub(super) fn check_current(&self, plugin_id: u64) -> Result<(), StartupSourceError> {
        if let Some(publisher) = self.publisher.as_ref() {
            publisher.check_current(plugin_id, self)
        } else {
            Ok(())
        }
    }

    pub(crate) fn has_workspace(&self) -> bool {
        self.roles[5].is_some()
    }
}

/// Reads only the selected native edition, without allocating an environment copy.
///
/// # Errors
/// Refuses every present selector other than the exact matched edition.
pub(crate) fn selected() -> Result<bool, StartupSourceError> {
    // SAFETY: the literal is NUL-terminated; installation precedes any plugin
    // worker mutation of process environment. The returned bytes are borrowed.
    let value = unsafe { libc::getenv(c"QEMU_CRUCIBLE_PREEXEC_SETUP".as_ptr()) };
    if value.is_null() {
        return Ok(false);
    }
    // SAFETY: getenv returned the process environment's NUL-terminated value.
    if !matches!(unsafe { CStr::from_ptr(value) }.to_bytes(), b"5" | b"6") {
        return Err(StartupSourceError::Ownership {
            reason: "native setup edition differs",
        });
    }
    Ok(true)
}

impl InstallerStartupSource {
    /// Prepares inline custody before the native once-owner acquisition.
    pub(crate) fn retain_native_setup(plugin_id: u64) -> Self {
        Self {
            control_reservation: Default::default(),
            runtime_reservation: Default::default(),
            setup_mapping: Default::default(),
            setup_exchange: Default::default(),
            plan: None,
            native_setup: None,
            plugin_id,
            api: None,
            #[cfg(test)]
            model_api: None,
            #[cfg(test)]
            model_setup: None,
            first_status: std::sync::atomic::AtomicI32::new(0),
            invalid_slice: std::sync::atomic::AtomicBool::new(false),
            acquisition_attempted: false,
            acquired: false,
            registration_completed: false,
        }
    }

    /// Acquires and retains the same native carrier before Hello/HelloAck.
    ///
    /// # Errors
    /// Preserves native original refusal, missing ABI, repeated acquisition or
    /// malformed output. Neither an error nor Drop retires native alias custody.
    pub(crate) fn acquire_native_setup(&mut self) -> Result<(), StartupSourceError> {
        if self.acquisition_attempted {
            return Err(StartupSourceError::Ownership {
                reason: "acquisition cannot be repeated",
            });
        }
        self.acquisition_attempted = true;
        #[cfg(test)]
        if let Some(api) = self.model_api.take() {
            self.api = Some(api);
            let setup = self
                .model_setup
                .as_ref()
                .ok_or(StartupSourceError::Ownership {
                    reason: "explicit modeled native setup custody is absent",
                })?;
            self.accept_status((api.acquire)(self.plugin_id, setup.plan_fd()))?;
            let retained = setup.borrow()?;
            self.acquired = true;
            self.plan = Some(retained.role(2)?);
            self.native_setup = Some(retained);
            return self.check();
        }
        self.api = Some(resolve_api()?);
        if publisher::selected() {
            return publisher::acquire(self);
        }
        let borrow = resolve_borrow()?;
        let mut output = NativeBorrow {
            schema_version: 0,
            struct_size: 0,
            control_fd: -1,
            reserved: 0,
            frame: std::ptr::null(),
            frame_bytes: 0,
            descriptors: std::ptr::null(),
            descriptor_count: 0,
        };
        self.accept_status(borrow(self.plugin_id, &mut output))?;
        // Native already retains every role on a malformed/failed postcut.
        // Never construct an owning descriptor or retry this same acquisition.
        self.complete_native_setup_acquisition(validate_output(&output))
    }

    fn complete_native_setup_acquisition(
        &mut self,
        retained: Result<NativeSetupBorrow, StartupSourceError>,
    ) -> Result<(), StartupSourceError> {
        let retained = retained?;
        self.plan = Some(retained.role(2)?);
        self.native_setup = Some(retained);
        // A successful Native status alone must not leave Source current after
        // its compulsory view is rejected. Native still retains all alias debt.
        self.acquired = true;
        self.check()
    }

    /// Moves only the already retained Native service into a paid Runtime field.
    ///
    /// # Errors
    /// Preserves missing/repeated custody, the Native move's first refusal and
    /// the same retained installing/runtime-purpose observations. A failed move
    /// never permits the old installer view to be borrowed or retried again.
    pub(crate) fn transfer_publisher_service(
        &self,
        transfer: impl FnOnce() -> i32,
    ) -> Result<(), StartupSourceError> {
        self.check_runtime_installation()?;
        self.native_setup()?.begin_publisher_transfer()?;
        let first = self.accept_status(transfer());
        let post = self.check_runtime_installation();
        first?;
        post
    }

    pub(crate) fn retained_native_setup(&self) -> Option<&NativeSetupBorrow> {
        self.native_setup.as_ref()
    }

    pub(crate) fn native_setup(&self) -> Result<&NativeSetupBorrow, StartupSourceError> {
        self.check()?;
        self.native_setup
            .as_ref()
            .ok_or(StartupSourceError::Ownership {
                reason: "native setup keeper is absent",
            })
    }
}

fn validate_output(output: &NativeBorrow) -> Result<NativeSetupBorrow, StartupSourceError> {
    if output.schema_version != 3
        || output.struct_size as usize != size_of::<NativeBorrow>()
        || output.reserved != 0
        || output.control_fd < 0
        || output.frame_bytes != 61
        || !matches!(output.descriptor_count, 5 | 6)
        || output.frame.is_null()
        || output.descriptors.is_null()
        || !output.descriptors.is_aligned()
    {
        return Err(StartupSourceError::Ownership {
            reason: "native setup borrow shape differs",
        });
    }
    // SAFETY: the exact matched native ABI publishes these initialized fixed
    // extents only after authenticating its retained process-lifetime owner.
    let frame: [u8; 61] = unsafe { *output.frame.cast::<[u8; 61]>() };
    let descriptors = unsafe {
        // SAFETY: the same accepted ABI guarantees descriptor_count initialized ints.
        std::slice::from_raw_parts(output.descriptors, output.descriptor_count)
    };
    if descriptors
        .iter()
        .enumerate()
        .any(|(index, fd)| *fd < 0 || *fd == output.control_fd || descriptors[..index].contains(fd))
    {
        return Err(StartupSourceError::Ownership {
            reason: "native setup alias roster differs",
        });
    }
    let mut roles = [None; 6];
    for (index, fd) in descriptors.iter().copied().enumerate() {
        // SAFETY: the sole native owner retains this exact alias until process
        // retirement. No Rust view closes, replaces, duplicates or owns it.
        roles[index] = Some(unsafe { BorrowedFd::borrow_raw(fd) });
    }
    // SAFETY: the same native owner retains the authenticated control endpoint.
    let control = unsafe { BorrowedFd::borrow_raw(output.control_fd) };
    Ok(NativeSetupBorrow {
        frame,
        control,
        roles,
        publisher: None,
    })
}

fn resolve_borrow() -> Result<Borrow, StartupSourceError> {
    // SAFETY: the literal name belongs to the frozen matched GPL-private SDK.
    let address = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"qemu_plugin_crucible_startup_setup_borrow_v3".as_ptr(),
        )
    };
    if address.is_null() {
        return Err(StartupSourceError::Unavailable {
            symbol: "qemu_plugin_crucible_startup_setup_borrow_v3",
        });
    }
    // SAFETY: the resolved native export has this exact frozen C declaration.
    Ok(unsafe { std::mem::transmute::<*mut c_void, Borrow>(address) })
}

#[cfg(test)]
mod tests;
