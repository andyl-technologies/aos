//! Borrows the matched Setup6 service without importing physical alias ownership.
//!
//! The process-private v4 output separates five/six base roles from the three
//! Native publisher roles. The retained Native child authenticates every view;
//! copied frame and descriptor facts do not create a Source or Runtime lender.
// SPDX-License-Identifier: GPL-2.0-only

use std::ffi::{CStr, c_void};
use std::os::fd::AsRawFd;
use std::sync::Mutex;

use crucible_qemu_protocol::publisher_subscription::{PUBLISHER_SETUP_FRAME_BYTES, PublisherSetup};

use super::{InstallerStartupSource, NativeBorrow, NativeSetupBorrow, StartupSourceError};

#[repr(C)]
struct Output {
    schema_version: u32,
    struct_size: u32,
    control_fd: i32,
    reserved: u32,
    frame: *const u8,
    frame_bytes: usize,
    descriptors: *const i32,
    descriptor_count: usize,
    publisher_descriptors: [i32; 3],
    reserved_tail: u32,
}

impl Output {
    fn empty() -> Self {
        Self {
            schema_version: 0,
            struct_size: 0,
            control_fd: -1,
            reserved: 0,
            frame: std::ptr::null(),
            frame_bytes: 0,
            descriptors: std::ptr::null(),
            descriptor_count: 0,
            publisher_descriptors: [-1; 3],
            reserved_tail: 0,
        }
    }
}

type Observe = extern "C" fn(u64, u32, usize, *mut Output) -> i32;

pub(super) struct PublisherBorrow {
    frame: [u8; PUBLISHER_SETUP_FRAME_BYTES],
    roles: [i32; 3],
    current: Observe,
    observation: Mutex<Observation>,
}

#[derive(Default)]
struct Observation {
    first: Option<StartupSourceError>,
    runtime_transfer_attempted: bool,
}

pub(super) fn selected() -> bool {
    // SAFETY: installation observes this borrowed environment value before
    // plugin worker creation; the literal is NUL-terminated.
    let value = unsafe { libc::getenv(c"QEMU_CRUCIBLE_PREEXEC_SETUP".as_ptr()) };
    !value.is_null() && unsafe { CStr::from_ptr(value) }.to_bytes() == b"6"
}

pub(super) fn acquire(source: &mut InstallerStartupSource) -> Result<(), StartupSourceError> {
    // Resolve both exact declarations before beginning any Native acquisition.
    let (borrow, current) = resolve()?;
    let mut output = Output::empty();
    source.accept_status(borrow(
        source.plugin_id,
        4,
        size_of::<Output>(),
        &mut output,
    ))?;
    source.acquired = true;

    // The Native creation holder already retains every role on a malformed
    // output or failed post. Validation never turns them into OwnedFd values.
    let retained = validate_output(&output, current)?;
    source.plan = Some(retained.role(2)?);
    source.native_setup = Some(retained);
    source.check()
}

impl PublisherBorrow {
    pub(super) fn setup(&self) -> Result<PublisherSetup, StartupSourceError> {
        PublisherSetup::decode(&self.frame).map_err(|_| malformed())
    }

    pub(super) fn begin_runtime_transfer(&self) -> Result<(), StartupSourceError> {
        let mut observation =
            self.observation
                .try_lock()
                .map_err(|_| StartupSourceError::Ownership {
                    reason: "publisher setup observation is already borrowed or poisoned",
                })?;
        if let Some(first) = observation.first {
            return Err(first);
        }
        if observation.runtime_transfer_attempted {
            return Err(StartupSourceError::Ownership {
                reason: "publisher service transfer cannot be repeated",
            });
        }
        observation.runtime_transfer_attempted = true;
        Ok(())
    }

    pub(super) fn check_current(
        &self,
        plugin_id: u64,
        retained: &NativeSetupBorrow,
    ) -> Result<(), StartupSourceError> {
        let mut observation =
            self.observation
                .try_lock()
                .map_err(|_| StartupSourceError::Ownership {
                    reason: "publisher setup observation is already borrowed or poisoned",
                })?;
        if let Some(first) = observation.first {
            return Err(first);
        }
        if observation.runtime_transfer_attempted {
            // The old v4 current API is installer-only. Once transfer is
            // attempted, the distinct durable Runtime field retains all debt;
            // the ordinary Source/runtime-purpose checks remain compulsory.
            return Ok(());
        }

        let mut output = Output::empty();
        let status = (self.current)(plugin_id, 4, size_of::<Output>(), &mut output);
        let result = if status != 0 {
            Err(StartupSourceError::NativeStatus { status })
        } else {
            validate_output(&output, self.current).and_then(|observed| {
                let publisher = observed.publisher.as_ref().ok_or_else(malformed)?;
                if observed.control.as_raw_fd() != retained.control.as_raw_fd()
                    || observed.roles.map(|role| role.map(|fd| fd.as_raw_fd()))
                        != retained.roles.map(|role| role.map(|fd| fd.as_raw_fd()))
                    || publisher.frame != self.frame
                    || publisher.roles != self.roles
                {
                    return Err(malformed());
                }
                Ok(())
            })
        };
        if let Err(first) = result {
            observation.first = Some(first);
        }
        result
    }
}

fn validate_output(
    output: &Output,
    current: Observe,
) -> Result<NativeSetupBorrow, StartupSourceError> {
    if output.schema_version != 4
        || output.struct_size as usize != size_of::<Output>()
        || output.reserved != 0
        || output.reserved_tail != 0
        || output.frame_bytes != PUBLISHER_SETUP_FRAME_BYTES
        || output.frame.is_null()
    {
        return Err(malformed());
    }
    // SAFETY: the matched Native ABI initializes this fixed immutable extent
    // only after authenticating its retained process-lifetime service owner.
    let frame = unsafe { *output.frame.cast::<[u8; PUBLISHER_SETUP_FRAME_BYTES]>() };
    let setup = PublisherSetup::decode(&frame).map_err(|_| malformed())?;
    if output.descriptor_count != 5 + usize::from(setup.device_digest_workspace.is_some()) {
        return Err(malformed());
    }

    // Base-role validation is shared without accepting a different wire frame.
    // The v3 shape here is private validation input, never a received edition.
    let mut retained = super::validate_output(&NativeBorrow {
        schema_version: 3,
        struct_size: size_of::<NativeBorrow>() as u32,
        control_fd: output.control_fd,
        reserved: 0,
        frame: frame.as_ptr(),
        frame_bytes: 61,
        descriptors: output.descriptors,
        descriptor_count: output.descriptor_count,
    })?;
    for (index, descriptor) in output.publisher_descriptors.iter().copied().enumerate() {
        if descriptor < 0
            || descriptor == output.control_fd
            || retained
                .roles
                .iter()
                .flatten()
                .any(|role| role.as_raw_fd() == descriptor)
            || output.publisher_descriptors[..index].contains(&descriptor)
        {
            return Err(malformed());
        }
    }
    retained.publisher = Some(PublisherBorrow {
        frame,
        roles: output.publisher_descriptors,
        current,
        observation: Mutex::new(Observation::default()),
    });
    Ok(retained)
}

fn malformed() -> StartupSourceError {
    StartupSourceError::Ownership {
        reason: "native publisher setup view differs",
    }
}

fn resolve() -> Result<(Observe, Observe), StartupSourceError> {
    macro_rules! entry {
        ($name:literal, $label:literal) => {{
            // SAFETY: the frozen GPL-private SDK declares this exact scalar
            // and fixed-output ABI. Symbol presence grants no ownership.
            let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, $name.as_ptr()) };
            if address.is_null() {
                return Err(StartupSourceError::Unavailable { symbol: $label });
            }
            // SAFETY: the matched export has the Observe signature above.
            unsafe { std::mem::transmute::<*mut c_void, Observe>(address) }
        }};
    }
    Ok((
        entry!(
            c"qemu_plugin_crucible_startup_setup_borrow_v4",
            "qemu_plugin_crucible_startup_setup_borrow_v4"
        ),
        entry!(
            c"qemu_plugin_crucible_startup_setup_current_v4",
            "qemu_plugin_crucible_startup_setup_current_v4"
        ),
    ))
}

#[cfg(test)]
mod tests;
