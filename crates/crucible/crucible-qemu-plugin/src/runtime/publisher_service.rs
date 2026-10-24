//! Retains the Native Setup6 service in the genuinely paid pinned Runtime.
//!
//! Only Native accesses the canonical field. The actual component return closes
//! the service after its users return; Rust never infers physical consumption
//! from a negative status, reads the foreign-managed cell, or closes aliases.
// SPDX-License-Identifier: GPL-2.0-only

use std::cell::UnsafeCell;
use std::ffi::c_void;

use super::registration_owner::Owner;
use crate::ram_error::RamError;
use crate::startup_source::{InstallerStartupSource, StartupSourceError};

/// Matches the SDK's true opaque publisher service tag.
#[repr(C)]
struct ModuleService {
    _private: [u8; 0],
}

type Transfer = extern "C" fn(u64, *mut Owner, *mut *mut ModuleService) -> i32;

pub(super) struct PublisherService {
    holder: UnsafeCell<*mut ModuleService>,
    attempted: bool,
    first: Option<StartupSourceError>,
}

impl PublisherService {
    pub(super) const fn new() -> Self {
        Self {
            holder: UnsafeCell::new(std::ptr::null_mut()),
            attempted: false,
            first: None,
        }
    }

    /// Transfers the existing service once, retaining its actual output on error.
    ///
    /// # Errors
    /// Refuses unavailable SDK, repeated transfer, invalid Source or the actual
    /// Native move. The entire Runtime and exact foreign output remain retained.
    pub(super) fn transfer(
        &mut self,
        plugin_id: u64,
        owner: *mut Owner,
        installer: &InstallerStartupSource,
    ) -> Result<(), RamError> {
        if let Some(first) = self.first {
            return Err(InstallerStartupSource::retained_ram_error(first));
        }
        if self.attempted {
            return Err(RamError::Invariant(
                "publisher service transfer already attempted",
            ));
        }
        let transfer = resolve()?;
        self.attempted = true;
        let result =
            installer.transfer_publisher_service(|| transfer(plugin_id, owner, self.holder.get()));
        if let Err(source) = result {
            self.first = Some(source);
            return Err(InstallerStartupSource::retained_ram_error(source));
        }
        Ok(())
    }
}

fn resolve() -> Result<Transfer, RamError> {
    // SAFETY: this literal export is the matched GPL-private SDK declaration.
    let address = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"qemu_plugin_crucible_startup_setup_transfer_v4".as_ptr(),
        )
    };
    if address.is_null() {
        return Err(RamError::MissingSymbol(
            b"qemu_plugin_crucible_startup_setup_transfer_v4\0",
        ));
    }
    // SAFETY: the exact Native declaration uses these true opaque tags and ABI.
    Ok(unsafe { std::mem::transmute::<*mut c_void, Transfer>(address) })
}
