//! Retains the actual family publication serial and its complete child span.
//!
//! A successful Source current lends typed preparation only. Global exposure,
//! callback enrollment and worker entry still require their actual Native owner.
//! Negative post results retain born outputs until identity return succeeds.
// SPDX-License-Identifier: GPL-2.0-only

use super::super::live_callbacks::{LiveVcpuTimeCallbackError, LiveVcpuTimeCallbackState};
use super::abi::Storage;
use crate::StartupSourceError;
use std::alloc::Layout;
use std::ffi::c_void;

/// Names the exact opaque Source publication lifetime, without a body projection.
#[repr(C)]
struct Loan {
    _private: [u8; 0],
}

/// Names the actual vCPU-initialization preparation cut from the owning SDK.
/// This is a native argument, never a process-protocol field or credit.
const VCPU_INIT_FAMILY: libc::c_int = 1;

#[derive(Clone, Copy)]
struct Api {
    begin: extern "C" fn(u64, *mut Storage, libc::c_int, *mut *mut Loan, *mut u64) -> i32,
    current: extern "C" fn(u64, *mut Loan, u64, *mut *mut c_void, *mut usize, *mut usize) -> i32,
    return_loan: extern "C" fn(u64, *mut *mut Loan, u64) -> i32,
}

impl Api {
    fn resolve() -> Result<Self, LiveVcpuTimeCallbackError> {
        macro_rules! entry {
            ($name:literal, $ty:ty) => {{
                // SAFETY: the immutable owning SDK specifies this exact GPL ABI.
                let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, $name.as_ptr()) };
                if address.is_null() {
                    return Err(super::source_error(StartupSourceError::Unavailable {
                        symbol: $name.to_str().map_err(|_| {
                            super::source_error(StartupSourceError::Ownership {
                                reason: "publication symbol is not ASCII",
                            })
                        })?,
                    }));
                }
                // SAFETY: these are the three actual annotated SDK signatures.
                unsafe { std::mem::transmute::<*mut c_void, $ty>(address) }
            }};
        }
        Ok(Self {
            begin: entry!(
                c"qemu_plugin_crucible_callback_child_publication_begin_v1",
                extern "C" fn(u64, *mut Storage, libc::c_int, *mut *mut Loan, *mut u64) -> i32
            ),
            current: entry!(
                c"qemu_plugin_crucible_callback_child_publication_current_v1",
                extern "C" fn(u64, *mut Loan, u64, *mut *mut c_void, *mut usize, *mut usize) -> i32
            ),
            return_loan: entry!(
                c"qemu_plugin_crucible_callback_child_publication_return_v1",
                extern "C" fn(u64, *mut *mut Loan, u64) -> i32
            ),
        })
    }
}

#[derive(Default)]
struct Span {
    address: *mut c_void,
    bytes: usize,
    alignment: usize,
}

/// Lives inline in the original priced Runtime; no extra holder allocation exists.
/// A retained projection, serial or span blocks physical child return.
pub(super) struct Publication {
    api: Option<Api>,
    id: u64,
    loan: *mut Loan,
    serial: u64,
    span: Span,
    uncertain: bool,
}

impl Publication {
    pub(super) const fn new() -> Self {
        Self {
            api: None,
            id: 0,
            loan: std::ptr::null_mut(),
            serial: 0,
            span: Span {
                address: std::ptr::null_mut(),
                bytes: 0,
                alignment: 0,
            },
            uncertain: false,
        }
    }

    pub(super) fn retained(&self) -> bool {
        !self.loan.is_null() || self.serial != 0 || !self.span.address.is_null() || self.uncertain
    }

    /// Prepares the complete typed child only under the genuine entered serial.
    ///
    /// # Errors
    /// Retains negative begin/current outputs, rejects mismatched geometry and
    /// preserves the first preparation failure over independent return failure.
    ///
    /// # Safety
    /// The Source child is initialized and transferred into its pinned Runtime.
    /// Preparation stores no reference beyond this loan. An address can escape
    /// only into the actual Source component constructor, whose distinct nominal
    /// child-owner dependency is retained before its born output and post.
    pub(super) unsafe fn prepare<F>(
        &mut self,
        id: u64,
        child: *mut Storage,
        preparation: F,
    ) -> Result<(), LiveVcpuTimeCallbackError>
    where
        F: FnOnce(&mut LiveVcpuTimeCallbackState) -> Result<(), LiveVcpuTimeCallbackError>,
    {
        let api = Api::resolve()?;
        self.prepare_using(id, child, preparation, api)
    }

    fn prepare_using<F>(
        &mut self,
        id: u64,
        child: *mut Storage,
        preparation: F,
        api: Api,
    ) -> Result<(), LiveVcpuTimeCallbackError>
    where
        F: FnOnce(&mut LiveVcpuTimeCallbackState) -> Result<(), LiveVcpuTimeCallbackError>,
    {
        if self.retained() {
            return Err(super::status_error(-libc::EBUSY));
        }
        self.api = Some(api);
        self.id = id;
        // These inline output cells survive negative preparation and postcuts.
        let begun = (api.begin)(
            id,
            child,
            VCPU_INIT_FAMILY,
            &mut self.loan,
            &mut self.serial,
        );
        let first = if begun != 0 {
            Err(super::status_error(begun))
        } else if self.loan.is_null() || self.serial == 0 {
            self.uncertain = true;
            Err(super::status_error(-libc::EPROTO))
        } else {
            let status = (api.current)(
                id,
                self.loan,
                self.serial,
                &mut self.span.address,
                &mut self.span.bytes,
                &mut self.span.alignment,
            );
            // Span facts are retained before status; negative post is no typed
            // permission, and returning it cannot discard its physical debt.
            if status != 0 {
                Err(super::status_error(status))
            } else {
                let layout = Layout::new::<LiveVcpuTimeCallbackState>();
                if self.span.address.is_null()
                    || self.span.bytes != layout.size()
                    || self.span.alignment != layout.align()
                    || (self.span.address as usize) % layout.align() != 0
                {
                    Err(super::status_error(-libc::EPROTO))
                } else {
                    let typed = unsafe {
                        // SAFETY: actual successful current lends this full initialized
                        // span until return. No other private child access is active;
                        // the closure cannot return a borrowed typed projection.
                        &mut *self.span.address.cast::<LiveVcpuTimeCallbackState>()
                    };
                    preparation(typed)
                }
            }
        };
        let returned = self.identity_return();
        first.and(returned)
    }

    /// Returns the same serial without manufacturing callback termination.
    ///
    /// # Errors
    /// Retains the pair and span when disposition refuses or is ambiguous.
    pub(super) fn identity_return(&mut self) -> Result<(), LiveVcpuTimeCallbackError> {
        if !self.retained() {
            return Ok(());
        }
        let Some(api) = self.api else {
            return Err(super::status_error(-libc::EPROTO));
        };
        if self.loan.is_null() || self.serial == 0 || self.uncertain {
            return Err(super::status_error(-libc::EPROTO));
        }
        let original = self.loan;
        let status = (api.return_loan)(self.id, &mut self.loan, self.serial);
        if status != 0 {
            if self.loan != original {
                // This violates refusal-preserves-pair. Save the original debt
                // and close reuse; it is never presented as renewed permission.
                self.loan = original;
                self.uncertain = true;
            }
            return Err(super::status_error(status));
        }
        if !self.loan.is_null() {
            return Err(super::status_error(-libc::EPROTO));
        }
        self.serial = 0;
        self.span = Span::default();
        Ok(())
    }
}

#[cfg(test)]
mod tests;
