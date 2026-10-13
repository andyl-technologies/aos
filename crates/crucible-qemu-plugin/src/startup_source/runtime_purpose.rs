//! Reserves the three actual runtime allocations from the retained installing native Source.
//!
//! Request geometry describes configured allocations; only the native containing
//! holder can admit them. A failed postcut retains the debit and closes retries.
//! Neither this holder nor registration completion issues later capture authority.
// SPDX-License-Identifier: GPL-2.0-only

use std::alloc::Layout;
use std::ffi::c_void;

use super::{InstallerStartupSource, StartupSourceError};

#[repr(C)]
pub(super) struct RuntimePurpose {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct Request {
    pub(super) extent_bytes: u64,
    pub(super) alignment_bytes: u64,
    pub(super) birth_count: u64,
}

type Reserve = extern "C" fn(u64, *const Request, *mut *mut RuntimePurpose) -> i32;
type Check = extern "C" fn(u64, *mut RuntimePurpose) -> i32;
type Interrupt = extern "C" fn(u64, *mut RuntimePurpose, i32) -> i32;
type ObserveInterrupt = extern "C" fn(u64, *mut RuntimePurpose, *mut InterruptStatus) -> i32;

/// Authenticated facts from the native owner's single terminal interruption.
#[repr(C)]
#[derive(Default)]
struct InterruptStatus {
    schema_version: u32,
    struct_size: u32,
    attempted: u32,
    result: i32,
    saved_errno: i32,
    first_status: i32,
    post_status: i32,
    reserved: u32,
}

/// Retains a native-owned purpose inline in the same installing Source.
///
/// The address is never dereferenced by Rust. Every native use authenticates the
/// actual current installing invocation and its retained containing holder.
#[derive(Default)]
pub(super) struct RuntimeReservation {
    attempted: bool,
    purpose_address: usize,
    check: Option<Check>,
    interrupt: Option<Interrupt>,
    observe_interrupt: Option<ObserveInterrupt>,
}

impl InstallerStartupSource {
    /// Admits and rechecks all three configured runtime allocations before birth.
    ///
    /// # Errors
    /// Preserves the original Source refusal, missing SDK, repeated attempt or
    /// actual native reserve/check refusal. No failed debit is refunded or retried.
    pub(crate) fn reserve_runtime_allocations(
        &mut self,
        layouts: [Layout; 3],
    ) -> Result<(), StartupSourceError> {
        self.check_installer_control_purpose()?;
        if self.runtime_reservation.attempted {
            return Err(StartupSourceError::Ownership {
                reason: "runtime allocation reservation cannot be repeated",
            });
        }
        #[cfg(test)]
        if self.model_setup.is_some() {
            return self.reserve_runtime_allocations_using(
                layouts,
                super::test_support::reserve_runtime,
                super::test_support::check_runtime,
            );
        }
        let (reserve, check, interrupt, observe_interrupt) = resolve()?;
        self.runtime_reservation.interrupt = Some(interrupt);
        self.runtime_reservation.observe_interrupt = Some(observe_interrupt);
        self.reserve_runtime_allocations_using(layouts, reserve, check)
    }

    fn reserve_runtime_allocations_using(
        &mut self,
        layouts: [Layout; 3],
        reserve: Reserve,
        check: Check,
    ) -> Result<(), StartupSourceError> {
        self.check()?;
        if self.runtime_reservation.attempted {
            return Err(StartupSourceError::Ownership {
                reason: "runtime allocation reservation cannot be repeated",
            });
        }
        let requests = layouts.map(|layout| {
            let extent_bytes =
                u64::try_from(layout.size()).map_err(|_| StartupSourceError::Ownership {
                    reason: "runtime allocation extent is not representable",
                })?;
            let alignment_bytes =
                u64::try_from(layout.align()).map_err(|_| StartupSourceError::Ownership {
                    reason: "runtime allocation alignment is not representable",
                })?;
            Ok::<Request, StartupSourceError>(Request {
                extent_bytes,
                alignment_bytes,
                birth_count: 1,
            })
        });
        let [runtime, quiescence, workers] = requests;
        let requests = [runtime?, quiescence?, workers?];
        self.runtime_reservation.attempted = true;
        self.runtime_reservation.check = Some(check);

        let mut purpose = std::ptr::null_mut();
        self.accept_status(reserve(self.plugin_id, requests.as_ptr(), &mut purpose))?;
        if purpose.is_null() {
            return Err(StartupSourceError::Ownership {
                reason: "native runtime reservation returned no retained holder",
            });
        }
        // Retain the genuine returned identity before the separate prebirth cut.
        self.runtime_reservation.purpose_address = purpose as usize;
        self.check_runtime_allocations()
    }

    /// Lends both genuine installing holders to the sole RAM actor exchange.
    ///
    /// The caller records every native output before returning its signed status.
    /// A failed independent postcut retains those effects and their same Source.
    ///
    /// # Errors
    /// Refuses absent or stale purpose custody, exchange failure, or an expired
    /// installing original. The exchange creates no later operation allowance.
    pub(crate) fn with_ram_actor_purposes(
        &self,
        exchange: impl FnOnce(u64, *mut c_void, *mut c_void) -> i32,
    ) -> Result<(), StartupSourceError> {
        self.check_runtime_allocations()?;
        self.with_control_holder(|control| {
            exchange(
                self.plugin_id,
                control,
                self.runtime_reservation.purpose_address as *mut c_void,
            )
        })?;
        self.check_runtime_allocations()
    }

    /// Requests terminal interruption through the same native runtime holder.
    ///
    /// This identity-only cut remains available after startup refusal or expiry.
    /// Native preserves its first/post causes separately from the shutdown result.
    /// A successful syscall permits a real reader join; it does not retire any
    /// callback, allocation, descriptor, module or containing purpose.
    ///
    /// # Errors
    /// Refuses absent custody, unavailable terminal SDK, rejected observation or
    /// malformed journal facts. No refusal permits Rust to interrupt its borrow.
    pub(crate) fn interrupt_runtime_reader(&self) -> Result<bool, StartupSourceError> {
        #[cfg(test)]
        if let Some(model) = self.model_setup.as_ref() {
            // This fixture owns its endpoint. It exercises real reader return
            // without pretending that its status model is native authority.
            model
                .shutdown_control()
                .map_err(|error| StartupSourceError::NativeStatus {
                    status: -error.raw_os_error().unwrap_or(libc::EIO),
                })?;
            return Ok(true);
        }
        let reservation = &self.runtime_reservation;
        if reservation.purpose_address == 0 {
            return Err(StartupSourceError::Ownership {
                reason: "runtime interruption holder is absent",
            });
        }
        let interrupt = reservation.interrupt.ok_or(StartupSourceError::Ownership {
            reason: "runtime interruption entry point is absent",
        })?;
        let observe = reservation
            .observe_interrupt
            .ok_or(StartupSourceError::Ownership {
                reason: "runtime interruption observer is absent",
            })?;
        let purpose = reservation.purpose_address as *mut RuntimePurpose;
        // The initiating signed cause is returned even when shutdown succeeds.
        // Observe the authentic journal after every return, including negatives.
        let _initiating_cause = interrupt(self.plugin_id, purpose, -libc::ECANCELED);
        let mut status = InterruptStatus::default();
        let observation = observe(self.plugin_id, purpose, &mut status);
        if observation != 0 {
            return Err(StartupSourceError::NativeStatus {
                status: observation,
            });
        }
        if status.schema_version != 2
            || status.struct_size as usize != size_of::<InterruptStatus>()
            || status.reserved != 0
            || status.attempted > 1
            || (status.result == 0 && status.saved_errno != 0)
        {
            return Err(StartupSourceError::Ownership {
                reason: "runtime interruption journal shape differs",
            });
        }
        Ok(status.attempted == 1 && status.result == 0)
    }

    /// Rechecks the same retained purpose immediately before allocation.
    ///
    /// # Errors
    /// Refuses missing custody, completed original or actual native prebirth cut.
    pub(crate) fn check_runtime_allocations(&self) -> Result<(), StartupSourceError> {
        self.live_api()?;
        let check = self
            .runtime_reservation
            .check
            .ok_or(StartupSourceError::Ownership {
                reason: "runtime reservation checker is absent",
            })?;
        if self.runtime_reservation.purpose_address == 0 {
            return Err(StartupSourceError::Ownership {
                reason: "runtime reservation holder is absent",
            });
        }
        self.accept_status(check(
            self.plugin_id,
            self.runtime_reservation.purpose_address as *mut RuntimePurpose,
        ))
    }
}

fn resolve() -> Result<(Reserve, Check, Interrupt, ObserveInterrupt), StartupSourceError> {
    macro_rules! resolve {
        ($name:literal, $signature:ty) => {{
            // SAFETY: the literal symbol belongs to the frozen GPL-private SDK.
            // Resolution alone issues no allocation or containing authority.
            let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, $name.as_ptr()) };
            if address.is_null() {
                return Err(StartupSourceError::Unavailable {
                    symbol: $name.to_str().map_err(|_| StartupSourceError::Ownership {
                        reason: "runtime reservation symbol is not ASCII",
                    })?,
                });
            }
            // SAFETY: this exact non-null symbol has the bound C declaration.
            unsafe { std::mem::transmute::<*mut c_void, $signature>(address) }
        }};
    }
    Ok((
        resolve!(c"qemu_plugin_crucible_startup_runtime_reserve_v2", Reserve),
        resolve!(c"qemu_plugin_crucible_startup_runtime_check_v2", Check),
        resolve!(
            c"qemu_plugin_crucible_startup_runtime_interrupt_v2",
            Interrupt
        ),
        resolve!(
            c"qemu_plugin_crucible_startup_runtime_interrupt_observe_v2",
            ObserveInterrupt
        ),
    ))
}

#[cfg(test)]
mod tests;
