//! Reserves the actual configured callback roster from the retained native Source.
//!
//! Request geometry describes configured allocations; only the native containing
//! holder can admit them. A failed postcut retains the debit and closes retries.
//! Neither this holder nor registration completion issues later capture authority.
// SPDX-License-Identifier: GPL-2.0-only

use std::alloc::Layout;
use std::ffi::c_void;

use super::{InstallerStartupSource, StartupSourceError};

/// Names the retained opaque Native Runtime containing owner.
#[repr(C)]
pub(crate) struct RuntimePurpose {
    _private: [u8; 0],
}

/// Names the once-issued opaque command payload claim from the closed roster.
#[repr(C)]
pub(crate) struct CommandClaim {
    _private: [u8; 0],
}

/// Names the separately issued once-only callback-child allocation claim.
#[repr(C)]
pub(crate) struct CallbackChildClaim {
    _private: [u8; 0],
}

/// Names the separately issued once-only full worker-control allocation claim.
#[repr(C)]
pub(crate) struct WorkerClaim {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct Request {
    pub(super) extent_bytes: u64,
    pub(super) alignment_bytes: u64,
    pub(super) birth_count: u64,
    pub(super) role: u32,
    pub(super) reserved: u32,
}

/// Source copies these three allocation facts into its role-less native array.
/// The V4 caller span has role/reserved fields; those are not stored row credit.
#[repr(C)]
struct StoredAllocationRequest {
    _extent_bytes: u64,
    _alignment_bytes: u64,
    _birth_count: u64,
}

const ROLE_ORDINARY: u32 = 0;
const ROLE_COMMAND_BRIDGE: u32 = 1;
const ROLE_CALLBACK_CHILD: u32 = 2;
const ROLE_WORKER_CONTROL: u32 = 3;

type Reserve = extern "C" fn(
    u64,
    *const Request,
    usize,
    *mut *mut RuntimePurpose,
    *mut *mut CommandClaim,
    *mut *mut CallbackChildClaim,
    *mut *mut WorkerClaim,
) -> i32;
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
/// The address is never dereferenced by Rust. Pure lifetime checks authenticate
/// retained containing custody; managed births also check installing admission.
#[derive(Default)]
pub(super) struct RuntimeReservation {
    attempted: bool,
    purpose_address: usize,
    command_claim_address: usize,
    callback_child_claim_address: usize,
    worker_claim_address: usize,
    check: Option<Check>,
    interrupt: Option<Interrupt>,
    observe_interrupt: Option<ObserveInterrupt>,
}

impl InstallerStartupSource {
    /// Admits and rechecks the immutable configured allocation span before birth.
    ///
    /// # Errors
    /// Preserves the original Source refusal, missing SDK, repeated attempt or
    /// actual native reserve/check refusal. No failed debit is refunded or retried.
    pub(crate) fn reserve_runtime_allocations(
        &mut self,
        configured: &crate::runtime::prebirth::RuntimeAllocationRequests,
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
                configured.layouts(),
                super::test_support::reserve_runtime,
                super::test_support::check_runtime,
            );
        }
        let (reserve, check, interrupt, observe_interrupt) = resolve()?;
        self.runtime_reservation.interrupt = Some(interrupt);
        self.runtime_reservation.observe_interrupt = Some(observe_interrupt);
        self.reserve_runtime_allocations_using(configured.layouts(), reserve, check)
    }

    fn reserve_runtime_allocations_using(
        &mut self,
        layouts: &[Layout],
        reserve: Reserve,
        check: Check,
    ) -> Result<(), StartupSourceError> {
        self.check()?;
        if self.runtime_reservation.attempted {
            return Err(StartupSourceError::Ownership {
                reason: "runtime allocation reservation cannot be repeated",
            });
        }
        if layouts.is_empty() || layouts.len() > crate::runtime::prebirth::MAX_RUNTIME_ALLOCATIONS {
            return Err(StartupSourceError::Ownership {
                reason: "configured runtime request span is empty or exceeds its typed producer",
            });
        }
        let mut requests = [Request {
            extent_bytes: 0,
            alignment_bytes: 0,
            birth_count: 0,
            role: 0,
            reserved: 0,
        }; crate::runtime::prebirth::MAX_RUNTIME_ALLOCATIONS];
        let mut payload_bytes = 0_u64;
        for (index, (request, layout)) in requests.iter_mut().zip(layouts).enumerate() {
            let extent_bytes =
                u64::try_from(layout.size()).map_err(|_| StartupSourceError::Ownership {
                    reason: "runtime allocation extent is not representable",
                })?;
            let alignment_bytes =
                u64::try_from(layout.align()).map_err(|_| StartupSourceError::Ownership {
                    reason: "runtime allocation alignment is not representable",
                })?;
            if extent_bytes == 0 {
                return Err(StartupSourceError::Ownership {
                    reason: "runtime request includes an absent allocation",
                });
            }
            payload_bytes =
                payload_bytes
                    .checked_add(extent_bytes)
                    .ok_or(StartupSourceError::Ownership {
                        reason: "runtime requested allocation sum overflowed",
                    })?;
            *request = Request {
                extent_bytes,
                alignment_bytes,
                birth_count: 1,
                role: if index == crate::runtime::prebirth::COMMAND_BRIDGE_ALLOCATION {
                    ROLE_COMMAND_BRIDGE
                } else if index == crate::runtime::prebirth::CALLBACK_CHILD_ALLOCATION {
                    ROLE_CALLBACK_CHILD
                } else if index == crate::runtime::prebirth::WORKER_CONTROL_ALLOCATION {
                    ROLE_WORKER_CONTROL
                } else {
                    ROLE_ORDINARY
                },
                reserved: 0,
            };
        }
        // Source stores the role-less native allocation row and charges its
        // actual array once. The role-bearing input row is a different wire/FFI geometry;
        // this check rejects arithmetic overflow and supplies no array credit.
        let stored_bytes = layouts
            .len()
            .checked_mul(size_of::<StoredAllocationRequest>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(StartupSourceError::Ownership {
                reason: "runtime stored roster extent overflowed",
            })?;
        payload_bytes
            .checked_add(stored_bytes)
            .ok_or(StartupSourceError::Ownership {
                reason: "runtime payload and stored roster sum overflowed",
            })?;
        self.runtime_reservation.attempted = true;
        self.runtime_reservation.check = Some(check);

        let mut purpose = std::ptr::null_mut();
        let mut claim = std::ptr::null_mut();
        let mut child_claim = std::ptr::null_mut();
        let mut worker_claim = std::ptr::null_mut();
        let result = reserve(
            self.plugin_id,
            requests.as_ptr(),
            layouts.len(),
            &mut purpose,
            &mut claim,
            &mut child_claim,
            &mut worker_claim,
        );
        if !purpose.is_null() {
            // V6 publishes the real Source-owned holder and separate claims before debit, allocator
            // and independent post failures. Save it before the signed result.
            self.runtime_reservation.purpose_address = purpose as usize;
        }
        if !claim.is_null() {
            self.runtime_reservation.command_claim_address = claim as usize;
        }
        if !child_claim.is_null() {
            self.runtime_reservation.callback_child_claim_address = child_claim as usize;
        }
        if !worker_claim.is_null() {
            self.runtime_reservation.worker_claim_address = worker_claim as usize;
        }
        self.accept_status(result)?;
        if purpose.is_null()
            || claim.is_null()
            || child_claim.is_null()
            || (layouts.len() > crate::runtime::prebirth::WORKER_CONTROL_ALLOCATION)
                != !worker_claim.is_null()
        {
            return Err(StartupSourceError::Ownership {
                reason: "native runtime reservation returned no retained holder",
            });
        }
        self.check_runtime_allocations()
    }

    /// Borrows the once-issued command claim and containing Runtime before birth.
    ///
    /// # Errors
    /// Refuses absent claim, installing admission or same-bank custody. This
    /// does not create a claim from its copied row geometry.
    pub(crate) fn command_storage_material(
        &self,
    ) -> Result<(u64, *mut RuntimePurpose, *mut CommandClaim), StartupSourceError> {
        self.check_runtime_installation()?;
        if self.runtime_reservation.command_claim_address == 0 {
            return Err(StartupSourceError::Ownership {
                reason: "command storage claim is absent",
            });
        }
        Ok((
            self.plugin_id,
            self.runtime_reservation.purpose_address as *mut RuntimePurpose,
            self.runtime_reservation.command_claim_address as *mut CommandClaim,
        ))
    }

    /// Borrows the distinct actual callback-child claim before its one birth.
    ///
    /// # Errors
    /// Refuses missing installing admission, retained account or child claim.
    /// Neither the row index nor layout facts can create this opaque owner.
    pub(crate) fn callback_child_material(
        &self,
    ) -> Result<(u64, *mut RuntimePurpose, *mut CallbackChildClaim), StartupSourceError> {
        self.check_runtime_installation()?;
        if self.runtime_reservation.callback_child_claim_address == 0 {
            return Err(StartupSourceError::Ownership {
                reason: "callback-child storage claim is absent",
            });
        }
        Ok((
            self.plugin_id,
            self.runtime_reservation.purpose_address as *mut RuntimePurpose,
            self.runtime_reservation.callback_child_claim_address as *mut CallbackChildClaim,
        ))
    }

    /// Borrows the actual once-issued optional worker claim before creation.
    ///
    /// # Errors
    /// Refuses an absent configured worker, expired installer or missing custody.
    pub(crate) fn fingerprint_worker_material(
        &self,
    ) -> Result<(u64, *mut RuntimePurpose, *mut WorkerClaim), StartupSourceError> {
        self.check_runtime_installation()?;
        if self.runtime_reservation.worker_claim_address == 0 {
            return Err(StartupSourceError::Ownership {
                reason: "fingerprint worker allocation claim is absent",
            });
        }
        Ok((
            self.plugin_id,
            self.runtime_reservation.purpose_address as *mut RuntimePurpose,
            self.runtime_reservation.worker_claim_address as *mut WorkerClaim,
        ))
    }

    // The mapping transfer consumes this actual retained same-bank holder; the
    // caller still checks installing admission independently before any effect.
    pub(super) fn setup_mapping_runtime_purpose(
        &self,
    ) -> Result<*mut RuntimePurpose, StartupSourceError> {
        self.check_runtime_allocations()?;
        Ok(self.runtime_reservation.purpose_address as *mut RuntimePurpose)
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

    /// Checks the genuine installing invocation and retained storage separately.
    ///
    /// # Errors
    /// Preserves an expired, completed or refused installing Source before the
    /// pure accounting query. This creates no new clock or operation allowance.
    pub(crate) fn check_runtime_installation(&self) -> Result<(), StartupSourceError> {
        self.check_installer_control_purpose()?;
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

    /// Rechecks the same retained Source-owned storage without querying a clock.
    ///
    /// # Errors
    /// Refuses a prior installing Source failure, missing custody, or an actual
    /// native retained-accounting mismatch. Temporal entry remains independent.
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
        resolve!(c"qemu_plugin_crucible_startup_runtime_reserve_v6", Reserve),
        resolve!(c"qemu_plugin_crucible_startup_runtime_check_v3", Check),
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
