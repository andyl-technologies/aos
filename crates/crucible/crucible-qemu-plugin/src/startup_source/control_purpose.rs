//! Retains the genuine seven-role native control purpose before managed births.
//!
//! Only configured controller/pager types produce the request. The matched
//! native installing Source compares it with its retained final artifact and
//! once-carrier purpose. Rust keeps the native-owned identity inline; it neither
//! allocates a second holder nor refunds the purpose on failure or Drop.
// SPDX-License-Identifier: GPL-2.0-only

use std::ffi::c_void;

use super::{InstallerStartupSource, StartupSourceError};

#[repr(C)]
pub(super) struct ControlPurpose {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Request {
    pub(super) extent_bytes: u64,
    pub(super) alignment_bytes: u64,
    pub(super) birth_count: u64,
}

type Reserve = extern "C" fn(u64, *const Request, *mut *mut ControlPurpose) -> i32;
type Check = extern "C" fn(u64, *mut ControlPurpose) -> i32;

/// Keeps the same native-owned control holder and first refusal without a birth.
#[derive(Default)]
pub(super) struct ControlReservation {
    attempted: bool,
    purpose_address: usize,
    check: Option<Check>,
    first_refusal: Option<StartupSourceError>,
}

impl InstallerStartupSource {
    /// Admits the configured seven controls before the separate three runtime allocations.
    ///
    /// # Errors
    /// Preserves original Source, missing SDK, repeated-attempt, configured
    /// geometry and actual native reserve/check refusals. Failed attempts close
    /// retries while the same Source retains any native custody or debit.
    pub(crate) fn reserve_installer_control_purpose(&mut self) -> Result<(), StartupSourceError> {
        self.begin_control_reservation()?;
        #[cfg(not(test))]
        let api = resolve();
        #[cfg(test)]
        let api = if self.model_setup.is_some() {
            Ok((
                super::test_support::reserve_control as Reserve,
                super::test_support::check_control as Check,
            ))
        } else {
            resolve()
        };
        let result = api.and_then(|(reserve, check)| self.reserve_controls(reserve, check));
        self.retain_control_result(result)
    }

    fn begin_control_reservation(&mut self) -> Result<(), StartupSourceError> {
        if let Some(error) = self.control_reservation.first_refusal {
            return Err(error);
        }
        self.check()?;
        if self.control_reservation.attempted {
            return Err(StartupSourceError::Ownership {
                reason: "fixed control reservation cannot be repeated",
            });
        }
        self.control_reservation.attempted = true;
        Ok(())
    }

    fn reserve_controls(
        &mut self,
        reserve: Reserve,
        check: Check,
    ) -> Result<(), StartupSourceError> {
        let requests = configured_requests()?;
        self.control_reservation.check = Some(check);
        let mut purpose = std::ptr::null_mut();
        self.accept_status(reserve(self.plugin_id, requests.as_ptr(), &mut purpose))?;
        if purpose.is_null() {
            return Err(StartupSourceError::Ownership {
                reason: "native fixed control reservation returned no retained holder",
            });
        }
        // Keep the returned identity before its separate prebirth check. The
        // native Source owns this address until physical process retirement.
        self.control_reservation.purpose_address = purpose as usize;
        self.check_installer_control_purpose()
    }

    fn retain_control_result(
        &mut self,
        result: Result<(), StartupSourceError>,
    ) -> Result<(), StartupSourceError> {
        if let Err(error) = result {
            self.control_reservation.first_refusal.get_or_insert(error);
        }
        result
    }

    /// Lends the actual retained control holder only during installing exchange.
    ///
    /// # Errors
    /// Preserves the original holder refusal, the exchange's raw status, or the
    /// independent installing postcut. No pointer is returned as a donor.
    pub(super) fn with_control_holder(
        &self,
        exchange: impl FnOnce(*mut c_void) -> i32,
    ) -> Result<(), StartupSourceError> {
        self.check_installer_control_purpose()?;
        let status = exchange(self.control_reservation.purpose_address as *mut c_void);
        self.accept_status(status)?;
        self.check_installer_control_purpose()
    }

    /// Rechecks the exact retained holder before actual fixed-control birth.
    ///
    /// # Errors
    /// Preserves the first attempt refusal or rejects missing custody, expired
    /// original, foreign/completed invocation or native holder mismatch.
    pub(crate) fn check_installer_control_purpose(&self) -> Result<(), StartupSourceError> {
        if let Some(error) = self.control_reservation.first_refusal {
            return Err(error);
        }
        self.check()?;
        let check = self
            .control_reservation
            .check
            .ok_or(StartupSourceError::Ownership {
                reason: "fixed control reservation checker is absent",
            })?;
        if self.control_reservation.purpose_address == 0 {
            return Err(StartupSourceError::Ownership {
                reason: "fixed control reservation holder is absent",
            });
        }
        self.accept_status(check(
            self.plugin_id,
            self.control_reservation.purpose_address as *mut ControlPurpose,
        ))
    }
}

fn configured_requests() -> Result<[Request; 7], StartupSourceError> {
    let controls = crate::paged_ram::controller::installer_control_requests().map_err(|_| {
        StartupSourceError::Ownership {
            reason: "configured fixed control layouts are not representable",
        }
    })?;
    controls
        .required_bytes()
        .map_err(|_| StartupSourceError::Ownership {
            reason: "configured fixed control roster is not canonical",
        })?;
    Ok(controls.allocations().map(|allocation| Request {
        extent_bytes: allocation.size(),
        alignment_bytes: allocation.alignment(),
        birth_count: allocation.count(),
    }))
}

fn resolve() -> Result<(Reserve, Check), StartupSourceError> {
    macro_rules! resolve {
        ($name:literal, $signature:ty) => {{
            // SAFETY: the literal symbol and signature are the matched frozen
            // GPL-private SDK. Resolution alone issues no credit or authority.
            let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, $name.as_ptr()) };
            if address.is_null() {
                return Err(StartupSourceError::Unavailable {
                    symbol: $name.to_str().map_err(|_| StartupSourceError::Ownership {
                        reason: "fixed control symbol is not ASCII",
                    })?,
                });
            }
            // SAFETY: the matched native declaration has this exact signature.
            unsafe { std::mem::transmute::<*mut c_void, $signature>(address) }
        }};
    }
    Ok((
        resolve!(c"qemu_plugin_crucible_startup_control_reserve_v2", Reserve),
        resolve!(c"qemu_plugin_crucible_startup_control_check_v2", Check),
    ))
}

#[cfg(test)]
mod tests;
