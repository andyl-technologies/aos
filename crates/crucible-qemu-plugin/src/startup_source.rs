//! Retains the installing invocation's original Source and exact third owner.
//!
//! The sole production caller follows the actual Setup SCM receive. Native
//! installation scope and the matched shipped module must authenticate that route;
//! descriptor metadata, symbol resolution and caller scalars never issue it.
//! Failed acquisition keeps the same descriptor through process containment.
// SPDX-License-Identifier: GPL-2.0-only

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, IntoRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::Duration;

type Acquire = extern "C" fn(u64, i32) -> i32;
type Check = extern "C" fn(u64) -> i32;
type QuerySlice = extern "C" fn(u64, *mut u64) -> i32;
type RegistrationComplete = extern "C" fn(u64, i32) -> i32;

/// An unformatted refusal of the actual installing Source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StartupSourceError {
    /// The matched native implementation lacks a compulsory entry point.
    #[error("native startup Source entry point {symbol} is unavailable")]
    Unavailable {
        /// Literal required symbol.
        symbol: &'static str,
    },
    /// Native returned its original signed refusal without errno conversion.
    #[error("native startup Source refused ({status})")]
    NativeStatus {
        /// Exact nonzero status from the native installing owner.
        status: i32,
    },
    /// The retained owner cannot accept another action.
    #[error("startup Source owner is invalid: {reason}")]
    Ownership {
        /// Fixed rule that refused the action.
        reason: &'static str,
    },
}

#[derive(Clone, Copy)]
struct NativeStartupApi {
    acquire: Acquire,
    check: Check,
    query_slice: QuerySlice,
    registration_complete: RegistrationComplete,
}

/// Inline custody prepared before native acquisition, with no fallible birth.
pub(crate) struct InstallerStartupSource {
    plan: Option<OwnedFd>,
    plugin_id: u64,
    api: Option<NativeStartupApi>,
    #[cfg(test)]
    model_api: Option<NativeStartupApi>,
    first_status: AtomicI32,
    invalid_slice: AtomicBool,
    acquisition_attempted: bool,
    acquired: bool,
    registration_completed: bool,
}

impl InstallerStartupSource {
    // Only runtime's literal receive callsite constructs a production owner.
    pub(super) fn retain_received_plan(plugin_id: u64, plan: OwnedFd) -> Self {
        Self {
            plan: Some(plan),
            plugin_id,
            api: None,
            #[cfg(test)]
            model_api: None,
            first_status: AtomicI32::new(0),
            invalid_slice: AtomicBool::new(false),
            acquisition_attempted: false,
            acquired: false,
            registration_completed: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn inject_model(&mut self, model: test_support::InstallerStartupSourceModel) {
        assert!(!self.acquisition_attempted);
        assert!(self.model_api.is_none());
        self.model_api = Some(model.api);
    }

    #[cfg(test)]
    pub(crate) fn acquire_was_attempted_for_test(&self) -> bool {
        self.acquisition_attempted
    }

    pub(super) fn acquire(&mut self) -> Result<(), StartupSourceError> {
        if self.acquisition_attempted {
            return Err(StartupSourceError::Ownership {
                reason: "acquisition cannot be repeated",
            });
        }
        self.acquisition_attempted = true;
        #[cfg(not(test))]
        let api = resolve_api()?;
        #[cfg(test)]
        let api = self.model_api.take().map(Ok).unwrap_or_else(resolve_api)?;
        // Store the resolved table before the effect: any ambiguous refusal
        // remains terminal and cannot reopen this same retained invocation.
        self.api = Some(api);
        self.accept_status((api.acquire)(self.plugin_id, self.plan_fd()?.as_raw_fd()))?;
        self.acquired = true;
        self.check()
    }

    pub(crate) fn plan_fd(&self) -> Result<BorrowedFd<'_>, StartupSourceError> {
        self.plan
            .as_ref()
            .map(AsFd::as_fd)
            .ok_or(StartupSourceError::Ownership {
                reason: "the actual third descriptor is absent",
            })
    }

    pub(crate) fn check(&self) -> Result<(), StartupSourceError> {
        let api = self.live_api()?;
        self.accept_status((api.check)(self.plugin_id))
    }

    pub(crate) fn wait_slice(&self) -> Result<Duration, StartupSourceError> {
        let api = self.live_api()?;
        let mut bounded_ns = 0;
        self.accept_status((api.query_slice)(self.plugin_id, &mut bounded_ns))?;
        if bounded_ns == 0 {
            self.invalid_slice.store(true, Ordering::Release);
            return Err(StartupSourceError::Ownership {
                reason: "native returned an empty successful observation slice",
            });
        }
        Ok(Duration::from_nanos(bounded_ns))
    }

    pub(crate) fn registration_complete(&mut self) -> Result<(), StartupSourceError> {
        if self.registration_completed {
            return Err(StartupSourceError::Ownership {
                reason: "registration completion cannot be repeated",
            });
        }
        let api = self.live_api()?;
        // Completion records registration once. The native event/module and
        // actual plan owner remain retained; this neither grants Cleanup nor
        // completes the host's later first-prime operation.
        self.registration_completed = true;
        self.accept_status((api.registration_complete)(self.plugin_id, 0))
    }

    #[cfg(not(test))]
    pub(crate) fn retained_ram_error(error: StartupSourceError) -> crate::ram_error::RamError {
        match error {
            StartupSourceError::NativeStatus { status } => crate::ram_error::RamError::Native {
                operation: "original installer startup",
                status,
            },
            StartupSourceError::Unavailable { symbol } => {
                crate::ram_error::RamError::Invariant(symbol)
            }
            StartupSourceError::Ownership { reason } => {
                crate::ram_error::RamError::Invariant(reason)
            }
        }
    }

    fn live_api(&self) -> Result<NativeStartupApi, StartupSourceError> {
        let status = self.first_status.load(Ordering::Acquire);
        if status != 0 {
            return Err(StartupSourceError::NativeStatus { status });
        }
        if self.invalid_slice.load(Ordering::Acquire) {
            return Err(StartupSourceError::Ownership {
                reason: "native returned an empty successful observation slice",
            });
        }
        if !self.acquired {
            return Err(StartupSourceError::Ownership {
                reason: "original acquisition did not succeed",
            });
        }
        self.api.ok_or(StartupSourceError::Ownership {
            reason: "acquired native entry points are absent",
        })
    }

    fn accept_status(&self, status: i32) -> Result<(), StartupSourceError> {
        if status != 0 {
            let first =
                self.first_status
                    .compare_exchange(0, status, Ordering::AcqRel, Ordering::Acquire);
            return Err(StartupSourceError::NativeStatus {
                status: first.err().unwrap_or(status),
            });
        }
        Ok(())
    }
}

impl Drop for InstallerStartupSource {
    fn drop(&mut self) {
        // Initial acceptance or its refusal may retain a native borrower.
        // There is no disposal ABI or independently paid Cleanup cut yet.
        // Keep the actual owner to process exit rather than retrying a numeric
        // fd close or inferring retirement from registration completion.
        if let Some(plan) = self.plan.take() {
            let _retained_until_process_exit = plan.into_raw_fd();
        }
    }
}

fn resolve_api() -> Result<NativeStartupApi, StartupSourceError> {
    macro_rules! resolve {
        ($name:literal, $signature:ty) => {{
            // SAFETY: these GPL-private declarations are literal paired scalar
            // C APIs. Resolution does not attest the caller or issue Source.
            let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, $name.as_ptr()) };
            if symbol.is_null() {
                return Err(StartupSourceError::Unavailable {
                    symbol: $name.to_str().map_err(|_| StartupSourceError::Ownership {
                        reason: "required native symbol is not ASCII",
                    })?,
                });
            }
            // SAFETY: matched native code declares this exact C signature.
            unsafe { std::mem::transmute::<*mut libc::c_void, $signature>(symbol) }
        }};
    }

    Ok(NativeStartupApi {
        acquire: resolve!(c"qemu_plugin_crucible_startup_source_acquire_v1", Acquire),
        check: resolve!(c"qemu_plugin_crucible_startup_source_check_v1", Check),
        query_slice: resolve!(
            c"qemu_plugin_crucible_startup_source_query_slice_v1",
            QuerySlice
        ),
        registration_complete: resolve!(
            c"qemu_plugin_crucible_startup_source_registration_complete_v1",
            RegistrationComplete
        ),
    })
}

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests;
