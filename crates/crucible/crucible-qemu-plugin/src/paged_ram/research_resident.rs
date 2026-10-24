//! Retains the experimental request until the real admission observer settles.
//!
//! This GPL-private state consumes the original TOTAL metadata once through the
//! existing native grant. It does not issue a host role or establish event
//! identity. A matching native implementation and genuinely admitted host launch
//! remain prerequisites; missing symbols fail before the ordinary install path.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::os::raw::{c_int, c_void};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::{PluginArgs, ram_error::RamError};

type Request = extern "C" fn(u32, u64, u64, u64, c_int) -> c_int;
type Grant = extern "C" fn(u64, u64, *mut u64) -> c_int;
type RefuseTransition = extern "C" fn() -> c_int;

const PENDING: u8 = 0;
const APPLIED: u8 = 1;
const FAILED: u8 = 2;

static RESEARCH: OnceLock<ResearchNative> = OnceLock::new();

struct ResearchNative {
    total_metadata: u64,
    full_resident: u64,
    full_backing: u64,
    grant: Grant,
    refuse_transition: RefuseTransition,
    state: AtomicU8,
}

impl ResearchNative {
    fn refuse_transition(&self) -> c_int {
        self.state.store(FAILED, Ordering::Release);
        (self.refuse_transition)()
    }

    fn apply(&self, generation: u64, logical_bytes: u64) -> Result<u64, RamError> {
        self.state
            .compare_exchange(PENDING, APPLIED, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| RamError::Invariant("research metadata grant is already settled"))?;

        if logical_bytes == 0
            || logical_bytes > self.full_resident
            || logical_bytes > self.full_backing
        {
            self.state.store(FAILED, Ordering::Release);
            return Err(RamError::Native {
                operation: "research resident FULL RAM admission",
                status: -libc::ENOSPC,
            });
        }

        let mut allowance = 0;
        let status = (self.grant)(generation, self.total_metadata, &mut allowance);
        if status != 0 {
            self.state.store(FAILED, Ordering::Release);
            return Err(RamError::Native {
                operation: "research resident original metadata admission",
                status,
            });
        }
        if allowance == 0 {
            self.state.store(FAILED, Ordering::Release);
            return Err(RamError::MetadataAdmission {
                required: 1,
                admitted: 0,
            });
        }
        Ok(allowance)
    }
}

pub(super) fn install(args: &PluginArgs) -> Result<(), RamError> {
    let Some(request_args) = args.research_resident() else {
        return Ok(());
    };
    let total_metadata = args.ram_metadata_budget().ok_or(RamError::Invariant(
        "research resident original metadata is absent",
    ))?;
    let resources = args.ram_resources().ok_or(RamError::Invariant(
        "research resident original FULL RAM projection is absent",
    ))?;
    if RESEARCH.get().is_some() {
        return Err(RamError::Invariant(
            "research resident request is already installed",
        ));
    }

    // SAFETY: matching GPL-private native functions have these exact signatures.
    // Their pointers never cross the socket/shared-memory process boundary.
    let (request, grant, refuse_transition) = unsafe {
        (
            std::mem::transmute::<*mut c_void, Request>(super::lifecycle::symbol(
                b"qemu_plugin_crucible_ram_research_resident_request_v1\0",
            )?),
            std::mem::transmute::<*mut c_void, Grant>(super::lifecycle::symbol(
                b"qemu_plugin_crucible_ram_admission_grant_v1\0",
            )?),
            std::mem::transmute::<*mut c_void, RefuseTransition>(super::lifecycle::symbol(
                b"qemu_plugin_crucible_ram_research_resident_refuse_transition_v1\0",
            )?),
        )
    };
    RESEARCH
        .set(ResearchNative {
            total_metadata,
            full_resident: resources.resident_peak_bytes,
            full_backing: resources.backing_peak_bytes,
            grant,
            refuse_transition,
            state: AtomicU8::new(PENDING),
        })
        .map_err(|_| RamError::Invariant("research resident request publication conflicted"))?;

    let status = request(
        1,
        total_metadata,
        resources.resident_peak_bytes,
        resources.backing_peak_bytes,
        request_args.cancellation_fd,
    );
    if status != 0 {
        if let Some(owner) = RESEARCH.get() {
            owner.state.store(FAILED, Ordering::Release);
        }
        return Err(RamError::Native {
            operation: "research resident classification request",
            status,
        });
    }
    Ok(())
}

/// Applies TOTAL metadata once; absence alone permits the ordinary observer.
pub(crate) fn apply_native_grant(
    generation: u64,
    logical_bytes: u64,
) -> Result<Option<u64>, RamError> {
    RESEARCH
        .get()
        .map(|owner| owner.apply(generation, logical_bytes))
        .transpose()
}

pub(super) fn selected() -> bool {
    RESEARCH.get().is_some()
}

pub(super) fn refuse_transition() -> c_int {
    RESEARCH
        .get()
        .map_or(-libc::ENOTSUP, ResearchNative::refuse_transition)
}

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" fn grant(generation: u64, total: u64, allowance: *mut u64) -> c_int {
        assert_eq!(generation, 7);
        assert_eq!(total, 1024);
        // SAFETY: the actual caller lends its own initialized synchronous output.
        unsafe { *allowance = 512 };
        0
    }

    extern "C" fn refuse(_: u64, _: u64, _: *mut u64) -> c_int {
        -libc::ECANCELED
    }

    extern "C" fn unsupported_transition() -> c_int {
        -libc::ENOTSUP
    }

    #[test]
    fn original_total_is_consumed_once_without_allowance_reinterpretation() {
        let owner = ResearchNative {
            total_metadata: 1024,
            full_resident: 4096,
            full_backing: 4096,
            grant,
            refuse_transition: unsupported_transition,
            state: AtomicU8::new(PENDING),
        };
        assert_eq!(owner.apply(7, 4096).unwrap(), 512);
        assert!(owner.apply(7, 4096).is_err());
        assert_eq!(owner.state.load(Ordering::Acquire), APPLIED);
    }

    #[test]
    fn native_refusal_is_terminal_on_second_request() {
        let owner = ResearchNative {
            total_metadata: 1024,
            full_resident: 4096,
            full_backing: 4096,
            grant: refuse,
            refuse_transition: unsupported_transition,
            state: AtomicU8::new(PENDING),
        };
        assert!(
            matches!(owner.apply(7, 4096), Err(RamError::Native { status, .. }) if status == -libc::ECANCELED)
        );
        assert_eq!(owner.state.load(Ordering::Acquire), FAILED);
        assert!(owner.apply(7, 4096).is_err());
    }

    #[test]
    fn actual_logical_bytes_must_fit_both_original_full_extents() {
        static GRANT_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

        extern "C" fn observe(_: u64, _: u64, _: *mut u64) -> c_int {
            GRANT_CALLS.fetch_add(1, Ordering::Relaxed);
            -libc::EIO
        }

        for (resident, backing, logical) in
            [(4095, 4096, 4096), (4096, 4095, 4096), (4096, 4096, 0)]
        {
            let owner = ResearchNative {
                total_metadata: 1024,
                full_resident: resident,
                full_backing: backing,
                grant: observe,
                refuse_transition: unsupported_transition,
                state: AtomicU8::new(PENDING),
            };

            assert!(
                matches!(owner.apply(7, logical), Err(RamError::Native { status, .. }) if status == -libc::ENOSPC)
            );
            assert_eq!(owner.state.load(Ordering::Acquire), FAILED);
            assert!(owner.apply(7, logical).is_err());
        }
        assert_eq!(GRANT_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn unsupported_transition_preserves_refusal_and_closes_applied_grant() {
        let owner = ResearchNative {
            total_metadata: 1024,
            full_resident: 4096,
            full_backing: 4096,
            grant,
            refuse_transition: unsupported_transition,
            state: AtomicU8::new(PENDING),
        };
        assert_eq!(owner.apply(7, 4096).unwrap(), 512);

        assert_eq!(owner.refuse_transition(), -libc::ENOTSUP);
        assert_eq!(owner.state.load(Ordering::Acquire), FAILED);
        assert!(owner.apply(7, 4096).is_err());
        assert_eq!(owner.refuse_transition(), -libc::ENOTSUP);
    }
}
