//! Loads the real RAM observer into resident native fault conformance fixtures.
//!
//! This explicitly selected test artifact uses the production observer,
//! admission, dirty capture and prepared mutation cache. Each ordinary coherent
//! root observation is independently checked by QEMU's C BLAKE3 full oracle.
//! It provides no managed pager, process IPC runtime or guest fault substitute.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::os::raw::{c_char, c_int, c_void};
use std::sync::OnceLock;

use crate::ram_diagnostics::{RamDiagnostic, emit};
use crate::ram_error::RamError;
use crate::{QemuPluginId, QemuPluginInfo};

type SetBudget = extern "C" fn(u64) -> c_int;
type FullRoot = extern "C" fn(u32, u64, *mut u8, *mut u64) -> c_int;

static ORACLE: OnceLock<FullRoot> = OnceLock::new();

/// Installs the production RAM observer and an independent native oracle.
///
/// # Safety
/// QEMU must supply an aligned, initialized `info`, a live NUL-terminated target
/// name, and `argc` initialized `argv` entries containing live NUL-terminated
/// strings. It must retain these foreign loans throughout the callback.
/// Argument shape checks cannot prove pointer validity or extend their lifetime.
#[unsafe(export_name = "qemu_plugin_install")]
pub(crate) unsafe extern "C" fn install(
    _id: QemuPluginId,
    info: *const QemuPluginInfo,
    argc: c_int,
    argv: *mut *mut c_char,
) -> c_int {
    let result = std::panic::catch_unwind(|| -> Result<(), RamError> {
        // SAFETY: QEMU lends live info and NUL-terminated argv entries according
        // to the same ABI contract as the production install entrypoint.
        let argument = unsafe { crate::abi::conformance_install_argument(info, argc, argv) }?;
        let budget = parse_budget(&argument)?;
        crate::ram_fingerprint::preflight()?;
        // SAFETY: these private native symbols have the exact synchronous
        // declarations above and retain none of the Rust output loans.
        let (set_budget, full_root) = unsafe {
            (
                std::mem::transmute::<*mut c_void, SetBudget>(symbol(
                    b"qemu_plugin_crucible_ram_set_metadata_budget_v1\0",
                )?),
                std::mem::transmute::<*mut c_void, FullRoot>(symbol(
                    b"qemu_plugin_crucible_ram_full_root_v2\0",
                )?),
            )
        };
        let status = set_budget(budget);
        if status != 0 {
            return Err(RamError::Native {
                operation: "set conformance metadata allowance",
                status,
            });
        }
        ORACLE
            .set(full_root)
            .map_err(|_| "native conformance oracle already installed")?;
        crate::ram_fingerprint::install()
    });
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => {
            emit(RamDiagnostic::ConformanceInstallFailed(&error));
            -1
        }
        Err(_) => -1,
    }
}

fn parse_budget(argument: &str) -> Result<u64, RamError> {
    let value = argument
        .strip_prefix("ram_metadata_budget=")
        .ok_or("conformance observer requires ram_metadata_budget")?;
    let budget = value.parse::<u64>()?;
    if budget == 0 || budget.to_string() != value {
        return Err(RamError::Invariant(
            "conformance RAM allowance must be a positive canonical integer",
        ));
    }
    Ok(budget)
}

pub(crate) extern "C" fn observe_root(
    scope: u32,
    owner_token: u64,
    output: *mut u8,
    logical_bytes: *mut u64,
    cleanup: *mut crate::ram_fingerprint::CaptureClose,
) -> c_int {
    let status =
        crate::ram_fingerprint::observe_root(scope, owner_token, output, logical_bytes, cleanup);
    if status != 0 || owner_token != 0 {
        return status;
    }
    let result = std::panic::catch_unwind(|| verify_root(scope, output, logical_bytes));
    let status = result.unwrap_or(-libc::EFAULT);
    if status != 0 {
        // SAFETY: the successful production observer validated both writable
        // output loans, which remain lent until this callback returns.
        unsafe {
            std::ptr::write_bytes(output, 0, 32);
            logical_bytes.write(0);
        }
    }
    status
}

fn verify_root(scope: u32, output: *mut u8, logical_bytes: *mut u64) -> c_int {
    let Some(oracle) = ORACLE.get() else {
        return -libc::ENODEV;
    };
    let mut expected = [0_u8; 32];
    let mut expected_bytes = 0_u64;
    let status = oracle(scope, 0, expected.as_mut_ptr(), &mut expected_bytes);
    if status != 0 {
        return status;
    }
    // SAFETY: the successful production observer validated QEMU's output loans,
    // which remain live under its retained writer fence through this callback.
    let matches = unsafe {
        std::slice::from_raw_parts(output, 32) == expected && logical_bytes.read() == expected_bytes
    };
    if !matches {
        emit(RamDiagnostic::OracleFailed { scope });
        return -libc::EPROTO;
    }
    emit(RamDiagnostic::OraclePassed { scope });
    0
}

fn symbol(name: &'static [u8]) -> Result<*mut c_void, RamError> {
    // SAFETY: each caller supplies a static NUL-terminated native symbol name.
    let pointer = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr().cast()) };
    if pointer.is_null() {
        return Err(RamError::MissingSymbol(name));
    }
    Ok(pointer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conformance_requires_explicit_canonical_admission() {
        assert_eq!(
            parse_budget("ram_metadata_budget=67108864").unwrap(),
            67108864
        );
        for argument in [
            "",
            "ram_metadata_budget=0",
            "ram_metadata_budget=01",
            "ram_metadata_budget=+1",
            "ram_metadata_budget=1,extra=1",
        ] {
            assert!(parse_budget(argument).is_err());
        }
    }
}
