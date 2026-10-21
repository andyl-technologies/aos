//! Keeps each immutable plan read inside the retained installing Original.
//!
//! A signal may interrupt any `pread`. Retrying it requires another check of
//! the same Source; neither progress nor EINTR starts a replacement interval.
//! Every attempted read also observes that Original before interpreting its
//! result, preserving a kernel refusal alongside a negative observation.
// SPDX-License-Identifier: GPL-2.0-only

use std::os::fd::{AsRawFd, BorrowedFd};

use super::PluginSetupPlanDescriptorError;
use crate::startup_source::InstallerStartupSource;
use crate::StartupSourceError;

/// Checks the retained installing Source before allocating the read buffer.
///
/// # Errors
/// Returns the actual Source refusal or missing production custody.
pub(super) fn check_original(
    original: Option<&InstallerStartupSource>,
) -> Result<(), PluginSetupPlanDescriptorError> {
    observe_original(original).map_err(|source| PluginSetupPlanDescriptorError::Original { source })
}

fn observe_original(original: Option<&InstallerStartupSource>) -> Result<(), StartupSourceError> {
    match original {
        Some(original) => original.check(),
        #[cfg(test)]
        None => Ok(()),
        #[cfg(not(test))]
        None => Err(StartupSourceError::Ownership {
            reason: "plugin plan read has no retained installing Original",
        }),
    }
}

/// Reads the exact plan body with the same Original around every syscall.
///
/// # Errors
/// Preserves read failure, truncation and independent Source refusal without
/// retrying after a negative Original observation.
pub(super) fn read(
    fd: BorrowedFd<'_>,
    bytes: &mut [u8],
    original: Option<&InstallerStartupSource>,
) -> Result<(), PluginSetupPlanDescriptorError> {
    read_with(
        bytes,
        || observe_original(original),
        |destination, offset| {
            let offset = libc::off_t::try_from(offset).map_err(|_| libc::EOVERFLOW)?;
            // SAFETY: the retained native owner keeps fd live for this call. The
            // destination is its exclusive initialized byte slice; pread retains
            // neither the pointer nor the slice and does not change file position.
            let count = unsafe {
                libc::pread(
                    fd.as_raw_fd(),
                    destination.as_mut_ptr().cast(),
                    destination.len(),
                    offset,
                )
            };
            if count < 0 {
                Err(super::last_errno())
            } else {
                usize::try_from(count).map_err(|_| libc::EOVERFLOW)
            }
        },
    )
}

fn read_with(
    bytes: &mut [u8],
    mut check: impl FnMut() -> Result<(), StartupSourceError>,
    mut read: impl FnMut(&mut [u8], usize) -> Result<usize, i32>,
) -> Result<(), PluginSetupPlanDescriptorError> {
    let mut offset = 0;
    while offset < bytes.len() {
        check().map_err(|source| PluginSetupPlanDescriptorError::Original { source })?;
        let result = read(&mut bytes[offset..], offset);
        if let Err(original_after) = check() {
            return Err(PluginSetupPlanDescriptorError::ReadOriginal {
                offset,
                result,
                original_after,
            });
        }

        let count = match result {
            Err(libc::EINTR) => continue,
            Err(errno) => {
                return Err(PluginSetupPlanDescriptorError::Io {
                    operation: "read plugin setup-plan descriptor",
                    errno,
                });
            }
            Ok(count) => count,
        };
        if count == 0 {
            return Err(PluginSetupPlanDescriptorError::Truncated {
                expected: bytes.len(),
                actual: offset,
            });
        }
        offset += count;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
