//! Scopes firmware-partition writes and restores its read-only mount afterward.
//!
//! Image staging and boot selection share this policy. They write through
//! `/boot`, leaving the sealed initrd journal's separate mount read-only.

use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, ensure};

use crate::image_profile::BOOT_ROOT;

/// Runs an operation with writable boot storage and restores read-only access.
///
/// # Errors
/// Returns a remount or operation error. Restoration is attempted after every
/// operation result; if both fail, the operation error retains the restoration
/// error as context. The operation is not invoked if writable remounting fails.
pub(crate) fn with_writable_boot<T>(mount: &Path, effect: impl FnOnce() -> Result<T>) -> Result<T> {
    with_writable_boot_using(
        |writable| {
            let (options, action) = if writable {
                ("remount,rw", "remounting boot storage writable")
            } else {
                ("remount,ro", "remounting boot storage read-only")
            };
            let status = Command::new(mount)
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .args(["-o", options, BOOT_ROOT])
                .status()
                .with_context(|| action.to_string())?;
            ensure!(status.success(), "{action} failed with {status}");
            Ok(())
        },
        effect,
    )
}

fn with_writable_boot_using<T>(
    mut remount: impl FnMut(bool) -> Result<()>,
    effect: impl FnOnce() -> Result<T>,
) -> Result<T> {
    remount(true)?;
    let result = effect();
    let read_only = remount(false);

    match (result, read_only) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(effect), Err(remount)) => {
            Err(effect.context(format!("also failed to restore boot storage: {remount:#}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    #[test]
    fn publication_restores_read_only_after_success_or_failure() {
        for publication_fails in [false, true] {
            let writable = Cell::new(false);
            let transitions = RefCell::new(Vec::new());

            let result = with_writable_boot_using(
                |requested| {
                    transitions.borrow_mut().push(requested);
                    writable.set(requested);
                    Ok(())
                },
                || {
                    assert!(writable.get());
                    ensure!(!publication_fails, "capsule publication failed");
                    Ok(42)
                },
            );

            assert!(!writable.get());
            assert_eq!(*transitions.borrow(), [true, false]);
            if publication_fails {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    "capsule publication failed"
                );
            } else {
                assert_eq!(result.unwrap(), 42);
            }
        }
    }

    #[test]
    fn failed_writable_remount_never_invokes_publication() {
        let publication_called = Cell::new(false);
        let transitions = RefCell::new(Vec::new());

        let result = with_writable_boot_using(
            |requested| {
                transitions.borrow_mut().push(requested);
                anyhow::bail!("writable remount failed")
            },
            || {
                publication_called.set(true);
                Ok(())
            },
        );

        assert!(!publication_called.get());
        assert_eq!(*transitions.borrow(), [true]);
        assert_eq!(result.unwrap_err().to_string(), "writable remount failed");
    }

    #[test]
    fn failed_restoration_is_reported_with_any_publication_error() {
        for publication_fails in [false, true] {
            let transitions = RefCell::new(Vec::new());

            let result = with_writable_boot_using(
                |requested| {
                    transitions.borrow_mut().push(requested);
                    ensure!(requested, "read-only remount failed");
                    Ok(())
                },
                || {
                    ensure!(!publication_fails, "capsule publication failed");
                    Ok(())
                },
            );

            assert_eq!(*transitions.borrow(), [true, false]);
            let message = format!("{:#}", result.unwrap_err());
            assert!(message.contains("read-only remount failed"));
            assert_eq!(
                message.contains("capsule publication failed"),
                publication_fails
            );
        }
    }
}
