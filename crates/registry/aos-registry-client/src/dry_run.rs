//! Process-wide preview policy for shared registry mutation primitives.
//!
//! Registry operations mutate through filesystem and Git primitives shared by
//! consumers and authoring tools. A preview handler reports proposed changes;
//! the primitives independently refuse mutation so a missed early return cannot
//! turn that preview into a signed or persisted change.
//!
//! This policy is process-global. Applications set it before dispatching a
//! single operation; it is not isolation between concurrent tasks. In-process
//! callers using [`ScopedDryRun`] must serialize policy changes: the guard
//! restores the previous setting, but does not lock other operations out.
//!
//! ```no_run
//! # use aos_registry_client::dry_run;
//! dry_run::set(true);
//! assert!(dry_run::active());
//! ```

use std::sync::atomic::{AtomicBool, Ordering};

/// Whether the current process is previewing rather than applying changes.
static DRY_RUN: AtomicBool = AtomicBool::new(false);

/// Sets process-wide dry-run mode.
///
/// Applications set this before dispatching a preview operation. The setting
/// applies to all registry primitives in the process, including other tasks.
pub fn set(active: bool) {
    DRY_RUN.store(active, Ordering::SeqCst);
}

/// Reports whether the process is in dry-run mode.
#[must_use]
pub fn active() -> bool {
    DRY_RUN.load(Ordering::SeqCst)
}

/// Restores the previous dry-run setting when dropped.
///
/// Intended for in-process tests, which must not leak the mode into whatever
/// runs next. Production code sets the mode once and never clears it.
pub struct ScopedDryRun {
    previous: bool,
}

impl ScopedDryRun {
    /// Enters dry-run mode until the returned guard is dropped.
    #[must_use]
    pub fn enter() -> Self {
        let previous = active();
        set(true);
        Self { previous }
    }
}

impl Drop for ScopedDryRun {
    fn drop(&mut self) {
        set(self.previous);
    }
}

/// Fails when a mutating operation is attempted during a dry run.
///
/// `operation` names what was about to happen, in the imperative, for an error
/// read by an operator who asked for a preview: `"commit to the registry"`.
///
/// # Errors
///
/// Returns an error whenever [`active`] is true. The message is deliberately a
/// bug report: reaching a mutation during a dry run means a handler failed to
/// stop, and the operator should not be left believing the preview was clean.
pub fn refuse_mutation(operation: &str) -> anyhow::Result<()> {
    if active() {
        anyhow::bail!(
            "internal error: attempted to {operation} during a --dry-run preview; \
             the operation was blocked and nothing was written, but this is a bug \
             in the command's dry-run handling and should be reported"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_dry_run_restores_the_previous_setting() {
        assert!(!active());
        {
            let _guard = ScopedDryRun::enter();
            assert!(active());
            assert!(refuse_mutation("write a file").is_err());
        }
        assert!(!active());
        assert!(refuse_mutation("write a file").is_ok());
    }
}
