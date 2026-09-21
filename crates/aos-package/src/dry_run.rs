//! Process-wide dry-run mode for the `apr` registry-authoring CLI.
//!
//! `--dry-run` promises that a command writes nothing. Honoring that promise
//! command by command is fragile: the registry tooling mutates through several
//! hundred filesystem and Git call sites, and a single missed one turns a
//! preview into a real, signed change — which is precisely the failure this
//! mode exists to prevent.
//!
//! So the promise is enforced at the mutation primitives instead of trusted to
//! each handler. A command handler still stops early and prints what it would
//! do, but if one forgets, the primitive underneath refuses rather than
//! writing. The barrier and the handler are deliberately redundant: the
//! handler produces a good preview, the barrier makes the preview honest.
//!
//! The flag is process-global because `apr` decides it once, from a
//! command-line argument, before dispatching a single subcommand. Tests that
//! need it in-process use [`ScopedDryRun`], which restores the previous value
//! on drop; tests that spawn the binary get the real thing.
//!
//! ```no_run
//! # use aos_package::dry_run;
//! dry_run::set(true);
//! assert!(dry_run::active());
//! ```

use std::sync::atomic::{AtomicBool, Ordering};

/// Whether the current process is previewing rather than applying changes.
static DRY_RUN: AtomicBool = AtomicBool::new(false);

/// Sets process-wide dry-run mode.
///
/// `apr` calls this once, before dispatching, from the parsed `--dry-run`
/// flag.
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
pub(crate) fn refuse_mutation(operation: &str) -> anyhow::Result<()> {
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
