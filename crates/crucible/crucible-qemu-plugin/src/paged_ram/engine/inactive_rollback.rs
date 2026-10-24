//! Keeps an inactive restore candidate through fallible cleanup prerequisites.
//!
//! The caller first rules out destructive commit and retained physical holds.
//! Its cleanup closure stops the real worker and returns the validated owner
//! guard. Candidate release runs while that same guard remains held; only the
//! caller's final infallible publication may clear the installed service.

// SPDX-License-Identifier: GPL-2.0-or-later

use crate::ram_error::RamError;

/// Aborts the retained candidate only after its cleanup prerequisites succeed.
///
/// # Errors
/// Preserves the candidate on prerequisite failure or an owned abort refusal.
/// Missing custody refuses before cleanup rather than claiming prior success.
pub(super) fn abort_inactive_candidate<C, G>(
    candidate: &mut Option<C>,
    prepare_cleanup: impl FnOnce() -> Result<G, RamError>,
    abort: impl FnOnce(C) -> Result<(), C>,
) -> Result<G, RamError> {
    if candidate.is_none() {
        return Err(RamError::Invariant("arena identity receipt absent"));
    }
    let owner = prepare_cleanup()?;

    let retained = candidate.take().ok_or("arena identity receipt absent")?;
    if let Err(retained) = abort(retained) {
        *candidate = Some(retained);
        return Err(RamError::Invariant(
            "arena identity rollback authority uncertain",
        ));
    }
    Ok(owner)
}

#[cfg(test)]
mod tests;
