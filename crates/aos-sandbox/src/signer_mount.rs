//! Fixed sandbox ancestry for independent Source and Cache signer views.
//!
//! Linux owns the shared physical observation. This private adapter selects the
//! original protected parent sequence and mount parent for both domain owners;
//! it neither opens journals nor constructs currentness or policy authority.

use std::io;

use aos_sandbox_linux::signer_mount::{SignerMountWitness, require_signer_mount as observe_mount};

/// Observes the original fixed sandbox ancestry and signer mount.
///
/// # Errors
/// Returns the original observation error or rejects an unsafe signer view.
pub(crate) fn require_signer_mount(
    view: &str,
    source: &str,
    signer_uid: u32,
) -> io::Result<SignerMountWitness> {
    observe_mount(
        view,
        source,
        signer_uid,
        "/run/aos",
        &[
            "/var",
            "/var/lib",
            "/var/lib/aos",
            "/var/lib/aos/sandbox",
            "/run",
            "/run/aos",
        ],
    )
}
