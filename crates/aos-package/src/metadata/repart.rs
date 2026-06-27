//! The two-boot custom-repart hand-off seam.
//!
//! First-boot substrate is **image-only**: `systemd-repart` runs in the initrd
//! before `host.nix` is evaluated, so operator `repart.d` fragments derived
//! from `host.nix` can neither be verified nor be present in time. Custom
//! topologies are therefore a two-boot flow:
//!
//! 1. **Boot 1, initrd** — the agent stashes the untrusted `host.nix`;
//!    first-boot repart carves only the image-baked `/usr/lib/repart.d`.
//! 2. **Boot 1, stage-2** — `aos-eval.service` verifies the `host.nix`
//!    signature and, *only on success*, persists operator fragments via
//!    [`persist_operator_repart`] to `/var/lib/aos/repart.d/`, writing the
//!    `.verified` gate.
//! 3. **Boot 2, initrd** — the repart run reads the fragments **only when**
//!    [`verified_fragments_present`] holds.
//!
//! This module owns only the persistence + gate primitives and their paths;
//! the agent writes nothing here (that is stage-2 `aos-eval`'s output), and the
//! initrd-side consumption of the gate is wired in a later changeset. The
//! `.verified` file is the load-bearing guard: destructive substrate never
//! runs from unverified input.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Directory on `/var` where verified operator repart fragments live.
pub const REPART_DIR: &str = "var/lib/aos/repart.d";
/// The gate file written iff the source `host.nix` signature passed.
pub const VERIFIED_MARKER: &str = ".verified";

/// One operator-declared `repart.d` fragment to persist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepartFragment {
    /// File name (e.g. `60-data.conf`); must end `.conf`.
    pub name: String,
    /// The `repart.d` ini contents.
    pub contents: String,
}

/// Persist verified operator `repart.d` fragments to `<var_root>/var/lib/aos/repart.d/`.
///
/// **Precondition**: the caller has already verified the `host.nix` signature.
/// Writing the `.verified` gate asserts that precondition for the next boot's
/// initrd repart run, so this function must never be called for unverified
/// input.
///
/// Existing fragments are cleared first so the set is convergent with the
/// current verified `host.nix`. Returns the fragment paths written.
///
/// # Errors
///
/// Returns `Err` on any directory-create or file-write failure, or when a
/// fragment name does not end in `.conf`.
pub fn persist_operator_repart(
    var_root: &Path,
    fragments: &[RepartFragment],
) -> Result<Vec<PathBuf>> {
    let dir = var_root.join(REPART_DIR);
    // Convergent: drop any stale fragments from a prior verified host.nix.
    if dir.exists() {
        std::fs::remove_dir_all(&dir)
            .with_context(|| format!("clearing {}", dir.display()))?;
    }
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    let mut written = Vec::with_capacity(fragments.len());
    for frag in fragments {
        if !frag.name.ends_with(".conf") {
            anyhow::bail!("repart fragment name must end in .conf: {}", frag.name);
        }
        // Reject path traversal: the name is a bare filename, never a path.
        if frag.name.contains('/') || frag.name.contains("..") {
            anyhow::bail!("repart fragment name must be a bare filename: {}", frag.name);
        }
        let path = dir.join(&frag.name);
        std::fs::write(&path, &frag.contents)
            .with_context(|| format!("writing {}", path.display()))?;
        written.push(path);
    }

    // The gate goes last: its presence means the whole set is verified.
    std::fs::write(dir.join(VERIFIED_MARKER), b"")
        .with_context(|| format!("writing {VERIFIED_MARKER} gate"))?;
    Ok(written)
}

/// Whether `<var_root>/var/lib/aos/repart.d/.verified` is present — the
/// load-bearing guard the boot-2 initrd repart run keys off.
///
/// A probe over real on-disk state, not a fallible marker: if the directory or
/// the gate is absent, the initrd carves only the image-baked convention.
pub fn verified_fragments_present(var_root: &Path) -> bool {
    var_root.join(REPART_DIR).join(VERIFIED_MARKER).is_file()
}
