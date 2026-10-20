//! Validates exact generated state scratch before portable startup cleanup.
//!
//! Partial scratch bytes may be discarded only under the generated temporary
//! grammar and actual private inode custody. Canonical bindings and leases are
//! never classified as scratch or deleted by this preflight.

use super::*;
use rustix::fs::AtFlags;

fn temporary_bound(name: &str) -> io::Result<Option<usize>> {
    let (suffix, bound) = if let Some(suffix) = name.strip_prefix(".binding-retirement-") {
        (suffix, 4096)
    } else if let Some(suffix) = name.strip_prefix(".binding-") {
        (suffix, 65536)
    } else {
        return Ok(None);
    };
    // Both existing producers use exactly 16 random bytes encoded lowercase.
    digest(suffix, 16)?;
    Ok(Some(bound))
}

/// Retains verified generated scratch through actual portable cleanup.
///
/// # Errors
/// Rejects unknown temporary names, unsafe/project-mismatched inodes,
/// oversized or changing scratch, and exhausted physical-entry budgets.
pub(super) fn capture(inventory: &NativeInventory) -> io::Result<RetainedScratch> {
    let mut budget = MAX_CANDIDATES;
    inventory.check_project(&inventory.root, InodeKind::Directory)?;
    let directory = inventory.scan_private_remnants(&mut budget)?;
    let mut files = Vec::new();
    for name in names(&directory, budget)? {
        charge(&mut budget)?;
        let Some(bound) = temporary_bound(&name)? else {
            continue;
        };
        let mut file = open(&directory, &name, false)?;
        inventory.check(&file, Custody::Publisher, InodeKind::File)?;
        let before = file.metadata()?;
        if before.nlink() != 1 {
            return Err(invalid("state scratch has unexpected additional links"));
        }
        // Real crash scratch may contain incomplete TOML; no parser or
        // claimed content authority is needed to discard generated scratch.
        let _partial_bytes = bytes(&mut file, bound)?;
        let after = file.metadata()?;
        if (
            before.dev(),
            before.ino(),
            before.len(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.ctime(),
            after.ctime_nsec(),
        ) {
            return Err(invalid("state scratch changed during preflight"));
        }
        files.push((name, file));
    }
    Ok(RetainedScratch { directory, files })
}

/// Checks actual removal and parent durability after portable cleanup.
///
/// # Errors
/// Rejects surviving/replaced scratch, unexpected remaining temporaries,
/// retained inode links or actual directory synchronization failure.
pub(super) fn verify_removed(scratch: &RetainedScratch) -> io::Result<()> {
    for (name, file) in &scratch.files {
        match fs::statat(&scratch.directory, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(invalid("state scratch survived or changed during cleanup")),
        }
        if file.metadata()?.nlink() != 0 {
            return Err(invalid("retained state scratch remains physically linked"));
        }
    }
    scratch.directory.sync_all()?;
    for name in names(&scratch.directory, MAX_CANDIDATES)? {
        if name.starts_with(".binding-") {
            return Err(invalid(
                "unreconciled state scratch appeared during cleanup",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_grammar_matches_only_actual_generated_temporary_names() {
        assert_eq!(
            temporary_bound(&format!(".binding-{}", "ab".repeat(16))).unwrap(),
            Some(65536)
        );
        assert_eq!(
            temporary_bound(&format!(".binding-retirement-{}", "01".repeat(16))).unwrap(),
            Some(4096)
        );
        assert_eq!(temporary_bound("retirement-existing.toml").unwrap(), None);
        assert_eq!(temporary_bound("unknown.toml").unwrap(), None);
        for name in [
            ".binding-incomplete",
            ".binding-",
            ".binding-retirement-incomplete",
            ".binding-ABCDEF0123456789abcdef0123456789",
        ] {
            assert!(temporary_bound(name).is_err());
        }
    }
}
