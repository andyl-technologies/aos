//! Owns repository path confinement before authorized directory materialization.

use crate::repository::Error;
use std::collections::{BTreeMap, VecDeque};

/// Checks composed targets, including traversal through another exposed link.
///
/// Lexical checks alone are insufficient: a confined link can shorten a path,
/// allowing a later `..` in another target to escape the presented root.
///
/// # Errors
/// Rejects invalid or escaping targets and link chains exceeding 40 expansions.
pub(crate) fn validate_symlink_targets(links: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<(), Error> {
    for (key, target) in links {
        validate_symlink(key, target)?;

        let mut resolved = key
            .split(|byte| *byte == b'/')
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        resolved.pop();
        let mut pending = target
            .split(|byte| *byte == b'/')
            .map(<[u8]>::to_vec)
            .collect::<VecDeque<_>>();
        let mut expansions = 0;

        while let Some(component) = pending.pop_front() {
            match component.as_slice() {
                b"" | b"." => continue,
                b".." => {
                    resolved.pop().ok_or(Error::PathEscape)?;
                }
                _ => {
                    resolved.push(component);
                    if let Some(next) = links.get(&resolved.join(&b'/')) {
                        expansions += 1;
                        if expansions > 40 {
                            return Err(Error::Unrealizable);
                        }
                        resolved.pop();
                        for part in next.split(|byte| *byte == b'/').rev() {
                            pending.push_front(part.to_vec());
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Checks that a verbatim symlink remains within the presented namespace.
///
/// Every relative component is evaluated from the link's exposed parent, so
/// a subtree cannot retain a link to content outside that subtree (SURF-7).
/// Targets are preserved byte for byte after validation.
///
/// # Errors
/// Rejects empty, absolute or NUL-containing targets and parent traversal
/// outside the presented namespace.
pub(super) fn validate_symlink(key: &[u8], target: &[u8]) -> Result<(), Error> {
    if target.is_empty() || target.starts_with(b"/") || target.contains(&0) {
        return Err(Error::PathEscape);
    }

    let mut depth = key.split(|byte| *byte == b'/').count().saturating_sub(1);
    for component in target.split(|byte| *byte == b'/') {
        match component {
            b"" | b"." => {}
            b".." => {
                depth = depth.checked_sub(1).ok_or(Error::PathEscape)?;
            }
            _ => {
                depth = depth.checked_add(1).ok_or(Error::PathEscape)?;
            }
        }
    }
    Ok(())
}

/// Refuses existing destinations and symbolic links in an absolute target path.
///
/// The checkout writes into a newly created private directory. This preflight
/// deliberately does not promise protection against concurrent same-user
/// replacement of an ancestor: that requires rooted filesystem operations.
///
/// # Errors
/// Rejects relative or noncanonical paths, symlink or nondirectory ancestors,
/// existing destinations and failed filesystem metadata reads.
#[cfg(all(feature = "surface-sdk", unix))]
pub(super) async fn validate_destination<F: crate::store::LocalFs + Sync>(
    fs: &F,
    destination: &std::path::Path,
) -> Result<(), Error> {
    use std::path::Component;

    if !destination.is_absolute() || destination.parent().is_none() {
        return Err(Error::PathEscape);
    }
    let mut current = std::path::PathBuf::new();
    for component in destination.components() {
        match component {
            Component::RootDir | Component::Normal(_) => current.push(component.as_os_str()),
            _ => return Err(Error::PathEscape),
        }
        if current == destination {
            continue;
        }
        let metadata = fs.symlink_metadata(&current).await?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(Error::PathEscape);
        }
    }
    match fs.symlink_metadata(destination).await {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "checkout destination exists",
        )
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_confined_targets_without_normalizing_them() {
        for (key, target) in [
            (b"a/link".as_slice(), b"../file".as_slice()),
            (b"link", b"nested/../file"),
            (b"a/b/link", b"./../file"),
        ] {
            assert!(validate_symlink(key, target).is_ok());
        }
    }

    #[test]
    fn rejects_absolute_nul_and_subtree_escape_targets() {
        for target in [
            b"/etc/passwd".as_slice(),
            b"../outside",
            b"a/../../outside",
            b"file\0tail",
            b"",
        ] {
            assert!(matches!(
                validate_symlink(b"link", target),
                Err(Error::PathEscape)
            ));
        }
    }

    #[test]
    fn rejects_escape_created_by_composing_confined_links() {
        let links = BTreeMap::from([
            (b"nested/a".to_vec(), b"..".to_vec()),
            (b"nested/link".to_vec(), b"a/../../outside".to_vec()),
        ]);
        assert!(validate_symlink(b"nested/link", b"a/../../outside").is_ok());
        assert!(matches!(
            validate_symlink_targets(&links),
            Err(Error::PathEscape)
        ));
    }

    #[test]
    fn rejects_cyclic_targets() {
        let links = BTreeMap::from([
            (b"a".to_vec(), b"b".to_vec()),
            (b"b".to_vec(), b"a".to_vec()),
        ]);
        assert!(matches!(
            validate_symlink_targets(&links),
            Err(Error::Unrealizable)
        ));
    }
}
