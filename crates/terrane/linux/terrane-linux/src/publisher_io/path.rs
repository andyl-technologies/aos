//! Opens native directories without following symlinks in any component.
//!
//! Systemd's `RestrictSUIDSGID` deliberately rejects `openat2` with `ENOSYS`.
//! These read-only opens instead walk one component at a time, retaining the
//! parent descriptor and requiring `O_NOFOLLOW | O_DIRECTORY` at every step.
//! Callers independently validate ownership, filesystem and original inode
//! bindings before treating the returned directory as publisher custody.

use std::{
    fs::File,
    io,
    path::{Component, Path},
};

use rustix::fs::{self, Mode, OFlags};

/// Opens an absolute directory through retained, nonsymlink parents.
///
/// Intermediate descriptors use `O_PATH`, preserving search-only access.
/// Every lookup receives exactly one normal component; neither symlinks nor
/// procfs magic links can redirect resolution, including at the final name.
///
/// # Errors
/// Refuses relative paths, parent traversal, symlinks, nondirectories and
/// inaccessible components. It never creates a directory or retries an unsafe
/// pathname operation when a lookup fails.
pub(crate) fn open_directory(path: &Path) -> io::Result<File> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native directory must be absolute without parent traversal",
        ));
    }

    let mut components = path.components().peekable();
    components.next(); // The validated absolute path begins at the root.
    let required = OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    if components.peek().is_none() {
        return Ok(File::from(fs::open(
            "/",
            required | OFlags::RDONLY,
            Mode::empty(),
        )?));
    }

    let mut directory = fs::open("/", required | OFlags::PATH, Mode::empty())?;
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native directory contains a noncanonical component",
            ));
        };
        let access = if components.peek().is_some() {
            OFlags::PATH
        } else {
            OFlags::RDONLY
        };
        directory = fs::openat(&directory, name, required | access, Mode::empty())?;
    }

    Ok(File::from(directory))
}

#[cfg(test)]
mod tests {
    use super::open_directory;
    use std::{
        fs, io,
        os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, symlink},
        },
        path::{Path, PathBuf},
    };

    struct Fixture(PathBuf);

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn directory_walk_rejects_symlinks_magic_links_and_parent_traversal() -> io::Result<()> {
        let path =
            std::env::temp_dir().join(format!("terrane-publisher-path-{}", std::process::id()));
        fs::create_dir(&path)?;
        let fixture = Fixture(path);
        let original = fixture.0.join("original");
        fs::create_dir(&original)?;
        fs::create_dir(original.join("child"))?;
        fs::write(fixture.0.join("regular"), b"not a directory")?;
        symlink(&original, fixture.0.join("link"))?;

        let directory = open_directory(&original.join("child"))?;
        let flags = rustix::fs::fcntl_getfl(&directory)?;
        assert!(!flags.intersects(
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::RDWR
        ));
        assert!(rustix::io::fcntl_getfd(&directory)?.contains(rustix::io::FdFlags::CLOEXEC));
        let identity = directory.metadata()?;
        let expected = fs::metadata(original.join("child"))?;
        assert_eq!(
            (identity.dev(), identity.ino()),
            (expected.dev(), expected.ino())
        );

        assert!(open_directory(&fixture.0.join("link")).is_err());
        assert!(open_directory(&fixture.0.join("link/child")).is_err());
        assert!(open_directory(&fixture.0.join("regular")).is_err());
        assert!(open_directory(&original.join("../original/child")).is_err());
        assert!(open_directory(Path::new("relative")).is_err());
        let magic = format!("/proc/{}/fd/{}", std::process::id(), directory.as_raw_fd());
        assert!(open_directory(Path::new(&magic)).is_err());

        fs::rename(&original, fixture.0.join("renamed"))?;
        symlink(fixture.0.join("renamed"), &original)?;
        assert!(open_directory(&original.join("child")).is_err());
        let retained = directory.metadata()?;
        assert_eq!(
            (retained.dev(), retained.ino()),
            (identity.dev(), identity.ino())
        );

        Ok(())
    }
}
