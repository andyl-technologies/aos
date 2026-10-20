//! Fixed physical-image admission for the original filesystem worker.
//!
//! The sole opener follows the image-owned store-link chain, never a caller's
//! path or received executable descriptor. It retains the immutable fragment
//! and executable objects. PID 1 still independently enforces its loaded
//! fragment and same-inode executable seal at launch; this pin grants no Mount,
//! Controller, lease, or content-read authority.

use std::ffi::CString;
use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::Path;

use rustix::fs::{FileType, Mode, OFlags, StatVfsMountFlags};

use crate::fuse_worker_objects::{FUSE_WORKER_EXECUTABLE_CONTEXT_V1, require_object_context};
use crate::path::{BeneathRoot, FileIdentity, ResolveOptions};
use crate::uapi::{
    self, OpenHow, RESOLVE_BENEATH, RESOLVE_NO_MAGICLINKS, RESOLVE_NO_SYMLINKS, RESOLVE_NO_XDEV,
};
use crate::{Error, Result};

const EROFS_SUPER_MAGIC: i64 = 0xe0f5_e1e2;
const TEMPLATE: &str = "aos-view-worker@.service";
const EXECUTABLE_SUFFIX: &str = "/bin/aos-filesystem-fuse-worker";
const ARGUMENT: &str = "--mount-owned-session-v1";
const MAXIMUM_FRAGMENT_BYTES: usize = 64 * 1024;
const STORE_HASH_ALPHABET: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

/// Retains the fixed worker's actual immutable fragment and executable pins.
///
/// No constructor adopts caller-selected paths, descriptors, or historical
/// image digests. The executable uses EROFS image custody, not Cache fs-verity
/// backing authority. The owner must keep this pin through the fixed PID 1
/// launch and independently join the original live Mount session.
pub struct FixedFuseWorkerImageV1 {
    root: BeneathRoot,
    fragment: OwnedFd,
    fragment_identity: FileIdentity,
    executable: OwnedFd,
    executable_identity: FileIdentity,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ImageFileRole {
    Fragment,
    Executable,
}

impl FixedFuseWorkerImageV1 {
    /// Opens only the image-owned worker from the fixed physical store chain.
    ///
    /// # Errors
    ///
    /// Rejects non-EROFS or writable roots, mount substitutions, malformed store
    /// links, foreign objects, unsupported fragment syntax, a different command
    /// or argument, a writable executable, and an unexpected executable label.
    pub fn open_fixed() -> Result<Self> {
        let root = rustix::fs::open(
            "/",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| kernel_error("open fixed worker image root", source))?;
        let mount = rustix::fs::fstatvfs(&root)
            .map_err(|source| kernel_error("inspect fixed worker image mount", source))?;
        if uapi::filesystem_type(root.as_fd())? != EROFS_SUPER_MAGIC
            || !mount
                .f_flag
                .contains(StatVfsMountFlags::RDONLY | StatVfsMountFlags::NODEV)
            || mount.f_flag.contains(StatVfsMountFlags::NOEXEC)
        {
            return Err(invalid(
                "root is not the executable read-only NODEV EROFS image",
            ));
        }
        let root = BeneathRoot::from_owned(root)?;
        let top = physical_store_link(&root, "aos-toplevel", None)?;
        require_image_directory(&root, &top)?;
        let units = physical_store_link(&root, &format!("{top}/systemd-units"), None)?;
        require_image_directory(&root, &units)?;
        let fragment_path = physical_store_link(
            &root,
            &format!("{units}/{TEMPLATE}"),
            Some(&format!("/{TEMPLATE}")),
        )?;

        let fragment = root.open_regular(Path::new(&fragment_path))?;
        require_image_file(
            fragment.as_fd(),
            root.identity().device,
            ImageFileRole::Fragment,
        )?;
        let fragment_identity = fragment.identity();
        let fragment = File::from(fragment.into_owned_fd());
        let mut bytes = Vec::new();
        (&fragment)
            .take((MAXIMUM_FRAGMENT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|source| Error::Syscall {
                operation: "read fixed worker image fragment",
                source,
            })?;
        if bytes.len() > MAXIMUM_FRAGMENT_BYTES {
            return Err(invalid("fragment exceeds its fixed bound"));
        }
        let executable_path = executable_from_fragment(&bytes)?;
        let executable = root.open_regular(Path::new(&executable_path))?;
        require_image_file(
            executable.as_fd(),
            root.identity().device,
            ImageFileRole::Executable,
        )?;
        require_object_context(executable.as_fd(), FUSE_WORKER_EXECUTABLE_CONTEXT_V1)?;

        Ok(Self {
            root,
            fragment: fragment.into(),
            fragment_identity,
            executable_identity: executable.identity(),
            executable: executable.into_owned_fd(),
        })
    }

    /// Borrows the actual independently opened executable for the fixed role.
    #[must_use]
    pub fn executable(&self) -> BorrowedFd<'_> {
        self.executable.as_fd()
    }

    /// Reopens the fixed chain and checks the retained objects before launch.
    ///
    /// This readback supplements, rather than replaces, PID 1's live fragment
    /// and execution seal. It does not observe the worker or confer read rights.
    ///
    /// # Errors
    ///
    /// Rejects a changed root, named chain, fragment, executable, label, or
    /// immutable filesystem profile, including a bind-mounted replacement.
    pub fn recheck(&self) -> Result<()> {
        require_image_file(
            self.fragment.as_fd(),
            self.root.identity().device,
            ImageFileRole::Fragment,
        )?;
        require_image_file(
            self.executable.as_fd(),
            self.root.identity().device,
            ImageFileRole::Executable,
        )?;
        require_object_context(self.executable.as_fd(), FUSE_WORKER_EXECUTABLE_CONTEXT_V1)?;
        let current = Self::open_fixed()?;
        if self.root.identity() != current.root.identity()
            || self.fragment_identity != current.fragment_identity
            || self.executable_identity != current.executable_identity
        {
            return Err(invalid("fixed named image objects changed"));
        }
        Ok(())
    }
}

fn require_image_file(fd: BorrowedFd<'_>, image_device: u64, role: ImageFileRole) -> Result<()> {
    let stat = rustix::fs::fstat(fd)
        .map_err(|source| kernel_error("inspect fixed worker image file", source))?;
    let mount = rustix::fs::fstatvfs(fd)
        .map_err(|source| kernel_error("inspect fixed worker image file mount", source))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_dev != image_device
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_mode & 0o222 != 0
        || uapi::filesystem_type(fd)? != EROFS_SUPER_MAGIC
        || !mount
            .f_flag
            .contains(StatVfsMountFlags::RDONLY | StatVfsMountFlags::NODEV)
        || (role == ImageFileRole::Executable
            && (stat.st_mode & 0o111 == 0 || mount.f_flag.contains(StatVfsMountFlags::NOEXEC)))
    {
        return Err(invalid(
            "file is not the required immutable physical image object",
        ));
    }
    Ok(())
}

fn require_image_directory(root: &BeneathRoot, path: &str) -> Result<()> {
    let directory = root.resolve(Path::new(path), ResolveOptions::directory())?;
    let stat = rustix::fs::fstat(directory.as_fd())
        .map_err(|source| kernel_error("inspect fixed worker image directory", source))?;
    if stat.st_dev != root.identity().device || stat.st_uid != 0 || stat.st_gid != 0 {
        return Err(invalid("image directory is foreign"));
    }
    Ok(())
}

fn physical_store_link(root: &BeneathRoot, path: &str, suffix: Option<&str>) -> Result<String> {
    // O_PATH|O_NOFOLLOW permits inspection of only the final symlink while
    // openat2 rejects symlinks or mount crossings in all ancestors.
    let path = CString::new(path).map_err(|_| invalid("fixed image path contains NUL"))?;
    let flags = u64::try_from(libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .map_err(|_| invalid("image open flags cannot be represented"))?;
    let link = uapi::openat2(
        root.as_fd(),
        &path,
        &OpenHow {
            flags,
            mode: 0,
            resolve: RESOLVE_BENEATH
                | RESOLVE_NO_MAGICLINKS
                | RESOLVE_NO_SYMLINKS
                | RESOLVE_NO_XDEV,
        },
    )?;
    let stat = rustix::fs::fstat(&link)
        .map_err(|source| kernel_error("inspect fixed worker image link", source))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Symlink
        || stat.st_dev != root.identity().device
        || stat.st_uid != 0
        || stat.st_gid != 0
    {
        return Err(invalid("image link is foreign or not a symlink"));
    }
    let target = rustix::fs::readlinkat(&link, c"", Vec::new())
        .map_err(|source| kernel_error("read pinned fixed worker image link", source))?;
    physical_store_path(target.to_bytes(), suffix)
}

fn physical_store_path(target: &[u8], suffix: Option<&str>) -> Result<String> {
    let target = std::str::from_utf8(target).map_err(|_| invalid("store target is not UTF-8"))?;
    let relative = target
        .strip_prefix("/nix/store/")
        .ok_or_else(|| invalid("target is not an absolute store link"))?;
    let (component, actual_suffix) = relative
        .split_once('/')
        .map_or((relative, None), |(component, suffix)| {
            (component, Some(format!("/{suffix}")))
        });
    if component.len() < 34
        || component.as_bytes()[32] != b'-'
        || !component.as_bytes()[..32]
            .iter()
            .all(|byte| STORE_HASH_ALPHABET.contains(byte))
        || component[33..].bytes().any(|byte| {
            !byte.is_ascii_alphanumeric()
                && !matches!(byte, b'+' | b'-' | b'_' | b'.' | b'?' | b'=')
        })
        || actual_suffix.as_deref() != suffix
    {
        return Err(invalid("store target does not have the fixed image shape"));
    }
    Ok(format!("nix.lower/store/{relative}"))
}

fn executable_from_fragment(bytes: &[u8]) -> Result<String> {
    if bytes.contains(&0) || bytes.contains(&b'\r') {
        return Err(invalid("fragment contains unsupported bytes"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("fragment is not UTF-8"))?;
    let mut service = false;
    let mut executable = None;
    for line in text.lines().map(str::trim) {
        if line.ends_with('\\') {
            return Err(invalid("fragment contains unsupported continuation"));
        }
        if line.starts_with('[') {
            service = line == "[Service]";
        } else if let Some(command) = line.strip_prefix("ExecStart=") {
            if !service || executable.is_some() {
                return Err(invalid("fragment has a foreign or duplicate command"));
            }
            let mut arguments = command.split_ascii_whitespace();
            let path = arguments
                .next()
                .ok_or_else(|| invalid("fragment has no executable"))?;
            if arguments.next() != Some(ARGUMENT) || arguments.next().is_some() {
                return Err(invalid("fragment has different fixed arguments"));
            }
            executable = Some(physical_store_path(
                path.as_bytes(),
                Some(EXECUTABLE_SUFFIX),
            )?);
        }
    }
    executable.ok_or_else(|| invalid("fragment has no fixed service command"))
}

fn invalid(message: &'static str) -> Error {
    Error::invalid("fixed worker image", message)
}

fn kernel_error(operation: &'static str, source: rustix::io::Errno) -> Error {
    Error::Syscall {
        operation,
        source: source.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STORE: &str = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-worker";

    #[test]
    fn only_exact_image_store_links_are_projected() {
        assert_eq!(
            physical_store_path(STORE.as_bytes(), None).unwrap(),
            "nix.lower/store/0123456789abcdfghijklmnpqrsvwxyz-worker"
        );
        for changed in [
            STORE.replace("/nix/store/", "/nix.lower/store/"),
            STORE.replace('0', "e"),
            format!("{STORE}/extra"),
            format!("{STORE}/../outside"),
            STORE.replace("-worker", "-worker name"),
        ] {
            assert!(physical_store_path(changed.as_bytes(), None).is_err());
        }
        assert!(physical_store_path(STORE.as_bytes(), Some(EXECUTABLE_SUFFIX)).is_err());
    }

    #[test]
    fn fragment_has_one_fixed_service_command_without_argv_or_path_substitution() {
        let exact = format!("[Service]\nExecStart={STORE}{EXECUTABLE_SUFFIX} {ARGUMENT}\n");
        assert_eq!(
            executable_from_fragment(exact.as_bytes()).unwrap(),
            format!("nix.lower/store/{}{EXECUTABLE_SUFFIX}", &STORE[11..])
        );
        for changed in [
            exact.replace("[Service]", "[Unit]"),
            exact.replace(ARGUMENT, "--caller-selected"),
            exact.replace("ExecStart=", "ExecStart=+"),
            exact.replace(EXECUTABLE_SUFFIX, "/bin/other"),
            format!("{exact}ExecStart={STORE}{EXECUTABLE_SUFFIX} {ARGUMENT}\n"),
            exact.replace(ARGUMENT, &format!("{ARGUMENT} extra")),
            exact.replace('\n', "\r\n"),
            format!("{exact}Environment=unexpected\\\n"),
        ] {
            assert!(executable_from_fragment(changed.as_bytes()).is_err());
        }
    }
}
