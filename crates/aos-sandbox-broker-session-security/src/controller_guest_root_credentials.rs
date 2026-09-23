//! Fixed controller deployment pins for the concrete guest-root template.
//!
//! Both credentials are exact SHA-256 lowercase-hex lines installed by
//! systemd from the AOS-built template output. No public request or Storage
//! response may choose a package path or substitute either digest.

use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use aos_sandbox::guest_root_publication::GuestRootTemplatePinsV1;
use rustix::fs::{CWD, Mode, OFlags, openat};

const PACKAGE_BINDING: &str = "guest-root-package-binding-v1";
const ROOT_TREE_DIGEST: &str = "guest-root-tree-digest-v1";
const HEX_LINE_BYTES: usize = 65;

/// Reports a missing, partial, or unsafe deployment pin set.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("controller guest-root template credentials are invalid")]
pub(crate) struct ControllerGuestRootCredentialErrorV1;

/// Loads the independently pinned package and complete root-tree digests.
///
/// An entirely absent pair leaves root publication unavailable. A partial
/// pair fails activation, preventing accidental authority downgrade.
///
/// # Errors
///
/// Rejects a non-absolute credential directory, unsafe leaf, malformed line,
/// partial pair, or zero digest.
pub(crate) fn load_guest_root_template_pins_optional()
-> Result<Option<GuestRootTemplatePinsV1>, ControllerGuestRootCredentialErrorV1> {
    let Some(directory) = std::env::var_os("CREDENTIALS_DIRECTORY") else {
        return Ok(None);
    };
    let directory = Path::new(&directory);
    if !directory.is_absolute() {
        return Err(ControllerGuestRootCredentialErrorV1);
    }
    let package = read_digest_line(directory, PACKAGE_BINDING)?;
    let tree = read_digest_line(directory, ROOT_TREE_DIGEST)?;
    match (package, tree) {
        (None, None) => Ok(None),
        (Some(package), Some(tree)) => GuestRootTemplatePinsV1::new(package, tree)
            .map(Some)
            .map_err(|_| ControllerGuestRootCredentialErrorV1),
        _ => Err(ControllerGuestRootCredentialErrorV1),
    }
}

fn read_digest_line(
    directory: &Path,
    name: &str,
) -> Result<Option<[u8; 32]>, ControllerGuestRootCredentialErrorV1> {
    let path = directory.join(name);
    let descriptor = match openat(
        CWD,
        &path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(ControllerGuestRootCredentialErrorV1),
    };
    let mut file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|_| ControllerGuestRootCredentialErrorV1)?;
    if !metadata.is_file()
        || metadata.len() != HEX_LINE_BYTES as u64
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err(ControllerGuestRootCredentialErrorV1);
    }
    let mut line = [0_u8; HEX_LINE_BYTES];
    file.read_exact(&mut line)
        .map_err(|_| ControllerGuestRootCredentialErrorV1)?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| ControllerGuestRootCredentialErrorV1)?
        != 0
        || line[64] != b'\n'
    {
        return Err(ControllerGuestRootCredentialErrorV1);
    }
    let mut digest = [0_u8; 32];
    for (byte, pair) in digest.iter_mut().zip(line[..64].chunks_exact(2)) {
        let high = hex_digit(pair[0]).ok_or(ControllerGuestRootCredentialErrorV1)?;
        let low = hex_digit(pair[1]).ok_or(ControllerGuestRootCredentialErrorV1)?;
        *byte = (high << 4) | low;
    }
    if digest == [0; 32] {
        return Err(ControllerGuestRootCredentialErrorV1);
    }
    Ok(Some(digest))
}

const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::hex_digit;

    #[test]
    fn digest_lines_require_lowercase_hex() {
        assert_eq!(hex_digit(b'a'), Some(10));
        assert_eq!(hex_digit(b'f'), Some(15));
        assert_eq!(hex_digit(b'F'), None);
        assert_eq!(hex_digit(b'/'), None);
    }
}
