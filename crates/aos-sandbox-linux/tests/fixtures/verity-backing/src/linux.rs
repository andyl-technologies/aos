//! Checks real-kernel descriptor admission, rejection, identity and pin lifetime.

use std::error::Error;
use std::fs::File;
use std::os::fd::AsFd;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::Path;

use aos_sandbox_linux::immutable_file::{
    FsVerityBacking, FsVerityDigest, FsVerityMapping, ImmutableFileError,
};
use aos_sandbox_linux::path::BeneathRoot;

const PAYLOAD: &[u8] = b"aos-fuse-passthrough-proof\n";

pub(super) fn run() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<_> = std::env::args_os().collect();
    require(
        arguments.len() == 3,
        "usage: verity-backing-probe ROOT SHA256_MEASUREMENT",
    )?;
    let root_path = Path::new(&arguments[1]);
    let digest_text = arguments[2].to_str().ok_or("measurement is not ASCII")?;
    let digest = decode_digest(digest_text)?;
    let expected = FsVerityDigest::Sha256(digest);
    let size = PAYLOAD.len() as u64;
    let root = BeneathRoot::from_owned(File::open(root_path)?.into())?;

    let backing = FsVerityBacking::open_beneath(&root, Path::new("payload"), expected, size, size)?;
    let reader = File::from(backing.as_fd().try_clone_to_owned()?);
    let metadata = reader.metadata()?;
    let identity = backing.identity();
    require(
        identity.device() == metadata.dev(),
        "device identity mismatch",
    )?;
    require(
        identity.inode() == metadata.ino(),
        "inode identity mismatch",
    )?;
    require(
        identity.bytes() == size && metadata.len() == size,
        "length mismatch",
    )?;
    check_bytes(&reader)?;

    // The mapping admission shares the filesystem-provenance check; exercise
    // that positive path too, without confusing mapping and owned-FD lifetimes.
    let mapped_matches = FsVerityMapping::run_beneath(
        &root,
        Path::new("payload"),
        expected,
        size,
        size,
        |bytes, mapped| bytes == PAYLOAD && mapped.inode() == identity.inode(),
    )?;
    require(
        mapped_matches,
        "scoped mapping differs from verified backing",
    )?;

    require(
        matches!(
            FsVerityBacking::open_beneath(
                &root,
                Path::new("payload"),
                expected,
                size + 1,
                size + 1
            ),
            Err(ImmutableFileError::SizeMismatch)
        ),
        "wrong size accepted",
    )?;
    require(
        matches!(
            FsVerityBacking::open_beneath(&root, Path::new("payload"), expected, size, size - 1),
            Err(ImmutableFileError::BackingLimitExceeded)
        ),
        "over-limit backing accepted",
    )?;

    let mut wrong_digest = digest;
    wrong_digest[0] ^= 1;
    require(
        matches!(
            FsVerityBacking::open_beneath(
                &root,
                Path::new("payload"),
                FsVerityDigest::Sha256(wrong_digest),
                size,
                size
            ),
            Err(ImmutableFileError::VerityMeasurementMismatch)
        ),
        "wrong measurement accepted",
    )?;

    // All fixture paths are under the harness's disposable ext4 mount.
    std::fs::write(root_path.join("unsealed"), PAYLOAD)?;
    require(
        matches!(
            FsVerityBacking::open_beneath(&root, Path::new("unsealed"), expected, size, size),
            Err(ImmutableFileError::Linux(_))
        ),
        "unsealed same-content file accepted",
    )?;
    std::os::unix::fs::symlink("payload", root_path.join("symlink"))?;
    require(
        matches!(
            FsVerityBacking::open_beneath(&root, Path::new("symlink"), expected, size, size),
            Err(ImmutableFileError::Linux(_))
        ),
        "symlink candidate accepted",
    )?;

    drop(root);
    std::fs::remove_file(root_path.join("payload"))?;
    drop(reader);
    // Borrow the owned descriptor again only after every earlier ordinary FD
    // and the directory pin is gone: the backing itself must retain the inode.
    let retained = File::from(backing.as_fd().try_clone_to_owned()?);
    check_bytes(&retained)?;
    let retained_metadata = retained.metadata()?;
    require(
        retained_metadata.nlink() == 0,
        "fixture inode remains linked",
    )?;
    require(
        retained_metadata.dev() == identity.device() && retained_metadata.ino() == identity.inode(),
        "retained identity changed",
    )?;
    drop(retained);
    drop(backing);

    println!(
        "{{\"schema_version\":\"aos.sandbox.verity-backing-proof/v1\",\"read_verified\":true,\"identity_verified\":true,\"mapping_verified\":true,\"wrong_size_rejected\":true,\"over_limit_rejected\":true,\"wrong_digest_rejected\":true,\"unsealed_rejected\":true,\"symlink_rejected\":true,\"unlinked_pin_verified\":true}}"
    );
    Ok(())
}

fn check_bytes(reader: &File) -> Result<(), Box<dyn Error>> {
    let mut bytes = [0; PAYLOAD.len()];
    reader.read_exact_at(&mut bytes, 0)?;
    require(bytes == PAYLOAD, "verified bytes mismatch")?;
    let mut beyond = [0];
    require(
        reader.read_at(&mut beyond, PAYLOAD.len() as u64)? == 0,
        "file exceeds expected size",
    )
}

fn decode_digest(value: &str) -> Result<[u8; 32], Box<dyn Error>> {
    require(
        value.len() == 64,
        "measurement must contain 64 lowercase hex digits",
    )?;
    let mut digest = [0; 32];
    for (slot, pair) in digest.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *slot = nibble(pair[0])? * 16 + nibble(pair[1])?;
    }
    Ok(digest)
}

fn nibble(value: u8) -> Result<u8, Box<dyn Error>> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("measurement contains noncanonical hex".into()),
    }
}

fn require(condition: bool, message: &'static str) -> Result<(), Box<dyn Error>> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
