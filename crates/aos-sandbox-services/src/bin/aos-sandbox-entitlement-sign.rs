//! Signs first-capability entitlements on an offline administration host.
//!
//! The seed is read from a caller-owned private file and never written to the
//! controller credential set. Outputs are created exclusively, so a mistaken
//! invocation cannot replace an existing signed policy or verifier.

use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::PathBuf;
use std::process::ExitCode;

use aos_sandbox::public_capability_issuance::sign_entitlement_document_v1;
use rustix::fs::{Mode, OFlags};
use zeroize::Zeroizing;

const MAXIMUM_UNSIGNED_BYTES: u64 = 1024 * 1024;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-entitlement-sign: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os();
    let _program = args.next();
    let unsigned_path = required_path(&mut args)?;
    let seed_path = required_path(&mut args)?;
    let signed_path = required_path(&mut args)?;
    let verifier_path = required_path(&mut args)?;
    if args.next().is_some() || signed_path == verifier_path {
        return Err(usage().into());
    }

    let mut unsigned = Vec::new();
    File::open(unsigned_path)?
        .take(MAXIMUM_UNSIGNED_BYTES + 1)
        .read_to_end(&mut unsigned)?;
    if unsigned.len() as u64 > MAXIMUM_UNSIGNED_BYTES {
        return Err(
            io::Error::new(io::ErrorKind::InvalidData, "unsigned document too large").into(),
        );
    }

    let descriptor = rustix::fs::open(
        &seed_path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    let mut seed_file = File::from(descriptor);
    let metadata = seed_file.metadata()?;
    if !metadata.is_file()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "seed must be a private regular file",
        )
        .into());
    }
    let mut seed = Zeroizing::new([0_u8; 32]);
    seed_file.read_exact(&mut seed[..])?;
    let mut extra = [0_u8; 1];
    if seed_file.read(&mut extra)? != 0 {
        return Err(
            io::Error::new(io::ErrorKind::InvalidData, "seed must be exactly 32 bytes").into(),
        );
    }

    let (signed, verifier) = sign_entitlement_document_v1(&unsigned, &seed)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid entitlement document"))?;
    create_output(&verifier_path, &verifier)?;
    create_output(&signed_path, &signed)?;
    Ok(())
}

fn required_path(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<PathBuf, io::Error> {
    args.next().map(PathBuf::from).ok_or_else(usage)
}

fn usage() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: aos-sandbox-entitlement-sign UNSIGNED_JSON PRIVATE_SEED_32B SIGNED_JSON_OUT PUBLIC_KEY_32B_OUT",
    )
}

fn create_output(path: &PathBuf, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
