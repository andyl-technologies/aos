//! Signs one independently compared initial-floor request outside the guest.
//!
//! The operator supplies its expected public provisioning and complete journal
//! checkpoint separately from the producer's request. Production codecs admit
//! the request; this fixture supplies no Source, writer or hardware authority.
//! Only the signature is delivered to the producer. The private seed stays on
//! the host and must match the image's independently selected public pin.
//!
//! ```text
//! PURPOSE PROVISION CHECKPOINT REQUEST OPERATOR_SEED APPROVAL_PUBLIC OUTPUT
//! PURPOSE = controller | storage
//! ```

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

use aos_sandbox_broker_session_security::method46_initial_provisioning::{
    Method46InitialIntentDataV1, Method46InitialPurposeV1, Method46InitialRequestDataV1,
};
use aos_sandbox_protocol::method46_provisioning::{Method46EndpointDataV1, decode_provision_v1};
use ed25519_dalek::{Signer as _, SigningKey};
use rustix::fs::{Mode, OFlags};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn main() {
    if let Err(error) = run() {
        eprintln!("independent METHOD46 approval refused: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() != 7 {
        return Err("expected PURPOSE PROVISION CHECKPOINT REQUEST SEED PUBLIC OUTPUT".into());
    }
    let purpose = match arguments[0].to_str() {
        Some("controller") => Method46InitialPurposeV1::ControllerStorageClient,
        Some("storage") => Method46InitialPurposeV1::StorageBroker,
        _ => return Err("expected the fixed controller or storage purpose".into()),
    };

    let provision = read_exact::<160>(Path::new(&arguments[1]), false)?;
    let checkpoint = read_exact::<156>(Path::new(&arguments[2]), false)?;
    let request = read_exact::<322>(Path::new(&arguments[3]), false)?;
    let seed = read_exact::<32>(Path::new(&arguments[4]), true)?;
    let public = read_exact::<32>(Path::new(&arguments[5]), false)?;
    let signature = approve(purpose, &provision, &checkpoint, &request, seed, public)?;

    // A failed comparison must publish nothing. Exclusive creation also keeps
    // an earlier independent decision from being silently replaced.
    let path = Path::new(&arguments[6]);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    output.write_all(&signature)?;
    output.sync_all()?;
    File::open(
        path.parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}

fn read_exact<const N: usize>(path: &Path, private: bool) -> Result<[u8; N]> {
    let file = File::from(rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != N as u64 {
        return Err("input must be an exact-width regular file".into());
    }
    if private
        && (metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.uid() != rustix::process::geteuid().as_raw())
    {
        return Err("operator seed must be an owner-only, singly linked file".into());
    }
    let mut bytes = Vec::with_capacity(N + 1);
    file.take(N as u64 + 1).read_to_end(&mut bytes)?;
    bytes
        .try_into()
        .map_err(|_| "input changed width during read".into())
}

fn approve(
    purpose: Method46InitialPurposeV1,
    provision: &[u8; 160],
    checkpoint: &[u8; 156],
    request: &[u8; 322],
    seed: [u8; 32],
    public: [u8; 32],
) -> Result<[u8; 64]> {
    let endpoint = match purpose {
        Method46InitialPurposeV1::ControllerStorageClient => {
            Method46EndpointDataV1::ControllerStorageClient
        }
        Method46InitialPurposeV1::StorageBroker => Method46EndpointDataV1::StorageBroker,
    };
    decode_provision_v1(provision, endpoint)?;
    let decoded = Method46InitialRequestDataV1::decode(request)?;
    if decoded.purpose() != purpose
        || request[12..158] != provision[12..158]
        || decoded.checkpoint() != *checkpoint
    {
        return Err("producer request differs from the independent expected cut".into());
    }
    if seed == [0; 32] {
        return Err("operator seed must be nonzero".into());
    }
    let signing = SigningKey::from_bytes(&seed);
    if signing.verifying_key().to_bytes() != public {
        return Err("operator seed differs from the independent public pin".into());
    }
    let signature = signing.sign(request).to_bytes();
    Method46InitialIntentDataV1::from_approval(decoded, signature, public)?;
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(purpose: Method46InitialPurposeV1) -> ([u8; 160], Method46InitialRequestDataV1) {
        let mut salt = [0x61; 34];
        salt[..2].copy_from_slice(&[0, 0x0b]);
        let request =
            Method46InitialRequestDataV1::new(purpose, [1; 16], [2; 16], [3; 32], salt, 7, [4; 32])
                .unwrap();
        let mut provision = [0; 160];
        provision[..8].copy_from_slice(b"AOSBTD01");
        provision[8..10].copy_from_slice(&1_u16.to_be_bytes());
        provision[12..158].copy_from_slice(&request.encode()[12..158]);
        (provision, request)
    }

    #[test]
    fn approval_verifies_only_for_the_complete_expected_request() {
        for purpose in [
            Method46InitialPurposeV1::ControllerStorageClient,
            Method46InitialPurposeV1::StorageBroker,
        ] {
            let (provision, request) = candidate(purpose);
            let seed = [9; 32];
            let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
            let bytes = request.encode();
            let signature = approve(
                purpose,
                &provision,
                &request.checkpoint(),
                &bytes,
                seed,
                public,
            )
            .unwrap();
            let intent =
                Method46InitialIntentDataV1::from_approval(request, signature, public).unwrap();
            Method46InitialIntentDataV1::decode(&intent.encode(), public).unwrap();

            for index in 0..bytes.len() {
                let mut changed = bytes;
                changed[index] ^= 1;
                assert!(
                    approve(
                        purpose,
                        &provision,
                        &request.checkpoint(),
                        &changed,
                        seed,
                        public
                    )
                    .is_err(),
                    "accepted request byte {index}"
                );
            }
        }
    }

    #[test]
    fn independent_expectations_and_key_substitutions_refuse() {
        let purpose = Method46InitialPurposeV1::StorageBroker;
        let (provision, request) = candidate(purpose);
        let seed = [9; 32];
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let bytes = request.encode();
        for index in 0..provision.len() {
            let mut changed = provision;
            changed[index] ^= 1;
            assert!(
                approve(
                    purpose,
                    &changed,
                    &request.checkpoint(),
                    &bytes,
                    seed,
                    public
                )
                .is_err()
            );
        }
        for index in 0..156 {
            let mut changed = request.checkpoint();
            changed[index] ^= 1;
            assert!(approve(purpose, &provision, &changed, &bytes, seed, public).is_err());
        }
        assert!(
            approve(
                Method46InitialPurposeV1::ControllerStorageClient,
                &provision,
                &request.checkpoint(),
                &bytes,
                seed,
                public
            )
            .is_err()
        );
        assert!(
            approve(
                purpose,
                &provision,
                &request.checkpoint(),
                &bytes,
                [0; 32],
                public
            )
            .is_err()
        );
        assert!(
            approve(
                purpose,
                &provision,
                &request.checkpoint(),
                &bytes,
                [8; 32],
                public
            )
            .is_err()
        );
    }
}
