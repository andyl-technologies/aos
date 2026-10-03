//! Creates one versioned public-key credential for the root policy authority.
//!
//! This offline administration tool reads only a public Ed25519 key. It never
//! handles a signing seed and creates the output exclusively with mode 0600.

use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aos_sandbox::cache_residency::encode_cache_owner_readback_signer_credential_v1;
use aos_sandbox::policy_compiler::encode_controller_hold_signer_credential_v1;
use aos_sandbox_broker_session_security::policy_signer_credential::{
    PolicySignerRoleV1, encode_policy_signer_credential_v1,
};
use ed25519_dalek::VerifyingKey;
use rustix::fs::{Mode, OFlags};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-policy-key-pin: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os();
    let _program = args.next();
    let role = args
        .next()
        .as_deref()
        .and_then(std::ffi::OsStr::to_str)
        .and_then(parse_role)
        .ok_or_else(usage)?;
    let generation: u64 = args
        .next()
        .as_deref()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(usage)?
        .parse()?;
    let public_key_path = args.next().map(PathBuf::from).ok_or_else(usage)?;
    let output_path = args.next().map(PathBuf::from).ok_or_else(usage)?;
    if args.next().is_some() || public_key_path == output_path {
        return Err(usage().into());
    }

    let descriptor = rustix::fs::open(
        &public_key_path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    let mut public_key_file = File::from(descriptor);
    if !public_key_file.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "public key must be a file").into());
    }
    let mut key_bytes = [0_u8; 32];
    public_key_file.read_exact(&mut key_bytes)?;
    let mut trailing = [0_u8; 1];
    if public_key_file.read(&mut trailing)? != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "public key length").into());
    }
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)?;
    let credential = encode_pin(role, generation, &verifying_key)?;

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&output_path)?;
    output.write_all(&credential)?;
    output.sync_all()?;
    let parent = output_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn encode_pin(
    role: PinRole,
    generation: u64,
    verifying_key: &VerifyingKey,
) -> Result<[u8; 80], Box<dyn std::error::Error>> {
    Ok(match role {
        PinRole::Policy(role) => {
            encode_policy_signer_credential_v1(role, generation, verifying_key)?
        }
        PinRole::Cache => {
            encode_cache_owner_readback_signer_credential_v1(generation, verifying_key)?
        }
        PinRole::ControllerHold => {
            encode_controller_hold_signer_credential_v1(generation, verifying_key)?
        }
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PinRole {
    Policy(PolicySignerRoleV1),
    Cache,
    ControllerHold,
}

fn parse_role(value: &str) -> Option<PinRole> {
    match value {
        "deployment" => Some(PinRole::Policy(PolicySignerRoleV1::Deployment)),
        "project" => Some(PinRole::Policy(PolicySignerRoleV1::Project)),
        "cache" => Some(PinRole::Cache),
        "controller-hold" => Some(PinRole::ControllerHold),
        _ => None,
    }
}

fn usage() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: aos-sandbox-policy-key-pin deployment|project|cache|controller-hold GENERATION PUBLIC_KEY_32B CREDENTIAL_OUT",
    )
}

#[cfg(test)]
mod tests {
    use aos_sandbox::cache_residency::PinnedCacheOwnerReadbackSignerV1;
    use aos_sandbox::policy_compiler::PinnedControllerHoldSignerV1;
    use aos_sandbox_broker_session_security::policy_signer_credential::PinnedPolicySignerV1;
    use ed25519_dalek::SigningKey;

    use super::*;

    #[test]
    fn role_parser_rejects_unscoped_signers() {
        assert_eq!(
            parse_role("deployment"),
            Some(PinRole::Policy(PolicySignerRoleV1::Deployment))
        );
        assert_eq!(
            parse_role("project"),
            Some(PinRole::Policy(PolicySignerRoleV1::Project))
        );
        assert_eq!(parse_role("cache"), Some(PinRole::Cache));
        assert_eq!(parse_role("controller-hold"), Some(PinRole::ControllerHold));
        assert_eq!(parse_role("root"), None);
    }

    #[test]
    fn cache_pin_cli_encoder_is_role_distinct() {
        let key = SigningKey::from_bytes(&[13; 32]).verifying_key();
        let credential = encode_pin(PinRole::Cache, 7, &key).expect("Cache pin");
        let cache = PinnedCacheOwnerReadbackSignerV1::decode(&credential).expect("Cache role");
        assert_eq!(cache.generation(), 7);
        assert!(PinnedPolicySignerV1::decode(PolicySignerRoleV1::Project, &credential).is_err());
        assert!(PinnedPolicySignerV1::decode(PolicySignerRoleV1::Deployment, &credential).is_err());
    }

    #[test]
    fn controller_hold_pin_cli_encoder_is_role_distinct() {
        let key = SigningKey::from_bytes(&[14; 32]).verifying_key();
        let credential = encode_pin(PinRole::ControllerHold, 8, &key).expect("Controller pin");
        let controller =
            PinnedControllerHoldSignerV1::decode(&credential).expect("Controller role");
        assert_eq!(controller.generation(), 8);
        assert!(PinnedCacheOwnerReadbackSignerV1::decode(&credential).is_err());
        assert!(PinnedPolicySignerV1::decode(PolicySignerRoleV1::Project, &credential).is_err());
        assert!(PinnedPolicySignerV1::decode(PolicySignerRoleV1::Deployment, &credential).is_err());
    }
}
