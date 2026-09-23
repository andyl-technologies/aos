//! Admits externally signed deployment policy inputs under root-owned custody.
//!
//! This one-shot service commits only the monotonic deployment input head. It
//! cannot issue compiler candidate bindings or authorize Create effects.

use std::{
    error::Error,
    fs::File,
    io::{self, Read as _},
    path::Path,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use aos_sandbox::policy_compiler::{
    PolicyDeploymentInputsV1, admit_fixed_policy_deployment_head_v1,
};
use ed25519_dalek::VerifyingKey;

const CREDENTIAL_ROOT: &str = "/run/credentials/aos-sandbox-policy-authorityd.service";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-policy-authorityd: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    if rustix::process::geteuid().as_raw() != 0 || rustix::process::getuid().as_raw() != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "root required").into());
    }

    let root = Path::new(CREDENTIAL_ROOT);
    let key_bytes = read_bounded(&root.join("deployment-public-key"), 32)?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid public key length"))?;
    let verifying_key = VerifyingKey::from_bytes(&key_array)?;
    let packet = read_bounded(&root.join("deployment-head.packet"), 224)?;
    let node = read_bounded(&root.join("node-policy.json"), 64 * 1024)?;
    let site = read_bounded(&root.join("site-policy.json"), 64 * 1024)?;
    let backend = read_bounded(&root.join("backend-capabilities.json"), 64 * 1024)?;
    let catalogs = read_bounded(&root.join("catalogs.json"), 64 * 1024)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let now_unix_seconds = i64::try_from(now.as_secs())?;

    let inputs = PolicyDeploymentInputsV1 {
        node: &node,
        site: &site,
        backend: &backend,
        catalogs: &catalogs,
    };
    admit_fixed_policy_deployment_head_v1(&packet, &inputs, &verifying_key, now_unix_seconds)?;
    Ok(())
}

fn read_bounded(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "credential size",
        ));
    }
    Ok(bytes)
}
