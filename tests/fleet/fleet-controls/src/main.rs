//! Prepares private fleet controls using the deployed shared wire codecs.
//!
//! This fixture signs requests and verifies correlated replies. It grants no
//! provider authority and reports no qualification or transport observations.
//!
//! The fleet reviewer retains this helper's source, fixture lock, executable
//! and shared source revision before selecting it at `shared-runtime-controls`.
//! Set `AOS_FLEET_CONTROL_CODEC_REVISION` to the independently checked shared
//! source commit when building this fixture through `cargo-shell.nix`. Execute
//! the resulting binary directly with one owner-private selection JSON path.
//! The revision names the shared codecs; the helper source has its own digest.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Result};
use aos_hub_db::hybrid_ingress::{HybridIngressAssertion, HybridIngressKey};
use aos_hub_db::storage_authority::lease::control::{
    sign_issuer_request, verify_issuer_reply_at_time, IssuerInstallation, IssuerOperation,
    IssuerRequest,
};
use aos_hub_db::storage_authority::lease::{EpochLeaseVerifier, LeaseClock, LeaseInteger};
use aos_hub_db::storage_work::StorageWorkKey;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Selection {
    IngressPrepare {
        key_file: PathBuf,
        deployment_id: String,
        authority: String,
        method: String,
        path_and_query: String,
        body_file: PathBuf,
        signed_phase: Option<String>,
        header_phase: Option<String>,
        output_directory: PathBuf,
    },
    IssuerPrepare {
        key_file: PathBuf,
        installation: IssuerInstallation,
        operation: IssuerOperation,
        output_directory: PathBuf,
    },
    IssuerVerify {
        request_file: PathBuf,
        reply_file: PathBuf,
        issuer_key_id: String,
        issuer_public_key: String,
        uncertainty_seconds: i64,
        previous_observed_seconds: i64,
        output_directory: PathBuf,
    },
}

fn now() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}

fn read(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    // Fleet guests are Linux; refuse links and avoid blocking on special files.
    const LINUX_NOFOLLOW_NONBLOCK: i32 = 0x20000 | 0x800;
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(LINUX_NOFOLLOW_NONBLOCK)
        .open(path)?;
    let metadata = input.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.permissions().mode() & 0o077 == 0
            && metadata.nlink() == 1
            && metadata.uid() == fs::metadata("/proc/self")?.uid(),
        "fixture input must be an owner-private regular file"
    );
    ensure!(metadata.len() <= maximum, "fixture input exceeds bound");
    let mut bytes = Vec::new();
    Read::by_ref(&mut input)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    let after = input.metadata()?;
    ensure!(
        bytes.len() as u64 == metadata.len()
            && after.mtime_nsec() == metadata.mtime_nsec()
            && after.mtime() == metadata.mtime()
            && after.ctime_nsec() == metadata.ctime_nsec()
            && after.ctime() == metadata.ctime()
            && after.len() == metadata.len(),
        "fixture input changed"
    );
    Ok(bytes)
}

fn key(path: &Path) -> Result<Vec<u8>> {
    let bytes = read(path, 65536)?;
    ensure!(bytes.len() >= 32, "fixture key length differs");
    Ok(bytes)
}

fn nonce() -> Result<String> {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex::encode(bytes))
}

fn write(directory: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(name))?;
    output.write_all(bytes)?;
    output.sync_all()?;
    Ok(())
}

fn directory(path: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn execute(selection: Selection) -> Result<Value> {
    match selection {
        Selection::IngressPrepare {
            key_file,
            deployment_id,
            authority,
            method,
            path_and_query,
            body_file,
            signed_phase,
            header_phase,
            output_directory,
        } => {
            let body = read(&body_file, 8 * 1024 * 1024)?;
            let observed = now()?;
            let assertion = HybridIngressAssertion {
                version: 1,
                deployment_id,
                issued_at: observed,
                expires_at: observed + 30,
                request_id: nonce()?,
                scheme: "https".into(),
                authority,
                method,
                path_and_query,
                body_sha256: digest(&body),
                upload_phase: signed_phase,
                client_ip: "192.0.2.10".into(),
            };
            let compact = HybridIngressKey::new(key(&key_file)?)?.sign(&assertion)?;
            let mut headers = format!("x-aos-hybrid-ingress: {compact}\n");
            if let Some(phase) = header_phase {
                ensure!(
                    matches!(phase.as_str(), "preflight" | "admit"),
                    "unsupported phase"
                );
                headers.push_str(&format!("x-aos-hybrid-upload-phase: {phase}\n"));
            }
            directory(&output_directory)?;
            write(&output_directory, "headers.txt", headers.as_bytes())?;
            Ok(json!({"requestSha256": digest(&serde_json::to_vec(&assertion)?)}))
        }
        Selection::IssuerPrepare {
            key_file,
            installation,
            operation,
            output_directory,
        } => {
            let observed = now()?;
            let request = IssuerRequest {
                protocol_version: 1,
                installation,
                nonce: nonce()?,
                issued_at: LeaseInteger::new(observed)?,
                expires_at: LeaseInteger::new(observed + 30)?,
                operation,
            };
            request.validate(&request.installation, observed)?;
            let bytes = serde_json::to_vec(&request)?;
            let signature = sign_issuer_request(&StorageWorkKey::new(key(&key_file)?)?, &bytes)?;
            let headers = format!(
                "Content-Type: application/json\nx-aos-storage-work-signature: {signature}\n"
            );
            directory(&output_directory)?;
            write(&output_directory, "request.json", &bytes)?;
            write(&output_directory, "headers.txt", headers.as_bytes())?;
            Ok(
                json!({"requestSha256": digest(&bytes), "observedAtSeconds": observed,
                "expiresAtSeconds": observed + 30}),
            )
        }
        Selection::IssuerVerify {
            request_file,
            reply_file,
            issuer_key_id,
            issuer_public_key,
            uncertainty_seconds,
            previous_observed_seconds,
            output_directory,
        } => {
            let request = IssuerRequest::decode(&read(&request_file, 1024 * 1024)?)?;
            let bytes = read(&reply_file, 1024 * 1024)?;
            let public: [u8; 32] = hex::decode(issuer_public_key)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid public key size"))?;
            let verifier = EpochLeaseVerifier::from_bytes(issuer_key_id, &public)?;
            let mut observed = 0;
            let reply = verify_issuer_reply_at_time(&verifier, &request, &bytes, || {
                observed = now()?;
                ensure!(observed >= previous_observed_seconds, "clock rolled back");
                Ok(LeaseClock {
                    observed_at: observed,
                    uncertainty: uncertainty_seconds,
                })
            })?;
            directory(&output_directory)?;
            write(
                &output_directory,
                "verified-reply.json",
                &serde_json::to_vec(&reply)?,
            )?;
            Ok(
                json!({"replySha256": digest(&bytes), "observedAtSeconds": observed,
                "journalSha256": digest(&serde_json::to_vec(&reply.current.journal)?),
                "tokenSha256": reply.lease.as_ref().map(|token| digest(token.as_bytes()))}),
            )
        }
    }
}

fn run() -> Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("selection required"))?;
    let selection = serde_json::from_slice(&read(Path::new(&path), 65536)?)?;
    let mut report = execute(selection)?;
    report["version"] = json!(1);
    report["codecRevision"] = json!(option_env!("AOS_FLEET_CONTROL_CODEC_REVISION")
        .ok_or_else(|| anyhow::anyhow!("explicit codec revision required"))?);
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn main() {
    if run().is_err() {
        eprintln!("fleet control preparation or verification refused");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests;
