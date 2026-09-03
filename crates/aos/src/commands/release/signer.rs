//! Bounded external-signer process protocol for release coordination.
//!
//! Production signer executables receive one canonical signing request on
//! standard input and return one canonical response on standard output. The
//! coordinator supplies the exact public payload after the canonical request;
//! private-key selection remains entirely behind provider policy.

use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::signing::{
    SignatureResponseV1, SigningRequestV1, TrustedEd25519Key, verify_ed25519_response,
    verify_response_binding,
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::Command;

use crate::cli::{ReleaseSignerCommand, ReleaseSignerInvokeArgs};

use super::capture;

const MAX_SIGNER_RESPONSE_BYTES: u64 = 1024 * 1024;
const MAX_SIGNER_DIAGNOSTIC_BYTES: u64 = 64 * 1024;
const SIGNER_EXCHANGE_DOMAIN: &[u8] = b"aos.release.signer-exchange/v1\0";
const SIGNER_RESPONSE_DOMAIN: &[u8] = b"aos.release.signer-exchange-response/v1\0";

/// Runs one external-signer maintenance operation.
pub(super) async fn run(
    command: &ReleaseSignerCommand,
    printer: &aos_core::output::Printer,
) -> Result<()> {
    match command {
        ReleaseSignerCommand::Invoke(args) => invoke(args, printer).await,
    }
}

async fn invoke(args: &ReleaseSignerInvokeArgs, printer: &aos_core::output::Printer) -> Result<()> {
    let request_bytes = capture::control_file(&args.request, "signing request")?;
    let request: SigningRequestV1 = canonical::from_slice(&request_bytes, "signing request")?;
    let payload = capture::control_file(&args.payload, "signing payload")?;
    let (key_id, key_path) = parse_key_spec(&args.trusted_key)?;
    if key_id != request.key_id {
        bail!("trusted signer key id does not match the request");
    }
    let key_bytes = capture::control_file(key_path, "trusted signer public key")?;
    let trusted_key = TrustedEd25519Key::from_encoded(key_id, &key_bytes)?;
    let signer = ExternalSigner::new(
        args.executable.clone(),
        Duration::from_secs(args.timeout_seconds),
    )?;
    let response = signer
        .sign_ed25519(
            &request,
            &payload,
            &trusted_key,
            &args.verification_identity,
        )
        .await?;
    let response_bytes = canonical::to_vec(&response)?;
    write_new_file(&args.output, &response_bytes)?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.signer-result/v1",
        "request_digest": response.request_digest,
        "key_id": response.key_id,
        "provider_operation_id": response.provider_operation_id,
        "output": args.output,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Verified signer operation {} and wrote {}",
        response.provider_operation_id,
        args.output.display()
    ));
    Ok(())
}

fn parse_key_spec(value: &str) -> Result<(&str, &Path)> {
    let (key_id, path) = value
        .split_once('=')
        .context("trusted signer key must use KEY_ID=PATH")?;
    if key_id.is_empty() || path.is_empty() {
        bail!("trusted signer key must use nonempty KEY_ID=PATH");
    }
    Ok((key_id, Path::new(path)))
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating signer response beside {}", path.display()))?;
    temporary.write_all(bytes)?;
    temporary.as_file_mut().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)
        .with_context(|| format!("installing signer response {}", path.display()))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// A signer executable selected by deployment configuration.
pub(super) struct ExternalSigner {
    executable: PathBuf,
    timeout: Duration,
}

impl ExternalSigner {
    /// Creates an adapter for an exact executable path and bounded call time.
    pub(super) fn new(executable: PathBuf, timeout: Duration) -> Result<Self> {
        if !executable.is_absolute() {
            bail!("external signer executable path must be absolute");
        }
        if timeout.is_zero() || timeout > Duration::from_secs(15 * 60) {
            bail!("external signer timeout must be within 1ns..=15m");
        }
        validate_signer_executable(&executable)?;
        Ok(Self {
            executable,
            timeout,
        })
    }

    /// Requests and verifies one detached Ed25519 authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if the executable is invalid, times out, emits an
    /// oversized or noncanonical response, exits unsuccessfully, or returns a
    /// response that fails request binding or Ed25519 verification.
    pub(super) async fn sign_ed25519(
        &self,
        request: &SigningRequestV1,
        payload: &[u8],
        trusted_key: &TrustedEd25519Key,
        expected_verification_identity: &str,
    ) -> Result<SignatureResponseV1> {
        request.validate()?;
        verify_payload_binding(request, payload)?;
        let request_bytes = canonical::to_vec(request)?;
        let (response_bytes, output) = self.invoke(&request_bytes, payload, 0).await?;
        if !output.is_empty() {
            bail!("detached signer returned transformed output bytes");
        }
        let response: SignatureResponseV1 =
            canonical::from_slice(&response_bytes, "external signer response")?;
        verify_ed25519_response(request, &response, trusted_key)?;
        verify_public_identity(&response, trusted_key, expected_verification_identity)?;
        Ok(response)
    }

    /// Requests one bounded artifact transformation and verifies its binding.
    ///
    /// The caller must additionally verify the artifact's embedded signature
    /// against the independently captured certificate before accepting it.
    ///
    /// # Errors
    ///
    /// Returns an error for a payload mismatch, invalid provider exchange,
    /// response-policy drift, public identity mismatch, or output digest
    /// mismatch.
    pub(super) async fn transform(
        &self,
        request: &SigningRequestV1,
        payload: &[u8],
        maximum_output_bytes: u64,
        expected_verification_identity: &str,
        expected_verification_material_digest: Sha256Digest,
    ) -> Result<(SignatureResponseV1, Vec<u8>)> {
        request.validate()?;
        verify_payload_binding(request, payload)?;
        let request_bytes = canonical::to_vec(request)?;
        let (response_bytes, output) = self
            .invoke(&request_bytes, payload, maximum_output_bytes)
            .await?;
        let response: SignatureResponseV1 =
            canonical::from_slice(&response_bytes, "external signer response")?;
        verify_response_binding(request, &response)?;
        if response.verification_identity != expected_verification_identity
            || response.verification_material_digest != expected_verification_material_digest
        {
            bail!("external signer returned unexpected public verification material");
        }
        if response.output_digest != Some(Sha256Digest::of_bytes(&output)) {
            bail!("external signer transformed output digest does not match its bytes");
        }
        Ok((response, output))
    }

    async fn invoke(
        &self,
        request: &[u8],
        payload: &[u8],
        maximum_output_bytes: u64,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut child = Command::new(&self.executable)
            .arg("sign-exchange-v1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| {
                format!(
                    "starting external signer executable {}",
                    self.executable.display()
                )
            })?;
        let mut stdin = child
            .stdin
            .take()
            .context("external signer has no standard input")?;
        stdin.write_all(SIGNER_EXCHANGE_DOMAIN).await?;
        stdin
            .write_all(&u64::try_from(request.len())?.to_be_bytes())
            .await?;
        stdin.write_all(request).await?;
        stdin
            .write_all(&u64::try_from(payload.len())?.to_be_bytes())
            .await?;
        stdin.write_all(payload).await?;
        stdin.shutdown().await?;
        drop(stdin);

        let stdout = child
            .stdout
            .take()
            .context("external signer has no standard output")?;
        let stderr = child
            .stderr
            .take()
            .context("external signer has no diagnostic output")?;
        let exchange = async {
            let wait = async { Ok::<_, anyhow::Error>(child.wait().await?) };
            let (status, stdout, stderr) = tokio::try_join!(
                wait,
                read_exchange_response(stdout, maximum_output_bytes),
                read_bounded(stderr, MAX_SIGNER_DIAGNOSTIC_BYTES),
            )?;
            Ok::<_, anyhow::Error>((status, stdout, stderr))
        };
        let (status, exchange_response, stderr) = tokio::time::timeout(self.timeout, exchange)
            .await
            .context("external signer timed out")??;
        if !status.success() {
            let diagnostic = String::from_utf8_lossy(&stderr);
            bail!(
                "external signer exited unsuccessfully: {}",
                diagnostic.trim()
            );
        }
        if !stderr.is_empty() {
            bail!("external signer wrote diagnostics on a successful request");
        }
        Ok(exchange_response)
    }
}

fn verify_payload_binding(request: &SigningRequestV1, payload: &[u8]) -> Result<()> {
    if Sha256Digest::of_bytes(payload) != request.payload_digest {
        bail!("signer payload does not match the request digest");
    }
    Ok(())
}

async fn read_bounded(reader: impl AsyncRead + Unpin, maximum: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(maximum + 1).read_to_end(&mut bytes).await?;
    if u64::try_from(bytes.len())? > maximum {
        bail!("external signer output exceeds its byte limit");
    }
    Ok(bytes)
}

async fn read_exchange_response(
    mut reader: impl AsyncRead + Unpin,
    maximum_output_bytes: u64,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut domain = vec![0_u8; SIGNER_RESPONSE_DOMAIN.len()];
    reader.read_exact(&mut domain).await?;
    if domain != SIGNER_RESPONSE_DOMAIN {
        bail!("external signer returned the wrong response framing domain");
    }
    let response_length = read_u64(&mut reader).await?;
    if response_length == 0 || response_length > MAX_SIGNER_RESPONSE_BYTES {
        bail!("external signer response JSON exceeds its byte limit");
    }
    let mut response = vec![0_u8; usize::try_from(response_length)?];
    reader.read_exact(&mut response).await?;

    let output_length = read_u64(&mut reader).await?;
    if output_length > maximum_output_bytes {
        bail!("external signer transformed output exceeds its byte limit");
    }
    let mut output = vec![0_u8; usize::try_from(output_length)?];
    reader.read_exact(&mut output).await?;
    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing).await? != 0 {
        bail!("external signer returned trailing exchange bytes");
    }
    Ok((response, output))
}

async fn read_u64(reader: &mut (impl AsyncRead + Unpin)) -> Result<u64> {
    let mut bytes = [0_u8; 8];
    reader.read_exact(&mut bytes).await?;
    Ok(u64::from_be_bytes(bytes))
}

fn verify_public_identity(
    response: &SignatureResponseV1,
    trusted_key: &TrustedEd25519Key,
    expected_verification_identity: &str,
) -> Result<()> {
    if response.verification_identity != expected_verification_identity {
        bail!("external signer returned an unexpected verification identity");
    }
    if response.verification_material_digest != Sha256Digest::of_bytes(trusted_key.public_key) {
        bail!("external signer returned the wrong public verification material digest");
    }
    Ok(())
}

/// Rejects an executable that is absent, non-regular, or group/world writable.
pub(super) fn validate_signer_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = path
        .symlink_metadata()
        .with_context(|| format!("inspecting external signer {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        bail!("external signer must be a single-link regular file");
    }
    if metadata.mode() & 0o022 != 0 {
        bail!("external signer cannot be group- or world-writable");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use aos_release::signing::{SignatureAlgorithm, SignerRole, SigningContext, SigningOperation};

    use super::*;

    #[test]
    fn signer_configuration_requires_an_absolute_bounded_command() {
        assert!(ExternalSigner::new(PathBuf::from("signer"), Duration::from_secs(30)).is_err());
        assert!(ExternalSigner::new(PathBuf::from("/provider/signer"), Duration::ZERO).is_err());
        assert!(
            ExternalSigner::new(PathBuf::from("/provider/signer"), Duration::from_secs(901))
                .is_err()
        );
    }

    #[test]
    fn public_identity_is_independently_pinned() {
        let key = TrustedEd25519Key {
            key_id: "release-key".to_owned(),
            public_key: [7; 32],
        };
        let response = SignatureResponseV1 {
            schema_version: "aos.release.signature-response/v1".to_owned(),
            request_digest: Sha256Digest::of_bytes("request"),
            role: SignerRole::ReleaseEvidence,
            key_id: key.key_id.clone(),
            provider_revision: "provider-v1".to_owned(),
            algorithm: SignatureAlgorithm::Ed25519,
            provider_operation_id: "operation-1".to_owned(),
            verification_identity: "device-slot-1".to_owned(),
            verification_material_digest: Sha256Digest::of_bytes(key.public_key),
            output_digest: None,
            signature_base64: String::new(),
        };
        assert!(verify_public_identity(&response, &key, "device-slot-1").is_ok());
        assert!(verify_public_identity(&response, &key, "device-slot-2").is_err());
    }

    #[test]
    fn payload_bytes_must_match_the_reviewed_request() {
        let request = payload_request();
        assert!(verify_payload_binding(&request, b"payload").is_ok());
        assert!(verify_payload_binding(&request, b"different").is_err());
    }

    #[allow(dead_code)]
    fn payload_request() -> SigningRequestV1 {
        SigningRequestV1 {
            schema_version: "aos.release.signing-request/v1".to_owned(),
            request_id: "request-1".to_owned(),
            nonce: "00".repeat(32),
            registry: aos_release::CANONICAL_REGISTRY.to_owned(),
            release_id: "release-1".to_owned(),
            plan_digest: Sha256Digest::of_bytes("plan"),
            manifest_digest: None,
            role: SignerRole::ReleaseEvidence,
            key_id: "release-key".to_owned(),
            provider_revision: "provider-v1".to_owned(),
            algorithm: SignatureAlgorithm::Ed25519,
            operation: SigningOperation::SignPayload,
            context: SigningContext::Payload {
                artifact_kind: "evidence".to_owned(),
            },
            payload_digest: Sha256Digest::of_bytes(b"payload"),
            approval_policy_digest: Sha256Digest::of_bytes("approval"),
        }
    }
}
