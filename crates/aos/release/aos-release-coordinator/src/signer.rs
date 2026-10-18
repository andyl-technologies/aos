//! Bounded external-signer process protocol for release coordination.
//!
//! Production signer executables receive one canonical signing request on
//! standard input and return one canonical response on standard output. The
//! coordinator supplies the exact public payload after the canonical request;
//! private-key selection remains entirely behind provider policy.
//!
//! The executable is either an external provider named by the maintainer
//! configuration or a `--signer-executable` flag, or, when none is named, the
//! file-backed `aos-release-signer` bundled in the installed
//! [tooling closure](super::tooling). A configured signer configuration path
//! reaches the child as `AOS_RELEASE_SIGNER_CONFIG`; nothing else about the
//! provider's key custody passes through the coordinator.

use std::fs::File;
use std::io::{Read as _, Seek as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use aos_image_finalizer::signer::ImageSigner;
use aos_release_format::canonical;
use aos_release_format::digest::Sha256Digest;
use aos_release_format::signing::{
    SignatureResponse, SigningRequest, TrustedEd25519Key, verify_ed25519_response,
    verify_response_binding,
};
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::Command;

use super::config::SignerConfig;
use super::tooling::{self, ToolingEnvironment};

/// Environment variable through which the spawned signer receives its
/// configuration path; `aos-release-signer` reads the same name.
const SIGNER_CONFIG_ENVIRONMENT: &str = "AOS_RELEASE_SIGNER_CONFIG";

/// The only operation the coordinator asks a signer executable to perform.
const SIGNER_EXCHANGE_OPERATION: &str = "sign-exchange-v1";

const MAX_SIGNER_RESPONSE_BYTES: u64 = 1024 * 1024;
const MAX_SIGNER_DIAGNOSTIC_BYTES: u64 = 64 * 1024;
const SIGNER_EXCHANGE_DOMAIN: &[u8] = b"aos.release.signer-exchange/v1\0";
const SIGNER_RESPONSE_DOMAIN: &[u8] = b"aos.release.signer-exchange-response/v1\0";

/// The signer executable the coordinator spawns and the configuration it
/// hands to that executable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerProgram {
    executable: PathBuf,
    config: Option<PathBuf>,
}

impl SignerProgram {
    /// Selects an explicit executable, else the tooling closure's bundled
    /// signer.
    ///
    /// An explicit executable keeps the external-provider contract: the
    /// signer configuration is optional and passed through only when given.
    /// Without one, the bundled `aos-release-signer` is used and `config` is
    /// required, because that signer cannot run without its key map.
    ///
    /// # Errors
    /// Returns an error for a relative executable or configuration path, an
    /// executable that fails immutable-store validation, a missing
    /// configuration for the bundled signer, or a process that does not run
    /// from release tooling that bundles a signer.
    pub fn resolve(executable: Option<&Path>, config: Option<&Path>) -> Result<Self> {
        Self::resolve_with(executable, config, ToolingEnvironment::require)
    }

    /// Implements [`Self::resolve`] against an explicit tooling lookup, which
    /// runs only when the bundled signer is selected.
    fn resolve_with(
        executable: Option<&Path>,
        config: Option<&Path>,
        tooling: impl FnOnce() -> Result<ToolingEnvironment>,
    ) -> Result<Self> {
        if config.is_some_and(|config| !config.is_absolute()) {
            bail!("signer configuration path must be absolute");
        }

        let executable = match executable {
            Some(executable) => {
                if !executable.is_absolute() {
                    bail!("external signer executable path must be absolute");
                }
                validate_signer_executable(executable)?;
                executable.to_path_buf()
            }
            None if config.is_none() => bail!(
                "the bundled release signer needs its configuration file \
                 ([signer] config, --signer-config, or --authority-config); \
                 otherwise name an external signer executable"
            ),
            None => {
                let tooling = tooling().context("locating the bundled release signer")?;
                tooling.signer()?.to_path_buf()
            }
        };

        Ok(Self {
            executable,
            config: config.map(Path::to_path_buf),
        })
    }

    /// Builds the `sign-exchange-v1` child command.
    ///
    /// The configuration travels in the environment rather than as a
    /// `--config` argument: external providers share only the fixed
    /// operation argument with the coordinator, while an environment
    /// variable they do not read is harmless. A configured path replaces any
    /// value the coordinator itself inherited.
    fn command(&self) -> Command {
        let mut command = Command::new(&self.executable);
        if let Some(config) = &self.config {
            command.env(SIGNER_CONFIG_ENVIRONMENT, config);
        }
        command.arg(SIGNER_EXCHANGE_OPERATION);
        command
    }
}

/// A signer executable selected by deployment configuration.
pub struct ExternalSigner {
    program: SignerProgram,
    timeout: Duration,
}

impl ExternalSigner {
    /// Creates an adapter for a selected signer program and bounded call time.
    ///
    /// # Errors
    /// Returns an error when `timeout` is zero or longer than 15 minutes.
    pub fn new(program: SignerProgram, timeout: Duration) -> Result<Self> {
        if timeout.is_zero() || timeout > Duration::from_secs(15 * 60) {
            bail!("external signer timeout must be within 1ns..=15m");
        }
        Ok(Self { program, timeout })
    }

    /// Creates an adapter from an optional executable and configuration, as
    /// given to the leaf `step` commands.
    ///
    /// # Errors
    /// Returns the errors of [`SignerProgram::resolve`] and [`Self::new`].
    pub fn resolve(
        executable: Option<&Path>,
        config: Option<&Path>,
        timeout: Duration,
    ) -> Result<Self> {
        Self::new(SignerProgram::resolve(executable, config)?, timeout)
    }

    /// Creates an adapter from the maintainer configuration's `[signer]`.
    ///
    /// # Errors
    /// Returns the errors of [`Self::resolve`].
    pub fn configured(config: &SignerConfig) -> Result<Self> {
        Self::resolve(
            config.executable.as_deref(),
            config.config.as_deref(),
            config.timeout(),
        )
    }

    /// Requests and verifies one detached Ed25519 authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if the executable is invalid, times out, emits an
    /// oversized or noncanonical response, exits unsuccessfully, or returns a
    /// response that fails request binding or Ed25519 verification.
    pub async fn sign_ed25519(
        &self,
        request: &SigningRequest,
        payload: &[u8],
        trusted_key: &TrustedEd25519Key,
        expected_verification_identity: &str,
    ) -> Result<SignatureResponse> {
        request.validate()?;
        verify_payload_binding(request, payload)?;
        let request_bytes = canonical::to_vec(request)?;
        let (response_bytes, output) = self.invoke(&request_bytes, payload, 0).await?;
        if !output.is_empty() {
            bail!("detached signer returned transformed output bytes");
        }
        let response: SignatureResponse =
            canonical::from_slice(&response_bytes, "external signer response")?;
        verify_ed25519_response(request, &response, trusted_key)?;
        verify_public_identity(&response, trusted_key, expected_verification_identity)?;
        Ok(response)
    }

    /// Requests and verifies one detached OpenSSH SSHSIG authorization.
    ///
    /// `trusted_key` is the exact `registry:Ed25519:<base64>` trust line
    /// committed in the registry roster. The provider must report the SHA-256
    /// identity of those exact UTF-8 bytes as its verification-material digest.
    ///
    /// # Errors
    ///
    /// Returns an error for request or provider-binding drift, transformed
    /// output, malformed signature armor, verification-material mismatch, or
    /// a signature that does not verify over `payload` in `namespace`.
    pub async fn sign_sshsig(
        &self,
        request: &SigningRequest,
        payload: &[u8],
        trusted_key: &str,
        namespace: &str,
        expected_verification_identity: &str,
    ) -> Result<(SignatureResponse, String)> {
        request.validate()?;
        verify_payload_binding(request, payload)?;
        let request_bytes = canonical::to_vec(request)?;
        let (response_bytes, output) = self.invoke(&request_bytes, payload, 0).await?;
        if !output.is_empty() {
            bail!("detached SSHSIG signer returned transformed output bytes");
        }
        let response: SignatureResponse =
            canonical::from_slice(&response_bytes, "external SSHSIG response")?;
        verify_response_binding(request, &response)?;
        if response.verification_identity != expected_verification_identity {
            bail!("external SSHSIG signer returned an unexpected verification identity");
        }
        if response.verification_material_digest != Sha256Digest::of_bytes(trusted_key.as_bytes()) {
            bail!("external SSHSIG signer returned the wrong public verification material digest");
        }
        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(&response.signature_base64)
            .context("decoding external SSHSIG armor")?;
        let signature = String::from_utf8(signature_bytes)
            .context("external SSHSIG armor is not valid UTF-8")?;
        if !aos_registry_client::security::verify_payload_signature(
            payload,
            &signature,
            trusted_key,
            namespace,
        )? {
            bail!("external SSHSIG does not verify against the trusted roster key");
        }
        Ok((response, signature))
    }

    /// Requests and verifies a raw Ed25519 signature over exact payload bytes.
    ///
    /// This mode exists for wire formats such as Nix narinfo whose signature
    /// grammar cannot embed the release request. Provider policy still receives
    /// and audits the complete request; the coordinator verifies the returned
    /// raw signature against independently pinned key material.
    ///
    /// # Errors
    ///
    /// Returns an error for request drift, transformed output, provider/public
    /// identity mismatch, malformed signature bytes, or failed verification.
    pub async fn sign_ed25519_payload(
        &self,
        request: &SigningRequest,
        payload: &[u8],
        trusted_key: &TrustedEd25519Key,
        expected_verification_identity: &str,
    ) -> Result<SignatureResponse> {
        request.validate()?;
        verify_payload_binding(request, payload)?;
        let request_bytes = canonical::to_vec(request)?;
        let (response_bytes, output) = self.invoke(&request_bytes, payload, 0).await?;
        if !output.is_empty() {
            bail!("raw Ed25519 signer returned transformed output bytes");
        }
        let response: SignatureResponse =
            canonical::from_slice(&response_bytes, "external payload-signature response")?;
        verify_response_binding(request, &response)?;
        verify_public_identity(&response, trusted_key, expected_verification_identity)?;
        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(&response.signature_base64)
            .context("decoding raw Ed25519 payload signature")?;
        let signature = Signature::from_slice(&signature_bytes)
            .context("parsing raw Ed25519 payload signature")?;
        let key = VerifyingKey::from_bytes(&trusted_key.public_key)
            .context("parsing trusted payload-signing key")?;
        key.verify(payload, &signature)
            .context("verifying raw Ed25519 payload signature")?;
        Ok(response)
    }

    /// Starts the signer with piped standard streams.
    fn spawn(&self) -> Result<tokio::process::Child> {
        self.program
            .command()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| {
                format!(
                    "starting external signer executable {}",
                    self.program.executable.display()
                )
            })
    }

    async fn invoke(
        &self,
        request: &[u8],
        payload: &[u8],
        maximum_output_bytes: u64,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut child = self.spawn()?;
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

    async fn invoke_file(
        &self,
        request: &SigningRequest,
        input: &Path,
        output: Option<(&Path, u64)>,
    ) -> Result<SignatureResponse> {
        request.validate()?;
        let input_capture = CapturedInput::open(input)?;
        if input_capture.digest != request.payload_digest {
            bail!("signer input does not match the request digest");
        }
        let request_bytes = canonical::to_vec(request)?;
        let maximum_output_bytes = output.map_or(0, |(_, maximum)| maximum);
        let mut temporary = match output {
            Some((path, _)) => Some(new_output_temporary(path)?),
            None => None,
        };

        let mut child = self.spawn()?;
        let stdin = child
            .stdin
            .take()
            .context("external signer has no standard input")?;
        let stdout = child
            .stdout
            .take()
            .context("external signer has no standard output")?;
        let stderr = child
            .stderr
            .take()
            .context("external signer has no diagnostic output")?;
        let input_file = tokio::fs::File::from_std(input_capture.file.try_clone()?);
        let output_file = temporary
            .as_ref()
            .map(tempfile::NamedTempFile::reopen)
            .transpose()?
            .map(tokio::fs::File::from_std);

        let write_request =
            write_file_exchange(stdin, &request_bytes, input_file, input_capture.size);
        let read_response =
            read_exchange_response_to_file(stdout, maximum_output_bytes, output_file);
        let exchange = async {
            let wait = async { Ok::<_, anyhow::Error>(child.wait().await?) };
            let ((), (response, output_digest), stderr, status) = tokio::try_join!(
                write_request,
                read_response,
                read_bounded(stderr, MAX_SIGNER_DIAGNOSTIC_BYTES),
                wait,
            )?;
            Ok::<_, anyhow::Error>((status, response, output_digest, stderr))
        };
        let (status, response_bytes, output_digest, stderr) =
            tokio::time::timeout(self.timeout, exchange)
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
        input_capture.verify_unchanged(input)?;

        let response: SignatureResponse =
            canonical::from_slice(&response_bytes, "external signer response")?;
        verify_response_binding(request, &response)?;
        if response.output_digest != output_digest {
            bail!("external signer transformed output digest does not match its bytes");
        }
        match (output, temporary.take(), output_digest) {
            (Some((path, _)), Some(temporary), Some(_)) => persist_output(temporary, path)?,
            (Some(_), _, None) => bail!("transforming signer returned no output bytes"),
            (None, _, Some(_)) => bail!("detached signer returned transformed output bytes"),
            (None, _, None) => {}
            _ => bail!("external signer output state is inconsistent"),
        }
        Ok(response)
    }
}

#[async_trait::async_trait]
impl ImageSigner for ExternalSigner {
    async fn transform(
        &self,
        request: &SigningRequest,
        input: &Path,
        output: &Path,
        maximum_output_bytes: u64,
    ) -> Result<SignatureResponse> {
        if maximum_output_bytes == 0 {
            bail!("signer transformed-output limit must be nonzero");
        }
        self.invoke_file(request, input, Some((output, maximum_output_bytes)))
            .await
    }

    async fn sign_detached(
        &self,
        request: &SigningRequest,
        input: &Path,
    ) -> Result<SignatureResponse> {
        self.invoke_file(request, input, None).await
    }
}

struct CapturedInput {
    file: File,
    metadata: std::fs::Metadata,
    size: u64,
    digest: Sha256Digest,
}

impl CapturedInput {
    fn open(path: &Path) -> Result<Self> {
        use sha2::{Digest as _, Sha256};

        let mut file =
            File::open(path).with_context(|| format!("opening signer input {}", path.display()))?;
        let metadata = file.metadata()?;
        let path_metadata = path.symlink_metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || path_metadata.dev() != metadata.dev()
            || path_metadata.ino() != metadata.ino()
        {
            bail!("signer input must be a single-link regular file, not a symbolic link");
        }
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        let mut size = 0_u64;
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            size = size
                .checked_add(u64::try_from(count)?)
                .context("signer input size overflow")?;
            hasher.update(&buffer[..count]);
        }
        if size != metadata.len() {
            bail!("signer input changed while it was captured");
        }
        file.rewind()?;
        Ok(Self {
            file,
            metadata,
            size,
            digest: Sha256Digest::from_bytes(hasher.finalize().into()),
        })
    }

    fn verify_unchanged(&self, path: &Path) -> Result<()> {
        let current = path.symlink_metadata()?;
        if current.dev() != self.metadata.dev()
            || current.ino() != self.metadata.ino()
            || current.len() != self.metadata.len()
            || current.mtime() != self.metadata.mtime()
            || current.mtime_nsec() != self.metadata.mtime_nsec()
        {
            bail!("signer input changed during the provider operation");
        }
        Ok(())
    }
}

fn new_output_temporary(path: &Path) -> Result<tempfile::NamedTempFile> {
    if path.symlink_metadata().is_ok() {
        bail!("signer output already exists");
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating signer output beside {}", path.display()))
}

fn persist_output(temporary: tempfile::NamedTempFile, path: &Path) -> Result<()> {
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)
        .with_context(|| format!("installing signer output {}", path.display()))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()?;
    Ok(())
}

async fn write_file_exchange(
    mut writer: impl tokio::io::AsyncWrite + Unpin,
    request: &[u8],
    mut input: tokio::fs::File,
    input_size: u64,
) -> Result<()> {
    writer.write_all(SIGNER_EXCHANGE_DOMAIN).await?;
    writer
        .write_all(&u64::try_from(request.len())?.to_be_bytes())
        .await?;
    writer.write_all(request).await?;
    writer.write_all(&input_size.to_be_bytes()).await?;
    let copied = tokio::io::copy(&mut input, &mut writer).await?;
    if copied != input_size {
        bail!("signer input changed while it was streamed");
    }
    writer.shutdown().await?;
    Ok(())
}

async fn read_exchange_response_to_file(
    mut reader: impl AsyncRead + Unpin,
    maximum_output_bytes: u64,
    mut output: Option<tokio::fs::File>,
) -> Result<(Vec<u8>, Option<Sha256Digest>)> {
    use sha2::{Digest as _, Sha256};

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
    if output_length == 0 {
        if output.is_some() {
            bail!("transforming signer returned an empty output");
        }
    } else if output.is_none() {
        bail!("detached signer returned transformed output bytes");
    }
    let mut hasher = Sha256::new();
    let mut remaining = output_length;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))?;
        reader.read_exact(&mut buffer[..wanted]).await?;
        if let Some(file) = output.as_mut() {
            file.write_all(&buffer[..wanted]).await?;
        }
        hasher.update(&buffer[..wanted]);
        remaining -= u64::try_from(wanted)?;
    }
    if let Some(file) = output.as_mut() {
        file.sync_all().await?;
    }
    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing).await? != 0 {
        bail!("external signer returned trailing exchange bytes");
    }
    let digest = (output_length != 0).then(|| Sha256Digest::from_bytes(hasher.finalize().into()));
    Ok((response, digest))
}

fn verify_payload_binding(request: &SigningRequest, payload: &[u8]) -> Result<()> {
    request.verify_payload_bytes(payload)
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
    response: &SignatureResponse,
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

/// Rejects an executable that is absent, non-regular, aliased by another
/// hard link, or group/world writable.
///
/// A program with one link has exactly one name: the path the operator
/// configured and reviewed. A second link publishes the same inode under a
/// name outside that review, so a program normally needs exactly one link.
/// Nix store files are the exception: store optimisation
/// (`auto-optimise-store` or `nix-store --optimise`) hard-links identical
/// files through `/nix/store/.links`, so the bundled signer and executors of
/// an optimised tooling closure have several links. Those links cannot alter
/// the program: a store file is read-only once its path is valid, and the
/// tooling closure's path is already the `tooling` fitness binding. A file
/// that resolves into the store and carries no write permission bit at all
/// is therefore accepted with any link count.
///
/// # Errors
/// Returns an error when `path` cannot be inspected or fails a check above.
pub fn validate_signer_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = path
        .symlink_metadata()
        .with_context(|| format!("inspecting external signer {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("external signer must be a single-link regular file");
    }
    if metadata.nlink() != 1 && !immutable_store_file(path, metadata.mode()) {
        bail!("external signer must be a single-link regular file");
    }
    if metadata.mode() & 0o022 != 0 {
        bail!("external signer cannot be group- or world-writable");
    }
    Ok(())
}

/// Reports whether `path` is a read-only file inside the Nix store, whose
/// extra hard links come from store optimisation rather than aliasing.
fn immutable_store_file(path: &Path, mode: u32) -> bool {
    mode & 0o222 == 0 && tooling::resolves_into_store(path)
}

#[cfg(test)]
mod tests {
    use aos_release_format::signing::{
        SignatureAlgorithm, SignerRole, SigningContext, SigningOperation,
    };

    use super::*;

    /// A tooling lookup that must not run.
    fn no_tooling() -> Result<ToolingEnvironment> {
        bail!("the tooling closure must not be consulted")
    }

    /// Writes an executable at `path` with the given mode.
    fn write_program(path: &Path, mode: u32) -> Result<PathBuf> {
        use std::os::unix::fs::PermissionsExt as _;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, b"#!/bin/sh\nexit 0\n")?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        Ok(path.to_path_buf())
    }

    /// Returns the value the child command receives for the signer
    /// configuration variable, if the command sets one.
    fn child_config(program: &SignerProgram) -> Option<PathBuf> {
        program
            .command()
            .as_std()
            .get_envs()
            .find(|(name, _)| *name == SIGNER_CONFIG_ENVIRONMENT)
            .and_then(|(_, value)| value.map(PathBuf::from))
    }

    #[test]
    fn signer_configuration_requires_an_absolute_bounded_command() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let executable = write_program(&directory.path().join("signer"), 0o755)?;
        let program = || SignerProgram::resolve_with(Some(&executable), None, no_tooling);

        assert!(SignerProgram::resolve_with(Some(Path::new("signer")), None, no_tooling).is_err());
        assert!(ExternalSigner::new(program()?, Duration::ZERO).is_err());
        assert!(ExternalSigner::new(program()?, Duration::from_secs(901)).is_err());
        assert!(ExternalSigner::new(program()?, Duration::from_secs(30)).is_ok());
        Ok(())
    }

    #[test]
    fn an_external_executable_needs_no_signer_configuration() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let executable = write_program(&directory.path().join("provider"), 0o755)?;

        let program = SignerProgram::resolve_with(Some(&executable), None, no_tooling)?;
        assert_eq!(program.executable, executable);
        assert_eq!(child_config(&program), None);

        let config = directory.path().join("signer.json");
        let program = SignerProgram::resolve_with(Some(&executable), Some(&config), no_tooling)?;
        assert_eq!(child_config(&program), Some(config));
        Ok(())
    }

    #[test]
    fn without_an_executable_the_bundled_signer_receives_the_configuration() -> Result<()> {
        let closure = tempfile::tempdir()?;
        let bundled = write_program(
            &closure
                .path()
                .join("libexec/aos-release/signer/aos-release-signer"),
            0o555,
        )?;
        let config = closure.path().join("signer.json");

        let program = SignerProgram::resolve_with(None, Some(&config), || {
            ToolingEnvironment::from_closure(closure.path())
        })?;
        assert_eq!(program.executable, bundled);
        assert_eq!(child_config(&program), Some(config));

        let command = program.command();
        let arguments: Vec<_> = command.as_std().get_args().collect();
        assert_eq!(arguments, [SIGNER_EXCHANGE_OPERATION]);
        Ok(())
    }

    #[test]
    fn the_bundled_signer_requires_a_configuration_and_a_closure_that_ships_it() -> Result<()> {
        assert!(SignerProgram::resolve_with(None, None, no_tooling).is_err());
        assert!(
            SignerProgram::resolve_with(None, Some(Path::new("signer.json")), no_tooling).is_err()
        );

        let empty = tempfile::tempdir()?;
        let config = empty.path().join("signer.json");
        assert!(
            SignerProgram::resolve_with(None, Some(&config), || {
                ToolingEnvironment::from_closure(empty.path())
            })
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn extra_links_are_accepted_only_for_read_only_store_files() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let program = write_program(&directory.path().join("provider"), 0o555)?;
        validate_signer_executable(&program)?;

        std::fs::hard_link(&program, directory.path().join("alias"))?;
        assert!(validate_signer_executable(&program).is_err());
        assert!(!immutable_store_file(&program, 0o555));
        Ok(())
    }

    #[test]
    fn public_identity_is_independently_pinned() {
        let key = TrustedEd25519Key {
            key_id: "release-key".to_owned(),
            public_key: [7; 32],
        };
        let response = SignatureResponse {
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

    fn payload_request() -> SigningRequest {
        SigningRequest {
            schema_version: "aos.release.signing-request/v1".to_owned(),
            request_id: "request-1".to_owned(),
            nonce: "00".repeat(32),
            registry: aos_release_format::registry::MAIN_REGISTRY.to_owned(),
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
