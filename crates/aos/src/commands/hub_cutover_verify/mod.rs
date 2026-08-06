//! Offline generation and verification of topology-cutover bundles.
//!
//! The verifier treats the root public key, its fingerprint, and its own
//! executable bytes as out-of-band trust inputs. Bundle metadata cannot grant
//! trust to itself: the root authenticates the manifest and signer key map,
//! and the authenticated `verifier` node must equal the running executable.

mod bundle;
mod canonical;
mod fixtures;
mod schema;
mod semantics;

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Read as _;

use anyhow::Result;
use aos_core::output::Printer;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cli::{
    HubTopologyCutoverGenerateArgs, HubTopologyCutoverMaterializeVerifierArgs,
    HubTopologyCutoverVerifyArgs,
};

pub(super) const DIALECT_URI: &str =
    "https://aos.andyl.org/schemas/aos-cutover-schema-v1.metaschema.json";
pub(super) const DIALECT_NAME: &str = "aos-cutover-schema/v1";
pub(super) const DOCUMENT_DOMAIN: &str = "aos.hub.topology-cutover.document/v1";
pub(super) const KEY_MAP_DOMAIN: &str = "aos.hub.topology-cutover.signer-key-map/v1";
pub(super) const BUNDLE_DOMAIN: &str = "aos.hub.topology-cutover.bundle-manifest/v1";

#[derive(Debug, Serialize)]
pub(super) struct MachineResult {
    pub(super) schema_version: &'static str,
    pub(super) result: &'static str,
    pub(super) code: &'static str,
    pub(super) validated_document_count: usize,
    pub(super) validated_contract_schema_count: usize,
    pub(super) bundle_entry_count: usize,
    pub(super) materialized_fixture_count: usize,
    pub(super) signatures_verified: usize,
    pub(super) verifier_sha256: String,
}

/// Closed machine-readable failure classes emitted by cutover commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CutoverErrorCode {
    FilesystemBoundaryInvalid,
    InputIdentityAliased,
    InputInvalid,
    SchemaInvalid,
    TrustRootInvalid,
    SignatureInvalid,
    SignerSeparationInvalid,
    BundleClosureInvalid,
    RunningVerifierIdentityMismatch,
    FixtureInvalid,
    OutputAlreadyExists,
    ExecutableHandleUnsupported,
    InternalError,
}

impl CutoverErrorCode {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::FilesystemBoundaryInvalid => "filesystem_boundary_invalid",
            Self::InputIdentityAliased => "input_identity_aliased",
            Self::InputInvalid => "input_invalid",
            Self::SchemaInvalid => "schema_invalid",
            Self::TrustRootInvalid => "trust_root_invalid",
            Self::SignatureInvalid => "signature_invalid",
            Self::SignerSeparationInvalid => "signer_separation_invalid",
            Self::BundleClosureInvalid => "bundle_closure_invalid",
            Self::RunningVerifierIdentityMismatch => "running_verifier_identity_mismatch",
            Self::FixtureInvalid => "fixture_invalid",
            Self::OutputAlreadyExists => "output_already_exists",
            Self::ExecutableHandleUnsupported => "executable_handle_unsupported",
            Self::InternalError => "internal_error",
        }
    }
}

#[derive(Debug)]
pub(super) struct CutoverError {
    code: CutoverErrorCode,
    source: anyhow::Error,
}

impl std::fmt::Display for CutoverError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {:#}", self.code.as_str(), self.source)
    }
}

impl std::error::Error for CutoverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

pub(super) fn typed_error(
    code: CutoverErrorCode,
    source: impl Into<anyhow::Error>,
) -> anyhow::Error {
    anyhow::Error::new(CutoverError {
        code,
        source: source.into(),
    })
}

pub(super) fn classify_error(error: anyhow::Error, code: CutoverErrorCode) -> anyhow::Error {
    if error
        .chain()
        .any(|source| source.downcast_ref::<CutoverError>().is_some())
    {
        error
    } else {
        typed_error(code, error)
    }
}

fn error_code(error: &anyhow::Error) -> CutoverErrorCode {
    error
        .chain()
        .find_map(|source| source.downcast_ref::<CutoverError>())
        .map_or(CutoverErrorCode::InternalError, |error| error.code)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GenerationRecipe {
    pub(super) schema_version: String,
    pub(super) bundle_id: String,
    pub(super) dialect: String,
    pub(super) layout: Vec<GenerationLayout>,
    pub(super) edges: Vec<BundleEdge>,
    pub(super) documents: BundleDocuments,
    pub(super) schemas: BundleSchemas,
    pub(super) trust: BundleTrust,
    pub(super) verifier_node_id: String,
    pub(super) complete: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GenerationLayout {
    pub(super) node_id: String,
    pub(super) path: String,
    pub(super) kind: String,
    pub(super) media_type: String,
    pub(super) role: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BundleManifestEnvelope {
    pub(super) schema_version: String,
    pub(super) payload: BundleManifest,
    pub(super) payload_sha256: String,
    pub(super) signer_key_id: String,
    pub(super) signer_role: String,
    pub(super) algorithm: String,
    pub(super) domain: String,
    pub(super) signature_base64: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BundleManifest {
    pub(super) schema_version: String,
    pub(super) bundle_id: String,
    pub(super) dialect: String,
    pub(super) entries: Vec<BundleEntry>,
    pub(super) edges: Vec<BundleEdge>,
    pub(super) documents: BundleDocuments,
    pub(super) schemas: BundleSchemas,
    pub(super) trust: BundleTrust,
    pub(super) verifier_node_id: String,
    pub(super) complete: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BundleEntry {
    pub(super) node_id: String,
    pub(super) path: String,
    pub(super) kind: String,
    pub(super) media_type: String,
    pub(super) role: String,
    pub(super) size_bytes: u64,
    pub(super) sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BundleEdge {
    pub(super) from_node_id: String,
    pub(super) relation: String,
    pub(super) to_node_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BundleDocuments {
    pub(super) plan_payload_node_id: String,
    pub(super) plan_signature_envelope_node_id: String,
    pub(super) report_payload_node_id: String,
    pub(super) report_signature_envelope_node_id: String,
    pub(super) verification_payload_node_id: String,
    pub(super) verification_signature_envelope_node_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BundleSchemas {
    pub(super) dialect_metaschema_node_id: String,
    pub(super) plan_node_id: String,
    pub(super) report_node_id: String,
    pub(super) verification_node_id: String,
    pub(super) bundle_node_id: String,
    pub(super) signature_envelope_node_id: String,
    pub(super) signer_key_map_node_id: String,
    pub(super) fixtures_node_id: String,
    pub(super) bundle_generation_node_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BundleTrust {
    pub(super) key_map_payload_node_id: String,
    pub(super) key_map_signature_envelope_node_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignerKeyMap {
    pub(super) schema_version: String,
    pub(super) keys: Vec<SignerKey>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignerKey {
    pub(super) key_id: String,
    pub(super) public_key_node_id: String,
    pub(super) public_key_sha256: String,
    pub(super) roles: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignatureEnvelope {
    pub(super) schema_version: String,
    pub(super) document_node_id: String,
    pub(super) document_kind: String,
    pub(super) canonical_payload_sha256: String,
    pub(super) omitted_json_pointers: Vec<String>,
    pub(super) signer_key_id: String,
    pub(super) signer_role: String,
    pub(super) signature_node_id: String,
    pub(super) signature_sha256: String,
    pub(super) algorithm: String,
    pub(super) domain: String,
}

pub(super) struct VerifiedInputs {
    pub(super) manifest_envelope: BundleManifestEnvelope,
    pub(super) manifest_value: Value,
    pub(super) bundle_files: BTreeMap<String, Vec<u8>>,
    pub(super) root_key_bytes: Vec<u8>,
    pub(super) running_executable_bytes: Vec<u8>,
}

pub(super) struct RunningExecutable {
    _handle: File,
    pub(super) bytes: Vec<u8>,
}

#[cfg(target_os = "linux")]
fn open_running_executable() -> Result<RunningExecutable> {
    let path = "/proc/self/exe";
    let mut options = OpenOptions::new();
    options.read(true);
    use std::os::unix::fs::OpenOptionsExt as _;
    // `/proc/self/exe` is a kernel magic link. Opening it directly pins the
    // executable inode; O_NOFOLLOW would reject the only trustworthy OS
    // handle and must therefore not be used here.
    options.custom_flags(libc::O_CLOEXEC);
    let mut handle = options.open(&path)?;
    let before = handle.metadata()?;
    if !before.is_file() {
        anyhow::bail!("running executable handle is not a regular file");
    }
    let mut bytes = Vec::new();
    handle.read_to_end(&mut bytes)?;
    let after = handle.metadata()?;
    if executable_identity(&before)? != executable_identity(&after)? {
        anyhow::bail!("running executable changed while opening immutable identity");
    }
    Ok(RunningExecutable {
        _handle: handle,
        bytes,
    })
}

#[cfg(not(target_os = "linux"))]
fn open_running_executable() -> Result<RunningExecutable> {
    Err(typed_error(
        CutoverErrorCode::ExecutableHandleUnsupported,
        anyhow::anyhow!("this platform has no implemented immutable running-executable handle"),
    ))
}

#[cfg(unix)]
fn executable_identity(metadata: &std::fs::Metadata) -> Result<(u64, u64, u64, i64, i64)> {
    use std::os::unix::fs::MetadataExt as _;
    Ok((
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
    ))
}

#[cfg(not(unix))]
fn executable_identity(metadata: &std::fs::Metadata) -> Result<(u64, std::time::SystemTime)> {
    Ok((metadata.len(), metadata.modified()?))
}

/// Verifies a cutover bundle and emits exactly one closed JSON result.
///
/// # Errors
///
/// Returns an error only if a verified success result cannot be serialized.
/// Verification failures emit their result and terminate with exit status 1.
pub fn run(printer: &Printer, args: &HubTopologyCutoverVerifyArgs) -> Result<()> {
    let result = open_running_executable()
        .map_err(|error| classify_error(error, CutoverErrorCode::FilesystemBoundaryInvalid))
        .and_then(|executable| bundle::verify(args, &executable));
    match result {
        Ok(result) => print_machine(printer, &result),
        Err(error) => emit_failure_and_exit(
            printer,
            "aos.hub.topology-cutover-verifier-result/v1",
            error_code(&error).as_str(),
            &error,
        ),
    }
}

/// Generates every signed artifact and the final manifest in one transaction.
///
/// # Errors
///
/// Returns an error only if a success result cannot be serialized. Generation
/// failures emit their result and terminate with exit status 1.
pub fn run_generate(printer: &Printer, args: &HubTopologyCutoverGenerateArgs) -> Result<()> {
    let result = open_running_executable()
        .map_err(|error| classify_error(error, CutoverErrorCode::FilesystemBoundaryInvalid))
        .and_then(|executable| bundle::generate(args, &executable));
    match result {
        Ok(result) => print_machine(printer, &result),
        Err(error) => emit_failure_and_exit(
            printer,
            "aos.hub.topology-cutover-generator-result/v1",
            error_code(&error).as_str(),
            &error,
        ),
    }
}

/// Installs the exact current executable at the declared bundle verifier path.
///
/// # Errors
///
/// Returns an error only if a success result cannot be serialized. Installation
/// failures emit a closed JSON result and terminate with exit status 1.
pub fn run_materialize_verifier(
    printer: &Printer,
    args: &HubTopologyCutoverMaterializeVerifierArgs,
) -> Result<()> {
    let result = open_running_executable()
        .map_err(|error| classify_error(error, CutoverErrorCode::FilesystemBoundaryInvalid))
        .and_then(|executable| bundle::materialize_verifier(args, &executable));
    match result {
        Ok(result) => print_machine(printer, &result),
        Err(error) => emit_failure_and_exit(
            printer,
            "aos.hub.topology-cutover-materializer-result/v1",
            error_code(&error).as_str(),
            &error,
        ),
    }
}

fn print_machine(printer: &Printer, value: &impl Serialize) -> Result<()> {
    printer.json(&serde_json::to_value(value)?);
    Ok(())
}

fn emit_failure_and_exit(
    printer: &Printer,
    schema_version: &str,
    code: &str,
    error: &anyhow::Error,
) -> ! {
    let failure = serde_json::json!({
        "schema_version": schema_version,
        "result": "failed",
        "code": code,
        "message": format!("{error:#}"),
        "validated_document_count": 0,
        "validated_contract_schema_count": 0,
        "bundle_entry_count": 0,
        "materialized_fixture_count": 0,
        "signatures_verified": 0,
        "verifier_sha256": null
    });
    printer.json(&failure);
    std::process::exit(1)
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;

    use super::*;

    #[test]
    fn leaf_error_code_survives_context_layers() {
        let error = typed_error(
            CutoverErrorCode::RunningVerifierIdentityMismatch,
            anyhow!("byte identity differs"),
        )
        .context("authenticated verifier stage");
        assert_eq!(
            error_code(&error),
            CutoverErrorCode::RunningVerifierIdentityMismatch
        );
    }

    #[test]
    fn unsupported_executable_handle_survives_command_boundary_classification() {
        let error = classify_error(
            typed_error(
                CutoverErrorCode::ExecutableHandleUnsupported,
                anyhow!("unsupported platform"),
            ),
            CutoverErrorCode::FilesystemBoundaryInvalid,
        );
        assert_eq!(
            error_code(&error),
            CutoverErrorCode::ExecutableHandleUnsupported
        );
    }
}
