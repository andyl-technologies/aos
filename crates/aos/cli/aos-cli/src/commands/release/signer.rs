//! CLI parsing and presentation for external signer maintenance.

use std::fs::File;
use std::io::Write as _;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use aos_release_coordinator::capture;
use aos_release_coordinator::signer::ExternalSigner;
use aos_release_format::canonical;
use aos_release_format::signing::{SigningRequest, TrustedEd25519Key};

use crate::cli::{ReleaseSignerCommand, ReleaseSignerInvokeArgs};

/// Runs one external-signer maintenance operation.
pub(super) async fn run(
    command: &ReleaseSignerCommand,
    printer: &aos_cli_ui::output::Printer,
) -> Result<()> {
    match command {
        ReleaseSignerCommand::Invoke(args) => invoke(args, printer).await,
    }
}

async fn invoke(
    args: &ReleaseSignerInvokeArgs,
    printer: &aos_cli_ui::output::Printer,
) -> Result<()> {
    let request_bytes = capture::control_file(&args.request, "signing request")?;
    let request: SigningRequest = canonical::from_slice(&request_bytes, "signing request")?;
    let payload = capture::control_file(&args.payload, "signing payload")?;
    let (key_id, key_path) = parse_key_spec(&args.trusted_key)?;
    if key_id != request.key_id {
        bail!("trusted signer key id does not match the request");
    }
    let key_bytes = capture::control_file(key_path, "trusted signer public key")?;
    let trusted_key = TrustedEd25519Key::from_encoded(key_id, &key_bytes)?;
    let signer = ExternalSigner::resolve(
        args.executable.as_deref(),
        args.signer_config.as_deref(),
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
