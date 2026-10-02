//! Produces the local package-attestation quote for the AOS package service.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use anyhow::{Context, Result, bail};

const NONCE_PATH: &str = "/run/aos-attest/nonce";
const EVENT_LOG_PATH: &str = "/run/log/aos-packages.cel";
const OUTPUT_DIRECTORY: &str = "/var/lib/aos-attest/quote";
const RESULT_PATH: &str = "/var/lib/aos-attest/quote.json";
const TEMPORARY_RESULT_PATH: &str = "/var/lib/aos-attest/quote.json.tmp";

fn main() {
    if let Err(error) = run() {
        eprintln!("aos-package-attestation-provider: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let nonce_path = Path::new(NONCE_PATH);
    let event_log_path = Path::new(EVENT_LOG_PATH);
    let output_directory = Path::new(OUTPUT_DIRECTORY);
    let result_path = Path::new(RESULT_PATH);
    let temporary_result_path = Path::new(TEMPORARY_RESULT_PATH);

    let result = (|| -> Result<()> {
        if !aos_package::local_attestation_tpm_available()? {
            return Ok(());
        }

        let nonce = fs::read_to_string(nonce_path)
            .with_context(|| format!("reading verifier nonce {}", nonce_path.display()))?;
        let event_log = fs::metadata(event_log_path).with_context(|| {
            format!("inspecting package event log {}", event_log_path.display())
        })?;
        if event_log.len() == 0 {
            bail!("package attestation event log is empty");
        }

        remove_directory_if_present(output_directory)?;
        remove_file_if_present(result_path)?;
        remove_file_if_present(temporary_result_path)?;

        let quote =
            aos_package::produce_local_package_attestation_quote(nonce.trim(), output_directory)?;
        let mut encoded =
            serde_json::to_vec(&quote).context("serializing package-attestation result")?;
        encoded.push(b'\n');
        fs::write(temporary_result_path, encoded)
            .with_context(|| format!("writing {}", temporary_result_path.display()))?;
        fs::rename(temporary_result_path, result_path).with_context(|| {
            format!(
                "publishing package-attestation result {}",
                result_path.display()
            )
        })?;
        Ok(())
    })();

    let cleanup = remove_file_if_present(nonce_path)
        .and_then(|()| remove_file_if_present(temporary_result_path));
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(error.context(format!(
            "also failed to clean package-attestation service state: {cleanup_error:#}"
        ))),
    }
}

fn remove_file_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

fn remove_directory_if_present(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}
