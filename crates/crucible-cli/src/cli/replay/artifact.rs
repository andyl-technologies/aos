//! Failure reproduction artifact materialization.

use super::*;

pub(in super::super) fn write_failure_reproduction_artifact(
    cli: &Cli,
    artifact_bytes: &[u8],
    failure_slug: &str,
) -> Result<FailureArtifactReport, CliError> {
    validate_replayable_reproduction_artifact(cli, artifact_bytes)?;
    let digest = content_address_bytes(artifact_bytes);
    fs::create_dir_all(&cli.artifact_dir)?;
    let file_name = format!(
        "repro-{}-{}.crucible",
        sanitize_slug(failure_slug),
        short_digest(&digest)
    );
    let path = cli.artifact_dir.join(file_name);
    fs::write(&path, artifact_bytes)?;
    let footer = failure_reproduction_footer(path.clone());

    Ok(FailureArtifactReport {
        path,
        digest,
        footer,
    })
}
