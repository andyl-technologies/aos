//! Failure reproduction artifact materialization.

use super::*;

pub(in super::super) fn write_reproduction_artifact(
    cli: &Cli,
    artifact_bytes: &[u8],
    outcome_slug: &str,
) -> Result<ReproductionArtifactWriteReport, CliError> {
    validate_replayable_reproduction_artifact(cli, artifact_bytes)?;
    let digest = content_address_bytes(artifact_bytes);
    fs::create_dir_all(&cli.artifact_dir)?;
    let file_name = format!(
        "repro-{}-{}.crucible",
        sanitize_slug(outcome_slug),
        short_digest(&digest)
    );
    let path = cli.artifact_dir.join(file_name);
    fs::write(&path, artifact_bytes)?;
    let footer = reproduction_footer(path.clone());

    Ok(ReproductionArtifactWriteReport {
        path,
        digest,
        footer,
    })
}
