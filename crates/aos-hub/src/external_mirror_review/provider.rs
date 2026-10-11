//! Rechecks actual retained provider phases with the source-owned offline projector.

use std::{
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use aos_hub_core::{mirror_work::MIRROR_PART_BYTES, storage_authority::StorageAuthorityHost};

use super::{
    assembly, files,
    observations::{Domain, ProviderProjection, ReadIdentity},
    selection::*,
};

pub(super) fn validate_projection(
    projected: &ProviderProjection,
    selected: &ExternalMirrorReviewSelection,
    domain: &Domain,
) -> Result<()> {
    let observed = &projected.provider_contract;
    let installed = &domain.provider_contract;
    let maximum: u64 = observed.maximum_copy_read_range_bytes.parse()?;
    ensure!(
        projected.version == 1
            && projected.report_sha256 == selected.inputs.provider_report.sha256
            && projected.executable_sha256
                == selected.inputs.provider_conformance_executable.sha256
            && aos_hub_core::direct_upload::valid_direct_digest(&projected.original_sha256)
            && observed.contract_id == "aos.operator-s3.protected-copy.v1"
            && observed.evidence_digest == projected.report_sha256
            && installed.observation_sha256 == projected.report_sha256
            && installed.read_identity == ReadIdentity::GuardedVersionless
            && !observed.versioned_conditional_range_read
            && !observed.versioned_multipart_complete
            && installed.maximum_conditional_read_bytes.get() as u64 == maximum
            && maximum >= MIRROR_PART_BYTES
            && maximum <= 64 * 1024 * 1024
            && installed.strong_conditional_read
                == observed.protected_versionless.strong_conditional_range_read
            && installed.strong_conditional_read
            && installed.private_incomplete_upload == observed.private_incomplete_upload
            && installed.private_incomplete_upload
            && installed.completed_upload_rejects_late_parts
                == observed.completed_upload_rejects_late_parts
            && installed.completed_upload_rejects_late_parts
            && installed.checksum_enforced == observed.upload_part_checksum_enforced
            && installed.checksum_enforced
            && installed.positive_complete_identity
                == observed.protected_versionless.positive_multipart_complete
            && installed.positive_complete_identity
            && observed.abort_closes_upload_id
            && installed.positive_empty_put_identity == observed.versioned_empty_put,
        "Mirror Read or closure contract differs from actual provider phases"
    );
    let endpoint = url::Url::parse(&projected.endpoint)?;
    let actual_host = match endpoint
        .host()
        .ok_or_else(|| anyhow::anyhow!("Mirror provider host absent"))?
    {
        url::Host::Domain(host) => StorageAuthorityHost::Dns(host.to_owned()),
        url::Host::Ipv4(host) => StorageAuthorityHost::Ipv4(host.octets()),
        url::Host::Ipv6(host) => StorageAuthorityHost::Ipv6(host.octets()),
    };
    let profile = &domain.profile.profile;
    ensure!(
        endpoint.scheme() == "https"
            && endpoint.username().is_empty()
            && endpoint.password().is_none()
            && endpoint.query().is_none()
            && endpoint.fragment().is_none()
            && endpoint.path() == "/"
            && actual_host == profile.read_cohort.alias.spec.host
            && endpoint.port_or_known_default() == Some(profile.read_cohort.alias.spec.port)
            && projected.bucket == profile.read_cohort.alias.spec.bucket
            && projected.private_policy == profile.private_stage_policy
            && aos_hub_core::direct_upload::valid_direct_digest(&projected.policy_review_sha256)
            && projected.private_staging_prefix == profile.staging_prefix,
        "Mirror provider report differs from the actual accepted physical coordinates"
    );
    Ok(())
}

pub(super) fn validate(
    base: &Path,
    selected: &ExternalMirrorReviewSelection,
    domain: &Domain,
) -> Result<()> {
    // The unchanged projector verifies every original, intent, response and
    // terminal phase, including conditional bytes and late-part refusals. It
    // contacts no provider; caller booleans cannot replace the actual journal.
    assembly::read(base, &selected.inputs.provider_report, 256 * 1024)?;
    let executable = base.join(&selected.inputs.provider_conformance_executable.path);
    let before = files::hash_installed(&executable)?;
    ensure!(
        before
            == (
                selected
                    .inputs
                    .provider_conformance_executable
                    .sha256
                    .clone(),
                selected.inputs.provider_conformance_executable.byte_size
            ),
        "Mirror conformance executable differs"
    );
    let directory = tempfile::Builder::new()
        .prefix("aos-mirror-offline-contract-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let output = directory.path().join("contract.json");
    let mut child = Command::new(&executable)
        .args(["copy-contract", "--report-file"])
        .arg(base.join(&selected.inputs.provider_report.path))
        .arg("--journal-directory")
        .arg(base.join(&selected.inputs.provider_journal))
        .arg("--output")
        .arg(&output)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("Mirror offline provider projection exceeded bound");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    ensure!(
        status.success() && files::hash_installed(&executable)? == before,
        "Mirror actual provider journal projection refused or executable changed"
    );
    let bytes = files::private_bytes(&output, files::DOCUMENT_LIMIT)?;
    let projected: ProviderProjection = serde_json::from_slice(&bytes)?;
    validate_projection(&projected, selected, domain)?;
    assembly::read(base, &selected.inputs.provider_report, 256 * 1024)?;
    Ok(())
}
