//! Reads one exact committed metadata decision from the authenticated initrd.
//!
//! The immutable binding selects a result identity that the image builder derived
//! from the configured operation. Inspection keeps the generic journal's shared
//! locks alive while the caller captures and publishes the authorized sources.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use aos_ability_plan::module_graph::GRAPH_LIMITS;
use aos_contract::Sha256Digest;
use aos_storage_provisioning::AuthorizedProvisioningInput;

use super::proof::{
    ImageAdmission, InitrdDecision, MetadataBinding, PreparationResult, validate_authorized_bytes,
};
use crate::deployment::model::{Deployment, ResolvedPackages};
use crate::deployment::transaction::{self, Snapshot};
use crate::native_deployment::{EvaluationInput, NativeDeploymentCommand};

const INITRD_INPUT: &str = "/usr/lib/aos/initrd/deployment";
const INITRD_STATE: &str = "/run/aos-boot-transaction-storage/aos/initrd-stage-journal";
const BINDING: &str = "/usr/lib/aos/boot-metadata-binding.json";
pub(super) const AUTHORIZATION_LIMIT: u64 = 2 * 1024 * 1024;

pub(super) struct VerifiedAuthorization {
    pub(super) input: AuthorizedProvisioningInput,
    pub(super) authorization: PathBuf,
    pub(super) authorization_sha256: Sha256Digest,
    pub(super) image: ImageAdmission,
    pub(super) decision: InitrdDecision,
    _snapshot: Snapshot,
}

pub(super) fn metadata_required() -> Result<bool> {
    let policy: MetadataBinding = GRAPH_LIMITS.decode(
        &read_bounded(Path::new(BINDING), 4096)?,
        "image metadata policy",
    )?;
    policy.required()
}

pub(super) fn read_initial(host: &NativeDeploymentCommand) -> Result<VerifiedAuthorization> {
    let input = PathBuf::from(INITRD_INPUT);
    let digest_path = fs::canonicalize(input.join("admission-sha256"))?;
    crate::deployment::nix::store_root_and_suffix(&digest_path)?;
    let digest = read_bounded(&digest_path, 128)?;
    let digest = std::str::from_utf8(&digest)?.trim_end_matches('\n');
    let initrd = NativeDeploymentCommand {
        input: input.clone(),
        state_directory: INITRD_STATE.into(),
        profile: None,
        nix_store: host.nix_store.clone(),
        admission: input.join("admission.json"),
        admission_sha256: Sha256Digest::parse(digest)?,
    };
    read_initial_in(host, &initrd, Path::new(BINDING))
}

pub(super) fn read_initial_in(
    host: &NativeDeploymentCommand,
    initrd: &NativeDeploymentCommand,
    binding_path: &Path,
) -> Result<VerifiedAuthorization> {
    let committed = read_committed_preparation(initrd, binding_path)?;
    let result = committed.result;
    let descriptor = EvaluationInput::read_in(
        &host.input.join("evaluation.json"),
        &host.nix_store,
        &Default::default(),
    )?;
    let authorization = result.authorized_input;
    let (root, suffix) = crate::deployment::nix::store_root_and_suffix(&authorization)?;
    ensure!(
        root == authorization && suffix.as_os_str().is_empty(),
        "authorization receipt is not an immutable root file"
    );
    let bytes = read_immutable_bounded(&authorization, &host.nix_store, AUTHORIZATION_LIMIT)?;
    let authorized =
        validate_authorized_bytes(&bytes, result.authorized_input_sha256, &descriptor)?;
    let source = serde_json::to_value(authorized.source)?;
    ensure!(
        source.as_str() == Some(result.source.as_str()),
        "committed disk source differs from the metadata authorization decision"
    );
    Ok(VerifiedAuthorization {
        input: authorized,
        authorization,
        authorization_sha256: result.authorized_input_sha256,
        image: ImageAdmission {
            path: fs::canonicalize(&initrd.admission)?,
            sha256: initrd.admission_sha256,
        },
        decision: committed.decision,
        _snapshot: committed.snapshot,
    })
}

/// Keeps the image-selected preparation result and its journal authority locked.
pub(super) struct CommittedPreparation {
    pub(super) result: PreparationResult,
    pub(super) decision: InitrdDecision,
    pub(super) snapshot: Snapshot,
}

/// Selects the exact committed preparation for transfer or host adoption.
///
/// # Errors
/// Returns an error for failed image admission, incomplete journal work,
/// a foreign binding, or a missing or malformed preparation result.
pub(super) fn read_committed_preparation(
    initrd: &NativeDeploymentCommand,
    binding_path: &Path,
) -> Result<CommittedPreparation> {
    let input = &initrd.input;
    crate::native_deployment::verify(initrd)?;

    let expected = read_initrd_deployment(input, &initrd.nix_store)?;
    let binding: MetadataBinding =
        GRAPH_LIMITS.decode(&read_bounded(binding_path, 4096)?, "image metadata binding")?;
    binding.validate(&expected)?;

    let snapshot = transaction::inspect(&initrd.state_directory, transaction::journal_limits())?;
    ensure!(
        !snapshot.has_pending_work()
            && snapshot.incomplete_tail_bytes() == 0
            && snapshot.activation().incomplete_tail_bytes == 0,
        "metadata source handoff requires a completely committed initrd journal"
    );
    let committed = snapshot
        .current()
        .context("initrd metadata authorization is not committed")?;
    ensure!(
        committed.content == expected.id()? && committed.deployment.scope() == binding.scope,
        "committed metadata decision differs from the verified image initrd"
    );
    let output = committed
        .outputs
        .get(&binding.effect)
        .context("the configured initrd metadata decision has no committed result")?;
    let result: PreparationResult = serde_json::from_value(output.clone())?;
    ensure!(
        !result.resource.is_empty(),
        "provisioning result has no committed disk resource"
    );
    crate::deployment::nix::store_root_and_suffix(&result.committed_plan)?;

    let decision = InitrdDecision {
        scope: binding.scope,
        sequence: committed.sequence,
        content: committed.content.clone(),
        effect: binding.effect,
    };
    Ok(CommittedPreparation {
        result,
        decision,
        snapshot,
    })
}

// Read producer-owned aliases through the selected store. This decodes the
// committed plan; its admission and journal authority are verified by the caller.
fn read_initrd_deployment(input: &Path, nix_store: &Path) -> Result<Deployment> {
    let packages: ResolvedPackages = GRAPH_LIMITS.decode(
        &crate::native_deployment::read_immutable_document_in(
            &input.join("packages.json"),
            nix_store,
            &Default::default(),
        )
        .context("reading committed initrd package aliases")?,
        "boot initrd packages",
    )?;
    Deployment::decode(
        &crate::native_deployment::read_immutable_document_in(
            &input.join("transaction.json"),
            nix_store,
            &Default::default(),
        )
        .context("reading committed initrd transaction alias")?,
        &packages,
    )
}

pub(super) fn read_immutable_bounded(
    path: &Path,
    nix_store: &Path,
    maximum: u64,
) -> Result<Vec<u8>> {
    let bytes =
        crate::native_deployment::read_immutable_document_in(path, nix_store, &Default::default())?;
    ensure!(
        u64::try_from(bytes.len())? <= maximum,
        "immutable boot source exceeds its byte bound"
    );
    Ok(bytes)
}

pub(super) fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| format!("opening bounded boot source {}", path.display()))?;
    let file = fs::File::from(descriptor);
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= maximum,
        "boot source document is not a bounded regular file"
    );
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(
        u64::try_from(bytes.len())? <= maximum,
        "boot source document exceeds its byte bound"
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn source_documents_reject_symlinks_and_oversized_files() {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("source.json");
        let missing = read_bounded(&path, 3).unwrap_err();
        assert!(format!("{missing:#}").contains(path.to_str().unwrap()));

        fs::write(&path, b"{}\n").unwrap();
        assert_eq!(read_bounded(&path, 3).unwrap(), b"{}\n");
        assert!(read_bounded(&path, 2).is_err());

        let link = scratch.path().join("link.json");
        symlink(&path, &link).unwrap();
        assert!(read_bounded(&link, 3).is_err());
    }

    #[test]
    #[ignore = "requires an actual source-built initrd bundle and selected Nix"]
    fn actual_initrd_alias_uses_selected_store_documents() -> Result<()> {
        let original = PathBuf::from(
            std::env::var_os("AOS_BOOT_IMAGE_INITRD_BUNDLE")
                .context("actual source-built initrd bundle is required")?,
        );
        let nix_store = PathBuf::from(
            std::env::var_os("AOS_NIX_STORE").context("source-built Nix is required")?,
        );
        let scratch = tempfile::tempdir()?;
        let alias = scratch.path().join("received-initrd");
        symlink(&original, &alias)?;

        assert!(
            crate::native_deployment::read_regular_document(&alias.join("packages.json")).is_err()
        );
        let retained = read_initrd_deployment(&original, &nix_store)?;
        let received = read_initrd_deployment(&alias, &nix_store)?;
        assert_eq!(received.id()?, retained.id()?);
        assert_eq!(received.scope(), retained.scope());

        fs::remove_file(&alias)?;
        symlink(scratch.path(), &alias)?;
        assert!(read_initrd_deployment(&alias, &nix_store).is_err());
        Ok(())
    }
}
