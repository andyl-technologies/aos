//! Read-only Git and Nix evaluation that freezes a canonical release plan.

use std::fs::File;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output};

use anyhow::{Context as _, Result, bail};
use aos_core::nix::NixRunner;
use aos_core::output::Printer;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::inventory::{DerivationInventoryV1, PackageInventoryV1};
use aos_release::plan::{PlanningSource, ReleaseClass, ReleasePlanRequestV1, SourceIdentity};
use aos_release::platform::Platform;

use crate::cli::ReleasePlanArgs;

use super::capture;

/// Evaluates immutable source and package intent and writes one new plan.
pub(super) fn run(args: &ReleasePlanArgs, nix: &NixRunner, printer: &Printer) -> Result<()> {
    let request_bytes = capture::control_file(&args.request, "release plan request")?;
    let request: ReleasePlanRequestV1 =
        canonical::from_slice(&request_bytes, "release plan request")?;

    let authorization = capture::control_file(
        &args.contributor_authorization,
        "contributor-authorization evidence",
    )?;
    let authorization_digest = Sha256Digest::of_bytes(&authorization);
    if authorization_digest != request.source.contributor_authorization_digest {
        bail!("contributor-authorization evidence digest does not match the request");
    }

    let inventory_value = nix.eval_json("releasePackageInventory")?;
    let inventory: PackageInventoryV1 = serde_json::from_value(inventory_value)
        .context("decoding Nix release package inventory")?;
    inventory.validate()?;
    let qualification: aos_release::qualification::QualificationContract =
        serde_json::from_value(nix.eval_json("releaseQualification")?)
            .context("decoding the shared Nix qualification contract")?;
    qualification.validate()?;
    if qualification.schema_version != aos_release::qualification::CONTRACT_V2 {
        bail!("new release plans require the typed v2 qualification contract");
    }
    let expected_policy = qualification.digest()?;
    if request.public_evidence_policy_digest != expected_policy
        || request.gates != qualification.gates(request.release_class)?
    {
        bail!(
            "reviewed request must select the complete shared qualification policy; inspect aos release contract"
        );
    }
    let mut derivations = Vec::with_capacity(Platform::ALL.len());
    for platform in Platform::ALL {
        let value =
            nix.eval_json_for_target("releasePackageDerivations", Some(platform.as_str()))?;
        let evaluated: DerivationInventoryV1 = serde_json::from_value(value)
            .with_context(|| format!("decoding {platform} derivation inventory"))?;
        if evaluated.platform != platform {
            bail!("Nix derivation inventory returned the wrong target");
        }
        evaluated.validate()?;
        derivations.push(evaluated);
    }
    let source = derive_source_identity(
        nix.root(),
        request.release_class,
        &request.source,
        authorization_digest,
    )?;
    let mut plan = request.materialize(&inventory, &derivations, source)?;
    plan.schema_version = aos_release::RELEASE_PLAN_V2.to_owned();
    plan.qualification = Some(qualification);
    plan.validate()?;
    let bytes = canonical::to_vec(&plan)?;
    write_new_file(&args.output, &bytes)?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.plan-result/v1",
        "release_id": plan.release_id,
        "version": plan.version,
        "plan_digest": Sha256Digest::of_bytes(&bytes),
        "package_count": plan.packages.len(),
        "output": args.output,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Wrote release plan {} with {} package matrices to {}",
        plan.release_id,
        plan.packages.len(),
        args.output.display()
    ));
    Ok(())
}

fn derive_source_identity(
    root: &Path,
    release_class: ReleaseClass,
    source_policy: &PlanningSource,
    authorization_digest: Sha256Digest,
) -> Result<SourceIdentity> {
    let status = git_text(
        root,
        &["status", "--porcelain=v1", "--untracked-files=normal"],
    )?;
    if !status.is_empty() {
        bail!("release planning requires a clean source tree");
    }
    let branch = git_text(root, &["symbolic-ref", "--quiet", "--short", "HEAD"])?;
    validate_source_branch(release_class, &branch, &source_policy.protected_branch)?;
    let object_format = git_text(root, &["rev-parse", "--show-object-format"])?;
    if !matches!(object_format.as_str(), "sha1" | "sha256") {
        bail!("source repository uses an unsupported Git object format");
    }
    let commit = git_text(root, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    require_lower_hex_oid(&commit, &object_format, "source commit")?;
    let reachable = git(
        root,
        &[
            "merge-base",
            "--is-ancestor",
            &commit,
            &source_policy.protected_branch,
        ],
    )?;
    if !reachable.status.success() {
        bail!("source commit is not reachable from the protected branch");
    }
    if release_class != ReleaseClass::Emergency {
        let protected_head = git_text(
            root,
            &["rev-parse", "--verify", &source_policy.protected_branch],
        )?;
        if commit != protected_head {
            bail!("normal release source is not the protected branch head");
        }
    }
    let tag_ref = format!("refs/tags/{}", source_policy.source_tag);
    let tag_probe = git(root, &["rev-parse", "--quiet", "--verify", &tag_ref])?;
    if tag_probe.status.success() {
        bail!("source tag already exists: {}", source_policy.source_tag);
    } else if tag_probe.status.code() != Some(1) {
        bail!("Git failed while checking whether the source tag exists");
    }

    Ok(SourceIdentity {
        commit,
        tree_digest: source_tree_digest(root)?,
        protected_branch: source_policy.protected_branch.clone(),
        source_tag: source_policy.source_tag.clone(),
        contributor_authorization_digest: authorization_digest,
    })
}

fn source_tree_digest(root: &Path) -> Result<Sha256Digest> {
    let output = git(root, &["ls-tree", "-rz", "--full-tree", "HEAD"])?;
    if !output.status.success() {
        bail!("Git failed to enumerate the complete source tree");
    }
    Ok(Sha256Digest::separated(
        "aos.release.git-tree/v1",
        output.stdout,
    ))
}

fn validate_source_branch(class: ReleaseClass, branch: &str, protected_branch: &str) -> Result<()> {
    if !matches!(protected_branch, "master" | "origin/master") {
        bail!("release planning requires the protected master branch");
    }
    if class == ReleaseClass::Emergency {
        if !branch.starts_with("dplecki/hotfix-") {
            bail!("emergency release planning requires a dplecki/hotfix-* branch");
        }
    } else if branch != "master" {
        bail!("normal release planning requires the local master branch");
    }
    Ok(())
}

fn git_text(root: &Path, arguments: &[&str]) -> Result<String> {
    let output = git(root, arguments)?;
    if !output.status.success() {
        bail!("Git command failed: git {}", arguments.join(" "));
    }
    String::from_utf8(output.stdout)
        .context("Git output is not UTF-8")
        .map(|text| text.trim_end().to_owned())
}

fn git(root: &Path, arguments: &[&str]) -> Result<Output> {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .with_context(|| format!("running git {}", arguments.join(" ")))
}

fn require_lower_hex_oid(value: &str, object_format: &str, label: &str) -> Result<()> {
    let expected_length = match object_format {
        "sha1" => 40,
        "sha256" => 64,
        _ => bail!("unsupported Git object format"),
    };
    if value.len() != expected_length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} does not match the repository's Git object format");
    }
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating release plan beside {}", path.display()))?;
    temporary.write_all(bytes)?;
    temporary.as_file_mut().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)
        .with_context(|| format!("installing new release plan {}", path.display()))?;
    File::open(parent)
        .with_context(|| format!("opening release plan directory {}", parent.display()))?
        .sync_all()
        .context("synchronizing release plan directory")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn oid_parser_requires_native_lowercase_git_oid() {
        assert!(require_lower_hex_oid(&"a".repeat(40), "sha1", "test").is_ok());
        assert!(require_lower_hex_oid(&"a".repeat(64), "sha256", "test").is_ok());
        assert!(require_lower_hex_oid(&"A".repeat(40), "sha1", "test").is_err());
        assert!(require_lower_hex_oid(&"a".repeat(64), "sha1", "test").is_err());
    }

    #[test]
    fn branch_policy_separates_normal_and_emergency_sources() {
        assert!(validate_source_branch(ReleaseClass::Edge, "master", "origin/master").is_ok());
        assert!(
            validate_source_branch(
                ReleaseClass::Emergency,
                "dplecki/hotfix-2026-9-1",
                "origin/master"
            )
            .is_ok()
        );
        assert!(
            validate_source_branch(ReleaseClass::Stable, "dplecki/topic", "origin/master").is_err()
        );
    }

    #[test]
    fn source_identity_accepts_sha1_git_and_rejects_dirty_state() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let initialized = git(
            directory.path(),
            &["init", "--initial-branch=master", "--object-format=sha1"],
        )?;
        assert!(initialized.status.success());
        fs::write(directory.path().join("source.txt"), b"source-v1")?;
        assert!(
            git(directory.path(), &["add", "source.txt"])?
                .status
                .success()
        );
        assert!(
            git(
                directory.path(),
                &[
                    "-c",
                    "user.name=AOS Test",
                    "-c",
                    "user.email=aos-test@example.invalid",
                    "commit",
                    "-m",
                    "fixture",
                ],
            )?
            .status
            .success()
        );

        let authorization_digest = Sha256Digest::of_bytes("authorization");
        let source = PlanningSource {
            protected_branch: "master".to_owned(),
            source_tag: "release/test-v1".to_owned(),
            contributor_authorization_digest: authorization_digest,
        };
        let identity = derive_source_identity(
            directory.path(),
            ReleaseClass::Edge,
            &source,
            authorization_digest,
        )?;
        assert_eq!(identity.commit.len(), 40);

        fs::write(directory.path().join("source.txt"), b"source-v2")?;
        assert!(
            derive_source_identity(
                directory.path(),
                ReleaseClass::Edge,
                &source,
                authorization_digest,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn plan_output_never_replaces_an_existing_file() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("plan.json");
        write_new_file(&output, b"first")?;
        assert!(write_new_file(&output, b"second").is_err());
        assert_eq!(std::fs::read(output)?, b"first");
        Ok(())
    }
}
