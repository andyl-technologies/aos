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
use aos_release::manifest::ReleaseManifestV1;
use aos_release::plan::{PlanningSource, ReleasePlan, ReleasePlanRequest, SourceIdentity};
use aos_release::platform::Platform;
use aos_release::profile_override::{AcceptedOverride, verify_overrides};
use aos_release::qualification::{ChangeScope, QualificationContract};

use crate::cli::ReleasePlanArgs;

use super::capture;

/// Evaluates immutable source and package intent and writes one new plan.
pub(super) fn run(args: &ReleasePlanArgs, nix: &NixRunner, printer: &Printer) -> Result<()> {
    let request_bytes = capture::control_file(&args.request, "release plan request")?;
    let mut request: ReleasePlanRequest =
        canonical::from_slice(&request_bytes, "release plan request")?;
    if request.schema_version != aos_release::plan::PLAN_REQUEST {
        bail!(
            "release plans require an {} request",
            aos_release::plan::PLAN_REQUEST
        );
    }
    for destination in &request.destinations {
        aos_release::registry::channel_kind(&destination.channel)?;
    }

    let authorization = capture::control_file(
        &args.contributor_authorization,
        "contributor-authorization evidence",
    )?;
    let authorization_digest = Sha256Digest::of_bytes(&authorization);
    if authorization_digest != request.source.contributor_authorization_digest {
        bail!("contributor-authorization evidence digest does not match the request");
    }

    let release_platforms = Platform::ALL.map(Platform::as_str);
    let inventory_bytes =
        nix.eval_release_json_bytes("releasePackageInventory", None, &release_platforms)?;
    let inventory: PackageInventoryV1 = serde_json::from_slice(&inventory_bytes)
        .context("decoding Nix release package inventory")?;
    inventory.validate()?;
    let qualification: QualificationContract =
        serde_json::from_value(nix.eval_json("releaseQualification")?)
            .context("decoding the shared Nix qualification contract")?;
    qualification.validate()?;
    if request.public_evidence_policy_digest != qualification.digest()? {
        bail!(
            "reviewed request must bind the complete shared qualification policy; inspect aos maintain release step contract"
        );
    }
    let accepted = apply_overrides(args, &qualification, &mut request)?;

    let build_platform: String =
        serde_json::from_value(nix.eval_json("stdenv.buildPlatform.system")?)
            .context("decoding the native Nix build platform")?;
    let mut derivations = Vec::with_capacity(Platform::ALL.len());
    for platform in Platform::ALL {
        // Passing the native platform as crossSystem selects a cross stdenv.
        // Native cells must retain the repository's ordinary build toolchain.
        let target = (platform.as_str() != build_platform).then_some(platform.as_str());
        let value =
            nix.eval_release_json("releasePackageDerivations", target, &release_platforms)?;
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
        !accepted.is_empty(),
        &request.source,
        authorization_digest,
    )?;
    let predecessor = args
        .predecessor_manifest
        .as_deref()
        .map(read_manifest)
        .transpose()?;
    let plan = materialize_with_scope(
        request,
        &inventory,
        &derivations,
        source,
        qualification,
        predecessor.as_ref(),
    )?;
    for accepted in &accepted {
        accepted.validate_for(&plan)?;
    }
    super::artifact_profiles::require_plan(nix, &plan)?;
    let bytes = canonical::to_vec(&plan)?;
    write_new_file(&args.output, &bytes)?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.plan-result/v1",
        "release_id": plan.release_id,
        "version": plan.version,
        "plan_digest": Sha256Digest::of_bytes(&bytes),
        "package_count": plan.packages.len(),
        "destinations": plan.destinations.iter().map(|destination| &destination.name).collect::<Vec<_>>(),
        "change_scope": plan.change_scope,
        "profile_overrides": plan.profile_overrides,
        "output": args.output,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Wrote release plan {} with {} package matrices and {} destinations to {}",
        plan.release_id,
        plan.packages.len(),
        plan.destinations.len(),
        args.output.display()
    ));
    Ok(())
}

/// Materializes the plan with a change scope derived from the plan itself.
///
/// Planning precedes building, so the scope compares planned store paths
/// with the predecessor manifest. The first pass freezes the package matrix
/// under a fail-closed provisional scope; the second binds the derived scope,
/// which may narrow change-scoped gates. A scope already present in the
/// request must equal the derived one.
fn materialize_with_scope(
    request: ReleasePlanRequest,
    inventory: &PackageInventoryV1,
    derivations: &[DerivationInventoryV1],
    source: SourceIdentity,
    qualification: QualificationContract,
    predecessor: Option<&ReleaseManifestV1>,
) -> Result<ReleasePlan> {
    let requested_scope = request.change_scope.clone();
    let mut provisional = request.clone();
    provisional.change_scope = Some(ChangeScope {
        schema_version: aos_release::qualification::change_scope::CHANGE_SCOPE.to_owned(),
        predecessor_manifest_digest: None,
        image_affecting: true,
        container_affecting: true,
        changed_package_cells: Vec::new(),
        reason: "provisional scope before change classification".to_owned(),
    });
    let first = provisional.materialize(
        inventory,
        derivations,
        source.clone(),
        qualification.clone(),
    )?;
    let scope = aos_release::qualification::change_scope::classify_plan(&first, predecessor)?;
    if requested_scope
        .as_ref()
        .is_some_and(|requested| requested != &scope)
    {
        bail!("requested change scope differs from the scope derived from the predecessor");
    }
    let mut request = request;
    request.change_scope = Some(scope);
    request.materialize(inventory, derivations, source, qualification)
}

/// Verifies signed profile overrides and applies them to the request.
///
/// Each `--override` directory holds the approvals (`*.json` envelopes) of one
/// override; they must reach the release-evidence threshold. The accepted
/// soak and rings replace the requested destination's, and the override
/// reference is bound into the plan.
fn apply_overrides(
    args: &ReleasePlanArgs,
    contract: &QualificationContract,
    request: &mut ReleasePlanRequest,
) -> Result<Vec<AcceptedOverride>> {
    if args.overrides.is_empty() {
        if !request.profile_overrides.is_empty() {
            bail!("the request references profile overrides; supply them with --override");
        }
        return Ok(Vec::new());
    }
    let keys = super::verify::load_trusted_keys(&args.override_keys)?;
    let mut accepted = Vec::with_capacity(args.overrides.len());
    let mut references = Vec::new();
    for directory in &args.overrides {
        let envelopes = override_envelopes(directory)?;
        let approval = verify_overrides(
            contract,
            &request.registry,
            &request.release_id,
            &request.signers,
            &envelopes,
            &keys,
        )
        .with_context(|| format!("verifying profile override {}", directory.display()))?;
        let wanted = approval.requested_destination()?;
        let destination = request
            .destinations
            .iter_mut()
            .find(|destination| {
                destination.surface == wanted.surface && destination.channel == wanted.channel
            })
            .with_context(|| {
                format!(
                    "profile override names unrequested destination {}",
                    approval.payload.destination
                )
            })?;
        if destination.effective.is_some() {
            bail!(
                "destination {} has more than one override",
                approval.payload.destination
            );
        }
        destination.effective = wanted.effective;
        references.push(approval.reference.clone());
        accepted.push(approval);
    }
    if !request.profile_overrides.is_empty() && request.profile_overrides != references {
        bail!("the request's override references differ from the supplied overrides");
    }
    request.profile_overrides = references;
    Ok(accepted)
}

fn override_envelopes(directory: &Path) -> Result<Vec<Vec<u8>>> {
    let mut paths = std::fs::read_dir(directory)
        .with_context(|| format!("reading profile override {}", directory.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
        .iter()
        .map(|path| capture::control_file(path, "profile override approval"))
        .collect()
}

/// Reads a manifest payload or signed manifest envelope.
fn read_manifest(path: &Path) -> Result<ReleaseManifestV1> {
    let bytes = capture::control_file(path, "predecessor manifest")?;
    let value: serde_json::Value = canonical::from_slice(&bytes, "predecessor manifest")?;
    if value.get("payload").is_some() {
        Ok(
            canonical::from_slice::<aos_release::manifest::ManifestEnvelopeV1>(
                &bytes,
                "predecessor manifest envelope",
            )?
            .payload,
        )
    } else {
        canonical::from_slice(&bytes, "predecessor manifest payload")
    }
}

fn derive_source_identity(
    root: &Path,
    overridden: bool,
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
    let hotfix = validate_source_branch(overridden, &branch, &source_policy.protected_branch)?;
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
    if !hotfix {
        let protected_head = git_text(
            root,
            &["rev-parse", "--verify", &source_policy.protected_branch],
        )?;
        if commit != protected_head {
            bail!("normal release source is not the protected branch head");
        }
    }
    require_unused_or_matching_source_tag(root, &source_policy.source_tag, &commit)?;

    Ok(SourceIdentity {
        commit,
        tree_digest: source_tree_digest(root)?,
        protected_branch: source_policy.protected_branch.clone(),
        source_tag: source_policy.source_tag.clone(),
        contributor_authorization_digest: authorization_digest,
    })
}

/// Requires the source tag to be absent or to already name the planned commit.
///
/// The tag is `release/<version>`, which is not registry-qualified. A main
/// edge release and a testing edge release of the same version are planned
/// from the same protected commit, so the second plan finds the tag the first
/// one created. That is the same immutable source identity, not a reuse of a
/// version for different content, so it is accepted. A tag naming any other
/// commit is a version collision and fails closed.
fn require_unused_or_matching_source_tag(
    root: &Path,
    source_tag: &str,
    commit: &str,
) -> Result<()> {
    let tag_ref = format!("refs/tags/{source_tag}");
    let tag_probe = git(root, &["rev-parse", "--quiet", "--verify", &tag_ref])?;
    if tag_probe.status.code() == Some(1) {
        return Ok(());
    }
    if !tag_probe.status.success() {
        bail!("Git failed while checking whether the source tag exists");
    }

    let peeled = format!("{tag_ref}^{{commit}}");
    let tagged_commit = git_text(root, &["rev-parse", "--verify", &peeled])?;
    if tagged_commit != commit {
        bail!("source tag {source_tag} already names a different commit");
    }
    Ok(())
}

/// Rejects profile evaluation from a checkout other than the frozen clean source.
pub(super) fn require_planned_source(root: &Path, source: &SourceIdentity) -> Result<()> {
    let status = git_text(
        root,
        &["status", "--porcelain=v1", "--untracked-files=normal"],
    )?;
    if !status.is_empty() {
        bail!("release artifact profile verification requires a clean source tree");
    }
    let commit = git_text(root, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    if commit != source.commit || source_tree_digest(root)? != source.tree_digest {
        bail!("release artifact profile source differs from the frozen release plan");
    }
    Ok(())
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

/// Checks the checked-out branch and returns whether it is a hotfix branch.
///
/// A `dplecki/hotfix-*` head may be planned only when the plan carries an
/// accepted profile override; every other plan builds the local master head.
fn validate_source_branch(overridden: bool, branch: &str, protected_branch: &str) -> Result<bool> {
    if !matches!(protected_branch, "master" | "origin/master") {
        bail!("release planning requires the protected master branch");
    }
    if branch.starts_with("dplecki/hotfix-") {
        if !overridden {
            bail!("only a plan with an accepted profile override may build a hotfix branch");
        }
        return Ok(true);
    }
    if branch != "master" {
        bail!("release planning requires the local master branch or an overridden hotfix branch");
    }
    Ok(false)
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
    fn branch_policy_keys_hotfix_heads_on_an_override() {
        assert!(matches!(
            validate_source_branch(false, "master", "origin/master"),
            Ok(false)
        ));
        assert!(matches!(
            validate_source_branch(true, "dplecki/hotfix-2026-9-1", "origin/master"),
            Ok(true)
        ));
        assert!(validate_source_branch(false, "dplecki/hotfix-2026-9-1", "origin/master").is_err());
        assert!(validate_source_branch(true, "dplecki/topic", "origin/master").is_err());
        assert!(validate_source_branch(false, "master", "main").is_err());
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
        let identity =
            derive_source_identity(directory.path(), false, &source, authorization_digest)?;
        assert_eq!(identity.commit.len(), 40);
        require_planned_source(directory.path(), &identity)?;

        let mut wrong_commit = identity.clone();
        wrong_commit.commit = "0".repeat(40);
        assert!(require_planned_source(directory.path(), &wrong_commit).is_err());

        let mut wrong_tree = identity.clone();
        wrong_tree.tree_digest = Sha256Digest::of_bytes("different source");
        assert!(require_planned_source(directory.path(), &wrong_tree).is_err());

        fs::write(directory.path().join("source.txt"), b"source-v2")?;
        assert!(require_planned_source(directory.path(), &identity).is_err());
        assert!(
            derive_source_identity(directory.path(), false, &source, authorization_digest).is_err()
        );
        Ok(())
    }

    #[test]
    fn source_tag_may_already_name_the_planned_commit_but_no_other() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        assert!(
            git(
                root,
                &["init", "--initial-branch=master", "--object-format=sha1"]
            )?
            .status
            .success()
        );
        let commit = |message: &str| -> Result<()> {
            fs::write(root.join("source.txt"), message.as_bytes())?;
            assert!(git(root, &["add", "source.txt"])?.status.success());
            assert!(
                git(
                    root,
                    &[
                        "-c",
                        "user.name=AOS Test",
                        "-c",
                        "user.email=aos-test@example.invalid",
                        "commit",
                        "-m",
                        message,
                    ],
                )?
                .status
                .success()
            );
            Ok(())
        };

        commit("first")?;
        let authorization_digest = Sha256Digest::of_bytes("authorization");
        let source = PlanningSource {
            protected_branch: "master".to_owned(),
            source_tag: "release/2026.10.0-dev.20261001.1".to_owned(),
            contributor_authorization_digest: authorization_digest,
        };

        // Planning the same version twice from the same commit, as a main and
        // a testing edge release do, sees the first plan's tag and accepts it.
        let first = derive_source_identity(root, false, &source, authorization_digest)?;
        // A lightweight tag is enough here; the operator's signing config must
        // not reach into the fixture repository.
        let tagged = git(
            root,
            &[
                "-c",
                "tag.gpgSign=false",
                "tag",
                &source.source_tag,
                &first.commit,
            ],
        )?;
        assert!(
            tagged.status.success(),
            "{}",
            String::from_utf8_lossy(&tagged.stderr)
        );
        let second = derive_source_identity(root, false, &source, authorization_digest)?;
        assert_eq!(second.commit, first.commit);

        // Once the protected branch moves, the tag names a different commit
        // and the version can no longer be planned.
        commit("second")?;
        let error = derive_source_identity(root, false, &source, authorization_digest)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("already names a different commit"),
            "{error}"
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
