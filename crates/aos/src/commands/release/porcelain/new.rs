//! `aos maintain release new`: derive the plan request and freeze the plan.
//!
//! The request (`aos.release.plan-request/v1`) comes from the maintainer
//! configuration plus live state behind [`LiveState`]:
//!
//! - the exported qualification contract (the `step contract` leaf over Nix);
//! - both surfaces' identities (Hub `/.well-known/aos-deployment`, or a
//!   static surface's `.aos-surface`);
//! - the registry base read from the staging surface: the current ready
//!   publication through Hub RPC, or `<readback>/HEAD` resolved through
//!   `info/refs` on a static surface (static surfaces always plan
//!   generation 0 and compare-and-swap on the commit alone).
//!
//! The destinations are the contract's destinations for the registry tier
//! whose channel kind the version's class allows. The predecessor bundle is
//! verified offline and names the qualification predecessor; the `step plan`
//! leaf derives the change scope against its manifest and verifies any
//! `--override` envelopes before it writes `plan.json`.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_core::nix::NixRunner;
use aos_core::output::Printer;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::plan::{
    ImagePlan, PLAN_REQUEST, PlanningSource, ReleaseClass, ReleasePlanRequest,
    RequestedDestination, RetentionPolicy, SurfaceKind, SurfaceRole, class_allows_channel_kind,
};
use aos_release::platform::MatrixCell;
use aos_release::qualification::QualificationContract;
use aos_release::qualification_evidence::QualificationPredecessor;
use aos_release::registry::registry_policy;
use aos_release::signing::SignerRole;
use async_trait::async_trait;

use super::super::capture;
use super::super::config::MaintainerConfig;
use super::super::surface::readback;
use super::super::{contract, plan};
use super::keys;
use super::workdir::{self, ReleaseIndex, WORK_INDEX, WorkDir, digest_string};
use crate::cli::{ReleaseContractArgs, ReleaseNewArgs, ReleasePlanArgs};

/// Bound on a static surface's `HEAD` object.
const MAX_HEAD_BYTES: usize = 4096;

/// Bound on a static surface's `info/refs` object.
const MAX_REFS_BYTES: usize = 16 * 1024 * 1024;

/// Registry state a plan starts from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RegistryBase {
    /// Registry default-branch commit.
    pub(super) commit: String,
    /// Compare-and-swap generation; zero for static surfaces.
    pub(super) generation: u64,
}

/// Live lookups `new` performs; stubbed in tests.
#[async_trait(?Send)]
pub(super) trait LiveState {
    /// Exports the qualification contract into `output` and returns it.
    async fn contract(&self, registry: &str, output: &Path) -> Result<QualificationContract>;

    /// Requires both configured surfaces to serve their configured identities.
    async fn verify_surfaces(&self, config: &MaintainerConfig) -> Result<()>;

    /// Reads the registry base from the staging surface.
    async fn registry_base(&self, config: &MaintainerConfig) -> Result<RegistryBase>;
}

/// Live lookups over Nix, the surfaces' public routes, and Hub RPC.
struct Live<'a> {
    nix: &'a NixRunner,
    printer: &'a Printer,
}

#[async_trait(?Send)]
impl LiveState for Live<'_> {
    async fn contract(&self, registry: &str, output: &Path) -> Result<QualificationContract> {
        // A resumed `new` reuses the contract it already exported; the plan
        // leaf re-evaluates it and rejects any drift.
        if !output.exists() {
            contract::run(
                &ReleaseContractArgs {
                    registry: registry.to_owned(),
                    to: None,
                    input: None,
                    output: Some(output.to_path_buf()),
                },
                self.nix,
                self.printer,
            )?;
        }
        let bytes = capture::control_file(output, "qualification contract")?;
        let contract: QualificationContract =
            canonical::from_slice(&bytes, "qualification contract")?;
        contract.validate()?;
        Ok(contract)
    }

    async fn verify_surfaces(&self, config: &MaintainerConfig) -> Result<()> {
        let client = readback::public_client()?;
        for role in [SurfaceRole::Staging, SurfaceRole::Production] {
            let planned = config.surface(role).planned(role);
            match planned.kind {
                SurfaceKind::Hub => {
                    readback::verify_deployment(&client, &planned.origin, &planned.identity).await
                }
                SurfaceKind::Static => {
                    let base = readback::base_url(planned.readback())?;
                    readback::verify_static_identity(&client, &base, &planned.identity).await
                }
            }
            .with_context(|| format!("verifying the {role} surface identity"))?;
        }
        Ok(())
    }

    async fn registry_base(&self, config: &MaintainerConfig) -> Result<RegistryBase> {
        let staging = &config.surfaces.staging;
        match staging.kind {
            SurfaceKind::Static => {
                let planned = staging.planned(SurfaceRole::Staging);
                let client = readback::public_client()?;
                let base = readback::base_url(planned.readback())?;
                let head = readback::fetch_small(&client, &base, "HEAD", MAX_HEAD_BYTES)
                    .await?
                    .context("the staging surface serves no registry HEAD; bootstrap it first")?;
                let refs = readback::fetch_small(&client, &base, "info/refs", MAX_REFS_BYTES)
                    .await?
                    .context("the staging surface serves no info/refs")?;
                Ok(RegistryBase {
                    commit:
                        crate::commands::hub::publication::inventory::publication_default_commit(
                            &head, &refs,
                        )?,
                    generation: 0,
                })
            }
            SurfaceKind::Hub => {
                let token = staging
                    .token()?
                    .context("reading the staging Hub registry base requires token_credential")?;
                let hub = aos_remote::hub::HubClient::connect_with_token(&staging.origin, &token)?;
                let listed = hub
                    .call_topology(
                        aos_remote::hub::hub_rpc::ListRegistryPublications,
                        &aos_proto_types::ListRegistryPublicationsRequest {
                            registry: config.registry.clone(),
                            state: "ready".to_owned(),
                            page_size: 1,
                            page_token: String::new(),
                        },
                    )
                    .await?;
                let current = listed
                    .publications
                    .first()
                    .context("the staging Hub holds no ready publication; bootstrap it first")?;
                Ok(RegistryBase {
                    commit: current.default_commit.clone(),
                    generation: u64::try_from(current.ordinal)
                        .context("staging Hub publication ordinal is negative")?,
                })
            }
        }
    }
}

/// Starts a release and freezes its plan.
///
/// # Errors
/// Returns an error for a registry other than the configured one, a work
/// directory that already holds a plan, a failed live lookup, or a plan the
/// planner rejects.
pub(super) async fn run(args: &ReleaseNewArgs, nix: &NixRunner, printer: &Printer) -> Result<()> {
    let (config_path, config) = MaintainerConfig::load(args.config.as_deref())?;
    let live = Live { nix, printer };
    let prepared = prepare(args, &config_path, &config, &live).await?;
    for (label, value) in &prepared.summary {
        printer.kv(label, value);
    }

    let work = &prepared.work;
    printer.info(&format!(
        "Planning {} destination(s) for {}",
        prepared.request.destinations.len(),
        prepared.request.release_id
    ));
    plan::run(
        &ReleasePlanArgs {
            request: work.request(),
            contributor_authorization: work.contributor_authorization(),
            predecessor_manifest: predecessor_manifest(&config),
            overrides: args.override_dir.iter().cloned().collect(),
            override_keys: if args.override_dir.is_some() {
                keys::role_specs(&config, SignerRole::ReleaseEvidence)?
            } else {
                Vec::new()
            },
            output: work.plan(),
        },
        nix,
        printer,
    )?;
    if !work.index_path().exists() {
        work.create_index(&prepared.index)?;
    }

    let plan_bytes = capture::control_file(&work.plan(), "release plan")?;
    let plan: aos_release::plan::ReleasePlan = canonical::from_slice(&plan_bytes, "release plan")?;
    printer.kv("Plan digest", &digest_string(&plan_bytes));
    if let Some(scope) = &plan.change_scope {
        printer.kv("Change scope", &scope.reason);
    }
    for destination in &plan.destinations {
        printer.kv(
            &destination.name,
            &format!(
                "profile {} ({}), soak {}s, {} ring(s)",
                destination.profile,
                destination.profile_digest,
                destination.soak_seconds,
                destination.rings.len()
            ),
        );
    }
    printer.success(&format!(
        "Started {} in {}",
        plan.release_id,
        work.root().display()
    ));
    Ok(())
}

/// A work directory with its derived request, before the plan is frozen.
pub(super) struct Prepared {
    /// The release's work directory.
    pub(super) work: WorkDir,
    /// Derived plan request, already written to `request.json`.
    pub(super) request: ReleasePlanRequest,
    /// Index to write once the plan is frozen.
    pub(super) index: ReleaseIndex,
    /// Request summary rows.
    pub(super) summary: Vec<(String, String)>,
}

/// Creates the work directory and writes the derived request.
///
/// # Errors
/// Returns an error for a registry mismatch, an existing plan, a failed
/// live lookup, or unreadable policy inputs.
pub(super) async fn prepare(
    args: &ReleaseNewArgs,
    config_path: &Path,
    config: &MaintainerConfig,
    live: &dyn LiveState,
) -> Result<Prepared> {
    if args.registry != config.registry {
        bail!(
            "configuration {} serves {}, not {}",
            config_path.display(),
            config.registry,
            args.registry
        );
    }
    let class = ReleaseClass::from_version(&args.version)?;
    let release_id = args
        .release_id
        .clone()
        .unwrap_or_else(|| format!("release-{}", args.version));
    let work = WorkDir::new(
        &args
            .work
            .clone()
            .unwrap_or_else(|| config.work_root.join(&release_id)),
    )?;
    if work.plan().exists() {
        bail!(
            "{} already holds a frozen plan; to change anything, start a new release",
            work.root().display()
        );
    }
    if work.index_path().exists() && work.read_index()?.release_id != release_id {
        bail!("{} belongs to another release", work.root().display());
    }
    std::fs::create_dir_all(work.root())?;

    let authorization = capture::control_file(
        &config.contributor_authorization,
        "contributor-authorization summary",
    )?;
    write_or_match(&work.contributor_authorization(), &authorization)?;

    let contract = live.contract(&config.registry, &work.contract()).await?;
    live.verify_surfaces(config).await?;
    let base = live.registry_base(config).await?;
    let images: Vec<ImagePlan> = canonical::from_slice(
        &capture::control_file(&args.images, "image decisions")?,
        "image decisions",
    )?;
    let inputs = RequestInputs {
        version: args.version.clone(),
        release_id: release_id.clone(),
        class,
        base,
        predecessor: predecessor(config)?.map(|(predecessor, _)| predecessor),
        images,
    };
    let request = assemble_request(config, &contract, &inputs, &authorization)?;
    write_or_match(&work.request(), &canonical::to_vec(&request)?)?;

    let config_bytes = capture::control_file(config_path, "maintainer configuration")?;
    let summary = summary(&request, &contract, args.override_dir.as_deref())?;
    Ok(Prepared {
        work,
        index: ReleaseIndex {
            schema_version: WORK_INDEX.to_owned(),
            registry: config.registry.clone(),
            version: args.version.clone(),
            release_id,
            config_digest: digest_string(&config_bytes),
            created_at: super::steps::now(),
            latest_journal: None,
        },
        request,
        summary,
    })
}

/// Values a request needs beyond the configuration and contract.
pub(super) struct RequestInputs {
    /// Calendar version.
    pub(super) version: String,
    /// Immutable release identity.
    pub(super) release_id: String,
    /// Class derived from the version.
    pub(super) class: ReleaseClass,
    /// Registry base read from the staging surface.
    pub(super) base: RegistryBase,
    /// Verified qualification predecessor, when configured.
    pub(super) predecessor: Option<QualificationPredecessor>,
    /// Reviewed Linux image decisions.
    pub(super) images: Vec<ImagePlan>,
}

/// Assembles the plan request from configuration, contract, and inputs.
///
/// # Errors
/// Returns an error for an unreadable policy file, an invalid signer roster,
/// or a retention policy file name that is not an identifier.
pub(super) fn assemble_request(
    config: &MaintainerConfig,
    contract: &QualificationContract,
    inputs: &RequestInputs,
    authorization: &[u8],
) -> Result<ReleasePlanRequest> {
    let tier = registry_policy(&config.registry)?.tier();
    let destinations = contract
        .destinations_for(tier)
        .filter(|destination| class_allows_channel_kind(inputs.class, &destination.channel))
        .map(|destination| RequestedDestination {
            surface: destination.surface,
            channel: destination.channel.clone(),
            effective: None,
        })
        .collect();
    let retention = capture::control_file(&config.retention_policy, "retention policy")?;
    let operator = capture::control_file(
        &config.restricted_operator_policy,
        "restricted operator policy",
    )?;
    let policy_id = config
        .retention_policy
        .file_stem()
        .and_then(|stem| stem.to_str())
        .context("retention policy file name is not UTF-8")?
        .to_owned();

    Ok(ReleasePlanRequest {
        schema_version: PLAN_REQUEST.to_owned(),
        qualification_predecessor: inputs.predecessor.clone(),
        release_id: inputs.release_id.clone(),
        version: inputs.version.clone(),
        release_class: inputs.class,
        registry: config.registry.clone(),
        registry_base_commit: inputs.base.commit.clone(),
        registry_base_generation: inputs.base.generation,
        source: PlanningSource {
            protected_branch: config.protected_branch.clone(),
            source_tag: format!("release/{}", inputs.version),
            contributor_authorization_digest: Sha256Digest::of_bytes(authorization),
        },
        images: inputs.images.clone(),
        signers: keys::signer_requirements(config)?,
        surfaces: [SurfaceRole::Staging, SurfaceRole::Production]
            .into_iter()
            .map(|role| config.surface(role).planned(role))
            .collect(),
        destinations,
        change_scope: None,
        profile_overrides: Vec::new(),
        retention: RetentionPolicy {
            policy_id,
            policy_digest: Sha256Digest::of_bytes(&retention),
            require_corresponding_source: true,
        },
        public_evidence_policy_digest: contract.digest()?,
        restricted_operator_policy_digest: Sha256Digest::of_bytes(&operator),
    })
}

/// Renders the request summary `new` prints before planning.
///
/// # Errors
/// Returns an error when a requested destination's profile is unknown.
pub(super) fn summary(
    request: &ReleasePlanRequest,
    contract: &QualificationContract,
    override_dir: Option<&Path>,
) -> Result<Vec<(String, String)>> {
    let tier = registry_policy(&request.registry)?.tier();
    let mut rows = vec![
        (
            "Release".to_owned(),
            format!(
                "{} ({}, {})",
                request.release_id, request.version, request.release_class
            ),
        ),
        (
            "Registry".to_owned(),
            format!(
                "{} at {} generation {}",
                request.registry, request.registry_base_commit, request.registry_base_generation
            ),
        ),
        (
            "Source".to_owned(),
            format!(
                "{}, tag {}",
                request.source.protected_branch, request.source.source_tag
            ),
        ),
        (
            "Predecessor".to_owned(),
            request.qualification_predecessor.as_ref().map_or_else(
                || "none: every target is in scope".to_owned(),
                |predecessor| format!("{} {}", predecessor.release_id, predecessor.manifest_digest),
            ),
        ),
    ];
    for surface in &request.surfaces {
        rows.push((
            format!("Surface {}", surface.role),
            format!(
                "{} {} ({})",
                surface_kind_name(surface.kind),
                surface.origin,
                surface.identity
            ),
        ));
    }
    for destination in &request.destinations {
        let cell = contract.destination(tier, destination.surface, &destination.channel)?;
        rows.push((
            format!(
                "Destination {}/{}",
                destination.surface, destination.channel
            ),
            format!("profile {}", cell.profile),
        ));
    }
    let images: Vec<String> = request
        .images
        .iter()
        .flat_map(|image| {
            image.platforms.iter().map(move |cell| match cell.decision {
                MatrixCell::Artifact { .. } => {
                    format!("{} {}", image.system_variant, cell.platform)
                }
                MatrixCell::NotApplicable { .. } => {
                    format!("{} {} not applicable", image.system_variant, cell.platform)
                }
                MatrixCell::Blocked { .. } => {
                    format!("{} {} blocked", image.system_variant, cell.platform)
                }
            })
        })
        .collect();
    rows.push((
        "Images".to_owned(),
        if images.is_empty() {
            "none".to_owned()
        } else {
            images.join(", ")
        },
    ));
    for signer in &request.signers {
        rows.push((
            format!("Signer {:?}", signer.role),
            format!(
                "{} of {} ({})",
                signer.threshold,
                signer.key_ids.join(", "),
                signer.provider_revision
            ),
        ));
    }
    rows.push((
        "Override".to_owned(),
        override_dir.map_or_else(|| "none".to_owned(), |path| path.display().to_string()),
    ));
    rows.push((
        "Policies".to_owned(),
        format!(
            "contract {}, retention {} {}, operator {}",
            request.public_evidence_policy_digest,
            request.retention.policy_id,
            request.retention.policy_digest,
            request.restricted_operator_policy_digest
        ),
    ));
    Ok(rows)
}

/// Returns the configuration spelling of a surface kind.
const fn surface_kind_name(kind: SurfaceKind) -> &'static str {
    match kind {
        SurfaceKind::Hub => "hub",
        SurfaceKind::Static => "static",
    }
}

/// Returns the configured predecessor bundle's manifest envelope path.
pub(super) fn predecessor_manifest(config: &MaintainerConfig) -> Option<PathBuf> {
    config
        .predecessor_bundle
        .as_ref()
        .map(|bundle| bundle.join("release-manifest.json"))
}

/// Verifies the configured predecessor bundle offline and names it.
///
/// The bundle may be a retained qualification snapshot; it must verify
/// against the configuration's independent `trusted_keys` and belong to the
/// configured registry.
///
/// # Errors
/// Returns an error for an unreadable, unverifiable, or foreign bundle.
pub(super) fn predecessor(
    config: &MaintainerConfig,
) -> Result<Option<(QualificationPredecessor, PathBuf)>> {
    let Some(bundle) = &config.predecessor_bundle else {
        return Ok(None);
    };
    let captured = capture::bundle(bundle)?;
    let trusted = super::super::verify::load_trusted_keys(&keys::trusted(config)?)?;
    let summary = aos_release::verify::verify_release(
        &captured.plan_bytes,
        &captured.manifest_bytes,
        &captured.files,
        &trusted,
    )
    .with_context(|| format!("verifying predecessor bundle {}", bundle.display()))?;
    let plan: aos_release::plan::ReleasePlan =
        canonical::from_slice(&captured.plan_bytes, "predecessor plan")?;
    if plan.registry != config.registry {
        bail!("predecessor bundle belongs to registry {}", plan.registry);
    }
    Ok(Some((
        QualificationPredecessor {
            registry: plan.registry,
            release_id: summary.release_id,
            manifest_digest: summary.manifest_digest,
        },
        bundle.join("release-manifest.json"),
    )))
}

/// Writes `bytes` to a new file, or accepts an identical existing file.
///
/// A resumed `new` may find its own earlier outputs; anything different
/// means live state moved and the operator must start over.
fn write_or_match(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        if capture::control_file(path, "work file")? != bytes {
            bail!(
                "{} already exists with different content; remove the unfinished work directory",
                path.display()
            );
        }
        return Ok(());
    }
    workdir::write_new_file(path, bytes)
}

#[cfg(test)]
#[path = "new_tests.rs"]
mod tests;
