//! Leaf-command invocations for each planner step.
//!
//! Every step constructs the leaf's Args struct from the maintainer
//! configuration and the work directory and calls the leaf's `run` function
//! in process. The leaf verifies everything it consumes and writes its
//! output without replacing an existing path; this module only chooses
//! inputs and output locations. The surface-metadata steps (`record`, `tuf`,
//! timestamp refresh and publication, `compose-surface`) live in
//! [`super::surface_metadata`].

use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::{Context as _, Result, bail};
use aos_core::nix::NixRunner;
use aos_core::output::Printer;
use aos_release::digest::Sha256Digest;
use aos_release::plan::{PlannedDestination, SurfaceRole};
use aos_release::platform::{MatrixCell, Platform};
use aos_release::receipt::ChannelReceipt;
use aos_release::signing::SignerRole;
use aos_release::state::ReleaseState;
use serde::Serialize;

use super::super::access::{self, SignerNeed};
use super::super::{
    build, capture, channel, finalize, finalize_cache, finalize_image, finalize_registry,
    qualification_run, verify,
};
use super::Session;
use super::keys;
use super::observe::{self, Observation};
use super::planner::Step;
use super::workdir::{self, Phase};
use crate::cli::{
    ReleaseAssembleArgs, ReleaseBuildArgs, ReleaseChannelAdvanceArgs, ReleaseChannelCommand,
    ReleaseChannelCompleteArgs, ReleaseFinalizeArgs, ReleaseFinalizeCacheArgs,
    ReleaseFinalizeImageArgs, ReleaseFinalizeRegistryArgs, ReleaseFitnessInputArgs,
    ReleasePrepareRegistryArgs, ReleasePublishArgs, ReleaseQualifyRunArgs, ReleaseVerifyArgs,
};

/// Cache priority written into `nix-cache-info`.
const CACHE_PRIORITY: u32 = 40;

/// Bound on one native executor operation.
const EXECUTOR_TIMEOUT_SECONDS: u64 = 1800;

/// Bound on one image finalization signer operation.
const IMAGE_SIGNER_TIMEOUT_SECONDS: u64 = 300;

/// Schema of the operator's recorded transaction acceptance.
const TRANSACTION_ACCEPTANCE: &str = "aos.release.transaction-acceptance/v1";

/// Schema of the driver's offline verification record.
const WORK_VERIFICATION: &str = "aos.release.work-verification/v1";

/// Runs leaf steps for one session.
pub(super) struct Driver<'a> {
    /// Open release.
    pub(super) session: &'a Session,
    /// Nix environment for steps that evaluate Nix.
    pub(super) nix: &'a NixRunner,
    /// Output sink shared with the leaves.
    pub(super) printer: &'a Printer,
}

impl Driver<'_> {
    /// Runs one planner step toward `destination`.
    ///
    /// # Errors
    /// Returns the leaf command's error verbatim.
    pub(super) async fn execute(
        &self,
        step: &Step,
        destination: &PlannedDestination,
        observation: &Observation,
    ) -> Result<()> {
        match step {
            Step::Build => self.build(),
            Step::FinalizeImage {
                system_variant,
                platform,
            } => self.finalize_image(system_variant, *platform).await,
            Step::PrepareRegistry => self.prepare_registry().await,
            Step::AcceptTransaction => self.accept_transaction(),
            Step::FinalizeRegistry => self.finalize_registry().await,
            Step::FinalizeCache => self.finalize_cache().await,
            Step::Assemble => self.assemble(),
            Step::Finalize => self.finalize().await,
            Step::Verify => self.verify(),
            Step::Retire(phase) => self.retire(destination, *phase),
            Step::Collect(phase) => self.qualify(destination, *phase, observation, false).await,
            Step::Admit(phase) => self.qualify(destination, *phase, observation, true).await,
            Step::Record => self.record(destination, observation),
            Step::Tuf => self.tuf(destination).await,
            Step::RefreshTimestamp => self.refresh_timestamp(destination).await,
            Step::RetireTimestamp => self.retire_timestamp(destination),
            Step::ComposeSurface => self.compose_surface(destination),
            Step::Publish => self.publish(destination, observation).await,
            Step::PublishTimestamp => self.publish_timestamp(destination).await,
            Step::AdvanceRing(ring) => self.advance_ring(destination, *ring, observation).await,
            Step::Complete => self.complete(destination, observation).await,
        }
    }

    fn build(&self) -> Result<()> {
        let work = &self.session.work;
        build::run(
            &ReleaseBuildArgs {
                plan: work.plan(),
                output: work.build(),
                started_at: now(),
            },
            self.nix,
            self.printer,
        )
    }

    async fn finalize_image(&self, system_variant: &str, platform: Platform) -> Result<()> {
        let config = &self.session.config;
        let work = &self.session.work;
        let output = work.image_work(platform, system_variant);
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let signer_keys = [
            ("secure-boot-db", SignerRole::SecureBootDb),
            ("kernel-module", SignerRole::KernelModule),
            ("pcr-policy", SignerRole::PcrPolicy),
        ]
        .into_iter()
        .map(|(name, role)| Ok(format!("{name}={}", keys::single(config, role)?.key_id)))
        .collect::<Result<Vec<_>>>()?;
        finalize_image::run(
            &ReleaseFinalizeImageArgs {
                plan: work.plan(),
                assembly: self.planned_assembly(system_variant, platform)?,
                signer_executable: config.signer.executable.clone(),
                signer_keys,
                signer_timeout_seconds: IMAGE_SIGNER_TIMEOUT_SECONDS,
                work: output,
            },
            self.nix,
            self.printer,
        )
        .await
    }

    /// Returns the unsigned assembly store path the plan's logical disk names.
    fn planned_assembly(&self, system_variant: &str, platform: Platform) -> Result<PathBuf> {
        let image = self
            .session
            .plan
            .images
            .iter()
            .find(|image| image.system_variant == system_variant)
            .with_context(|| format!("the plan has no {system_variant} image"))?;
        let cell = image
            .platforms
            .iter()
            .find(|cell| cell.platform == platform)
            .with_context(|| format!("the plan has no {system_variant} {platform} cell"))?;
        let MatrixCell::Artifact { artifact } = &cell.decision else {
            bail!("the plan does not authorize a {system_variant} {platform} image");
        };
        artifact
            .artifacts
            .iter()
            .find(|planned| planned.id.rsplit('/').next() == Some("logical-disk"))
            .and_then(|planned| planned.store_path.as_deref())
            .map(PathBuf::from)
            .context("the planned image cell lacks its logical-disk assembly store path")
    }

    async fn prepare_registry(&self) -> Result<()> {
        let config = &self.session.config;
        let work = &self.session.work;
        let provenance = keys::single(config, SignerRole::Provenance)?;
        let (container_release, container_signature_input) = self.container_inputs();
        finalize_registry::prepare(
            &ReleasePrepareRegistryArgs {
                plan: work.plan(),
                build_report: work.build_report(),
                container_release,
                container_signature_input,
                source_registry: work.source_registry(),
                output: work.registry(),
                transaction: work.transaction(),
                signer_executable: config.signer.executable.clone(),
                provenance_key: keys::spec(&provenance),
                provenance_verification_identity: provenance.verification_identity,
                signer_timeout_seconds: config.signer.timeout_seconds,
            },
            self.printer,
        )
        .await
    }

    /// Records that the operator accepted the exact generated transaction.
    fn accept_transaction(&self) -> Result<()> {
        let work = &self.session.work;
        let transaction = capture::control_file(&work.transaction(), "registry transaction")?;
        #[derive(Serialize)]
        struct Acceptance {
            schema_version: &'static str,
            transaction_digest: Sha256Digest,
            accepted_at: String,
        }
        workdir::write_new_json(
            &work.transaction_acceptance(),
            &Acceptance {
                schema_version: TRANSACTION_ACCEPTANCE,
                transaction_digest: Sha256Digest::of_bytes(&transaction),
                accepted_at: now(),
            },
        )?;
        self.printer
            .success("Recorded operator acceptance of registry/transaction.json");
        Ok(())
    }

    async fn finalize_registry(&self) -> Result<()> {
        let config = &self.session.config;
        let work = &self.session.work;
        let registry = keys::single(config, SignerRole::Registry)?;
        let (container_release, container_signature_input) = self.container_inputs();
        finalize_registry::finalize(
            &ReleaseFinalizeRegistryArgs {
                plan: work.plan(),
                build_report: work.build_report(),
                transaction: work.transaction(),
                prepared_registry: work.registry(),
                container_release,
                container_signature_input,
                result: work.registry_result(),
                signer_executable: config.signer.executable.clone(),
                registry_key: keys::spec(&registry),
                registry_verification_identity: registry.verification_identity,
                signer_timeout_seconds: config.signer.timeout_seconds,
                git_name: config.git.name.clone(),
                git_email: config.git.email.clone(),
                git_unix_seconds: unix_seconds()?,
                git_offset_minutes: 0,
            },
            self.printer,
        )
        .await
    }

    /// Returns the container sidecar inputs when the operator supplied a bundle.
    fn container_inputs(&self) -> (Option<PathBuf>, Option<PathBuf>) {
        let container = self.session.work.container();
        if container.is_dir() {
            (
                Some(container.join("container-release.json")),
                Some(container.join("signature-input.json")),
            )
        } else {
            (None, None)
        }
    }

    async fn finalize_cache(&self) -> Result<()> {
        let config = &self.session.config;
        let work = &self.session.work;
        let cache = keys::single(config, SignerRole::Cache)?;
        finalize_cache::run(
            &ReleaseFinalizeCacheArgs {
                plan: work.plan(),
                build_report: work.build_report(),
                registry: work.registry(),
                cache_key: keys::spec(&cache),
                verification_identity: cache.verification_identity,
                signer_executable: config.signer.executable.clone(),
                signer_timeout_seconds: config.signer.timeout_seconds,
                priority: CACHE_PRIORITY,
                jobs: None,
                output: work.cache(),
            },
            self.printer,
        )
        .await
    }

    fn assemble(&self) -> Result<()> {
        let config = &self.session.config;
        let work = &self.session.work;
        let image_sets = self
            .session
            .plan
            .images
            .iter()
            .flat_map(|image| {
                image.platforms.iter().filter_map(move |cell| {
                    matches!(cell.decision, MatrixCell::Artifact { .. }).then(|| {
                        work.image_work(cell.platform, &image.system_variant)
                            .join("finalized")
                    })
                })
            })
            .collect();
        let container = work.container();
        super::super::assemble::run(
            &ReleaseAssembleArgs {
                plan: work.plan(),
                build_report: work.build_report(),
                sbom: work.sbom(),
                contributor_authorization: work.contributor_authorization(),
                advisory_disposition: work.advisory_disposition(),
                cache: work.cache(),
                cache_key: keys::spec(&keys::single(config, SignerRole::Cache)?),
                registry: work.registry(),
                registry_result: work.registry_result(),
                image_sets,
                container: container.is_dir().then_some(container),
                completed_at: now(),
                output: work.assembled(),
            },
            self.nix,
            self.printer,
        )
    }

    async fn finalize(&self) -> Result<()> {
        let config = &self.session.config;
        let work = &self.session.work;
        let signers = keys::threshold(config, SignerRole::ReleaseEvidence)?;
        finalize::run(
            &ReleaseFinalizeArgs {
                plan: work.plan(),
                payload: work.assembled().join("payload"),
                manifest_payload: work.assembled().join("release-manifest-payload.json"),
                journal: work.build_journal(),
                signing_keys: signers.iter().map(keys::spec).collect(),
                verification_identities: signers
                    .iter()
                    .map(|key| format!("{}={}", key.key_id, key.verification_identity))
                    .collect(),
                signer_executable: config.signer.executable.clone(),
                signer_timeout_seconds: config.signer.timeout_seconds,
                recorded_at: now(),
                output: work.finalized(),
            },
            self.printer,
        )
        .await
    }

    /// Verifies the finalized bundle offline and records the verification.
    fn verify(&self) -> Result<()> {
        let work = &self.session.work;
        verify::run(
            &ReleaseVerifyArgs {
                bundle: work.bundle(),
                trusted_keys: keys::trusted(&self.session.config)?,
                journal: Some(work.finalized_journal()),
            },
            self.printer,
        )?;
        let journal = capture::control_file(&work.finalized_journal(), "finalized journal")?;
        #[derive(Serialize)]
        struct Verification {
            schema_version: &'static str,
            finalized_journal_digest: Sha256Digest,
            verified_at: String,
        }
        workdir::write_new_json(
            &work.verification(),
            &Verification {
                schema_version: WORK_VERIFICATION,
                finalized_journal_digest: Sha256Digest::of_bytes(&journal),
                verified_at: now(),
            },
        )
    }

    /// Moves a rejected report or stale admission aside without deleting it.
    fn retire(&self, destination: &PlannedDestination, phase: Phase) -> Result<()> {
        let current = self.session.work.phase(&destination.name, phase);
        let parent = current
            .parent()
            .context("qualification directory has no parent")?;
        let target = (1..=u32::MAX)
            .map(|attempt| parent.join(format!("{}.retired-{attempt}", phase.directory_name())))
            .find(|candidate| !candidate.exists())
            .context("no free retired-attempt name")?;
        workdir::rename_noreplace(&current, &target)?;
        self.printer.info(&format!(
            "Retired {} to {}; it will be recollected",
            self.session.work.relative(&current),
            self.session.work.relative(&target)
        ));
        Ok(())
    }

    /// Collects (`admit == false`) or signs (`admit == true`) one hold point.
    async fn qualify(
        &self,
        destination: &PlannedDestination,
        phase: Phase,
        observation: &Observation,
        admit: bool,
    ) -> Result<()> {
        let session = self.session;
        let config = &session.config;
        let work = &session.work;
        let name = destination.name.as_str();
        let directory = work.phase(name, phase);
        std::fs::create_dir_all(&directory)?;

        // The staging phase observes the staging surface; later phases the
        // destination's own publication.
        let (receipt, receipt_role) = match phase {
            Phase::Staging => (self.staging_receipt(observation)?, SurfaceRole::Staging),
            _ => (work.publication_receipt(name), destination.surface),
        };
        let journal = match phase {
            Phase::Staging => None,
            _ => Some(observation.require_journal()?.0.clone()),
        };
        let prior_generation = match phase {
            Phase::Rollout(_) => Some(self.current_generation(destination, observation).await?),
            _ => None,
        };
        let review_receipts = if admit {
            let tally = observe::tally_reviews(
                work,
                Sha256Digest::of_bytes(&session.plan_bytes),
                name,
                phase,
                &observation.evidence_keys,
            )?;
            tally.accepted.into_iter().map(|(_, path)| path).collect()
        } else {
            Vec::new()
        };
        let authority = keys::single(config, SignerRole::Qualification)?;
        let predecessor_bundle = if admit {
            None
        } else {
            config.predecessor_bundle.clone()
        };

        let args = ReleaseQualifyRunArgs {
            to: name.to_owned(),
            prepare_only: !admit,
            report_input: admit.then(|| directory.join("prepared/qualification-report.json")),
            phase: phase.leaf_phase().to_owned(),
            ring: match phase {
                Phase::Rollout(ring) => Some(ring),
                _ => None,
            },
            prior_generation,
            journal,
            review_receipts,
            bundle: work.bundle(),
            staging_receipt: receipt,
            predecessor_bundle,
            trusted_keys: keys::trusted(config)?,
            hub_receipt_keys: keys::receipt(config, receipt_role)?,
            executors: executor_specs(config, |executor| executor.path.display().to_string())?,
            executor_identities: executor_specs(config, |executor| executor.identity.clone())?,
            executor_timeout_seconds: EXECUTOR_TIMEOUT_SECONDS,
            authority_executable: config.signer.executable.clone(),
            authority_key: keys::spec(&authority),
            authority_verification_identity: authority.verification_identity,
            authority_timeout_seconds: config.signer.timeout_seconds,
            executor_nonce: fresh_nonce(),
            authority_nonce: fresh_nonce(),
            qualified_at: "now".to_owned(),
            output: directory.join(if admit { "signed" } else { "prepared" }),
        };
        qualification_run::run(&args, self.printer).await
    }

    /// Returns the receipt of the staging publication the journal recorded.
    pub(super) fn staging_receipt(&self, observation: &Observation) -> Result<PathBuf> {
        let (_, journal) = observation.require_journal()?;
        let plan = &self.session.plan;
        let name = journal
            .entries
            .iter()
            .filter(|entry| entry.new_state == ReleaseState::Published)
            .filter_map(|entry| entry.destination.as_deref())
            .find(|name| {
                plan.destination(name)
                    .is_ok_and(|destination| destination.surface == SurfaceRole::Staging)
            })
            .context("no staging destination is published yet")?;
        Ok(self.session.work.publication_receipt(name))
    }

    /// Reads the destination channel's current generation from its surface.
    async fn current_generation(
        &self,
        destination: &PlannedDestination,
        observation: &Observation,
    ) -> Result<u64> {
        let session = self.session;
        let (_, journal) = observation.require_journal()?;
        let earlier: Vec<ChannelReceipt> =
            observe::ring_receipts(&session.work, journal, &destination.name)?
                .into_iter()
                .map(|(_, _, receipt)| receipt)
                .collect();
        let client = access::connect(
            &session.plan,
            destination.surface,
            None,
            Some(&session.config_path),
            SignerNeed::None,
        )
        .await?;
        client.verify_identity().await?;
        client
            .current_generation(&destination.channel, &earlier)
            .await
    }

    async fn publish(
        &self,
        destination: &PlannedDestination,
        observation: &Observation,
    ) -> Result<()> {
        let session = self.session;
        let config = &session.config;
        let work = &session.work;
        let name = destination.name.as_str();
        let (journal, replayed) = observation.require_journal()?;
        let production = destination.surface == SurfaceRole::Production;
        // The first publication on a surface carries its composed TUF
        // metadata; a surface already holding the release is only verified.
        let surface = if replayed
            .summary
            .surface_holds_publication(destination.surface)
        {
            None
        } else {
            let overlay = work.surface_overlay(name);
            if !overlay.is_dir() {
                bail!(
                    "{} has no composed surface overlay at {}",
                    name,
                    work.relative(&overlay)
                );
            }
            Some(overlay)
        };
        // A composed overlay is admitted only against the independent TUF
        // root trust; the TUF steps that composed it already required [tuf].
        let (trusted_root_keys, trusted_root_threshold) = match (&surface, &config.tuf) {
            (None, _) => (Vec::new(), 1),
            (Some(_), Some(tuf)) => (tuf.trusted_root_keys.clone(), tuf.trusted_root_threshold),
            (Some(_), None) => bail!("publishing a composed surface requires the [tuf] section"),
        };
        let args = ReleasePublishArgs {
            to: name.to_owned(),
            bundle: work.bundle(),
            journal: journal.clone(),
            surface,
            trusted_root_keys,
            trusted_root_threshold,
            trusted_keys: keys::trusted(config)?,
            receipt_keys: keys::receipt(config, destination.surface)?,
            predecessor_receipt: production
                .then(|| self.staging_receipt(observation))
                .transpose()?,
            predecessor_receipt_keys: if production {
                keys::receipt(config, SurfaceRole::Staging)?
            } else {
                Vec::new()
            },
            evidence: if production {
                vec![work.phase(name, Phase::Staging).join("signed")]
            } else {
                Vec::new()
            },
            qualification_keys: if production {
                keys::role_specs(config, SignerRole::Qualification)?
            } else {
                Vec::new()
            },
            fitness: ReleaseFitnessInputArgs::default(),
            token: None,
            config: Some(session.config_path.clone()),
            output: work.published(name),
        };
        super::super::publish::run(&args, self.printer).await
    }

    async fn advance_ring(
        &self,
        destination: &PlannedDestination,
        ring: u16,
        observation: &Observation,
    ) -> Result<()> {
        let session = self.session;
        let config = &session.config;
        let work = &session.work;
        let name = destination.name.as_str();
        let (journal_path, journal) = observation.require_journal()?;
        let signed = work.phase(name, Phase::Rollout(ring)).join("signed");
        let admission = observe::read_admission(&signed)?;
        // The channel operation must name exactly the generation the rollout
        // admission was signed for; without an admission the leaf reads it.
        let prior_generation = admission
            .as_ref()
            .and_then(|admission| admission.rollout.as_ref())
            .map(|intent| intent.prior_generation);
        let args = ReleaseChannelAdvanceArgs {
            to: name.to_owned(),
            ring,
            prior_generation,
            qualification: admission.is_some().then_some(signed),
            qualification_keys: keys::role_specs(config, SignerRole::Qualification)?,
            bundle: work.bundle(),
            journal: journal_path.clone(),
            publication_receipt: work.publication_receipt(name),
            channel_receipts: observe::ring_receipts(work, journal, name)?
                .into_iter()
                .map(|(_, path, _)| path)
                .collect(),
            trusted_keys: keys::trusted(config)?,
            receipt_keys: keys::receipt(config, destination.surface)?,
            channel_receipt_keys: Vec::new(),
            fitness: ReleaseFitnessInputArgs::default(),
            token: None,
            config: Some(session.config_path.clone()),
            output: work.ring(name, ring),
        };
        channel::run(&ReleaseChannelCommand::Advance(args), self.printer).await
    }

    async fn complete(
        &self,
        destination: &PlannedDestination,
        observation: &Observation,
    ) -> Result<()> {
        let session = self.session;
        let config = &session.config;
        let work = &session.work;
        let name = destination.name.as_str();
        let (journal_path, journal) = observation.require_journal()?;
        let head = journal
            .entries
            .last()
            .context("release journal is empty")?
            .digest()?;
        let approvals = observe::tally_completions(work, name, head, &observation.evidence_keys)?;
        let completion_keys = approvals
            .iter()
            .map(|(key_id, _, _)| {
                keys::find(config, SignerRole::ReleaseEvidence, key_id).map(|key| keys::spec(&key))
            })
            .collect::<Result<Vec<_>>>()?;
        let signed = work.phase(name, Phase::Complete).join("signed");
        let args = ReleaseChannelCompleteArgs {
            to: name.to_owned(),
            qualification: signed
                .join("signed-qualification.json")
                .is_file()
                .then_some(signed),
            qualification_keys: keys::role_specs(config, SignerRole::Qualification)?,
            bundle: work.bundle(),
            journal: journal_path.clone(),
            publication_receipt: work.publication_receipt(name),
            channel_receipts: observe::ring_receipts(work, journal, name)?
                .into_iter()
                .map(|(_, path, _)| path)
                .collect(),
            completion_receipts: approvals.into_iter().map(|(_, path, _)| path).collect(),
            trusted_keys: keys::trusted(config)?,
            receipt_keys: keys::receipt(config, destination.surface)?,
            channel_receipt_keys: Vec::new(),
            completion_keys,
            output: work.completion(name),
        };
        channel::run(&ReleaseChannelCommand::Complete(args), self.printer).await
    }
}

/// Renders one `PLATFORM=VALUE` specification per configured executor.
fn executor_specs(
    config: &super::super::config::MaintainerConfig,
    value: impl Fn(&super::super::config::ExecutorConfig) -> String,
) -> Result<Vec<String>> {
    if config.executors.is_empty() {
        bail!("maintainer configuration has no [executors.<platform>] tables");
    }
    Ok(config
        .executors
        .iter()
        .map(|(platform, executor)| format!("{platform}={}", value(executor)))
        .collect())
}

/// Returns a fresh 32-byte lowercase hexadecimal nonce.
fn fresh_nonce() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

/// Returns the current time as RFC 3339 UTC with second precision.
pub(super) fn now() -> String {
    super::super::journal::now_utc()
}

fn unix_seconds() -> Result<i64> {
    let elapsed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    Ok(i64::try_from(elapsed.as_secs())?)
}
