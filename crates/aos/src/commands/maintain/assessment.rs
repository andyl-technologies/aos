//! Local execution of the shared package assessment acquisition and policy engine.
//!
//! Explicit profiles select portable assessments. Existing scans without those
//! profiles retain their maintenance v1 contract. Provider requests and parsing
//! use the same source executor and coordinator as the Hub service.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
use aos_assessment::bundle::{AssessmentBundleV1, BundleProfile};
use aos_assessment::input::{
    ASSESSMENT_POLICY_V1, AssessmentPolicyV1, EvaluationData, FreshnessMode, Profile,
};
use aos_assessment::metadata::{PackageAssessmentInventoryV1, SourcePackageBindingV1};
use aos_assessment::time::Timestamp;
use aos_assessment_http::{
    NativeSourceTransport, PhysicalClock, SourceCredential, SourceCredentials,
};
use aos_assessment_runtime::acquisition::{AcquisitionPort, acquire, acquire_stale};
use aos_assessment_runtime::ports::{Clock, EvidenceStore};
use aos_assessment_runtime::provider::{
    BudgetReservation, PROVIDER_WORK_PLAN_V1, ProviderLimits, ProviderOperation, ProviderPageV1,
    ProviderWorkPlanV1, ProviderWorkResultV1, execute_source,
};
use aos_assessment_runtime::scan::{ScanLimits, ScanState, TaskClaim};
use aos_contract::Sha256Digest;
use aos_core::nix::NixRunner;
use aos_core::output::{OutputMode, Printer};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{inventory, state::StateStore};
use crate::cli::{Cli, MaintainArgs, MaintainScanArgs};

/// Runs explicit portable profiles using package metadata or an exact input closure.
///
/// # Errors
/// Returns an error for invalid inputs/selection, missing tools or credentials,
/// unavailable protected state, custody failure or evaluation/export failure.
pub async fn run_assessment(
    cli: &Cli,
    args: &MaintainArgs,
    command: &MaintainScanArgs,
    printer: &Printer,
) -> Result<()> {
    let profiles = crate::cli::assessment_profiles(&command.profiles);
    let freshness = if command.offline {
        FreshnessMode::Offline
    } else {
        command
            .freshness
            .map(Into::into)
            .unwrap_or(FreshnessMode::Refresh)
    };
    let acquire_sources = matches!(
        freshness,
        FreshnessMode::Refresh | FreshnessMode::RefreshStale
    );
    let nix = NixRunner::new(cli.verbose, cli.quiet)?;
    let (mut data, store) = if let Some(input) = &command.assessment_input {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(input)?;
        let mut bytes = Vec::new();
        file.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        let data = EvaluationData::from_slice(&bytes)?;
        let coordinates = inventory::repository_coordinates(nix.root())?;
        (
            data,
            StateStore::open(args.state_dir.as_deref(), &coordinates)?,
        )
    } else {
        let metadata =
            nix.eval_json_for_target("assessmentInventory", command.target.as_deref())?;
        let metadata = PackageAssessmentInventoryV1::from_slice(&serde_json::to_vec(&metadata)?)?;
        let bindings =
            nix.eval_json_for_target("assessmentSourceBindings", command.target.as_deref())?;
        let bindings: Vec<SourcePackageBindingV1> = serde_json::from_value(bindings)?;
        let envelope = inventory::evaluate(&nix, command.target.as_deref())?;
        let source_digest = Sha256Digest::of_canonical("aos.source-content/v1", &envelope.content)?;
        let data = EvaluationData {
            inventory: metadata.source_inventory(&bindings, "aos/source", source_digest)?,
            definitions: metadata.definitions()?,
            upstream: vec![],
            advisory_snapshot: None,
            advisories: vec![],
            dispositions: vec![],
            history: vec![],
            policy: AssessmentPolicyV1 {
                schema: ASSESSMENT_POLICY_V1.into(),
                upstream_max_age_seconds: 86400,
                advisory_max_age_seconds: 86400,
                required_advisory_sources: vec![],
                require_dependency_coverage: true,
            },
        };
        (
            data,
            StateStore::open_for_envelope(args.state_dir.as_deref(), &envelope)?,
        )
    };
    if let Some(cached) = store.assessment_closure()? {
        // First-observation history survives source and inventory changes.
        // Exact evidence bindings are reused only for the identical inventory.
        data.history = merge_history(&cached.history, &data.history);
        if cached.inventory.digest()? == data.inventory.digest()?
            && cached.policy.digest()? == data.policy.digest()?
        {
            data.upstream = cached.upstream;
            data.advisory_snapshot = cached.advisory_snapshot;
            data.advisories = cached.advisories;
        }
    }
    let mut subjects = data
        .inventory
        .subjects
        .iter()
        .filter(|subject| {
            command.packages.is_empty() || command.packages.contains(&subject.package_coordinate)
        })
        .map(|subject| subject.subject_ref.clone())
        .collect::<Vec<_>>();
    if subjects.is_empty()
        || command.packages.iter().any(|coordinate| {
            !data
                .inventory
                .subjects
                .iter()
                .any(|subject| &subject.package_coordinate == coordinate)
        })
    {
        bail!("assessment selection contains an unknown package coordinate");
    }
    subjects.sort();
    let partition = format!(
        "local-{}",
        Sha256Digest::of_bytes(store.root().as_os_str().as_encoded_bytes())
    );
    let credentials = Arc::new(LocalCredentials {
        github: if !acquire_sources {
            None
        } else {
            read_secret(&command.token_env)?
        },
        nvd: if !acquire_sources {
            None
        } else {
            read_secret(&command.nvd_key_env)?
        },
    });
    let scan_id = Uuid::new_v4().to_string();
    let _scan_lease = store.acquire_operation_lease(&scan_id)?;
    store.recover_local_assessment_scans(100)?;
    let issued_at = PhysicalClock.now()?;
    let (receipt, is_new) = store.admit_local_assessment_scan(
        &scan_id,
        &data,
        subjects.clone(),
        profiles.clone(),
        freshness,
        command.idempotency_key.as_deref().unwrap_or(&scan_id),
        issued_at.clone(),
    )?;
    if !is_new {
        super::assessment_scans::print_local_receipt(args, printer, &receipt);
        return Ok(());
    }
    let _provider_lane = store.acquire_operation_lease("package-assessment")?;
    let started = store.start_local_assessment_scan(&scan_id)?;
    if started.state != ScanState::Running {
        super::assessment_scans::print_local_receipt(args, printer, &started);
        bail!("local assessment scan was cancelled before execution");
    }
    let port = LocalPort {
        transport: NativeSourceTransport::new(credentials.clone()),
        credentials,
        evidence: LocalEvidence {
            store: &store,
            partition: &partition,
        },
        inventory_digest: started.request.inventory_digest,
        policy_digest: started.request.policy_digest,
        request_digest: started.request_digest,
        inventory_revision: started.request.inventory_revision,
        generation: started.generation,
        scan_id: scan_id.clone(),
        issued_at,
        limits: started.request.limits.clone(),
    };
    let executed = tokio::select! {
        result = execute_assessment(cli, args, command, printer, &store, &port, data, profiles, subjects, &partition, freshness) => result,
        signal = tokio::signal::ctrl_c() => {
            signal?;
            Err(anyhow::anyhow!("assessment interrupted; admitted evidence remains available"))
        }
    };
    if let Err(error) = executed {
        store.fail_local_assessment_scan(&scan_id, "local-scan-failed")?;
        return Err(error);
    }
    Ok(())
}

async fn execute_assessment(
    cli: &Cli,
    args: &MaintainArgs,
    command: &MaintainScanArgs,
    printer: &Printer,
    store: &StateStore,
    port: &LocalPort<'_>,
    mut data: EvaluationData,
    profiles: Vec<Profile>,
    subjects: Vec<String>,
    partition: &str,
    freshness: FreshnessMode,
) -> Result<()> {
    let diagnostics = if matches!(freshness, FreshnessMode::Offline | FreshnessMode::Cached) {
        if profiles.contains(&Profile::Vulnerabilities) && data.advisory_snapshot.is_none() {
            data.advisory_snapshot = Some(aos_assessment::advisory::AdvisorySnapshotV1 {
                schema: aos_assessment::advisory::ADVISORY_SNAPSHOT_V1.into(),
                sources: vec![],
                exploit_catalog: None,
            });
        }
        vec![]
    } else if freshness == FreshnessMode::RefreshStale {
        acquire_stale(
            port,
            &port.evidence,
            partition,
            &mut data,
            &subjects,
            &profiles,
            &PhysicalClock.now()?,
        )
        .await?
    } else {
        acquire(
            port,
            &port.evidence,
            partition,
            &mut data,
            &subjects,
            &profiles,
        )
        .await?
    };
    let evaluated_at = PhysicalClock.now()?;
    let input = data.freeze_selected(profiles, subjects, evaluated_at)?;
    let result = aos_assessment::evaluator::evaluate(&input, &data)?;
    let usage = store.inspect_local_assessment_scan(&port.scan_id)?.usage;
    let receipt =
        store.commit_local_assessment_scan(&port.scan_id, &input, &data, &result, &usage)?;
    if !matches!(receipt.state, ScanState::Succeeded | ScanState::Partial) {
        super::assessment_scans::print_local_receipt(args, printer, &receipt);
        bail!("local assessment scan ended in {}", receipt.state.as_str());
    }
    if let Some(path) = &command.evidence_output {
        let bundle = AssessmentBundleV1::export(
            input.clone(),
            data.clone(),
            BundleProfile::Reference,
            vec![],
        )?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .context("creating a new assessment evidence export")?;
        output.write_all(&bundle.encoded()?)?;
        output.sync_all()?;
    }
    if cli.json || args.jsonl || printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "schema_version":"aos.assessment-cli/v1", "kind":"package-assessment",
            "execution":{"mode":"local", "scan_id":port.scan_id,"scan_input_digest":input.digest()?,"diagnostics":diagnostics,"scan":receipt},
            "data":result,
        }));
    } else {
        for subject in &result.subject_results {
            let package = data
                .inventory
                .subjects
                .iter()
                .find(|package| package.subject_ref == subject.subject_ref)
                .context("assessment result contains an unknown subject")?;
            let label = format!(
                "{} {} ({})",
                package.package_coordinate, package.version, package.platform
            );
            for line in aos_maintain::presentation::assessment_subject_lines(subject, &label) {
                printer.info(&line);
            }
        }
        for diagnostic in diagnostics {
            printer.info(&diagnostic);
        }
    }
    Ok(())
}

fn read_secret(name: &str) -> Result<Option<Zeroizing<String>>> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        bail!("invalid assessment credential environment variable name");
    }
    match std::env::var(name) {
        Ok(value) if value.is_empty() => Ok(None),
        Ok(value) if value.len() <= 8192 && !value.chars().any(char::is_control) => {
            Ok(Some(Zeroizing::new(value)))
        }
        Ok(_) => bail!("assessment source credential has an invalid bounded header value"),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => bail!("assessment source credential is not valid text"),
    }
}

fn merge_history(
    left: &[aos_assessment::input::CandidateHistory],
    right: &[aos_assessment::input::CandidateHistory],
) -> Vec<aos_assessment::input::CandidateHistory> {
    let mut merged = BTreeMap::new();
    for entry in left.iter().chain(right) {
        let key = (
            entry.provider.clone(),
            entry.project.clone(),
            entry.raw_id.clone(),
        );
        merged
            .entry(key)
            .and_modify(|previous: &mut Timestamp| {
                *previous = previous.clone().min(entry.first_observed_at.clone())
            })
            .or_insert_with(|| entry.first_observed_at.clone());
    }
    merged
        .into_iter()
        .map(|((provider, project, raw_id), first_observed_at)| {
            aos_assessment::input::CandidateHistory {
                provider,
                project,
                raw_id,
                first_observed_at,
            }
        })
        .collect()
}

struct LocalCredentials {
    github: Option<Zeroizing<String>>,
    nvd: Option<Zeroizing<String>>,
}

#[async_trait::async_trait]
impl SourceCredentials for LocalCredentials {
    async fn resolve(&self, plan: &ProviderWorkPlanV1) -> Result<SourceCredential> {
        match (plan.credential_ref.as_deref(), plan.operation.provider()) {
            (None, _) => Ok(SourceCredential::Anonymous),
            (Some("local-github-read"), "github-releases" | "github-tags") => {
                Ok(SourceCredential::Github(
                    self.github
                        .clone()
                        .context("local GitHub credential is absent")?,
                ))
            }
            (Some("local-nvd-read"), "nvd") => Ok(SourceCredential::Nvd(
                self.nvd.clone().context("local NVD credential is absent")?,
            )),
            _ => bail!("local credential is outside its installed source scope"),
        }
    }
}

struct LocalEvidence<'a> {
    store: &'a StateStore,
    partition: &'a str,
}

#[async_trait::async_trait]
impl EvidenceStore for LocalEvidence<'_> {
    async fn retain(&self, partition: &str, bytes: &[u8]) -> Result<Sha256Digest> {
        anyhow::ensure!(
            partition == self.partition,
            "local evidence partition mismatch"
        );
        self.store.retain_assessment_source(partition, bytes)
    }
    async fn read(&self, partition: &str, digest: Sha256Digest, limit: u64) -> Result<Vec<u8>> {
        anyhow::ensure!(
            partition == self.partition,
            "local evidence partition mismatch"
        );
        self.store.read_assessment_source(partition, digest, limit)
    }
}

struct LocalPort<'a> {
    transport: NativeSourceTransport,
    credentials: Arc<LocalCredentials>,
    evidence: LocalEvidence<'a>,
    inventory_digest: Sha256Digest,
    policy_digest: Sha256Digest,
    scan_id: String,
    request_digest: Sha256Digest,
    inventory_revision: u64,
    generation: u64,
    issued_at: Timestamp,
    limits: ScanLimits,
}

#[async_trait::async_trait]
impl AcquisitionPort for LocalPort<'_> {
    async fn require_current(&self) -> Result<()> {
        self.evidence
            .store
            .require_local_assessment_running(&self.scan_id)
    }

    async fn invoke(
        &self,
        operation: &ProviderOperation,
        previous: Option<&ProviderPageV1>,
    ) -> Result<ProviderWorkResultV1> {
        let now = PhysicalClock.now()?;
        anyhow::ensure!(
            now.elapsed_since(&self.issued_at)? < u64::from(self.limits.wall_seconds),
            "local assessment wall time is exhausted"
        );
        let requests = operation.source_requests()?.len() as u32;
        let expires = Timestamp::from_unix_seconds(now.unix_seconds() + 60)?;
        let id = Uuid::new_v4().to_string();
        let credential_ref = match operation.provider() {
            "github-releases" | "github-tags" if self.credentials.github.is_some() => {
                Some("local-github-read".into())
            }
            "nvd" if self.credentials.nvd.is_some() => Some("local-nvd-read".into()),
            _ => None,
        };
        let cache_ref = self.evidence.store.local_conditional_response(
            self.evidence.partition,
            operation,
            &now,
            ProviderLimits::default().response_bytes,
        )?;
        let plan = ProviderWorkPlanV1 {
            schema: PROVIDER_WORK_PLAN_V1.into(),
            deployment_id: "local".into(),
            issuer: "local-coordinator".into(),
            audience: "local-provider".into(),
            plan_id: id.clone(),
            claim: TaskClaim {
                scan_id: self.scan_id.clone(),
                task_id: id.clone(),
                request_digest: self.request_digest,
                generation: self.generation,
                inventory_revision: self.inventory_revision,
                claim_token: Uuid::new_v4().simple().to_string(),
                expires_at: expires.clone(),
                attempt: 1,
            },
            issued_at: now,
            expires_at: expires.clone(),
            nonce: Uuid::new_v4().simple().to_string(),
            inventory_digest: self.inventory_digest,
            policy_digest: self.policy_digest,
            authorization_partition: self.evidence.partition.into(),
            credential_ref,
            budget_reservation: BudgetReservation {
                source_budget: format!("local-{}", operation.provider()),
                reservation_id: id,
                requests,
                deadline: expires,
            },
            cache_ref,
            continuation: previous.map(ProviderPageV1::digest).transpose()?,
            continuation_ref: previous.cloned(),
            operation: operation.clone(),
            adapter_version: operation.adapter_version().into(),
            limits: ProviderLimits {
                requests,
                concurrency: 1,
                ..Default::default()
            },
        };
        self.evidence
            .store
            .reserve_local_assessment_source(&plan, &PhysicalClock.now()?)?;
        let executed = execute_source(
            &self.transport,
            &self.evidence,
            &PhysicalClock,
            &plan,
            "aos-local/v1",
            86400,
        )
        .await;
        let settled_at = PhysicalClock.now()?;
        let result = match executed {
            Ok(result) => {
                self.evidence
                    .store
                    .settle_assessment_source(&plan, Some(&result), &settled_at)?;
                self.evidence
                    .store
                    .retain_local_conditional_response(&plan, &result)?;
                result
            }
            Err(error) => {
                self.evidence
                    .store
                    .settle_assessment_source(&plan, None, &settled_at)?;
                return Err(error);
            }
        };
        let bytes = serde_json::to_vec(&result)?.len() as u64;
        self.evidence
            .store
            .consume_local_assessment_bytes(&self.scan_id, bytes)?;
        Ok(result)
    }
}
