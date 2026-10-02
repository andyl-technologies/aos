//! Read-only assembly of a dedicated Fleet OCI profile and fixture control.
//!
//! The caller supplies real operator exports, independently selected provider
//! facts and an existing exact PostgreSQL schema. This helper rechecks current
//! SQL and uses the shared cohort/profile/candidate codecs. It creates no SQL,
//! grants, installations, probes or acceptance artifacts. Profile preparation
//! precedes the ordinary placement scan; candidate preparation requires that
//! scan and writer promotion to have actually completed.
//!
//! ```text
//! AOS_EXTERNAL_OCI_SETUP_INPUT -> private closed JSON
//! phase=profile   -> profile.json, setup-receipt.json
//! phase=candidate -> profile.json, candidate.json, candidate.signature,
//!                    setup-receipt.json
//! ```

use std::{
    fs,
    io::Write as _,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::{
    backend::{Backend as _, SqlxBackend},
    db::Database,
    direct_upload::DirectPrivateStagePolicyRef,
    storage_authority::{
        control::StorageAuthorityPublication,
        external_object::oci::{
            candidate::ExternalOciCandidate, qualification::ExternalOciProfile,
        },
        lease::{LeaseCohort, LeaseEffect, LeasePurpose},
    },
    storage_work::{StorageBindingSnapshot, StorageWorkKey},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const MAX_DOCUMENT: u64 = 1024 * 1024;

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Profile,
    Candidate,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Input {
    version: u8,
    phase: Phase,
    run_id: String,
    deployment_id: String,
    source_digest: String,
    script_version: String,
    binding_id: i64,
    placement_id: Option<i64>,
    placement_prefix: String,
    database_url_file: PathBuf,
    issuer_configuration_file: PathBuf,
    bootstrap_file: PathBuf,
    list_cohort_file: PathBuf,
    private_policy_file: PathBuf,
    provider_review_file: PathBuf,
    provider_review_sha256: String,
    versionless_conditional_reads: bool,
    maximum_blob_bytes: u64,
    clock_uncertainty_seconds: i64,
    lifetime_seconds: u64,
    expected_profile_sha256: Option<String>,
    candidate_key_file: PathBuf,
    work_key_file: PathBuf,
    guard_key_file: PathBuf,
    output_directory: PathBuf,
}

fn digest(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}

fn hex_value(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl Input {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && hex_value(&self.run_id, 32)
                && hex_value(&self.source_digest, 64)
                && self.script_version
                    == aos_hub_core::direct_upload::direct_worker_emulated_script_id(
                        &self.source_digest
                    )?
                && self.binding_id > 0
                && !self.deployment_id.is_empty()
                && self.deployment_id.len() <= 256
                && (1..30).contains(&self.clock_uncertainty_seconds)
                && (1..=900).contains(&self.lifetime_seconds)
                && self.maximum_blob_bytes > 0
                && self.maximum_blob_bytes <= aos_hub_core::storage_work::MAX_OCI_COMPOSE_BYTES
                && hex_value(&self.provider_review_sha256, 64),
            "External OCI setup selection differs"
        );
        ensure!(
            self.placement_prefix
                == format!(
                    ".aos-direct-qualification/external-oci/{}/registry",
                    self.run_id
                ),
            "External OCI setup placement leaves its reserved run"
        );
        let root = Path::new("/var/lib/hybrid-native/external-oci").join(&self.run_id);
        ensure!(
            self.output_directory.parent() == Some(root.as_path())
                && self
                    .output_directory
                    .file_name()
                    .is_some_and(|name| name == "profile" || name == "candidate"),
            "External OCI setup output leaves its private run"
        );
        match self.phase {
            Phase::Profile => ensure!(
                self.output_directory
                    .file_name()
                    .is_some_and(|name| name == "profile")
                    && self.placement_id.is_none()
                    && self.expected_profile_sha256.is_none(),
                "profile preparation cannot assert a ready placement"
            ),
            Phase::Candidate => ensure!(
                self.output_directory
                    .file_name()
                    .is_some_and(|name| name == "candidate")
                    && self.placement_id.is_some_and(|id| id > 0)
                    && self
                        .expected_profile_sha256
                        .as_ref()
                        .is_some_and(|hash| hex_value(hash, 64)),
                "candidate preparation requires the original profile and actual placement"
            ),
        }
        Ok(())
    }
}

fn private(path: &Path, cap: u64) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    crate::auth::seal::read_secret_file_zeroizing_capped(path, cap)
}

fn field<T: serde::de::DeserializeOwned>(value: &Value, name: &str) -> Result<T> {
    serde_json::from_value(
        value
            .get(name)
            .context("operator export field absent")?
            .clone(),
    )
    .map_err(Into::into)
}

// These documents are existing operator outputs. Their wrapper is projected
// without granting authority; shared records and a fresh full SQL equality
// check below determine whether any selected field is usable.
fn profile_from_exports(
    input: &Input,
    bootstrap: &Value,
    list_export: &Value,
    configuration: &crate::authority_server::AuthorityConfiguration,
    snapshot: &StorageBindingSnapshot,
    policy: DirectPrivateStagePolicyRef,
    latest: i64,
) -> Result<(ExternalOciProfile, StorageAuthorityPublication)> {
    ensure!(
        bootstrap["version"] == 1 && bootstrap["deployment_id"] == input.deployment_id,
        "operator deployment differs"
    );
    let publication: StorageAuthorityPublication = field(bootstrap, "publication")?;
    let installation = &configuration.installation;
    publication.validate(
        &installation.authority.guard_namespace_id,
        &installation.executor_identity,
    )?;
    ensure!(
        publication.authority == installation.authority
            && field::<aos_hub_core::storage_authority::lease::control::IssuerInstallation>(
                bootstrap,
                "issuer_installation"
            )? == *installation
            && field::<i64>(bootstrap, "clock_uncertainty")? == input.clock_uncertainty_seconds
            && configuration.clock_uncertainty.get() == input.clock_uncertainty_seconds
            && field::<aos_hub_core::storage_authority::lease::LeaseTimingProfile>(
                bootstrap,
                "timing_profile"
            )? == configuration.policy.timing_profile
            && field::<String>(bootstrap, "issuer_key_id")? == configuration.signing_key_id,
        "operator export differs from the installed issuer"
    );
    let read: LeaseCohort = field(bootstrap, "read_cohort")?;
    let write: LeaseCohort = field(bootstrap, "write_cohort")?;
    let list: LeaseCohort = field(list_export, "list_cohort")?;
    ensure!(
        list_export["version"] == 1
            && field::<StorageAuthorityPublication>(list_export, "publication")? == publication
            && field::<aos_hub_core::storage_authority::lease::control::IssuerInstallation>(
                list_export,
                "issuer_installation"
            )? == *installation,
        "List export differs from the full current publication"
    );
    for (cohort, purpose, effects) in [
        (
            &read,
            LeasePurpose::Read,
            vec![LeaseEffect::Head, LeaseEffect::Read],
        ),
        (
            &write,
            LeasePurpose::Write,
            vec![
                LeaseEffect::Put,
                LeaseEffect::MultipartCreate,
                LeaseEffect::MultipartPart,
                LeaseEffect::MultipartComplete,
                LeaseEffect::MultipartAbort,
            ],
        ),
        (&list, LeasePurpose::List, vec![LeaseEffect::List]),
    ] {
        ensure!(
            cohort
                == &LeaseCohort::from_publication(
                    &publication,
                    &installation.executor_identity,
                    &write.association.association_id,
                    purpose,
                    &write.admitted_prefix,
                    effects
                )?
                && latest < cohort.attestation_valid_until.get(),
            "exported purpose or original attestation differs"
        );
    }
    let profile = ExternalOciProfile {
        issuer_installation: installation.clone(),
        read_cohort: read,
        write_cohort: write,
        binding_spec_revision: snapshot.binding_spec_revision()?,
        private_policy: policy,
        maximum_blob_bytes: input.maximum_blob_bytes,
        maximum_chunk_bytes:
            aos_hub_core::storage_authority::external_object::oci::MAX_EXTERNAL_OCI_CHUNK_BYTES,
        part_bytes: aos_hub_core::storage_authority::external_object::oci::EXTERNAL_OCI_PART_BYTES,
        versionless_conditional_reads: input.versionless_conditional_reads,
    };
    profile.validate_snapshot(snapshot, latest)?;
    ensure!(
        profile.write_cohort.association.binding_id.get() == input.binding_id,
        "profile selected another binding"
    );
    Ok((profile, publication))
}

async fn database(path: &Path) -> Result<Database> {
    let raw = private(path, 8192)?;
    let url = std::str::from_utf8(&raw)?.trim();
    ensure!(
        url.starts_with("postgres://") || url.starts_with("postgresql://"),
        "setup requires existing PostgreSQL"
    );
    #[cfg(not(feature = "postgres"))]
    anyhow::bail!("setup PostgreSQL support was not compiled");
    #[cfg(feature = "postgres")]
    {
        let backend = SqlxBackend::connect_postgres(url).await?;
        let versions = backend
            .query("SELECT version FROM schema_version", &[])
            .await?;
        let identities = backend
            .query("SELECT identity FROM hub_schema_identity", &[])
            .await?;
        ensure!(
            versions.len() == 1
                && versions[0].get::<i64>(0)? == aos_hub_core::db::MIGRATIONS.len() as i64
                && identities.len() == 1
                && identities[0].get::<String>(0)? == aos_hub_core::db::SCHEMA_IDENTITY,
            "existing setup schema differs"
        );
        let db = Database::attach(Box::new(backend));
        db.validate_binding_identity_reservations().await?;
        Ok(db)
    }
}

async fn current_snapshot(
    db: &Database,
    input: &Input,
    latest: i64,
) -> Result<StorageBindingSnapshot> {
    let binding = db
        .binding(input.binding_id)
        .await?
        .context("existing binding absent")?;
    ensure!(
        !binding.is_instance_default && matches!(binding.kind.as_str(), "s3" | "r2"),
        "setup cannot select Managed storage"
    );
    let credentials = db.list_current_binding_credentials(binding.id).await?;
    let snapshot = StorageBindingSnapshot::from_binding(
        input.deployment_id.clone(),
        &binding,
        &credentials,
        latest,
        latest.checked_add(30).context("snapshot window overflow")?,
    )?;
    if let Some(id) = input.placement_id {
        let placement = db
            .surface_placement(id)
            .await?
            .context("existing placement absent")?;
        ensure!(
            placement.binding_id == binding.id
                && placement.registry_id.is_some()
                && placement.prefix == input.placement_prefix
                && placement.effective_read_enabled
                && placement.effective_write_enabled,
            "actual placement scan or writer promotion is incomplete"
        );
    }
    Ok(snapshot)
}

fn publish(path: &Path, documents: &[(&str, Vec<u8>)]) -> Result<()> {
    let parent = fs::symlink_metadata(path.parent().context("output parent absent")?)?;
    ensure!(
        parent.is_dir()
            && !parent.file_type().is_symlink()
            && parent.permissions().mode() & 0o077 == 0
            && parent.uid() == fs::metadata("/proc/self")?.uid(),
        "output parent is not owner-private"
    );
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    for (name, bytes) in documents {
        ensure!(
            bytes.len() as u64 <= MAX_DOCUMENT,
            "setup document exceeds bound"
        );
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.join(name))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires genuine fresh Fleet SQL, current exports and independent provider inputs"]
async fn actual_external_oci_fleet_setup() -> Result<()> {
    let input_path = PathBuf::from(
        std::env::var_os("AOS_EXTERNAL_OCI_SETUP_INPUT").context("private setup input required")?,
    );
    let input_bytes = private(&input_path, 64 * 1024)?;
    let input: Input = serde_json::from_slice(&input_bytes)?;
    input.validate()?;
    let bootstrap_bytes = private(&input.bootstrap_file, MAX_DOCUMENT)?;
    let list_bytes = private(&input.list_cohort_file, MAX_DOCUMENT)?;
    let review = private(&input.provider_review_file, MAX_DOCUMENT)?;
    ensure!(
        !review.is_empty() && digest(&review) == input.provider_review_sha256,
        "independently selected provider bytes changed"
    );
    let bootstrap: Value = serde_json::from_slice(&bootstrap_bytes)?;
    let list: Value = serde_json::from_slice(&list_bytes)?;
    let configuration =
        crate::authority_server::AuthorityConfiguration::read(&input.issuer_configuration_file)?;
    let policy: DirectPrivateStagePolicyRef =
        serde_json::from_slice(&private(&input.private_policy_file, 65536)?)?;
    let db = database(&input.database_url_file).await?;
    let now = aos_hub_core::clock::now_unix_secs();
    let latest = now
        .checked_add(input.clock_uncertainty_seconds)
        .context("setup clock overflow")?;
    let snapshot = current_snapshot(&db, &input, latest).await?;
    let (profile, publication) = profile_from_exports(
        &input,
        &bootstrap,
        &list,
        &configuration,
        &snapshot,
        policy,
        latest,
    )?;
    let profile_bytes = serde_json::to_vec(&profile)?;
    let profile_sha = digest(&profile_bytes);
    let mut documents = vec![("profile.json", profile_bytes)];
    let mut candidate_sha: Option<String> = None;
    let mut original_candidate = None;
    if input.phase == Phase::Candidate {
        ensure!(
            input.expected_profile_sha256.as_ref() == Some(&profile_sha),
            "profile changed after placement setup"
        );
        let key = StorageWorkKey::new(private(&input.candidate_key_file, 8192)?.as_slice())?;
        let work = StorageWorkKey::new(private(&input.work_key_file, 8192)?.as_slice())?;
        let guard = StorageWorkKey::new(private(&input.guard_key_file, 8192)?.as_slice())?;
        let domain = b"aos.oci.fixture.role-separation";
        ensure!(
            key.sign_body(domain)? != work.sign_body(domain)?
                && key.sign_body(domain)? != guard.sign_body(domain)?,
            "fixture key overlaps a production role"
        );
        let issued = aos_hub_core::clock::now_unix_secs();
        let expires = issued
            .checked_add(i64::try_from(input.lifetime_seconds)?)
            .context("candidate expiry overflow")?;
        let candidate = ExternalOciCandidate {
            version: 1,
            deployment_id: input.deployment_id.clone(),
            source_digest: input.source_digest.clone(),
            script_version: input.script_version.clone(),
            profile_digest: profile.digest()?,
            placement_prefix: input.placement_prefix.clone(),
            issued_at: issued,
            expires_at: expires,
        };
        candidate.validate(
            &input.deployment_id,
            &input.source_digest,
            &input.script_version,
            &profile,
            &input.placement_prefix,
            issued
                .checked_add(input.clock_uncertainty_seconds)
                .context("candidate clock overflow")?,
        )?;
        let (bytes, signature) = candidate.sign(&key)?;
        candidate_sha = Some(digest(&bytes));
        original_candidate = Some(candidate);
        documents.extend([
            ("candidate.json", bytes),
            ("candidate.signature", signature.into_bytes()),
        ]);
    }
    let latest = aos_hub_core::clock::now_unix_secs()
        .checked_add(input.clock_uncertainty_seconds)
        .context("setup clock overflow")?;
    ensure!(
        db.storage_authority_publication(
            &publication.authority.authority_id,
            &configuration.installation.authority.guard_namespace_id,
            &configuration.installation.executor_identity
        )
        .await?
            == publication,
        "SQL publication changed during setup"
    );
    profile.validate_snapshot(&current_snapshot(&db, &input, latest).await?, latest)?;
    let final_latest = aos_hub_core::clock::now_unix_secs()
        .checked_add(input.clock_uncertainty_seconds)
        .context("setup clock overflow")?;
    for cohort in [&profile.read_cohort, &profile.write_cohort] {
        ensure!(
            final_latest < cohort.attestation_valid_until.get(),
            "original attestation expired during setup"
        );
    }
    if let Some(candidate) = original_candidate {
        candidate.validate(
            &input.deployment_id,
            &input.source_digest,
            &input.script_version,
            &profile,
            &input.placement_prefix,
            final_latest,
        )?;
    }
    ensure!(
        *private(&input.bootstrap_file, MAX_DOCUMENT)? == *bootstrap_bytes
            && *private(&input.list_cohort_file, MAX_DOCUMENT)? == *list_bytes
            && digest(&private(&input.provider_review_file, MAX_DOCUMENT)?)
                == input.provider_review_sha256,
        "operator exports or independent provider input changed during setup"
    );
    documents.push(("setup-receipt.json", serde_json::to_vec(&json!({"version":1,
        "inputSha256":digest(&input_bytes),"bootstrapSha256":digest(&bootstrap_bytes),"listExportSha256":digest(&list_bytes),
        "providerReviewSha256":input.provider_review_sha256,"profileSha256":profile_sha,"profileDigest":profile.digest()?,
        "candidateSha256":candidate_sha,"bindingId":input.binding_id,"placementId":input.placement_id,
        "processPid":std::process::id(),"observedAt":aos_hub_core::clock::now_unix_secs(),
        "providerCalls":null,"qualification":null,"sqlMutation":false}))?));
    publish(&input.output_directory, &documents)
}

#[test]
fn outputs_are_private_create_new_and_do_not_replace_prior_candidate() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let output = root.path().join("candidate");
    publish(
        &output,
        &[("profile.json", b"synthetic-local-custody-test".to_vec())],
    )
    .unwrap();
    assert_eq!(
        fs::metadata(output.join("profile.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(publish(&output, &[("profile.json", b"replacement".to_vec())]).is_err());
    assert_eq!(
        fs::read(output.join("profile.json")).unwrap(),
        b"synthetic-local-custody-test"
    );
}

#[test]
fn projected_operator_records_cannot_omit_or_rewrite_shared_types() {
    assert!(field::<StorageAuthorityPublication>(&json!({}), "publication").is_err());
    assert!(
        field::<LeaseCohort>(&json!({"read_cohort":{"purpose":"write"}}), "read_cohort").is_err()
    );
}

fn synthetic_input() -> Value {
    let run = "a".repeat(32);
    let source = "b".repeat(64);
    json!({"version":1,"phase":"profile","runId":run,"deploymentId":"synthetic-local-shape-test",
        "sourceDigest":source,"scriptVersion":aos_hub_core::direct_upload::direct_worker_emulated_script_id(&source).unwrap(),
        "bindingId":1,"placementId":null,"placementPrefix":format!(".aos-direct-qualification/external-oci/{run}/registry"),
        "databaseUrlFile":"/private/database.url","issuerConfigurationFile":"/private/issuer.json",
        "bootstrapFile":"/private/bootstrap.json","listCohortFile":"/private/list.json","privatePolicyFile":"/private/policy.json",
        "providerReviewFile":"/private/report.json","providerReviewSha256":"c".repeat(64),"versionlessConditionalReads":false,
        "maximumBlobBytes":16777216,"clockUncertaintySeconds":2,"lifetimeSeconds":900,
        "expectedProfileSha256":null,"candidateKeyFile":"/private/candidate.key","workKeyFile":"/private/work.key",
        "guardKeyFile":"/private/guard.key","outputDirectory":format!("/var/lib/hybrid-native/external-oci/{run}/profile")})
}

#[test]
fn original_window_source_and_reserved_output_are_closed_before_io() {
    let original = synthetic_input();
    serde_json::from_value::<Input>(original.clone())
        .unwrap()
        .validate()
        .unwrap();
    for (key, replacement) in [
        ("lifetimeSeconds", json!(901)),
        ("clockUncertaintySeconds", json!(30)),
        ("placementPrefix", json!("normal/registry")),
        ("scriptVersion", json!("other-source")),
        (
            "outputDirectory",
            json!("/var/lib/hybrid-native/main/profile"),
        ),
    ] {
        let mut changed = original.clone();
        changed[key] = replacement;
        assert!(
            serde_json::from_value::<Input>(changed)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    let mut unknown = original;
    unknown["hostedAccepted"] = json!(true);
    assert!(serde_json::from_value::<Input>(unknown).is_err());
}

#[test]
fn candidate_requires_actual_placement_and_unchanged_profile_selection() {
    let mut candidate = synthetic_input();
    candidate["phase"] = json!("candidate");
    candidate["outputDirectory"] = json!(format!(
        "/var/lib/hybrid-native/external-oci/{}/candidate",
        "a".repeat(32)
    ));
    assert!(
        serde_json::from_value::<Input>(candidate.clone())
            .unwrap()
            .validate()
            .is_err()
    );
    candidate["placementId"] = json!(5);
    candidate["expectedProfileSha256"] = json!("d".repeat(64));
    serde_json::from_value::<Input>(candidate.clone())
        .unwrap()
        .validate()
        .unwrap();
    candidate["outputDirectory"] = json!(format!(
        "/var/lib/hybrid-native/external-oci/{}/profile",
        "a".repeat(32)
    ));
    assert!(
        serde_json::from_value::<Input>(candidate)
            .unwrap()
            .validate()
            .is_err()
    );
}
