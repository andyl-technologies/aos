//! Operator export of reviewed authority metadata and qualification hydration.
//!
//! Local database custody authorizes this interface. It transports no object
//! bytes and produces no provider contract, runtime acceptance, or readiness.
//! The closed metadata is supplied to independent issuer/Worker configuration.
//!
//! Publication-only export writes the actual admitted, blocked or retired SQL
//! head and its byte commitment without selecting a qualification association.
//!
//! ```text
//! export-directory/
//!   publication.json  canonical root-reviewed StorageAuthorityPublication
//!   bootstrap.json    exact binding, selector, issuer and narrowed cohorts
//! ```

use std::path::Path;

use anyhow::{ensure, Context, Result};
use aos_hub::authority_server::AuthorityConfiguration;
use aos_hub::storage_work::RemoteStorageWorkClient;
use aos_hub_core::db::{BindingRecord, Database};
use aos_hub_core::direct_upload::{
    DirectCredentialRevision, DirectExternalProfileSelector, WireInteger,
};
use aos_hub_core::secret_version::SecretVersionResolver;
use aos_hub_core::storage_authority::{
    control::StorageAuthorityPublication,
    lease::{
        control::IssuerInstallation, LeaseCohort, LeaseEffect, LeasePurpose, LeaseTimingProfile,
    },
    PhysicalStorageAuthorityId,
};
use aos_hub_core::storage_work::StorageBindingSnapshot;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

mod credential;
mod custody;
mod publication;

pub use credential::{stage_queued_credential, write_cleanup_stage_receipt, write_stage_receipt};
pub use publication::export_publication;

#[cfg(test)]
mod tests;

const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// Attaches to an existing exact production schema without creating or migrating it.
///
/// # Errors
/// Rejects unsupported database schemes, unavailable connections, missing SQL,
/// or a foreign, old, newer or ambiguous schema identity/version.
pub async fn open_existing(url: &str) -> Result<Database> {
    use aos_hub_core::backend::{Backend as _, SqlxBackend};

    let backend = if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        #[cfg(feature = "postgres")]
        {
            SqlxBackend::connect_postgres(url).await?
        }
        #[cfg(not(feature = "postgres"))]
        {
            anyhow::bail!("operator PostgreSQL support is not compiled in");
        }
    } else {
        ensure!(
            !url.contains("://") || url.starts_with("sqlite://") || url.starts_with("file://"),
            "operator database scheme unsupported"
        );
        let path = url
            .strip_prefix("sqlite://")
            .or_else(|| url.strip_prefix("file://"))
            .unwrap_or(url);
        SqlxBackend::connect_sqlite_read_only(path).await?
    };
    let versions = backend
        .query("SELECT version FROM schema_version", &[])
        .await?;
    ensure!(
        versions.len() == 1
            && versions[0].get::<i64>(0)? == aos_hub_core::db::MIGRATIONS.len() as i64,
        "operator database schema version differs"
    );
    let identities = backend
        .query("SELECT identity FROM hub_schema_identity", &[])
        .await?;
    ensure!(
        identities.len() == 1
            && identities[0].get::<String>(0)? == aos_hub_core::db::SCHEMA_IDENTITY,
        "operator database schema identity differs"
    );
    let database = Database::attach(Box::new(backend));
    database.validate_binding_identity_reservations().await?;
    Ok(database)
}

/// Exact nonsecret input to separately installed issuer and qualification controls.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    /// Closed document format, currently one.
    pub version: u8,
    /// Immutable Native/Worker deployment audience.
    pub deployment_id: String,
    /// Actual root-reviewed SQL publication, including complete attestation membership.
    pub publication: StorageAuthorityPublication,
    /// Binding coordinates and validated credential references; contains no material.
    pub binding_snapshot: StorageBindingSnapshot,
    /// Exact server-derived selector for the protected qualification producer.
    pub selector: DirectExternalProfileSelector,
    /// Independently provisioned issuer resource, supplied by the operator.
    pub issuer_installation: IssuerInstallation,
    /// Independently selected issuer verifier identity.
    pub issuer_key_id: String,
    /// Actual public verifier pin; the issuer seed is never read by this tool.
    pub issuer_public_key: String,
    /// Explicit reviewed timing policy from the issuer configuration.
    pub timing_profile: LeaseTimingProfile,
    /// Explicit issuer clock bound; does not claim measurement or Worker qualification.
    pub clock_uncertainty: i64,
    /// Narrowed write cohort derived from the admitted publication.
    pub write_cohort: LeaseCohort,
    /// Narrowed read cohort derived from the same publication.
    pub read_cohort: LeaseCohort,
    /// Isolated configured stage namespace, ending in `.aos-direct-upload`.
    pub staging_prefix: String,
}

/// Exact local acknowledgement of protected binding metadata delivery.
#[derive(Debug, Serialize)]
pub struct HydrationReceipt {
    /// Closed receipt format, currently one.
    pub version: u8,
    /// Immutable paired deployment audience.
    pub deployment_id: String,
    /// Commitment to the private bootstrap document that was rechecked.
    pub bootstrap_digest: String,
    /// Configured HTTPS executor that acknowledged the protected publication.
    pub executor_public_origin: String,
    /// Original reviewed publication commitment.
    pub publication_digest: String,
    /// Actual snapshot acknowledged by this client over the configured TLS channel.
    pub snapshot: StorageBindingSnapshot,
    /// Exact acknowledged snapshot revision, not a provider permission.
    pub snapshot_revision: String,
    /// True only after publication acknowledgement and current SQL recheck.
    pub binding_hydrated: bool,
    /// Always false; provider qualification is a later independent operation.
    pub provider_readiness_evaluated: bool,
}

/// Resolves a qualification bootstrap exclusively from current reviewed SQL facts.
///
/// # Errors
/// Rejects stale or denied publications, wrong issuer installation, absent current
/// credentials, an unadmitted association, or an unconfined qualification prefix.
pub async fn derive(
    db: &Database,
    deployment_id: &str,
    authority_id: &PhysicalStorageAuthorityId,
    association_id: &str,
    configuration: &AuthorityConfiguration,
    public_key: &str,
    admitted_prefix: &str,
) -> Result<Bootstrap> {
    db.validate_binding_identity_reservations().await?;
    configuration.validate()?;
    let installation = &configuration.installation;
    ensure!(
        installation.authority.authority_id == *authority_id,
        "issuer authority differs"
    );
    let publication = db
        .storage_authority_publication(
            authority_id,
            &installation.authority.guard_namespace_id,
            &installation.executor_identity,
        )
        .await?;
    ensure!(
        publication.authority == installation.authority,
        "issuer installation differs from reviewed authority"
    );
    let association = publication
        .associations
        .iter()
        .find(|item| item.association_id == association_id)
        .context("selected reviewed association absent")?;
    let binding = db
        .binding(association.binding_id)
        .await?
        .context("selected SQL binding absent")?;
    let now = aos_hub_core::clock::now_unix_secs();
    let snapshot = current_snapshot(db, deployment_id, &binding, now).await?;
    let bootstrap = project(
        publication,
        snapshot,
        installation.clone(),
        &configuration.signing_key_id,
        public_key,
        configuration.policy.timing_profile.clone(),
        configuration.clock_uncertainty.get(),
        association_id,
        admitted_prefix,
    )?;
    recheck(db, &bootstrap).await?;
    Ok(bootstrap)
}

#[allow(clippy::too_many_arguments)]
fn project(
    publication: StorageAuthorityPublication,
    snapshot: StorageBindingSnapshot,
    installation: IssuerInstallation,
    key_id: &str,
    public_key: &str,
    timing_profile: LeaseTimingProfile,
    clock_uncertainty: i64,
    association_id: &str,
    admitted_prefix: &str,
) -> Result<Bootstrap> {
    ensure!(
        admitted_prefix
            .split('/')
            .any(|part| part == ".aos-direct-qualification"),
        "qualification prefix must contain .aos-direct-qualification"
    );
    let write_cohort = LeaseCohort::from_publication(
        &publication,
        &installation.executor_identity,
        association_id,
        LeasePurpose::Write,
        admitted_prefix,
        vec![
            LeaseEffect::Put,
            LeaseEffect::MultipartCreate,
            LeaseEffect::MultipartPart,
            LeaseEffect::MultipartComplete,
            LeaseEffect::MultipartAbort,
        ],
    )?;
    let read_cohort = LeaseCohort::from_publication(
        &publication,
        &installation.executor_identity,
        association_id,
        LeasePurpose::Read,
        admitted_prefix,
        vec![LeaseEffect::Head, LeaseEffect::Read],
    )?;
    let credential = |purpose: &str| -> Result<DirectCredentialRevision> {
        let member = publication
            .attestation
            .as_ref()
            .context("reviewed attestation absent")?
            .credentials
            .iter()
            .find(|item| item.association_id == association_id && item.purpose == purpose)
            .context("selected reviewed purpose absent")?;
        let identity = serde_json::to_vec(&(
            &snapshot.binding_stable_id,
            purpose,
            member.generation,
            &member.secret_version_ref,
            &member.credential_fingerprint,
        ))?;
        // SQL has no separate provider credential label. This nonsecret identity
        // is stable for exactly one immutable binding/purpose revision.
        Ok(DirectCredentialRevision {
            purpose: purpose.into(),
            credential_id: hex::encode(Sha256::digest(identity)),
            generation: WireInteger::new(u64::try_from(member.generation)?),
            secret_version_ref: member.secret_version_ref.clone(),
            credential_fingerprint: member.credential_fingerprint.clone(),
        })
    };
    let selector = DirectExternalProfileSelector {
        physical_authority_id: publication.authority.authority_id.clone(),
        association: write_cohort.association.clone(),
        write_credential: credential("write")?,
        read_credential: credential("read")?,
        presign_credential: credential("presign")?,
    };
    let bootstrap = Bootstrap {
        version: 1,
        deployment_id: snapshot.deployment_id.clone(),
        publication,
        binding_snapshot: snapshot,
        selector,
        issuer_installation: installation,
        issuer_key_id: key_id.into(),
        issuer_public_key: public_key.into(),
        timing_profile,
        clock_uncertainty,
        write_cohort,
        read_cohort,
        staging_prefix: format!("{admitted_prefix}/.aos-direct-upload"),
    };
    bootstrap.validate()?;
    Ok(bootstrap)
}

impl Bootstrap {
    /// Checks the complete local metadata projection without granting live authority.
    ///
    /// # Errors
    /// Rejects malformed, oversized, unconfined or internally inconsistent metadata.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && !self.deployment_id.is_empty() && self.deployment_id.len() <= 128,
            "invalid bootstrap audience"
        );
        self.issuer_installation.validate()?;
        self.publication.validate(
            &self.issuer_installation.authority.guard_namespace_id,
            &self.issuer_installation.executor_identity,
        )?;
        ensure!(
            self.publication.authority == self.issuer_installation.authority,
            "bootstrap issuer authority differs"
        );
        self.selector.validate()?;
        self.timing_profile.validate()?;
        ensure!(
            self.clock_uncertainty >= 0
                && self.clock_uncertainty <= self.timing_profile.maximum_clock_uncertainty.get(),
            "bootstrap clock policy differs"
        );
        ensure!(
            !self.issuer_key_id.is_empty() && self.issuer_key_id.len() <= 128,
            "bootstrap issuer key identity invalid"
        );
        let key: [u8; 32] = hex::decode(&self.issuer_public_key)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bootstrap public verifier invalid"))?;
        ed25519_dalek::VerifyingKey::from_bytes(&key)?;
        ensure!(
            hex::encode(key) == self.issuer_public_key,
            "bootstrap public verifier is not canonical"
        );
        self.binding_snapshot
            .validate(&self.deployment_id, self.binding_snapshot.issued_at)?;
        ensure!(
            self.binding_snapshot.access_mode == "private",
            "qualification binding must be private"
        );
        ensure!(
            self.selector.physical_authority_id == self.publication.authority.authority_id
                && self.selector.association == self.write_cohort.association
                && self.read_cohort.association == self.write_cohort.association
                && self.selector.association.binding_id.get() == self.binding_snapshot.binding_id
                && self.selector.association.binding_stable_id
                    == self.binding_snapshot.binding_stable_id
                && self.selector.association.binding_resource_version.get()
                    == self.binding_snapshot.binding_resource_version
                && self.selector.association.binding_prefix == self.binding_snapshot.object_prefix,
            "bootstrap SQL binding projection differs"
        );
        let prefix = &self.write_cohort.admitted_prefix;
        ensure!(
            prefix
                .split('/')
                .any(|part| part == ".aos-direct-qualification")
                && self.read_cohort.admitted_prefix == *prefix
                && self.staging_prefix == format!("{prefix}/.aos-direct-upload"),
            "bootstrap qualification stage escapes isolated prefix"
        );
        for (cohort, purpose, effects) in [
            (
                &self.write_cohort,
                LeasePurpose::Write,
                vec![
                    LeaseEffect::Put,
                    LeaseEffect::MultipartCreate,
                    LeaseEffect::MultipartPart,
                    LeaseEffect::MultipartComplete,
                    LeaseEffect::MultipartAbort,
                ],
            ),
            (
                &self.read_cohort,
                LeasePurpose::Read,
                vec![LeaseEffect::Head, LeaseEffect::Read],
            ),
        ] {
            let expected = LeaseCohort::from_publication(
                &self.publication,
                &self.issuer_installation.executor_identity,
                &self.selector.association.association_id,
                purpose,
                prefix,
                effects,
            )?;
            ensure!(
                *cohort == expected,
                "bootstrap cohort differs from reviewed publication"
            );
        }
        for credential in [
            &self.selector.write_credential,
            &self.selector.read_credential,
            &self.selector.presign_credential,
        ] {
            ensure!(
                self.binding_snapshot
                    .credentials
                    .iter()
                    .any(|item| item.purpose == credential.purpose
                        && item.generation == credential.generation.get() as i64
                        && item.secret_version_ref == credential.secret_version_ref
                        && item.fingerprint == credential.credential_fingerprint),
                "bootstrap purpose differs from current validated snapshot"
            );
            let member = self
                .publication
                .attestation
                .as_ref()
                .context("bootstrap attestation absent")?
                .credentials
                .iter()
                .find(|member| {
                    member.association_id == self.selector.association.association_id
                        && member.purpose == credential.purpose
                })
                .context("bootstrap attested purpose absent")?;
            let identity = serde_json::to_vec(&(
                &self.binding_snapshot.binding_stable_id,
                &credential.purpose,
                member.generation,
                &member.secret_version_ref,
                &member.credential_fingerprint,
            ))?;
            ensure!(
                credential.credential_id == hex::encode(Sha256::digest(identity))
                    && credential.generation.get() == u64::try_from(member.generation)?
                    && credential.secret_version_ref == member.secret_version_ref
                    && credential.credential_fingerprint == member.credential_fingerprint,
                "bootstrap selector differs from reviewed credential membership"
            );
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_DOCUMENT_BYTES,
            "bootstrap document exceeds bound"
        );
        Ok(())
    }

    /// Returns a commitment to this exact private metadata document.
    ///
    /// # Errors
    /// Returns an error for invalid or unserializable metadata.
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(self)?)))
    }
}

async fn current_snapshot(
    db: &Database,
    deployment: &str,
    binding: &BindingRecord,
    now: i64,
) -> Result<StorageBindingSnapshot> {
    let credentials = db.list_current_binding_credentials(binding.id).await?;
    StorageBindingSnapshot::from_binding(
        deployment.into(),
        binding,
        &credentials,
        now,
        now.checked_add(3600)
            .context("binding metadata deadline overflowed")?,
    )
}

/// Rechecks the entire original publication and binding against current SQL.
///
/// # Errors
/// Rejects expired/revoked decisions, altered metadata or changed SQL revisions.
pub async fn recheck(db: &Database, bootstrap: &Bootstrap) -> Result<BindingRecord> {
    bootstrap.validate()?;
    let installation = &bootstrap.issuer_installation;
    let publication = db
        .storage_authority_publication(
            &bootstrap.publication.authority.authority_id,
            &installation.authority.guard_namespace_id,
            &installation.executor_identity,
        )
        .await?;
    ensure!(
        publication == bootstrap.publication,
        "reviewed authority publication changed since export"
    );
    let binding = db
        .binding(bootstrap.binding_snapshot.binding_id)
        .await?
        .context("exported SQL binding absent")?;
    let credentials = db.list_current_binding_credentials(binding.id).await?;
    let expected = StorageBindingSnapshot::from_binding(
        bootstrap.deployment_id.clone(),
        &binding,
        &credentials,
        bootstrap.binding_snapshot.issued_at,
        bootstrap.binding_snapshot.expires_at,
    )?;
    ensure!(
        expected == bootstrap.binding_snapshot,
        "SQL binding or purpose revisions changed since export"
    );
    Ok(binding)
}

/// Publishes current selected credentials only through the protected Worker control.
///
/// # Errors
/// Rejects stale exported pins, unresolved secrets, mismatched fingerprints,
/// unavailable acknowledgements, or SQL changes during either awaited exchange.
pub async fn hydrate(
    db: &Database,
    bootstrap: &Bootstrap,
    client: &RemoteStorageWorkClient,
    resolver: &dyn SecretVersionResolver,
) -> Result<HydrationReceipt> {
    ensure!(
        client.deployment_id() == bootstrap.deployment_id,
        "hydration executor deployment differs from export"
    );
    let executor_public_origin = client.executor_origin()?;
    let binding = recheck(db, bootstrap).await?;
    client
        .ensure_binding_snapshot(db, &binding, resolver)
        .await?;
    let snapshot = client.acknowledged_binding_snapshot(binding.id)?;
    let checked = recheck(db, bootstrap).await;
    if let Err(error) = checked {
        let revision = snapshot.revision()?;
        let now = aos_hub_core::clock::now_unix_secs().max(snapshot.issued_at.saturating_add(1));
        client
            .revoke_binding_snapshot(binding.id, &revision, now)
            .await
            .context("revoking hydration after changed reviewed authority")?;
        return Err(error);
    }
    ensure!(
        snapshot.binding_spec_revision()? == bootstrap.binding_snapshot.binding_spec_revision()?
            && snapshot.binding_resource_version
                == bootstrap.binding_snapshot.binding_resource_version
            && snapshot.credentials == bootstrap.binding_snapshot.credentials,
        "acknowledged hydration differs from exported pins"
    );
    Ok(HydrationReceipt {
        version: 1,
        deployment_id: bootstrap.deployment_id.clone(),
        bootstrap_digest: bootstrap.digest()?,
        executor_public_origin,
        publication_digest: bootstrap.write_cohort.publication_digest.clone(),
        snapshot_revision: snapshot.revision()?,
        snapshot,
        binding_hydrated: true,
        provider_readiness_evaluated: false,
    })
}

/// Publishes both canonical export files under one new private directory.
///
/// # Errors
/// Rejects existing output, insecure custody, oversized data or I/O failure.
pub fn write_export(directory: &Path, bootstrap: &Bootstrap) -> Result<()> {
    bootstrap.validate()?;
    custody::publish_directory(
        directory,
        &[
            (
                "publication.json",
                serde_json::to_vec(&bootstrap.publication)?,
            ),
            ("bootstrap.json", serde_json::to_vec(bootstrap)?),
        ],
    )
}

/// Reads one closed canonical metadata document under strict private custody.
///
/// # Errors
/// Rejects insecure, replaced, oversized, noncanonical or invalid input.
pub fn read_bootstrap(path: &Path) -> Result<Bootstrap> {
    let bytes = custody::read_file(path)?;
    let value: Bootstrap = serde_json::from_slice(&bytes)?;
    ensure!(
        serde_json::to_vec(&value)? == bytes,
        "bootstrap input is not canonical"
    );
    value.validate()?;
    Ok(value)
}

/// Publishes the local hydration receipt without overwriting prior evidence.
///
/// # Errors
/// Rejects existing output, insecure custody, oversized data or I/O failure.
pub fn write_receipt(directory: &Path, receipt: &HydrationReceipt) -> Result<()> {
    custody::publish_directory(
        directory,
        &[("hydration.json", serde_json::to_vec(receipt)?)],
    )
}
