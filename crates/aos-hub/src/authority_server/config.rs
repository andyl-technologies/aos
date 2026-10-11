//! Explicit private configuration for the dedicated authority process.
//!
//! No environment fallback creates keys, state or a Hub database. The timing
//! profile names externally reviewed evidence; parsing it proves no clock,
//! retained-volume or physical-resource qualification.
//!
//! ```json
//! {"format_version":1,"issuance_enabled":false}
//! ```
//!
//! This abbreviated example omits mandatory installation, paths and policy.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Result};
use aos_hub_core::storage_authority::{
    control::{StorageAuthorityPublication, MAX_AUTHORITY_PUBLICATION_BYTES},
    lease::{BoundedLeaseRevocationPolicy, LeaseInteger},
};
use serde::{Deserialize, Serialize};

use crate::authority_journal::{AuthorityJournal, HubDataBoundary, IssuerInstallation};

/// Explicit owner-controlled configuration of one retained issuer resource.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityConfiguration {
    /// Format one selects journal 2; format two selects fresh recoverable journal 3.
    pub format_version: u8,
    /// Private listener address, with no inferred public Hub endpoint.
    pub listen: SocketAddr,
    /// Existing dedicated per-authority SQLite file outside Hub data.
    pub journal_file: PathBuf,
    /// Externally supplied exact immutable installation marker.
    pub installation: IssuerInstallation,
    /// Actual Hub root excluded from this installation.
    pub hub_root: PathBuf,
    /// Actual Hub SQLite file when Hub SQL uses SQLite.
    pub hub_sqlite_file: Option<PathBuf>,
    /// Exact externally reviewed bounded lease policy.
    pub policy: BoundedLeaseRevocationPolicy,
    /// Qualified absolute clock uncertainty, never inferred from a local read.
    pub clock_uncertainty: LeaseInteger,
    /// Externally reviewed maximum observation/commit latency in seconds.
    /// One extra second accounts for conversion to the wire's whole seconds.
    pub clock_commit_latency: LeaseInteger,
    /// Immutable independent recovery policy, mandatory only for format two.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_recovery: Option<crate::authority_journal::recovery::ClockRecoveryPolicy>,
    /// Explicit opt-in to issuance; omission leaves issuance disabled.
    #[serde(default)]
    pub issuance_enabled: bool,
    /// Dedicated publisher authentication key file, distinct from renewal.
    pub publisher_key_file: PathBuf,
    /// Dedicated executor-renewal authentication key file.
    pub renewal_key_file: PathBuf,
    /// Issuer-only Ed25519 seed file; never mounted in Hub or executor roles.
    pub signing_seed_file: PathBuf,
    /// Externally pinned issuer signing identity.
    pub signing_key_id: String,
    /// Optional Native TLS certificate/key/SNI coordinates.
    pub tls: Option<AuthorityTlsConfiguration>,
}

/// Explicit certificate and expected SNI for a Native TLS listener.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityTlsConfiguration {
    /// PEM certificate chain file.
    pub certificate_file: PathBuf,
    /// Owner-private PEM key file.
    pub private_key_file: PathBuf,
    /// Exact expected client SNI.
    pub expected_server_name: String,
}

impl AuthorityConfiguration {
    /// Loads closed configuration from an owner-private file.
    ///
    /// # Errors
    /// Returns an error for insecure/unavailable files, unknown/duplicate fields,
    /// or invalid installation, paths, policy or TLS shape.
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = crate::auth::seal::read_secret_file_zeroizing(path)?;
        let configuration: Self = serde_json::from_slice(&bytes)?;
        configuration.validate()?;
        Ok(configuration)
    }

    /// Validates explicit configuration without establishing deployment readiness.
    ///
    /// # Errors
    /// Returns an error for malformed installation, policy, uncertainty, paths,
    /// reused credential paths or an unprotected non-loopback listener.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.format_version, 1 | 2),
            "unsupported authority configuration"
        );
        self.installation.validate()?;
        self.policy.timing_profile.validate()?;
        match (&self.clock_recovery, self.format_version) {
            (None, 1) => {}
            (Some(recovery), 2) => {
                recovery.validate()?;
                ensure!(
                    recovery.clock_uncertainty == self.clock_uncertainty
                        && recovery.clock_commit_latency == self.clock_commit_latency
                        && recovery.reviewer_key_id != self.signing_key_id,
                    "clock recovery qualification or reviewer role differs"
                );
            }
            _ => anyhow::bail!("authority configuration and recovery format differ"),
        }
        ensure!(
            self.clock_commit_latency.get() > 0
                && self
                    .clock_uncertainty
                    .get()
                    .checked_add(self.clock_commit_latency.get())
                    .and_then(|value| value.checked_add(1))
                    .is_some_and(
                        |total| total <= self.policy.timing_profile.maximum_clock_uncertainty.get()
                    ),
            "clock uncertainty exceeds reviewed profile"
        );
        for path in [
            &self.journal_file,
            &self.hub_root,
            &self.publisher_key_file,
            &self.renewal_key_file,
            &self.signing_seed_file,
        ] {
            ensure!(
                path.is_absolute(),
                "authority paths must be explicit and absolute"
            );
        }
        ensure!(
            self.publisher_key_file != self.renewal_key_file
                && self.publisher_key_file != self.signing_seed_file
                && self.renewal_key_file != self.signing_seed_file,
            "authority credentials must use distinct files"
        );
        ensure!(
            self.tls.is_some() || self.listen.ip().is_loopback(),
            "non-loopback authority listener requires explicit Native TLS"
        );
        if let Some(tls) = &self.tls {
            ensure!(
                tls.certificate_file.is_absolute()
                    && tls.private_key_file.is_absolute()
                    && !tls.expected_server_name.is_empty(),
                "incomplete authority TLS configuration"
            );
        }
        Ok(())
    }

    pub(super) fn boundary(&self) -> HubDataBoundary {
        HubDataBoundary {
            hub_root: self.hub_root.clone(),
            hub_sqlite_file: self.hub_sqlite_file.clone(),
        }
    }

    /// Explicitly initializes a never-used dedicated resource from reviewed input.
    ///
    /// This never overwrites a file or proves resource novelty from disk absence.
    /// Operators must retain irreversible provisioning and external qualification.
    ///
    /// # Errors
    /// Returns an error for invalid configuration/publication/time or any private
    /// resource initialization/commit failure. Partial files are never served.
    pub fn initialize(&self, publication_file: &Path) -> Result<AuthorityJournal> {
        self.validate()?;
        let bytes = crate::auth::seal::read_secret_file_zeroizing(publication_file)?;
        ensure!(
            bytes.len() <= MAX_AUTHORITY_PUBLICATION_BYTES,
            "initial publication exceeds bound"
        );
        let publication: StorageAuthorityPublication = serde_json::from_slice(&bytes)?;
        ensure!(
            serde_json::to_vec(&publication)? == *bytes,
            "noncanonical initial publication"
        );
        // Initialization obtains its first clock only for the create-new
        // transaction; serving observations require that retained actual file.
        let observed_at = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        )?;
        let observation = aos_hub_core::storage_authority::lease::LeaseClock {
            observed_at,
            uncertainty: self.clock_uncertainty.get(),
        };
        match &self.clock_recovery {
            Some(recovery) => AuthorityJournal::initialize_recoverable(
                &self.journal_file,
                &self.boundary(),
                self.installation.clone(),
                publication,
                self.policy.clone(),
                observation,
                recovery.clone(),
            ),
            None => AuthorityJournal::initialize_fresh(
                &self.journal_file,
                &self.boundary(),
                self.installation.clone(),
                publication,
                self.policy.clone(),
                observation,
            ),
        }
    }

    /// Opens exact existing state for an explicit operator recovery operation.
    ///
    /// No issuer or renewal secret is read, and no listener or SQL Hub is opened.
    ///
    /// # Errors
    /// Returns an error for invalid configuration, changed state or policy mismatch.
    pub fn open_recovery_journal(&self) -> Result<AuthorityJournal> {
        self.validate()?;
        let recovery = self
            .clock_recovery
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("clock recovery requires configuration format two"))?;
        let journal = AuthorityJournal::open_recovery_existing(
            &self.journal_file,
            &self.boundary(),
            self.installation.clone(),
            recovery,
        )?;
        ensure!(
            journal.load()?.journal.policy == self.policy,
            "configured timing profile differs"
        );
        Ok(journal)
    }
}
