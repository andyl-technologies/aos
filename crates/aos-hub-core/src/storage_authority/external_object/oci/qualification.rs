//! Independent acceptance of the external OCI workflow and exact raw material.
//!
//! Existing metadata, direct-upload staging or managed-R2 acceptance is not an
//! OCI producer permission. This artifact has its own signature domain and binds
//! actual source, script, provider material, private writer policy, capacity,
//! correctness and whole-Worker measurements. Parsing or constructing a fixture
//! does not create acceptance; production requires an independently installed
//! reviewer key and genuinely supplied signed evidence.
//!
//! ```text
//! accepted external OCI = signed OCI purpose + current raw profile
//!                       + current source/script + immutable measured cutoff
//! ```

use anyhow::{ensure, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::direct_upload::DirectPrivateStagePolicyRef;
use crate::storage_authority::{
    canonical_digest,
    lease::{control::IssuerInstallation, LeaseCohort, LeaseEffect, LeasePurpose},
};
use crate::storage_work::StorageBindingSnapshot;

use super::{digest_string, identifier, EXTERNAL_OCI_PART_BYTES, MAX_EXTERNAL_OCI_CHUNK_BYTES};

/// Maximum supplied acceptance artifact, checked before decoding.
pub const MAX_EXTERNAL_OCI_ACCEPTANCE_BYTES: usize = 64 * 1024;
const DOMAIN: &[u8] = b"aos.external-oci-workflow-acceptance.v1\0";

/// Actual independently installed material and fixed producer geometry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalOciProfile {
    /// Exact independently installed issuer attachment.
    pub issuer_installation: IssuerInstallation,
    /// Exact current physical read cohort and credential purpose.
    pub read_cohort: LeaseCohort,
    /// Exact current physical write cohort and credential purpose.
    pub write_cohort: LeaseCohort,
    /// Fingerprint of raw binding coordinates, excluding renewable snapshot time.
    pub binding_spec_revision: String,
    /// Independently reviewed private staging and writer closure policy.
    pub private_policy: DirectPrivateStagePolicyRef,
    /// Actual maximum accepted OCI blob, measured by this workflow's evidence.
    pub maximum_blob_bytes: u64,
    /// Fixed upper bound of an existing public resumable OCI chunk.
    pub maximum_chunk_bytes: u64,
    /// Fixed bounded storage-local multipart producer buffer size.
    pub part_bytes: u64,
    /// Admits genuine guard incarnations on a versionless provider only when
    /// the corresponding conditional-read/writer-closure case was measured.
    pub versionless_conditional_reads: bool,
}

impl ExternalOciProfile {
    /// Checks exact cohort material and explicit bounded OCI geometry.
    ///
    /// # Errors
    /// Refuses cross-domain/read-write material, missing multipart effects,
    /// malformed private policy or an unsupported producer geometry.
    pub fn validate(&self) -> Result<()> {
        self.issuer_installation.validate()?;
        let read = &self.read_cohort;
        let write = &self.write_cohort;
        ensure!(
            read.credential.purpose == LeasePurpose::Read
                && write.credential.purpose == LeasePurpose::Write
                && read.authority == write.authority
                && read.authority == self.issuer_installation.authority
                && read.alias == write.alias
                && read.association == write.association
                && read.executor_identity == write.executor_identity
                && read.executor_identity == self.issuer_installation.executor_identity
                && read.allowed_effects.contains(&LeaseEffect::Head)
                && read.allowed_effects.contains(&LeaseEffect::Read)
                && [
                    LeaseEffect::Put,
                    LeaseEffect::MultipartCreate,
                    LeaseEffect::MultipartPart,
                    LeaseEffect::MultipartComplete,
                    LeaseEffect::MultipartAbort
                ]
                .iter()
                .all(|effect| write.allowed_effects.contains(effect))
                && digest_string(&self.binding_spec_revision)
                && identifier(&self.private_policy.policy_id)
                && digest_string(&self.private_policy.policy_digest)
                && self.private_policy.namespace == read.authority.guard_namespace_id
                && self.maximum_blob_bytes > 0
                && self.maximum_blob_bytes <= crate::storage_work::MAX_OCI_COMPOSE_BYTES
                && self.maximum_chunk_bytes == MAX_EXTERNAL_OCI_CHUNK_BYTES
                && self.part_bytes == EXTERNAL_OCI_PART_BYTES,
            "external OCI profile is incomplete or differs from fixed geometry"
        );
        Ok(())
    }

    /// Correlates actual protected binding coordinates and exact credential pins.
    ///
    /// Snapshot expiry is checked separately on every dispatch; it cannot renew
    /// either the retained profile or the acceptance artifact.
    ///
    /// # Errors
    /// Refuses changed raw coordinates, lifetime, prefix, purpose or generation.
    pub fn validate_snapshot(&self, snapshot: &StorageBindingSnapshot, now: i64) -> Result<()> {
        self.validate()?;
        snapshot.validate(&snapshot.deployment_id, now)?;
        let association = &self.read_cohort.association;
        ensure!(
            snapshot.binding_spec_revision()? == self.binding_spec_revision
                && snapshot.binding_id == association.binding_id.get()
                && snapshot.binding_stable_id == association.binding_stable_id
                && snapshot.binding_resource_version == association.binding_resource_version.get()
                && snapshot.object_prefix == association.binding_prefix
                && snapshot.access_mode == "private",
            "external OCI protected material differs from reviewed profile"
        );
        for cohort in [&self.read_cohort, &self.write_cohort] {
            ensure!(
                snapshot
                    .credentials
                    .iter()
                    .any(|reference| reference.purpose
                        == match cohort.credential.purpose {
                            LeasePurpose::Read => "read",
                            LeasePurpose::Write => "write",
                            LeasePurpose::List => "list",
                            LeasePurpose::Delete => "delete",
                        }
                        && reference.generation == cohort.credential.generation.get()
                        && reference.secret_version_ref == cohort.credential.secret_version_ref
                        && reference.fingerprint == cohort.credential.credential_fingerprint),
                "external OCI credential differs from exact reviewed cohort"
            );
        }
        Ok(())
    }

    /// Returns this purpose's canonical complete raw profile commitment.
    ///
    /// # Errors
    /// Refuses malformed material or canonical encoding failure.
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest(&("aos.external-oci-profile.v1", self))
    }
}

/// Records one exact controlled correctness boundary, without body or secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalOciCase {
    /// Actual conditional empty PUT, positive incarnation and independent readback.
    EmptyBlob,
    /// Actual largest accepted OCI semantic document.
    ManifestBoundary,
    /// Actual largest accepted resumable upload chunk.
    ChunkBoundary,
    /// Actual largest admitted canonical blob composition.
    BlobBoundary,
    /// Current OCI actor refusal before public body consumption.
    ActorRefusal,
    /// Placement/binding/credential drift before a new provider dispatch.
    WriterDriftRefusal,
    /// Incorrect source bytes or chunk digest refuses catalogue publication.
    HashRefusal,
    /// Conditional source replacement refuses without selecting new identity.
    SourceSubstitutionRefusal,
    /// Unknown Create retains the exact original without another Create.
    UnknownCreateHeld,
    /// Unknown part retains the exact effect and prevents redispatch.
    UnknownPartHeld,
    /// Unknown Complete remains owned and cannot be settled by HEAD.
    UnknownCompleteHeld,
    /// Positive terminal replay after a lost reply issues no provider effect.
    LostReplyReplay,
    /// Restart preserves actual durable originals, receipts and pending effects.
    ColdGuardRestart,
    /// Quota refusal retains positive physical facts without a catalogue commit.
    QuotaRollback,
    /// Required graph and independent canonical readback precede tag publication.
    CatalogueBarrier,
    /// Known positive completed private stage denies anonymous provider read.
    AnonymousStageDenied,
    /// Versionless conditional read matches actual guard incarnation and closure.
    VersionlessConditionalRead,
    /// The original short control expires after a wait without fresh dispatch.
    DispatchDeadline,
    /// Actual bulk and metadata overlap under the accepted aggregate pool.
    CapacityOverlap,
    /// Incoming cancellation closes real source/provider owners and permits.
    ClientCancellation,
}

/// Exact retained query/effect/result join for one measured workflow boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalOciCaseReport {
    /// Closed case whose actual observation is reported.
    pub case: ExternalOciCase,
    /// Digest of the retained complete business original.
    pub original_sha256: String,
    /// Digest of exact authenticated request/control bytes.
    pub request_sha256: String,
    /// Digest of exact returned semantic result bytes.
    pub result_sha256: String,
    /// Digest of actual independent raw runtime/provider observation report.
    pub raw_report_sha256: String,
    /// Actual source bytes consumed, independently observed beside storage.
    pub source_bytes: u64,
    /// Actual object bytes accepted by the physical destination.
    pub destination_bytes: u64,
    /// Actual bulk bytes transported by Native; production requires zero.
    pub native_bulk_bytes: u64,
    /// Actual provider requests attributed to this original.
    pub provider_dispatches: u64,
}

/// Separates controlled measurement from a genuinely hosted production corpus.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalOciExecution {
    /// Actual controlled runtime; it cannot authorize production effects.
    Controlled,
    /// Actual independently reviewed hosted Worker and provider workflow.
    Hosted,
}

/// Independently signed OCI-purpose acceptance for one exact runtime/profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalOciAcceptance {
    /// Closed artifact version, currently one.
    pub version: u8,
    /// Actual measured environment; controlled evidence never enables Hosted.
    pub execution: ExternalOciExecution,
    /// Independently installed reviewer role identity, never a key in evidence.
    pub reviewer_key_id: String,
    /// Actual shared deployment whose producer was measured.
    pub deployment_id: String,
    /// Actual compiled Worker source digest.
    pub source_digest: String,
    /// Actual installed hosted script identity.
    pub script_version: String,
    /// Complete independently selected raw physical profile and private policy.
    pub profile: ExternalOciProfile,
    /// Exact actual release-pack provenance and source-built gate report.
    pub release_pack_sha256: String,
    /// Exact actual ordinary Worker Wasm bytes measured in this corpus.
    pub wasm_sha256: String,
    /// Exact actual installed shim bytes measured in this corpus.
    pub shim_sha256: String,
    /// Actual ordinary script bytes, separately from whole-isolate memory.
    pub script_bytes: u64,
    /// Actual measured whole-isolate peak including Wasm, JS and SDK copies.
    pub whole_worker_peak_bytes: u64,
    /// Digest of actual raw whole-isolate memory observations.
    pub memory_report_sha256: String,
    /// Actual maximum CPU and wall runtime observations in milliseconds.
    pub cpu_milliseconds: u64,
    /// Actual maximum total wall runtime observation in milliseconds.
    pub wall_milliseconds: u64,
    /// Actual maximum script startup observation in milliseconds.
    pub startup_milliseconds: u64,
    /// Immutable first accepted measurement time.
    pub issued_at: i64,
    /// Immutable independently reviewed cutoff; configuration cannot renew it.
    pub valid_until: i64,
    /// Sorted complete closed corpus of genuine measured cases.
    pub cases: Vec<ExternalOciCaseReport>,
    /// Separate-domain reviewer signature over the full unsigned artifact.
    pub signature: String,
}

impl ExternalOciAcceptance {
    /// Validates the bounded actual evidence closure without accepting a signature.
    ///
    /// # Errors
    /// Refuses missing/duplicate cases, insufficient boundary measurements,
    /// nonzero Native bulk, unknown memory or unsupported measured budgets.
    pub fn validate_unsigned(&self) -> Result<()> {
        self.profile.validate()?;
        ensure!(
            self.version == 1
                && identifier(&self.reviewer_key_id)
                && identifier(&self.deployment_id)
                && digest_string(&self.source_digest)
                && identifier(&self.script_version)
                && [
                    &self.release_pack_sha256,
                    &self.wasm_sha256,
                    &self.shim_sha256,
                    &self.memory_report_sha256
                ]
                .iter()
                .all(|digest| digest_string(digest))
                && self.script_bytes > 0
                && self.script_bytes <= 64 * 1024 * 1024
                && self.whole_worker_peak_bytes > 0
                && self.whole_worker_peak_bytes < 128 * 1024 * 1024
                && self.cpu_milliseconds > 0
                && self.cpu_milliseconds <= 300_000
                && self.wall_milliseconds > 0
                && self.wall_milliseconds <= 900_000
                && self.startup_milliseconds > 0
                && self.startup_milliseconds < 1000
                && self.issued_at > 0
                && self.valid_until > self.issued_at,
            "external OCI evidence or actual runtime bounds incomplete"
        );
        let mut expected = vec![
            ExternalOciCase::EmptyBlob,
        ExternalOciCase::ManifestBoundary,
            ExternalOciCase::ChunkBoundary,
            ExternalOciCase::BlobBoundary,
            ExternalOciCase::ActorRefusal,
            ExternalOciCase::WriterDriftRefusal,
            ExternalOciCase::HashRefusal,
            ExternalOciCase::SourceSubstitutionRefusal,
            ExternalOciCase::UnknownCreateHeld,
            ExternalOciCase::UnknownPartHeld,
            ExternalOciCase::UnknownCompleteHeld,
            ExternalOciCase::LostReplyReplay,
            ExternalOciCase::ColdGuardRestart,
            ExternalOciCase::QuotaRollback,
            ExternalOciCase::CatalogueBarrier,
            ExternalOciCase::AnonymousStageDenied,
            ExternalOciCase::DispatchDeadline,
            ExternalOciCase::CapacityOverlap,
            ExternalOciCase::ClientCancellation,
        ];
        if self.profile.versionless_conditional_reads {
            expected.push(ExternalOciCase::VersionlessConditionalRead);
        }
        expected.sort();
        ensure!(
            self.cases.iter().map(|case| case.case).collect::<Vec<_>>() == expected,
            "external OCI measured corpus missing, duplicated or unordered"
        );
        for case in &self.cases {
            ensure!(
                [
                    &case.original_sha256,
                    &case.request_sha256,
                    &case.result_sha256,
                    &case.raw_report_sha256
                ]
                .iter()
                .all(|digest| digest_string(digest))
                    && case.native_bulk_bytes == 0,
                "external OCI measurement join incomplete or Native bulk observed"
            );
            let boundary = match case.case {
                ExternalOciCase::ManifestBoundary => {
                    Some(crate::hybrid_ingress::MAX_HYBRID_OCI_MANIFEST_BYTES as u64)
                }
                ExternalOciCase::ChunkBoundary => Some(self.profile.maximum_chunk_bytes),
                ExternalOciCase::BlobBoundary => Some(self.profile.maximum_blob_bytes),
                _ => None,
            };
            if let Some(bytes) = boundary {
                ensure!(
                    case.source_bytes >= bytes
                        && case.destination_bytes == bytes
                        && case.provider_dispatches > 0,
                    "external OCI boundary was not actually measured"
                );
            }
            if case.case == ExternalOciCase::EmptyBlob {
                ensure!(case.source_bytes == 0 && case.destination_bytes == 0
                    && case.provider_dispatches > 0,
                    "external OCI empty blob lacks an actual positive conditional PUT");
            }
            if matches!(
                case.case,
                ExternalOciCase::ActorRefusal
                    | ExternalOciCase::WriterDriftRefusal
                    | ExternalOciCase::DispatchDeadline
                    | ExternalOciCase::LostReplyReplay
            ) {
                ensure!(
                    case.provider_dispatches == 0 && case.destination_bytes == 0,
                    "external OCI refusal or replay issued a provider effect"
                );
            }
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_EXTERNAL_OCI_ACCEPTANCE_BYTES,
            "external OCI acceptance oversized"
        );
        Ok(())
    }

    /// Returns separate-domain bytes for independent reviewer verification.
    ///
    /// # Errors
    /// Refuses invalid evidence closure or canonical encoding errors.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        self.validate_unsigned()?;
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        Ok([DOMAIN, serde_json::to_vec(&unsigned)?.as_slice()].concat())
    }

    /// Requires genuine supplied Hosted evidence under an independently installed role.
    ///
    /// # Errors
    /// Refuses controlled evidence, stale cutoff, changed runtime/profile or
    /// a signature not verified by the separately trusted reviewer public key.
    pub fn require_production(
        &self,
        trusted_public_hex: &str,
        reviewer_key_id: &str,
        deployment: &str,
        source: &str,
        script: &str,
        profile: &ExternalOciProfile,
        latest_now: i64,
    ) -> Result<()> {
        self.validate_unsigned()?;
        self.check_time(latest_now)?;
        ensure!(
            self.execution == ExternalOciExecution::Hosted
                && self.reviewer_key_id == reviewer_key_id
                && self.deployment_id == deployment
                && self.source_digest == source
                && self.script_version == script
                && &self.profile == profile
                && digest_string(trusted_public_hex)
                && self.signature.len() == 128,
            "external OCI acceptance purpose/runtime/profile differs"
        );
        let public: [u8; 32] = hex::decode(trusted_public_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("external OCI reviewer key malformed"))?;
        let signature = Signature::from_slice(&hex::decode(&self.signature)?)?;
        VerifyingKey::from_bytes(&public)?
            .verify_strict(&self.signing_bytes()?, &signature)
            .map_err(|_| anyhow::anyhow!("external OCI acceptance signature invalid"))
    }

    /// Rechecks the immutable review cutoff after any asynchronous capacity wait.
    ///
    /// # Errors
    /// Refuses rollback, future observations or an expired acceptance artifact.
    pub fn check_time(&self, latest_now: i64) -> Result<()> {
        ensure!(
            self.issued_at <= latest_now && latest_now < self.valid_until,
            "external OCI immutable acceptance cutoff reached"
        );
        Ok(())
    }
}
