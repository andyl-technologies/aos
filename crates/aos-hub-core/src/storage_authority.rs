//! Permanent physical storage identity and reviewed admission contracts.
//!
//! These types prepare external, nonversioned S3 coordination. They do not
//! advertise provider deletion capability. An object incarnation is issued by
//! its durable guard, independently of SQL snapshots and provider ETags.
//!
//! ```json
//! {"physical_authority_id":"00000000-0000-4000-8000-000000000001","incarnation":"1"}
//! ```

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[path = "storage_authority/control.rs"]
pub mod control;

#[path = "storage_authority/external_object/mod.rs"]
pub mod external_object;

#[path = "storage_authority/lease/mod.rs"]
pub mod lease;

/// Permanent identity for one physical bucket and its object guard domain.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PhysicalStorageAuthorityId(String);

impl PhysicalStorageAuthorityId {
    /// Parses an immutable, canonical UUID authority identity.
    ///
    /// # Errors
    ///
    /// Returns an error for a nil or noncanonical UUID.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let uuid = uuid::Uuid::parse_str(&value)?;
        ensure!(
            !uuid.is_nil() && uuid.hyphenated().to_string() == value,
            "physical authority identity must be a canonical non-nil UUID"
        );
        Ok(Self(value))
    }

    /// Borrows the permanent identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PhysicalStorageAuthorityId {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        Self::parse(value)
    }
}

impl From<PhysicalStorageAuthorityId> for String {
    fn from(value: PhysicalStorageAuthorityId) -> Self {
        value.0
    }
}

/// Positive guard-issued incarnation, encoded as an exact decimal wire string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct GuardIncarnation(String);

impl GuardIncarnation {
    /// Constructs a positive incarnation representable by every Hub SQL bridge.
    ///
    /// The guard must block mutation rather than wrap an exhausted counter.
    ///
    /// # Errors
    ///
    /// Returns an error for zero, overflow, or a noncanonical decimal string.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let parsed = value.parse::<i64>()?;
        ensure!(
            parsed > 0 && parsed <= 9_007_199_254_740_991 && parsed.to_string() == value,
            "invalid guard incarnation"
        );
        Ok(Self(value))
    }

    /// Borrows the exact decimal representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for GuardIncarnation {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        Self::parse(value)
    }
}

impl From<GuardIncarnation> for String {
    fn from(value: GuardIncarnation) -> Self {
        value.0
    }
}

/// Durable guard identity captured with one acknowledged object observation.
///
/// This is separate from R2's provider-issued upload version. Neither a later
/// HEAD nor identical provider metadata may backfill a missing frozen stamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageGuardStamp {
    /// Permanent physical storage domain; independent of logical bindings.
    pub physical_authority_id: PhysicalStorageAuthorityId,
    /// Guard-issued generation for the exact full physical key.
    pub incarnation: GuardIncarnation,
}

/// Canonical host representation used to approve an endpoint alias.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum StorageAuthorityHost {
    /// Canonical ASCII DNS name; DNS resolution does not establish equivalence.
    Dns(String),
    /// Exact IPv4 octets.
    Ipv4([u8; 4]),
    /// Exact IPv6 octets.
    Ipv6([u8; 16]),
}

/// One exact endpoint/bucket address approved as a physical authority alias.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageAuthorityAliasSpec {
    /// Typed canonical host, without inferred DNS or redirect equivalence.
    pub host: StorageAuthorityHost,
    /// Explicit HTTPS port, including 443.
    pub port: u16,
    /// Exact case-sensitive provider bucket name.
    pub bucket: String,
}

impl StorageAuthorityAliasSpec {
    /// Checks canonical coordinates without contacting a provider.
    ///
    /// # Errors
    ///
    /// Returns an error for a noncanonical host, port, or bucket.
    pub fn validate(&self) -> Result<()> {
        ensure!(self.port > 0, "alias requires an explicit HTTPS port");
        ensure!(
            !self.bucket.is_empty()
                && self.bucket.len() <= 255
                && self.bucket.trim() == self.bucket
                && !self
                    .bucket
                    .chars()
                    .any(|c| c.is_control() || matches!(c, '/' | '\\')),
            "alias bucket is invalid"
        );
        if let StorageAuthorityHost::Dns(host) = &self.host {
            ensure!(
                crate::db::canonical_delivery_hostname(host)? == *host,
                "alias DNS host is not canonical"
            );
        }
        Ok(())
    }

    /// Computes the global exact-address key; signing region is not identity.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid coordinates or JSON encoding failure.
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        canonical_digest(self)
    }
}

/// Immutable physical authority creation input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePhysicalStorageAuthority {
    /// Caller-generated permanent identity frozen in the reviewed plan.
    pub authority_id: PhysicalStorageAuthorityId,
    /// Actual immutable executor namespace identity, shared by physical domains.
    /// Guards additionally include the permanent authority ID and full object key;
    /// this value alone does not prove that a caller owns the executor namespace.
    pub guard_namespace_id: String,
    /// Digest of operator evidence identifying the physical provider resource.
    pub physical_resource_evidence_digest: String,
    /// Digest of fresh, zero-operation namespace qualification evidence.
    pub qualification_digest: String,
    /// Immutable prefix covered by initial fresh, exclusive qualification.
    /// Empty means the entire bucket; later attestations may only stay within it.
    pub qualified_managed_prefix: String,
}

impl CreatePhysicalStorageAuthority {
    /// Validates the immutable coordinates and initial qualification ceiling.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed namespace, evidence digests, or a
    /// noncanonical qualification prefix. Missing legacy JSON is rejected by
    /// deserialization; no attestation or provider HEAD can supply a replacement.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.guard_namespace_id.is_empty()
                && self.guard_namespace_id.len() <= 255
                && self.guard_namespace_id.trim() == self.guard_namespace_id
                && !self.guard_namespace_id.chars().any(char::is_control),
            "authority namespace is invalid"
        );
        for digest in [
            &self.physical_resource_evidence_digest,
            &self.qualification_digest,
        ] {
            ensure!(
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
                "authority qualification digest is invalid"
            );
        }

        let prefix = &self.qualified_managed_prefix;
        ensure!(
            prefix.len() <= 512
                && prefix.trim() == prefix
                && prefix.trim_matches('/') == prefix
                && (prefix.is_empty()
                    || prefix
                        .split('/')
                        .all(|part| !part.is_empty() && part != "." && part != ".."))
                && !prefix
                    .chars()
                    .any(|character| character.is_control() || character == '\\'),
            "authority qualified prefix is invalid"
        );
        Ok(())
    }
}

/// Root-reviewed exact-address equivalence approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveStorageAuthorityAlias {
    /// Alias identity frozen by the review.
    pub alias_id: String,
    /// Permanent authority owning this address forever, including after revocation.
    pub authority_id: PhysicalStorageAuthorityId,
    /// Canonical endpoint/bucket coordinates.
    pub spec: StorageAuthorityAliasSpec,
    /// Root decision's explicit equivalence evidence digest.
    pub equivalence_evidence_digest: String,
}

/// Immutable binding revision and physical prefix association.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssociateStorageAuthorityBinding {
    /// Immutable association identity.
    pub association_id: String,
    /// Permanent physical authority.
    pub authority_id: PhysicalStorageAuthorityId,
    /// Exact root-approved endpoint/bucket alias.
    pub alias_id: String,
    /// Logical binding database identity.
    pub binding_id: i64,
    /// Logical binding stable identity, preventing numeric-ID substitution.
    pub binding_stable_id: String,
    /// Exact coordinate revision reviewed by the operator.
    pub binding_resource_version: i64,
    /// Exact immutable writer and credential revision.
    pub binding_write_revision: i64,
    /// Exact canonical binding prefix; object guards use full physical keys.
    pub binding_prefix: String,
}

/// Exact immutable credential included in a provider exclusivity attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageAuthorityCredentialMember {
    /// Root-approved binding association retaining these coordinates.
    pub association_id: String,
    /// Exact immutable credential purpose.
    pub purpose: String,
    /// Exact purpose-local credential generation.
    pub generation: i64,
    /// Immutable secret-manager reference; this contract carries no secret.
    pub secret_version_ref: String,
    /// Fingerprint of the provider credential covered by the operator evidence.
    pub credential_fingerprint: String,
}

/// Immutable operator assertion of provider and credential exclusivity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestStorageAuthorityExclusivity {
    /// Immutable attestation identity.
    pub attestation_id: String,
    /// Physical domain whose provider access was reviewed.
    pub authority_id: PhysicalStorageAuthorityId,
    /// Current exclusive admission prefix, equal to or within the immutable
    /// qualified ceiling. Narrowing or reopening inside it never settles effects.
    pub managed_prefix: String,
    /// Same initial zero-operation qualification retained throughout this lifetime.
    pub qualification_digest: String,
    /// Evidence that provider policy excludes all uncoordinated writers.
    pub provider_policy_evidence_digest: String,
    /// Approved storage executor identity; not merely a mutable hostname.
    pub executor_identity: String,
    /// Exact sorted credential members covered by the evidence.
    pub credentials: Vec<StorageAuthorityCredentialMember>,
    /// Time until which new admission may rely on this assertion.
    pub valid_until: i64,
}

/// Desired admission lifecycle; changing it never settles provider effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageAuthorityAdmissionState {
    /// Reviewed configuration awaiting an actual executor enforcement gate.
    Admitted,
    /// Stops new admission while retaining every pending-effect fence.
    Blocked,
    /// Terminal authority retirement; physical aliases remain reserved.
    Retired,
}

/// Exact immutable desired authority admission generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetStorageAuthorityAdmission {
    /// Permanent physical authority.
    pub authority_id: PhysicalStorageAuthorityId,
    /// Expected latest SQL generation, zero before the first reviewed decision.
    pub expected_generation: i64,
    /// Expected prior canonical admission digest, absent only at generation zero.
    pub expected_digest: Option<String>,
    /// Immutable guard namespace; alteration is rejected even during retirement.
    pub guard_namespace_id: String,
    /// Reviewed desired lifecycle.
    pub state: StorageAuthorityAdmissionState,
    /// Exact immutable exclusivity attestation required for admitted state.
    pub attestation_id: Option<String>,
    /// Sorted immutable associations admitted by this generation.
    pub association_ids: Vec<String>,
}

/// Closed reviewed operation families stored in ordinary topology plans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "input",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum StorageAuthorityDecisionInput {
    /// Allocates permanent identity without admitting provider work.
    Create(CreatePhysicalStorageAuthority),
    /// Reserves canonical endpoint/bucket equivalence under root approval.
    ApproveAlias(ApproveStorageAuthorityAlias),
    /// Freezes binding coordinates and writer revision.
    AssociateBinding(AssociateStorageAuthorityBinding),
    /// Records explicit operator evidence; it is not an automatic provider proof.
    Attest(AttestStorageAuthorityExclusivity),
    /// Appends desired admission, requiring remote reconciliation before use.
    SetAdmission(SetStorageAuthorityAdmission),
}

impl StorageAuthorityDecisionInput {
    /// Returns the exact reviewed topology-plan family.
    pub fn plan_kind(&self) -> &'static str {
        match self {
            Self::Create(_) => "create_storage_authority",
            Self::ApproveAlias(_) => "approve_storage_authority_alias",
            Self::AssociateBinding(_) => "associate_storage_authority_binding",
            Self::Attest(_) => "attest_storage_authority_exclusivity",
            Self::SetAdmission(_) => "set_storage_authority_admission",
        }
    }
}

/// Exact canonical operator review, including its explicit target version.
///
/// Version 1 confirms this entire envelope rather than only the decision. Legacy
/// bare decisions remain a DB-only compatibility format, never a canonical API
/// plan. This format contains immutable references and evidence, not secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageAuthorityReviewedPlanInput {
    /// Closed format marker; only version 1 is admitted.
    pub schema_version: u32,
    /// Exact canonical target version supplied in the planning request.
    pub expected_resource_version: String,
    /// Immutable typed intent loaded during apply.
    pub decision: StorageAuthorityDecisionInput,
}

impl StorageAuthorityReviewedPlanInput {
    /// Checks the format and agreement between generic and typed target versions.
    ///
    /// # Errors
    /// Returns an error for unknown format versions or noncanonical/mismatched
    /// target versions. Current database state is checked separately.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "authority review version is unknown"
        );
        let matches = match &self.decision {
            StorageAuthorityDecisionInput::Create(_) => self.expected_resource_version.is_empty(),
            StorageAuthorityDecisionInput::AssociateBinding(input) => {
                input.binding_resource_version > 0
                    && input.binding_resource_version <= 9_007_199_254_740_991
                    && self.expected_resource_version == input.binding_resource_version.to_string()
            }
            StorageAuthorityDecisionInput::SetAdmission(input) => {
                input.expected_generation >= 0
                    && input.expected_generation <= 9_007_199_254_740_991
                    && self.expected_resource_version == input.expected_generation.to_string()
            }
            StorageAuthorityDecisionInput::ApproveAlias(_)
            | StorageAuthorityDecisionInput::Attest(_) => {
                self.expected_resource_version.len() == 64
                    && self
                        .expected_resource_version
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            }
        };
        ensure!(matches, "authority review target version is invalid");
        Ok(())
    }
}

/// Fresh executor watermark obtained through an authenticated control channel.
///
/// SQL persistence cannot authenticate this value. A future executor adapter
/// must verify its response before passing it to reconciliation or admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageAuthorityRemoteWatermark {
    /// Permanent physical authority acknowledged by the executor.
    pub authority_id: PhysicalStorageAuthorityId,
    /// Actual immutable guard namespace enforcing this domain.
    pub guard_namespace_id: String,
    /// Executor's latest durable control generation.
    pub generation: i64,
    /// Exact canonical desired admission digest acknowledged by the executor.
    pub digest: String,
}

pub(crate) fn canonical_digest(value: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}
