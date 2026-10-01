//! Authenticated authority control and fresh executor watermark messages.
//!
//! SQL decisions are trusted inputs after root review. This protocol transports
//! those exact decisions; it cannot establish provider exclusivity. A response
//! binds a fresh caller nonce and the entire request, independently of TLS.

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use super::{
    canonical_digest, ApproveStorageAuthorityAlias, AssociateStorageAuthorityBinding,
    AttestStorageAuthorityExclusivity, CreatePhysicalStorageAuthority, PhysicalStorageAuthorityId,
    SetStorageAuthorityAdmission, StorageAuthorityAdmissionState, StorageAuthorityRemoteWatermark,
    StorageGuardStamp,
};
use crate::storage_work::StorageWorkKey;

/// Signed control and watermark endpoint; it exposes no provider operations.
pub const STORAGE_AUTHORITY_CONTROL_PATH: &str = "/_internal/storage/v1/authorities";
/// Bound on both request and response bodies.
pub const MAX_AUTHORITY_CONTROL_BYTES: usize = 768 * 1024;
/// Maximum deployment identity length in an authenticated authority envelope.
pub const MAX_AUTHORITY_DEPLOYMENT_ID_BYTES: usize = 128;
/// Maximum immutable configured guard namespace identity length.
pub const MAX_AUTHORITY_NAMESPACE_ID_BYTES: usize = 255;

// Quote and backslash each require two JSON bytes; controls are prohibited.
// The fixed shape includes both widest nonnegative i64 timestamps and the
// Ordinary Publish operation wrapper, excluding its serialized input value.
// DenyFromWatermark adds a remote CAS and is separately checked against the
// complete request bound; its denied publication has no member collections.
const MAX_AUTHORITY_REQUEST_ENVELOPE_BYTES: usize =
    br#"{"version":1,"deployment_id":"","guard_namespace_id":"","nonce":"","issued_at":9223372036854775807,"expires_at":9223372036854775807,"operation":{"kind":"publish","input":}}"#.len()
        + 2 * MAX_AUTHORITY_DEPLOYMENT_ID_BYTES
        + 2 * MAX_AUTHORITY_NAMESPACE_ID_BYTES
        + 64;

/// Maximum encoded publication that fits every ordinary Publish envelope.
///
/// This aggregate budget applies in addition to member count and individual
/// field bounds. SQL desired state may require smaller publication members
/// before the executor can reconcile it; refusal grants no provider admission.
pub const MAX_AUTHORITY_PUBLICATION_BYTES: usize =
    MAX_AUTHORITY_CONTROL_BYTES - MAX_AUTHORITY_REQUEST_ENVELOPE_BYTES;

/// Maximum immutable members per atomic control publication.
pub const MAX_AUTHORITY_MEMBERS: usize = 256;
/// Highest generation representable exactly by all Hub bridges.
pub const MAX_AUTHORITY_GENERATION: i64 = 9_007_199_254_740_991;

/// Exact root-reviewed facts required to enforce one desired admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageAuthorityPublication {
    /// Permanent physical identity and immutable guard domain.
    pub authority: CreatePhysicalStorageAuthority,
    /// Sorted exact aliases referenced by this publication's associations.
    pub aliases: Vec<ApproveStorageAuthorityAlias>,
    /// Sorted immutable binding facts referenced by the exact attestation.
    /// Only `admission.association_ids` permits resolving object work scopes.
    pub associations: Vec<AssociateStorageAuthorityBinding>,
    /// Exact exclusivity decision; absent for blocked or retired state.
    pub attestation: Option<AttestStorageAuthorityExclusivity>,
    /// Exact SQL desired specification, never synthesized by the executor.
    pub admission: SetStorageAuthorityAdmission,
    /// Desired SQL generation, equal to expected generation plus one.
    pub generation: i64,
    /// Canonical digest of admission, matching the SQL outbox contract.
    pub digest: String,
}

impl StorageAuthorityPublication {
    /// Resolves one reviewed association to its permanent full-key guard scope.
    ///
    /// The caller must also match the current binding snapshot and exact
    /// attested credential before provider dispatch. This scope is not an
    /// execution permit; the object DO must recheck fresh admission itself.
    ///
    /// # Errors
    /// Returns an error for blocked admission, expired evidence, missing
    /// association, or a noncanonical or out-of-scope full object key.
    pub fn object_scope(
        &self,
        association_id: &str,
        placement_prefix: &str,
        path: &str,
        now: i64,
    ) -> Result<StorageAuthorityObjectScope> {
        ensure!(
            self.admission.state == StorageAuthorityAdmissionState::Admitted,
            "authority stops new object admission"
        );
        ensure!(
            self.admission
                .association_ids
                .iter()
                .any(|id| id == association_id),
            "association is not admitted"
        );
        self.validate_admission_time(now)?;
        valid_prefix(placement_prefix)?;
        valid_prefix(path)?;
        ensure!(!path.is_empty(), "object path is empty");
        let association = self
            .associations
            .iter()
            .find(|association| association.association_id == association_id)
            .ok_or_else(|| anyhow::anyhow!("association is not admitted"))?;
        let full_key = [association.binding_prefix.as_str(), placement_prefix, path]
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("/");
        ensure!(
            full_key.len() <= 1024,
            "full object key exceeds provider bound"
        );
        Ok(StorageAuthorityObjectScope {
            guard_namespace_id: self.authority.guard_namespace_id.clone(),
            physical_authority_id: self.authority.authority_id.clone(),
            full_key,
        })
    }

    /// Validates structural facts against the configured executor domain.
    ///
    /// # Errors
    /// Returns an error for noncanonical facts, mismatched scope, or an invalid
    /// generation. Provider ownership and root approval remain prerequisites.
    pub fn validate(&self, namespace: &str, executor: &str) -> Result<()> {
        ensure!(
            encoded_within_budget(self, MAX_AUTHORITY_PUBLICATION_BYTES)?,
            "authority publication exceeds the encoded admission budget"
        );
        let authority = &self.authority;
        let admission = &self.admission;
        authority.validate()?;
        valid_key(namespace, 255)?;
        valid_key(executor, 255)?;
        valid_digest(&authority.physical_resource_evidence_digest)?;
        valid_digest(&authority.qualification_digest)?;
        ensure!(
            authority.guard_namespace_id == namespace
                && admission.guard_namespace_id == namespace
                && admission.authority_id == authority.authority_id,
            "authority domain does not match the configured executor"
        );
        ensure!(
            admission.expected_generation >= 0
                && admission.expected_generation < MAX_AUTHORITY_GENERATION
                && self.generation == admission.expected_generation + 1
                && canonical_digest(admission)? == self.digest,
            "authority generation or digest is invalid"
        );
        ensure!(
            (admission.expected_generation == 0) == admission.expected_digest.is_none(),
            "authority predecessor digest is required"
        );
        if let Some(digest) = &admission.expected_digest {
            valid_digest(digest)?;
        }
        ensure!(
            self.aliases.len() <= MAX_AUTHORITY_MEMBERS
                && self.associations.len() <= MAX_AUTHORITY_MEMBERS,
            "authority publication exceeds the atomic membership bound"
        );
        sorted(self.aliases.iter().map(|alias| alias.alias_id.as_str()))?;
        for alias in &self.aliases {
            valid_key(&alias.alias_id, 64)?;
            alias.spec.validate()?;
            valid_digest(&alias.equivalence_evidence_digest)?;
            ensure!(
                alias.authority_id == authority.authority_id,
                "alias authority differs"
            );
        }
        sorted(
            self.associations
                .iter()
                .map(|association| association.association_id.as_str()),
        )?;
        for association in &self.associations {
            valid_key(&association.association_id, 64)?;
            valid_key(&association.binding_stable_id, 255)?;
            valid_prefix(&association.binding_prefix)?;
            ensure!(
                association.authority_id == authority.authority_id
                    && association.binding_id > 0
                    && association.binding_resource_version > 0
                    && association.binding_write_revision > 0
                    && self
                        .aliases
                        .iter()
                        .any(|alias| alias.alias_id == association.alias_id),
                "binding association is outside approved authority aliases"
            );
        }

        if admission.state != StorageAuthorityAdmissionState::Admitted {
            ensure!(
                self.attestation.is_none()
                    && self.associations.is_empty()
                    && admission.attestation_id.is_none()
                    && admission.association_ids.is_empty(),
                "blocked authority retains admission members"
            );
            return Ok(());
        }

        let attestation = self
            .attestation
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("admission has no attestation"))?;
        valid_key(&attestation.attestation_id, 64)?;
        valid_prefix(&attestation.managed_prefix)?;
        valid_digest(&attestation.provider_policy_evidence_digest)?;
        ensure!(
            attestation.authority_id == authority.authority_id
                && attestation.qualification_digest == authority.qualification_digest
                && attestation.executor_identity == executor
                && within_prefix(
                    &attestation.managed_prefix,
                    &authority.qualified_managed_prefix
                )
                && admission.attestation_id.as_ref() == Some(&attestation.attestation_id)
                && !admission.association_ids.is_empty()
                && admission.association_ids.len() <= MAX_AUTHORITY_MEMBERS
                && !attestation.credentials.is_empty()
                && attestation.credentials.len() <= MAX_AUTHORITY_MEMBERS,
            "admission attestation or member set differs"
        );
        sorted(admission.association_ids.iter().map(String::as_str))?;
        for association_id in &admission.association_ids {
            valid_key(association_id, 64)?;
            ensure!(
                self.associations
                    .iter()
                    .any(|association| &association.association_id == association_id),
                "admitted association has no immutable binding facts"
            );
        }
        let mut previous = None;
        for member in &attestation.credentials {
            let identity = (member.association_id.as_str(), member.purpose.as_str());
            ensure!(
                previous.is_none_or(|prior| prior < identity),
                "credentials must be sorted and unique"
            );
            previous = Some(identity);
            valid_key(&member.secret_version_ref, 255)?;
            valid_digest(&member.credential_fingerprint)?;
            ensure!(
                member.generation > 0
                    && matches!(
                        member.purpose.as_str(),
                        "read" | "write" | "list" | "delete" | "presign"
                    )
                    && self
                        .associations
                        .iter()
                        .any(|association| association.association_id == member.association_id),
                "attested credential has no immutable binding facts"
            );
        }
        for association in &self.associations {
            ensure!(
                within_prefix(&association.binding_prefix, &attestation.managed_prefix)
                    && attestation
                        .credentials
                        .iter()
                        .any(|member| member.association_id == association.association_id),
                "binding facts fall outside the exact attestation"
            );
            ensure!(
                !admission
                    .association_ids
                    .contains(&association.association_id)
                    || attestation
                        .credentials
                        .iter()
                        .any(|member| member.association_id == association.association_id
                            && member.purpose == "write"),
                "admitted association lacks an exclusive attested writer"
            );
        }
        Ok(())
    }

    /// Checks freshness for first admission, without changing retained facts.
    ///
    /// # Errors
    /// Returns an error when an admitted attestation expired.
    pub fn validate_admission_time(&self, now: i64) -> Result<()> {
        if let Some(attestation) = &self.attestation {
            ensure!(
                attestation.valid_until > now,
                "authority attestation expired"
            );
        }
        Ok(())
    }
}

/// Permanent addressed object scope, independent of logical credential revisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageAuthorityObjectScope {
    /// Actual immutable configured executor/DO namespace.
    pub guard_namespace_id: String,
    /// Approved physical bucket identity shared by all proven aliases.
    pub physical_authority_id: PhysicalStorageAuthorityId,
    /// Complete physical key; logical prefixes cannot create separate fences.
    pub full_key: String,
}

impl StorageAuthorityObjectScope {
    /// Computes the stable addressed object name in the configured namespace.
    ///
    /// # Errors
    /// Returns an error for malformed namespace, key, or JSON encoding.
    pub fn guard_name(&self) -> Result<String> {
        valid_key(&self.guard_namespace_id, 255)?;
        ensure!(
            !self.full_key.is_empty() && self.full_key.len() <= 1024,
            "full object key is invalid"
        );
        // A full key may be longer than an individual prefix/path contract.
        ensure!(
            self.full_key
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
                && !self
                    .full_key
                    .chars()
                    .any(|character| character.is_control() || character == '\\'),
            "full object key is noncanonical"
        );
        Ok(format!(
            "external-object-v1:{}",
            canonical_digest(&("aos-external-object-scope-v1", self))?
        ))
    }

    /// Checks a guard-issued stamp's physical domain without backfilling it.
    ///
    /// Incarnation capture still belongs to this addressed object's durable
    /// acknowledgement. A stamp alone omits the key and is not an authority.
    ///
    /// # Errors
    /// Returns an error when frozen evidence belongs to another authority.
    pub fn validate_stamp(&self, stamp: &StorageGuardStamp) -> Result<()> {
        ensure!(
            stamp.physical_authority_id == self.physical_authority_id,
            "guard stamp belongs to another physical authority"
        );
        Ok(())
    }
}

/// Exact current SQL denial and the freshly observed remote predecessor.
///
/// This command bridges undelivered history only to stop new admission. Its
/// publication retains the SQL predecessor and digest unchanged. Remote absence
/// means no control head, never absent provider objects or settled effects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageAuthorityDeniedTransition {
    /// Current reviewed blocked or retired publication with no member bundle.
    pub publication: StorageAuthorityPublication,
    /// Exact fresh remote CAS, or verified absence of a durable control head.
    pub expected_remote: Option<StorageAuthorityRemoteWatermark>,
}

impl StorageAuthorityDeniedTransition {
    /// Validates a bounded denial and its permanent remote authority scope.
    ///
    /// # Errors
    /// Returns an error for admission, member bundles, malformed remote evidence
    /// or a changed immutable authority/executor domain.
    pub fn validate(&self, namespace: &str, executor: &str) -> Result<()> {
        self.publication.validate(namespace, executor)?;
        ensure!(
            matches!(
                self.publication.admission.state,
                StorageAuthorityAdmissionState::Blocked | StorageAuthorityAdmissionState::Retired
            ) && self.publication.aliases.is_empty()
                && self.publication.associations.is_empty(),
            "denial transition requires a blocked or retired publication without members"
        );
        if let Some(remote) = &self.expected_remote {
            valid_digest(&remote.digest)?;
            ensure!(
                remote.authority_id == self.publication.authority.authority_id
                    && remote.guard_namespace_id == namespace
                    && remote.generation > 0
                    && remote.generation <= MAX_AUTHORITY_GENERATION,
                "denial predecessor is outside its authority scope"
            );
        }
        Ok(())
    }
}

/// Closed control operations; none authorize object mutations or deletion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "input",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum StorageAuthorityOperation {
    /// Publishes one exact SQL admission generation.
    Publish(StorageAuthorityPublication),
    /// Applies the current denial from an exact remote CAS without admitting history.
    DenyFromWatermark(StorageAuthorityDeniedTransition),
    /// Reads durable current state using a fresh nonce.
    Watermark(PhysicalStorageAuthorityId),
}

/// Fresh authenticated request for the immutable configured guard domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageAuthorityRequest {
    /// Protocol version.
    pub version: u8,
    /// Paired Native deployment authentication scope.
    pub deployment_id: String,
    /// Immutable physical guard namespace, independent of SQL identities.
    pub guard_namespace_id: String,
    /// Fresh random 256-bit lowercase hex nonce; never reused by the client.
    pub nonce: String,
    /// Request creation time.
    pub issued_at: i64,
    /// Maximum thirty-second request deadline.
    pub expires_at: i64,
    /// Exact control or lookup operation.
    pub operation: StorageAuthorityOperation,
}

impl StorageAuthorityRequest {
    /// Validates deployment, physical domain, nonce and bounded lifetime.
    ///
    /// # Errors
    /// Returns an error for stale, malformed, or mismatched requests.
    pub fn validate(&self, deployment: &str, namespace: &str, now: i64) -> Result<()> {
        ensure!(
            encoded_within_budget(self, MAX_AUTHORITY_CONTROL_BYTES)?,
            "authority request exceeds its encoded wire bound"
        );
        valid_key(&self.deployment_id, MAX_AUTHORITY_DEPLOYMENT_ID_BYTES)?;
        valid_key(&self.guard_namespace_id, MAX_AUTHORITY_NAMESPACE_ID_BYTES)?;
        valid_digest(&self.nonce)?;
        ensure!(
            self.version == 1
                && self.deployment_id == deployment
                && self.guard_namespace_id == namespace
                && now >= 0
                && self.issued_at >= 0
                && self.issued_at <= now
                && self.expires_at > now
                && self.expires_at.saturating_sub(self.issued_at) <= 30,
            "authority request is stale or outside the authenticated domain"
        );
        Ok(())
    }

    /// Selects the permanent authority addressed by this operation.
    pub fn authority_id(&self) -> &PhysicalStorageAuthorityId {
        match &self.operation {
            StorageAuthorityOperation::Publish(publication) => &publication.authority.authority_id,
            StorageAuthorityOperation::DenyFromWatermark(transition) => {
                &transition.publication.authority.authority_id
            }
            StorageAuthorityOperation::Watermark(authority) => authority,
        }
    }
}

/// Immutable receipt for a control publication, separate from current state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageAuthorityControlReceipt {
    /// Exact previously applied generation.
    pub generation: i64,
    /// Digest acknowledged for that generation.
    pub digest: String,
    /// Entire immutable fact bundle, preventing changed-payload replay.
    pub publication_digest: String,
}

/// Nonce-bound reply; a historical receipt never substitutes for latest state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageAuthorityResponse {
    /// Protocol version.
    pub version: u8,
    /// Canonical digest of the complete requesting message.
    pub request_digest: String,
    /// Echoed fresh caller nonce.
    pub nonce: String,
    /// Paired deployment identity.
    pub deployment_id: String,
    /// Actual configured immutable physical guard domain.
    pub guard_namespace_id: String,
    /// Response creation time.
    pub issued_at: i64,
    /// Original request deadline; no extension on response loss.
    pub expires_at: i64,
    /// Latest durable watermark, including when an old control is replayed.
    pub watermark: Option<StorageAuthorityRemoteWatermark>,
    /// Exact historical control acknowledgement, absent for a lookup.
    pub control_receipt: Option<StorageAuthorityControlReceipt>,
}

impl StorageAuthorityResponse {
    /// Checks correlation after verifying the exact response signature.
    ///
    /// # Errors
    /// Returns an error for stale, mismatched, or malformed response evidence.
    pub fn validate_for(&self, request: &StorageAuthorityRequest, now: i64) -> Result<()> {
        request.validate(&request.deployment_id, &request.guard_namespace_id, now)?;
        ensure!(
            self.version == 1
                && self.request_digest == canonical_digest(request)?
                && self.nonce == request.nonce
                && self.deployment_id == request.deployment_id
                && self.guard_namespace_id == request.guard_namespace_id
                && self.issued_at >= request.issued_at
                && self.issued_at <= now
                && self.expires_at == request.expires_at
                && self.expires_at > now,
            "authority response is stale or does not answer this fresh request"
        );
        if let Some(watermark) = &self.watermark {
            valid_digest(&watermark.digest)?;
            ensure!(
                &watermark.authority_id == request.authority_id()
                    && watermark.guard_namespace_id == request.guard_namespace_id
                    && watermark.generation > 0
                    && watermark.generation <= MAX_AUTHORITY_GENERATION,
                "authority response watermark is outside its scope"
            );
        }
        match (&request.operation, &self.control_receipt) {
            (StorageAuthorityOperation::Watermark(_), None) => {}
            (StorageAuthorityOperation::Publish(publication), Some(receipt))
            | (
                StorageAuthorityOperation::DenyFromWatermark(StorageAuthorityDeniedTransition {
                    publication,
                    ..
                }),
                Some(receipt),
            ) => ensure!(
                receipt.generation == publication.generation
                    && receipt.digest == publication.digest
                    && receipt.publication_digest == canonical_digest(publication)?
                    && self.watermark.is_some(),
                "authority control receipt differs from the reviewed publication"
            ),
            _ => anyhow::bail!("authority response operation differs"),
        }
        Ok(())
    }
}

/// Signs a bounded authority message in its distinct request/response domain.
///
/// # Errors
/// Returns an error for oversized bodies or invalid signing material.
pub fn sign_authority_message(key: &StorageWorkKey, response: bool, body: &[u8]) -> Result<String> {
    key.sign_body(&signature_input(response, body)?)
        .map_err(Into::into)
}

/// Verifies an exact authority message before any deserialization or I/O.
///
/// # Errors
/// Returns an error for oversized bodies, bad signatures, or the wrong domain.
pub fn verify_authority_message(
    key: &StorageWorkKey,
    response: bool,
    signature: &str,
    body: &[u8],
) -> Result<()> {
    key.verify_body(signature, &signature_input(response, body)?)
        .map_err(Into::into)
}

fn signature_input(response: bool, body: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        body.len() <= MAX_AUTHORITY_CONTROL_BYTES,
        "authority message exceeds its wire bound"
    );
    let domain: &[u8] = if response {
        b"aos-storage-authority-response-v1\0"
    } else {
        b"aos-storage-authority-request-v1\0"
    };
    let mut bytes = Vec::with_capacity(domain.len() + body.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(body);
    Ok(bytes)
}

// Reject while streaming into a counter, without allocating an oversized JSON
// buffer for a model supplied directly by Native or another in-process caller.
fn encoded_within_budget(value: &impl Serialize, maximum: usize) -> Result<bool> {
    let mut budget = EncodedBudget {
        remaining: maximum,
        exceeded: false,
    };
    match serde_json::to_writer(&mut budget, value) {
        Ok(()) => Ok(true),
        Err(_) if budget.exceeded => Ok(false),
        Err(error) => Err(error.into()),
    }
}

struct EncodedBudget {
    remaining: usize,
    exceeded: bool,
}

impl std::io::Write for EncodedBudget {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(std::io::Error::other("encoded authority budget exceeded"));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn valid_key(value: &str, maximum: usize) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= maximum
            && value.trim() == value
            && !value.chars().any(char::is_control),
        "authority key is invalid"
    );
    Ok(())
}

fn valid_digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "authority digest is invalid"
    );
    Ok(())
}

fn valid_prefix(value: &str) -> Result<()> {
    ensure!(
        value.len() <= 512
            && value.trim() == value
            && value.trim_matches('/') == value
            && (value.is_empty()
                || value
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != ".."))
            && !value
                .chars()
                .any(|character| character.is_control() || character == '\\'),
        "authority prefix is invalid"
    );
    Ok(())
}

fn within_prefix(value: &str, prefix: &str) -> bool {
    prefix.is_empty()
        || value == prefix
        || value
            .strip_prefix(prefix)
            .is_some_and(|tail| tail.starts_with('/'))
}

fn sorted<'a>(values: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let mut previous = None;
    for value in values {
        ensure!(
            previous.is_none_or(|prior| prior < value),
            "authority members must be sorted and unique"
        );
        previous = Some(value);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use serde::ser::SerializeSeq;

    use super::*;

    #[test]
    fn encoded_budget_counts_escaped_bytes_and_stops_the_serializer() {
        assert!(encoded_within_budget(&"\"", 4).unwrap());
        assert!(!encoded_within_budget(&"\"", 3).unwrap());

        struct LongSequence(Cell<usize>);

        impl Serialize for LongSequence {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut sequence = serializer.serialize_seq(None)?;
                for _ in 0..10_000 {
                    self.0.set(self.0.get() + 1);
                    sequence.serialize_element(&"authority-member")?;
                }
                sequence.end()
            }
        }

        let input = LongSequence(Cell::new(0));
        assert!(!encoded_within_budget(&input, 32).unwrap());
        assert!(
            input.0.get() < 3,
            "serialization must stop at the byte limit"
        );
    }
}
