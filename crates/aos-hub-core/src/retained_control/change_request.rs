//! Change-request revisions, collaboration timeline, and publication gates.

use std::collections::BTreeSet;

use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::iam::{
    membership_index_id, MembershipSnapshotEntry, MembershipState, PrincipalKind, PrincipalRef,
    Role,
};
use super::plan::HeadSeal;
use super::primitives::{
    Actor, ActorKind, ContentDigest, ControlError, Generation, ResourceVersion, Revision, StableId,
};

/// A canonical algorithm-qualified Git object identity.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct GitObjectId(String);

impl GitObjectId {
    /// Validates `sha1:<40 lowercase hex>` or `sha256:<64 lowercase hex>`.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] for a missing algorithm tag, wrong
    /// length, or non-lowercase-hex object id.
    pub fn new(value: impl Into<String>) -> Result<Self, ControlError> {
        let value = value.into();
        let valid = match value.split_once(':') {
            Some(("sha1", hex)) => valid_hex(hex, 40),
            Some(("sha256", hex)) => valid_hex(hex, 64),
            _ => false,
        };
        if !valid {
            return Err(invalid(
                "git_object_id",
                "must be an algorithm-qualified lowercase Git object id",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the canonical algorithm-qualified identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn algorithm(&self) -> &str {
        self.0
            .split_once(':')
            .map_or("", |(algorithm, _)| algorithm)
    }
}

/// Git object kind admitted by retained cryptographic evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitObjectKind {
    /// Commit object.
    Commit,
    /// Annotated tag object.
    Tag,
}

impl GitObjectKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Tag => "tag",
        }
    }
}

/// Canonical raw Git object bytes bound to their recomputed object identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GitObjectProof {
    /// Recomputed algorithm-qualified Git object identity.
    pub object_id: GitObjectId,
    /// Exact Git object kind used in the hash header.
    pub kind: GitObjectKind,
    /// Canonical unpadded base64 raw object contents, excluding Git hash header.
    pub raw_base64: String,
}

impl GitObjectProof {
    /// Computes an algorithm-qualified identity from exact raw object contents.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error for an unsupported algorithm or oversized
    /// raw object.
    pub fn from_raw(
        algorithm: &str,
        kind: GitObjectKind,
        raw: &[u8],
    ) -> Result<Self, ControlError> {
        if raw.len() > 1_048_576 || !matches!(algorithm, "sha1" | "sha256") {
            return Err(invalid(
                "git_object",
                "unsupported algorithm or oversized object",
            ));
        }
        let header = format!("{} {}\0", kind.as_str(), raw.len());
        let mut hashed = header.into_bytes();
        hashed.extend_from_slice(raw);
        let hex = match algorithm {
            "sha1" => hex_bytes(&sha1_digest(&hashed)),
            "sha256" => hex_bytes(&Sha256::digest(&hashed)),
            _ => return Err(invalid("git_object", "unsupported Git hash algorithm")),
        };
        Self::new(
            GitObjectId::new(format!("{algorithm}:{hex}"))?,
            kind,
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(raw),
        )
    }

    /// Constructs and verifies a bounded raw Git-object proof.
    ///
    /// # Errors
    ///
    /// Returns an encoding, size, or object-id mismatch error.
    pub fn new(
        object_id: GitObjectId,
        kind: GitObjectKind,
        raw_base64: String,
    ) -> Result<Self, ControlError> {
        let proof = Self {
            object_id,
            kind,
            raw_base64,
        };
        proof.verify()?;
        Ok(proof)
    }

    /// Decodes the bounded canonical raw contents.
    ///
    /// # Errors
    ///
    /// Returns an encoding or size error.
    pub fn raw_bytes(&self) -> Result<Vec<u8>, ControlError> {
        if self.raw_base64.is_empty() || self.raw_base64.len() > 1_398_102 {
            return Err(invalid("git_object", "raw object must not exceed 1 MiB"));
        }
        let raw = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(&self.raw_base64)
            .map_err(|_| invalid("git_object", "must use canonical unpadded base64"))?;
        if raw.len() > 1_048_576
            || base64::engine::general_purpose::STANDARD_NO_PAD.encode(&raw) != self.raw_base64
        {
            return Err(invalid("git_object", "must be canonical and at most 1 MiB"));
        }
        Ok(raw)
    }

    fn verify(&self) -> Result<(), ControlError> {
        let raw = self.raw_bytes()?;
        let header = format!("{} {}\0", self.kind.as_str(), raw.len());
        let mut hashed = header.into_bytes();
        hashed.extend_from_slice(&raw);
        let hex = match self.object_id.algorithm() {
            "sha1" => hex_bytes(&sha1_digest(&hashed)),
            "sha256" => hex_bytes(&Sha256::digest(&hashed)),
            _ => return Err(invalid("git_object", "unsupported Git hash algorithm")),
        };
        if self.object_id.as_str() != format!("{}:{hex}", self.object_id.algorithm()) {
            return Err(ControlError::DigestMismatch);
        }
        Ok(())
    }
}

/// Parsed canonical AOS annotated-tag claims.
pub(crate) struct VerifiedGitTagClaims {
    /// Exact canonical annotated-tag name.
    pub(crate) tag_name: String,
    /// Exact commit targeted by the annotated tag.
    pub(crate) target: GitObjectId,
    /// Stable signing-key identity embedded in the tag message.
    pub(crate) signer_key_id: StableId,
    /// Exact immutable signing-key generation embedded in the tag message.
    pub(crate) signing_key_generation: Generation,
    /// Canonical semantic claim digest embedded in the tag message.
    pub(crate) signed_claim_digest: ContentDigest,
    /// Canonical Ed25519 signature embedded in the tag message.
    pub(crate) signature: String,
}

/// Parses exact AOS signature claims from a rehashed annotated Git tag.
///
/// # Errors
///
/// Returns an encoding, object-id, structure, identity, or duplicate-claim
/// error unless the proof is one canonical annotated tag targeting a commit.
pub(crate) fn parse_verified_git_tag(
    proof: &GitObjectProof,
) -> Result<VerifiedGitTagClaims, ControlError> {
    proof.verify()?;
    if proof.kind != GitObjectKind::Tag {
        return Err(invalid("git_tag", "proof must contain an annotated tag"));
    }
    let raw = proof.raw_bytes()?;
    let text = std::str::from_utf8(&raw)
        .map_err(|_| invalid("git_tag", "annotated tag must be canonical UTF-8"))?;
    let (headers, message) = text
        .split_once("\n\n")
        .ok_or_else(|| invalid("git_tag", "annotated tag requires headers and message"))?;
    let header_lines = headers.lines().collect::<Vec<_>>();
    if header_lines.len() != 4
        || header_lines[1] != "type commit"
        || !canonical_tagger(header_lines[3])
    {
        return Err(invalid(
            "git_tag",
            "annotated tag must use the exact canonical four-header template",
        ));
    }
    let object = header_lines[0]
        .strip_prefix("object ")
        .ok_or_else(|| invalid("git_tag", "missing object header"))?;
    let tag_name = header_lines[2]
        .strip_prefix("tag ")
        .ok_or_else(|| invalid("git_tag", "missing tag header"))?;
    if tag_name.is_empty()
        || tag_name.len() > 64
        || tag_name.starts_with('-')
        || tag_name.ends_with('-')
        || !tag_name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(invalid("git_tag", "tag name must be a canonical slug"));
    }
    let qualify = |hex: &str| GitObjectId::new(format!("{}:{hex}", proof.object_id.algorithm()));
    let target = qualify(object)?;
    if !message.ends_with('\n') {
        return Err(invalid(
            "git_tag",
            "canonical tag message must end in one newline",
        ));
    }
    let message_lines = message.trim_end_matches('\n').lines().collect::<Vec<_>>();
    if message_lines.len() != 4 || message.ends_with("\n\n") {
        return Err(invalid(
            "git_tag",
            "tag message must contain exactly four ordered AOS claims",
        ));
    }
    let signer = message_lines[0]
        .strip_prefix("aos-signer-key ")
        .ok_or_else(|| invalid("git_tag", "missing signer claim"))?;
    let generation = message_lines[1]
        .strip_prefix("aos-signing-generation ")
        .ok_or_else(|| invalid("git_tag", "missing generation claim"))?;
    let claim = message_lines[2]
        .strip_prefix("aos-signed-claim ")
        .ok_or_else(|| invalid("git_tag", "missing digest claim"))?;
    let signature = message_lines[3]
        .strip_prefix("aos-signature ")
        .ok_or_else(|| invalid("git_tag", "missing signature claim"))?;
    if message_lines.iter().any(|line| line.len() > 512) {
        return Err(invalid("git_tag", "AOS tag claim line is oversized"));
    }
    Ok(VerifiedGitTagClaims {
        tag_name: tag_name.to_owned(),
        target,
        signer_key_id: StableId::new(signer)?,
        signing_key_generation: Generation::new(
            generation
                .parse::<u64>()
                .map_err(|_| invalid("git_tag", "invalid signing generation"))?,
        )?,
        signed_claim_digest: ContentDigest::new(claim)?,
        signature: signature.to_owned(),
    })
}

fn canonical_tagger(line: &str) -> bool {
    line.strip_prefix("tagger AOS <aos@example.test> ")
        .and_then(|suffix| suffix.strip_suffix(" +0000"))
        .and_then(|timestamp| {
            timestamp
                .parse::<u64>()
                .ok()
                .map(|value| (timestamp, value))
        })
        .is_some_and(|(timestamp, value)| value.to_string() == timestamp)
}

fn parse_commit_links(proof: &GitObjectProof) -> Result<(GitObjectId, GitObjectId), ControlError> {
    proof.verify()?;
    if proof.kind != GitObjectKind::Commit {
        return Err(invalid("git_commit", "proof must contain a commit"));
    }
    let raw = proof.raw_bytes()?;
    let text = std::str::from_utf8(&raw)
        .map_err(|_| invalid("git_commit", "commit must be canonical UTF-8"))?;
    let headers = text
        .split_once("\n\n")
        .ok_or_else(|| invalid("git_commit", "commit requires headers and message"))?
        .0;
    let qualify = |hex: &str| GitObjectId::new(format!("{}:{hex}", proof.object_id.algorithm()));
    let mut tree = None;
    let mut parent = None;
    for line in headers.lines() {
        if let Some(value) = line.strip_prefix("tree ") {
            if tree.replace(qualify(value)?).is_some() {
                return Err(invalid("git_commit", "commit must contain one tree"));
            }
        } else if let Some(value) = line.strip_prefix("parent ") {
            if parent.replace(qualify(value)?).is_some() {
                return Err(invalid(
                    "git_commit",
                    "change-request candidate must have exactly one parent",
                ));
            }
        }
    }
    Ok((
        tree.ok_or_else(|| invalid("git_commit", "missing tree header"))?,
        parent.ok_or_else(|| invalid("git_commit", "missing parent header"))?,
    ))
}

impl<'de> Deserialize<'de> for GitObjectId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Change-request lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeRequestState {
    /// The proposal may receive reviews and be applied.
    Open,
    /// The proposal was withdrawn without application.
    Closed,
    /// The exact signed candidate was published.
    Applied,
}

/// Immutable contents of a change-request revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChangeRequestRevisionContents {
    /// Target registry stable identity.
    pub registry_id: StableId,
    /// Human title.
    pub title: String,
    /// Optional human description.
    pub body: Option<String>,
    /// Registry head on which the draft was based.
    pub base_commit: GitObjectId,
    /// Exact signed draft commit.
    pub draft_commit: GitObjectId,
    /// Exact tree reviewed by humans and later re-signed by a roster key.
    pub draft_tree: GitObjectId,
    /// Digest of the complete ordered file-change manifest.
    pub file_manifest_digest: ContentDigest,
    /// Lifecycle state.
    pub state: ChangeRequestState,
}

/// One immutable change-request proposal or lifecycle revision.
pub type ChangeRequestRevision = Revision<ChangeRequestRevisionContents>;

impl ChangeRequestRevisionContents {
    /// Validates a new open proposal.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] for an empty/oversized title or body,
    /// identical base/draft commits, or a non-open initial state.
    pub fn validate_new(&self) -> Result<(), ControlError> {
        if self.registry_id.kind() != "registry" {
            return Err(invalid(
                "registry_id",
                "must use a registry stable identity",
            ));
        }
        if self.title.trim().is_empty() || self.title.len() > 256 {
            return Err(invalid("title", "must contain 1-256 non-whitespace bytes"));
        }
        if self.body.as_ref().is_some_and(|body| body.len() > 65_536) {
            return Err(invalid("body", "must not exceed 65536 bytes"));
        }
        if self.base_commit == self.draft_commit {
            return Err(invalid("draft_commit", "must differ from the base commit"));
        }
        if self.state != ChangeRequestState::Open {
            return Err(invalid("state", "new change requests must be open"));
        }
        Ok(())
    }

    /// Closes an open change request.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] unless the current state is open.
    pub fn close(&self) -> Result<Self, ControlError> {
        self.transition(ChangeRequestState::Closed)
    }

    /// Reopens a closed change request without changing its exact draft.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] unless the current state is closed.
    pub fn reopen(&self) -> Result<Self, ControlError> {
        if self.state != ChangeRequestState::Closed {
            return Err(invalid("state", "only a closed change request may reopen"));
        }
        let mut next = self.clone();
        next.state = ChangeRequestState::Open;
        Ok(next)
    }

    /// Marks an open change request applied after publication gates pass.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] unless the current state is open.
    pub fn applied(&self) -> Result<Self, ControlError> {
        self.transition(ChangeRequestState::Applied)
    }

    fn transition(&self, state: ChangeRequestState) -> Result<Self, ControlError> {
        if self.state != ChangeRequestState::Open || state == ChangeRequestState::Open {
            return Err(invalid("state", "change-request transition is not allowed"));
        }
        let mut next = self.clone();
        next.state = state;
        Ok(next)
    }
}

/// Advisory review verdict stored in the append-only timeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewVerdict {
    /// The reviewer approves the exact current revision.
    Approve,
    /// The reviewer requests changes to the exact current revision.
    RequestChanges,
}

/// One append-only change-request collaboration event kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TimelineEventKind {
    /// A discussion comment.
    Comment {
        /// Digest of the non-empty comment body.
        body_digest: ContentDigest,
    },
    /// A review bound to an exact change-request revision.
    Review {
        /// Review verdict.
        verdict: ReviewVerdict,
        /// Reviewed change-request content digest.
        revision_digest: ContentDigest,
        /// Optional review-note digest.
        body_digest: Option<ContentDigest>,
    },
    /// A reviewed close operation.
    Closed,
    /// A reviewed reopen operation.
    Reopened,
    /// A reviewed publication operation completed.
    Applied {
        /// Exact resulting registry publication identity.
        publication_id: StableId,
    },
}

/// One append-only, actor-attributed timeline event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TimelineEvent {
    /// Globally stable event identity.
    pub event_id: StableId,
    /// Change-request stable identity.
    pub change_request_id: StableId,
    /// Strictly increasing sequence within the change request.
    pub sequence: u64,
    /// Complete responsible actor.
    pub actor: Actor,
    /// Exact typed principal when the event exercises principal authority.
    pub principal: Option<PrincipalRef>,
    /// Event-specific immutable contents.
    pub kind: TimelineEventKind,
    /// Unix occurrence timestamp.
    pub occurred_at: i64,
}

/// The compare-and-swap pointer for an append-only timeline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TimelineHead {
    /// Change-request stable identity.
    change_request_id: StableId,
    /// Last committed sequence, or zero for an empty timeline.
    last_sequence: u64,
    /// Optimistic concurrency version.
    resource_version: ResourceVersion,
    /// Hash-chain commitment through the exact last timeline event.
    event_chain_digest: ContentDigest,
}

impl TimelineHead {
    /// Creates the authoritative empty head for one change-request timeline.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] unless the identity is a change request.
    pub fn initial(change_request_id: StableId) -> Result<Self, ControlError> {
        if change_request_id.kind() != "change-request" {
            return Err(invalid(
                "change_request_id",
                "timeline heads require a change-request identity",
            ));
        }
        Ok(Self {
            event_chain_digest: ContentDigest::of_value(&(
                "aos-hub-change-request-timeline-v1",
                &change_request_id,
            ))?,
            change_request_id,
            last_sequence: 0,
            resource_version: ResourceVersion::new(1)?,
        })
    }

    /// Returns the last committed timeline sequence.
    #[must_use]
    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    /// Returns the current compare-and-swap resource version.
    #[must_use]
    pub fn resource_version(&self) -> ResourceVersion {
        self.resource_version
    }

    /// Returns the hash-chain commitment through the last event.
    #[must_use]
    pub fn event_chain_digest(&self) -> &ContentDigest {
        &self.event_chain_digest
    }

    /// Advances a timeline with exactly its next event under CAS.
    ///
    /// # Errors
    ///
    /// Returns an identity, stale-version, sequence, or overflow error.
    pub fn append(
        &self,
        expected_version: ResourceVersion,
        event: &TimelineEvent,
    ) -> Result<Self, ControlError> {
        if self.change_request_id.kind() != "change-request"
            || event.change_request_id.kind() != "change-request"
            || event.event_id.kind() != "event"
            || matches!(
                &event.kind,
                TimelineEventKind::Applied { publication_id }
                    if publication_id.kind() != "publication"
            )
        {
            return Err(invalid(
                "timeline_identity",
                "timeline, event, and publication identities must be typed",
            ));
        }
        if let Some(principal) = &event.principal {
            principal.validate()?;
            let compatible = matches!(
                (event.actor.kind(), principal.kind()),
                (ActorKind::User, PrincipalKind::User)
                    | (ActorKind::ServiceAccount, PrincipalKind::ServiceAccount)
            );
            if !compatible {
                return Err(invalid(
                    "timeline_principal",
                    "event actor and authority principal kinds must agree",
                ));
            }
        }
        if self.resource_version != expected_version {
            return Err(ControlError::StaleVersion {
                expected: expected_version.get(),
                current: self.resource_version.get(),
            });
        }
        if self.change_request_id != event.change_request_id {
            return Err(ControlError::IdentityMismatch {
                expected: self.change_request_id.to_string(),
                received: event.change_request_id.to_string(),
            });
        }
        let next_sequence = self
            .last_sequence
            .checked_add(1)
            .ok_or(ControlError::CounterOverflow("timeline sequence"))?;
        if event.sequence != next_sequence {
            return Err(ControlError::NonContiguousGeneration {
                expected: next_sequence,
                received: event.sequence,
            });
        }
        Ok(Self {
            change_request_id: self.change_request_id.clone(),
            last_sequence: next_sequence,
            resource_version: self.resource_version.next()?,
            event_chain_digest: ContentDigest::of_value(&(&self.event_chain_digest, event))?,
        })
    }
}

/// Exact registry-publication facts sealed before applying a change request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChangeRequestApplyGate {
    /// Exact change-request revision head.
    change_request_head: HeadSeal,
    /// Expected current registry publication identity.
    base_publication_id: StableId,
    /// Digest of the expected current registry publication.
    base_publication_digest: ContentDigest,
    /// Signed candidate commit to publish.
    candidate_commit: GitObjectId,
    /// Parent of the signed candidate commit.
    candidate_parent: GitObjectId,
    /// Tree of the signed candidate commit.
    candidate_tree: GitObjectId,
    /// Canonical raw reviewed draft commit with recomputed identity/tree/parent.
    draft_commit_proof: GitObjectProof,
    /// Canonical raw candidate commit with a recomputed object identity.
    candidate_commit_proof: GitObjectProof,
    /// Exact annotated tag object identity expected from publication.
    candidate_tag_object: GitObjectId,
    /// Canonical raw annotated tag carrying the exact AOS signature claims.
    candidate_tag_proof: GitObjectProof,
    /// Cryptographic proof binding a trusted roster key to the exact candidate.
    candidate_signature: VerifiedCandidateSignature,
    /// Complete trusted roster entries for this registry, strictly key-sorted.
    trusted_signers: Vec<TrustedSignerEntry>,
    /// Authoritative current head of the registry's trusted signer roster.
    trust_roster_head: HeadSeal,
    /// Review-policy facts bound to the exact proposal revision.
    review_policy: ReviewPolicyGate,
    /// Complete authoritative publication-target snapshot, strictly id sorted.
    publication_targets: Vec<PublicationTargetSnapshotEntry>,
    /// Authoritative current head of the complete publication-target index.
    publication_target_index_head: HeadSeal,
}

/// One exact target required for change-request publication.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicationTargetSnapshotEntry {
    /// Stable publication-target identity.
    pub target_id: StableId,
    /// Exact current target revision.
    pub target_head: HeadSeal,
}

/// One exact trusted signer generation in a registry roster snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TrustedSignerEntry {
    /// Trusted signing-key identity.
    pub signer_key_id: StableId,
    /// Exact trusted immutable generation.
    pub signing_key_generation: Generation,
    /// Fingerprint of the exact trusted parsed public key.
    pub public_key_fingerprint: ContentDigest,
}

/// Cryptographic evidence for the exact candidate commit and apply-plan claims.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VerifiedCandidateSignature {
    /// Stable trusted roster-key identity.
    pub signer_key_id: StableId,
    /// Exact immutable signer generation.
    pub signing_key_generation: Generation,
    /// Canonical unpadded standard-base64 Ed25519 public key.
    pub public_key: String,
    /// Digest of the exact parsed public key.
    pub public_key_fingerprint: ContentDigest,
    /// Canonical unpadded standard-base64 Ed25519 signature.
    pub signature: String,
    /// Digest of the exact signature bytes.
    pub signature_digest: ContentDigest,
    /// Digest of the canonical apply claim recovered from the signed payload.
    pub signed_claim_digest: ContentDigest,
    /// Digest of trust-roster resolution and verifier evidence.
    pub verification_evidence_digest: ContentDigest,
}

impl VerifiedCandidateSignature {
    fn verify(&self, expected_claim: &ContentDigest) -> Result<(), ControlError> {
        if self.signer_key_id.kind() != "signing-key"
            || self.public_key.len() != 43
            || self.signature.len() != 86
            || &self.signed_claim_digest != expected_claim
        {
            return Err(invalid(
                "candidate_signature",
                "must name a typed key and the exact canonical candidate claim",
            ));
        }
        let public_key = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(&self.public_key)
            .map_err(|_| invalid("public_key", "must be canonical unpadded base64"))?;
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| invalid("public_key", "Ed25519 public keys must contain 32 bytes"))?;
        if base64::engine::general_purpose::STANDARD_NO_PAD.encode(public_key) != self.public_key
            || ContentDigest::of_bytes(public_key) != self.public_key_fingerprint
        {
            return Err(ControlError::DigestMismatch);
        }
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| invalid("public_key", "must encode a valid Ed25519 key"))?;
        let signature = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(&self.signature)
            .map_err(|_| invalid("signature", "must be canonical unpadded base64"))?;
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| invalid("signature", "Ed25519 signatures must contain 64 bytes"))?;
        if base64::engine::general_purpose::STANDARD_NO_PAD.encode(signature) != self.signature
            || ContentDigest::of_bytes(signature) != self.signature_digest
        {
            return Err(ControlError::DigestMismatch);
        }
        let mut message = b"aos-hub-change-request-apply-v1\0".to_vec();
        message.extend_from_slice(expected_claim.as_str().as_bytes());
        verifying_key
            .verify_strict(&message, &Signature::from_bytes(&signature))
            .map_err(|_| invalid("signature", "does not verify the exact candidate claim"))
    }
}

/// Review-policy snapshot sealed for a change-request apply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReviewPolicyGate {
    /// Exact reviewed proposal content digest.
    revision_digest: ContentDigest,
    /// Exact authoritative review-policy contents.
    policy: ReviewPolicyContents,
    /// Authoritative current head of the registry review policy.
    policy_head: HeadSeal,
    /// Strictly sorted stable identities of approving principals.
    approving_principals: Vec<StableId>,
    /// Strictly sorted stable identities of principals requesting changes.
    blocking_principals: Vec<StableId>,
    /// Digest of the complete review-event snapshot.
    review_snapshot_digest: ContentDigest,
    /// Complete effective review contents, strictly principal-id sorted.
    review_events: Vec<ReviewSnapshotEntry>,
    /// Authoritative exact current head of the effective-review index.
    review_index_head: HeadSeal,
    /// Exact authoritative append-only timeline head read for this review snapshot.
    timeline_head: TimelineHead,
    /// Exact timeline hash-chain commitment resolved with the effective-review index.
    timeline_event_chain_digest: ContentDigest,
    /// Complete current registry-membership snapshot for reviewer authority.
    reviewer_membership_snapshot: Vec<MembershipSnapshotEntry>,
    /// Authoritative current head of the registry membership index.
    reviewer_membership_index_head: HeadSeal,
}

/// Exact effective review contents for one principal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReviewSnapshotEntry {
    /// Stable timeline event identity.
    pub event_id: StableId,
    /// Timeline sequence at which this verdict was recorded.
    pub sequence: u64,
    /// Exact stable reviewer principal.
    pub principal: PrincipalRef,
    /// Effective verdict.
    pub verdict: ReviewVerdict,
    /// Exact proposal revision reviewed.
    pub revision_digest: ContentDigest,
    /// Optional bounded-note digest.
    pub body_digest: Option<ContentDigest>,
    /// Unix occurrence timestamp.
    pub occurred_at: i64,
    /// Exact append-only timeline event from which this effective review derives.
    pub timeline_event: TimelineEvent,
}

/// Immutable authoritative review policy for one registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReviewPolicyContents {
    /// Registry governed by this policy.
    pub registry_id: StableId,
    /// Non-zero minimum number of distinct effective approvals.
    pub required_approvals: u32,
    /// Minimum registry role allowed to approve.
    pub minimum_approver_role: Role,
}

impl ReviewPolicyGate {
    /// Validates approvals for one exact proposal revision.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] for unordered/duplicate reviewers, a
    /// blocking review, or fewer distinct approvals than policy requires.
    pub fn validate(
        &self,
        registry_id: &StableId,
        change_request_id: &StableId,
    ) -> Result<(), ControlError> {
        if self.policy.registry_id != *registry_id
            || self.policy.required_approvals == 0
            || self.policy.required_approvals > 256
            || self.policy.minimum_approver_role < Role::Developer
            || self.policy_head.stable_id != review_policy_id(registry_id)?
            || self.policy_head.content_digest != ContentDigest::of_value(&self.policy)?
        {
            return Err(invalid(
                "review_policy",
                "must bind a non-zero authoritative registry review policy",
            ));
        }
        if self.policy.required_approvals > 256
            || self.approving_principals.len() > 256
            || self.blocking_principals.len() > 256
        {
            return Err(invalid(
                "reviews",
                "review snapshots must not exceed 256 actors",
            ));
        }
        if self
            .approving_principals
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
            || self
                .blocking_principals
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid(
                "reviews",
                "reviewer identities must be strictly ordered and duplicate-free",
            ));
        }
        if !self.blocking_principals.is_empty() {
            return Err(invalid(
                "reviews",
                "a request-changes review is still active",
            ));
        }
        if self.approving_principals.len() < self.policy.required_approvals as usize {
            return Err(invalid("reviews", "required approvals are not satisfied"));
        }
        if self.review_events.len() > 256
            || self.reviewer_membership_snapshot.len() > 4_096
            || self
                .review_events
                .windows(2)
                .any(|pair| pair[0].principal.stable_id() >= pair[1].principal.stable_id())
            || self
                .reviewer_membership_snapshot
                .windows(2)
                .any(|pair| pair[0].membership_id >= pair[1].membership_id)
        {
            return Err(invalid(
                "reviews",
                "review and membership snapshots must be bounded and strictly ordered",
            ));
        }
        let mut event_ids = BTreeSet::new();
        let mut sequences = BTreeSet::new();
        let mut derived_approvals = Vec::new();
        let mut derived_blocks = Vec::new();
        for review in &self.review_events {
            review.principal.validate()?;
            let expected_kind = TimelineEventKind::Review {
                verdict: review.verdict,
                revision_digest: review.revision_digest.clone(),
                body_digest: review.body_digest.clone(),
            };
            if review.event_id.kind() != "event"
                || review.sequence == 0
                || !event_ids.insert(review.event_id.clone())
                || !sequences.insert(review.sequence)
                || review.revision_digest != self.revision_digest
                || review.timeline_event.event_id != review.event_id
                || review.timeline_event.change_request_id != *change_request_id
                || review.timeline_event.sequence != review.sequence
                || review.timeline_event.principal.as_ref() != Some(&review.principal)
                || !matches!(
                    (review.timeline_event.actor.kind(), review.principal.kind()),
                    (ActorKind::User, PrincipalKind::User)
                        | (ActorKind::ServiceAccount, PrincipalKind::ServiceAccount)
                )
                || review.timeline_event.kind != expected_kind
                || review.timeline_event.occurred_at != review.occurred_at
            {
                return Err(invalid(
                    "review_events",
                    "every review must be unique and target the exact proposal revision",
                ));
            }
            let authorized = self.reviewer_membership_snapshot.iter().any(|membership| {
                membership.contents.principal == review.principal
                    && membership.contents.scope == *registry_id
                    && membership.contents.state == MembershipState::Active
                    && membership.contents.role >= self.policy.minimum_approver_role
            });
            if !authorized {
                return Err(invalid(
                    "reviewer_authority",
                    "every effective reviewer requires an exact active registry grant",
                ));
            }
            match review.verdict {
                ReviewVerdict::Approve => {
                    derived_approvals.push(review.principal.stable_id().clone())
                }
                ReviewVerdict::RequestChanges => {
                    derived_blocks.push(review.principal.stable_id().clone())
                }
            }
        }
        for membership in &self.reviewer_membership_snapshot {
            membership.validate()?;
            if membership.contents.scope != *registry_id {
                return Err(invalid(
                    "reviewer_membership_snapshot",
                    "snapshot may contain only the exact registry scope",
                ));
            }
        }
        if derived_approvals != self.approving_principals
            || derived_blocks != self.blocking_principals
            || ContentDigest::of_value(&self.review_events)? != self.review_snapshot_digest
            || self.review_index_head.stable_id != review_index_id(change_request_id)?
            || self.review_index_head.content_digest
                != ContentDigest::of_value(&(&self.review_events, &self.timeline_head))?
            || ContentDigest::of_value(&self.reviewer_membership_snapshot)?
                != self.reviewer_membership_index_head.content_digest
            || self.reviewer_membership_index_head.stable_id != membership_index_id(registry_id)?
            || self.timeline_head.change_request_id != *change_request_id
            || self.timeline_event_chain_digest != self.timeline_head.event_chain_digest
            || self
                .review_events
                .iter()
                .map(|review| review.sequence)
                .max()
                .is_some_and(|sequence| sequence > self.timeline_head.last_sequence)
        {
            return Err(ControlError::DigestMismatch);
        }
        Ok(())
    }
}

impl ChangeRequestApplyGate {
    /// Validates that an apply gate targets the exact open proposal.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] when the proposal is not open or the
    /// signed candidate differs from its immutable draft commit.
    pub fn validate(&self, proposal: &ChangeRequestRevisionContents) -> Result<(), ControlError> {
        proposal.validate_new()?;
        if proposal.state != ChangeRequestState::Open {
            return Err(invalid("state", "only an open change request may apply"));
        }
        if self.change_request_head.stable_id.kind() != "change-request"
            || self.base_publication_id.kind() != "publication"
        {
            return Err(invalid(
                "apply_identity",
                "apply head and base publication must use typed stable identities",
            ));
        }
        if self.change_request_head.content_digest != ContentDigest::of_value(proposal)? {
            return Err(invalid(
                "change_request_head",
                "must seal the exact reviewed proposal revision",
            ));
        }
        if self.review_policy.revision_digest != self.change_request_head.content_digest {
            return Err(invalid(
                "reviews",
                "review approvals target another proposal revision",
            ));
        }
        self.review_policy
            .validate(&proposal.registry_id, &self.change_request_head.stable_id)?;
        if self.publication_targets.is_empty()
            || self.publication_targets.len() > 256
            || self
                .publication_targets
                .windows(2)
                .any(|pair| pair[0].target_id >= pair[1].target_id)
            || self.publication_targets.iter().any(|target| {
                target.target_id.kind() != "publication-target"
                    || target.target_head.stable_id != target.target_id
            })
            || self.publication_target_index_head.stable_id
                != publication_target_index_id(&proposal.registry_id)?
            || self.publication_target_index_head.content_digest
                != ContentDigest::of_value(&self.publication_targets)?
        {
            return Err(invalid(
                "publication_targets",
                "must bind the exact non-empty authoritative publication-target index",
            ));
        }
        if self.trusted_signers.is_empty()
            || self.trusted_signers.len() > 256
            || self
                .trusted_signers
                .windows(2)
                .any(|pair| pair[0].signer_key_id >= pair[1].signer_key_id)
            || self
                .trusted_signers
                .iter()
                .any(|entry| entry.signer_key_id.kind() != "signing-key")
        {
            return Err(invalid(
                "trusted_signers",
                "must be a non-empty bounded canonical signing-key roster",
            ));
        }
        let roster_id = StableId::new(format!(
            "signing-roster:{}",
            ContentDigest::of_value(&proposal.registry_id)?.as_str()
        ))?;
        if self.trust_roster_head.stable_id != roster_id
            || self.trust_roster_head.content_digest
                != ContentDigest::of_value(&self.trusted_signers)?
            || !self.trusted_signers.iter().any(|entry| {
                entry.signer_key_id == self.candidate_signature.signer_key_id
                    && entry.signing_key_generation
                        == self.candidate_signature.signing_key_generation
                    && entry.public_key_fingerprint
                        == self.candidate_signature.public_key_fingerprint
            })
        {
            return Err(invalid(
                "trust_roster_head",
                "must bind the exact candidate signer to the current registry roster",
            ));
        }
        if self.candidate_parent != proposal.base_commit {
            return Err(invalid(
                "candidate_parent",
                "must equal the exact reviewed registry base commit",
            ));
        }
        if self.candidate_tree != proposal.draft_tree {
            return Err(invalid(
                "candidate_tree",
                "must equal the exact reviewed draft tree",
            ));
        }
        let algorithm = proposal.base_commit.algorithm();
        if algorithm.is_empty()
            || [
                &proposal.draft_commit,
                &proposal.draft_tree,
                &self.candidate_commit,
                &self.candidate_parent,
                &self.candidate_tree,
                &self.draft_commit_proof.object_id,
                &self.candidate_commit_proof.object_id,
                &self.candidate_tag_object,
                &self.candidate_tag_proof.object_id,
            ]
            .iter()
            .any(|object| object.algorithm() != algorithm)
        {
            return Err(invalid(
                "git_object_format",
                "all reviewed, candidate, and tag identities must use one repository hash format",
            ));
        }
        self.draft_commit_proof.verify()?;
        if self.draft_commit_proof.object_id != proposal.draft_commit {
            return Err(ControlError::DigestMismatch);
        }
        let (draft_tree, draft_parent) = parse_commit_links(&self.draft_commit_proof)?;
        if draft_tree != proposal.draft_tree || draft_parent != proposal.base_commit {
            return Err(invalid(
                "draft_commit_proof",
                "raw reviewed draft must contain the exact reviewed tree and base parent",
            ));
        }
        self.candidate_commit_proof.verify()?;
        if self.candidate_commit_proof.object_id != self.candidate_commit {
            return Err(ControlError::DigestMismatch);
        }
        let (raw_tree, raw_parent) = parse_commit_links(&self.candidate_commit_proof)?;
        if raw_tree != self.candidate_tree || raw_parent != self.candidate_parent {
            return Err(invalid(
                "candidate_commit_proof",
                "raw commit tree and parent must equal the reviewed claims",
            ));
        }
        let expected_claim = self.expected_claim_digest(proposal)?;
        self.candidate_signature.verify(&expected_claim)?;
        self.candidate_tag_proof.verify()?;
        if self.candidate_tag_proof.object_id != self.candidate_tag_object {
            return Err(ControlError::DigestMismatch);
        }
        let tag = parse_verified_git_tag(&self.candidate_tag_proof)?;
        if tag.tag_name != "aos-change-request"
            || tag.target != self.candidate_commit
            || tag.signer_key_id != self.candidate_signature.signer_key_id
            || tag.signing_key_generation != self.candidate_signature.signing_key_generation
            || tag.signed_claim_digest != expected_claim
            || tag.signature != self.candidate_signature.signature
        {
            return Err(invalid(
                "candidate_tag_proof",
                "raw tag target and embedded signature must equal the exact apply claims",
            ));
        }
        Ok(())
    }

    fn expected_claim_digest(
        &self,
        proposal: &ChangeRequestRevisionContents,
    ) -> Result<ContentDigest, ControlError> {
        ContentDigest::of_value(&(
            (
                &proposal.registry_id,
                &self.change_request_head,
                &self.base_publication_id,
                &self.base_publication_digest,
                &self.candidate_commit,
                &self.candidate_parent,
                &self.candidate_tree,
                &proposal.draft_commit,
                &proposal.draft_tree,
                &proposal.file_manifest_digest,
                &self.review_policy,
                &self.publication_targets,
                &self.publication_target_index_head,
            ),
            (&self.trusted_signers, &self.trust_roster_head),
            (
                &self.candidate_signature.signer_key_id,
                self.candidate_signature.signing_key_generation,
                &self.candidate_signature.public_key_fingerprint,
                &self.candidate_signature.verification_evidence_digest,
            ),
        ))
    }
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn review_index_id(change_request_id: &StableId) -> Result<StableId, ControlError> {
    StableId::new(format!(
        "review-index:{}",
        ContentDigest::of_value(change_request_id)?.as_str()
    ))
}

fn review_policy_id(registry_id: &StableId) -> Result<StableId, ControlError> {
    StableId::new(format!(
        "review-policy:{}",
        ContentDigest::of_value(registry_id)?.as_str()
    ))
}

fn publication_target_index_id(registry_id: &StableId) -> Result<StableId, ControlError> {
    StableId::new(format!(
        "publication-target-index:{}",
        ContentDigest::of_value(registry_id)?.as_str()
    ))
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn sha1_digest(input: &[u8]) -> [u8; 20] {
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    let mut state = [
        0x6745_2301_u32,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    for chunk in padded.chunks_exact(64) {
        let mut words = [0_u32; 80];
        for (index, word) in chunk.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for index in 16..80 {
            words[index] =
                (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                    .rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = state;
        for (index, word) in words.iter().enumerate() {
            let (function, constant) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let next = a
                .rotate_left(5)
                .wrapping_add(function)
                .wrapping_add(e)
                .wrapping_add(constant)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e]) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut digest = [0_u8; 20];
    for (chunk, value) in digest.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    digest
}

fn invalid(field: &'static str, reason: &str) -> ControlError {
    ControlError::Invalid {
        field,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Signer as _;

    use super::*;
    use crate::retained_control::iam::{MembershipContents, PrincipalKind};
    use crate::retained_control::primitives::ActorKind;

    fn oid(byte: char) -> GitObjectId {
        GitObjectId::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn commit_proof(parent: &GitObjectId, tree: &GitObjectId) -> GitObjectProof {
        let raw = format!(
            "tree {}\nparent {}\nauthor AOS <aos@example.test> 1 +0000\ncommitter AOS <aos@example.test> 1 +0000\n\nreviewed candidate\n",
            tree.as_str().split_once(':').unwrap().1,
            parent.as_str().split_once(':').unwrap().1,
        );
        GitObjectProof::from_raw("sha256", GitObjectKind::Commit, raw.as_bytes()).unwrap()
    }

    fn tag_proof(target: &GitObjectId, claim: &ContentDigest, signature: &str) -> GitObjectProof {
        let raw = format!(
            "object {}\ntype commit\ntag aos-change-request\ntagger AOS <aos@example.test> 1 +0000\n\naos-signer-key signing-key:roster\naos-signing-generation 4\naos-signed-claim {}\naos-signature {}\n",
            target.as_str().split_once(':').unwrap().1,
            claim.as_str(),
            signature,
        );
        GitObjectProof::from_raw("sha256", GitObjectKind::Tag, raw.as_bytes()).unwrap()
    }

    #[test]
    fn git_object_ids_revalidate_during_deserialization() {
        assert!(serde_json::from_str::<GitObjectId>(
            r#""sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA""#
        )
        .is_err());
        assert!(serde_json::from_str::<GitObjectId>(r#""sha1:abc""#).is_err());
    }

    #[test]
    fn git_proofs_use_exact_git_hashing_and_reject_duplicate_tag_claims() {
        assert_eq!(
            hex_bytes(&sha1_digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        let target = oid('a');
        let claim = ContentDigest::of_bytes("claim");
        let signature = base64::engine::general_purpose::STANDARD_NO_PAD.encode([7_u8; 64]);
        let raw = format!(
            "object {}\ntype commit\ntag duplicate\ntagger AOS <aos@example.test> 1 +0000\n\naos-signer-key signing-key:roster\naos-signer-key signing-key:other\naos-signing-generation 4\naos-signed-claim {}\naos-signature {}\n",
            target.as_str().split_once(':').unwrap().1,
            claim.as_str(),
            signature,
        );
        let proof = GitObjectProof::from_raw("sha256", GitObjectKind::Tag, raw.as_bytes()).unwrap();
        assert!(parse_verified_git_tag(&proof).is_err());
    }

    #[test]
    fn applied_change_request_is_terminal() {
        let proposal = ChangeRequestRevisionContents {
            registry_id: StableId::new("registry:main").unwrap(),
            title: "Update cache policy".into(),
            body: None,
            base_commit: oid('a'),
            draft_commit: oid('b'),
            draft_tree: oid('c'),
            file_manifest_digest: ContentDigest::of_bytes("files"),
            state: ChangeRequestState::Open,
        };
        proposal.validate_new().unwrap();
        let applied = proposal.applied().unwrap();
        assert!(applied.reopen().is_err());
    }

    #[test]
    fn timeline_requires_exact_next_sequence_and_actor() {
        let change_request_id = StableId::new("change-request:one").unwrap();
        let head = TimelineHead::initial(change_request_id.clone()).unwrap();
        let event = TimelineEvent {
            event_id: StableId::new("event:one").unwrap(),
            change_request_id,
            sequence: 1,
            actor: Actor::new(ActorKind::User, Some(1), "reviewer@example.test").unwrap(),
            principal: None,
            kind: TimelineEventKind::Comment {
                body_digest: ContentDigest::of_bytes("looks good"),
            },
            occurred_at: 1,
        };
        assert_eq!(
            head.append(ResourceVersion::new(1).unwrap(), &event)
                .unwrap()
                .last_sequence,
            1
        );
    }

    #[test]
    fn roster_resigning_may_change_commit_but_not_reviewed_tree_or_parent() {
        let base_commit = oid('a');
        let draft_tree = oid('c');
        let draft_commit_proof = commit_proof(&base_commit, &draft_tree);
        let proposal = ChangeRequestRevisionContents {
            registry_id: StableId::new("registry:main").unwrap(),
            title: "Update cache policy".into(),
            body: None,
            base_commit,
            draft_commit: draft_commit_proof.object_id.clone(),
            draft_tree,
            file_manifest_digest: ContentDigest::of_bytes("files"),
            state: ChangeRequestState::Open,
        };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11_u8; 32]);
        let public_key_bytes = signing_key.verifying_key().to_bytes();
        let public_key_fingerprint = ContentDigest::of_bytes(public_key_bytes);
        let trusted_signers = vec![TrustedSignerEntry {
            signer_key_id: StableId::new("signing-key:roster").unwrap(),
            signing_key_generation: Generation::new(4).unwrap(),
            public_key_fingerprint: public_key_fingerprint.clone(),
        }];
        let roster_id = StableId::new(format!(
            "signing-roster:{}",
            ContentDigest::of_value(&proposal.registry_id)
                .unwrap()
                .as_str()
        ))
        .unwrap();
        let change_request_id = StableId::new("change-request:one").unwrap();
        let reviewer =
            PrincipalRef::new(PrincipalKind::User, StableId::new("user:reviewer").unwrap())
                .unwrap();
        let reviewer_membership = MembershipContents {
            principal: reviewer.clone(),
            scope: proposal.registry_id.clone(),
            role: Role::Developer,
            state: MembershipState::Active,
        };
        let membership_id = reviewer_membership.stable_id().unwrap();
        let reviewer_membership_snapshot = vec![MembershipSnapshotEntry {
            membership_id: membership_id.clone(),
            head: HeadSeal {
                stable_id: membership_id,
                generation: Generation::new(1).unwrap(),
                content_digest: ContentDigest::of_value(&reviewer_membership).unwrap(),
                resource_version: ResourceVersion::new(1).unwrap(),
            },
            contents: reviewer_membership,
        }];
        let reviewer_membership_digest =
            ContentDigest::of_value(&reviewer_membership_snapshot).unwrap();
        let review_timeline_event = TimelineEvent {
            event_id: StableId::new("event:review-one").unwrap(),
            change_request_id: change_request_id.clone(),
            sequence: 1,
            actor: Actor::new(ActorKind::User, Some(2), "reviewer@example.test").unwrap(),
            principal: Some(reviewer.clone()),
            kind: TimelineEventKind::Review {
                verdict: ReviewVerdict::Approve,
                revision_digest: ContentDigest::of_value(&proposal).unwrap(),
                body_digest: None,
            },
            occurred_at: 2,
        };
        let review_events = vec![ReviewSnapshotEntry {
            event_id: review_timeline_event.event_id.clone(),
            sequence: review_timeline_event.sequence,
            principal: reviewer,
            verdict: ReviewVerdict::Approve,
            revision_digest: ContentDigest::of_value(&proposal).unwrap(),
            body_digest: None,
            occurred_at: review_timeline_event.occurred_at,
            timeline_event: review_timeline_event,
        }];
        let timeline_head = TimelineHead::initial(change_request_id.clone())
            .unwrap()
            .append(
                ResourceVersion::new(1).unwrap(),
                &review_events[0].timeline_event,
            )
            .unwrap();
        let review_snapshot_digest = ContentDigest::of_value(&review_events).unwrap();
        let review_index_digest =
            ContentDigest::of_value(&(&review_events, &timeline_head)).unwrap();
        let candidate_commit_proof = commit_proof(&proposal.base_commit, &proposal.draft_tree);
        let candidate_commit = candidate_commit_proof.object_id.clone();
        let pending_tag_proof = tag_proof(
            &candidate_commit,
            &ContentDigest::of_bytes("pending"),
            &base64::engine::general_purpose::STANDARD_NO_PAD.encode([0_u8; 64]),
        );
        let review_policy = ReviewPolicyContents {
            registry_id: proposal.registry_id.clone(),
            required_approvals: 1,
            minimum_approver_role: Role::Developer,
        };
        let publication_targets = vec![PublicationTargetSnapshotEntry {
            target_id: StableId::new("publication-target:primary").unwrap(),
            target_head: HeadSeal {
                stable_id: StableId::new("publication-target:primary").unwrap(),
                generation: Generation::new(1).unwrap(),
                content_digest: ContentDigest::of_bytes("publication-target-primary"),
                resource_version: ResourceVersion::new(1).unwrap(),
            },
        }];
        let mut gate = ChangeRequestApplyGate {
            change_request_head: HeadSeal {
                stable_id: change_request_id.clone(),
                generation: crate::retained_control::primitives::Generation::new(1).unwrap(),
                content_digest: ContentDigest::of_value(&proposal).unwrap(),
                resource_version: ResourceVersion::new(1).unwrap(),
            },
            base_publication_id: StableId::new("publication:one").unwrap(),
            base_publication_digest: ContentDigest::of_bytes("publication"),
            candidate_commit: candidate_commit.clone(),
            candidate_parent: proposal.base_commit.clone(),
            candidate_tree: proposal.draft_tree.clone(),
            draft_commit_proof,
            candidate_commit_proof,
            candidate_tag_object: pending_tag_proof.object_id.clone(),
            candidate_tag_proof: pending_tag_proof,
            candidate_signature: VerifiedCandidateSignature {
                signer_key_id: StableId::new("signing-key:roster").unwrap(),
                signing_key_generation: Generation::new(4).unwrap(),
                public_key: base64::engine::general_purpose::STANDARD_NO_PAD
                    .encode(public_key_bytes),
                public_key_fingerprint,
                signature: base64::engine::general_purpose::STANDARD_NO_PAD.encode([0_u8; 64]),
                signature_digest: ContentDigest::of_bytes([0_u8; 64]),
                signed_claim_digest: ContentDigest::of_bytes("pending"),
                verification_evidence_digest: ContentDigest::of_bytes("trusted-roster"),
            },
            trust_roster_head: HeadSeal {
                stable_id: roster_id,
                generation: Generation::new(2).unwrap(),
                content_digest: ContentDigest::of_value(&trusted_signers).unwrap(),
                resource_version: ResourceVersion::new(3).unwrap(),
            },
            trusted_signers,
            review_policy: ReviewPolicyGate {
                revision_digest: ContentDigest::of_value(&proposal).unwrap(),
                policy_head: HeadSeal {
                    stable_id: review_policy_id(&proposal.registry_id).unwrap(),
                    generation: Generation::new(1).unwrap(),
                    content_digest: ContentDigest::of_value(&review_policy).unwrap(),
                    resource_version: ResourceVersion::new(1).unwrap(),
                },
                policy: review_policy,
                approving_principals: vec![StableId::new("user:reviewer").unwrap()],
                blocking_principals: Vec::new(),
                review_snapshot_digest: review_snapshot_digest.clone(),
                review_events,
                review_index_head: HeadSeal {
                    stable_id: review_index_id(&change_request_id).unwrap(),
                    generation: Generation::new(1).unwrap(),
                    content_digest: review_index_digest,
                    resource_version: ResourceVersion::new(1).unwrap(),
                },
                timeline_event_chain_digest: timeline_head.event_chain_digest.clone(),
                timeline_head,
                reviewer_membership_snapshot,
                reviewer_membership_index_head: HeadSeal {
                    stable_id: membership_index_id(&proposal.registry_id).unwrap(),
                    generation: Generation::new(1).unwrap(),
                    content_digest: reviewer_membership_digest,
                    resource_version: ResourceVersion::new(1).unwrap(),
                },
            },
            publication_target_index_head: HeadSeal {
                stable_id: publication_target_index_id(&proposal.registry_id).unwrap(),
                generation: Generation::new(1).unwrap(),
                content_digest: ContentDigest::of_value(&publication_targets).unwrap(),
                resource_version: ResourceVersion::new(1).unwrap(),
            },
            publication_targets,
        };
        let claim = gate.expected_claim_digest(&proposal).unwrap();
        let mut message = b"aos-hub-change-request-apply-v1\0".to_vec();
        message.extend_from_slice(claim.as_str().as_bytes());
        let signature_bytes = signing_key.sign(&message).to_bytes();
        gate.candidate_signature.signed_claim_digest = claim;
        gate.candidate_signature.signature =
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(signature_bytes);
        gate.candidate_signature.signature_digest = ContentDigest::of_bytes(signature_bytes);
        gate.candidate_tag_proof = tag_proof(
            &gate.candidate_commit,
            &gate.candidate_signature.signed_claim_digest,
            &gate.candidate_signature.signature,
        );
        gate.candidate_tag_object = gate.candidate_tag_proof.object_id.clone();
        gate.validate(&proposal).unwrap();

        let mut tampered_raw_commit = gate.clone();
        tampered_raw_commit.candidate_commit_proof.raw_base64 =
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(b"different commit");
        assert!(tampered_raw_commit.validate(&proposal).is_err());

        let mut unauthorized_review = gate.review_policy.clone();
        unauthorized_review.reviewer_membership_snapshot[0]
            .contents
            .role = Role::Viewer;
        let unauthorized_contents_digest =
            ContentDigest::of_value(&unauthorized_review.reviewer_membership_snapshot[0].contents)
                .unwrap();
        unauthorized_review.reviewer_membership_snapshot[0]
            .head
            .content_digest = unauthorized_contents_digest;
        unauthorized_review
            .reviewer_membership_index_head
            .content_digest =
            ContentDigest::of_value(&unauthorized_review.reviewer_membership_snapshot).unwrap();
        assert!(unauthorized_review
            .validate(&proposal.registry_id, &change_request_id)
            .is_err());

        let mut substituted_commit = gate.clone();
        substituted_commit.candidate_commit = oid('e');
        assert!(substituted_commit.validate(&proposal).is_err());

        let mut substituted_signer = gate.clone();
        substituted_signer.candidate_signature.signer_key_id =
            StableId::new("signing-key:other").unwrap();
        assert!(substituted_signer.validate(&proposal).is_err());

        let mut substituted_tag_object = gate.clone();
        substituted_tag_object.candidate_tag_object = oid('e');
        assert!(substituted_tag_object.validate(&proposal).is_err());

        let mut tampered_draft = gate.clone();
        tampered_draft.draft_commit_proof.raw_base64 =
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(b"different draft");
        assert!(tampered_draft.validate(&proposal).is_err());

        let mut zero_approval_policy = gate.clone();
        zero_approval_policy.review_policy.policy.required_approvals = 0;
        assert!(zero_approval_policy.validate(&proposal).is_err());

        let mut substituted_policy_head = gate.clone();
        substituted_policy_head
            .review_policy
            .policy_head
            .content_digest = ContentDigest::of_bytes("other-policy");
        assert!(substituted_policy_head.validate(&proposal).is_err());

        let mut tampered_timeline_event = gate.clone();
        tampered_timeline_event.review_policy.review_events[0]
            .timeline_event
            .occurred_at = 3;
        assert!(tampered_timeline_event.validate(&proposal).is_err());

        let mut mixed_object_format = gate.clone();
        mixed_object_format.candidate_tag_object =
            GitObjectId::new(format!("sha1:{}", "e".repeat(40))).unwrap();
        assert!(mixed_object_format.validate(&proposal).is_err());

        let mut substituted_plan = gate;
        substituted_plan
            .publication_target_index_head
            .content_digest = ContentDigest::of_bytes("other-targets");
        assert!(substituted_plan.validate(&proposal).is_err());

        let mut replayed_under_new_roster = substituted_plan;
        replayed_under_new_roster.trust_roster_head.resource_version =
            ResourceVersion::new(4).unwrap();
        assert!(replayed_under_new_roster.validate(&proposal).is_err());
    }
}
