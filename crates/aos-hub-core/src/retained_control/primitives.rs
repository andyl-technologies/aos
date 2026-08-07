//! Shared identity, revision, actor, and commit-intent primitives.

use std::fmt;
use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// A validation or concurrency failure in a retained control-plane contract.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ControlError {
    /// A caller supplied an invalid bounded identifier or field value.
    #[error("invalid {field}: {reason}")]
    Invalid {
        /// Name of the rejected field.
        field: &'static str,
        /// Stable explanation suitable for an API error.
        reason: String,
    },
    /// A compare-and-swap version no longer names the current head.
    #[error("stale resource version: expected {expected}, current {current}")]
    StaleVersion {
        /// Version sealed by the caller or plan.
        expected: u64,
        /// Current authoritative version.
        current: u64,
    },
    /// A revision does not immediately follow the current generation.
    #[error("non-contiguous generation: expected {expected}, received {received}")]
    NonContiguousGeneration {
        /// Required next generation.
        expected: u64,
        /// Supplied revision generation.
        received: u64,
    },
    /// A revision or plan targets another stable identity.
    #[error("stable identity mismatch: expected {expected}, received {received}")]
    IdentityMismatch {
        /// Current stable identity.
        expected: String,
        /// Supplied stable identity.
        received: String,
    },
    /// A canonical digest does not match the supplied contents.
    #[error("content digest mismatch")]
    DigestMismatch,
    /// A monotonically increasing counter overflowed.
    #[error("{0} overflowed")]
    CounterOverflow(&'static str),
    /// Canonical JSON serialization failed.
    #[error("canonical serialization failed: {0}")]
    Serialization(String),
}

/// A bounded, canonical route-safe identity that remains stable across renames and moves.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct StableId(String);

impl StableId {
    /// Validates and constructs a stable identity.
    ///
    /// Stable identities use `kind:opaque-id`: one lowercase kind, one colon,
    /// and one lowercase opaque component. Components start and end with an
    /// ASCII letter or digit. The kind may contain single hyphens; the opaque
    /// component may contain single hyphens or underscores. Human-readable
    /// hierarchy and slugs are intentionally not encoded in this identity.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] when `value` is empty, too long,
    /// hierarchical, percent-encoded, non-lowercase, or has ambiguous
    /// separators.
    pub fn new(value: impl Into<String>) -> Result<Self, ControlError> {
        let value = value.into();
        let components = value.split(':').collect::<Vec<_>>();
        let valid = value.len() <= 255
            && components.len() == 2
            && valid_stable_id_component(components[0], false, true, 63)
            && valid_stable_id_component(components[1], true, false, 191);
        if !valid {
            return Err(ControlError::Invalid {
                field: "stable_id",
                reason: "must use canonical route-safe kind:opaque-id syntax".into(),
            });
        }
        Ok(Self(value))
    }

    /// Returns the canonical identity string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the resource-kind component before the colon.
    #[must_use]
    pub fn kind(&self) -> &str {
        self.0.split_once(':').map_or("", |(kind, _)| kind)
    }

    /// Returns the opaque identity component after the colon.
    #[must_use]
    pub fn opaque(&self) -> &str {
        self.0.split_once(':').map_or("", |(_, opaque)| opaque)
    }
}

impl<'de> Deserialize<'de> for StableId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for StableId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn valid_stable_id_component(
    value: &str,
    allow_underscore: bool,
    must_start_with_letter: bool,
    max_len: usize,
) -> bool {
    if value.is_empty() || value.len() > max_len {
        return false;
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_lowercase() && (must_start_with_letter || !bytes[0].is_ascii_digit()) {
        return false;
    }
    if !bytes[bytes.len() - 1].is_ascii_lowercase() && !bytes[bytes.len() - 1].is_ascii_digit() {
        return false;
    }
    let mut previous_was_separator = false;
    for byte in bytes {
        let is_separator = *byte == b'-' || (allow_underscore && *byte == b'_');
        if !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && !is_separator {
            return false;
        }
        if is_separator && previous_was_separator {
            return false;
        }
        previous_was_separator = is_separator;
    }
    true
}

/// A positive optimistic-concurrency version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ResourceVersion(NonZeroU64);

impl ResourceVersion {
    /// Constructs a positive resource version.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] when `value` is zero.
    pub fn new(value: u64) -> Result<Self, ControlError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| ControlError::Invalid {
                field: "resource_version",
                reason: "must be positive".into(),
            })
    }

    /// Returns the numeric representation used only by persistence adapters.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next resource version.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::CounterOverflow`] at `u64::MAX`.
    pub fn next(self) -> Result<Self, ControlError> {
        self.get()
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .map(Self)
            .ok_or(ControlError::CounterOverflow("resource version"))
    }
}

/// A positive immutable revision or key generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Generation(NonZeroU64);

impl Generation {
    /// Constructs a positive generation.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] when `value` is zero.
    pub fn new(value: u64) -> Result<Self, ControlError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| ControlError::Invalid {
                field: "generation",
                reason: "must be positive".into(),
            })
    }

    /// Returns the numeric generation.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next immutable generation.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::CounterOverflow`] at `u64::MAX`.
    pub fn next(self) -> Result<Self, ControlError> {
        self.get()
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .map(Self)
            .ok_or(ControlError::CounterOverflow("generation"))
    }
}

/// A lowercase SHA-256 digest of canonical bytes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ContentDigest(String);

impl ContentDigest {
    /// Validates a lowercase hexadecimal SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] unless `value` is exactly 64 lowercase
    /// hexadecimal characters.
    pub fn new(value: impl Into<String>) -> Result<Self, ControlError> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ControlError::Invalid {
                field: "content_digest",
                reason: "must be lowercase SHA-256 hex".into(),
            });
        }
        Ok(Self(value))
    }

    /// Hashes exact bytes with SHA-256.
    #[must_use]
    pub fn of_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(hex::encode(Sha256::digest(bytes.as_ref())))
    }

    /// Hashes the canonical JSON representation of a serializable value.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Serialization`] when the value cannot be
    /// represented as canonical integer-only JSON.
    pub fn of_value<T: Serialize>(value: &T) -> Result<Self, ControlError> {
        Ok(Self::of_bytes(canonical_json(value)?))
    }

    /// Returns the lowercase hexadecimal digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ContentDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// The authenticated kind of an actor responsible for a mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    /// A human user.
    User,
    /// An organization-owned automation principal.
    ServiceAccount,
    /// A cryptographic key principal without a database row id.
    Key,
    /// An internal controller or bootstrap process.
    System,
}

/// Complete actor attribution carried into audit and outbox records.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Actor {
    /// Authenticated actor kind.
    kind: ActorKind,
    /// Stable database principal id for users and service accounts.
    principal_id: Option<u64>,
    /// Human-readable immutable label captured at mutation time.
    label: String,
}

impl<'de> Deserialize<'de> for Actor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ActorWire {
            kind: ActorKind,
            principal_id: Option<u64>,
            label: String,
        }

        let wire = ActorWire::deserialize(deserializer)?;
        Self::new(wire.kind, wire.principal_id, wire.label).map_err(serde::de::Error::custom)
    }
}

impl Actor {
    /// Validates complete actor attribution.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] for a missing/oversized label or an id
    /// whose presence does not match the actor kind.
    pub fn new(
        kind: ActorKind,
        principal_id: Option<u64>,
        label: impl Into<String>,
    ) -> Result<Self, ControlError> {
        let label = label.into();
        if label.trim().is_empty() || label.trim() != label || label.len() > 255 {
            return Err(ControlError::Invalid {
                field: "actor_label",
                reason: "must contain 1-255 non-whitespace bytes".into(),
            });
        }
        let id_is_valid = match kind {
            ActorKind::User | ActorKind::ServiceAccount => principal_id.is_some_and(|id| id > 0),
            ActorKind::Key | ActorKind::System => principal_id.is_none(),
        };
        if !id_is_valid {
            return Err(ControlError::Invalid {
                field: "actor_id",
                reason: "presence must match actor kind".into(),
            });
        }
        Ok(Self {
            kind,
            principal_id,
            label,
        })
    }

    /// Returns a stable digest suitable for sealing the exact actor into a plan.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Serialization`] if canonical serialization fails.
    pub fn fingerprint(&self) -> Result<ContentDigest, ControlError> {
        ContentDigest::of_value(self)
    }

    /// Returns the authenticated actor kind.
    #[must_use]
    pub fn kind(&self) -> ActorKind {
        self.kind
    }

    /// Returns the stable database principal id when the actor kind has one.
    #[must_use]
    pub fn principal_id(&self) -> Option<u64> {
        self.principal_id
    }

    /// Returns the immutable audit label captured at mutation time.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// An immutable content-addressed resource revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Revision<T> {
    /// Stable identity shared by every revision in the lineage.
    pub stable_id: StableId,
    /// Strictly increasing immutable generation.
    pub generation: Generation,
    /// Digest of `contents` in canonical JSON.
    pub content_digest: ContentDigest,
    /// Actor that authored the revision.
    pub authored_by: Actor,
    /// Unix timestamp at which the revision was authored.
    pub authored_at: i64,
    /// Domain-specific immutable contents.
    pub contents: T,
}

impl<T: Serialize> Revision<T> {
    /// Constructs an immutable revision and derives its content digest.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Serialization`] when `contents` cannot be
    /// canonicalized.
    pub fn new(
        stable_id: StableId,
        generation: Generation,
        contents: T,
        authored_by: Actor,
        authored_at: i64,
    ) -> Result<Self, ControlError> {
        let content_digest = ContentDigest::of_value(&contents)?;
        Ok(Self {
            stable_id,
            generation,
            content_digest,
            authored_by,
            authored_at,
            contents,
        })
    }
}

/// The mutable compare-and-swap pointer to an immutable revision lineage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RevisionHead {
    /// Stable identity of the resource.
    pub stable_id: StableId,
    /// Current immutable generation.
    pub generation: Generation,
    /// Current revision content digest.
    pub content_digest: ContentDigest,
    /// Optimistic concurrency version.
    pub resource_version: ResourceVersion,
}

impl RevisionHead {
    /// Creates the first head for a revision lineage.
    ///
    /// # Errors
    ///
    /// Returns a digest or identity error when `revision` is inconsistent.
    pub fn initial<T: Serialize>(revision: &Revision<T>) -> Result<Self, ControlError> {
        if revision.generation.get() != 1 {
            return Err(ControlError::NonContiguousGeneration {
                expected: 1,
                received: revision.generation.get(),
            });
        }
        verify_revision_digest(revision)?;
        Ok(Self {
            stable_id: revision.stable_id.clone(),
            generation: revision.generation,
            content_digest: revision.content_digest.clone(),
            resource_version: ResourceVersion::new(1)?,
        })
    }

    /// Advances the head to exactly the next immutable revision under CAS.
    ///
    /// # Errors
    ///
    /// Returns an identity, stale-version, generation, digest, or overflow
    /// error when the supplied revision cannot immediately follow this head.
    pub fn advance<T: Serialize>(
        &self,
        expected_version: ResourceVersion,
        revision: &Revision<T>,
    ) -> Result<Self, ControlError> {
        if self.resource_version != expected_version {
            return Err(ControlError::StaleVersion {
                expected: expected_version.get(),
                current: self.resource_version.get(),
            });
        }
        if self.stable_id != revision.stable_id {
            return Err(ControlError::IdentityMismatch {
                expected: self.stable_id.to_string(),
                received: revision.stable_id.to_string(),
            });
        }
        let required_generation = self.generation.next()?;
        if revision.generation != required_generation {
            return Err(ControlError::NonContiguousGeneration {
                expected: required_generation.get(),
                received: revision.generation.get(),
            });
        }
        verify_revision_digest(revision)?;
        Ok(Self {
            stable_id: self.stable_id.clone(),
            generation: revision.generation,
            content_digest: revision.content_digest.clone(),
            resource_version: self.resource_version.next()?,
        })
    }
}

/// One append-only audit record intended to commit with a resource mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuditIntent {
    /// Canonical action name.
    pub action: String,
    /// Authorization scope stable identity.
    pub owner_scope: StableId,
    /// Mutated resource identity.
    pub resource_stable_id: StableId,
    /// Responsible actor.
    pub actor: Actor,
    /// Digest of the reviewed mutation detail.
    pub detail_digest: ContentDigest,
}

/// One transactional event-outbox record intended to commit with a mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OutboxIntent {
    /// Globally stable event identity.
    pub event_id: StableId,
    /// Canonical event name.
    pub event_name: String,
    /// Authorization scope stable identity.
    pub owner_scope: StableId,
    /// Canonical resource kind.
    pub resource_kind: String,
    /// Mutated resource identity.
    pub resource_stable_id: StableId,
    /// Immutable resource generation.
    pub resource_generation: Generation,
    /// Responsible actor.
    pub actor: Actor,
    /// Digest of the complete canonical event payload.
    pub payload_digest: ContentDigest,
    /// Unix timestamp of the committed mutation.
    pub occurred_at: i64,
}

/// The three records a persistence adapter must commit atomically.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MutationCommit<T> {
    /// New authoritative resource state or head.
    resource: T,
    /// Append-only audit intent.
    audit: AuditIntent,
    /// Transactional event-outbox intent.
    outbox: OutboxIntent,
}

mod sealed_mutation_resource {
    use serde::Serialize;

    use super::{Revision, RevisionHead};

    pub trait Sealed {}

    impl<T: Serialize> Sealed for Revision<T> {}
    impl Sealed for RevisionHead {}
}

/// Exposes the immutable identity and generation committed by a mutation.
///
/// This trait is sealed; callers cannot introduce resource types that bypass
/// the retained-control validation contract.
pub trait MutationResourceIdentity: sealed_mutation_resource::Sealed {
    /// Validates the complete committed resource before persistence.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::DigestMismatch`] or an invariant error when the
    /// resource was not produced by its checked constructor.
    fn validate_mutation_resource(&self) -> Result<(), ControlError>;
    /// Returns the stable resource identity.
    fn mutation_stable_id(&self) -> &StableId;
    /// Returns the immutable generation being committed.
    fn mutation_generation(&self) -> Generation;
}

impl<T: Serialize> MutationResourceIdentity for Revision<T> {
    fn validate_mutation_resource(&self) -> Result<(), ControlError> {
        verify_revision_digest(self)
    }

    fn mutation_stable_id(&self) -> &StableId {
        &self.stable_id
    }

    fn mutation_generation(&self) -> Generation {
        self.generation
    }
}

impl MutationResourceIdentity for RevisionHead {
    fn validate_mutation_resource(&self) -> Result<(), ControlError> {
        if self.stable_id.kind().is_empty() {
            return Err(ControlError::Invalid {
                field: "revision_head",
                reason: "must retain a typed stable identity".into(),
            });
        }
        Ok(())
    }

    fn mutation_stable_id(&self) -> &StableId {
        &self.stable_id
    }

    fn mutation_generation(&self) -> Generation {
        self.generation
    }
}

impl<T: MutationResourceIdentity> MutationCommit<T> {
    /// Constructs an atomic commit intent after checking shared attribution.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::IdentityMismatch`] or
    /// [`ControlError::Invalid`] when audit and outbox describe different
    /// mutations.
    pub fn new(
        resource: T,
        audit: AuditIntent,
        outbox: OutboxIntent,
    ) -> Result<Self, ControlError> {
        resource.validate_mutation_resource()?;
        if audit.resource_stable_id != *resource.mutation_stable_id() {
            return Err(ControlError::IdentityMismatch {
                expected: resource.mutation_stable_id().to_string(),
                received: audit.resource_stable_id.to_string(),
            });
        }
        if outbox.resource_stable_id != *resource.mutation_stable_id() {
            return Err(ControlError::IdentityMismatch {
                expected: resource.mutation_stable_id().to_string(),
                received: outbox.resource_stable_id.to_string(),
            });
        }
        if audit.owner_scope != outbox.owner_scope || audit.actor != outbox.actor {
            return Err(ControlError::Invalid {
                field: "mutation_attribution",
                reason: "audit and outbox attribution must be identical".into(),
            });
        }
        if outbox.resource_generation != resource.mutation_generation()
            || outbox.resource_kind != resource.mutation_stable_id().kind()
        {
            return Err(ControlError::Invalid {
                field: "mutation_resource",
                reason: "outbox kind/generation must equal the committed resource".into(),
            });
        }
        Ok(Self {
            resource,
            audit,
            outbox,
        })
    }

    /// Returns the authoritative resource committed by this transaction unit.
    #[must_use]
    pub fn resource(&self) -> &T {
        &self.resource
    }

    /// Returns the append-only audit intent committed with the resource.
    #[must_use]
    pub fn audit(&self) -> &AuditIntent {
        &self.audit
    }

    /// Returns the transactional outbox intent committed with the resource.
    #[must_use]
    pub fn outbox(&self) -> &OutboxIntent {
        &self.outbox
    }

    /// Consumes the checked transaction unit into persistence-layer records.
    #[must_use]
    pub fn into_parts(self) -> (T, AuditIntent, OutboxIntent) {
        (self.resource, self.audit, self.outbox)
    }
}

fn verify_revision_digest<T: Serialize>(revision: &Revision<T>) -> Result<(), ControlError> {
    let actual = ContentDigest::of_value(&revision.contents)?;
    if actual != revision.content_digest {
        return Err(ControlError::DigestMismatch);
    }
    Ok(())
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ControlError> {
    let value = serde_json::to_value(value)
        .map_err(|error| ControlError::Serialization(error.to_string()))?;
    let mut output = String::new();
    write_canonical_json(&value, &mut output)?;
    Ok(output.into_bytes())
}

fn write_canonical_json(
    value: &serde_json::Value,
    output: &mut String,
) -> Result<(), ControlError> {
    match value {
        serde_json::Value::Null => output.push_str("null"),
        serde_json::Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        serde_json::Value::Number(value) => {
            if value.as_i64().is_none() && value.as_u64().is_none() {
                return Err(ControlError::Serialization(
                    "floating-point values are not accepted in control-plane seals".into(),
                ));
            }
            output.push_str(&value.to_string());
        }
        serde_json::Value::String(value) => output.push_str(
            &serde_json::to_string(value)
                .map_err(|error| ControlError::Serialization(error.to_string()))?,
        ),
        serde_json::Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(']');
        }
        serde_json::Value::Object(values) => {
            output.push('{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key)
                        .map_err(|error| ControlError::Serialization(error.to_string()))?,
                );
                output.push(':');
                if let Some(value) = values.get(key) {
                    write_canonical_json(value, output)?;
                }
            }
            output.push('}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde::Serialize;

    use super::*;

    fn actor() -> Actor {
        Actor::new(ActorKind::User, Some(7), "alice@example.test").unwrap()
    }

    #[test]
    fn canonical_digest_is_independent_of_object_key_order() {
        let left = serde_json::json!({"b": 2, "a": 1});
        let right = serde_json::json!({"a": 1, "b": 2});
        assert_eq!(
            ContentDigest::of_value(&left).unwrap(),
            ContentDigest::of_value(&right).unwrap()
        );
    }

    #[test]
    fn head_advance_requires_identity_version_generation_and_digest() {
        #[derive(Clone, Serialize)]
        struct Body {
            value: u64,
        }

        let id = StableId::new("instance-settings:branding").unwrap();
        let first = Revision::new(
            id.clone(),
            Generation::new(1).unwrap(),
            Body { value: 1 },
            actor(),
            10,
        )
        .unwrap();
        let head = RevisionHead::initial(&first).unwrap();
        let second = Revision::new(
            id,
            Generation::new(2).unwrap(),
            Body { value: 2 },
            actor(),
            11,
        )
        .unwrap();

        let next = head
            .advance(ResourceVersion::new(1).unwrap(), &second)
            .unwrap();
        assert_eq!(next.generation.get(), 2);
        assert_eq!(next.resource_version.get(), 2);
        assert!(matches!(
            next.advance(ResourceVersion::new(1).unwrap(), &second),
            Err(ControlError::StaleVersion { .. })
        ));
    }

    #[test]
    fn actor_kind_controls_principal_id_presence() {
        assert!(Actor::new(ActorKind::User, None, "alice").is_err());
        assert!(Actor::new(ActorKind::System, Some(1), "controller").is_err());
        assert!(Actor::new(ActorKind::ServiceAccount, Some(2), "sa:controller").is_ok());
    }

    #[test]
    fn stable_ids_are_single_segment_and_route_safe() {
        assert!(StableId::new("registry:01j5m5hk7pz1").is_ok());
        for invalid in [
            "registry:acme/main",
            "registry:..",
            "registry:%2f",
            "Registry:main",
            "registry::main",
            "registry:-main",
            "registry:main__blue",
            "registry:main/../other",
        ] {
            assert!(StableId::new(invalid).is_err(), "accepted {invalid}");
        }
        assert!(serde_json::from_str::<StableId>(r#""registry:%2f""#).is_err());
    }

    #[test]
    fn actor_deserialization_revalidates_and_denies_unknown_fields() {
        assert!(serde_json::from_str::<Actor>(
            r#"{"kind":"user","principal_id":null,"label":"alice"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<Actor>(
            r#"{"kind":"system","principal_id":null,"label":"system","token":"leak"}"#
        )
        .is_err());
    }
}
