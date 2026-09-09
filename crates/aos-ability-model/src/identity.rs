//! Stable logical identities and scoped references.
//!
//! Persisted identities use structured records. Display formatting is for
//! diagnostics and is never parsed as authority.

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::fmt;
use std::num::NonZeroU32;
use std::str::FromStr;

use aos_contract::Sha256Digest;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

const MAX_LOCAL_KEY_BYTES: usize = 128;
const MAX_OPAQUE_ID_BYTES: usize = 1_048_576;
const MAX_SCOPE_COMPONENTS: usize = 64;

/// Reports why an ability identity component is invalid.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IdentityError {
    /// A required identity component was empty.
    #[error("{kind} must not be empty")]
    Empty { kind: &'static str },
    /// An identity component exceeded its format bound byte limit.
    #[error("{kind} exceeds its {limit} byte limit")]
    TooLong { kind: &'static str, limit: usize },
    /// A local key used a character outside the closed grammar.
    #[error("local key contains a character outside [A-Za-z0-9._-]")]
    InvalidLocalKey,
    /// A qualified name lacked a namespace or used an invalid segment.
    #[error("interface name must contain at least two nonempty [A-Za-z0-9_-] segments")]
    InvalidQualifiedName,
    /// A hierarchy exceeded the version-1 structural depth bound.
    #[error("scope path exceeds its {limit} component limit")]
    ScopeTooDeep { limit: usize },
}

/// Identifies one bounded local name inside an authenticated parent scope.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LocalKey(String);

impl LocalKey {
    /// Constructs a local key from the version-1 key grammar.
    ///
    /// # Errors
    ///
    /// Returns an error when `value` is empty, exceeds 128 bytes, is not
    /// ASCII, or contains a character outside `[A-Za-z0-9._-]`.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        validate_local_key(&value)?;
        Ok(Self(value))
    }

    /// Returns the serialized key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for LocalKey {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for LocalKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for LocalKey {
    type Err = IdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for LocalKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for LocalKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Identifies a namespace-qualified interface or guarantee name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InterfaceName(String);

impl InterfaceName {
    /// Constructs a namespace-qualified name.
    ///
    /// # Errors
    ///
    /// Returns an error unless `value` contains at least two nonempty ASCII
    /// segments separated by dots and is no longer than 128 bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        validate_qualified_name(&value)?;
        Ok(Self(value))
    }

    /// Returns the serialized qualified name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InterfaceName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for InterfaceName {
    type Err = IdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for InterfaceName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for InterfaceName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Identifies an opaque provider-assigned incarnation or broker value.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IncarnationId(String);

impl IncarnationId {
    /// Constructs a nonempty bounded opaque identity.
    ///
    /// # Errors
    ///
    /// Returns an error when `value` is empty or exceeds the version-1 string
    /// limit. No local-key grammar is imposed on provider-owned identities.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        if value.is_empty() {
            return Err(IdentityError::Empty {
                kind: "incarnation identity",
            });
        }
        if value.len() > MAX_OPAQUE_ID_BYTES {
            return Err(IdentityError::TooLong {
                kind: "incarnation identity",
                limit: MAX_OPAQUE_ID_BYTES,
            });
        }
        Ok(Self(value))
    }

    /// Returns the opaque identity without interpreting it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IncarnationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for IncarnationId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for IncarnationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Names the execution stage and manager boundary of an environment.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionStage {
    /// Runs while constructing immutable artifacts.
    Build,
    /// Runs in the early boot environment.
    Initrd,
    /// Runs under the host system manager.
    Host,
    /// Runs under a system container's local manager.
    SystemContainer,
    /// Runs under a user manager.
    User,
    /// Runs in an application-container environment.
    ApplicationContainer,
}

impl ExecutionStage {
    /// Returns the stable version-1 semantic ordering rank.
    #[must_use]
    pub const fn canonical_rank(self) -> u8 {
        match self {
            Self::Build => 0,
            Self::Initrd => 1,
            Self::Host => 2,
            Self::SystemContainer => 3,
            Self::User => 4,
            Self::ApplicationContainer => 5,
        }
    }
}

/// Identifies one authority-assigned environment at an execution stage.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentId {
    /// Names the authority that assigned the environment identity.
    pub authority: LocalKey,
    /// Names the stable environment within that authority.
    pub key: LocalKey,
    /// Distinguishes host, initrd, user, and container execution boundaries.
    pub stage: ExecutionStage,
}

/// Identifies one deployment-owned package instance.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceId {
    /// Identifies the environment containing the instance.
    pub environment: EnvironmentId,
    /// Names the stable instance across package revisions.
    pub key: LocalKey,
}

/// Identifies a composition hierarchy, with an empty vector naming the root.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ScopePath(Vec<LocalKey>);

impl ScopePath {
    /// Constructs a scope path from ordered hierarchy components.
    ///
    /// # Errors
    ///
    /// Returns an error when the hierarchy exceeds 64 components. An empty
    /// vector is the valid root scope.
    pub fn new(components: Vec<LocalKey>) -> Result<Self, IdentityError> {
        if components.len() > MAX_SCOPE_COMPONENTS {
            return Err(IdentityError::ScopeTooDeep {
                limit: MAX_SCOPE_COMPONENTS,
            });
        }
        Ok(Self(components))
    }

    /// Constructs the root composition scope.
    #[must_use]
    pub const fn root() -> Self {
        Self(Vec::new())
    }

    /// Returns the hierarchy components in declared order.
    #[must_use]
    pub fn as_slice(&self) -> &[LocalKey] {
        &self.0
    }

    /// Reports whether this scope contains `other`.
    #[must_use]
    pub fn contains(&self, other: &Self) -> bool {
        other.0.starts_with(&self.0)
    }
}

impl Serialize for ScopePath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ScopePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(Vec::<LocalKey>::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Identifies a consumer request and its recursive composition scope.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestId {
    /// Identifies the consuming deployment instance.
    pub consumer: InstanceId,
    /// Identifies the nested composition scope.
    pub scope: ScopePath,
    /// Names the request within its scope.
    pub key: LocalKey,
}

/// Identifies one provider-owned aggregation group.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateId {
    /// Identifies the provider instance owning the aggregate.
    pub provider: InstanceId,
    /// Names the provider-declared aggregation group.
    pub group: LocalKey,
}

/// Identifies one logical provider-owned resource.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceId {
    /// Identifies the provider instance that owns the resource.
    pub provider: InstanceId,
    /// Names the logical resource across content revisions.
    pub key: LocalKey,
}

/// Identifies the semantic content revision of a resource or contract.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RevisionId(pub Sha256Digest);

/// Identifies an exact binding or effect plan by canonical content digest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PlanId(pub Sha256Digest);

/// Names one operation within a transition plan before the plan is digested.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedOperationKey {
    /// Identifies the provider-composition scope that created the operation.
    pub scope: ScopePath,
    /// Names the operation within that scope.
    pub key: LocalKey,
}

/// Identifies one operation in an exact transition plan.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationId {
    /// Identifies the canonical effect plan.
    pub plan: PlanId,
    /// Names the operation inside the plan.
    pub operation: ScopedOperationKey,
}

/// Identifies one durable controller allocation for a plan execution.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TransactionId(pub LocalKey);

/// Identifies one exact public interface contract.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceKey {
    /// Names the interface within its namespace.
    pub name: InterfaceName,
    /// Identifies the caller-visible ABI family.
    pub abi: NonZeroU32,
    /// Identifies the exact semantic public descriptor.
    pub descriptor: Sha256Digest,
}

/// Returns the explicit canonical ordering for environment identities.
#[must_use]
pub fn compare_environment_ids(left: &EnvironmentId, right: &EnvironmentId) -> Ordering {
    left.authority
        .cmp(&right.authority)
        .then_with(|| left.key.cmp(&right.key))
        .then_with(|| {
            left.stage
                .canonical_rank()
                .cmp(&right.stage.canonical_rank())
        })
}

/// Returns the explicit canonical ordering for deployment instance identities.
#[must_use]
pub fn compare_instance_ids(left: &InstanceId, right: &InstanceId) -> Ordering {
    compare_environment_ids(&left.environment, &right.environment)
        .then_with(|| left.key.cmp(&right.key))
}

/// Returns the explicit canonical ordering for request identities.
#[must_use]
pub fn compare_request_ids(left: &RequestId, right: &RequestId) -> Ordering {
    compare_instance_ids(&left.consumer, &right.consumer)
        .then_with(|| left.scope.as_slice().cmp(right.scope.as_slice()))
        .then_with(|| left.key.cmp(&right.key))
}

/// Returns the explicit canonical ordering for logical resource identities.
#[must_use]
pub fn compare_resource_ids(left: &ResourceId, right: &ResourceId) -> Ordering {
    compare_instance_ids(&left.provider, &right.provider).then_with(|| left.key.cmp(&right.key))
}

fn validate_local_key(value: &str) -> Result<(), IdentityError> {
    if value.is_empty() {
        return Err(IdentityError::Empty { kind: "local key" });
    }
    if value.len() > MAX_LOCAL_KEY_BYTES {
        return Err(IdentityError::TooLong {
            kind: "local key",
            limit: MAX_LOCAL_KEY_BYTES,
        });
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(IdentityError::InvalidLocalKey);
    }
    Ok(())
}

fn validate_qualified_name(value: &str) -> Result<(), IdentityError> {
    if value.len() > MAX_LOCAL_KEY_BYTES {
        return Err(IdentityError::TooLong {
            kind: "interface name",
            limit: MAX_LOCAL_KEY_BYTES,
        });
    }

    let mut segments = value.split('.');
    let first = segments.next();
    let second = segments.next();
    let segments_are_valid = first.is_some_and(valid_qualified_segment)
        && second.is_some_and(valid_qualified_segment)
        && segments.all(valid_qualified_segment);
    if !segments_are_valid {
        return Err(IdentityError::InvalidQualifiedName);
    }
    Ok(())
}

fn valid_qualified_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn local_keys_enforce_the_closed_grammar() {
        assert!(LocalKey::new("edge.v1_0-main").is_ok());
        assert!(LocalKey::new("").is_err());
        assert!(LocalKey::new("host/path").is_err());
        assert!(LocalKey::new("é").is_err());
        assert!(LocalKey::new("x".repeat(129)).is_err());
    }

    #[test]
    fn interface_names_require_a_namespace() {
        assert!(InterfaceName::new("nginx.virtual-host").is_ok());
        assert!(InterfaceName::new("virtual-host").is_err());
        assert!(InterfaceName::new("nginx..virtual-host").is_err());
    }

    #[test]
    fn scope_containment_uses_components_instead_of_string_prefixes() {
        let parent = ScopePath::new(vec![LocalKey::new("nginx").expect("valid test key")])
            .expect("valid test scope");
        let child = ScopePath::new(vec![
            LocalKey::new("nginx").expect("valid test key"),
            LocalKey::new("configuration").expect("valid test key"),
        ])
        .expect("valid test scope");

        assert!(parent.contains(&child));
        assert!(!child.contains(&parent));
    }

    #[test]
    fn scope_paths_allow_the_root_and_reject_excessive_depth() {
        assert_eq!(ScopePath::new(Vec::new()), Ok(ScopePath::root()));

        let component = LocalKey::new("level").expect("valid test key");
        assert!(ScopePath::new(vec![component.clone(); MAX_SCOPE_COMPONENTS]).is_ok());
        assert!(ScopePath::new(vec![component; MAX_SCOPE_COMPONENTS + 1]).is_err());
        let too_deep_json = serde_json::to_value(vec!["level"; MAX_SCOPE_COMPONENTS + 1])
            .expect("serialize test scope");
        assert!(serde_json::from_value::<ScopePath>(too_deep_json).is_err());
    }
}
