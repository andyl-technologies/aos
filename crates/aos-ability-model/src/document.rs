//! Canonical envelopes and explicit feature admission for realized artifact evidence.
//!
//! Native deployment documents have their own schema. This module preserves the
//! independent artifact-consumption format and its bounded canonical encoding.

use std::collections::BTreeSet;

use aos_contract::Sha256Digest;
use aos_contract::limits::BoundedWriter;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::identity::LocalKey;
use crate::limits::{ABILITY_LIMITS_V1, LimitProfile};

/// Identifies one required format semantic understood by a consumer.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequiredFeature(LocalKey);

impl RequiredFeature {
    /// Constructs a required feature using the version-1 local-key grammar.
    ///
    /// # Errors
    ///
    /// Returns an error when `value` is not a valid local key.
    pub fn new(value: impl Into<String>) -> Result<Self, crate::identity::IdentityError> {
        LocalKey::new(value).map(Self)
    }

    /// Returns the serialized required-feature name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Serialize for RequiredFeature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RequiredFeature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        LocalKey::deserialize(deserializer).map(Self)
    }
}

/// Reports a canonical envelope decoding or feature-negotiation failure.
#[derive(Debug, Error)]
pub enum DocumentError {
    /// The document exceeded an effective input bound.
    #[error("{label} exceeds the effective {limit} limit")]
    Limit {
        /// Names the document being processed.
        label: String,
        /// Names the exceeded limit.
        limit: &'static str,
    },
    /// The bytes were not exact canonical JSON for the closed schema.
    #[error("invalid canonical {label}")]
    Decode {
        /// Names the document being processed.
        label: String,
        /// Retains the parser or schema error chain.
        #[source]
        source: anyhow::Error,
    },
    /// The document carried another format discriminator.
    #[error("unsupported schema '{actual}', expected '{expected}'")]
    Schema {
        /// Gives the required exact discriminator.
        expected: &'static str,
        /// Gives the received discriminator.
        actual: String,
    },
    /// A required-feature set was duplicated or out of canonical order.
    #[error("required_features must be strictly sorted without duplicates")]
    RequiredFeatureOrder,
    /// The consumer does not implement a required semantic feature.
    #[error("unsupported required feature '{feature}'")]
    UnsupportedFeature {
        /// Names the unsupported semantic feature.
        feature: String,
    },
    /// The document's embedded limit profile is invalid.
    #[error("the document limit profile exceeds the version-1 ceiling or contains a zero bound")]
    InvalidLimitProfile,
}

impl DocumentError {
    /// Returns the stable diagnostic code for this decoding or envelope failure.
    #[must_use]
    pub const fn diagnostic_code(&self) -> crate::DiagnosticCode {
        match self {
            Self::Limit { .. } | Self::InvalidLimitProfile => crate::DiagnosticCode::LimitExceeded,
            Self::Decode { .. } => crate::DiagnosticCode::ValueTypeMismatch,
            Self::Schema { .. } => crate::DiagnosticCode::UnsupportedSchema,
            Self::RequiredFeatureOrder => crate::DiagnosticCode::NonCanonicalOrder,
            Self::UnsupportedFeature { .. } => crate::DiagnosticCode::UnsupportedRequiredFeature,
        }
    }
}

/// Defines behavior shared by every versioned ability document envelope.
pub trait VersionedDocument: Serialize + DeserializeOwned {
    /// Gives the exact versioned schema discriminator and digest domain.
    const SCHEMA: &'static str;

    /// Returns the schema discriminator carried by this document.
    fn schema(&self) -> &str;

    /// Returns required semantics in canonical order.
    fn required_features(&self) -> &[RequiredFeature];

    /// Returns the document's effective embedded limit profile, when present.
    fn limit_profile(&self) -> Option<&LimitProfile> {
        None
    }

    /// Checks recursive in-memory structures before serde traverses them.
    ///
    /// # Errors
    ///
    /// Returns an error when a recursive schema or expression exceeds the
    /// effective structural-depth limit.
    fn validate_structure(&self, _limits: &LimitProfile) -> Result<(), DocumentError> {
        Ok(())
    }

    /// Computes the exact domain-separated identity of the canonical document.
    ///
    /// # Errors
    ///
    /// Returns an error when the document violates the canonical JSON dialect.
    fn content_digest(&self) -> Result<Sha256Digest, DocumentError> {
        Ok(Sha256Digest::separated(
            Self::SCHEMA,
            encode_canonical(self)?,
        ))
    }
}

/// Decodes one exact canonical document under explicit feature support.
///
/// # Errors
///
/// Returns an error for a size or structural bound violation, noncanonical or
/// ambiguous JSON, a closed-schema violation, a discriminator mismatch, a
/// noncanonical required-feature set, or an unsupported required feature.
pub fn decode_canonical<T>(
    bytes: &[u8],
    limits: LimitProfile,
    supported_features: &BTreeSet<RequiredFeature>,
) -> Result<T, DocumentError>
where
    T: VersionedDocument,
{
    let label = T::SCHEMA;
    if !limits.is_admissible_v1() {
        return Err(DocumentError::InvalidLimitProfile);
    }
    if bytes.len() as u64 > limits.max_document_bytes {
        return Err(DocumentError::Limit {
            label: label.to_string(),
            limit: "document byte",
        });
    }

    let json_limits = aos_contract::limits::JsonLimits {
        max_bytes: bounded_usize(limits.max_document_bytes),
        max_depth: limits.max_structural_depth as usize,
        max_items: bounded_usize(limits.max_collection_items),
        max_string_bytes: bounded_usize(limits.max_string_bytes),
    };
    let document =
        json_limits
            .decode::<T>(bytes, label)
            .map_err(|source| DocumentError::Decode {
                label: label.to_string(),
                source,
            })?;

    validate_envelope(&document, supported_features)?;
    let canonical = encode_canonical(&document)?;
    if canonical != bytes {
        return Err(DocumentError::Decode {
            label: label.to_string(),
            source: anyhow::anyhow!(
                "document is not the exact canonical encoding of its closed schema"
            ),
        });
    }
    Ok(document)
}

/// Encodes one document into the exact canonical JSON dialect.
///
/// # Errors
///
/// Returns an error for a discriminator mismatch, a noncanonical feature set,
/// an invalid embedded limit profile, or a canonical encoding failure.
pub fn encode_canonical<T>(document: &T) -> Result<Vec<u8>, DocumentError>
where
    T: VersionedDocument,
{
    validate_envelope(
        document,
        &document.required_features().iter().cloned().collect(),
    )?;
    let limits = document.limit_profile().unwrap_or(&ABILITY_LIMITS_V1);
    document.validate_structure(limits)?;

    let max_bytes = limits.max_document_bytes;
    preflight_serialized_size(document, max_bytes)?;

    let bytes =
        aos_contract::canonical::to_vec(document).map_err(|source| DocumentError::Decode {
            label: T::SCHEMA.to_string(),
            source,
        })?;
    if bytes.len() as u64 > max_bytes {
        return Err(DocumentError::Limit {
            label: T::SCHEMA.to_string(),
            limit: "document byte",
        });
    }

    let json_limits = aos_contract::limits::JsonLimits {
        max_bytes: bounded_usize(limits.max_document_bytes),
        max_depth: limits.max_structural_depth as usize,
        max_items: bounded_usize(limits.max_collection_items),
        max_string_bytes: bounded_usize(limits.max_string_bytes),
    };
    json_limits
        .decode::<serde_json::Value>(&bytes, T::SCHEMA)
        .map_err(|source| DocumentError::Decode {
            label: T::SCHEMA.to_string(),
            source,
        })?;
    Ok(bytes)
}

fn preflight_serialized_size<T>(value: &T, max_bytes: u64) -> Result<(), DocumentError>
where
    T: VersionedDocument,
{
    let mut writer = BoundedWriter::new(max_bytes, "serialized document exceeds its byte limit");
    serde_json::to_writer(&mut writer, value).map_err(|source| {
        if writer.exceeded() {
            DocumentError::Limit {
                label: T::SCHEMA.to_string(),
                limit: "document byte",
            }
        } else {
            DocumentError::Decode {
                label: T::SCHEMA.to_string(),
                source: source.into(),
            }
        }
    })
}

/// Identifies a target platform without consulting the evaluator host.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformIdentity {
    /// Names the operating-system family.
    pub system: LocalKey,
    /// Names the target machine architecture.
    pub architecture: LocalKey,
}

fn validate_envelope<T>(
    document: &T,
    supported_features: &BTreeSet<RequiredFeature>,
) -> Result<(), DocumentError>
where
    T: VersionedDocument,
{
    if document.schema() != T::SCHEMA {
        return Err(DocumentError::Schema {
            expected: T::SCHEMA,
            actual: document.schema().to_string(),
        });
    }
    if !strictly_sorted(document.required_features()) {
        return Err(DocumentError::RequiredFeatureOrder);
    }
    for feature in document.required_features() {
        if !supported_features.contains(feature) {
            return Err(DocumentError::UnsupportedFeature {
                feature: feature.as_str().to_string(),
            });
        }
    }
    if document
        .limit_profile()
        .is_some_and(|limits| !limits.is_admissible_v1())
    {
        return Err(DocumentError::InvalidLimitProfile);
    }
    Ok(())
}

fn strictly_sorted<T>(values: &[T]) -> bool
where
    T: Ord,
{
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn bounded_usize(value: u64) -> usize {
    match usize::try_from(value) {
        Ok(value) => value,
        Err(_) => usize::MAX,
    }
}
