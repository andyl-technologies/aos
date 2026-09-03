//! Closed capability resource, operation, and selector vocabularies.
//!
//! Selectors contain only portable logical identities. They never contain a
//! host path, PID, namespace path, descriptor number, interface name, or
//! backend option. Path components remain bytes and are never Unicode
//! normalized or interpreted with locale-dependent rules.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{ExportId, ResourceId};

/// Identifies one closed v1 resource class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[repr(u8)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceKind {
    /// A durable logical sandbox.
    Sandbox = 0,
    /// One admitted command execution.
    Execution = 1,
    /// A durable snapshot and retained dependencies.
    Snapshot = 2,
    /// An immutable portable filesystem tree.
    Tree = 3,
    /// A generation-fenced live sandbox export.
    LiveExport = 4,
    /// A private writable filesystem delta.
    PrivateDelta = 5,
    /// A mediated secret projection.
    Secret = 6,
    /// A specifically authorized device resource.
    Device = 7,
    /// A logical network endpoint policy resource.
    NetworkEndpoint = 8,
    /// A mediated IPC or Unix-socket service.
    IpcService = 9,
    /// Read access to one cache disclosure domain.
    CacheRead = 10,
    /// Transactional cache publication authority.
    CachePublish = 11,
    /// An immutable project-environment generation.
    Environment = 12,
    /// A broker-owned attachment destination slot.
    AttachmentSlot = 13,
    /// Authority to create or delegate to a child sandbox.
    ChildDelegation = 14,
}

/// Identifies one closed v1 operation bit.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum Operation {
    /// Discovers that a concealed resource exists.
    Discover = 0,
    /// Reads resource or filesystem metadata.
    MetadataRead = 1,
    /// Reads file or object content.
    ContentRead = 2,
    /// Executes content or creates a command execution.
    Execute = 3,
    /// Creates a resource or filesystem entry.
    Create = 4,
    /// Mutates file or object content.
    ContentWrite = 5,
    /// Removes a resource or filesystem entry.
    Remove = 6,
    /// Renames a filesystem entry.
    Rename = 7,
    /// Creates a policy-authorized link.
    Link = 8,
    /// Mutates portable metadata.
    MetadataWrite = 9,
    /// Attaches a view or service to a destination slot.
    Attach = 10,
    /// Controls resource lifecycle.
    LifecycleControl = 11,
    /// Requests a broker-mediated attenuated capability.
    Delegate = 12,
    /// Publishes a verified immutable or transactional result.
    Publish = 13,
    /// Reads a live view sharing socket, FIFO, and lock identity.
    LiveKernelCoupledRead = 14,
}

impl Operation {
    const fn bit(self) -> u16 {
        1_u16 << (self as u8)
    }
}

/// Stores a validated set of closed v1 operation bits.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct OperationSet(u16);

impl OperationSet {
    const VALID_BITS: u16 = 0x7fff;

    /// The empty operation set, which grants no authority.
    pub const EMPTY: Self = Self(0);
    /// The complete closed v1 operation set.
    pub const ALL: Self = Self(Self::VALID_BITS);

    /// Creates a set containing one operation.
    #[must_use]
    pub const fn one(operation: Operation) -> Self {
        Self(operation.bit())
    }

    /// Validates a raw v1 operation bitmap.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidOperationSet`] if an unknown high bit is set.
    pub const fn from_bits(bits: u16) -> Result<Self, InvalidOperationSet> {
        if bits & !Self::VALID_BITS == 0 {
            Ok(Self(bits))
        } else {
            Err(InvalidOperationSet { bits })
        }
    }

    /// Returns the stable v1 bitmap.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Reports whether the set grants no operation.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Reports whether this set contains `operation`.
    #[must_use]
    pub const fn contains(self, operation: Operation) -> bool {
        self.0 & operation.bit() != 0
    }

    /// Reports whether every bit is present in `ceiling`.
    #[must_use]
    pub const fn is_subset_of(self, ceiling: Self) -> bool {
        self.0 & !ceiling.0 == 0
    }

    /// Returns the union of two validated sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns the intersection of two validated sets.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}

impl Serialize for OperationSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u16(self.bits())
    }
}

impl<'de> Deserialize<'de> for OperationSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_bits(u16::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Reports operation bits outside the closed v1 registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("operation bitmap 0x{bits:04x} contains an unknown v1 bit")]
pub struct InvalidOperationSet {
    bits: u16,
}

/// Stores an exact SHA-256 object digest.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObjectDigest([u8; 32]);

impl ObjectDigest {
    /// Constructs a digest from its exact portable bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ObjectDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "sha256:{}", hex::encode(self.0))
    }
}

impl fmt::Debug for ObjectDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ObjectDigest")
            .field(&self.to_string())
            .finish()
    }
}

impl FromStr for ObjectDigest {
    type Err = InvalidObjectDigest;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let hex = input.strip_prefix("sha256:").ok_or(InvalidObjectDigest)?;
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(InvalidObjectDigest);
        }
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(hex, &mut bytes).map_err(|_| InvalidObjectDigest)?;
        Ok(Self(bytes))
    }
}

impl Serialize for ObjectDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.collect_str(self)
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for ObjectDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            String::deserialize(deserializer)?
                .parse()
                .map_err(serde::de::Error::custom)
        } else {
            deserialize_exact_bytes::<D, 32>(deserializer).map(Self)
        }
    }
}

/// Reports a digest outside the exact lowercase SHA-256 display profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("digest must be sha256 followed by exactly 64 lowercase hexadecimal digits")]
pub struct InvalidObjectDigest;

/// Stores a syntactically valid portable object media type.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct MediaType(String);

impl MediaType {
    /// Validates a lowercase ASCII media type without parameters.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMediaType`] for an empty component, extra slash,
    /// unsupported byte, or value longer than 255 bytes. Registry membership
    /// is checked separately.
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidMediaType> {
        let value = value.into();
        let slash_count = value.bytes().filter(|byte| *byte == b'/').count();
        let valid_bytes = value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-' | b'/'
                )
        });
        let valid_parts = value
            .split_once('/')
            .is_some_and(|(kind, subtype)| !kind.is_empty() && !subtype.is_empty());

        if value.len() <= 255 && slash_count == 1 && valid_bytes && valid_parts {
            Ok(Self(value))
        } else {
            Err(InvalidMediaType)
        }
    }

    /// Returns the validated media type.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for MediaType {
    type Error = InvalidMediaType;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<MediaType> for String {
    fn from(value: MediaType) -> Self {
        value.0
    }
}

/// Reports a malformed portable object media type.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("media type must be 1..=255 bytes of lowercase ASCII type/subtype syntax")]
pub struct InvalidMediaType;

/// Identifies a stored portable object by type, digest, and exact byte size.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectDescriptor {
    media_type: MediaType,
    digest: ObjectDigest,
    encoded_size: u64,
}

impl ObjectDescriptor {
    /// Constructs a descriptor from validated components.
    #[must_use]
    pub const fn new(media_type: MediaType, digest: ObjectDigest, encoded_size: u64) -> Self {
        Self {
            media_type,
            digest,
            encoded_size,
        }
    }

    /// Returns the syntactically validated media type.
    #[must_use]
    pub const fn media_type(&self) -> &MediaType {
        &self.media_type
    }

    /// Returns the exact SHA-256 digest.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Returns the exact stored object size.
    #[must_use]
    pub const fn encoded_size(&self) -> u64 {
        self.encoded_size
    }
}

/// Identifies one versioned feature or presentation profile.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct FeatureRef {
    namespace: String,
    major: u32,
    minor: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FeatureRefWire {
    namespace: String,
    major: u32,
    minor: u32,
}

impl<'de> Deserialize<'de> for FeatureRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = FeatureRefWire::deserialize(deserializer)?;
        Self::new(wire.namespace, wire.major, wire.minor).map_err(serde::de::Error::custom)
    }
}

impl FeatureRef {
    /// Constructs a syntactically valid feature reference.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidFeatureNamespace`] unless the namespace contains
    /// 1..=255 normalized lowercase ASCII bytes.
    pub fn new(
        namespace: impl Into<String>,
        major: u32,
        minor: u32,
    ) -> Result<Self, InvalidFeatureNamespace> {
        let namespace = namespace.into();
        let mut component_has_byte = false;
        if namespace.is_empty() || namespace.len() > 255 {
            return Err(InvalidFeatureNamespace);
        }
        for byte in namespace.bytes() {
            match byte {
                b'a'..=b'z' | b'0'..=b'9' => component_has_byte = true,
                b'.' | b'_' | b'-' if component_has_byte => component_has_byte = false,
                _ => return Err(InvalidFeatureNamespace),
            }
        }
        if !component_has_byte {
            return Err(InvalidFeatureNamespace);
        }
        Ok(Self {
            namespace,
            major,
            minor,
        })
    }

    /// Returns the registered feature namespace.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Returns the feature major version.
    #[must_use]
    pub const fn major(&self) -> u32 {
        self.major
    }

    /// Returns the feature minor version.
    #[must_use]
    pub const fn minor(&self) -> u32 {
        self.minor
    }
}

/// Reports a malformed feature namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("feature namespace must be 1..=255 normalized lowercase ASCII bytes")]
pub struct InvalidFeatureNamespace;

/// Stores one validated nonempty portable filesystem name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PathName(Vec<u8>);

impl PathName {
    /// Validates one byte-exact path component.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPathName`] if the name is empty, exceeds 255 bytes,
    /// contains NUL or `/`, or equals `.` or `..`.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, InvalidPathName> {
        let bytes = bytes.into();
        if bytes.is_empty()
            || bytes.len() > 255
            || bytes.contains(&0)
            || bytes.contains(&b'/')
            || bytes == b"."
            || bytes == b".."
        {
            Err(InvalidPathName)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Returns the uninterpreted filesystem name bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for PathName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for PathName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_bounded_bytes::<D, 1, 255>(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

impl TryFrom<Vec<u8>> for PathName {
    type Error = InvalidPathName;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Reports a path component outside the portable byte-name profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("path name must be 1..=255 bytes and exclude NUL, slash, dot, and dot-dot")]
pub struct InvalidPathName;

/// Stores a byte-exact normalized relative path.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RelativePath(Vec<PathName>);

impl RelativePath {
    /// Absolute decoder ceiling for portable path components.
    pub const MAX_COMPONENTS: usize = 4_096;

    /// Constructs a bounded relative path from validated components.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidRelativePath`] if the path exceeds the absolute
    /// portable decoder ceiling. Compiled policy may impose a smaller limit.
    pub fn new(components: Vec<PathName>) -> Result<Self, InvalidRelativePath> {
        if components.len() <= Self::MAX_COMPONENTS {
            Ok(Self(components))
        } else {
            Err(InvalidRelativePath)
        }
    }

    /// Returns the ordered path components.
    #[must_use]
    pub fn components(&self) -> &[PathName] {
        &self.0
    }

    /// Reports whether this path is an ancestor of or equal to `candidate`.
    #[must_use]
    pub fn contains(&self, candidate: &Self) -> bool {
        candidate.0.starts_with(&self.0)
    }
}

impl<'de> Deserialize<'de> for RelativePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RelativePathVisitor;

        impl<'de> Visitor<'de> for RelativePathVisitor {
            type Value = RelativePath;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded sequence of portable path names")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                if sequence
                    .size_hint()
                    .is_some_and(|length| length > RelativePath::MAX_COMPONENTS)
                {
                    return Err(de::Error::invalid_length(
                        RelativePath::MAX_COMPONENTS + 1,
                        &self,
                    ));
                }
                let mut components = Vec::with_capacity(
                    sequence
                        .size_hint()
                        .unwrap_or(0)
                        .min(RelativePath::MAX_COMPONENTS),
                );
                while let Some(component) = sequence.next_element::<PathName>()? {
                    if components.len() == RelativePath::MAX_COMPONENTS {
                        return Err(de::Error::invalid_length(
                            RelativePath::MAX_COMPONENTS + 1,
                            &self,
                        ));
                    }
                    components.push(component);
                }
                RelativePath::new(components).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_seq(RelativePathVisitor)
    }
}

/// Reports a path exceeding the absolute portable component ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("relative path exceeds the absolute 4096-component decoder ceiling")]
pub struct InvalidRelativePath;

/// Selects a logical resource without exposing node-local implementation data.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind", deny_unknown_fields)]
pub enum Selector {
    /// Selects one exact logical resource.
    Resource {
        /// Exact portable resource identity.
        resource: ResourceId,
    },
    /// Selects one exact immutable tree descriptor.
    Tree {
        /// Exact type, digest, and encoded size.
        tree: ObjectDescriptor,
    },
    /// Selects one byte-exact subtree of a named export.
    Path {
        /// Logical export identity.
        export: ExportId,
        /// Inclusive relative path prefix.
        prefix: RelativePath,
    },
    /// Selects one registered profile predicate and immutable body.
    Profile {
        /// Registered predicate semantics and version.
        feature: FeatureRef,
        /// Immutable profile-specific selector body.
        body: ObjectDescriptor,
    },
}

impl Selector {
    /// Reports whether this grant selector includes `requested`.
    ///
    /// Exact-resource, tree, and profile selectors require equality. A path
    /// selector includes equal or deeper paths only within the same export.
    #[must_use]
    pub fn contains(&self, requested: &Self) -> bool {
        match (self, requested) {
            (
                Self::Resource { resource: granted },
                Self::Resource {
                    resource: requested,
                },
            ) => granted == requested,
            (Self::Tree { tree: granted }, Self::Tree { tree: requested }) => granted == requested,
            (
                Self::Path {
                    export: granted_export,
                    prefix: granted_prefix,
                },
                Self::Path {
                    export: requested_export,
                    prefix: requested_prefix,
                },
            ) => granted_export == requested_export && granted_prefix.contains(requested_prefix),
            (
                Self::Profile {
                    feature: granted_feature,
                    body: granted_body,
                },
                Self::Profile {
                    feature: requested_feature,
                    body: requested_body,
                },
            ) => granted_feature == requested_feature && granted_body == requested_body,
            _ => false,
        }
    }
}

struct BoundedBytesVisitor<const MIN: usize, const MAX: usize>;

impl<'de, const MIN: usize, const MAX: usize> Visitor<'de> for BoundedBytesVisitor<MIN, MAX> {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a byte string of length {MIN}..={MAX}")
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if (MIN..=MAX).contains(&value.len()) {
            Ok(value.to_vec())
        } else {
            Err(E::invalid_length(value.len(), &self))
        }
    }

    fn visit_borrowed_bytes<E>(self, value: &'de [u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_bytes(value)
    }

    fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if (MIN..=MAX).contains(&value.len()) {
            Ok(value)
        } else {
            Err(E::invalid_length(value.len(), &self))
        }
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if sequence.size_hint().is_some_and(|length| length > MAX) {
            return Err(de::Error::invalid_length(MAX + 1, &self));
        }
        let mut value = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX));
        while let Some(byte) = sequence.next_element::<u8>()? {
            if value.len() == MAX {
                return Err(de::Error::invalid_length(MAX + 1, &self));
            }
            value.push(byte);
        }
        if value.len() < MIN {
            return Err(de::Error::invalid_length(value.len(), &self));
        }
        Ok(value)
    }
}

fn deserialize_bounded_bytes<'de, D, const MIN: usize, const MAX: usize>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_bytes(BoundedBytesVisitor::<MIN, MAX>)
}

fn deserialize_exact_bytes<'de, D, const LENGTH: usize>(
    deserializer: D,
) -> Result<[u8; LENGTH], D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = deserialize_bounded_bytes::<D, LENGTH, LENGTH>(deserializer)?;
    bytes.try_into().map_err(|value: Vec<u8>| {
        de::Error::invalid_length(value.len(), &BoundedBytesVisitor::<LENGTH, LENGTH>)
    })
}

#[cfg(test)]
mod tests {
    use super::{ObjectDigest, Operation, OperationSet, PathName, RelativePath, Selector};
    use crate::{ExportId, ResourceId};

    fn name(value: &[u8]) -> PathName {
        match PathName::new(value) {
            Ok(name) => name,
            Err(error) => panic!("static test name must be valid: {error}"),
        }
    }

    fn path(components: Vec<PathName>) -> RelativePath {
        match RelativePath::new(components) {
            Ok(path) => path,
            Err(error) => panic!("static test path must be valid: {error}"),
        }
    }

    #[test]
    fn unknown_operation_bits_fail_closed() {
        assert!(OperationSet::from_bits(1 << 15).is_err());
        assert!(OperationSet::ALL.contains(Operation::LiveKernelCoupledRead));
        assert!(OperationSet::one(Operation::ContentRead).is_subset_of(
            OperationSet::one(Operation::ContentRead).union(OperationSet::one(Operation::Discover))
        ));
    }

    #[test]
    fn path_selector_contains_only_deeper_paths_in_the_same_export() {
        let export = ExportId::new();
        let granted = Selector::Path {
            export,
            prefix: path(vec![name(b"src")]),
        };
        let child = Selector::Path {
            export,
            prefix: path(vec![name(b"src"), name(b"lib")]),
        };
        let sibling = Selector::Path {
            export,
            prefix: path(vec![name(b"tests")]),
        };
        let other = Selector::Path {
            export: ExportId::new(),
            prefix: path(vec![name(b"src"), name(b"lib")]),
        };

        assert!(granted.contains(&child));
        assert!(!granted.contains(&sibling));
        assert!(!granted.contains(&other));
    }

    #[test]
    fn path_names_preserve_non_utf8_bytes_in_cbor() {
        let path_name = name(&[0xff, b'a']);
        let mut encoded = Vec::new();
        let result = ciborium::into_writer(&path_name, &mut encoded);

        assert!(result.is_ok());
        assert_eq!(encoded, vec![0x42, 0xff, b'a']);
        assert_eq!(
            ciborium::from_reader::<PathName, _>(encoded.as_slice()).ok(),
            Some(path_name)
        );
    }

    #[test]
    fn invalid_path_names_are_rejected() {
        for invalid in [&b""[..], &b"."[..], &b".."[..], &b"a/b"[..], &b"a\0b"[..]] {
            assert!(PathName::new(invalid).is_err());
        }
    }

    #[test]
    fn digest_text_has_one_canonical_spelling() {
        let digest = ObjectDigest::from_bytes([0xab; 32]);
        let text = digest.to_string();

        assert_eq!(text.parse::<ObjectDigest>(), Ok(digest));
        assert!(text.to_ascii_uppercase().parse::<ObjectDigest>().is_err());
    }

    #[test]
    fn selector_kinds_do_not_cross_match() {
        let resource = Selector::Resource {
            resource: ResourceId::new(),
        };
        let path = Selector::Path {
            export: ExportId::new(),
            prefix: RelativePath::default(),
        };

        assert!(!resource.contains(&path));
    }

    #[test]
    fn validated_feature_and_path_decoders_fail_closed() {
        let feature = serde_json::from_str::<super::FeatureRef>(
            r#"{"namespace":"Bad.Feature","major":1,"minor":0}"#,
        );
        assert!(feature.is_err());

        let oversized = vec![name(b"a"); RelativePath::MAX_COMPONENTS + 1];
        assert!(RelativePath::new(oversized).is_err());
    }
}
