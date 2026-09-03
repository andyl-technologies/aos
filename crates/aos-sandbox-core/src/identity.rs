//! Opaque identities for portable sandbox resources.
//!
//! Every identity is an unpredictable UUIDv4 represented as 16 bytes in AOS
//! portable CBOR and as a canonical lowercase hyphenated UUID in human-readable
//! protocols. Distinct Rust types prevent accidentally using, for example, a
//! sandbox identifier where an incarnation identifier is required.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

/// Reports that text is not the canonical representation of an AOS identity.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("identity must be a canonical lowercase hyphenated UUID")]
pub struct ParseIdentityError;

struct UuidBytesVisitor;

impl<'de> Visitor<'de> for UuidBytesVisitor {
    type Value = Uuid;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an exact 16-byte AOS identity")
    }

    fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Uuid::from_slice(bytes).map_err(E::custom)
    }

    fn visit_borrowed_bytes<E>(self, bytes: &'de [u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_bytes(bytes)
    }

    fn visit_byte_buf<E>(self, bytes: Vec<u8>) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_bytes(&bytes)
    }
}

fn deserialize_uuid_bytes<'de, D>(deserializer: D) -> Result<Uuid, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_bytes(UuidBytesVisitor)
}

macro_rules! define_identity {
    ($name:ident, $summary:literal) => {
        #[doc = $summary]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a new unpredictable identity.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Constructs an identity from its exact portable 16-byte value.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(Uuid::from_bytes(bytes))
            }

            /// Returns the exact 16 bytes used by portable formats.
            #[must_use]
            pub const fn into_bytes(self) -> [u8; 16] {
                self.0.into_bytes()
            }

            /// Borrows the exact 16 bytes used by portable formats.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.as_hyphenated().fmt(formatter)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0.as_hyphenated())
                    .finish()
            }
        }

        impl FromStr for $name {
            type Err = ParseIdentityError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                let parsed = Uuid::parse_str(input).map_err(|_| ParseIdentityError)?;
                if parsed.as_hyphenated().to_string() != input {
                    return Err(ParseIdentityError);
                }

                Ok(Self(parsed))
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                if serializer.is_human_readable() {
                    serializer.collect_str(self)
                } else {
                    serializer.serialize_bytes(self.as_bytes())
                }
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                if deserializer.is_human_readable() {
                    let text = String::deserialize(deserializer)?;
                    text.parse().map_err(serde::de::Error::custom)
                } else {
                    deserialize_uuid_bytes(deserializer).map(Self)
                }
            }
        }
    };
}

define_identity!(ProjectId, "Identifies a sandbox project authority domain.");
define_identity!(SandboxId, "Identifies a durable logical sandbox.");
define_identity!(
    IncarnationId,
    "Identifies one realization of a logical sandbox."
);
define_identity!(
    NodeId,
    "Identifies a node participating in sandbox placement."
);
define_identity!(
    OperationId,
    "Identifies one durable asynchronous operation."
);
define_identity!(
    ExecutionId,
    "Identifies one execution admitted to a sandbox."
);
define_identity!(SnapshotId, "Identifies one durable sandbox snapshot.");
define_identity!(ViewId, "Identifies one logical filesystem view.");
define_identity!(
    AttachmentId,
    "Identifies one attachment of a view to a consumer."
);
define_identity!(ExportId, "Identifies one named sandbox export.");

#[cfg(test)]
mod tests {
    use super::{IncarnationId, SandboxId};

    #[test]
    fn byte_round_trip_preserves_identity() {
        let bytes = [0x5a; 16];
        let id = SandboxId::from_bytes(bytes);

        assert_eq!(id.into_bytes(), bytes);
    }

    #[test]
    fn text_requires_the_single_canonical_spelling() {
        let canonical = "00112233-4455-6677-8899-aabbccddeeff";
        let id = canonical.parse::<SandboxId>();

        assert_eq!(id.map(|value| value.to_string()), Ok(canonical.to_owned()));
        assert!(
            "00112233445566778899aabbccddeeff"
                .parse::<SandboxId>()
                .is_err()
        );
        assert!(
            "00112233-4455-6677-8899-AABBCCDDEEFF"
                .parse::<SandboxId>()
                .is_err()
        );
    }

    #[test]
    fn distinct_types_share_encoding_without_being_interchangeable() {
        let bytes = [0x11; 16];
        let sandbox = SandboxId::from_bytes(bytes);
        let incarnation = IncarnationId::from_bytes(bytes);

        assert_eq!(sandbox.as_bytes(), incarnation.as_bytes());
        assert_ne!(sandbox.to_string(), SandboxId::new().to_string());
    }

    #[test]
    fn human_readable_serde_uses_canonical_text() {
        let id = SandboxId::from_bytes([0x22; 16]);
        let encoded = serde_json::to_string(&id);

        assert_eq!(
            encoded.ok().as_deref(),
            Some("\"22222222-2222-2222-2222-222222222222\"")
        );
    }

    #[test]
    fn binary_serde_uses_an_exact_byte_string() {
        let id = SandboxId::from_bytes([0x33; 16]);
        let mut encoded = Vec::new();
        let encode_result = ciborium::into_writer(&id, &mut encoded);

        assert!(encode_result.is_ok());
        assert_eq!(encoded.first(), Some(&0x50));
        assert_eq!(encoded.get(1..), Some(id.as_bytes().as_slice()));

        let decoded = ciborium::from_reader::<SandboxId, _>(encoded.as_slice());
        assert_eq!(decoded.ok(), Some(id));
    }
}
