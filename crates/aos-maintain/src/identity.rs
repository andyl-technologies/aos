//! Validated identities shared by maintenance contracts.

use std::fmt;

use anyhow::{Result, bail};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const MAX_IDENTIFIER_BYTES: usize = 96;

macro_rules! identifier {
    ($name:ident, $summary:literal) => {
        #[doc = $summary]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Parses and validates an external identifier.
            ///
            /// # Errors
            ///
            /// Returns an error when the identifier is empty, oversized, or
            /// contains characters outside the portable identifier alphabet.
            pub fn parse(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                validate_identifier(&value)?;
                Ok(Self(value))
            }

            /// Returns the validated identifier text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

identifier!(
    UnitId,
    "Identifies one independently maintained upstream stream."
);
identifier!(FamilyId, "Identifies one upstream software family.");
identifier!(
    ComponentId,
    "Identifies one independently versioned component."
);
identifier!(
    MemberId,
    "Identifies one AOS package member of an update unit."
);
identifier!(
    SourceSlotId,
    "Identifies one source input within a component."
);
identifier!(
    ArtifactSlotId,
    "Identifies one generated fixed-output artifact."
);
identifier!(
    CohortId,
    "Identifies an explicitly atomic multi-unit campaign cohort."
);
identifier!(RunId, "Identifies one durable maintenance run.");
identifier!(OperationId, "Identifies one typed controller operation.");

fn validate_identifier(value: &str) -> Result<()> {
    if value.is_empty() {
        bail!("identifier must not be empty");
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        bail!("identifier exceeds {MAX_IDENTIFIER_BYTES} bytes");
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+' | b':')
    }) {
        bail!("identifier contains a non-portable character");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_round_trip_through_json() -> Result<()> {
        let unit = UnitId::parse("bazel-8")?;
        let bytes = serde_json::to_vec(&unit)?;
        assert_eq!(serde_json::from_slice::<UnitId>(&bytes)?, unit);
        Ok(())
    }

    #[test]
    fn identifiers_reject_paths_controls_and_oversize_values() {
        assert!(UnitId::parse("").is_err());
        assert!(UnitId::parse("../bazel").is_err());
        assert!(UnitId::parse("bazel\n8").is_err());
        assert!(UnitId::parse("x".repeat(MAX_IDENTIFIER_BYTES + 1)).is_err());
    }
}
