//! Selects captured Source and transferred spend grammars independently.
//!
//! ```text
//! source_family = "captured17" | "captured18" | "imported18"
//! native_family = "snapshot17" | "snapshot18"
//! semantic_spend_family = "legacy17" | "complete18"
//! ```
//!
//! These finite DATA labels are required operands of the new import18 binding.
//! A media match supplies no archive provenance, source ownership or parser
//! result. The consumer must run the exact corresponding full body validator.

use super::super::restored_settled18::{
    RESTORED_SETTLED_SEMANTIC_SPEND18_MEDIA, RESTORED_SETTLED_SEMANTIC_SPEND18_SCHEMA,
    RESTORED_SETTLED_SEMANTIC18_MEDIA, RESTORED_SETTLED_SEMANTIC18_SCHEMA,
    RESTORED_SETTLED_SOURCE18_SCHEMA,
};
use super::*;

/// Identifies the exact outer captured semantic-body grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PacketNativeImport18SourceFamily {
    /// Retains the original complete semantic17 family.
    #[serde(rename = "captured17")]
    Captured17,
    /// Retains semantic18 captured from genuine InitialInvocation15 lineage.
    #[serde(rename = "captured18")]
    Captured18,
    /// Retains semantic18 with a genuine completed NativeImport18 first lineage.
    #[serde(rename = "imported18")]
    Imported18,
}

impl PacketNativeImport18SourceFamily {
    /// Returns the outer semantic schema, independently of its inner Source tag.
    pub const fn schema_data(self) -> &'static str {
        match self {
            Self::Captured17 => "source-private.semantic-state-restored-settled/17",
            Self::Captured18 | Self::Imported18 => RESTORED_SETTLED_SEMANTIC18_SCHEMA,
        }
    }

    /// Returns the separately checked inner Source object schema.
    pub const fn source_schema_data(self) -> &'static str {
        match self {
            Self::Captured17 => "source-private.source-restored-settled-state/17",
            Self::Captured18 | Self::Imported18 => RESTORED_SETTLED_SOURCE18_SCHEMA,
        }
    }

    /// Returns the exact full semantic-body media type.
    pub const fn media_type_data(self) -> &'static str {
        match self {
            Self::Captured17 => "application/vnd.source-owned.packet-semantic-custody.v17+json",
            Self::Captured18 | Self::Imported18 => RESTORED_SETTLED_SEMANTIC18_MEDIA,
        }
    }

    /// Checks full-reference syntax and exact media without fetching its body.
    ///
    /// # Errors
    /// Refuses malformed, empty or differently typed references.
    pub fn authenticate_reference_data(self, reference: &ContentRef) -> Result<(), ProviderError> {
        authenticate_reference(reference, self.media_type_data())
    }
}

/// Identifies the native Snapshot grammar independently of the Source body.
///
/// A first semantic18 capture can retain native Snapshot17. Imported18 lineage
/// separately requires its genuine native18 completed owner; neither label nor
/// a matching media type constructs that owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PacketNativeImport18NativeFamily {
    /// Selects the unchanged native Snapshot17 grammar.
    #[serde(rename = "snapshot17")]
    Snapshot17,
    /// Selects the distinct native Snapshot18 grammar.
    #[serde(rename = "snapshot18")]
    Snapshot18,
}

impl PacketNativeImport18NativeFamily {
    /// Returns the exact Snapshot schema identifier and literal version.
    pub const fn snapshot_schema_data(self) -> (&'static str, u16) {
        match self {
            Self::Snapshot17 => ("source-owned.packet-native-continuation/17", 17),
            Self::Snapshot18 => ("source-owned.packet-native-continuation/18", 18),
        }
    }
}

/// Identifies the independent actual seventh-bank grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PacketNativeImport18SemanticSpendFamily {
    /// Retains the unchanged legacy semantic-spend17 body as historical DATA.
    #[serde(rename = "legacy17")]
    Legacy17,
    /// Selects complete pending, outcome and failure relations in spend18.
    #[serde(rename = "complete18")]
    Complete18,
}

impl PacketNativeImport18SemanticSpendFamily {
    /// Returns the exact seventh-bank body schema.
    pub const fn schema_data(self) -> &'static str {
        match self {
            Self::Legacy17 => "source-private.semantic-spend/17",
            Self::Complete18 => RESTORED_SETTLED_SEMANTIC_SPEND18_SCHEMA,
        }
    }

    /// Returns the exact seventh-bank body media type.
    pub const fn media_type_data(self) -> &'static str {
        match self {
            Self::Legacy17 => "application/vnd.source-owned.packet-semantic-spend.v17+json",
            Self::Complete18 => RESTORED_SETTLED_SEMANTIC_SPEND18_MEDIA,
        }
    }

    /// Checks exact media without inferring this bank from the captured Source.
    ///
    /// # Errors
    /// Refuses malformed, empty or differently typed references.
    pub fn authenticate_reference_data(self, reference: &ContentRef) -> Result<(), ProviderError> {
        authenticate_reference(reference, self.media_type_data())
    }
}

fn authenticate_reference(reference: &ContentRef, media: &str) -> Result<(), ProviderError> {
    reference.validate()?;
    if reference.length.get() == 0 || reference.media_type != media {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_families_preserve_outer_inner_and_spend_grammars() {
        let source = PacketNativeImport18SourceFamily::Captured17;
        let spend = PacketNativeImport18SemanticSpendFamily::Complete18;
        let reference = canonical::content_ref(b"{}", spend.media_type_data()).unwrap();

        assert_ne!(source.schema_data(), source.source_schema_data());
        spend.authenticate_reference_data(&reference).unwrap();
        assert!(
            PacketNativeImport18SemanticSpendFamily::Legacy17
                .authenticate_reference_data(&reference)
                .is_err()
        );
        assert!(source.authenticate_reference_data(&reference).is_err());
        assert_eq!(serde_json::to_string(&source).unwrap(), "\"captured17\"");
        assert_eq!(serde_json::to_string(&spend).unwrap(), "\"complete18\"");
    }

    #[test]
    fn first_capture18_does_not_infer_native_snapshot18() {
        let source = PacketNativeImport18SourceFamily::Captured18;
        let native = PacketNativeImport18NativeFamily::Snapshot17;

        assert_eq!(source.schema_data(), RESTORED_SETTLED_SEMANTIC18_SCHEMA);
        assert_eq!(serde_json::to_string(&source).unwrap(), "\"captured18\"");
        assert_eq!(native.snapshot_schema_data().1, 17);
        assert_eq!(serde_json::to_string(&native).unwrap(), "\"snapshot17\"");
        assert_ne!(source, PacketNativeImport18SourceFamily::Imported18);
    }

    #[test]
    fn family_tags_refuse_old_aliases_and_unknown_values() {
        for raw in ["\"17\"", "\"semantic17\"", "null", "{}"] {
            assert!(serde_json::from_str::<PacketNativeImport18SourceFamily>(raw).is_err());
            assert!(serde_json::from_str::<PacketNativeImport18NativeFamily>(raw).is_err());
            assert!(serde_json::from_str::<PacketNativeImport18SemanticSpendFamily>(raw).is_err());
        }
    }
}
