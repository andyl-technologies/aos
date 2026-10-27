//! Checks object-only records through direct, borrowed and tagged decoders.

use crate::{ContentRef, HashRef, canonical};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn rejects_all_inputs<T: serde::de::DeserializeOwned>(value: Value) -> TestResult {
    assert!(T::deserialize(&value).is_err());
    assert!(T::deserialize(value.clone()).is_err());
    assert!(serde_json::from_slice::<T>(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}

#[test]
fn full_positional_references_are_refused_at_every_json_entry() -> TestResult {
    let reference = canonical::content_ref(b"content", "application/octet-stream")?;
    let hash = &reference.hash;
    let positional_hash = json!([hash.algorithm, hash.domain, hash.digest]);
    let positional_reference = json!([hash, reference.length, reference.media_type]);

    rejects_all_inputs::<HashRef>(positional_hash.clone())?;
    rejects_all_inputs::<ContentRef>(positional_reference)?;
    let mut nested = serde_json::to_value(&reference)?;
    nested["hash"] = positional_hash;
    rejects_all_inputs::<ContentRef>(nested)?;

    // The former derive accepts the complete array, so this is a full-shaped
    // protocol counterexample rather than a missing-field refusal.
    #[derive(Deserialize)]
    struct PreviousHash {
        algorithm: String,
        domain: String,
        digest: String,
    }
    let previous: PreviousHash =
        serde_json::from_value(json!([hash.algorithm, hash.domain, hash.digest]))?;
    assert_eq!(previous.algorithm, hash.algorithm);
    assert_eq!(previous.domain, hash.domain);
    assert_eq!(previous.digest, hash.digest);
    Ok(())
}

#[test]
fn tagged_content_buffer_cannot_bypass_the_nested_record_rule() -> TestResult {
    #[derive(Deserialize, Serialize)]
    #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
    enum Tagged {
        Reference { reference: ContentRef },
    }
    let reference = canonical::content_ref(b"content", "application/octet-stream")?;
    let original = json!({"kind":"reference", "reference":reference});

    let decoded: Tagged = serde_json::from_value(original.clone())?;
    assert_eq!(serde_json::to_value(decoded)?, original);
    let mut positional = original;
    positional["reference"] = json!([reference.hash, reference.length, reference.media_type]);

    rejects_all_inputs::<Tagged>(positional)?;
    Ok(())
}

crate::wire_record! {
    #[derive(Debug, PartialEq, Serialize)]
    struct FieldPolicies {
        #[serde(rename = "wire_name")]
        name: String,
        #[serde(default)]
        optional: Option<bool>,
        #[serde(deserialize_with = "crate::literal_json::deserialize_value")]
        literal: Value,
    }
}

#[test]
fn single_record_roster_preserves_field_attributes_and_literal_arrays() -> TestResult {
    let original = json!({
        "wire_name":"record",
        "literal":[{"$serde_json::private::RawValue":"ordinary DATA"}, null, 7]
    });

    let borrowed = FieldPolicies::deserialize(&original)?;
    let owned = FieldPolicies::deserialize(original.clone())?;
    let streamed: FieldPolicies = serde_json::from_slice(&serde_json::to_vec(&original)?)?;

    assert_eq!(borrowed, owned);
    assert_eq!(borrowed, streamed);
    assert_eq!(borrowed.name, "record");
    assert_eq!(borrowed.optional, None);
    assert_eq!(borrowed.literal, original["literal"]);

    let mut unknown = original.clone();
    unknown["unknown"] = Value::Null;
    rejects_all_inputs::<FieldPolicies>(unknown)?;
    let mut renamed = original;
    let fields = renamed.as_object_mut().unwrap();
    let name = fields.remove("wire_name").unwrap();
    fields.insert("name".into(), name);
    rejects_all_inputs::<FieldPolicies>(renamed)?;
    Ok(())
}

#[test]
fn object_golden_bytes_and_strict_field_failures_are_unchanged() -> TestResult {
    let reference = canonical::content_ref(b"content", "application/octet-stream")?;
    let expected = format!(
        r#"{{"hash":{{"algorithm":"blake3-256","domain":"cnp.blob.v1","digest":"{}"}},"length":"7","media_type":"application/octet-stream"}}"#,
        reference.hash.digest,
    );

    assert_eq!(serde_json::to_string(&reference)?, expected);
    assert_eq!(serde_json::from_str::<ContentRef>(&expected)?, reference);
    for value in [Value::Null, json!(false), json!(0), json!("reference")] {
        rejects_all_inputs::<ContentRef>(value)?;
    }
    let original = serde_json::to_value(&reference)?;
    for field in ["hash", "length", "media_type"] {
        let mut missing = original.clone();
        missing.as_object_mut().unwrap().remove(field);
        rejects_all_inputs::<ContentRef>(missing)?;
    }
    let duplicate = expected.replace(r#""length":"7""#, r#""length":"7","length":"7""#);
    assert!(serde_json::from_str::<ContentRef>(&duplicate).is_err());
    Ok(())
}

fn refuses_sequence_before_reading_fields<T: serde::de::DeserializeOwned>() {
    let mut read = false;
    let input = std::iter::once_with(|| {
        read = true;
        0u8
    });
    let decoder = serde::de::value::SeqDeserializer::<_, serde::de::value::Error>::new(input);

    assert!(T::deserialize(decoder).is_err());
    assert!(
        !read,
        "{} visited a positional field",
        std::any::type_name::<T>()
    );
}

#[test]
fn every_portable_wire_record_refuses_sequences_before_reading_fields() {
    refuses_sequence_before_reading_fields::<crate::HashRef>();
    refuses_sequence_before_reading_fields::<crate::ContentRef>();
    refuses_sequence_before_reading_fields::<crate::Position>();
    refuses_sequence_before_reading_fields::<crate::Endpoint>();
    refuses_sequence_before_reading_fields::<crate::Bound>();
    refuses_sequence_before_reading_fields::<crate::ArtifactIdentity>();
    refuses_sequence_before_reading_fields::<crate::ImplementationIdentity>();
    refuses_sequence_before_reading_fields::<crate::BindingCompatibility>();
    refuses_sequence_before_reading_fields::<crate::LiveAuthority>();
    refuses_sequence_before_reading_fields::<crate::NodeBinding>();
    refuses_sequence_before_reading_fields::<crate::NodeBindingRef>();
    refuses_sequence_before_reading_fields::<crate::OwnerBinding>();
    refuses_sequence_before_reading_fields::<crate::WorldBinding>();
    refuses_sequence_before_reading_fields::<crate::CaptureManifest>();
    refuses_sequence_before_reading_fields::<crate::CapturedOwner>();
    refuses_sequence_before_reading_fields::<crate::InputCustodyRecord>();
    refuses_sequence_before_reading_fields::<crate::ClosedGateRecord>();
    refuses_sequence_before_reading_fields::<crate::ActivationReadyRecord>();
    refuses_sequence_before_reading_fields::<crate::UnchangedCutRecord>();
    refuses_sequence_before_reading_fields::<crate::CleanupRecord>();
    refuses_sequence_before_reading_fields::<crate::AdmissionRecord>();
    refuses_sequence_before_reading_fields::<crate::SchemaRef>();
    refuses_sequence_before_reading_fields::<crate::OwnerRef>();
    refuses_sequence_before_reading_fields::<crate::LaneDescriptor>();
    refuses_sequence_before_reading_fields::<crate::PortDescriptor>();
    refuses_sequence_before_reading_fields::<crate::NodeDescriptor>();
    refuses_sequence_before_reading_fields::<crate::ConnectionDescriptor>();
    refuses_sequence_before_reading_fields::<crate::Event>();
    refuses_sequence_before_reading_fields::<crate::InputBatch>();
    refuses_sequence_before_reading_fields::<crate::InputAuthorization>();
    refuses_sequence_before_reading_fields::<crate::ObservationBatch>();
    refuses_sequence_before_reading_fields::<crate::PendingInventory>();
    refuses_sequence_before_reading_fields::<crate::PendingEntry>();
    refuses_sequence_before_reading_fields::<crate::SemanticVersion>();
    refuses_sequence_before_reading_fields::<crate::ExtensionNamespaceOwner>();
    refuses_sequence_before_reading_fields::<crate::ExtensionSelection>();
    refuses_sequence_before_reading_fields::<crate::ExtensionApplicability>();
    refuses_sequence_before_reading_fields::<crate::ExtensionLimits>();
    refuses_sequence_before_reading_fields::<crate::ExtensionDeclaration>();
    refuses_sequence_before_reading_fields::<crate::ExtensionUse>();
    refuses_sequence_before_reading_fields::<crate::NodeManifest>();
    refuses_sequence_before_reading_fields::<crate::ProviderManifest>();
    refuses_sequence_before_reading_fields::<crate::RealizationManifest>();
    refuses_sequence_before_reading_fields::<crate::ResourceLimits>();
    refuses_sequence_before_reading_fields::<crate::FacetSelection>();
    refuses_sequence_before_reading_fields::<crate::OperatingContract>();
    refuses_sequence_before_reading_fields::<crate::GuaranteeProfile>();
    refuses_sequence_before_reading_fields::<crate::CapabilityProfile>();
    refuses_sequence_before_reading_fields::<crate::StopReceipt>();
    refuses_sequence_before_reading_fields::<crate::PortBound>();
    refuses_sequence_before_reading_fields::<crate::ActivationManifest>();
    refuses_sequence_before_reading_fields::<crate::PreparedOwner>();
    refuses_sequence_before_reading_fields::<crate::ControlReceipt>();
}
