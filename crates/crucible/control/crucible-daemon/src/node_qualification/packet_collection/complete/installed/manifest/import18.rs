//! Decodes only the explicit new installation18 mechanism envelope.
//!
//! The complete baseline7 remains installation DATA. Its old Source purpose is
//! never constructed: the distinct fresh installer binds the actual import18
//! declaration only after its real typed Launch5 exists and before bank reserve.
//! This decoder supplies no native row, ticket, lease, model or Ready authority.
//!
//! ```json
//! {"schema":"crucible.complete-scene.installation/8",
//!  "mechanism":"SourceSignedImport18", "baseline":{"schema":"crucible.complete-scene.installation/7"}}
//! ```
//!
//! The baseline shown above is abbreviated; every complete7 field is mandatory.

use super::*;
use crucible_node_transport::reference_packet::service::complete_restore::import18::PacketNativeImport18Selection;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    mechanism: PacketNativeImport18Selection,
    baseline: serde_json::Value,
}

pub(in super::super) fn load_import18(
    pin: &InstalledCompleteSceneManifest,
) -> Result<(Manifest, PacketNativeImport18Selection), QualificationError> {
    let value = read_pinned_value(pin)?;
    let envelope = decode_envelope(value)?;
    mechanism::authenticate_edition_data(&envelope.baseline)?;
    let baseline: Manifest = serde_json::from_value(envelope.baseline)
        .map_err(crucible_node_format::ContractError::from)?;
    validate_declaration(&baseline)?;
    Ok((baseline, envelope.mechanism))
}

fn decode_envelope(value: serde_json::Value) -> Result<Envelope, QualificationError> {
    let envelope: Envelope =
        serde_json::from_value(value).map_err(crucible_node_format::ContractError::from)?;
    if envelope.schema != "crucible.complete-scene.installation/8"
        || envelope
            .baseline
            .get("schema")
            .and_then(serde_json::Value::as_str)
            != Some("crucible.complete-scene.installation/7")
    {
        return Err(refused());
    }
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> serde_json::Value {
        serde_json::json!({
            "schema":"crucible.complete-scene.installation/8",
            "mechanism":"SourceSignedImport18",
            "baseline":{"schema":"crucible.complete-scene.installation/7"}
        })
    }

    #[test]
    fn distinct_header_is_data_and_old_editions_never_select_it() {
        let value = envelope();
        let decoded = decode_envelope(value.clone()).unwrap();
        assert_eq!(
            decoded.mechanism,
            PacketNativeImport18Selection::SourceSignedImport18
        );
        assert!(mechanism::authenticate_edition_data(&value).is_err());
        // A complete baseline is still mandatory after the new closed header.
        assert!(serde_json::from_value::<Manifest>(decoded.baseline).is_err());

        for old in 1..=7 {
            let mut changed = value.clone();
            changed["schema"] =
                serde_json::json!(format!("crucible.complete-scene.installation/{old}"));
            assert!(decode_envelope(changed).is_err());
        }
    }

    #[test]
    fn missing_foreign_and_legacy_selector_fields_refuse() {
        for name in ["schema", "mechanism", "baseline"] {
            let mut value = envelope();
            value.as_object_mut().unwrap().remove(name);
            assert!(decode_envelope(value).is_err());
        }
        for selector in [
            serde_json::Value::Null,
            serde_json::json!("SourceSignedTransfer12"),
        ] {
            let mut value = envelope();
            value["mechanism"] = selector;
            assert!(decode_envelope(value).is_err());
        }
        let mut unknown = envelope();
        unknown["native_ready"] = serde_json::json!(true);
        assert!(decode_envelope(unknown).is_err());
        let mut old_baseline = envelope();
        old_baseline["baseline"]["schema"] =
            serde_json::json!("crucible.complete-scene.installation/6");
        assert!(decode_envelope(old_baseline).is_err());
    }
}
