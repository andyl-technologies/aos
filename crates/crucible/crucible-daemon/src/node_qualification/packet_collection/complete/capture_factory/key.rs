//! Matches one returned key to its actual retained installed schema without copies.
//!
//! This closed data comparison runs beneath the factory's real source/plan/Host
//! currentness checks. Equal labels or a successful comparison grant no native
//! capability, preflight row, capture ticket or restoration permission.

use crucible_node_format::{SchemaRef, Version};

pub(super) fn matches_installed_schema_data(
    actual: &SchemaRef,
    installed: &[SchemaRef],
    schema_id: &str,
    schema_version: Version,
) -> bool {
    let mut matching = installed
        .iter()
        .filter(|schema| schema.id.as_str() == schema_id && schema.version == schema_version);
    let Some(original) = matching.next() else {
        return false;
    };
    matching.next().is_none() && actual == original && actual.extensions.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::{Id, canonical};

    #[test]
    fn selected_owned11_key_matches_exact_original_but_refuses_stale_or_altered_data()
    -> Result<(), Box<dyn std::error::Error>> {
        // These are the actual source-authored data definitions, not a modeled
        // native issuer or a constructed source/capture permission.
        let schema =
            crucible_node_transport::reference_packet::service::native_owned11_snapshot_schema()?;
        let installed = [schema.clone()];
        let id = "source-owned.packet-native-continuation/11";
        assert!(matches_installed_schema_data(&schema, &installed, id, 11));
        let mut wrong = schema.clone();
        wrong.definition = canonical::content_ref(b"changed schema body", "application/json")?;
        assert!(!matches_installed_schema_data(&wrong, &installed, id, 11));
        wrong = schema.clone();
        wrong.id = Id::new("source-owned.packet-native-continuation/5")?;
        wrong.version = 5;
        assert!(!matches_installed_schema_data(&wrong, &installed, id, 11));
        assert!(!matches_installed_schema_data(&schema, &[], id, 11));
        assert!(!matches_installed_schema_data(
            &schema,
            &[schema.clone(), schema.clone()],
            id,
            11
        ));
        wrong = schema.clone();
        wrong
            .extensions
            .insert("unknown".to_owned(), serde_json::Value::Null);
        assert!(!matches_installed_schema_data(
            &wrong,
            &[wrong.clone()],
            id,
            11
        ));
        assert!(!matches_installed_schema_data(&schema, &installed, id, 10));
        Ok(())
    }

    #[test]
    fn host2_key_stays_exact_and_cannot_select_a_native_schema()
    -> Result<(), Box<dyn std::error::Error>> {
        let schema = crucible_engine::node_contract::host_scheduling_complete_continuation_schema()
            .map_err(|error| std::io::Error::other(error.reason))?;
        assert!(matches_installed_schema_data(
            &schema,
            std::slice::from_ref(&schema),
            "source-owned.host-scheduling-continuation/2",
            2
        ));
        let native =
            crucible_node_transport::reference_packet::service::native_owned11_snapshot_schema()?;
        assert!(!matches_installed_schema_data(
            &schema,
            &[native],
            "source-owned.host-scheduling-continuation/2",
            2
        ));
        Ok(())
    }

    #[test]
    fn all_legacy_capture_keys_match_only_their_exact_selected_definition()
    -> Result<(), Box<dyn std::error::Error>> {
        use crucible_node_transport::reference_packet::service::{
            native_owned11_snapshot_schema, native_owned13_snapshot_schema,
            native_snapshot::native_owned14_snapshot_schema,
        };
        let schemas = [
            native_owned11_snapshot_schema()?,
            native_owned13_snapshot_schema()?,
            native_owned14_snapshot_schema()?,
        ];
        for (index, schema) in schemas.iter().enumerate() {
            assert!(matches_installed_schema_data(
                schema,
                &schemas,
                schema.id.as_str(),
                schema.version
            ));
            for (other_index, other) in schemas.iter().enumerate() {
                if index != other_index {
                    assert!(!matches_installed_schema_data(
                        schema,
                        &schemas,
                        other.id.as_str(),
                        other.version
                    ));
                }
            }
            let mut changed = schema.clone();
            changed.definition =
                canonical::content_ref(b"changed selected grammar", "application/json")?;
            assert!(!matches_installed_schema_data(
                &changed,
                &schemas,
                schema.id.as_str(),
                schema.version
            ));
        }
        Ok(())
    }
}
