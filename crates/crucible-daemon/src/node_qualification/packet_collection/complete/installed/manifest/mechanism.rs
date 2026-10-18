//! Separates preparation, legacy full mechanism and invocation snapshot declarations.
//!
//! ```json
//! {"schema":"crucible.complete-scene.installation/2", "mechanism":{
//!   "complete_restore":"SourceSignedTransfer12",
//!   "restore_input_emitter":"CanonicalSdkRestoreInputs12",
//!   "fresh_restore_allocation":"completed_admit13"}}
//! ```
//!
//! This declaration selects real compiled constructors before private birth. It
//! supplies no startup allocation permission, active runtime or archive ticket.
//! Edition three retains this exact tuple and additionally requires the full
//! compiled outer14 definition in both immutable format rosters and content.
//! Editions one and two cannot acquire that declaration implicitly.

use super::*;
use crucible::node_adapters::cnp::PacketCompleteSemanticSource;
use crucible_node_provider::reference_packet::service::{
    complete_restore::{
        PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection,
    },
    fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection,
};

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::node_qualification::packet_collection::complete::installed) struct CompleteMechanism {
    pub(in crate::node_qualification::packet_collection::complete::installed) complete_restore:
        PacketNative5CompleteRestoreSelection,
    pub(in crate::node_qualification::packet_collection::complete::installed) restore_input_emitter:
        PacketNative5RestoreInputEmitterSelection,
    pub(in crate::node_qualification::packet_collection::complete::installed) fresh_restore_allocation:
        PacketNative5FreshRestoreAllocationSelection,
}

pub(super) fn authenticate_edition_data(
    value: &serde_json::Value,
) -> Result<(), QualificationError> {
    let object = value.as_object().ok_or_else(refused)?;
    if object.get("schema").and_then(serde_json::Value::as_str)
        == Some("crucible.complete-scene.installation/7")
    {
        if !object
            .get("maximum_coordinator_records")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|maximum| maximum >= 2 && usize::try_from(maximum).is_ok())
        {
            return Err(refused());
        }
    } else if object.contains_key("maximum_coordinator_records") {
        // Presence under an old edition, including null, cannot extend that
        // edition's closed identity or silently infer a new lifetime policy.
        return Err(refused());
    }
    match object.get("schema").and_then(serde_json::Value::as_str) {
        Some("crucible.complete-scene.installation/1") if !object.contains_key("mechanism") => {
            Ok(())
        }
        Some(
            "crucible.complete-scene.installation/2" | "crucible.complete-scene.installation/3",
        ) if object
            .get("mechanism")
            .is_some_and(serde_json::Value::is_object) =>
        {
            Ok(())
        }
        Some(
            "crucible.complete-scene.installation/5"
            | "crucible.complete-scene.installation/6"
            | "crucible.complete-scene.installation/7",
        ) if object
            .get("mechanism")
            .is_some_and(serde_json::Value::is_object) =>
        {
            Ok(())
        }
        Some("crucible.complete-scene.installation/4")
            if object
                .get("mechanism")
                .is_some_and(serde_json::Value::is_object) =>
        {
            Ok(())
        }
        _ => Err(refused()),
    }
}

pub(super) fn authenticate_selection_data(
    schema: &str,
    selected: Option<CompleteMechanism>,
) -> Result<(), QualificationError> {
    match (schema, selected) {
        ("crucible.complete-scene.installation/1", None) => Ok(()),
        (
            "crucible.complete-scene.installation/2" | "crucible.complete-scene.installation/3",
            Some(selected),
        ) => selected.authenticate(),
        ("crucible.complete-scene.installation/4", Some(selected)) => selected.authenticate(),
        (
            "crucible.complete-scene.installation/5"
            | "crucible.complete-scene.installation/6"
            | "crucible.complete-scene.installation/7",
            Some(selected),
        ) => selected.authenticate(),
        _ => Err(refused()),
    }
}

/// Checks the explicit format declaration before Source banks or acquisition.
///
/// This compares package DATA only. Both later invocation purposes retain these
/// same immutable rosters; the declaration cannot select purpose or issue credit.
///
/// # Errors
/// Refuses missing, duplicate or changed outer14 definitions, or outer14 under
/// an older installation edition.
pub(super) fn authenticate_snapshot_declaration_data(
    schema: &str,
    rosters: [(&[SchemaRef], &[SchemaRef]); 3],
    content: &[Content],
) -> Result<(), QualificationError> {
    const SNAPSHOT: &str = "source-owned.packet-native-continuation/14";
    if matches!(
        schema,
        "crucible.complete-scene.installation/1" | "crucible.complete-scene.installation/2"
    ) {
        if rosters.iter().any(|(provider, binding)| {
            provider
                .iter()
                .chain(binding.iter())
                .any(|one| one.id.as_str() == SNAPSHOT)
        }) {
            return Err(refused());
        }
        return Ok(());
    }
    if schema != "crucible.complete-scene.installation/3" {
        return Err(refused());
    }

    use crucible_node_provider::reference_packet::service::native_snapshot::{
        native_owned14_snapshot_contract, native_owned14_snapshot_schema,
    };
    // The compiled schema constructor's temporary definition drops before this
    // one retained 2606-byte definition is built. No package-controlled sizing,
    // new content, format repair or permission is introduced here.
    let expected = native_owned14_snapshot_schema().map_err(|_| refused())?;
    let body = native_owned14_snapshot_contract().map_err(|_| refused())?;
    expected.definition.verify(&body)?;
    for (provider, binding) in rosters {
        authenticate_snapshot_roster_data(provider, &expected)?;
        authenticate_snapshot_roster_data(binding, &expected)?;
    }
    let mut matching = content
        .iter()
        .filter(|row| row.reference == expected.definition);
    let row = matching.next().ok_or_else(refused)?;
    if matching.next().is_some() || row.bytes.as_slice() != body.as_slice() {
        return Err(refused());
    }
    Ok(())
}

fn authenticate_snapshot_roster_data(
    formats: &[SchemaRef],
    expected: &SchemaRef,
) -> Result<(), QualificationError> {
    let mut matching = formats.iter().filter(|one| one.id == expected.id);
    if matching.next() != Some(expected) || matching.next().is_some() {
        return Err(refused());
    }
    Ok(())
}

impl CompleteMechanism {
    fn authenticate(self) -> Result<(), QualificationError> {
        if self.complete_restore != PacketNative5CompleteRestoreSelection::SourceSignedTransfer12
            || self.restore_input_emitter
                != PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12
            || self.fresh_restore_allocation
                != PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13
        {
            return Err(refused());
        }
        Ok(())
    }

    pub(in crate::node_qualification::packet_collection::complete::installed) fn bind_source(
        self,
        source: &mut PacketCompleteSemanticSource,
    ) -> Result<(), QualificationError> {
        self.authenticate()?;
        // These original binders check full provider/binding schema definitions,
        // features, origin and phase before bank/key/native construction. No
        // declaration is inserted or repaired to make a mismatched package fit.
        source
            .bind_original_complete_restore_selection(Some(self.complete_restore))
            .map_err(|_| refused())?;
        source
            .bind_original_restore_input_emitter_selection(Some(self.restore_input_emitter))
            .map_err(|_| refused())?;
        source
            .bind_original_fresh_restore_allocation_selection(Some(self.fresh_restore_allocation))
            .map_err(|_| refused())
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod invocation_declaration_tests {
    use super::*;
    use crucible_node_provider::reference_packet::service::native_snapshot::{
        native_owned14_snapshot_contract, native_owned14_snapshot_schema,
    };

    fn check(
        schema: &str,
        provider: &[SchemaRef],
        binding: &[SchemaRef],
        content: &[Content],
    ) -> bool {
        authenticate_snapshot_declaration_data(schema, [(provider, binding); 3], content).is_ok()
    }

    #[test]
    fn explicit_edition_requires_both_exact_rosters_and_original_content() {
        let expected = native_owned14_snapshot_schema().unwrap();
        let body = native_owned14_snapshot_contract().unwrap();
        let content = [Content {
            reference: expected.definition.clone(),
            bytes: Bytes::new(body.clone()),
        }];
        let formats = [expected.clone()];

        assert!(check(
            "crucible.complete-scene.installation/3",
            &formats,
            &formats,
            &content
        ));
        for member in 0..3 {
            let mut rosters = [(&formats[..], &formats[..]); 3];
            rosters[member] = (&[], &formats);
            assert!(
                authenticate_snapshot_declaration_data(
                    "crucible.complete-scene.installation/3",
                    rosters,
                    &content
                )
                .is_err()
            );
        }
        for missing in [true, false] {
            let (provider, binding) = if missing {
                (&[][..], &formats[..])
            } else {
                (&formats[..], &[][..])
            };
            assert!(!check(
                "crucible.complete-scene.installation/3",
                provider,
                binding,
                &content
            ));
        }
        assert!(!check(
            "crucible.complete-scene.installation/3",
            &formats,
            &formats,
            &[]
        ));
        let changed = [Content {
            reference: expected.definition.clone(),
            bytes: Bytes::new(b"changed".to_vec()),
        }];
        assert!(!check(
            "crucible.complete-scene.installation/3",
            &formats,
            &formats,
            &changed
        ));
        let duplicate = [expected.clone(), expected.clone()];
        assert!(!check(
            "crucible.complete-scene.installation/3",
            &duplicate,
            &formats,
            &content
        ));
        assert!(!check(
            "crucible.complete-scene.installation/3",
            &formats,
            &duplicate,
            &content
        ));
        let duplicate_content = [
            Content {
                reference: expected.definition.clone(),
                bytes: Bytes::new(body.clone()),
            },
            Content {
                reference: expected.definition.clone(),
                bytes: Bytes::new(body),
            },
        ];
        assert!(!check(
            "crucible.complete-scene.installation/3",
            &formats,
            &formats,
            &duplicate_content
        ));
    }

    #[test]
    fn every_full_schema_axis_refuses_independently_in_either_roster() {
        let expected = native_owned14_snapshot_schema().unwrap();
        let content = [Content {
            reference: expected.definition.clone(),
            bytes: Bytes::new(native_owned14_snapshot_contract().unwrap()),
        }];
        for axis in 0..8 {
            let mut changed = expected.clone();
            match axis {
                0 => changed.id = Id::new("foreign.snapshot/14").unwrap(),
                1 => changed.version = 13,
                2 => changed.definition.media_type = "application/octet-stream".into(),
                3 => changed.definition.length = U64::new(changed.definition.length.get() + 1),
                4 => changed.definition.hash.algorithm = "foreign".into(),
                5 => changed.definition.hash.domain = "foreign".into(),
                6 => changed.definition.hash.digest = "0".repeat(64),
                7 => {
                    changed
                        .extensions
                        .insert("unexpected".into(), serde_json::Value::Null);
                }
                _ => unreachable!(),
            }

            assert!(!check(
                "crucible.complete-scene.installation/3",
                std::slice::from_ref(&changed),
                std::slice::from_ref(&expected),
                &content
            ));
            assert!(!check(
                "crucible.complete-scene.installation/3",
                std::slice::from_ref(&expected),
                std::slice::from_ref(&changed),
                &content
            ));
        }
    }

    #[test]
    fn old_editions_remain_unselected_and_new_edition_cannot_choose_a_purpose() {
        let expected = native_owned14_snapshot_schema().unwrap();
        for schema in [
            "crucible.complete-scene.installation/1",
            "crucible.complete-scene.installation/2",
        ] {
            assert!(check(schema, &[], &[], &[]));
            assert!(!check(schema, std::slice::from_ref(&expected), &[], &[]));
            assert!(!check(schema, &[], std::slice::from_ref(&expected), &[]));
        }
        let tuple = serde_json::json!({"complete_restore":"SourceSignedTransfer12", "restore_input_emitter":"CanonicalSdkRestoreInputs12", "fresh_restore_allocation":"completed_admit13"});
        let selected: CompleteMechanism = serde_json::from_value(tuple.clone()).unwrap();
        assert!(
            authenticate_selection_data("crucible.complete-scene.installation/3", Some(selected))
                .is_ok()
        );
        assert!(
            authenticate_selection_data("crucible.complete-scene.installation/3", None).is_err()
        );
        let mut weaker = tuple.clone();
        weaker["complete_restore"] = serde_json::json!("SourceSignedOwned11");
        let weaker: CompleteMechanism = serde_json::from_value(weaker).unwrap();
        assert!(
            authenticate_selection_data("crucible.complete-scene.installation/3", Some(weaker))
                .is_err()
        );

        let mut purpose = tuple;
        purpose["purpose"] = serde_json::json!("OriginalExecution");
        assert!(serde_json::from_value::<CompleteMechanism>(purpose).is_err());
    }

    #[test]
    fn actual_installer_refuses_edition_three_missing_full_definition_before_namespace() {
        use crate::node_qualification::packet_collection::complete::{
            installed::{InstalledCompleteScene, InstalledCompleteSceneManifest},
            tests::installed_scene_declaration,
        };
        let (_original, mut declaration) = installed_scene_declaration();
        declaration["schema"] = serde_json::json!("crucible.complete-scene.installation/3");
        declaration["mechanism"] = serde_json::json!({
            "complete_restore":"SourceSignedTransfer12",
            "restore_input_emitter":"CanonicalSdkRestoreInputs12",
            "fresh_restore_allocation":"completed_admit13",
        });
        let bytes = canonical::canonical_json(&declaration).unwrap();
        let reference = canonical::content_ref(&bytes, "application/json").unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("installation.json");
        std::fs::write(&path, &bytes).unwrap();
        let pin = InstalledCompleteSceneManifest::new(path.clone(), reference).unwrap();
        let target = directory.path().join("uncreated-scene");

        assert!(InstalledCompleteScene::install(pin, target.clone()).is_err());
        assert!(!target.exists());
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
}

mod restoration_activation;
mod restoration_observation;
pub(super) fn authenticate_profile_declaration_data(
    selected: &Manifest,
) -> Result<(), QualificationError> {
    settled_recapture::authenticate_profile_declaration_data(selected)
}

#[path = "mechanism/restored_suffix.rs"]
mod restored_suffix;

#[path = "mechanism/settled_recapture.rs"]
mod settled_recapture;

#[cfg(test)]
mod coordinator_policy_tests {
    use super::*;

    #[test]
    fn only_explicit_seven_accepts_a_nonnullable_funded_coordinator_policy() {
        for edition in 1..=6 {
            let mut value = serde_json::json!({"schema":format!("crucible.complete-scene.installation/{edition}")});
            if edition != 1 {
                value["mechanism"] = serde_json::json!({});
            }
            authenticate_edition_data(&value).unwrap();
            for policy in [
                serde_json::Value::Null,
                serde_json::json!(0),
                serde_json::json!(256),
            ] {
                value["maximum_coordinator_records"] = policy;
                assert!(authenticate_edition_data(&value).is_err());
            }
        }
        let mut selected =
            serde_json::json!({"schema":"crucible.complete-scene.installation/7","mechanism":{}});
        assert!(authenticate_edition_data(&selected).is_err());
        for policy in [
            serde_json::Value::Null,
            serde_json::json!(0),
            serde_json::json!(1),
            serde_json::json!(-1),
            serde_json::json!("256"),
        ] {
            selected["maximum_coordinator_records"] = policy;
            assert!(authenticate_edition_data(&selected).is_err());
        }
        selected["maximum_coordinator_records"] = serde_json::json!(256);
        authenticate_edition_data(&selected).unwrap();
    }
}
