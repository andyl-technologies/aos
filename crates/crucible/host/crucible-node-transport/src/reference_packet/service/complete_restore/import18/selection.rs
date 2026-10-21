//! Checks an explicitly requested import18 mechanism against real launch rosters.
//!
//! ```text
//! mechanism = "SourceSignedImport18"
//! ```
//!
//! A requested mechanism is DATA. The actual Core factory/Source-purpose/Birth
//! member supplies it explicitly; no format, media, Source family, old selection
//! or fitting row is promoted into that request or into permission.

use super::*;
use crate::reference_packet::service::{PacketNative5CaptureProfile, PacketNative5SourceLaunch};
use std::mem::size_of;

/// Identifies the new requested mechanism independently of transfer12 selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PacketNativeImport18Selection {
    /// Requires genuine new Source/Birth, original escrow and full import18 chain.
    SourceSignedImport18,
}

impl PacketNativeImport18Selection {
    /// Checks actual immutable full declarations after independent factory admission.
    ///
    /// The caller already authenticates this actual typed launch/base5/Source
    /// custody and independently runs its unchanged baseline launch validators.
    /// This method checks only explicit new mechanism declarations. It never
    /// selects a Source purpose, creates a Birth/member or issues phase funding.
    ///
    /// # Errors
    /// Refuses a different launch edition/profile, absent baseline metadata,
    /// empty binding roster, duplicate/missing/changed full18 schemas or features.
    pub fn authenticate_launch_data(
        self,
        launch: &PacketNative5SourceLaunch,
    ) -> Result<(), ProviderError> {
        if launch.schema_version != 5
            || launch.protocol_metadata_limits.is_none()
            || launch.native_codec_metadata_extent.is_none()
            || launch.ack_emitter_selection.is_none()
            || !matches!(
                launch.capture_profile,
                PacketNative5CaptureProfile::OwnedProtocol11 { .. }
            )
            || launch.selection.realization.bindings.is_empty()
        {
            return Err(invalid());
        }
        for which in [Definition::Import, Definition::Stage] {
            // Sequential factory lifetimes are intentional: no first schema
            // owner survives into the second factory's DOM/JCS window.
            let expected = match which {
                Definition::Import => native_import18_schema_data()?,
                Definition::Stage => native_import18_stage_schema_data()?,
            };
            full_definition(&launch.selection.provider.implementation.formats, &expected)?;
            for binding in &launch.selection.realization.bindings {
                full_definition(&binding.compatibility.implementation.formats, &expected)?;
            }
            let mut count = 0usize;
            for feature in &launch.selection.provider.extensions_supported {
                if feature == &expected.id {
                    count = count.checked_add(1).ok_or_else(invalid)?;
                }
            }
            if count != 1 {
                return Err(invalid());
            }
        }
        let mut bootstrap_features = 0usize;
        for feature in &launch.selection.provider.extensions_supported {
            if feature.as_str() == bootstrap_ack::NATIVE_IMPORT18_BOOTSTRAP_FEATURE {
                bootstrap_features = bootstrap_features.checked_add(1).ok_or_else(invalid)?;
            }
        }
        if bootstrap_features != 1 {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Definition {
    Import,
    Stage,
}

/// Authenticates both immutable rosters and all three import18 feature names.
///
/// This checks declared contract DATA only. A launch must independently pass
/// its full typed comparison and explicit mechanism selection; no Source,
/// native owner or phase permission follows from these rosters.
///
/// # Errors
/// Refuses a missing, duplicate or changed definition or required feature.
pub fn authenticate_native_import18_immutable_declaration_data(
    provider: &[SchemaRef],
    binding: &[SchemaRef],
    features: &[Id],
) -> Result<(), ProviderError> {
    for which in [Definition::Import, Definition::Stage] {
        let schema = match which {
            Definition::Import => native_import18_schema_data()?,
            Definition::Stage => native_import18_stage_schema_data()?,
        };
        full_definition(provider, &schema)?;
        full_definition(binding, &schema)?;
    }
    for required in native_import18_declared_features_data() {
        if features
            .iter()
            .filter(|feature| feature.as_str() == required)
            .count()
            != 1
        {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Returns the complete immutable import18 feature roster without selection.
pub const fn native_import18_declared_features_data() -> [&'static str; 3] {
    [
        NATIVE_IMPORT18_EXTENSION,
        NATIVE_IMPORT18_STAGE_SELECTION,
        bootstrap_ack::NATIVE_IMPORT18_BOOTSTRAP_FEATURE,
    ]
}

fn full_definition(formats: &[SchemaRef], expected: &SchemaRef) -> Result<(), ProviderError> {
    let mut found = None;
    for schema in formats {
        if schema.id == expected.id && found.replace(schema).is_some() {
            return Err(invalid());
        }
    }
    if found != Some(expected) {
        return Err(invalid());
    }
    Ok(())
}

/// Prices the sequential exact compiled import18 and stage18 factory windows.
///
/// This allocation-free quote performs no launch serialization or validation.
/// Actual existing launch/Source/member owners stay independently charged.
/// Strict parser and JCS fixed controls require their defining canonical helper.
///
/// # Errors
/// Refuses checked overflow or a restriction below actual factory T plus S.
pub fn native_import18_selection_construction_storage_data(
    maximum: usize,
) -> Result<(usize, usize), ProviderError> {
    let import = native_import18_contract_storage_data(maximum)?;
    let stage = native_import18_stage_contract_storage_data(maximum)?;
    let temporary = import.0.max(stage.0);
    let scratch = native_import18_selection_counter_scratch_data()
        .checked_add(import.1.max(stage.1))
        .ok_or_else(invalid)?;
    if temporary
        .checked_add(scratch)
        .is_none_or(|value| value > maximum)
    {
        return Err(invalid());
    }
    Ok((temporary, scratch))
}

/// Names only the actual allocation-free compiled-definition quote controls.
///
/// This is the fixed prewalk admitted before construction_storage_data; it
/// does not invoke a schema factory, observe a launch or admit its execution.
pub fn native_import18_selection_prewalk_data() -> usize {
    use crate::retained_metadata::serialization_storage::original_json_value_storage_extent_counter_scratch_data;

    original_json_value_storage_extent_counter_scratch_data()
        + size_of::<(usize, usize)>() * 3
        + size_of::<Result<(usize, usize), ProviderError>>()
        + size_of::<usize>() * 3
}

/// Names actual borrowed launch, roster, enum and equality controls.
pub fn native_import18_selection_counter_scratch_data() -> usize {
    size_of::<&PacketNative5SourceLaunch>()
        + size_of::<PacketNativeImport18Selection>()
        + size_of::<[Definition; 2]>()
        + size_of::<std::array::IntoIter<Definition, 2>>()
        + size_of::<std::slice::Iter<'static, SchemaRef>>()
        + size_of::<Option<&SchemaRef>>()
        + size_of::<std::slice::Iter<'static, Id>>()
        + size_of::<std::slice::Iter<'static, crucible_node_format::schema::NodeBinding>>()
        + size_of::<usize>()
        + size_of::<Result<(), ProviderError>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immutable_import18_rosters_require_both_full_definitions_and_all_features() {
        let formats = vec![
            native_import18_schema_data().unwrap(),
            native_import18_stage_schema_data().unwrap(),
        ];
        let features: Vec<_> = native_import18_declared_features_data()
            .into_iter()
            .map(|feature| Id::new(feature).unwrap())
            .collect();
        authenticate_native_import18_immutable_declaration_data(&formats, &formats, &features)
            .unwrap();
        formats[0]
            .definition
            .verify(&native_import18_contract_data().unwrap())
            .unwrap();
        formats[1]
            .definition
            .verify(&native_import18_stage_contract_data().unwrap())
            .unwrap();

        for side in 0..2 {
            for index in 0..formats.len() {
                let mut missing = formats.clone();
                missing.remove(index);
                let mut duplicate = formats.clone();
                duplicate.push(formats[index].clone());
                let mut changed = formats.clone();
                changed[index].definition =
                    canonical::content_ref(b"changed", "application/json").unwrap();
                for altered in [&missing, &duplicate, &changed] {
                    let mut rosters = [&formats, &formats];
                    rosters[side] = altered;
                    assert!(
                        authenticate_native_import18_immutable_declaration_data(
                            rosters[0], rosters[1], &features
                        )
                        .is_err()
                    );
                }
            }
        }
        for index in 0..features.len() {
            let mut missing = features.clone();
            missing.remove(index);
            let mut duplicate = features.clone();
            duplicate.push(features[index].clone());
            assert!(
                authenticate_native_import18_immutable_declaration_data(
                    &formats, &formats, &missing
                )
                .is_err()
            );
            assert!(
                authenticate_native_import18_immutable_declaration_data(
                    &formats, &formats, &duplicate
                )
                .is_err()
            );
        }
    }

    #[test]
    fn requested_mechanism_does_not_accept_legacy_selection_aliases() {
        let actual = PacketNativeImport18Selection::SourceSignedImport18;
        assert_eq!(
            serde_json::to_string(&actual).unwrap(),
            "\"SourceSignedImport18\""
        );
        for raw in [
            "\"SourceSignedTransfer12\"",
            "\"SourceSignedOwned11\"",
            "null",
            "{}",
        ] {
            assert!(serde_json::from_str::<PacketNativeImport18Selection>(raw).is_err());
        }
    }

    #[test]
    fn full_definition_rejects_missing_duplicate_and_changed_reference() {
        let expected = native_import18_schema_data().unwrap();
        full_definition(std::slice::from_ref(&expected), &expected).unwrap();
        assert!(full_definition(&[], &expected).is_err());
        assert!(full_definition(&[expected.clone(), expected.clone()], &expected).is_err());
        let mut changed = expected.clone();
        changed.definition.length = U64::new(changed.definition.length.get() + 1);
        assert!(full_definition(&[changed], &expected).is_err());
    }
}
