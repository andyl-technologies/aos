//! Authenticates optional immutable suffix grammar without choosing startup16.
//!
//! A captured original and its fresh target retain the same full implementation
//! identity. The original can advertise this exact grammar while its live Source
//! remains on the first-Observe declaration. This DATA check never binds or
//! renews a Source selection; complete content authentication stays in records.

use super::*;
use crucible_engine::node_adapters::cnp::CnpSemanticInstallation;
use crucible_node_transport::reference_packet::service::native_startup::{
    PACKET_RESTORATION_SUFFIX_FEATURE, authenticate_restoration_suffix_schema_data,
    restoration_suffix_contract_data, restoration_suffix_schema,
};

pub(super) fn declared_definition_data(
    selected: &CnpSemanticInstallation,
) -> Result<Option<(SchemaRef, Vec<u8>)>, QualificationError> {
    let rosters = [
        selected.provider.implementation.formats.as_slice(),
        selected
            .binding
            .compatibility
            .implementation
            .formats
            .as_slice(),
    ];
    if !rosters
        .iter()
        .any(|formats| formats.iter().any(is_suffix_schema))
        && !selected
            .provider
            .extensions_supported
            .iter()
            .any(is_suffix_feature)
    {
        return Ok(None);
    }

    authenticate_declared_rosters_data(rosters, &selected.provider.extensions_supported)?;
    Ok(Some((
        restoration_suffix_schema().map_err(|_| refused())?,
        restoration_suffix_contract_data().to_vec(),
    )))
}

fn is_suffix_schema(schema: &SchemaRef) -> bool {
    schema.id.as_str() == PACKET_RESTORATION_SUFFIX_FEATURE
}

fn is_suffix_feature(feature: &Id) -> bool {
    feature.as_str() == PACKET_RESTORATION_SUFFIX_FEATURE
}

fn authenticate_declared_rosters_data(
    rosters: [&[SchemaRef]; 2],
    features: &[Id],
) -> Result<(), QualificationError> {
    for formats in rosters {
        let mut definitions = formats.iter().filter(|schema| is_suffix_schema(schema));
        let definition = definitions.next().ok_or_else(refused)?;
        if definitions.next().is_some() {
            return Err(refused());
        }
        authenticate_restoration_suffix_schema_data(definition).map_err(|_| refused())?;
    }

    let mut features = features.iter().filter(|feature| is_suffix_feature(feature));
    if features.next().is_none() || features.next().is_some() {
        return Err(refused());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::{Extensions, U64};

    #[test]
    fn declared_suffix_requires_both_exact_rosters_and_one_feature() {
        let schema = restoration_suffix_schema().unwrap();
        let formats = [schema.clone()];
        let features = [Id::new(PACKET_RESTORATION_SUFFIX_FEATURE).unwrap()];
        let rosters = [formats.as_slice(); 2];
        authenticate_declared_rosters_data(rosters, &features).unwrap();

        for side in 0..2 {
            let mut missing = rosters;
            missing[side] = &[];
            assert!(authenticate_declared_rosters_data(missing, &features).is_err());
            let duplicated = [schema.clone(), schema.clone()];
            let mut changed = rosters;
            changed[side] = &duplicated;
            assert!(authenticate_declared_rosters_data(changed, &features).is_err());

            for axis in 0..8 {
                let mut altered = schema.clone();
                match axis {
                    0 => altered.id = Id::new("foreign.suffix/1").unwrap(),
                    1 => altered.version += 1,
                    2 => altered.definition.media_type = "application/octet-stream".into(),
                    3 => altered.definition.length = U64::new(altered.definition.length.get() + 1),
                    4 => altered.definition.hash.algorithm = "foreign".into(),
                    5 => altered.definition.hash.domain = "foreign".into(),
                    6 => altered.definition.hash.digest = "0".repeat(64),
                    7 => {
                        altered.extensions =
                            Extensions::from_iter([("foreign".into(), serde_json::Value::Null)])
                    }
                    _ => unreachable!(),
                }
                let changed_formats = [altered];
                let mut changed = rosters;
                changed[side] = &changed_formats;
                assert!(authenticate_declared_rosters_data(changed, &features).is_err());
            }
        }
        assert!(authenticate_declared_rosters_data(rosters, &[]).is_err());
        assert!(
            authenticate_declared_rosters_data(
                rosters,
                &[features[0].clone(), features[0].clone()]
            )
            .is_err()
        );
    }
}
