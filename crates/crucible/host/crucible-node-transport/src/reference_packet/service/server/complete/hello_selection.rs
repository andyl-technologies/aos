//! Reconciles invocation Hello selection with its immutable installed plan.
//!
//! The caller borrows this registration from its original private boot. Public
//! Hello offers never select the installed feature or envelope-key roster.

use std::{collections::BTreeMap, mem::size_of};

use crucible_node_format::{Id, IdSet, ProviderManifest};
use serde_json::Value;

use crate::{ProviderError, handshake::EXTENSION_NEGOTIATION_V1};

type Selection = (IdSet, BTreeMap<String, Id>);

/// Constructs exactly the declared feature and authenticated envelope-key sets.
///
/// # Errors
/// Refuses changed feature membership/order, duplicate keys, or keys without
/// their independently declared semantic feature.
pub(in crate::reference_packet::service) fn invocation_selection(
    provider: &ProviderManifest,
    registration: &Value,
) -> Result<Selection, ProviderError> {
    let mut features = provider.extensions_supported.clone();
    features.push(Id::new("cnp.core/1")?);
    features.push(Id::new(EXTENSION_NEGOTIATION_V1)?);
    features.sort();
    features.dedup();

    let planned = registration
        .get("features")
        .and_then(Value::as_array)
        .ok_or_else(refused)?;
    if planned.len() != features.len()
        || planned
            .iter()
            .zip(&features)
            .any(|(value, expected)| value.as_str() != Some(expected.as_str()))
    {
        return Err(refused());
    }

    let keys = registration
        .get("envelope_extensions")
        .and_then(Value::as_array)
        .ok_or_else(refused)?;
    let mut extensions = BTreeMap::new();
    let mut previous: Option<&str> = None;
    for value in keys {
        let key = value.as_str().ok_or_else(refused)?;
        if previous.is_some_and(|previous| previous >= key) {
            return Err(refused());
        }
        // Accepted keys name an already validated declaration Id or one of
        // the fixed aliases; no independent temporary Id allocation is needed.
        let feature = envelope_feature(key);
        let selected = features
            .iter()
            .find(|selected| selected.as_str() == feature)
            .ok_or_else(refused)?;
        extensions.insert(key.to_owned(), selected.clone());
        previous = Some(key);
    }
    Ok((features, extensions))
}

fn envelope_feature(key: &str) -> &str {
    use crate::reference_packet::service::{confirmation, fresh_restore_allocation};
    match key {
        confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION => {
            confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_FEATURE
        }
        fresh_restore_allocation::PACKET_FRESH_RESTORE_ALLOCATION_QUERY
        | fresh_restore_allocation::PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING => {
            fresh_restore_allocation::PACKET_FRESH_RESTORE_ALLOCATION_FEATURE
        }
        _ => key,
    }
}

/// Bounds the old compiled subset and the invocation's actual declaration.
///
/// # Errors
/// Refuses overflow while adding the two independently required core features.
pub(in crate::reference_packet::service) fn feature_count_bound(
    provider: &ProviderManifest,
) -> Result<usize, ProviderError> {
    provider
        .extensions_supported
        .len()
        .checked_add(2)
        .map(|count| count.max(19))
        .ok_or_else(refused)
}

/// Counts fixed selection and borrowed private-birth validation headers.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> usize {
    size_of::<Selection>()
        + size_of::<Option<Selection>>()
        + size_of::<Result<Option<Selection>, ProviderError>>()
        + size_of::<Result<Selection, ProviderError>>()
        + size_of::<Option<&Value>>()
        + size_of::<Result<Option<&Value>, ProviderError>>()
        + size_of::<Option<&str>>()
        + size_of::<std::slice::Iter<'static, Value>>()
        + size_of::<
            std::cell::Ref<'static, crate::reference_packet::service::ack_emitter::NativeAckBoot>,
        >()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<[usize; 8]>()
}

fn refused() -> ProviderError {
    ProviderError::Correlation(
        "native invocation Hello registration differs from installed declaration",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_packet::service::fresh_restore_allocation::*;

    fn fixture() -> (ProviderManifest, Value) {
        let (_, _, selection, _) =
            crate::reference_packet::coordinator::original_native5_controller_scope();
        let mut provider = selection.provider;
        provider
            .extensions_supported
            .push(Id::new(PACKET_FRESH_RESTORE_ALLOCATION_FEATURE).unwrap());
        provider.extensions_supported.sort();
        provider.extensions_supported.dedup();
        let mut features = provider.extensions_supported.clone();
        features.extend([
            Id::new("cnp.core/1").unwrap(),
            Id::new(EXTENSION_NEGOTIATION_V1).unwrap(),
        ]);
        features.sort();
        features.dedup();
        let mut keys = vec![
            EXTENSION_NEGOTIATION_V1,
            PACKET_FRESH_RESTORE_ALLOCATION_QUERY,
            PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING,
        ];
        keys.sort();
        (
            provider,
            serde_json::json!({"features":features,"envelope_extensions":keys}),
        )
    }

    #[test]
    fn invocation_hello_preserves_full_installed_roster_and_both_allocation_aliases() {
        let (provider, registration) = fixture();
        let (features, keys) = invocation_selection(&provider, &registration).unwrap();
        assert_eq!(
            serde_json::to_value(&features).unwrap(),
            registration["features"]
        );
        assert_eq!(
            keys[PACKET_FRESH_RESTORE_ALLOCATION_QUERY].as_str(),
            PACKET_FRESH_RESTORE_ALLOCATION_FEATURE
        );
        assert_eq!(
            keys[PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING].as_str(),
            PACKET_FRESH_RESTORE_ALLOCATION_FEATURE
        );
        assert!(features.len() <= feature_count_bound(&provider).unwrap());
        assert_eq!(
            registration["features"].as_array().unwrap().len(),
            features.len()
        );
    }

    #[test]
    fn invocation_hello_refuses_changed_membership_order_and_undeclared_keys() {
        let (provider, registration) = fixture();
        let mut missing = registration.clone();
        missing["features"].as_array_mut().unwrap().pop();
        assert!(invocation_selection(&provider, &missing).is_err());
        let mut duplicate = registration.clone();
        duplicate["features"]
            .as_array_mut()
            .unwrap()
            .push(registration["features"][0].clone());
        assert!(invocation_selection(&provider, &duplicate).is_err());
        let mut reordered = registration.clone();
        reordered["features"].as_array_mut().unwrap().swap(0, 1);
        assert!(invocation_selection(&provider, &reordered).is_err());
        let mut unknown = registration.clone();
        unknown["envelope_extensions"]
            .as_array_mut()
            .unwrap()
            .push(Value::String("uninstalled/key".into()));
        assert!(invocation_selection(&provider, &unknown).is_err());
        let mut duplicate_key = registration.clone();
        duplicate_key["envelope_extensions"]
            .as_array_mut()
            .unwrap()
            .push(registration["envelope_extensions"][0].clone());
        assert!(invocation_selection(&provider, &duplicate_key).is_err());
    }
}
