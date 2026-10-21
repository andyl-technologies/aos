//! Prices the immutable installation and policy clones for the import18 registrar.
//!
//! This is backing DATA only. The actual constructor's validation work, private
//! controls, shared registration gate, partial owners and original admission
//! must be funded separately before a fresh Handshake can be constructed.

#[path = "hello_registrar/clone_backing.rs"]
mod clone_backing;

use crate::ProviderError;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::import18::hello::native_import18_hello_declaration_data;
use crucible_node_format::{Id, SchemaRef};

/// Prices the fresh configuration from the defining original launch declaration.
///
/// The supported and required feature vectors are independent allocations. The
/// closed native boot profile leaves `required_schemas` empty, as the existing
/// boot constructor does; full import18 definition checks remain separate. No
/// configuration, issuer, empty registry or authority is constructed here.
///
/// # Errors
/// Refuses a foreign declaration, missing sole binding, unsupported clone layout,
/// exhausted independent traversal/backing bound or checked layout overflow.
pub(super) fn configuration_clone_backing_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<usize, ProviderError> {
    if launch.selection.realization.bindings.len() != 1 {
        return Err(refused());
    }
    let binding = launch
        .selection
        .realization
        .bindings
        .first()
        .ok_or_else(refused)?;
    let declaration = native_import18_hello_declaration_data(launch)?;
    let mut walk = clone_backing::Walk::new_data(maximum)?;
    walk.observe_data(&binding.authority.session_id)?;
    walk.observe_data(&binding.authority.incarnation_id)?;
    walk.observe_data(&launch.selection.provider.implementation)?;
    walk.observe_data(&launch.selection.admission_receipt)?;

    for _ in 0..2 {
        walk.vector_population_data::<Id>(declaration.feature_count_data())?;
        for feature in declaration.features_data().iter().flatten() {
            walk.text_data(feature)?;
        }
    }
    walk.observe_data(&launch.limits)?;
    walk.vector_population_data::<SchemaRef>(0)?;
    walk.observe_data(&binding.compatibility.guarantees_ref)?;
    walk.tree_population_data::<String, Id>(declaration.key_count_data())?;
    for (key, feature) in declaration.keys_data().iter().flatten() {
        walk.text_data(key)?;
        walk.text_data(feature)?;
    }
    Ok(walk.finish_data())
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("original import18 Hello configuration clone")
}

#[cfg(test)]
mod tests {
    use super::clone_backing::{CloneBacking, Walk};
    use super::*;
    use crate::handshake::{NegotiationPolicy, TrustedInstallation};
    use crate::reference_packet::service::complete_restore::import18::inert_bootstrap_fixtures;
    use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};

    #[test]
    fn prospective_clone_quote_matches_both_actual_native_configurations() {
        for reactive in [false, true] {
            let selected = inert_bootstrap_fixtures::initial_selected_launch(reactive);
            let launch: PacketNative5SourceLaunch =
                serde_json::from_value(selected["launch"].clone()).unwrap();
            let declaration = native_import18_hello_declaration_data(&launch).unwrap();
            let binding = &launch.selection.realization.bindings[0];
            let mut selection = None;
            declaration
                .retain_selection_into_data(&mut selection)
                .unwrap();
            let (features, keys) = selection.as_ref().unwrap();
            let installation = TrustedInstallation {
                session_id: binding.authority.session_id.clone(),
                incarnation_id: binding.authority.incarnation_id.clone(),
                measured_implementation: launch.selection.provider.implementation.clone(),
                launch_receipt: launch.selection.admission_receipt.clone(),
                admission_token: [0; 32],
            };
            let policy = NegotiationPolicy {
                supported_features: features.clone(),
                required_features: features.clone(),
                provider_limits: launch.limits,
                required_schemas: Vec::new(),
                required_guarantees: binding.compatibility.guarantees_ref.clone(),
                envelope_extension_features: keys.clone(),
            };
            let projected = configuration_clone_backing_data(&launch, 268_435_456).unwrap();

            let mut actual_walk = Walk::new_data(268_435_456).unwrap();
            installation.count_data(&mut actual_walk).unwrap();
            policy.count_data(&mut actual_walk).unwrap();
            assert_eq!(actual_walk.finish_data(), projected);

            let mut observer = MetadataObserver::new();
            observer.observe(&installation.session_id).unwrap();
            observer.observe(&installation.incarnation_id).unwrap();
            observer
                .observe(&installation.measured_implementation)
                .unwrap();
            observer.observe(&installation.launch_receipt).unwrap();
            observer.observe(&policy.supported_features).unwrap();
            observer.observe(&policy.required_features).unwrap();
            observer.observe(&policy.required_schemas).unwrap();
            observer.observe(&policy.required_guarantees).unwrap();
            observer
                .observe(&policy.envelope_extension_features)
                .unwrap();
            let actual = requested_metadata_backing_storage_data(&observer.finish()).unwrap();
            assert!(
                actual <= projected,
                "actual={actual}, projected={projected}"
            );
            assert!(configuration_clone_backing_data(&launch, projected - 1).is_err());
            assert!(configuration_clone_backing_data(&launch, 0).is_err());
        }
    }
}
