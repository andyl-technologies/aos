//! Owns fresh configuration, issuer and empty-registry construction for import18.
//!
//! Independent rows cover actual cloning, validation and shared allocations.
//! The original bootstrap retains the physical attempt before its first read,
//! admits quote work and construction separately, then keeps every surviving
//! owner under the same input/cut guards. The unselected wrapper grants no
//! connection, reply, ACK, native policy or readiness.

#[path = "hello_registrar/clone_backing.rs"]
mod clone_backing;

#[path = "hello_registrar/clone_controls.rs"]
mod clone_controls;

#[path = "hello_registrar/hello_result_clone.rs"]
mod hello_result_clone;
pub(super) use hello_result_clone::{
    construction_data as hello_result_clone_construction_data,
    counter_scratch_data as hello_result_clone_counter_scratch_data,
};

#[path = "hello_registrar/validation_storage.rs"]
mod validation_storage;

#[path = "hello_registrar/attempt.rs"]
mod attempt;

#[path = "hello_registrar/storage.rs"]
mod storage;

#[path = "hello_registrar/native.rs"]
mod native;
pub(super) use attempt::Attempt;
pub(in super::super) use native::OriginalImport18HelloRegistrarAdmission;

use crate::ProviderError;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::import18::hello::native_import18_hello_declaration_data;
use crucible_node_format::{Id, SchemaRef};
use std::mem::size_of;

/// Quotes the physical fresh registrar before any configuration is cloned.
///
/// # Errors
/// Refuses invalid declarations, unsupported layouts, checked overflow or an
/// independent complete-peak restriction.
pub(in crate::reference_packet::service) fn construction_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    storage::construction_data(launch, maximum)
}

/// Names actual declaration, clone/validation quotes and physical owner controls.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> usize {
    use crate::handshake::{NegotiationPolicy, TrustedInstallation};
    use crate::reference_packet::service::complete_restore::import18::hello::PacketNativeImport18HelloDeclarationData;
    use clone_backing::CloneBacking;
    use clone_controls::CloneControls;

    PacketNativeImport18HelloDeclarationData::declaration_counter_scratch_data()
        + clone_backing::counter_scratch_data()
        + TrustedInstallation::counter_scratch_data()
        + NegotiationPolicy::counter_scratch_data()
        + TrustedInstallation::quote_counter_scratch_data()
        + NegotiationPolicy::quote_counter_scratch_data()
        + validation_storage::counter_scratch_data()
        + storage::counter_scratch_data()
        + native::counter_scratch_data_native()
        + size_of::<PacketNativeImport18HelloDeclarationData>()
        + size_of::<clone_backing::Walk>()
        + size_of::<Result<clone_backing::Walk, ProviderError>>()
        + size_of::<std::iter::Flatten<std::slice::Iter<'static, Option<&'static str>>>>()
        + size_of::<
            std::iter::Flatten<std::slice::Iter<'static, Option<(&'static str, &'static str)>>>,
        >()
        + size_of::<std::ops::Range<usize>>()
        + size_of::<[usize; 3]>() * 2
        + size_of::<[usize; 2]>() * 2
        + size_of::<usize>() * 8
        + size_of::<Result<usize, ProviderError>>() * 3
        + size_of::<Result<[usize; 3], ProviderError>>()
}

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
    Ok(configuration_clone_walk_data(launch, maximum)?.finish_data())
}

/// Prices fresh configuration clone backing and actual pinned clone controls.
///
/// Validation, shared epoch/gate allocations, destination owners, quote controls
/// and original admission remain separate obligations before constructing an issuer.
///
/// # Errors
/// Refuses unsupported layouts, invalid declarations, arithmetic or independent
/// backing/traversal/complete-peak restriction.
pub(super) fn configuration_clone_construction_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    use crate::handshake::{NegotiationPolicy, TrustedInstallation};
    use clone_controls::CloneControls;

    let walk = configuration_clone_walk_data(launch, maximum)?;
    let typed = clone_controls::combine(&[
        TrustedInstallation::fresh_controls_data()?,
        NegotiationPolicy::fresh_controls_data()?,
    ])?;
    walk.finish_clone_data(typed)
}

fn configuration_clone_walk_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<clone_backing::Walk, ProviderError> {
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

    for _ in 0usize..2 {
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
    Ok(walk)
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

    pub(super) fn configuration_data(
        reactive: bool,
    ) -> (
        PacketNative5SourceLaunch,
        TrustedInstallation,
        NegotiationPolicy,
    ) {
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
        (launch, installation, policy)
    }

    #[test]
    fn prospective_clone_quote_matches_both_actual_native_configurations() {
        for reactive in [false, true] {
            let (launch, installation, policy) = configuration_data(reactive);
            let projected = configuration_clone_backing_data(&launch, 268_435_456).unwrap();
            let cloned_row = configuration_clone_construction_data(&launch, 268_435_456).unwrap();
            assert_eq!(cloned_row[0], projected);
            let clone_peak = cloned_row.into_iter().sum::<usize>();
            assert!(configuration_clone_construction_data(&launch, clone_peak - 1).is_err());

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
