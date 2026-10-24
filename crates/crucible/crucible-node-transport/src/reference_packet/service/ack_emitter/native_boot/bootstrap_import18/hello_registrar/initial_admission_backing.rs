//! Projects the additional retained owners of an initial empty-registry SDK lease.
//!
//! The original immutable launch determines the two selected-feature clones,
//! identities and complete installed envelope-name projection. A bounded future
//! request ID is priced by the format's identifier ceiling. This calculation
//! grants no SDK construction admission: decoder, insertion, validation, trusted
//! callback, diagnostic and terminal windows must be funded separately.

use super::clone_backing::Walk;
use super::configuration_clone_walk_data;
use crate::ProviderError;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::import18::hello::{
    NATIVE_IMPORT18_CONNECTION_ID, PacketNativeImport18HelloDeclarationData,
    native_import18_hello_declaration_data,
};
use crate::reference_packet::service::server::complete::birth::EmptyBootExtensions;
use crate::retained_metadata::requested_storage::shared_header_storage_data;
use crucible_node_format::{ExtensionSelection, Id, MAX_ID_BYTES};
use std::mem::{align_of, size_of};
use std::sync::{Mutex, atomic::AtomicU64};

/// Prices additional successful initial registration backing without a lease.
///
/// The configuration walk seeds the same combined tree geometry as the fresh
/// issuer. Adding trees in isolation could underprice their census when an
/// existing JSON map has a larger entry layout. No existing allocation is
/// reclaimed or discounted. The second request-tree root is conservative;
/// its existing empty census root remains charged by the registrar row.
///
/// # Errors
/// Refuses an invalid native declaration, missing sole binding, unsupported
/// clone/census layout, checked overflow or the independent restriction.
pub(in crate::reference_packet::service) fn retained_backing_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<usize, ProviderError> {
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    let declaration = native_import18_hello_declaration_data(launch)?;
    let mut walk = configuration_clone_walk_data(launch, maximum)?;
    walk.tree_population_data::<Id, ()>(0)?;
    let baseline = walk.current_backing_data();

    // The SDK retains the input connection in the lease and a fresh clone in
    // the issuer. Session/incarnation are independent lease-owned clones.
    walk.text_data(NATIVE_IMPORT18_CONNECTION_ID)?;
    walk.text_data(NATIVE_IMPORT18_CONNECTION_ID)?;
    walk.observe_data(&binding.authority.session_id)?;
    walk.observe_data(&binding.authority.incarnation_id)?;
    for _ in 0..2 {
        walk.vector_population_data::<Id>(declaration.feature_count_data())?;
        for feature in declaration.features_data().iter().flatten() {
            walk.text_data(feature)?;
        }
    }

    // All declared native features are selected. Their complete installed key
    // map therefore contributes every name to the lease's final retained set.
    walk.tree_population_data::<String, ()>(declaration.key_count_data())?;
    for (name, _) in declaration.keys_data().iter().flatten() {
        walk.text_data(name)?;
    }
    walk.tree_population_data::<Id, ()>(1)?;
    let additional = walk
        .finish_data()
        .checked_sub(baseline)
        .ok_or_else(refused)?;

    // Exact empty-registry initial admission creates one empty selection Arc
    // shared by the same wrapper and returned lease. The existing SDK gate/epoch
    // Arcs and registry Rc acquire edges without new allocations.
    let existing_alignment = align_of::<AtomicU64>()
        .max(align_of::<Mutex<()>>())
        .max(align_of::<EmptyBootExtensions>());
    let shared_selection =
        shared_header_storage_data(4, existing_alignment.max(align_of::<ExtensionSelection>()))?
            .checked_sub(shared_header_storage_data(3, existing_alignment)?)
            .ok_or_else(refused)?;
    let backing = additional
        .checked_add(MAX_ID_BYTES)
        .and_then(|n| n.checked_add(shared_selection))
        .ok_or_else(refused)?;
    if maximum == 0 || backing > maximum {
        return Err(refused());
    }
    Ok(backing)
}

/// Names the complete immutable walk and its checked accumulation controls.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> usize {
    super::counter_scratch_data()
        + PacketNativeImport18HelloDeclarationData::declaration_counter_scratch_data()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<PacketNativeImport18HelloDeclarationData>()
        + size_of::<Walk>()
        + size_of::<Result<Walk, ProviderError>>()
        + size_of::<std::ops::Range<usize>>()
        + size_of::<std::iter::Flatten<std::slice::Iter<'static, Option<&'static str>>>>()
        + size_of::<
            std::iter::Flatten<std::slice::Iter<'static, Option<(&'static str, &'static str)>>>,
        >()
        + size_of::<usize>() * 10
        + size_of::<Option<usize>>() * 3
        + size_of::<Result<usize, ProviderError>>() * 3
        + size_of::<Result<(), ProviderError>>() * 3
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("original import18 initial SDK retained backing")
}
