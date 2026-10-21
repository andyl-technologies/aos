//! Combines fresh clone, validation and physical registrar constructor demand.
//!
//! This prices configuration retained alongside its actual fresh issuer, shared
//! epoch/gate and one concrete empty registry. It constructs none of them. The
//! enclosing original initial owner admits quote work before this calculation
//! and the complete row before actual construction.

use super::clone_controls::CloneControls;
use super::{attempt, clone_controls, configuration_clone_walk_data, validation_storage};
use crate::ProviderError;
use crate::handshake::{
    ExtensionHandshake, Handshake, InstalledExtensionNegotiationVerifier, NegotiationPolicy,
    TrustedInstallation,
};
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::server::complete::birth::EmptyBootExtensions;
use crate::retained_metadata::requested_storage::shared_header_storage_data;
use crucible_node_format::Id;
use std::mem::{align_of, size_of};
use std::rc::Rc;
use std::sync::{Arc, Mutex, atomic::AtomicU64};

type ConstructorTransientFields = [usize; 19];
type SharedBackingFields = [usize; 4];
type RetainedFields = [usize; 4];

/// Quotes the complete physical fresh-registrar constructor as ordinary DATA.
///
/// # Errors
/// Refuses unsupported clone geometry, invalid declarations, checked overflow
/// or a row above the enclosing original independent complete-peak restriction.
pub(super) fn construction_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let walk = configuration_clone_walk_data(launch, maximum)?;
    // Handshake::new also retains its real empty request-ID tree census. It is
    // not cloned, and shares the configuration census's maximum entry layout.
    let request_ids = walk.additional_retained_tree_backing_data::<Id, ()>(0)?;
    let typed = clone_controls::combine(&[
        TrustedInstallation::fresh_controls_data()?,
        NegotiationPolicy::fresh_controls_data()?,
    ])?;
    let cloned = walk.finish_clone_data(typed)?;
    let validation = validation_storage::construction_data(launch, maximum)?;
    let shared = shared_backing_data()?;
    let retained_fields: RetainedFields = [cloned[0], request_ids, validation[0], shared];
    let retained = total(&retained_fields)?;
    let transient = cloned[1]
        .max(validation[1])
        .max(constructor_transient_data()?);
    let scratch = cloned[2]
        .max(validation[2])
        .max(super::counter_scratch_data());
    let row = [retained, transient, scratch];
    if maximum == 0 || total(&row)? > maximum {
        return Err(refused());
    }
    Ok(row)
}

fn shared_backing_data() -> Result<usize, ProviderError> {
    let alignment = align_of::<AtomicU64>()
        .max(align_of::<Mutex<()>>())
        .max(align_of::<EmptyBootExtensions>());
    let fields: SharedBackingFields = [
        size_of::<AtomicU64>(),
        size_of::<Mutex<()>>(),
        size_of::<EmptyBootExtensions>(),
        shared_header_storage_data(3, alignment)?,
    ];
    total(&fields)
}

fn constructor_transient_data() -> Result<usize, ProviderError> {
    // Arc::new / Rc::new initialize their actual two-count shared payload before
    // converting the Box to a handle. The pinned shared layout is also an upper
    // bound for these real temporary initializer records.
    let shared_initializers = shared_backing_data()?;
    let fields: ConstructorTransientFields = [
        shared_initializers,
        size_of::<TrustedInstallation>(), // actual installation move
        size_of::<NegotiationPolicy>(),   // actual policy move
        size_of::<Option<TrustedInstallation>>(),
        size_of::<Option<NegotiationPolicy>>(),
        size_of::<(Option<TrustedInstallation>, Option<NegotiationPolicy>)>(), // take pair
        size_of::<Handshake>(),          // fresh issuer initializer
        size_of::<Handshake>(),          // issuer return
        size_of::<Option<Handshake>>(),  // retained plain issuer assignment
        size_of::<Arc<AtomicU64>>() * 2, // constructor result / field move
        size_of::<Arc<Mutex<()>>>() * 2,
        size_of::<Rc<EmptyBootExtensions>>() * 2,
        size_of::<Rc<dyn InstalledExtensionNegotiationVerifier>>() * 2, // actual erased edge
        size_of::<ExtensionHandshake>(),                                // wrapper initializer
        size_of::<Result<ExtensionHandshake, ProviderError>>(),         // wrapper return
        size_of::<Option<ExtensionHandshake>>(), // retained wrapper assignment
        size_of::<ProviderError>() * 2,          // retained actual failure / returned diagnostic
        size_of::<Option<ProviderError>>(),
        size_of::<Result<(), ProviderError>>() * 2,
    ];
    total(&fields)
}

/// Names the actual combination, shared geometry and physical-owner controls.
pub(super) fn counter_scratch_data() -> usize {
    attempt::Attempt::counter_scratch_data()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<[usize; 3]>() * 4
        + size_of::<[usize; 2]>()
        + size_of::<[[usize; 2]; 2]>()
        + size_of::<RetainedFields>()
        + size_of::<SharedBackingFields>()
        + size_of::<ConstructorTransientFields>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<usize>() * 8
        + size_of::<Result<usize, ProviderError>>() * 4
        + size_of::<Result<[usize; 3], ProviderError>>()
}

fn total(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |sum, value| {
        sum.checked_add(*value).ok_or_else(refused)
    })
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("original import18 fresh registrar construction")
}
