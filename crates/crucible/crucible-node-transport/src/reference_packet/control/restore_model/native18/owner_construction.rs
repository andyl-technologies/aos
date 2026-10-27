//! Prices the installer's inline destinations and separate physical Hold.
//!
//! This fixed component complements the input-dependent target, model and
//! inventory-boundary quotes. Archive and policy backing are existing owners;
//! the boundary's hash moves into the Hold without cloning its string backing.
//! Kernel resources and protocol phase owners require their own funding.

use super::*;
use crate::retained_metadata::requested_storage::shared_header_storage_data;
use std::mem::{align_of, size_of};

/// Quotes the installer and physical Hold's retained, transient and fixed axes.
///
/// Returns `[additional_retained, simultaneous_transient, counter_scratch]`.
/// Retained storage includes the inline installer and the actual shared Hold
/// allocation. It includes the installer's embedded target, Control, archive
/// adoption and socket destinations. The enclosing owner supplies its own
/// container allocation overhead and separately counts existing archive, policy
/// and socket custody, new target backing, model validation and boundary hash
/// construction. The shared Control identity is priced by the target quote.
///
/// Transient storage covers the named by-value initializers, destination
/// wrappers and archive/model ownership moves. It excludes child decoder and
/// validator work, compiler-generated frames and protocol phase constructors.
/// Each of those remains a separate term in the enclosing phase admission.
/// This fixed DATA quote neither constructs an owner nor authorizes Commit.
///
/// # Errors
/// Refuses requested-layout overflow or a restriction below the complete sum.
pub fn native_import18_installation_owner_construction_data(
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let hold = shared_header_storage_data(
        size_of::<PacketCompleteRestorePhysicalHold>(),
        align_of::<PacketCompleteRestorePhysicalHold>(),
    )?;
    let retained = sum(&[size_of::<Native18ModelInstallation>(), hold])?;
    let transient = sum(&[
        size_of::<Native18ModelInstallation>(),
        size_of::<Option<Native18ModelInstallation>>(),
        size_of::<Native18ModelInstallationInputs>(),
        size_of::<Option<Native18ModelInstallationInputs>>(),
        size_of::<PacketCompleteRestorePhysicalHold>(),
        size_of::<PacketModelCaptureBoundaryData>(),
        size_of::<CurrentModel18Program>(),
        size_of::<Option<CurrentModel18Program>>(),
        RestoredSettledNative18ModelAdoption::construction_value_temporary_data(),
    ])?;
    let counter = native_import18_installation_owner_construction_counter_scratch_data();
    let axes = [retained, transient, counter];
    if sum(&axes)? > maximum {
        return Err(ProviderError::ResourceExhausted(
            "native18 installation owner construction storage",
        ));
    }
    Ok(axes)
}

/// Names fixed installer construction, origin and physical Hold controls.
///
/// The caller admits these controls before computing the quote. Dynamic child
/// traversals, target construction, boundary formatting and enclosing Source
/// guards retain their independently declared counters.
pub fn native_import18_installation_owner_construction_counter_scratch_data() -> usize {
    size_of::<&mut Option<Native18ModelInstallation>>()
        + size_of::<&mut Native18ModelInstallation>()
        + size_of::<&mut Option<Native18ModelInstallationInputs>>()
        + size_of::<&mut Native18ModelInstallationInputs>()
        + size_of::<&Rc<NativeImport18PolicyData>>()
        + size_of::<&mut Native18InstallationTarget>()
        + size_of::<&mut PacketControl>()
        + size_of::<&Rc<PacketCompleteRestorePhysicalHold>>()
        + size_of::<&mut RestoredSettledNative18ModelAdoption>()
        + size_of::<&mut Option<CurrentModel18Program>>()
        + size_of::<&mut Option<UnixDatagram>>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<[usize; 3]>()
        + size_of::<std::thread::Thread>()
        + size_of::<ThreadId>()
        + size_of::<u32>()
        + size_of::<HoldPhase>()
        + size_of::<usize>() * 5
        + size_of::<Result<usize, ProviderError>>() * 3
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<Result<(), ProviderError>>() * 3
        + RestoredSettledNative18ModelAdoption::counter_scratch_data()
        + PacketCompleteRestorePhysicalHold::settled_history_counter_scratch_data()
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms
        .iter()
        .try_fold(0usize, |total, term| total.checked_add(*term))
        .ok_or_else(refused18)
}
