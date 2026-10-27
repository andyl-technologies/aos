//! Quotes the fresh target's actual selection, coordinator and identity owners.
//!
//! This component covers the target built by the installer. Its enclosing owner
//! separately counts the inline installer, archive/model transition, boundary,
//! physical Hold, socket and protocol phases. Original policy/launch backing is
//! already retained. No returned number supplies native phase admission.

use super::*;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::native_startup::PacketNative5CoordinatorConstructionStorage;
use crate::retained_metadata::{
    MetadataObserver, RetainedProtocolMetadataFacts, requested_metadata_backing_storage_data,
    requested_storage::tree_storage_data,
    serialization_storage::original_serialization_formatter_temporary_storage_data,
};
use std::mem::{align_of, size_of};

/// Quotes additional target backing and its complete constructor window.
///
/// Returns `[additional_retained, simultaneous_transient, counter_scratch]`.
/// The same immutable launch supplies both the selection clone and canonical
/// coordinator bytes. The defining decoder quote covers its actual typed
/// owner, nested reparses, validation and diagnostics. Selection backing and
/// its independent counting-serializer formatter remain separate. The
/// enclosing caller admits this prewalk and counter before entry, then admits
/// the returned row beside every existing owner before constructing a target.
///
/// Retained backing includes the new Control identity allocation. The
/// installer already embeds both target and Control headers; those headers
/// belong to its independently counted inline layout. Archive, model, Hold,
/// inventory hashing, kernel resources and complete Commit demand are not
/// included in this target component. The prebirth Source can derive this DATA
/// before a native policy exists; it authenticates the original launch separately.
///
/// # Errors
/// Refuses unsupported coordinator geometry, checked layout overflow or an
/// independently short complete restriction. Successful quoting does not
/// validate the launch or authorize any constructor.
pub fn native_import18_target_construction_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    target_construction_data(
        &launch.selection,
        launch.initial_coordinator.bytes.as_slice(),
        maximum,
    )
}

/// Names the defining target prewalk and constructor controls before entry.
///
/// Input-dependent decoder controls are included in the returned row.
/// Compiler frames and enclosing Source/phase guards remain separate.
pub fn native_import18_target_construction_counter_scratch_data() -> usize {
    PacketNative5CoordinatorInstallation::decode_construction_counter_scratch_data()
        + crate::retained_metadata::retained_native_coordinator_counter_scratch_data()
        + PacketControl::restored_settled_history_counter_scratch_data()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&PacketControlSelection>()
        + size_of::<&[u8]>()
        + size_of::<[usize; 3]>() * 3
        + size_of::<Result<[usize; 3], ProviderError>>() * 2
        + size_of::<Result<usize, ProviderError>>() * 3
        + size_of::<usize>() * 6
}

fn target_construction_data(
    selection: &PacketControlSelection,
    coordinator_bytes: &[u8],
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let mut observer = MetadataObserver::new();
    observer.observe(selection)?;
    observe_empty_control_trees(&mut observer)?;
    let facts = observer.finish();
    let selection_backing = requested_metadata_backing_storage_data(&facts)?;
    let selection_formatter = original_serialization_formatter_temporary_storage_data(&facts)?;
    let [coordinator_backing, coordinator_work, decoder_scratch] =
        PacketNative5CoordinatorInstallation::decode_construction_storage_data(
            coordinator_bytes,
            maximum,
        )?;

    let identity = crate::retained_metadata::requested_storage::shared_header_storage_data(
        1,
        align_of::<()>(),
    )?;
    // The final Control census uses its widest cache-map layout for every tree,
    // including coordinator Value maps. Reprice the complete coordinator bound
    // for that enclosing layout; adding two standalone counters is insufficient.
    let coordinator_backing = reprice_coordinator_backing(coordinator_backing, &facts)?;
    let retained = sum(&[selection_backing, coordinator_backing, identity])?;

    // Decoder work includes the original canonical check. The typed coordinator
    // stays independently retained while it moves beneath the fresh Control.
    let transient = sum(&[
        coordinator_work,
        selection_formatter,
        size_of::<Native18InstallationTarget>() * 3,
        size_of::<PacketControlSelection>(),
        size_of::<PacketNative5CoordinatorInstallation>(),
        size_of::<PacketControl>() * 3,
        size_of::<Result<PacketControl, Native18InstallationTarget>>(),
    ])?;
    let scratch = sum(&[
        decoder_scratch,
        native_import18_target_construction_counter_scratch_data(),
    ])?;
    if sum(&[retained, transient, scratch])? > maximum {
        return Err(ProviderError::ResourceExhausted(
            "native18 target construction storage",
        ));
    }
    Ok([retained, transient, scratch])
}

fn observe_empty_control_trees(observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
    // Field loans infer the actual cache types without constructing a Control.
    // The defining census includes a possible root even for each empty tree.
    observe_empty_tree(|control| &control.originals, observer)?;
    observe_empty_tree(|control| &control.begins, observer)?;
    observe_empty_tree(|control| &control.begin_requests, observer)?;
    observe_empty_tree(|control| &control.content, observer)?;
    observe_empty_tree(|control| &control.terminals, observer)
}

fn observe_empty_tree<K, V>(
    _field: fn(&PacketControl) -> &BTreeMap<K, V>,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    observer.tree::<K, V>(0)
}

fn reprice_coordinator_backing(
    backing: usize,
    enclosing: &RetainedProtocolMetadataFacts,
) -> Result<usize, ProviderError> {
    // Every decoded coordinator visits String/Value extension maps, including
    // empty ones. Its standalone census therefore uses at least this node B.
    let baseline = tree_storage_data(
        1,
        0,
        size_of::<String>() + size_of::<Value>(),
        align_of::<String>().max(align_of::<Value>()),
    )?;
    let widened = tree_storage_data(
        1,
        0,
        enclosing.maximum_tree_key_value_bytes,
        enclosing.maximum_tree_entry_alignment.max(1),
    )?;
    if widened <= baseline {
        return Ok(backing);
    }

    // For non-tree backing X and tree units N, X + N*B <= backing implies
    // X + N*W <= ceil(backing*W/B) when W >= B. This scales a requested-byte
    // upper bound; it does not infer events or containers from heap bytes.
    backing
        .checked_mul(widened)
        .map(|scaled| scaled.div_ceil(baseline))
        .ok_or_else(refused18)
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms
        .iter()
        .try_fold(0usize, |total, term| total.checked_add(*term))
        .ok_or_else(refused18)
}

#[cfg(test)]
mod tests {
    //! Compares the target quote with actual fresh Control backing and bounds.

    use super::*;

    #[test]
    fn native18_installation_target_quote_covers_actual_fresh_control() -> Result<(), ProviderError>
    {
        for reactive in [false, true] {
            let actual =
                super::super::super::super::native5::current_control17_fixture_data(reactive)?;
            let coordinator = actual.complete_coordinator.as_ref().ok_or_else(refused18)?;
            let value = serde_json::to_value(coordinator).map_err(ContractError::from)?;
            let bytes = canonical::canonical_json(&value)?;
            let before = serde_json::to_vec(&actual.selection).map_err(ContractError::from)?;
            let row = target_construction_data(&actual.selection, &bytes, usize::MAX)?;
            let peak = sum(&row)?;

            assert_eq!(
                target_construction_data(&actual.selection, &bytes, peak)?,
                row
            );
            assert!(target_construction_data(&actual.selection, &bytes, peak - 1).is_err());

            let target = Native18InstallationTarget {
                selection: Some(actual.selection.clone()),
                coordinator: Some(PacketNative5CoordinatorInstallation::decode(
                    &bytes,
                    &actual.selection,
                )?),
            }
            .into_model_absent_control()
            .map_err(|_| refused18())?;
            let mut observer = MetadataObserver::new();
            target.observe_restored_settled_history_metadata_data(&mut observer)?;
            let facts = observer.finish();
            let backing = requested_metadata_backing_storage_data(&facts)?;

            assert!(
                row[0] >= backing,
                "reactive={reactive}, row={row:?}, actual={backing}, tree_width={}",
                facts.maximum_tree_key_value_bytes
            );
            assert!(row[1] > 0 && row[2] > 0);
            assert!(target.fenced && !target.immediate && target.restoration_activation_required);
            assert!(matches!(
                target.program,
                NativeProgram::RestorationInProgress
            ));
            assert_eq!(
                serde_json::to_vec(&actual.selection).map_err(ContractError::from)?,
                before
            );
        }
        Ok(())
    }
}
