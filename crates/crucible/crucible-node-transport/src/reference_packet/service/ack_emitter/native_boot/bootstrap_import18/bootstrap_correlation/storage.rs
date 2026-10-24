//! Prices actual SDK correlation parameters and its one original request clone.
//!
//! The ordinary metadata census combines all trees using its largest entry
//! layout. Request-map entries contain Envelope headers; that same maximum must
//! therefore cover the nested body/proof maps and selected extension set too.

use super::*;
use crate::reference_packet::service::complete_restore::import18::hello::{
    PacketNativeImport18HelloDeclarationData, native_import18_hello_declaration_data,
};
use crate::retained_metadata::RetainedProtocolMetadataFacts;
use crate::retained_metadata::requested_storage::tree_storage_data;
use crucible_node_format::{Id, values::MAX_ID_BYTES};
use std::mem::{align_of, size_of};

/// Quotes the actual guard header, cloned parameters and one original request.
///
/// Empty pending/writing maps retain headers even before the request arrives.
/// The closed Envelope's four maps contribute eleven entries. Every selected
/// key is bounded by the actual launch declaration, independently of a request.
///
/// # Errors
/// Refuses launch declarations, checked arithmetic or a short restriction.
pub(super) fn construction_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let declaration = native_import18_hello_declaration_data(launch)?;
    let mut keys = 0usize;
    let mut text = 0usize;
    for (key, _) in declaration.keys_data().iter().flatten() {
        keys = add(keys, 1)?;
        text = add(text, key.len())?;
    }
    if keys != declaration.key_count_data() {
        return Err(refused());
    }
    // Four cloned Envelope maps, three guard request maps and one key set all
    // share the ordinary census's maximum (Id, Envelope) requested layout.
    let trees = tree_storage_data(
        8,
        add(12, keys)?,
        add(size_of::<Id>(), size_of::<Envelope>())?,
        align_of::<Id>().max(align_of::<Envelope>()),
    )?;
    let backing = sum(&[
        trees,
        text,
        mul(3, MAX_ID_BYTES)?,
        super::super::bootstrap_codec::envelope_text_data()?,
    ])?;
    let retained = add(size_of::<Attempt>(), backing)?;
    // Successful clones and any partially built string/tree prefix are covered
    // before a constructor or receive is allowed to allocate.
    let transient = sum(&[
        backing,
        size_of::<CorrelationGuard>(),
        size_of::<Option<CorrelationGuard>>(),
        size_of::<Result<CorrelationGuard, ProviderError>>(),
        size_of::<Attempt>(),
        size_of::<Option<Attempt>>(),
        size_of::<Envelope>(),
        size_of::<Option<Envelope>>(),
        size_of::<Id>(),
        size_of::<Option<Id>>(),
        size_of::<std::collections::BTreeSet<String>>(),
        size_of::<String>(),
    ])?;
    let row = [retained, transient, counter_scratch_data()];
    if sum(&row)? > maximum {
        return Err(exhausted());
    }
    Ok(row)
}

/// Names actual cloning, SDK receive, borrowed walks and checked layout controls.
pub(super) fn counter_scratch_data() -> usize {
    PacketNativeImport18HelloDeclarationData::declaration_counter_scratch_data()
        + size_of::<PacketNativeImport18HelloDeclarationData>()
        + size_of::<Result<PacketNativeImport18HelloDeclarationData, ProviderError>>()
        + size_of::<
            std::iter::Flatten<std::slice::Iter<'static, Option<(&'static str, &'static str)>>>,
        >()
        + size_of::<&str>() * 2
        + size_of::<MetadataObserver<'static>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<crate::handshake::Limits>()
        + size_of::<Result<usize, std::num::TryFromIntError>>()
        + size_of::<&mut Option<CorrelationGuard>>()
        + size_of::<&crate::handshake::ConnectionAuthority>()
        + size_of::<&CorrelationGuard>()
        + size_of::<&mut CorrelationGuard>()
        + size_of::<&Envelope>() * 2
        + size_of::<&Id>() * 3
        + size_of::<&String>()
        + size_of::<&serde_json::Value>()
        + size_of::<std::collections::btree_map::Iter<'static, Id, Envelope>>()
        + size_of::<std::collections::btree_map::Values<'static, Id, Envelope>>() * 2
        + size_of::<std::collections::btree_set::Iter<'static, String>>()
        + size_of::<std::collections::btree_map::Iter<'static, String, serde_json::Value>>() * 4
        + size_of::<serde_json::map::Iter<'static>>() * 4
        + size_of::<[usize; 12]>()
        + size_of::<[usize; 4]>()
        + size_of::<[usize; 6]>()
        + size_of::<[usize; 3]>() * 3
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<&[usize]>()
        + size_of::<usize>() * 12
        + size_of::<Option<usize>>() * 2
        + size_of::<Result<usize, ProviderError>>() * 4
        + size_of::<Result<(), ProviderError>>() * 7
        + size_of::<Result<[usize; 3], ProviderError>>()
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(exhausted)
}
fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(exhausted)
}
fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values
        .iter()
        .try_fold(0usize, |total, value| add(total, *value))
}
