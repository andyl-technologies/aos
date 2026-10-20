//! Compares signed requirement snapshots with actual ordinary root resolution.

use terrane_format::properties::{Defaults, PropertyName, RootLayer, Value};
use terrane_format::provenance::VerifiedCommit;
use terrane_format::tree_builder::Tree;
use terrane_format::{cbor, properties};

use crate::guard::invalid;
use crate::store::{InvalidReason, StoreErrorKind, StoreFailure};

/// Checks all four signed requirement fields against the original namespace root.
///
/// # Errors
/// Refuses missing snapshots, malformed root policies, or any differing signed
/// projection. An empty Index alone never establishes this agreement. The
/// constructor runs only after the required signed snapshot is present.
pub(super) fn check<'a>(
    commit: &VerifiedCommit,
    defaults: Defaults<'_>,
    selection: properties::selected::Selection,
    construct: impl FnOnce() -> Result<Tree<'a>, StoreFailure>,
) -> Result<Tree<'a>, StoreFailure> {
    let signed = commit
        .commit()
        .profile_pair
        .required_properties
        .as_deref()
        .ok_or_else(|| StoreFailure::new(StoreErrorKind::Unsupported))?;
    let tree = construct()?;
    let resolved = selection
        .resolve(
            &[RootLayer {
                properties: tree.props().unwrap_or(&[]),
                overrides: &[],
            }],
            defaults,
        )
        .map_err(|error| {
            StoreFailure::with_source(
                StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
                error,
            )
        })?;

    let names = [
        PropertyName::Index,
        PropertyName::Hashes,
        PropertyName::Classify,
        PropertyName::StrictAttrs,
    ];
    let mut projected = Vec::new();
    cbor::write_map(&mut projected, names.len());
    for name in names {
        cbor::write_text(&mut projected, name.as_str());
        match resolved.get(name) {
            Some(Value::Names(values)) => {
                cbor::write_array(&mut projected, values.len());
                for value in values {
                    cbor::write_text(&mut projected, value);
                }
            }
            Some(Value::Boolean(value)) => projected.push(if *value { 0xf5 } else { 0xf4 }),
            _ => return Err(invalid()),
        }
    }
    if signed != projected {
        return Err(invalid());
    }

    Ok(tree)
}
