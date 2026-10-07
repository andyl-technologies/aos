//! Compares signed requirement snapshots with actual ordinary root resolution.

use terrane_core::properties::{Defaults, PropertyName, RootLayer, Value};
use terrane_core::provenance::VerifiedCommit;
use terrane_core::{cbor, properties};

use crate::guard::{TreeEvidence, invalid};
use crate::store::{InvalidReason, StoreErrorKind, StoreFailure};

/// Checks all four signed requirement fields against the original namespace root.
///
/// # Errors
/// Refuses missing snapshots, malformed root policies, or any differing signed
/// projection. An empty Index alone never establishes this agreement.
pub(super) fn check(
    commit: &VerifiedCommit,
    evidence: &TreeEvidence,
    defaults: Defaults<'_>,
    minimum: u64,
    selection: properties::selected::Selection,
) -> Result<(), StoreFailure> {
    let signed = commit
        .commit()
        .profile_pair
        .required_properties
        .as_deref()
        .ok_or_else(|| StoreFailure::new(StoreErrorKind::Unsupported))?;
    let tree = evidence.tree(evidence.root, minimum)?;
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

    Ok(())
}
