//! Merges typed root properties without inventing conflict-valued properties.
//!
//! Conflict reports retain each canonical property map for caller resolution:
//!
//! ```text
//! {"trust": "strict", "retain": "forever"}
//! ```

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::{Error, MergePolicy};
use crate::cbor;
use crate::tree_builder::Tree;
use crate::tree_format::Property;

/// A root metadata conflict requiring explicit caller resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootPropertiesConflict {
    /// Canonical base property map, absent when no map was encoded.
    pub base: Option<Vec<u8>>,
    /// Canonical destination property map, preserving absent versus empty.
    pub ours: Option<Vec<u8>>,
    /// Canonical incoming property map, preserving absent versus empty.
    pub theirs: Option<Vec<u8>>,
}

fn encode(properties: Option<&[Property<'_>]>) -> Option<Vec<u8>> {
    properties.map(|properties| {
        let mut bytes = Vec::new();
        cbor::write_map(&mut bytes, properties.len());
        for property in properties {
            cbor::write_text(&mut bytes, property.name);
            bytes.extend_from_slice(property.value);
        }
        bytes
    })
}

pub(super) fn merge_properties<'a>(
    base: &Tree<'a>,
    ours: &Tree<'a>,
    theirs: &Tree<'a>,
    policies: &[MergePolicy],
) -> Result<Option<Vec<Property<'a>>>, Error> {
    let maps = [base.props(), ours.props(), theirs.props()];
    if maps[1] == maps[2] {
        return Ok(maps[1].map(<[_]>::to_vec));
    }
    if maps[1] == maps[0] {
        return Ok(maps[2].map(<[_]>::to_vec));
    }
    if maps[2] == maps[0] {
        return Ok(maps[1].map(<[_]>::to_vec));
    }

    let mut values = BTreeMap::new();
    for (side, properties) in maps.into_iter().enumerate() {
        for property in properties.into_iter().flatten() {
            values.entry(property.name).or_insert([None; 3])[side] = Some(*property);
        }
    }
    let mut merged = Vec::new();
    for candidates in values.into_values() {
        let [base, ours, theirs] = candidates;
        let value = if ours == theirs {
            ours
        } else if ours == base {
            theirs
        } else if theirs == base {
            ours
        } else {
            let mut chosen = None;
            for policy in policies {
                match policy {
                    MergePolicy::PreferOurs => {
                        chosen = Some(ours);
                        break;
                    }
                    MergePolicy::PreferTheirs => {
                        chosen = Some(theirs);
                        break;
                    }
                    MergePolicy::KeepConflict | MergePolicy::Error => break,
                    MergePolicy::PreferTrusted | MergePolicy::PreferNewer => {}
                }
            }
            chosen.ok_or_else(|| {
                Error::RootPropertiesConflict(RootPropertiesConflict {
                    base: encode(maps[0]),
                    ours: encode(maps[1]),
                    theirs: encode(maps[2]),
                })
            })?
        };
        if let Some(property) = value {
            merged.push(property);
        }
    }
    merged.sort_by(|left, right| {
        left.name
            .len()
            .cmp(&right.name.len())
            .then_with(|| left.name.as_bytes().cmp(right.name.as_bytes()))
    });
    let presence = [maps[0].is_some(), maps[1].is_some(), maps[2].is_some()];
    let present = if presence[1] == presence[0] {
        presence[2]
    } else {
        presence[1]
    };
    Ok((present || !merged.is_empty()).then_some(merged))
}
