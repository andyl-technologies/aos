//! Copies resolved overlay boundary policy and validates actual parent rights.
//!
//! Retained bindings use the existing canonical property-value encoding. An
//! unset baseline remains an absent value, never an encoded root property.
//! The owner supplies no authorization and has no separate wire format.
//! For example, resolved bindings can carry these existing property values:
//! ```text
//! domain = "private:owner", store = "authority", acl = [],
//! trust = "any" (baseline absent)
//! ```

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::Error;
use crate::auth::{Verb, Verbs};
use crate::properties::{Defaults, EffectiveProperties, PropertyName, RootLayer, Value};
use crate::tree_format::Property;

/// Owns normalized authority and trust bindings for an authenticated occurrence.
///
/// This value copies already resolved policy; it authenticates neither that
/// resolution nor the committing principal. Repository callers independently
/// select the immutable interpretation, defaults, and current authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverlayPolicy {
    pub(super) values: Vec<(PropertyName, Option<Vec<u8>>)>,
}

impl OverlayPolicy {
    /// Copies domain, store, ACL, trust, and baseline from effective policy.
    ///
    /// ACL grants are combined per principal using the registered verb
    /// evaluator, including implied Read and Admin rights. Equivalent ordering,
    /// split grants, zero masks, and implied masks compare as the same policy.
    ///
    /// # Errors
    /// Returns `Boundary` if a required value is absent or has an invalid type.
    pub fn from_effective(effective: &EffectiveProperties<'_>) -> Result<Self, Error> {
        let mut values = Vec::new();
        for name in [
            PropertyName::Domain,
            PropertyName::Store,
            PropertyName::Acl,
            PropertyName::Trust,
            PropertyName::Baseline,
        ] {
            let mut value = Vec::new();
            match effective.get(name).ok_or(Error::Boundary)? {
                Value::Text(text) => crate::cbor::write_text(&mut value, text),
                Value::Grants(grants) => {
                    let grants = normalized_grants(grants)?;
                    crate::cbor::write_array(&mut value, grants.len());
                    for (principal, verbs) in grants {
                        crate::cbor::write_array(&mut value, 2);
                        crate::cbor::write_text(&mut value, principal);
                        crate::cbor::write_uint(&mut value, u64::from(verbs));
                    }
                }
                Value::Selector(bytes) => value.extend_from_slice(bytes),
                Value::Unset if name == PropertyName::Baseline => {
                    // Unset is a registry default, not a valid explicit binding.
                    // Keep its distinct state for comparison without emitting it.
                    values.push((name, None));
                    continue;
                }
                _ => return Err(Error::Boundary),
            }
            crate::properties::validate_property(&Property {
                name: name.as_str(),
                value: &value,
            })
            .map_err(|_| Error::Boundary)?;
            values.push((name, Some(value)));
        }
        Ok(Self { values })
    }

    pub(super) fn value(&self, name: PropertyName) -> Result<Option<&[u8]>, Error> {
        self.values
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_deref())
            .ok_or(Error::Boundary)
    }

    fn with_effective<T>(
        &self,
        inspect: impl FnOnce(&EffectiveProperties<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let properties: Vec<_> = self
            .values
            .iter()
            .filter_map(|(name, value)| {
                value.as_deref().map(|value| Property {
                    name: name.as_str(),
                    value,
                })
            })
            .collect();
        let text = |name| {
            let property = properties
                .iter()
                .find(|property| property.name == name)
                .ok_or(Error::Boundary)?;
            match crate::properties::validate_property(property)
                .map_err(|_| Error::Boundary)?
                .1
            {
                Value::Text(text) => Ok(text),
                _ => Err(Error::Boundary),
            }
        };
        let effective = crate::properties::resolve(
            &[RootLayer {
                properties: &properties,
                overrides: &[],
            }],
            Defaults {
                store: text("store")?,
                // Boundary bindings are explicit; the omitted unset baseline
                // resolves to its registry default at this isolated root. This
                // required fallback never supplies the resolved disclosure label.
                private_domain: "private:overlay-policy",
                home: "overlay",
            },
        )
        .map_err(|_| Error::Boundary)?;
        inspect(&effective)
    }

    pub(super) fn validate_parent(&self, parent: &Self) -> Result<(), Error> {
        self.with_effective(|child| {
            parent.with_effective(|parent| {
                // This checks the unconditional domain and inherited-Admin rules.
                // The repository separately verifies the caller's actual authority;
                // policy values never establish its permission to widen grants.
                crate::properties::validate_boundary_transition(parent, child, true)
                    .map_err(|_| Error::Boundary)
            })
        })
    }
}

fn normalized_grants<'a>(grants: &[(&'a str, u8)]) -> Result<BTreeMap<&'a str, u8>, Error> {
    let mut output = BTreeMap::new();
    for (principal, mask) in grants {
        if *mask == 0 {
            continue;
        }
        let verbs = Verbs::new(*mask).map_err(|_| Error::Boundary)?;
        let mut effective = 0;
        for verb in [Verb::Read, Verb::Fork, Verb::Commit, Verb::Tag, Verb::Admin] {
            if verbs.contains(verb) {
                effective |= verb as u8;
            }
        }
        *output.entry(*principal).or_insert(0) |= effective;
    }
    Ok(output)
}
