//! Preserves resolved disclosure ownership when algebra encodes a changed root.
//!
//! Native admission supplies effective labels after resolving the actual view's
//! ancestors and graft overrides. A label is bound to its immutable input root;
//! an algebra edit never invents ownership from the new root's identity.
//!
//! Recipes record ownership as canonical, root-sorted pairs:
//! ```text
//! "domains": [[input-root-digest, "private:previous-owner"], ...]
//! ```

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::identity::Digest;
use crate::properties::{self, EffectiveProperties, PropertyName, Value};
use crate::tree_builder::Tree;
use crate::tree_format::Property;

#[cfg(test)]
#[path = "domain_tests.rs"]
mod tests;

/// A missing, ambiguous, or malformed operation ownership binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DomainError {
    /// The input has neither resolved context nor an explicit domain property.
    Missing(Digest),
    /// One immutable root was bound to different effective domains.
    Ambiguous(Digest),
    /// Serialized recipe labels have not been bound to trusted resolution.
    Unverified,
    /// A supplied label or encoded property is invalid.
    Property(properties::Error),
}

impl core::fmt::Display for DomainError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Missing(_) => formatter.write_str("root edit requires effective domain context"),
            Self::Ambiguous(_) => formatter.write_str("root has ambiguous effective domains"),
            Self::Unverified => formatter.write_str("recipe domain evidence requires verification"),
            Self::Property(error) => error.fmt(formatter),
        }
    }
}

impl core::error::Error for DomainError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Property(error) => Some(error),
            _ => None,
        }
    }
}

/// Owns effective disclosure labels bound to immutable operation inputs.
///
/// The caller obtains these properties from trusted resolution of its actual
/// view, including ancestor properties and graft overrides. Syntax validation
/// does not authenticate that resolution. Keep this owner alive while using
/// materialized trees, whose explicit domain properties borrow its bytes.
/// A root appearing with different inherited labels requires separate operation
/// contexts; one registry rejects that ambiguity rather than choosing a label.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationDomains {
    labels: BTreeMap<Digest, Vec<u8>>,
    authenticated: bool,
}

impl Default for OperationDomains {
    fn default() -> Self {
        Self {
            labels: BTreeMap::new(),
            authenticated: true,
        }
    }
}

impl OperationDomains {
    /// Creates an empty operation ownership registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Binds a root to the effective domain resolved by the trusted caller.
    ///
    /// # Errors
    /// Rejects an invalid or absent effective domain and a different label
    /// already bound to the same root identity.
    pub fn bind_resolved(
        &mut self,
        root: Digest,
        effective: &EffectiveProperties<'_>,
    ) -> Result<(), DomainError> {
        if !self.authenticated {
            return Err(DomainError::Unverified);
        }
        effective.domain().map_err(DomainError::Property)?;
        let Some(Value::Text(label)) = effective.get(PropertyName::Domain) else {
            return Err(DomainError::Property(properties::Error::InvalidValue));
        };
        let mut encoded = Vec::new();
        crate::cbor::write_text(&mut encoded, label);

        if let Some(previous) = self.labels.get(&root) {
            if previous != &encoded {
                return Err(DomainError::Ambiguous(root));
            }
            return Ok(());
        }
        self.labels.insert(root, encoded);
        Ok(())
    }

    pub(super) fn encode(&self, output: &mut Vec<u8>) {
        crate::cbor::write_array(output, self.labels.len());
        for (root, domain) in &self.labels {
            crate::cbor::write_array(output, 2);
            crate::cbor::write_bytes(output, root);
            output.extend_from_slice(domain);
        }
    }

    pub(super) fn decode(
        decoder: &mut crate::cbor::Decoder<'_>,
        limit: usize,
    ) -> Result<Self, super::RecipeError> {
        let count = decoder.array(limit).map_err(super::RecipeError::Encoding)?;
        let mut labels = BTreeMap::new();
        let mut previous = None;
        for _ in 0..count {
            if decoder.array(2).map_err(super::RecipeError::Encoding)? != 2 {
                return Err(super::RecipeError::Schema);
            }
            let root: Digest = decoder
                .bytes(32)
                .map_err(super::RecipeError::Encoding)?
                .try_into()
                .map_err(|_| super::RecipeError::Schema)?;
            if previous.is_some_and(|previous| previous >= root) {
                return Err(super::RecipeError::Schema);
            }
            let label = decoder.text(limit).map_err(super::RecipeError::Encoding)?;
            properties::Domain::parse(label).map_err(|_| super::RecipeError::Schema)?;
            let mut encoded = Vec::new();
            crate::cbor::write_text(&mut encoded, label);
            labels.insert(root, encoded);
            previous = Some(root);
        }
        Ok(Self {
            labels,
            authenticated: false,
        })
    }

    pub(super) fn bind(&self, trusted: &Self) -> Result<Self, super::RecipeError> {
        if !trusted.authenticated || self.labels != trusted.labels {
            return Err(super::RecipeError::Schema);
        }
        Ok(trusted.clone())
    }
}

fn explicit_domain<'a>(properties: Option<&[Property<'a>]>) -> Option<Property<'a>> {
    properties?
        .iter()
        .find(|property| property.name == "domain")
        .copied()
}

fn domain_label<'a>(property: &Property<'a>) -> Result<&'a str, DomainError> {
    let (_, value) = properties::validate_property(property).map_err(DomainError::Property)?;
    let Value::Text(label) = value else {
        return Err(DomainError::Property(properties::Error::InvalidValue));
    };
    properties::Domain::parse(label).map_err(DomainError::Property)?;
    Ok(label)
}

pub(super) fn preserved_properties<'a>(
    source: &Tree<'a>,
    proposed: Option<Vec<Property<'a>>>,
    domains: Option<&'a OperationDomains>,
) -> Result<Option<Vec<Property<'a>>>, super::Error> {
    if domains.is_some_and(|domains| !domains.authenticated) {
        return Err(super::Error::DomainContext(DomainError::Unverified));
    }
    let original = explicit_domain(source.props());
    let resolved = domains
        .and_then(|domains| domains.labels.get(&source.root_identity()))
        .map(|value| Property {
            name: "domain",
            value,
        })
        .or(original)
        .ok_or_else(|| super::Error::DomainContext(DomainError::Missing(source.root_identity())))?;
    let resolved_label = domain_label(&resolved).map_err(super::Error::DomainContext)?;

    let mut properties = proposed.unwrap_or_default();
    if let Some(current) = properties
        .iter_mut()
        .find(|property| property.name == "domain")
    {
        // A domain deliberately changed by metadata merge remains a metadata
        // change. An unchanged raw binding must retain the actual view's owner,
        // which may have been supplied by a graft-local override.
        if Some(*current) == original
            && domain_label(current).map_err(super::Error::DomainContext)? != resolved_label
        {
            *current = resolved;
        }
    } else {
        properties.push(resolved);
    }
    properties.sort_by(|left, right| {
        left.name
            .len()
            .cmp(&right.name.len())
            .then_with(|| left.name.as_bytes().cmp(right.name.as_bytes()))
    });
    Ok(Some(properties))
}

pub(super) fn preserve<'a>(
    source: &Tree<'a>,
    result: Tree<'a>,
    domains: Option<&'a OperationDomains>,
) -> Result<crate::tree_builder::Mutation<'a>, super::Error> {
    let properties = preserved_properties(source, result.props().map(<[_]>::to_vec), domains)?;
    Ok(result.with_properties(properties)?)
}

pub(super) fn owned_context(
    source: &Tree<'_>,
    domains: Option<&OperationDomains>,
) -> Result<OperationDomains, super::Error> {
    let properties = preserved_properties(source, None, domains)?;
    let property = explicit_domain(properties.as_deref())
        .ok_or_else(|| super::Error::DomainContext(DomainError::Missing(source.root_identity())))?;
    let label = domain_label(&property).map_err(super::Error::DomainContext)?;
    let mut encoded = Vec::new();
    crate::cbor::write_text(&mut encoded, label);
    Ok(OperationDomains {
        labels: BTreeMap::from([(source.root_identity(), encoded)]),
        authenticated: true,
    })
}

pub(super) fn encoded_domain(
    context: &OperationDomains,
    root: &Digest,
) -> Result<Vec<u8>, super::Error> {
    context
        .labels
        .get(root)
        .cloned()
        .ok_or(super::Error::DomainContext(DomainError::Missing(*root)))
}
