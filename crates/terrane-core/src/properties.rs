//! Validates registered root properties and evaluates policy without I/O.
//!
//! Resolution follows the supplied graft path, including graft-local overrides.
//! Commit checks consume already available derived records and domain metadata;
//! callers remain responsible for fetching records and enforcing storage policy.

mod registry;
mod validation;
mod value;

pub use registry::{Class, PropertyName, Value, validate_property};
pub use validation::{
    CommitContext, Completeness, DerivedAttribute, EntryChange, completeness, registered_attribute,
    validate_commit, validate_commit_with_context,
};

use crate::cbor;
use crate::tree_format::{MAX_GRAFT_DEPTH, Property};
use alloc::vec::Vec;
use core::fmt;

/// A property validation or policy failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A value is malformed or noncanonical CBOR.
    Cbor(cbor::Error),
    /// A property name is not registered.
    UnknownProperty,
    /// A registered value has an invalid type or vocabulary.
    InvalidValue,
    /// An input exceeds its encoded or graft-depth bound.
    Limit,
    /// A required attribute is absent or invalid.
    MissingAttribute,
    /// Required reference-domain or graft-policy metadata is unavailable.
    IncompleteContext,
    /// An attribute name is not registered under strict policy.
    UnknownAttribute,
    /// A reference or domain transition would widen disclosure.
    Domain,
    /// A descendant widens commit or admin grants without authority.
    Authority,
}

impl From<cbor::Error> for Error {
    fn from(value: cbor::Error) -> Self {
        Self::Cbor(value)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Cbor(_) => "invalid property CBOR",
            Self::UnknownProperty => "unregistered property",
            Self::InvalidValue => "invalid property value",
            Self::Limit => "property input limit exceeded",
            Self::MissingAttribute => "missing required attribute",
            Self::IncompleteContext => "incomplete property validation context",
            Self::UnknownAttribute => "unregistered attribute",
            Self::Domain => "disclosure domain violation",
            Self::Authority => "unauthorized ACL widening",
        })
    }
}

impl core::error::Error for Error {}

/// A disclosure label with its registered sharing scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Domain<'a> {
    /// Content may be disclosed globally.
    Public,
    /// Content belongs to one tenant.
    Tenant(&'a str),
    /// Content belongs to one group.
    Group(&'a str),
    /// Content belongs to one private root.
    Private(&'a str),
}

impl<'a> Domain<'a> {
    /// Parses a registered disclosure-domain label.
    ///
    /// # Errors
    /// Returns [`Error::InvalidValue`] for an unknown kind or empty identifier.
    pub fn parse(label: &'a str) -> Result<Self, Error> {
        if label == "public" {
            return Ok(Self::Public);
        }
        let (kind, name) = label.split_once(':').ok_or(Error::InvalidValue)?;
        if name.is_empty() {
            return Err(Error::InvalidValue);
        }
        match kind {
            "tenant" => Ok(Self::Tenant(name)),
            "group" => Ok(Self::Group(name)),
            "private" => Ok(Self::Private(name)),
            _ => Err(Error::InvalidValue),
        }
    }

    /// Reports whether this domain may reference content in `source`.
    pub fn permits_reference(self, source: Self) -> bool {
        self == source
            || matches!(
                (self, source),
                (_, Self::Public)
                    | (Self::Group(_) | Self::Private(_), Self::Tenant(_))
                    | (Self::Private(_), Self::Group(_))
            )
    }
}

/// One root encountered in the current view's graft path.
#[derive(Clone, Copy, Debug)]
pub struct RootLayer<'a> {
    /// The referenced root's own properties.
    pub properties: &'a [Property<'a>],
    /// Properties on the graft entry, which override this root locally.
    pub overrides: &'a [Property<'a>],
}

/// Context-dependent registry defaults supplied by the repository.
#[derive(Clone, Copy, Debug)]
pub struct Defaults<'a> {
    /// Instance authority store expression name.
    pub store: &'a str,
    /// Private label for the current root when no domain is specified.
    pub private_domain: &'a str,
    /// Authority region captured at the first write.
    pub home: &'a str,
}

/// Effective policy resolved for one path through a view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveProperties<'a> {
    values: Vec<(PropertyName, Value<'a>)>,
}

impl<'a> EffectiveProperties<'a> {
    /// Returns a resolved, typed registry value.
    pub fn get(&self, property: PropertyName) -> Option<&Value<'a>> {
        self.values
            .iter()
            .find(|(name, _)| *name == property)
            .map(|(_, value)| value)
    }

    /// Returns the effective disclosure domain.
    ///
    /// # Errors
    /// Returns [`Error::InvalidValue`] if the effective domain is absent or invalid.
    pub fn domain(&self) -> Result<Domain<'a>, Error> {
        match self.get(PropertyName::Domain) {
            Some(Value::Text(label)) => Domain::parse(label),
            _ => Err(Error::InvalidValue),
        }
    }

    /// Reports equality of the domain, store, and ACL flatten boundaries.
    pub fn same_boundaries(&self, other: &Self) -> bool {
        [PropertyName::Domain, PropertyName::Store, PropertyName::Acl]
            .iter()
            .all(|name| self.get(*name) == other.get(*name))
    }
}

/// Resolves registered values along a view-specific, ancestor-first graft path.
///
/// No cache is retained. Unknown names are rejected; callers preserving later
/// registered names must keep their raw bytes outside behavioral policy.
///
/// # Errors
/// Rejects malformed properties, invalid defaults, and more than 64 graft edges.
pub fn resolve<'a>(
    path: &[RootLayer<'a>],
    defaults: Defaults<'a>,
) -> Result<EffectiveProperties<'a>, Error> {
    resolve_with_registry(path, defaults, &[])
}

/// Resolves known policy while preserving trusted later-version registrations.
///
/// Unknown registered properties remain in the supplied raw maps and do not
/// change behavior. The registry extension must come from a trusted schema,
/// never from names asserted by an untrusted property writer.
///
/// # Errors
/// Rejects unregistered or malformed values, invalid defaults, and excessive
/// graft depth, with the same rules as [`resolve`].
pub fn resolve_with_registry<'a>(
    path: &[RootLayer<'a>],
    defaults: Defaults<'a>,
    later_registered: &[&str],
) -> Result<EffectiveProperties<'a>, Error> {
    if path.len().saturating_sub(1) > MAX_GRAFT_DEPTH {
        return Err(Error::Limit);
    }
    let mut values = registry::defaults(defaults)?;
    let mut wipe_set = false;
    for (position, layer) in path.iter().enumerate() {
        for properties in [layer.properties, layer.overrides] {
            validate_preserved_map(properties, later_registered)?;
        }
        // A graft-local override replaces the whole binding, including its
        // inherit flag. A local non-inheriting override must not uncover the
        // referenced root's own value in descendant roots.
        for property in layer
            .properties
            .iter()
            .filter(|property| {
                !layer
                    .overrides
                    .iter()
                    .any(|other| other.name == property.name)
            })
            .chain(layer.overrides.iter())
        {
            if PropertyName::parse(property.name).is_err() {
                continue;
            }
            let (name, value) = validate_property(property)?;
            let (_, inherit) = registry::binding(property.value)?;
            if !inherit && position + 1 != path.len() {
                continue;
            }
            if name == PropertyName::Wipe {
                wipe_set = true;
            }
            if let Some(existing) = values.iter_mut().find(|(key, _)| *key == name) {
                existing.1 = value;
            }
        }
    }
    let mut effective = EffectiveProperties { values };
    if !wipe_set {
        let wipe = if matches!(effective.domain()?, Domain::Private(_)) {
            "zero"
        } else {
            "none"
        };
        if let Some((_, value)) = effective
            .values
            .iter_mut()
            .find(|(name, _)| *name == PropertyName::Wipe)
        {
            *value = Value::Text(wipe);
        }
    }
    validate_domain_policy(&effective)?;
    Ok(effective)
}

/// Validates all property names and values in a root property map.
///
/// # Errors
/// Rejects unknown names, duplicate names, oversized maps, or invalid values.
pub fn validate_map(properties: &[Property<'_>]) -> Result<(), Error> {
    let mut bytes = 0usize;
    for property in properties {
        if property.name.is_empty() || property.name.len() > 255 {
            return Err(Error::Limit);
        }
        bytes = bytes
            .checked_add(property.name.len())
            .and_then(|size| size.checked_add(property.value.len()))
            .ok_or(Error::Limit)?;
        if bytes > 65536 {
            return Err(Error::Limit);
        }
    }
    for (position, property) in properties.iter().enumerate() {
        if properties[..position]
            .iter()
            .any(|other| other.name == property.name)
        {
            return Err(Error::InvalidValue);
        }
        validate_property(property)?;
    }
    Ok(())
}

/// Checks that deduplication cannot exceed the effective domain's scope.
///
/// # Errors
/// Rejects global deduplication outside public domains or invalid policy.
pub fn validate_domain_policy(properties: &EffectiveProperties<'_>) -> Result<(), Error> {
    if properties.domain()? != Domain::Public
        && properties.get(PropertyName::Dedup) == Some(&Value::Text("global"))
    {
        return Err(Error::Domain);
    }
    Ok(())
}

/// Checks the domain and ACL transition between effective ancestor policies.
///
/// Repository callers pass the committing principal's verified `admin` grant
/// on the ancestor. Read resolution does not perform authorization checks.
///
/// # Errors
/// Rejects disclosure widening or unauthorized widening of commit/admin grants.
pub fn validate_boundary_transition(
    parent: &EffectiveProperties<'_>,
    child: &EffectiveProperties<'_>,
    ancestor_admin: bool,
) -> Result<(), Error> {
    if !child.domain()?.permits_reference(parent.domain()?) {
        return Err(Error::Domain);
    }
    if ancestor_admin {
        return Ok(());
    }
    let (Some(Value::Grants(parent_grants)), Some(Value::Grants(child_grants))) =
        (parent.get(PropertyName::Acl), child.get(PropertyName::Acl))
    else {
        return Err(Error::InvalidValue);
    };
    for (principal, verbs) in child_grants {
        let inherited = parent_grants
            .iter()
            .filter(|(name, _)| name == principal)
            .fold(0u8, |mask, (_, verbs)| mask | verbs);
        if verbs & 20 & !inherited != 0 {
            return Err(Error::Authority);
        }
    }
    Ok(())
}

/// Validates a later-version property map while preserving unsupported bytes.
///
/// `later_registered` is an explicit trusted registry extension. Unsupported
/// registered properties do not participate in resolution or behavior.
///
/// # Errors
/// Rejects unknown names not in either registry, invalid known properties,
/// duplicate names, malformed preserved CBOR, or an oversized map.
pub fn validate_preserved_map(
    properties: &[Property<'_>],
    later_registered: &[&str],
) -> Result<(), Error> {
    let mut bytes = 0usize;
    for property in properties {
        if property.name.is_empty() || property.name.len() > 255 {
            return Err(Error::Limit);
        }
        bytes = bytes
            .checked_add(property.name.len())
            .and_then(|size| size.checked_add(property.value.len()))
            .ok_or(Error::Limit)?;
        if bytes > 65536 {
            return Err(Error::Limit);
        }
    }
    for (position, property) in properties.iter().enumerate() {
        if properties[..position]
            .iter()
            .any(|other| other.name == property.name)
        {
            return Err(Error::InvalidValue);
        }
        match PropertyName::parse(property.name) {
            Ok(_) => {
                validate_property(property)?;
            }
            Err(_) if later_registered.contains(&property.name) => {
                let mut decoder = cbor::Decoder::new(property.value);
                value::skip_value(&mut decoder, 65536)?;
                decoder.finish()?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;

#[cfg(test)]
#[allow(clippy::expect_used)]
mod depth_tests;
