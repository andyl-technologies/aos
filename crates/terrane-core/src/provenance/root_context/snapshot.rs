//! Compares actual root occurrences while ignoring propagated graft target hashes.

use super::super::{Rejected, VerifiedHistory};
use super::bootstrap;
use crate::{
    identity::{Digest, IdentityKind, TERRANE_V1},
    properties::{self, Defaults, PropertyName, RootLayer, Value},
    tree_format::{self, EntryKind, Property},
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

pub(super) fn private_owner(root: Digest) -> Result<String, Rejected> {
    let identity = TERRANE_V1
        .from_digest(IdentityKind::Node, &root)
        .map_err(|_| Rejected)?;
    let digest: String = root.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!(
        "private:{}:{:?}:{digest}",
        identity.profile(),
        identity.kind()
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PolicyValue {
    Text(String),
    Unsigned(u64),
    Boolean(bool),
    Names(Vec<String>),
    Ttl(u64),
    Count(u64),
    Quota(u64, u64),
    Grants(Vec<(String, u8)>),
    Selector(Vec<u8>),
    Unset,
}

impl From<&Value<'_>> for PolicyValue {
    fn from(value: &Value<'_>) -> Self {
        match value {
            Value::Text(value) => Self::Text((*value).to_string()),
            Value::Unsigned(value) => Self::Unsigned(*value),
            Value::Boolean(value) => Self::Boolean(*value),
            Value::Names(values) => {
                Self::Names(values.iter().map(|value| (*value).to_string()).collect())
            }
            Value::Ttl(value) => Self::Ttl(*value),
            Value::Count(value) => Self::Count(*value),
            Value::Quota { root, principal } => Self::Quota(*root, *principal),
            Value::Grants(values) => Self::Grants(
                values
                    .iter()
                    .map(|(name, verbs)| ((*name).to_string(), *verbs))
                    .collect(),
            ),
            Value::Selector(bytes) => Self::Selector(bytes.to_vec()),
            Value::Unset => Self::Unset,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct Root {
    pub path: Vec<u8>,
    pub identity: Digest,
    pub domain: String,
    pub entries: Vec<(Vec<u8>, Vec<u8>)>,
    effective: Vec<(PropertyName, PolicyValue)>,
    local: Vec<(String, Vec<u8>)>,
}

impl Root {
    pub fn acl_changed(&self, other: &Self) -> bool {
        self.effective
            .iter()
            .find(|(name, _)| *name == PropertyName::Acl)
            != other
                .effective
                .iter()
                .find(|(name, _)| *name == PropertyName::Acl)
    }

    pub fn widens_delegation(&self, ancestor: &Self) -> bool {
        self.acl()
            .zip(ancestor.acl())
            .is_none_or(|(child, parent)| bootstrap::widens(child, parent))
    }

    /// Returns the actual effective principal/group grants on this occurrence.
    pub fn acl(&self) -> Option<&[(String, u8)]> {
        match self
            .effective
            .iter()
            .find(|(name, _)| *name == PropertyName::Acl)
        {
            Some((_, PolicyValue::Grants(acl))) => Some(acl),
            _ => None,
        }
    }

    pub fn implicit_owner(&self) -> bool {
        !self.local.iter().any(|(name, _)| name == "domain")
    }

    pub fn same_policy(&self, other: &Self) -> bool {
        if self.effective != other.effective {
            return false;
        }
        let old = self
            .local
            .iter()
            .filter(|(name, _)| name != "domain")
            .collect::<Vec<_>>();
        let new = other
            .local
            .iter()
            .filter(|(name, _)| name != "domain")
            .collect::<Vec<_>>();
        if old != new {
            return false;
        }
        let old_domain = self
            .local
            .iter()
            .find(|(name, _)| name == "domain")
            .map(|(_, bytes)| bytes);
        let new_domain = other
            .local
            .iter()
            .find(|(name, _)| name == "domain")
            .map(|(_, bytes)| bytes);
        if old_domain == new_domain {
            return true;
        }
        // DOM-1 materializes an existing implicit owner as a bare inheriting
        // domain label. It does not change local or descendant effective policy.
        match (old_domain, new_domain) {
            (None, Some(bytes)) => {
                bytes.first().is_some_and(|byte| byte >> 5 == 3) && self.domain == other.domain
            }
            _ => false,
        }
    }
}

pub(super) struct Snapshot {
    pub roots: BTreeMap<Vec<u8>, Root>,
}

fn properties<'a>(
    history: &'a VerifiedHistory,
    root: Digest,
    overrides: Vec<Property<'a>>,
) -> Result<Vec<Property<'a>>, Rejected> {
    let mut properties = history.root_properties(root)?;
    for replacement in overrides {
        properties.retain(|property| property.name != replacement.name);
        properties.push(replacement);
    }
    properties.sort_by(|left, right| left.name.cmp(right.name));
    Ok(properties)
}

fn state(
    root: Digest,
    path: Vec<u8>,
    layers: &[Vec<Property<'_>>],
    defaults: Defaults<'_>,
    selection: properties::selected::Selection,
) -> Result<Root, Rejected> {
    let policy_layers: Vec<_> = layers
        .iter()
        .map(|properties| RootLayer {
            properties,
            overrides: &[],
        })
        .collect();
    let policy = selection
        .resolve(&policy_layers, defaults)
        .map_err(|_| Rejected)?;
    if policy_layers.len() > 1 {
        let parent = selection
            .resolve(&policy_layers[..policy_layers.len() - 1], defaults)
            .map_err(|_| Rejected)?;
        if !policy
            .domain()
            .map_err(|_| Rejected)?
            .permits_reference(parent.domain().map_err(|_| Rejected)?)
        {
            return Err(Rejected);
        }
        let (Some(Value::Grants(parent)), Some(Value::Grants(child))) =
            (parent.get(PropertyName::Acl), policy.get(PropertyName::Acl))
        else {
            return Err(Rejected);
        };
        // AUTH-25 protects existing ancestor administrators even when the
        // current author has Admin. Delegation permission cannot erase them.
        for (principal, _) in parent.iter().filter(|(_, verbs)| verbs & 16 != 0) {
            let inherited = child
                .iter()
                .filter(|(name, _)| name == principal)
                .fold(0u8, |mask, (_, verbs)| mask | verbs);
            // AUTH-22's Admin implication preserves every registered verb.
            if inherited & 16 == 0 {
                return Err(Rejected);
            }
        }
    }
    let domain = match policy.get(PropertyName::Domain) {
        Some(Value::Text(domain)) => (*domain).to_string(),
        _ => return Err(Rejected),
    };
    let effective = PropertyName::ALL
        .iter()
        .map(|name| Ok((*name, PolicyValue::from(policy.get(*name).ok_or(Rejected)?))))
        .collect::<Result<Vec<_>, Rejected>>()?;
    let local = layers
        .last()
        .ok_or(Rejected)?
        .iter()
        .map(|property| (property.name.to_string(), property.value.to_vec()))
        .collect();
    Ok(Root {
        path,
        identity: root,
        domain,
        entries: Vec::new(),
        effective,
        local,
    })
}

pub(super) fn complete(
    history: &VerifiedHistory,
    root: Digest,
    defaults: Defaults<'_>,
    selection: properties::selected::Selection,
) -> Result<Snapshot, Rejected> {
    let private_domain = private_owner(root)?;
    let defaults = Defaults {
        private_domain: &private_domain,
        ..defaults
    };
    let mut roots = BTreeMap::new();
    let mut pending = vec![(
        root,
        Vec::new(),
        Vec::new(),
        Vec::<Property<'_>>::new(),
        BTreeSet::new(),
    )];
    while let Some((root, prefix, mut layers, overrides, mut ancestors)) = pending.pop() {
        if !ancestors.insert(root) || ancestors.len() > tree_format::MAX_GRAFT_DEPTH + 1 {
            return Err(Rejected);
        }
        if !prefix.is_empty() {
            tree_format::validate_key(&prefix).map_err(|_| Rejected)?;
        }
        layers.push(properties(history, root, overrides)?);
        let mut absolute = vec![b'/'];
        absolute.extend_from_slice(&prefix);
        let mut current = state(root, absolute.clone(), &layers, defaults, selection)?;
        for item in history.root_items(root)? {
            let mut entry = item.entry;
            if let EntryKind::Tree {
                root: target,
                props,
            } = &mut entry.kind
            {
                let mut child_path = prefix.clone();
                if !child_path.is_empty() {
                    child_path.push(b'/');
                }
                child_path.extend_from_slice(&item.key);
                pending.push((
                    *target,
                    child_path,
                    layers.clone(),
                    props.clone().unwrap_or_default(),
                    ancestors.clone(),
                ));
                // The containing root's descriptor retains all metadata. Only
                // the immutable target digest is propagated from child edits.
                *target = [0; 32];
            }
            current.entries.push((
                item.key,
                tree_format::encode_entry(&entry, history.min_chunk_size())
                    .map_err(|_| Rejected)?,
            ));
        }
        current.entries.sort();
        if roots.insert(absolute, current).is_some() {
            return Err(Rejected);
        }
    }
    Ok(Snapshot { roots })
}

/// Resolves only a claimed root path, preserving constant-cost copied-tree checks.
pub(super) fn at_path(
    history: &VerifiedHistory,
    root: Digest,
    path: &[u8],
    defaults: Defaults<'_>,
    selection: properties::selected::Selection,
) -> Result<Root, Rejected> {
    let private_domain = private_owner(root)?;
    let defaults = Defaults {
        private_domain: &private_domain,
        ..defaults
    };
    if path.first() != Some(&b'/') {
        return Err(Rejected);
    }
    let relative = &path[1..];
    if !relative.is_empty() {
        tree_format::validate_key(relative).map_err(|_| Rejected)?;
    }
    let mut root = root;
    let mut remaining = relative;
    let mut layers = Vec::new();
    let mut overrides = Vec::new();
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(root) || seen.len() > tree_format::MAX_GRAFT_DEPTH + 1 {
            return Err(Rejected);
        }
        layers.push(properties(history, root, overrides)?);
        if remaining.is_empty() {
            return state(root, path.to_vec(), &layers, defaults, selection);
        }
        let mut selected = None;
        for end in
            (1..=remaining.len()).filter(|end| *end == remaining.len() || remaining[*end] == b'/')
        {
            let Ok(entry) = history.root_entry(root, &remaining[..end]) else {
                continue;
            };
            if let EntryKind::Tree { root: child, props } = &entry.kind {
                selected = Some((*child, end, props.clone().unwrap_or_default()));
                break;
            }
        }
        let (child, end, properties) = selected.ok_or(Rejected)?;
        remaining = if end == remaining.len() {
            &[]
        } else {
            &remaining[end + 1..]
        };
        root = child;
        overrides = properties;
    }
}
