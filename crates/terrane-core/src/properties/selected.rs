//! Resolves namespace policy under an explicitly selected registered execution.
//!
//! Selection describes semantics only. The genuine caller independently binds
//! it to each signed view; decoded names or revisions never grant authority.

use super::*;
use crate::indexing::IndexRoots;

/// Names exact registered namespace interpretations without selecting authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Selection {
    /// Retains the original 33-name Legacy property and attribute1 behavior.
    Legacy,
    /// Selects current property3/attribute2/tree1 execution explicitly.
    Active,
}

impl Selection {
    /// Resolves all ordinary values and exact owner-local structural bindings.
    ///
    /// # Errors
    /// Rejects unknown/malformed properties, inherited or graft-override pointers, every
    /// namespace index-gaps placement, invalid policy or excessive graft depth.
    pub fn resolve<'a>(
        self,
        path: &[RootLayer<'a>],
        defaults: Defaults<'a>,
    ) -> Result<EffectiveProperties<'a>, Error> {
        if self == Self::Legacy {
            return super::resolve(path, defaults);
        }
        for layer in path {
            if layer
                .overrides
                .iter()
                .any(|property| property.name == "index-roots")
            {
                return Err(Error::InvalidValue);
            }
            for properties in [layer.properties, layer.overrides] {
                if properties
                    .iter()
                    .any(|property| property.name == "index-gaps")
                {
                    return Err(Error::InvalidValue);
                }
                validate_preserved_map(properties, &["index-roots"])?;
                for property in properties {
                    if property.name == "index-roots" {
                        IndexRoots::decode_binding(property.value)
                            .map_err(|_| Error::InvalidValue)?;
                    }
                }
            }
        }
        // index-gaps is deliberately absent from the namespace registry here:
        // its only valid role is checked by the actual auxiliary primary loader.
        let mut effective = resolve_with_registry(path, defaults, &["index-roots"])?;
        if let Some(layer) = path.last() {
            let local = layer
                .properties
                .iter()
                .find(|property| property.name == "index-roots");
            effective.active_index_roots = local
                .map(|property| {
                    IndexRoots::decode_binding(property.value).map_err(|_| Error::InvalidValue)
                })
                .transpose()?;
        }
        Ok(effective)
    }
}

impl<'a> EffectiveProperties<'a> {
    /// Returns only the active final owning root's noninherited binding map.
    ///
    /// Ancestor bindings never become a descendant pointer. This ordinary data
    /// remains subject to actual owner-bound loading and complete relationship checks.
    pub fn active_index_roots(&self) -> Option<&IndexRoots<'a>> {
        self.active_index_roots.as_ref()
    }
}

#[cfg(test)]
mod tests;
