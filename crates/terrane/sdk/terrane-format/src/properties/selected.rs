//! Resolves namespace policy under an explicitly selected registered execution.
//!
//! Selection describes semantics only. The genuine caller independently binds
//! it to each signed view; decoded names or revisions never grant authority.

use super::*;
use crate::indexing::IndexRoots;

/// Names exact registered namespace interpretations without selecting authority.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Selection {
    /// Retains the original 33-name Legacy property and attribute1 behavior.
    Legacy,
    /// Selects current property3/attribute2/tree1 execution explicitly.
    Active,
    /// Retains independently supplied exact historical property interpretation.
    Recorded(super::semantics::RecordedContext),
}

impl Selection {
    /// Resolves all ordinary values and exact owner-local structural bindings.
    ///
    /// # Errors
    /// Rejects unknown or malformed properties, active inherited or graft-override
    /// pointers, active namespace gaps, invalid policy or excessive graft depth.
    /// Recorded preserve-only names receive canonical syntax validation only.
    pub fn resolve<'a>(
        &self,
        path: &[RootLayer<'a>],
        defaults: Defaults<'a>,
    ) -> Result<EffectiveProperties<'a>, Error> {
        match self {
            Self::Legacy => {
                super::semantics::RecordedContext::new(1, 1, &[])?.resolve(path, defaults)
            }
            Self::Active => {
                super::semantics::RecordedContext::new(3, 3, &[])?.resolve(path, defaults)
            }
            Self::Recorded(context) => context.resolve(path, defaults),
        }
    }

    /// Checks original maps before graft replacements can hide invalid placement.
    ///
    /// # Errors
    /// Rejects invalid raw maps or structural owner-local/graft placement.
    pub(crate) fn validate_layer(
        &self,
        properties: &[Property<'_>],
        overrides: &[Property<'_>],
    ) -> Result<(), Error> {
        match self {
            Self::Legacy => super::semantics::RecordedContext::new(1, 1, &[])?
                .validate_layer(properties, overrides),
            Self::Active => super::semantics::RecordedContext::new(3, 3, &[])?
                .validate_layer(properties, overrides),
            Self::Recorded(context) => context.validate_layer(properties, overrides),
        }
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
#[allow(
    clippy::unwrap_used,
    reason = "invalid selected-property test fixtures must fail their assertions"
)]
mod tests;
