//! Checks terminal currency of the same original installation owners.
//!
//! These callbacks lend existing revisions; this helper creates no owner or
//! acceptance. Every original is checked after the final callback, because a
//! later behavioral or class inspection can withdraw an earlier source.

use std::rc::Rc;

use crucible_engine::{
    node_admission::EvidenceError,
    node_contract::{
        InstalledProviderBehavioral, InstalledProviderSource, ProviderAuthorityKind,
        ProviderAuthorizationLease, ProviderAuthorizationScope,
    },
};

#[cfg(test)]
#[path = "currency_tests.rs"]
mod tests;

pub(super) fn original_behavioral(
    scope: &ProviderAuthorizationScope,
    source: impl FnOnce() -> Result<ProviderAuthorizationLease, EvidenceError>,
    behavioral: impl FnOnce() -> Result<ProviderAuthorizationLease, EvidenceError>,
    class: impl FnOnce() -> Result<ProviderAuthorizationLease, EvidenceError>,
) -> Result<ProviderAuthorizationLease, EvidenceError> {
    let original_source = source()?;
    let original_behavioral = behavioral()?;
    let original_class = class()?;

    original_source.authenticate(scope, ProviderAuthorityKind::Source)?;
    original_behavioral.authenticate(scope, ProviderAuthorityKind::Behavioral)?;
    original_class.authenticate(scope, ProviderAuthorityKind::CatalogClass)?;
    Ok(original_behavioral)
}

// Retains real installation owners; a portable selection cannot construct them.
pub(super) struct OriginalBirthAuthorities {
    pub(super) source: Rc<dyn InstalledProviderSource>,
    pub(super) behavioral: Rc<dyn InstalledProviderBehavioral>,
    pub(super) class: Rc<dyn crate::node_qualification::InstalledAcceptancePolicy>,
    pub(super) scope: ProviderAuthorizationScope,
}

impl OriginalBirthAuthorities {
    pub(super) fn retain_original(&self) -> Result<OriginalBirthCurrency, EvidenceError> {
        let source = self.source.current_source_revision(&self.scope)?;
        let behavioral = self.behavioral.current_behavioral_revision(&self.scope)?;
        let class = self
            .class
            .provider_revision(&self.scope)
            .map_err(|error| EvidenceError {
                message: error.to_string(),
            })?;
        let original = OriginalBirthCurrency {
            scope: self.scope.clone(),
            source,
            behavioral,
            class,
        };
        original.authenticate()?;
        Ok(original)
    }
}

// This exact tuple stays in the original launch/queue holder across every
// repeated plan/preflight callback and the final actual birth check.
pub(super) struct OriginalBirthCurrency {
    scope: ProviderAuthorizationScope,
    source: ProviderAuthorizationLease,
    behavioral: ProviderAuthorizationLease,
    class: ProviderAuthorizationLease,
}

impl OriginalBirthCurrency {
    pub(super) fn scope(&self) -> &ProviderAuthorizationScope {
        &self.scope
    }

    fn authenticate(&self) -> Result<(), EvidenceError> {
        self.source
            .authenticate(&self.scope, ProviderAuthorityKind::Source)?;
        self.behavioral
            .authenticate(&self.scope, ProviderAuthorityKind::Behavioral)?;
        self.class
            .authenticate(&self.scope, ProviderAuthorityKind::CatalogClass)
    }

    pub(super) fn before_birth<T>(
        &self,
        spawn_original: impl FnOnce() -> Result<T, crucible_node_transport::ProviderError>,
    ) -> Result<T, crucible_node_transport::ProviderError> {
        self.authenticate().map_err(|error| {
            crucible_node_transport::ProviderError::Io(std::io::Error::other(error.message))
        })?;
        spawn_original()
    }
}
