//! Callback-free terminal currency of installed original provider authorities.
//!
//! A revision is a revocation fence, not qualification evidence. Source and
//! behavioral validation, including the ordinary catalog's accepted report and
//! required classes, remain mandatory before any terminal lease is consumed.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crucible_node_contract::{ContentRef, HashRef, Id, ResourceLimits};

use crate::node_admission::EvidenceError;

use super::{ProviderPlanningRequest, ProviderPreparationPlan};

/// Binds a retained revision to exact original profile and planning metadata.
#[derive(Clone, Debug, PartialEq)]
pub struct ProviderAuthorizationScope {
    profile: Id,
    configuration: ContentRef,
    bindings: Vec<HashRef>,
    resources: ResourceLimits,
}

impl ProviderAuthorizationScope {
    /// Derives finite revision scope from independently validated original data.
    ///
    /// This data constructor grants no source installation, behavioral acceptance
    /// or native permission. Each installed authority must compare it with its
    /// own authenticated original scope before lending a revision.
    ///
    /// # Errors
    /// Refuses excessive metadata or node count and invalid binding identities.
    pub fn from_plan(
        selection: ProviderPlanningRequest<'_>,
        plan: &ProviderPreparationPlan,
    ) -> Result<Self, EvidenceError> {
        let maximum = super::ProviderRegistryLimits::default();
        if selection.limits.metadata_bytes == 0
            || selection.limits.metadata_bytes > maximum.metadata_bytes
            || plan.bindings.is_empty()
            || plan.bindings.len() > super::ProviderRegistryLimits::default().nodes
            || plan.bindings.len() != selection.nodes.len()
            || plan
                .bindings
                .iter()
                .zip(selection.nodes)
                .any(|(binding, node)| &binding.node_id != node)
        {
            return Err(refused("provider revision lacks a finite original roster"));
        }
        super::installed_provider::credit(
            &(
                selection.profile,
                selection.configuration,
                selection.resources,
                plan,
            ),
            selection.limits.metadata_bytes,
        )?;
        let mut bindings = Vec::new();
        bindings
            .try_reserve_exact(plan.bindings.len())
            .map_err(|_| refused("provider revision storage unavailable"))?;
        for binding in &plan.bindings {
            bindings.push(
                binding
                    .identity()
                    .map_err(|error| refused(&error.to_string()))?,
            );
        }
        Ok(Self {
            profile: selection.profile.clone(),
            configuration: selection.configuration.clone(),
            bindings,
            resources: selection.resources.clone(),
        })
    }

    /// Borrows the exact original selected profile.
    pub fn profile(&self) -> &Id {
        &self.profile
    }

    /// Borrows the full original configuration commitment.
    pub fn configuration(&self) -> &ContentRef {
        &self.configuration
    }

    /// Borrows all complete binding identities in original node order.
    pub fn binding_hashes(&self) -> &[HashRef] {
        &self.bindings
    }

    /// Borrows the unchanged original resource ceilings.
    pub fn resources(&self) -> &ResourceLimits {
        &self.resources
    }
}

/// Identifies which independent installed authority owns a retained revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderAuthorityKind {
    /// Independently installed original source and schema owner.
    Source,
    /// Registered behavioral evidence owner.
    Behavioral,
    /// The ordinary catalog's actual normal class and accepted-report owner.
    CatalogClass,
}

/// Owns a monotonic revision fence next to an installed original authority.
///
/// The operator-installed authority retains this owner with its authenticated
/// original source or accepted report. Withdrawing that scope must revoke this
/// same owner. Constructing a fence never qualifies a profile or report.
pub struct InstalledProviderRevision {
    scope: Arc<ProviderAuthorizationScope>,
    kind: ProviderAuthorityKind,
    current: Arc<AtomicBool>,
}

impl InstalledProviderRevision {
    /// Creates a fence for an authority's exact retained original scope.
    ///
    /// This installation operation has no portable DTO or serialized authority.
    /// It cannot substitute for source validation or the catalog's complete
    /// current class acceptance and authentic original evidence.
    pub fn new(scope: ProviderAuthorizationScope, kind: ProviderAuthorityKind) -> Self {
        Self {
            scope: Arc::new(scope),
            kind,
            current: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Revokes all original leases permanently without invoking user callbacks.
    pub fn revoke(&self) {
        self.current.store(false, Ordering::Release);
    }

    /// Lends this exact original revision without renewing a withdrawn scope.
    pub fn lease(&self) -> ProviderAuthorizationLease {
        ProviderAuthorizationLease {
            scope: Arc::clone(&self.scope),
            kind: self.kind,
            current: Arc::clone(&self.current),
        }
    }
}

impl Drop for InstalledProviderRevision {
    fn drop(&mut self) {
        self.revoke();
    }
}

/// Borrows direct currency of one retained original installed authority.
///
/// There is no public lease constructor or renewal. Checking this object calls
/// no source, provider, policy or evidence code. It grants no acceptance itself.
#[derive(Clone)]
pub struct ProviderAuthorizationLease {
    scope: Arc<ProviderAuthorizationScope>,
    kind: ProviderAuthorityKind,
    current: Arc<AtomicBool>,
}

impl ProviderAuthorizationLease {
    /// Checks exact scope, authority role and original currency without callbacks.
    ///
    /// # Errors
    /// Refuses foreign scopes or roles, withdrawn owners and dropped originals.
    pub fn authenticate(
        &self,
        scope: &ProviderAuthorizationScope,
        kind: ProviderAuthorityKind,
    ) -> Result<(), EvidenceError> {
        if self.scope.as_ref() != scope
            || self.kind != kind
            || !self.current.load(Ordering::Acquire)
        {
            return Err(refused(
                "installed provider original revision is foreign or withdrawn",
            ));
        }
        Ok(())
    }

    /// Checks membership of an exact original node beneath its source revision.
    ///
    /// Native identity and session inspection remain mandatory. This check
    /// grants no operation permission or class acceptance to a copied binding.
    ///
    /// # Errors
    /// Refuses a foreign profile, binding, role or withdrawn original owner.
    pub fn authenticate_node(&self, profile: &Id, binding: &HashRef) -> Result<(), EvidenceError> {
        if self.kind != ProviderAuthorityKind::Source
            || &self.scope.profile != profile
            || !self.scope.bindings.contains(binding)
            || !self.current.load(Ordering::Acquire)
        {
            return Err(refused(
                "original vendor node source revision is withdrawn or foreign",
            ));
        }
        Ok(())
    }
}

fn refused(message: &str) -> EvidenceError {
    EvidenceError {
        message: message.into(),
    }
}

/// Retains the same independently installed currency fences through callbacks.
///
/// Only the registry constructs this object after full source and behavioral
/// authentication. It is never a portable acceptance record or native permit.
pub(super) struct ProviderPreparationAuthorization {
    scope: ProviderAuthorizationScope,
    source: ProviderAuthorizationLease,
    behavioral: ProviderAuthorizationLease,
    class: Option<ProviderAuthorizationLease>,
}

impl ProviderPreparationAuthorization {
    pub(super) fn new(
        scope: ProviderAuthorizationScope,
        source: ProviderAuthorizationLease,
        behavioral: ProviderAuthorizationLease,
        class: Option<ProviderAuthorizationLease>,
    ) -> Self {
        Self {
            scope,
            source,
            behavioral,
            class,
        }
    }

    pub(super) fn authenticate(&self, require_class: bool) -> Result<(), EvidenceError> {
        self.source
            .authenticate(&self.scope, ProviderAuthorityKind::Source)?;
        self.behavioral
            .authenticate(&self.scope, ProviderAuthorityKind::Behavioral)?;
        match &self.class {
            Some(class) => class.authenticate(&self.scope, ProviderAuthorityKind::CatalogClass),
            None if require_class => Err(refused("ordinary vendor class revision absent")),
            None => Ok(()),
        }
    }
}
