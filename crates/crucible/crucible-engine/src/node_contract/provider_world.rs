//! Installed complete-world source semantics and original mixed-provider currency.
//!
//! Local provider evidence cannot authenticate cross-provider coordination. A
//! separately installed world source must authenticate the complete partition,
//! configuration and owner activation. A revision fence observes that original
//! authority; constructing the fence is never acceptance or execution permission.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crucible_node_format::{HashRef, Id, canonical};

use crate::node_admission::{AdmissionEvidence, EvidenceError};

use super::{
    ActivationRecord, ProviderAuthorizationScope, ProviderPreparationPlan, ProviderRegistryLimits,
};

/// Commits to a complete source-installed partition and original activation.
#[derive(Clone, Debug, PartialEq)]
pub struct ProviderWorldAuthorizationScope {
    plan_hash: HashRef,
    contributions: Vec<(Id, ProviderAuthorizationScope)>,
    activation: ActivationRecord,
}

impl ProviderWorldAuthorizationScope {
    pub(super) fn new(
        plan: &ProviderPreparationPlan,
        contributions: Vec<(Id, ProviderAuthorizationScope)>,
        activation: &ActivationRecord,
        limits: ProviderRegistryLimits,
    ) -> Result<Self, EvidenceError> {
        super::installed_provider::credit(
            &(
                plan,
                &contributions,
                &activation.activation_id,
                &activation.world_binding_hash,
                activation.generation,
                activation.boundary,
                &activation.owners,
            ),
            limits.metadata_bytes,
        )?;
        let plan_hash =
            canonical::json_hash("cnp.provider-world-plan.v1", plan).map_err(|error| {
                EvidenceError {
                    message: error.to_string(),
                }
            })?;
        Ok(Self {
            plan_hash,
            contributions,
            activation: activation.clone(),
        })
    }

    /// Borrows the full original plan commitment.
    pub fn plan_hash(&self) -> &HashRef {
        &self.plan_hash
    }

    /// Borrows exact installed provider identities and their original scopes.
    pub fn contributions(&self) -> &[(Id, ProviderAuthorizationScope)] {
        &self.contributions
    }

    /// Borrows the original complete world incarnation and cut.
    pub fn activation(&self) -> &ActivationRecord {
        &self.activation
    }
}

/// Authenticates complete world source semantics independently of local providers.
///
/// The catalog installs this trusted owner, not a portable selection or remote
/// response. Its content/schema/global-claim methods must authenticate complete
/// original coordination, causal connections and selected preservation policy.
pub trait InstalledProviderWorldSource: AdmissionEvidence {
    /// Authenticates the full original partition and planning before native birth.
    ///
    /// # Errors
    /// Refuses absent whole-world qualification, foreign partitions or unsupported
    /// cross-provider source semantics. Local accepted profiles are insufficient.
    fn authenticate_world_plan(
        &self,
        scope: &ProviderWorldAuthorizationScope,
        plan: &ProviderPreparationPlan,
    ) -> Result<(), EvidenceError>;

    /// Authenticates complete actual inactive originals under the global slot.
    ///
    /// # Errors
    /// Defaults to refusal without installed full-world native source inspection.
    fn authenticate_world_prepared(
        &self,
        _scope: &ProviderWorldAuthorizationScope,
        _prepared: &super::PreparedRealization,
    ) -> Result<(), EvidenceError> {
        Err(EvidenceError {
            message: "mixed world native source inspection unsupported".into(),
        })
    }

    /// Lends direct currency of this same authenticated whole-world source.
    ///
    /// # Errors
    /// Defaults to refusal without retained original world revision ownership.
    fn current_world_revision(
        &self,
        _scope: &ProviderWorldAuthorizationScope,
    ) -> Result<ProviderWorldAuthorizationLease, EvidenceError> {
        Err(EvidenceError {
            message: "mixed world source revision unsupported".into(),
        })
    }
}

/// Retains a monotonic fence beside the authentic complete-world source owner.
///
/// Issuance requires independently installed original source ownership and never
/// replaces that owner's complete plan, native or ordinary class authentication.
pub struct InstalledProviderWorldRevision {
    scope: Arc<ProviderWorldAuthorizationScope>,
    current: Arc<AtomicBool>,
}

impl InstalledProviderWorldRevision {
    /// Creates a currency fence for an already authenticated original world scope.
    pub fn new(scope: ProviderWorldAuthorizationScope) -> Self {
        Self {
            scope: Arc::new(scope),
            current: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Permanently withdraws every lease of the same original world authority.
    pub fn revoke(&self) {
        self.current.store(false, Ordering::Release);
    }

    /// Borrows original currency without renewing a revoked world scope.
    pub fn lease(&self) -> ProviderWorldAuthorizationLease {
        ProviderWorldAuthorizationLease {
            scope: Arc::clone(&self.scope),
            current: Arc::clone(&self.current),
        }
    }
}

impl Drop for InstalledProviderWorldRevision {
    fn drop(&mut self) {
        self.revoke();
    }
}

/// Checks original world currency without any callback or serialized authority.
#[derive(Clone)]
pub struct ProviderWorldAuthorizationLease {
    scope: Arc<ProviderWorldAuthorizationScope>,
    current: Arc<AtomicBool>,
}

impl ProviderWorldAuthorizationLease {
    /// Checks the exact original world scope and owner without external callbacks.
    ///
    /// # Errors
    /// Refuses foreign activation, partition, plan or a withdrawn source owner.
    pub fn authenticate(
        &self,
        scope: &ProviderWorldAuthorizationScope,
    ) -> Result<(), EvidenceError> {
        if self.scope.as_ref() != scope || !self.current.load(Ordering::Acquire) {
            return Err(EvidenceError {
                message: "original mixed-world source withdrawn or foreign".into(),
            });
        }
        Ok(())
    }
}
