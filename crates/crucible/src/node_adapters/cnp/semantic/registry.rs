//! Explicit host installation of generic native role oracles and acceptance policy.

use std::{collections::BTreeSet, rc::Rc};

use crucible_node_contract::{HashRef, canonical};

use crate::node_contract::OperationFailure;

use super::{CnpSemanticAcceptance, CnpSemanticInstallation, CnpSemanticSource, refused, unknown};

/// Authenticates a complete source-selected generic role before registry enrollment.
///
/// Implementations are independently installed host code. They bind actual
/// measured artifact identities, role/payload/facet schemas and native oracle
/// selection to an allowed complete configuration. Provider body strings and a
/// successful behavioral report cannot replace this separate source policy.
pub trait CnpSemanticRegistrationPolicy {
    /// Authenticates the complete host-selected role and original native scope.
    ///
    /// # Errors
    /// Refuses unknown source/native oracles, changed artifacts/schema/config,
    /// unsupported capabilities or a vendor-selected reduced requirement scope.
    fn authenticate(&self, selection: &CnpSemanticInstallation) -> Result<(), OperationFailure>;
}

/// Retains one explicitly installed role without granting native execution authority.
///
/// The capsule has no public constructor or decoded representation. Realization
/// must still authenticate the actual Child, kernel peer, complete native gate
/// and current independent behavioral acceptance before original Admit.
#[must_use = "retain the installed source and acceptance policies for native preparation"]
pub struct InstalledCnpSemanticRole {
    pub(super) policy: Rc<dyn CnpSemanticRegistrationPolicy>,
    pub(super) identity: HashRef,
    pub(super) source: Rc<dyn CnpSemanticSource>,
    pub(super) acceptance: Option<Rc<dyn CnpSemanticAcceptance>>,
    pub(super) conformance: Option<Rc<dyn super::CnpSemanticConformanceAuthority>>,
    pub(super) collection_plan: Option<crate::node_admission::InstalledConformancePlan>,
}

/// Enrolls finite complete host selections with mandatory independent source policy.
///
/// This registry grants no native/class qualification or readiness. Its opaque
/// result prevents generic preparation from accepting an unregistered bare role
/// description or silently omitting the installed acceptance policy.
pub struct CnpSemanticRegistry {
    policy: Rc<dyn CnpSemanticRegistrationPolicy>,
    installed: BTreeSet<HashRef>,
    maximum_roles: usize,
}

impl CnpSemanticRegistry {
    /// Retains the independent source installation policy and a finite role ceiling.
    ///
    /// # Errors
    /// Refuses zero or greater-than-256 original registration credits.
    pub fn new(
        policy: Rc<dyn CnpSemanticRegistrationPolicy>,
        maximum_roles: usize,
    ) -> Result<Self, OperationFailure> {
        if maximum_roles == 0 || maximum_roles > 256 {
            return Err(refused(
                "generic installed source registration credit is unsupported",
            ));
        }
        Ok(Self {
            policy,
            installed: BTreeSet::new(),
            maximum_roles,
        })
    }

    /// Installs the exact native oracle and mandatory acceptance policy for one original.
    ///
    /// The current source policy authenticates every call, including an identical
    /// selection. Hash equality only indexes finite bookkeeping; it never skips
    /// current installation checks or grants later common/native authority.
    ///
    /// # Errors
    /// Refuses changed or unsupported source scope, missing complete policy,
    /// duplicate original enrollment or exhausted registration/serialization credit.
    pub fn install(
        &mut self,
        source: Rc<dyn CnpSemanticSource>,
        acceptance: Rc<dyn CnpSemanticAcceptance>,
    ) -> Result<InstalledCnpSemanticRole, OperationFailure> {
        let selected = source.installation();
        super::preparation::validate_installation(selected)?;
        self.policy.authenticate(selected)?;
        if self.installed.len() >= self.maximum_roles {
            return Err(refused(
                "generic source registry has no original role credit",
            ));
        }
        let identity = installation_identity(selected)?;
        if !self.installed.insert(identity.clone()) {
            return Err(refused("generic original source role was already enrolled"));
        }
        Ok(InstalledCnpSemanticRole {
            policy: self.policy.clone(),
            identity,
            source,
            acceptance: Some(acceptance),
            conformance: None,
            collection_plan: None,
        })
    }

    /// Installs an independently authorized collection scope without accepted classes.
    ///
    /// The distinct capsule cannot use ordinary preparation or node constructors.
    /// The host authority retains the complete original fixture plan and must
    /// authenticate its normative population, source tuple and finite credits.
    ///
    /// # Errors
    /// Refuses missing fixture authority, changed source scope, duplicate original
    /// enrollment, or exhausted finite registration credit.
    pub fn install_for_conformance(
        &mut self,
        source: Rc<dyn CnpSemanticSource>,
        authority: Rc<dyn super::CnpSemanticConformanceAuthority>,
        plan: &crate::node_admission::InstalledConformancePlan,
    ) -> Result<super::InstalledCnpConformanceRole, OperationFailure> {
        let selected = source.installation();
        super::preparation::validate_installation(selected)?;
        self.policy.authenticate(selected)?;
        super::preparation::authenticate_collection_selection(plan, authority.as_ref(), selected)?;
        if self.installed.len() >= self.maximum_roles {
            return Err(refused(
                "generic source registry has no original role credit",
            ));
        }
        let identity = installation_identity(selected)?;
        if !self.installed.insert(identity.clone()) {
            return Err(refused("generic original source role was already enrolled"));
        }
        Ok(super::InstalledCnpConformanceRole(
            InstalledCnpSemanticRole {
                policy: self.policy.clone(),
                identity,
                source,
                acceptance: None,
                conformance: Some(authority),
                collection_plan: Some(plan.retained()),
            },
        ))
    }
}

/// Commits every selected field, including source limits and exact current policy scope.
pub(super) fn installation_identity(
    selected: &CnpSemanticInstallation,
) -> Result<HashRef, OperationFailure> {
    // Borrowed tuples avoid copying any source body during current reauthentication.
    let projection = (
        (
            &selected.provider,
            &selected.profile,
            &selected.descriptor,
            &selected.binding,
        ),
        (
            &selected.capabilities,
            &selected.exact_facet,
            &selected.guarantees,
            &selected.owner,
        ),
        (
            &selected.realize,
            &selected.admission,
            &selected.transaction,
            &selected.gate,
        ),
        (
            &selected.admission_receipt,
            &selected.world_binding_hash,
            &selected.receipt_schema,
        ),
        (
            selected.maximum_operations,
            selected.maximum_semantic_bytes,
            selected.maximum_result_bytes,
            selected.maximum_authorization_bytes,
        ),
    );
    super::budget::serialized_size(&projection, selected.maximum_semantic_bytes)?;
    canonical::json_hash("crucible.cnp-installed-semantic.v1", &projection).map_err(unknown)
}
