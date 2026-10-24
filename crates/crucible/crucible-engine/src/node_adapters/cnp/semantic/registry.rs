//! Explicit host installation of generic native role oracles and acceptance policy.

use std::{collections::BTreeSet, rc::Rc};

use crucible_node_format::{HashRef, canonical};

use crate::node_contract::OperationFailure;

use super::{CnpSemanticAcceptance, CnpSemanticInstallation, CnpSemanticSource, refused, unknown};

/// Authenticates a complete source-selected generic role before registry enrollment.
///
/// Implementations are independently installed host code. They bind actual
/// measured artifact identities, role/payload/facet schemas and native oracle
/// selection to an allowed complete configuration. Provider body strings and a
/// successful behavioral report cannot replace this separate source policy.
pub trait CnpSemanticRegistrationPolicy {
    /// Observes actual nested backing before allocation credit, using raw failures.
    ///
    /// Implementations walk the same concrete owner without heap allocation,
    /// formatting, serialization, I/O, or currentness callbacks. The caller
    /// separately charges the actual outer allocation and observer scratch.
    /// `None` retains an unknown owner. This default never calls the legacy
    /// allocating-error observer and grants no native or allocation authority.
    ///
    /// # Errors
    /// Returns a typed origin, busy-loan, unsupported-layout or checked-bound
    /// refusal without constructing an owned diagnostic.
    fn retained_requested_storage_precredit_data(
        &self,
        _maximum: usize,
    ) -> Result<Option<usize>, crate::node_contract::RuntimeError> {
        Ok(None)
    }

    /// Observes this same installed owner's nested requested storage as data.
    ///
    /// The caller charges the actual Rc header and inline payload separately.
    /// Supported concrete implementations walk their actual retained capacities
    /// and shared roots under original process/thread guards. None preserves an
    /// unresolved owner; neither a configured maximum nor encoded length is a
    /// backing observation. This grants no native, source or Capture authority.
    ///
    /// # Errors
    /// Refuses a foreign origin, unsupported mutable loan, arithmetic overflow
    /// or actual nested storage above the supplied bound.
    fn retained_requested_storage_data(
        &self,
        _maximum: usize,
    ) -> Result<Option<usize>, OperationFailure> {
        Ok(None)
    }

    /// Authenticates the complete host-selected role and original native scope.
    ///
    /// # Errors
    /// Refuses unknown source/native oracles, changed artifacts/schema/config,
    /// unsupported capabilities or a vendor-selected reduced requirement scope.
    fn authenticate(&self, selection: &CnpSemanticInstallation) -> Result<(), OperationFailure>;
}

// The public installation cannot choose this discriminator. Only the concrete
// complete packet enrollment below issues its conformance-only variant.
#[derive(Clone, Copy)]
pub(super) enum SemanticInstallationKind {
    ExactOnly,
    CollectingCompletePacket,
}

impl SemanticInstallationKind {
    pub(super) fn authenticate(
        self,
        installation: &CnpSemanticInstallation,
    ) -> Result<(), OperationFailure> {
        match self {
            Self::ExactOnly => super::preparation::validate_installation(installation),
            Self::CollectingCompletePacket => {
                super::preparation::validate_complete_installation(installation)
            }
        }
    }
}

/// Retains one explicitly installed role without granting native execution authority.
///
/// The capsule has no public constructor or decoded representation. Realization
/// must still authenticate the actual Child, kernel peer, complete native gate
/// and current independent behavioral acceptance before original Admit.
#[must_use = "retain the installed source and acceptance policies for native preparation"]
pub struct InstalledCnpSemanticRole {
    pub(super) kind: SemanticInstallationKind,
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
            kind: SemanticInstallationKind::ExactOnly,
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
                kind: SemanticInstallationKind::ExactOnly,
                policy: self.policy.clone(),
                identity,
                source,
                acceptance: None,
                conformance: Some(authority),
                collection_plan: Some(plan.retained()),
            },
        ))
    }
    /// Enrolls a concrete edition-five packet source for collection only.
    ///
    /// Ordinary enrollment and preparation retain their exact-only checks. The
    /// private registration kind follows the same original source into custody;
    /// matching profile strings cannot select this path for arbitrary adapters.
    ///
    /// # Errors
    /// Refuses a changed complete source, absent independent fixture authority,
    /// duplicate enrollment or exhausted registration and serialization credit.
    pub fn install_complete_packet_for_conformance(
        &mut self,
        source: Rc<super::PacketCompleteSemanticSource>,
        authority: Rc<dyn super::CnpSemanticConformanceAuthority>,
        plan: &crate::node_admission::InstalledConformancePlan,
    ) -> Result<super::InstalledCnpConformanceRole, OperationFailure> {
        source.authenticate_registration()?;
        let selected = source.installation();
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
                kind: SemanticInstallationKind::CollectingCompletePacket,
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

mod initial_lifecycle_storage;
