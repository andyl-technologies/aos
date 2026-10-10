//! Reauthenticates retained behavioral acceptance at the common Node admission seam.

use std::collections::BTreeSet;

use crucible::node_admission::{
    AdmissionEvidence, EvidenceError, InstalledExtensionRegistry, NodeCapabilityRequirement,
    QualificationClaim as AdmissionClaim,
};
use crucible_node_contract::{
    BindingCompatibility, ContentRef, Id, ImplementationIdentity, NodeBinding, SchemaRef,
    WorldBinding,
};

use super::{
    AcceptanceDecision, AcceptanceLimits, AcceptanceRecord, InstalledQualificationAuthority,
    QualificationClass, QualificationError, QualificationUnit, accept_claim,
};

/// Supplies independently measured current scope and retained original evidence.
///
/// The policy derives required classes from the actual selected configuration,
/// contracts and guarantees, never from the provider's requested subset.
pub struct AcceptanceScope<'a> {
    /// Borrows the independently enrolled exact selected binding.
    pub binding: &'a BindingCompatibility,
    /// Contains the freshly measured complete qualification unit.
    pub current_unit: QualificationUnit,
    /// Enumerates every class required by this actual host configuration.
    pub required_classes: BTreeSet<QualificationClass>,
    /// Borrows immutable original claim bytes under the qualification ceiling.
    pub original_bytes: &'a [u8],
    /// Borrows their exact installed content identity.
    pub original_claim: &'a ContentRef,
    /// Borrows the historical audit decision; it cannot replace reauthentication.
    pub record: &'a AcceptanceRecord,
}

/// Installs current binding/class selection independently of vendor reports.
pub trait InstalledAcceptancePolicy: InstalledQualificationAuthority {
    /// Reopens actual current scope and original evidence for the selected node.
    ///
    /// # Errors
    /// Rejects unknown nodes, stale measurements or unsupported selected profiles.
    /// Implementations must bound owned returned metadata before allocation and
    /// borrow original bytes from a finite retained owner.
    fn scope_for_node(&self, node: &Id) -> Result<AcceptanceScope<'_>, QualificationError>;
}

/// Adds fresh behavioral acceptance checks without replacing native authority.
pub struct BehavioralAdmissionEvidence<'a> {
    underlying: &'a dyn AdmissionEvidence,
    policy: &'a dyn InstalledAcceptancePolicy,
    limits: AcceptanceLimits,
}

impl<'a> BehavioralAdmissionEvidence<'a> {
    /// Wraps an existing admission source with independently installed acceptance.
    pub fn new(
        underlying: &'a dyn AdmissionEvidence,
        policy: &'a dyn InstalledAcceptancePolicy,
        limits: AcceptanceLimits,
    ) -> Self {
        Self {
            underlying,
            policy,
            limits,
        }
    }

    fn reauthenticate(
        &self,
        binding: &BindingCompatibility,
        binding_hash: &crucible_node_contract::HashRef,
        references: &[ContentRef],
    ) -> Result<(), QualificationError> {
        let scope = self.policy.scope_for_node(&binding.node_id)?;
        let record = scope.record;
        super::record::bounded(binding, self.limits.maximum_record_bytes)?;
        super::record::bounded(record, self.limits.maximum_record_bytes)?;
        if scope.binding != binding
            || binding.identity()? != *binding_hash
            || references != binding.qualification_refs
            || !references.contains(scope.original_claim)
            || record.format != "crucible.node-acceptance"
            || record.version != 1
            || record.original_claim != *scope.original_claim
            || record.evaluated_unit != scope.current_unit
            || record.required_classes != scope.required_classes
            || !record.missing_requirements.is_empty()
            || record.decision != AcceptanceDecision::Accepted
        {
            return Err(QualificationError::Refused(
                "outside current installed acceptance scope",
            ));
        }
        if scope.original_bytes.len() > self.limits.qualification.maximum_claim_bytes
            || !record.matches_original(
                scope.original_bytes,
                self.limits.qualification.maximum_claim_bytes,
            )?
        {
            return Err(QualificationError::Refused(
                "changed retained acceptance original",
            ));
        }
        // Historical Passed data and delegated acceptance cannot bypass current
        // original evidence/oracle authentication. Native admission remains next.
        accept_claim(
            scope.original_bytes,
            scope.original_claim,
            &scope.current_unit,
            &scope.required_classes,
            self.policy,
            self.limits.qualification,
        )?;
        Ok(())
    }
}

impl AdmissionEvidence for BehavioralAdmissionEvidence<'_> {
    fn extension_registry(&self) -> Option<&InstalledExtensionRegistry> {
        self.underlying.extension_registry()
    }

    fn content(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        self.underlying.content(reference, maximum_bytes)
    }

    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        self.underlying.authenticate_implementation(implementation)
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        self.underlying.authenticate_authority(binding)
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        self.underlying.authenticate_schema(schema)
    }

    fn qualify_capability(
        &self,
        world: &WorldBinding,
        binding: &NodeBinding,
        requirement: &NodeCapabilityRequirement,
    ) -> Result<(), EvidenceError> {
        self.underlying
            .qualify_capability(world, binding, requirement)
    }

    fn qualify(&self, claim: AdmissionClaim<'_>) -> Result<(), EvidenceError> {
        if let AdmissionClaim::Node {
            binding,
            binding_hash,
            qualification_refs,
        } = &claim
        {
            self.reauthenticate(binding, binding_hash, qualification_refs)
                .map_err(|error| EvidenceError {
                    message: error.to_string(),
                })?;
        }
        self.underlying.qualify(claim)
    }
}
