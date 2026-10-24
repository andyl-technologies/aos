//! Retains the same normal reference acceptance beside registry currency.
//!
//! The revision is only a withdrawal fence. Complete source projections, full
//! original Accepted classes and their current evidence are reauthenticated on
//! every lease. No passed checksum or collecting report substitutes for them.

use std::rc::Rc;

use crucible_engine::{
    node_admission::{AdmissionEvidence, EvidenceError, QualificationClaim},
    node_contract::{
        InstalledProviderBehavioral, InstalledProviderSource, ProviderAuthorizationLease,
        ProviderAuthorizationScope,
    },
};
use crucible_node_format::{ContentRef, ImplementationIdentity, NodeBinding, SchemaRef};

use crate::node_qualification::{
    AcceptanceLimits, BehavioralAdmissionEvidence, CnpBehavioralAcceptance,
    InstalledAcceptancePolicy,
};

use super::source::ReferenceVendorSource;

pub(super) struct ReferenceVendorBehavioral {
    pub(super) source: Rc<ReferenceVendorSource>,
    pub(super) policy: Rc<dyn InstalledAcceptancePolicy>,
    pub(super) limits: AcceptanceLimits,
    pub(super) independent: Rc<dyn InstalledProviderBehavioral>,
}

impl AdmissionEvidence for ReferenceVendorBehavioral {
    fn content(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        self.source.content(reference, maximum_bytes)
    }

    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        self.source.authenticate_implementation(implementation)?;
        self.independent
            .authenticate_implementation(implementation)?;
        CnpBehavioralAcceptance::new(self.policy.as_ref(), self.limits)
            .authenticate_prelaunch(&self.source.profile, &self.source.resources)
            .map_err(error)
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        self.source.authenticate_authority(binding)
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        self.source.authenticate_schema(schema)
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        self.independent.qualify(claim.clone())?;
        BehavioralAdmissionEvidence::new(self.source.as_ref(), self.policy.as_ref(), self.limits)
            .qualify(claim)
    }

    fn qualify_capability(
        &self,
        world: &crucible_node_format::WorldBinding,
        binding: &NodeBinding,
        requirement: &crucible_engine::node_admission::NodeCapabilityRequirement,
    ) -> Result<(), EvidenceError> {
        self.source.qualify_capability(world, binding, requirement)
    }
}

impl InstalledProviderBehavioral for ReferenceVendorBehavioral {
    fn current_behavioral_revision(
        &self,
        scope: &ProviderAuthorizationScope,
    ) -> Result<ProviderAuthorizationLease, EvidenceError> {
        self.authenticate_implementation(&self.source.profile.implementation)?;
        super::currency::original_behavioral(
            scope,
            || self.source.current_source_revision(scope),
            || self.independent.current_behavioral_revision(scope),
            || self.policy.provider_revision(scope).map_err(error),
        )
    }
}

fn error(error: impl std::fmt::Display) -> EvidenceError {
    EvidenceError {
        message: error.to_string(),
    }
}
