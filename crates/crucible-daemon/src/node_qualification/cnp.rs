//! Applies complete original behavioral acceptance to actual public CNP preparation.
//!
//! The source projection binds measured profile/configuration data; independent
//! installed policy still supplies environment, harness and fixture measurements.
//! Neither projected content identities nor report decoding grant native authority.

use std::collections::BTreeSet;

use crucible::node_adapters::cnp::{CnpAcceptanceScope, CnpRealizationAcceptance};
use crucible::node_contract::{EffectKnowledge, OperationFailure};
use crucible_node_contract::{
    CaptureScope, ContentRef, NodeBinding, OperatingMode, OwnerBinding, Repeatability,
    ResourceLimits, Validate, canonical,
};
use crucible_node_provider::{bodies::RealizeResult, reference_service::ReferenceProfile};
use serde::Serialize;

use super::{AcceptanceLimits, InstalledAcceptancePolicy, QualificationClass, QualificationError};

const MAXIMUM_PROJECTION_BYTES: usize = 256 * 1024;

/// Describes source-derived acceptance scope without granting any qualification.
pub struct CnpQualificationProjection {
    /// Binds the actual selected implementation record and measured artifacts.
    pub implementation: ContentRef,
    /// Binds actual configuration, selected profile and complete owner geometry.
    pub realization: ContentRef,
    /// Binds the complete original descriptor roster.
    pub descriptors: ContentRef,
    /// Binds timing, capabilities and independent guarantee axes together.
    pub contracts: ContentRef,
    /// Binds the actual semantic port roster and referenced profile.
    pub port_profiles: ContentRef,
    /// Enumerates the independent classes required by the actual selected source.
    pub required_classes: BTreeSet<QualificationClass>,
}

/// Projects bounded source profile data for independently installed acceptance.
///
/// This function only computes data identities. It is useful when installing a
/// finite host policy, but cannot authenticate a process, oracle or report.
/// Fresh native preparation separately compares the complete actual realization.
///
/// # Errors
/// Refuses changed descriptor/owner/implementation scope, invalid guarantees or
/// source records exceeding the separate projection ceiling before copying.
pub fn project_cnp_qualification(
    profile: &ReferenceProfile,
    realization: &RealizeResult,
    resources: &ResourceLimits,
) -> Result<CnpQualificationProjection, QualificationError> {
    let manifest = &realization.realization_manifest;
    if manifest.descriptors.as_slice() != std::slice::from_ref(&profile.descriptor)
        || manifest.owners.as_slice() != std::slice::from_ref(&profile.owner)
    {
        return Err(QualificationError::Refused(
            "changed actual CNP profile roster",
        ));
    }
    resources.validate()?;
    profile.guarantees.validate()?;
    let mut classes = BTreeSet::from([
        QualificationClass::BaseProvider,
        QualificationClass::RoleProfile,
        match profile.operating_contract.mode {
            OperatingMode::Exact => QualificationClass::ExactTiming,
            OperatingMode::Quantized => QualificationClass::QuantizedTiming,
        },
    ]);
    if profile.guarantees.repeatability == Repeatability::Qualified {
        classes.insert(QualificationClass::Repeatable);
    }
    match profile.guarantees.capture_scope {
        CaptureScope::Architectural => {
            classes.insert(QualificationClass::CaptureArchitectural);
        }
        CaptureScope::CompleteModel => {
            classes.insert(QualificationClass::CaptureModeledLive);
        }
        CaptureScope::None => {}
    }
    for (selected, class) in [
        (
            profile.guarantees.durable_restart,
            QualificationClass::CaptureModeledDurable,
        ),
        (
            profile.guarantees.isolated_fork,
            QualificationClass::BranchIsolated,
        ),
        (
            profile.guarantees.conditional_replay,
            QualificationClass::ConditionalReplay,
        ),
    ] {
        if selected {
            classes.insert(class);
        }
    }

    Ok(CnpQualificationProjection {
        implementation: object(&profile.implementation)?,
        realization: object(&(
            &profile.configuration_ref,
            &profile.node_manifest.profile_id,
            &manifest.owners,
            resources,
        ))?,
        descriptors: object(&manifest.descriptors)?,
        contracts: object(&(
            &profile.operating_contract,
            &profile.capabilities,
            &profile.guarantees,
        ))?,
        port_profiles: object(&(&profile.node_manifest, &profile.descriptor.ports))?,
        required_classes: classes,
    })
}

fn object(value: &impl Serialize) -> Result<ContentRef, QualificationError> {
    super::record::bounded(value, MAXIMUM_PROJECTION_BYTES)?;
    let value = serde_json::to_value(value).map_err(crucible_node_contract::ContractError::from)?;
    let bytes = canonical::canonical_json(&value)?;
    Ok(canonical::content_ref(&bytes, "application/json")?)
}

/// Requires independent current acceptance before the actual CNP Admit request.
///
/// This adapter supplements the native qualifier; it does not replace measured
/// process custody, complete graph admission or durable activation. Policies
/// retain original report bytes and freshly authenticate environment/harness
/// scope on each call. Missing policies cannot construct this adapter.
pub struct CnpBehavioralAcceptance<'a> {
    policy: &'a dyn InstalledAcceptancePolicy,
    limits: AcceptanceLimits,
}

impl<'a> CnpBehavioralAcceptance<'a> {
    /// Borrows finite installed policy for actual pre-Admit and construction checks.
    pub fn new(policy: &'a dyn InstalledAcceptancePolicy, limits: AcceptanceLimits) -> Self {
        Self { policy, limits }
    }

    pub(super) fn check(
        &self,
        profile: &ReferenceProfile,
        realization: &RealizeResult,
        binding: &NodeBinding,
        owner: &OwnerBinding,
        resources: &ResourceLimits,
    ) -> Result<(), QualificationError> {
        // The direct Rust entry point receives borrowed data, so bound its
        // serialization before computing the identity or consulting policy.
        super::record::bounded(&binding.compatibility, self.limits.maximum_record_bytes)?;

        let manifest = &realization.realization_manifest;
        if manifest.bindings.as_slice() != std::slice::from_ref(binding)
            || manifest.owner_bindings.as_slice() != std::slice::from_ref(owner)
        {
            return Err(QualificationError::Refused(
                "changed actual CNP binding/owner",
            ));
        }
        let projection = project_cnp_qualification(profile, realization, resources)?;
        let scope = self.policy.scope_for_node(&binding.compatibility.node_id)?;
        let unit = &scope.current_unit;
        if unit.implementation != projection.implementation
            || unit.realization != projection.realization
            || unit.descriptors != projection.descriptors
            || unit.contracts != projection.contracts
            || unit.port_profiles != projection.port_profiles
            || scope.required_classes != projection.required_classes
        {
            return Err(QualificationError::Refused(
                "outside actual CNP source/class projection",
            ));
        }
        super::admission::authenticate_scope(
            scope,
            self.policy,
            self.limits,
            &binding.compatibility,
            &binding.compatibility.identity()?,
            &binding.compatibility.qualification_refs,
        )
    }
}

impl CnpRealizationAcceptance for CnpBehavioralAcceptance<'_> {
    fn authenticate(&self, scope: CnpAcceptanceScope<'_>) -> Result<(), OperationFailure> {
        self.check(
            scope.profile,
            scope.realization,
            scope.binding,
            scope.owner,
            scope.resources,
        )
        .map_err(|error| OperationFailure {
            // Realization has already allocated original native resources.
            effects: EffectKnowledge::Unknown,
            reason: error.to_string(),
        })
    }
}
