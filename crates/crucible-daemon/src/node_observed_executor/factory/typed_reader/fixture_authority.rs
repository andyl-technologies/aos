//! Separates bounded onboarding fixtures from accepted ordinary provider classes.
//!
//! A host independently installs this test authority and freezes complete planned
//! applicability, source identity, inputs and oracles before Child. It authorizes
//! only collection of original evidence. An independent report validator must
//! later authenticate all required obligations before ordinary class acceptance.

use super::InstalledTypedReaderPackage;
use crucible::node_adapters::cnp::OriginalRuntimeLineage;
use crucible::node_contract::{InputProvenanceClosure, OriginalInputLineage};
use crucible::node_scheduling::RuntimeInputBatch;
use crucible_node_contract::{ContentRef, ResourceLimits};
use crucible_node_provider::{
    ProviderError,
    client::OriginalLineageRealization,
    reference_lineage::LineageSourceGuard,
    reference_service::{ReferenceNegotiatedLineageReaderLaunchBootstrap, ReferenceProfile},
};

/// Authenticates one independently declared finite typed-source conformance plan.
///
/// Package files, matching metadata and historical fixture helpers cannot install
/// this host trust. The same installed object also authenticates the complete
/// production witness population and current Refused collection scope. This
/// interface cannot return an accepted class, graph, Ready,
/// operation token or replacement native owner. All callbacks default to refusal.
pub trait InstalledTypedReaderFixtureAuthority:
    crate::node_qualification::InstalledConformanceAuthority
{
    /// Authenticates the complete frozen applicability/input/oracle plan identity.
    ///
    /// # Errors
    /// Refuses missing independent fixture trust, unknown cases or changed source,
    /// resource, input, environment or oracle scope before files or Child work.
    fn authenticate_fixture_plan(
        &self,
        _package: &ContentRef,
        _resources: &ResourceLimits,
    ) -> Result<ContentRef, ProviderError> {
        Err(unavailable())
    }

    /// Reads current original source ownership at the actual collecting send boundary.
    ///
    /// # Errors
    /// Refuses by default. A configured implementation checks the complete current
    /// plan first and finishes with direct retained native-owner/registrar reads.
    fn authenticate_terminal_native(&self, _plan: &ContentRef) -> Result<(), ProviderError> {
        Err(unavailable())
    }

    /// Checks this exact regenerated logical source against the declared plan.
    ///
    /// # Errors
    /// Refuses substituted roles, artifacts, schemas or planned input geometry.
    fn authenticate_source(
        &self,
        _plan: &ContentRef,
        _package: &InstalledTypedReaderPackage,
        _profile: &ReferenceProfile,
        _resources: &ResourceLimits,
    ) -> Result<(), ProviderError> {
        Err(unavailable())
    }

    /// Authenticates private host launch authority against the frozen fixture plan.
    ///
    /// The private token and original authority remain solely in owning launch
    /// memory. Implementations must not persist/hash them into public evidence.
    ///
    /// # Errors
    /// Refuses substituted host receipt, generation, owner, source roles or inputs.
    fn authenticate_launch(
        &self,
        _plan: &ContentRef,
        _package: &InstalledTypedReaderPackage,
        _profile: &ReferenceProfile,
        _launch: &ReferenceNegotiatedLineageReaderLaunchBootstrap,
    ) -> Result<(), ProviderError> {
        Err(unavailable())
    }

    /// Checks the actual borrowed realization against original host fixture trust.
    ///
    /// The owning policy independently authenticates actual Child/kernel/maps,
    /// Initialize/Ready and the surviving registrar around this callback.
    ///
    /// # Errors
    /// Refuses foreign binding/qualification/host authority or changed plan scope.
    fn authenticate_realization(
        &self,
        _plan: &ContentRef,
        _package: &InstalledTypedReaderPackage,
        _profile: &ReferenceProfile,
        _guard: &LineageSourceGuard,
        _original: &OriginalLineageRealization<'_>,
        _resources: &ResourceLimits,
    ) -> Result<(), ProviderError> {
        Err(unavailable())
    }

    /// Checks an actual opaque terminal window against independently declared oracles.
    ///
    /// # Errors
    /// Refuses missing or mismatched original token, grant, output, proof or ACK
    /// witnesses. A terminal Complete is retained custody, not an ACK assertion.
    fn authenticate_window(
        &self,
        _plan: &ContentRef,
        _package: &InstalledTypedReaderPackage,
        _profile: &ReferenceProfile,
        _original: &OriginalRuntimeLineage<'_>,
    ) -> Result<(), ProviderError> {
        Err(unavailable())
    }

    /// Checks actual original producer custody before consumer native Stage.
    ///
    /// # Errors
    /// Refuses unknown planned deliveries or missing original producer witnesses.
    fn authenticate_inputs(
        &self,
        _plan: &ContentRef,
        _package: &InstalledTypedReaderPackage,
        _profile: &ReferenceProfile,
        _original: &RuntimeInputBatch,
        _provenance: &InputProvenanceClosure,
        _lineage: &OriginalInputLineage,
    ) -> Result<(), ProviderError> {
        Err(unavailable())
    }
}

fn unavailable() -> ProviderError {
    ProviderError::Correlation("independent typed conformance fixture authority unavailable")
}
