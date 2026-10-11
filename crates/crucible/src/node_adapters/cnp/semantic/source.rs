//! Mandatory independently installed native semantics and behavioral acceptance.

use crucible_node_contract::{
    ContentRef, Id, NodeBinding, NodeDescriptor, NodeManifest, OwnerBinding, ProviderManifest,
    ResourceLimits,
};
use crucible_node_provider::{bodies::*, client::CnpController};

use crate::{
    node_contract::{
        ActivationRecord, FacetKind, OperationAdmission, OperationFailure, OperationOutcome,
        ReadyAttestation, WorldActivation,
    },
    node_scheduling::{NativeInputAcknowledgement, NativeSchedulingObservation, RuntimeInputBatch},
};

use super::CnpSemanticProcessCustody;

/// Contains the exact independently selected source unit for one generic native role.
///
/// The host installation supplies this complete selection. Provider discovery
/// cannot reduce its required roles, capabilities, owner roster or acceptance
/// classes. Its artifact references must name actual measured native bytes.
pub struct CnpSemanticInstallation {
    /// Defines the complete independently installed provider implementation.
    pub provider: ProviderManifest,
    /// Defines the exact source-selected profile and facet schemas.
    pub profile: NodeManifest,
    /// Defines all actual source-selected public roles and ports.
    pub descriptor: NodeDescriptor,
    /// Binds original implementation, model, configuration and live native scope.
    pub binding: NodeBinding,
    /// Declares complete actual capability axes under the exact referenced body.
    pub capabilities: crucible_node_contract::CapabilityProfile,
    /// Names the independently installed exact facet implementation and schemas.
    pub exact_facet: crucible_node_contract::FacetSelection,
    /// Declares exact independently selected guarantee axes, not inferred from a role.
    pub guarantees: crucible_node_contract::GuaranteeProfile,
    /// Binds the complete indivisible native execution and capture ownership.
    pub owner: OwnerBinding,
    /// Contains the exact original publicly dispatched realization request.
    pub realize: RealizeRequest,
    /// Names the original host admission and nonexecuting preparation transaction.
    pub admission: Id,
    /// Names the original complete world transaction for this source selection.
    pub transaction: Id,
    /// Names the original actual closed gate, never inferred from a stopped cursor.
    pub gate: Id,
    /// Contains the exact host evidence receipt accepted by the installed provider.
    pub admission_receipt: ContentRef,
    /// Commits to the complete original independently installed host world.
    pub world_binding_hash: crucible_node_contract::HashRef,
    /// Lists only independently qualified source facet implementations.
    pub facets: Vec<FacetKind>,
    /// Names the source-selected versioned native role receipt dialect.
    pub receipt_schema: crucible_node_contract::SchemaRef,
    /// Limits all retained common operation/input/outcome associations before effects.
    pub maximum_operations: usize,
    /// Limits one source-expanded outcome, input ACK or readiness/owner record.
    ///
    /// The common adapter reserves this entire serialized extent before native
    /// effects. The source oracle must check association and allocation bounds
    /// before producing the corresponding owned value.
    pub maximum_result_bytes: usize,
    /// Limits an original input-authorization or publication-consumption body.
    pub maximum_authorization_bytes: usize,
    /// Limits aggregate retained expanded common semantic bytes before copies.
    pub maximum_semantic_bytes: usize,
}

/// Borrows complete actual original native realization and its installed selection.
///
/// This scope grants no qualification, readiness or execution authority. Every
/// reference remains backed by original bytes retained beneath the actual Child.
#[derive(Clone, Copy)]
pub struct CnpSemanticRealizationScope<'a> {
    /// Borrows the independent host installation rather than a remote subset.
    pub installation: &'a CnpSemanticInstallation,
    /// Borrows actual Child, private group and finite original native custody.
    pub native: &'a CnpSemanticProcessCustody,
    /// Borrows the authenticated original transport and complete content journals.
    pub controller: &'a CnpController,
    /// Borrows the original complete actual discovery response.
    pub discovery: &'a DiscoverResult,
    /// Borrows the original complete publicly realized response.
    pub realization: &'a RealizeResult,
}

impl CnpSemanticRealizationScope<'_> {
    /// Borrows exact original resource limits, not a default or revised tuple.
    pub fn resources(&self) -> &ResourceLimits {
        &self.installation.realize.resource_limits
    }
}

/// Requires current complete original vendor acceptance independently of native syntax.
///
/// An implementation is an explicit trusted host policy. It must derive every
/// required class from the actual source selection and reauthenticate the full
/// original normative catalog, report, realized-provider evidence, environment,
/// harness and fixtures. Decoding a report or historical Passed rows cannot
/// satisfy this boundary. There is no absent-policy or default-success route.
pub trait CnpSemanticAcceptance {
    /// Reauthenticates exact current realized-unit acceptance before admission.
    ///
    /// # Errors
    /// Refuses missing or stale policy/evidence, changed scope, vendor-reduced
    /// classes, unresolved applicable requirements or model-only qualification.
    fn authenticate(&self, scope: CnpSemanticRealizationScope<'_>) -> Result<(), OperationFailure>;
}

/// Identifies a complete source-selected original control prefix before dispatch.
///
/// This nonserialized selector carries no operation permission. The installed
/// source must account for all outgoing uploads, incoming native bodies and
/// original journals, beneath actual opaque common authority checked separately.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum CnpSemanticTransition {
    /// Covers the original discovery and realization, including complete native proof.
    Preparation,
    /// Covers the original native admission response.
    Admission,
    /// Covers original nonexecuting readiness and its complete native proof.
    Readiness,
    /// Covers initial global activation when necessary and the original observation.
    Observation,
    /// Covers one read-only original Poll or cancellation query.
    Query,
    /// Covers the complete original consumption upload and native retirement.
    Retirement,
}

/// Authenticates source-specific native facts beneath generic original CNP control.
///
/// This trait belongs to the source-installed host registry. It is deliberately
/// distinct from provider JSON, receipt parsing and behavioral acceptance.
/// Implementations bind actual measured process/model state and complete native
/// journals to the supplied opaque common authority before returning any fact.
/// A generic frontend cannot infer a Clock, Compute or other role from labels.
/// Unsupported facets must remain absent from the exact installation.
pub trait CnpSemanticSource {
    /// Borrows the immutable independently installed whole role selection.
    fn installation(&self) -> &CnpSemanticInstallation;

    /// Authenticates actual source/native custody before realization or semantic reads.
    ///
    /// # Errors
    /// Refuses changed actual process, implementation, native model or private owner scope.
    fn authenticate_provider(
        &self,
        native: &CnpSemanticProcessCustody,
    ) -> Result<(), OperationFailure>;

    /// Checks all source-selected prefix custody before any original dispatch.
    ///
    /// Unknown source prefixes refuse by default. A final response bound alone
    /// does not cover its preceding uploads, proof transfers or native effects.
    /// The same exclusively owned controller must remain held through dispatch.
    ///
    /// # Errors
    /// Refuses unsupported transitions, exhausted original journals or incomplete
    /// whole-prefix native object/transfer byte and association credit.
    fn preflight_transition(
        &self,
        _native: &CnpSemanticProcessCustody,
        _transition: CnpSemanticTransition,
    ) -> Result<(), OperationFailure> {
        Err(super::refused(
            "generic complete source prefix is unsupported",
        ))
    }

    /// Authenticates complete original realization and genuine nonexecuting gate.
    ///
    /// # Errors
    /// Refuses unqualified source, changed model/configuration/contracts, missing
    /// actual gate proof, incomplete owner/domain coverage or stale native custody.
    fn authenticate_realization(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<(), OperationFailure>;

    /// Reserves the source-defined complete native callback and response obligations.
    ///
    /// This preflight checks remaining original request/content associations,
    /// native input/output/timer occupancy and source-selected complete expanded
    /// receipt bounds before the generic frontend dispatches the original Begin.
    /// It grants no replacement operation or permission beyond the supplied token.
    ///
    /// # Errors
    /// Refuses incomplete callback/source coverage, unavailable full response or
    /// native occupancy credit, unsupported operations and changed original scope.
    fn preflight_operation(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
    ) -> Result<(), OperationFailure>;

    /// Reads actual lifecycle and physical state under the original native owner.
    ///
    /// # Errors
    /// Refuses unavailable or incomplete native state; no host cursor substitutes suspension.
    fn status(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<crate::node_contract::NodeStatus, OperationFailure>;

    /// Maps the original actual preparation token to a public owner record.
    ///
    /// # Errors
    /// Refuses unsupported mapping or changed native gate, readiness and binding evidence.
    fn prepared_owner(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<crucible_node_contract::PreparedOwner, OperationFailure>;

    /// Verifies genuine unused native initial state beneath the still-closed gate.
    ///
    /// # Errors
    /// Refuses restored, used or incompletely authenticated native preparations.
    fn validate_initial_preparation(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure>;

    /// Reads and authenticates original source-owned native proof bodies.
    ///
    /// Each requested object must belong to the supplied activation and, when
    /// present, the exact original operation. Complete dependencies remain owned
    /// beneath native custody after ACK; arbitrary controller blobs do not qualify.
    ///
    /// # Errors
    /// Refuses missing, foreign or changed original closure, exhausted expanded
    /// byte/association credit or unavailable actual source validation.
    fn evidence(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
        original: Option<&OperationAdmission>,
        references: &[ContentRef],
        maximum_bytes: usize,
    ) -> Result<Vec<crate::node_scheduling::InputPayload>, OperationFailure>;

    /// Returns an authentic source receipt after actual kernel cleanup and native release.
    ///
    /// # Errors
    /// Refuses outstanding source handles, incomplete native release or missing original proof.
    fn reclamation(
        &self,
        native: &CnpSemanticProcessCustody,
        owner: &crate::node_contract::OwnerIdentity,
    ) -> Result<crate::node_contract::NativeReclamationReceipt, OperationFailure>;

    /// Authenticates complete original nonprocess resource reclamation.
    ///
    /// Kernel child/group disappearance is checked separately. This hook must
    /// prove all source-owned native handles, device resources and obligations
    /// discharged; descriptor syntax and child exit alone cannot do so.
    ///
    /// # Errors
    /// Refuses unavailable or incomplete source-specific release evidence.
    fn validate_reclamation(
        &self,
        native: &CnpSemanticProcessCustody,
        receipt: &crate::node_contract::NativeReclamationReceipt,
    ) -> Result<(), OperationFailure>;

    /// Maps original activation response only after actual nonexecuting native validation.
    ///
    /// The implementation checks original control/body closure and retains an
    /// authentic public owner mapping. It must not construct readiness from
    /// receipt syntax, empty host ledgers or the requested boundary.
    ///
    /// # Errors
    /// Refuses unsupported readiness, changed source scope or incomplete actual native state.
    fn readiness(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        record: &ActivationRecord,
        response: &ActivateResult,
    ) -> Result<ReadyAttestation, OperationFailure>;

    /// Authenticates readiness again against actual unchanged native custody.
    ///
    /// # Errors
    /// Refuses changed or incomplete original gate/readiness/owner evidence.
    fn validate_readiness(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        record: &ActivationRecord,
        readiness: &ReadyAttestation,
    ) -> Result<(), OperationFailure>;

    /// Authenticates complete original common publication before opening the native gate.
    ///
    /// # Errors
    /// Refuses foreign, incomplete or unavailable actual owner/coordinator
    /// custody before any original native WorldActivate dispatch.
    fn preflight_world_activation(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
    ) -> Result<(), OperationFailure>;

    /// Authenticates the original complete all-owner publication before semantic access.
    ///
    /// # Errors
    /// Refuses missing coordinator custody, changed original owner preparation,
    /// foreign activation or incomplete actual provider activation evidence.
    fn validate_world_activation(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
        response: &WorldActivateResult,
    ) -> Result<(), OperationFailure>;

    /// Maps an authentic complete original input cut into the selected role's CNP events.
    ///
    /// Port semantics and every source/destination/payload/causal association must
    /// match the installed source schema. The selected semantic credit applies
    /// before copies. This mapping grants no permission to consume the input.
    ///
    /// # Errors
    /// Refuses unsupported ingress, altered associations, overwide role payloads
    /// or insufficient original event/body credit before allocating the mapping.
    fn input_batch(
        &self,
        batch: &RuntimeInputBatch,
        sequence: crucible_node_contract::U64,
    ) -> Result<crucible_node_contract::InputBatch, OperationFailure>;

    /// Authenticates genuine unchanged native staging without semantic consumption.
    ///
    /// # Errors
    /// Refuses missing or changed original native input receipt and full batch custody.
    fn input_acknowledgement(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        batch: &RuntimeInputBatch,
        response: &InputResult,
    ) -> Result<NativeInputAcknowledgement, OperationFailure>;

    /// Selects the proven CNP stop policy for this exact common grant.
    ///
    /// CNP OrdinaryStop and common HorizonPark have different enum names.
    /// The source must prove this translation preserves the exclusive full cut
    /// without a reaction at its ceiling; unsupported policies refuse.
    ///
    /// # Errors
    /// Refuses unqualified stop semantics or changed original native permission.
    fn boundary_policy(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
    ) -> Result<crucible_node_provider::bodies::BoundaryPolicy, OperationFailure>;

    /// Returns source-qualified original input-prefix evidence for this exact grant.
    ///
    /// The returned bytes bind the original common staging/arbitration proof.
    /// No input lane may infer EOF from an empty batch or the requested limit.
    ///
    /// # Errors
    /// Refuses unknown inbound closure, changed original grant/input association
    /// or unsupported boundary policy before native execution effects.
    fn input_authorization(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        watermark: crucible_node_contract::U64,
    ) -> Result<crate::node_scheduling::InputPayload, OperationFailure>;

    /// Authenticates and translates the original terminal native operation response.
    ///
    /// Every output, frontier, consumed input and stop fact must be checked
    /// against the same actual original native journal and receipt schema. The
    /// installed byte/association credit applies before constructing the result.
    ///
    /// # Errors
    /// Refuses an unqualified operation, changed original, incomplete raw proof
    /// closure, invalid role semantics or exceeded expanded result credit.
    fn outcome(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        response: &ResponseBody,
    ) -> Result<OperationOutcome, OperationFailure>;

    /// Reauthenticates every returned outcome against actual retained source custody.
    ///
    /// # Errors
    /// Refuses stale native evidence or any changed original operation/output/body association.
    fn validate_outcome(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure>;

    /// Authenticates a current complete source-selected output bound and native inventory.
    ///
    /// # Errors
    /// Refuses unknown bound evidence, incomplete output/timer/queue coverage,
    /// changed active scope or an unsupported native observation contract.
    fn scheduling(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
        response: &ObserveResult,
    ) -> Result<NativeSchedulingObservation, OperationFailure>;

    /// Reauthenticates the same actual full native scheduling observation.
    ///
    /// # Errors
    /// Refuses stale or altered source evidence, incomplete inventory or changed original activation.
    fn validate_scheduling(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
        observation: &NativeSchedulingObservation,
    ) -> Result<(), OperationFailure>;

    /// Verifies genuine original native retirement without replacing output history.
    ///
    /// # Errors
    /// Refuses missing or changed native ACK/release evidence, foreign original
    /// consumption data, or incomplete retained output/receipt history.
    fn validate_retirement(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        consumption: &crate::node_scheduling::InputPayload,
        response: &RetireResult,
    ) -> Result<(), OperationFailure>;

    /// Defines the selected original host consumption record after runtime publication.
    ///
    /// This source-specific record binds the original operation/result/output
    /// population and unchanged source namespace. Native retirement cannot be
    /// authorized by an arbitrary provider field or a newly generated run.
    ///
    /// # Errors
    /// Refuses foreign or incomplete original publication custody and exceeded record credit.
    fn consumption(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        outputs: &[Id],
    ) -> Result<crate::node_scheduling::InputPayload, OperationFailure>;
}
