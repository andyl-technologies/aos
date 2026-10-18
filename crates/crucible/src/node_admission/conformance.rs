//! Seals a source-authenticated collection world without ordinary Node acceptance.
//!
//! The opaque graph preserves every ordinary structural, content, schema and
//! ownership check. Node behavioral claims and dormant Capture profiles use
//! explicit collection authorization. Its private ordinary graph cannot escape through a getter or
//! serialized record, so missing class evidence cannot become ordinary admission.

use std::rc::{Rc, Weak};

use crucible_node_contract::{
    ContentRef, HashRef, NodeBinding, NodeDescriptor, OwnerBinding, WorldBinding,
};

use super::*;

mod archive_code;
mod extensions;
mod fresh_restore_host;
mod host_startup;
mod native_startup;
mod report_startup;
mod runtime_construction;

#[path = "conformance/weak_plan_history.rs"]
mod weak_plan_history;
pub use host_startup::{
    CompleteOriginalNativeHostStartupAdmission, OriginalNativeHostStartupMemberScope,
    OriginalNativeHostStartupPolicy, OriginalNativeHostStartupScope,
    OriginalNativeHostStartupStorage,
};
pub(crate) use host_startup::{OriginalNativeHostStartupMember, OriginalNativeHostStartupQuote};
pub(crate) use native_startup::{
    NativeStartupRows, OriginalHostFinalizationBarrier, OriginalHostFinalizationSource,
    OriginalNativeStartupMember, OriginalNativeStartupQuote, OriginalRestoredSuffixStartupMember,
};

pub use runtime_construction::{
    CompleteOriginalRuntimeConstructionDiagnostics, CompleteOriginalRuntimeConstructionMember,
    OriginalRuntimeConstructionPhase, OriginalRuntimeConstructionPolicy,
    OriginalRuntimeConstructionScope, OriginalRuntimeConstructionStorage,
};

pub use native_startup::{
    CompleteOriginalNativeInvocationAdmission, CompleteOriginalNativeStartupAdmission,
    CompleteOriginalRestoredSuffixStartupAdmission, OriginalNativeStartupMemberScope,
    OriginalNativeStartupPolicy, OriginalNativeStartupScope, OriginalNativeStartupStorage,
};

pub use fresh_restore_host::{
    CompleteOriginalFreshRestoreHostWindow, OriginalFreshRestoreHostMemberScope,
    OriginalFreshRestoreHostPolicy, OriginalFreshRestoreHostScope, OriginalFreshRestoreHostStorage,
};

pub(crate) use report_startup::{OriginalReportStartupMember, StartupRows};

pub use archive_code::{CompleteArchiveCodeGraph, admit_complete_archive_code_graph};
pub use report_startup::{
    CompleteOriginalReportStartupAdmission, OriginalReportStartupMemberScope,
    OriginalReportStartupPolicy, OriginalReportStartupScope, OriginalReportStartupStorage,
};

const MAXIMUM_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;
const MAXIMUM_SOURCE_OBJECTS: usize = 32;

/// Borrows the complete independently installed collection plan and refused audit.
///
/// Neither document is acceptance authority. The installed callback must verify
/// the original normative population, exact unit/classes, current refused decision,
/// source/harness/fixtures and all original failed or unexecuted rows.
pub struct ConformancePlanEvidence<'a> {
    /// Identifies the complete original witness plan.
    pub plan_ref: &'a ContentRef,
    /// Retains its full canonical bytes.
    pub plan_bytes: &'a [u8],
    /// Identifies the original refused acceptance audit.
    pub refused_ref: &'a ContentRef,
    /// Retains every original audit row and its refused decision.
    pub refused_bytes: &'a [u8],
    /// Identifies the complete original world selected for collection.
    pub world: &'a HashRef,
    /// Identifies all independently installed source/harness/fixture prerequisites.
    pub sources: &'a [ContentRef],
}

/// Authenticates source-installed collection separately from ordinary acceptance.
///
/// Node behavioral claims and dormant Capture profiles use separate collection
/// callbacks. Every other admission claim retains its original meaning through
/// [`AdmissionEvidence`]. Collection authorization must never issue an accepted
/// class or use vendor-selected omissions as a normative witness population.
pub trait ConformanceAdmissionAuthority: AdmissionEvidence {
    /// Optionally authenticates a complete code-only binding schema roster.
    ///
    /// The actual retained plan must belong to this same issuer. This hook
    /// authenticates immutable schema membership only; ordinary live admission
    /// and all other evidence callbacks retain their individual checks.
    ///
    /// # Errors
    /// A selected implementation refuses another actual plan authority, binding
    /// or complete roster, changed original files or unavailable code custody.
    fn authenticate_complete_archive_code_schema_roster(
        &self,
        _plan: &InstalledConformancePlan,
        _binding: &NodeBinding,
        _schemas: &[crucible_node_contract::SchemaRef],
    ) -> Option<Result<(), EvidenceError>> {
        None
    }

    /// Selects the exact registered inactive restoration construction phase.
    ///
    /// This origin-only callback must consume the actual holder's phase before
    /// returning its installed policy; no DATA total or decoded class supplies it.
    ///
    /// # Errors
    /// Defaults to refusal for unsupported or already-spent installed ownership.
    fn original_restoration_construction_policy(
        &self,
        _evidence: &ConformancePlanEvidence<'_>,
        _scope: &OriginalRestorationConstructionScope<'_>,
    ) -> Result<OriginalRestorationConstructionPolicy, crate::node_contract::RuntimeError> {
        Err(crate::node_contract::RuntimeError::UnsupportedFacet)
    }

    /// Observes the genuine restored-phase external holder and callback owners.
    ///
    /// # Errors
    /// Defaults to refusal; initial/prebirth observers cannot stand in for this row.
    fn authenticate_original_restoration_construction(
        &self,
        _evidence: &ConformancePlanEvidence<'_>,
        _scope: &OriginalRestorationConstructionScope<'_>,
        _policy: &OriginalRestorationConstructionPolicy,
    ) -> Result<OriginalRestorationConstructionStorage, crate::node_contract::RuntimeError> {
        Err(crate::node_contract::RuntimeError::UnsupportedFacet)
    }

    /// Rechecks actual registered spent member identities without mutable banks.
    ///
    /// # Errors
    /// Defaults to refusal; no Source association, runtime, preparation or SDK loan
    /// may be opened here. The Core terminal live fence runs after this callback.
    fn authenticate_original_restoration_construction_member(
        &self,
        _evidence: &ConformancePlanEvidence<'_>,
        _scope: &OriginalRestorationMemberScope<'_>,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        Err(crate::node_contract::RuntimeError::UnsupportedFacet)
    }

    /// Selects the same installed inactive-runtime construction resource action.
    ///
    /// # Errors
    /// Defaults to refusal; no numeric row, graph or report supplies this action.
    fn original_runtime_construction_policy(
        &self,
        _evidence: &ConformancePlanEvidence<'_>,
        _scope: &OriginalRuntimeConstructionScope<'_>,
    ) -> Result<OriginalRuntimeConstructionPolicy, crate::node_contract::RuntimeError> {
        Err(crate::node_contract::RuntimeError::UnsupportedFacet)
    }

    /// Observes all same-holder owners and actual closed prospective constructor phases.
    ///
    /// # Errors
    /// Defaults to refusal for unknown owners, unsupported phases or stale originals.
    fn authenticate_original_runtime_construction(
        &self,
        _evidence: &ConformancePlanEvidence<'_>,
        _scope: &OriginalRuntimeConstructionScope<'_>,
        _policy: &OriginalRuntimeConstructionPolicy,
    ) -> Result<OriginalRuntimeConstructionStorage, crate::node_contract::RuntimeError> {
        Err(crate::node_contract::RuntimeError::UnsupportedFacet)
    }

    /// Reauthenticates the same spent original member without borrowing constructor banks.
    ///
    /// # Errors
    /// Defaults to refusal; callbacks must retain bank-free identity checks.
    fn authenticate_original_runtime_construction_member(
        &self,
        _evidence: &ConformancePlanEvidence<'_>,
        _scope: &OriginalRuntimeConstructionScope<'_>,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        Err(crate::node_contract::RuntimeError::UnsupportedFacet)
    }

    /// Supplies the same installed policy before initial host lifecycle observers.
    ///
    /// This callback checks raw original identity only, with no allocation,
    /// serialization, currentness, kernel or owning-data observation.
    ///
    /// # Errors
    /// Refuses unsupported or foreign originals with a raw failure enum.
    fn original_host_initial_lifecycle_policy(
        &self,
        _evidence: &ConformancePlanEvidence<'_>,
        _scope: &OriginalHostInitialLifecycleScope<'_>,
    ) -> Result<OriginalHostInitialLifecyclePolicy, crate::node_contract::RuntimeError> {
        Err(crate::node_contract::RuntimeError::UnsupportedFacet)
    }

    /// Observes the same concrete holder under its precredited observer window.
    ///
    /// This follows only typed raw owning-data leaves. Source3 storage is counted
    /// independently by Core. Unknown backing or kernel-resource views refuse.
    ///
    /// # Errors
    /// Refuses unsupported/changed originals, busy owners or incomplete census.
    fn authenticate_original_host_initial_lifecycle(
        &self,
        _evidence: &ConformancePlanEvidence<'_>,
        _scope: &OriginalHostInitialLifecycleScope<'_>,
        _policy: &OriginalHostInitialLifecyclePolicy,
    ) -> Result<OriginalHostInitialLifecycleStorage, crate::node_contract::RuntimeError> {
        Err(crate::node_contract::RuntimeError::UnsupportedFacet)
    }

    /// Rechecks the actual registered member without borrowing mutable SDK banks.
    ///
    /// This callback checks retained identity/revision only. It performs no I/O,
    /// allocation, serializer, kernel read, owner walk or registrar callback.
    /// Core privately checks original SDK/read-owner identity around this call.
    ///
    /// # Errors
    /// Refuses unsupported, revoked or changed original membership.
    fn authenticate_original_host_initial_lifecycle_member(
        &self,
        _evidence: &ConformancePlanEvidence<'_>,
        _scope: &OriginalHostInitialLifecycleMemberScope<'_>,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        Err(crate::node_contract::RuntimeError::UnsupportedFacet)
    }

    /// Reads the same installed original HOST SDK construction resource action.
    ///
    /// # Errors
    /// Defaults to refusal before any constructor or owning observer runs.
    fn original_native_host_startup_policy(
        &self,
        _: &ConformancePlanEvidence<'_>,
        _: &OriginalNativeHostStartupScope<'_>,
    ) -> Result<OriginalNativeHostStartupPolicy, crate::node_contract::RuntimeError> {
        Err(crate::node_contract::RuntimeError::UnsupportedFacet)
    }

    /// Observes the actual registered constructor holder after fixed precredit.
    ///
    /// # Errors
    /// Refuses unknown, foreign, busy, revoked or unpriced original owners.
    fn authenticate_original_native_host_startup(
        &self,
        _: &ConformancePlanEvidence<'_>,
        _: &OriginalNativeHostStartupScope<'_>,
        _: &OriginalNativeHostStartupPolicy,
    ) -> Result<OriginalNativeHostStartupStorage, crate::node_contract::RuntimeError> {
        Err(crate::node_contract::RuntimeError::UnsupportedFacet)
    }

    /// Authenticates a private constructor member without borrowing SDK slots.
    ///
    /// # Errors
    /// Refuses a foreign, expired, revoked or unsupported original member.
    fn authenticate_original_native_host_startup_member(
        &self,
        _: &ConformancePlanEvidence<'_>,
        _: &OriginalNativeHostStartupMemberScope<'_>,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        Err(crate::node_contract::RuntimeError::UnsupportedFacet)
    }

    /// Selects the installed resource action for the same pre-Child native roster.
    ///
    /// # Errors
    /// Defaults to refusal; limits or report grants cannot substitute this action.
    fn original_native_startup_policy(
        &self,
        _: &ConformancePlanEvidence,
        _: &OriginalNativeStartupScope<'_>,
    ) -> Result<OriginalNativeStartupPolicy, crate::node_contract::RuntimeError> {
        Err(crate::node_contract::RuntimeError::UnsupportedFacet)
    }

    /// Authenticates and observes the actual registered baseline holder.
    ///
    /// # Errors
    /// Refuses unsupported, foreign, busy, revoked or unpriced owners.
    fn authenticate_original_native_startup(
        &self,
        _: &ConformancePlanEvidence,
        _: &OriginalNativeStartupScope<'_>,
        _: &OriginalNativeStartupPolicy,
    ) -> Result<OriginalNativeStartupStorage, crate::node_contract::RuntimeError> {
        Err(crate::node_contract::RuntimeError::UnsupportedFacet)
    }

    /// Derives complete invocation DATA from the actual registered startup holder.
    ///
    /// The callback copies bounded inline fields only, after Core has admitted
    /// its fixed scratch. Public DATA values cannot substitute a native member.
    ///
    /// # Errors
    /// Defaults to refusal for unknown holders, missing original archive tickets,
    /// changed Source/target identity or unavailable actual prebirth custody.
    fn original_native_invocation_data(
        &self,
        _: &ConformancePlanEvidence<'_>,
        _: &OriginalNativeStartupScope<'_>,
    ) -> Result<[crucible_node_provider::reference_packet::service::native_startup::PacketNativeInvocationPurposeData; 3], crate::node_contract::RuntimeError>{
        Err(crate::node_contract::RuntimeError::UnsupportedFacet)
    }

    /// Quotes suffix DATA from the same registered prebirth tickets and scenario.
    ///
    /// Core preadmits fixed counter views before this callback. Each row must
    /// derive from the actual ticket's cached complete owner geometry and the
    /// same retained canonical launch, with the installed scenario action bound.
    /// Equal numeric rows or a decoded reservation supply no construction right.
    ///
    /// # Errors
    /// Defaults to refusal for unsupported holders, missing declarations,
    /// foreign tickets, unavailable backing or an unsupported scenario bound.
    fn original_restored_suffix_startup_data(
        &self,
        _: &ConformancePlanEvidence<'_>,
        _: &OriginalNativeStartupScope<'_>,
    ) -> Result<[
        crucible_node_provider::reference_packet::service::native_startup::PacketNativeRestoredSuffixStartupStorageData;
        3
    ], crate::node_contract::RuntimeError>{
        Err(crate::node_contract::RuntimeError::UnsupportedFacet)
    }

    /// Quotes new Capture17 storage from actual registered prebirth tickets.
    ///
    /// Each non-Clone result is independent of old startup/suffix rows. The
    /// callback lends exact authenticated import geometry and installed count;
    /// its returned DATA alone cannot install a Source or native reservation.
    ///
    /// # Errors
    /// Defaults to refusal for unsupported holders, foreign tickets, absent
    /// selected17 declarations or any complete unchanged resource overrun.
    fn original_restored_settled_startup_data(
        &self,
        _: &ConformancePlanEvidence<'_>,
        _: &OriginalNativeStartupScope<'_>,
        _: &[crucible_node_provider::reference_packet::service::native_startup::PacketRestoredSettledNativeExistingRowsData; 3],
    ) -> Result<
        [crucible_node_provider::reference_packet::service::native_startup::PacketRestoredSettledNativeStorageData; 3],
        crate::node_contract::RuntimeError,
    >{
        Err(crate::node_contract::RuntimeError::UnsupportedFacet)
    }

    /// Checks a privately issued member without invoking live native callbacks.
    ///
    /// # Errors
    /// Refuses a foreign, revoked or unsupported same-holder member.
    fn authenticate_original_native_startup_member(
        &self,
        _: &ConformancePlanEvidence,
        _: &OriginalNativeStartupMemberScope<'_>,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        Err(crate::node_contract::RuntimeError::UnsupportedFacet)
    }

    /// Reads the actual installed host-query resource action without allocation.
    ///
    /// # Errors
    /// Refuses unsupported actions and foreign registered holders by default.
    fn original_fresh_restore_host_policy(
        &self,
        _evidence: ConformancePlanEvidence<'_>,
        _scope: &OriginalFreshRestoreHostScope<'_>,
    ) -> Result<OriginalFreshRestoreHostPolicy, crate::node_contract::RuntimeError> {
        Err(crate::node_contract::RuntimeError::UnsupportedFacet)
    }

    /// Observes the same registered host holder after its scratch is precredited.
    ///
    /// # Errors
    /// Refuses unsupported backing or a changed original holder by default.
    fn authenticate_original_fresh_restore_host(
        &self,
        _evidence: ConformancePlanEvidence<'_>,
        _scope: &OriginalFreshRestoreHostScope<'_>,
        _policy: &OriginalFreshRestoreHostPolicy,
    ) -> Result<OriginalFreshRestoreHostStorage, crate::node_contract::RuntimeError> {
        Err(crate::node_contract::RuntimeError::UnsupportedFacet)
    }

    /// Checks raw installed-holder currency while mutable query custody is held.
    ///
    /// This callback must not borrow the preparation bank or observe its owners.
    /// It checks only the registered original Source/plan and actual revision.
    ///
    /// # Errors
    /// Refuses unsupported actions or a revoked/foreign holder by default.
    fn authenticate_original_fresh_restore_host_member(
        &self,
        _evidence: ConformancePlanEvidence<'_>,
        _scope: &OriginalFreshRestoreHostMemberScope<'_>,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        Err(crate::node_contract::RuntimeError::UnsupportedFacet)
    }

    /// Reads the installed resource policy before startup observers or reports allocate.
    ///
    /// This callback authenticates the actual immutable Source/launch roster and
    /// registered pre-Child holder using only origin checks and borrowed data.
    /// Its declared scratch is admitted before the owning observation callback.
    ///
    /// # Errors
    /// Defaults to refusal for an absent installed startup action or foreign holder.
    fn original_report_startup_policy(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        _scope: &OriginalReportStartupScope<'_>,
    ) -> Result<OriginalReportStartupPolicy, EvidenceError> {
        Err(failure(
            "installed original report startup policy is unavailable",
        ))
    }

    /// Observes the actual registered startup holder under its admitted scratch.
    ///
    /// The holder excludes the three Source roots counted independently by Core.
    /// No native query, controller callback, graph admission or report allocation
    /// may occur here. Returning these data does not construct a startup grant.
    ///
    /// # Errors
    /// Defaults to refusal for unknown ownership, changed policy or association.
    fn authenticate_original_report_startup(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        _scope: &OriginalReportStartupScope<'_>,
        _policy: &OriginalReportStartupPolicy,
    ) -> Result<OriginalReportStartupStorage, EvidenceError> {
        Err(failure(
            "installed original report startup holder is unavailable",
        ))
    }

    /// Rechecks a private startup member against its actual registered holder.
    ///
    /// The callback authenticates the same plan, Source and holder revision with
    /// borrowed origin data only. It must not enter ordinary plan/currentness
    /// callbacks, hash or serialize data, allocate, query the kernel or perform
    /// native work. Private-boot and launch authentication remain independent.
    ///
    /// # Errors
    /// Defaults to refusal for an absent, expired, borrowed or changed holder.
    fn authenticate_original_report_startup_member(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        _scope: &OriginalReportStartupMemberScope<'_>,
    ) -> Result<(), EvidenceError> {
        Err(failure(
            "installed original report startup member is unavailable",
        ))
    }

    /// Observes actual installed authority backing without authorizing a claim.
    ///
    /// The caller charges this concrete Rc data/header root separately. A
    /// supported row includes all independently owned child heaps and retained
    /// shared owners; unresolved backing returns `None`, never scalar zero.
    ///
    /// # Errors
    /// Refuses foreign original custody, busy loans, arithmetic overflow or a
    /// requested extent above `maximum`. It performs no admission or native work.
    fn retained_requested_storage_data(
        &self,
        _maximum: usize,
    ) -> Result<Option<usize>, EvidenceError> {
        Ok(None)
    }

    /// Observes the same concrete authority with allocation-free refusal values.
    ///
    /// This separate precredit path never invokes the legacy string-error
    /// observer. Unknown backing remains `None`; metadata grants no authority.
    ///
    /// # Errors
    /// Refuses foreign origins, busy ownership, unsupported phases or the bound.
    fn retained_requested_storage_precredit_data(
        &self,
        _maximum: usize,
    ) -> Result<Option<usize>, crate::node_contract::RuntimeError> {
        Ok(None)
    }

    /// Reauthenticates the complete original refused plan and installed prerequisites.
    ///
    /// # Errors
    /// Defaults to refusal; rejects stale/accepted audits, changed complete plan,
    /// missing original bodies, wrong unit/classes or insufficient native credits.
    fn authenticate_collection_plan(
        &self,
        _plan: ConformancePlanEvidence<'_>,
    ) -> Result<(), EvidenceError> {
        Err(EvidenceError {
            message: "installed collection plan is unavailable".into(),
        })
    }

    /// Authorizes the complete actual world solely for its original collection plan.
    ///
    /// # Errors
    /// Defaults to refusal; rejects changed scenario, source bindings, omitted
    /// participants, unsupported native fixtures or a foreign original plan.
    fn authenticate_collection_world(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        _request: AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        Err(EvidenceError {
            message: "installed collection world is unavailable".into(),
        })
    }

    /// Authorizes one exact Node behavioral claim for evidence collection only.
    ///
    /// # Errors
    /// Defaults to refusal; rejects unknown or changed source realization and
    /// any claim not covered by the complete original refused witness scope.
    fn authenticate_collection_node(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        _claim: QualificationClaim<'_>,
    ) -> Result<(), EvidenceError> {
        Err(EvidenceError {
            message: "installed collection Node scope is unavailable".into(),
        })
    }

    /// Authenticates a dormant Capture profile for the original collection plan.
    ///
    /// The source authority must authenticate the same preassociated complete
    /// factory, native source custody and host preparation before graph creation.
    /// Decoded bounds, portable claims and active runtime capture geometry cannot
    /// establish that association. Success grants neither ordinary Capture
    /// qualification nor active capture, restoration or execution authority.
    ///
    /// # Errors
    /// Defaults to refusal; rejects non-Capture claims, foreign world/owner/cut
    /// procedures, stale original plans or unavailable preconstruction custody.
    fn authenticate_collection_capture_profile(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        _claim: QualificationClaim<'_>,
    ) -> Result<(), EvidenceError> {
        Err(failure(
            "installed dormant collection Capture profile is unavailable",
        ))
    }

    /// Authenticates one exact installed extension solely for original collection.
    ///
    /// Namespace publication, actual features, schema bounds, immutable handler
    /// and every semantic axis remain checked by the original registry. This
    /// callback replaces only ordinary behavioral application qualification.
    ///
    /// # Errors
    /// Defaults to refusal; rejects foreign or stale scope, missing source/native
    /// custody, unsupported interpretation or incomplete original fixture plan.
    fn authenticate_collection_extension(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        _application: &ExtensionApplication<'_>,
        _declaration: &crucible_node_contract::ExtensionDeclaration,
        _selected: &crucible_node_contract::ExtensionUse,
        _semantics: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError> {
        Err(failure("installed collection extension is unavailable"))
    }

    /// Authenticates an imported extension under its original collection root.
    ///
    /// # Errors
    /// Defaults to refusal; rejects unknown dependency semantics, changed root
    /// scope or unavailable independently installed original fixture evidence.
    fn authenticate_collection_extension_dependency(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        _application: &ExtensionApplication<'_>,
        _selected_root: &crucible_node_contract::ExtensionUse,
        _dependent: &crucible_node_contract::ExtensionDeclaration,
        _prerequisite: &crucible_node_contract::ExtensionDeclaration,
        _semantics: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError> {
        Err(failure(
            "installed collection extension dependency is unavailable",
        ))
    }

    /// Reads the final installed revision of the complete original collecting scope.
    ///
    /// This trusted host authority reads the exact plan, world, selected nodes,
    /// owners and current source/native-owner revision after preceding callbacks.
    /// It must not delegate to vendor or node callbacks: no such callback may
    /// follow this final read before collection dispatch. Portable reports and
    /// advertised policy flags cannot establish this current revision.
    ///
    /// # Errors
    /// Defaults to refusal; rejects absent final revision authority, independently
    /// revoked world/node/native custody or any changed original scope.
    fn authenticate_collection_current_scope(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        _request: AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        Err(failure(
            "current installed collection revision is unavailable",
        ))
    }

    /// Authorizes internal quantized input collection for the complete original world.
    ///
    /// # Errors
    /// Defaults to refusal; rejects unsupported input roles, source fixtures,
    /// operating contracts or a plan lacking complete native staging custody.
    fn authenticate_collection_quantized(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        _request: AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        Err(failure(
            "installed quantized collection lifecycle is unavailable",
        ))
    }

    /// Authenticates exact input collection under the same original common scheduler owner.
    ///
    /// The installed source authority must bind the actual host source, complete
    /// world and original native peers. Portable declarations are insufficient.
    /// Preparation authentication must allow the initial unattached host slot;
    /// operation and input callbacks additionally require its actual live attachment.
    ///
    /// # Errors
    /// Defaults to refusal; rejects foreign original host/source custody,
    /// unsupported exact input roles or unavailable original native staging.
    fn authenticate_collection_exact_inputs(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        _request: AdmissionRequest<'_>,
        _source: &crate::node_contract::HostSchedulingSource,
    ) -> Result<(), EvidenceError> {
        Err(failure(
            "installed exact input collection lifecycle is unavailable",
        ))
    }

    /// Authorizes complete capture solely under the same original collecting plan.
    ///
    /// The installed source must conjunct its actual native peers and genuine
    /// host factory with the unchanged common state. Portable scope reports,
    /// source labels and parsed Refused audits do not provide this authority.
    ///
    /// # Errors
    /// Defaults to refusal; rejects foreign plan/source/current native custody,
    /// unsupported physical capture or a changed complete cut and capture ID.
    fn authenticate_collection_capture(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        _request: AdmissionRequest<'_>,
        _source: &crate::node_contract::HostSchedulingSource,
        _runtime: &crate::node_contract::OriginalLineageRuntimeRecord,
        _scheduling: &crate::node_scheduling::SchedulingSnapshot,
        _capture_id: &crucible_node_contract::Id,
    ) -> Result<(), EvidenceError> {
        Err(failure(
            "installed complete collecting capture is unavailable",
        ))
    }

    /// Authenticates the scheduler's complete original batch before native Stage.
    ///
    /// # Errors
    /// Defaults to refusal; rejects changed producer closure, payloads, routes,
    /// input identities, cuts, plan scope or unavailable native custody credit.
    fn authenticate_collection_inputs(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        _batch: &crate::node_scheduling::RuntimeInputBatch,
    ) -> Result<(), EvidenceError> {
        Err(failure(
            "installed original collection input custody is unavailable",
        ))
    }

    /// Authorizes an exact original collection request before its native Begin.
    ///
    /// # Errors
    /// Defaults to refusal; rejects changed node/operation/window, unsupported
    /// effects, or exhausted original fixture/native result credit.
    fn authenticate_collection_operation(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        _node: &crucible_node_contract::Id,
        _operation: &crucible_node_contract::Id,
        _request: &crate::node_contract::OperationRequest,
    ) -> Result<(), EvidenceError> {
        Err(failure(
            "installed original collection request is unavailable",
        ))
    }
}

struct Plan {
    plan_ref: ContentRef,
    plan_bytes: Vec<u8>,
    refused_ref: ContentRef,
    refused_bytes: Vec<u8>,
    world: HashRef,
    sources: Vec<ContentRef>,
    authority: Rc<dyn ConformanceAdmissionAuthority>,
}

/// Retains a host-authenticated refused collection scope without acceptance authority.
///
/// Construction precredits both complete documents before parsing or copying.
/// Fresh installation authentication is repeated before every collection effect.
/// There is no decoded constructor, public Clone, or accepted-token conversion.
pub struct InstalledConformancePlan(Rc<Plan>);

/// Observes an actual installed plan without retaining its authority graph.
///
/// Native tickets retain their archive source; the source must not strongly own
/// the fresh authority that in turn owns those same tickets. Factories/runtimes
/// keep the strong plan, and an expired observation never renews one.
pub(crate) struct WeakInstalledConformancePlan(Weak<Plan>);

impl WeakInstalledConformancePlan {
    pub(crate) fn upgrade(&self) -> Result<InstalledConformancePlan, EvidenceError> {
        self.0
            .upgrade()
            .map(InstalledConformancePlan)
            .ok_or_else(|| failure("original collecting plan owner is unavailable"))
    }

    pub(crate) fn retained_allocation_bytes(&self) -> usize {
        // A Weak keeps the allocation even after Plan's child owners drop.
        // Strong owners separately account their reachable child allocations.
        crate::node_contract::NodeRuntime::capture_shared_allocation_storage::<Plan>()
    }
}

impl InstalledConformancePlan {
    pub(crate) fn downgrade(&self) -> WeakInstalledConformancePlan {
        WeakInstalledConformancePlan(Rc::downgrade(&self.0))
    }

    pub(crate) fn same_authority(&self, other: &Self) -> bool {
        std::ptr::addr_eq(self.0.authority.as_ref(), other.0.authority.as_ref())
    }

    pub(crate) fn charge_original_retained_storage(
        &self,
        counter: &mut crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        self.charge_original_retained_storage_for_purpose(counter, false)
    }

    pub(crate) fn charge_original_retained_storage_precredit_data(
        &self,
        counter: &mut crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        self.charge_original_retained_storage_for_purpose(counter, true)
    }

    fn charge_original_retained_storage_for_purpose(
        &self,
        counter: &mut crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter,
        precredit: bool,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        use crate::node_contract::RuntimeError;
        if !counter.rc(&self.0)? {
            return Ok(());
        }
        let Plan {
            plan_ref,
            plan_bytes,
            refused_ref,
            refused_bytes,
            world,
            sources,
            authority,
        } = self.0.as_ref();
        counter.owned(plan_ref)?;
        counter.owned(plan_bytes)?;
        counter.owned(refused_ref)?;
        counter.owned(refused_bytes)?;
        counter.owned(world)?;
        counter.owned(sources)?;
        if counter.rc(authority)? {
            let backing = if precredit {
                authority.retained_requested_storage_precredit_data(counter.maximum())?
            } else {
                authority
                    .retained_requested_storage_data(counter.maximum())
                    .map_err(|_| RuntimeError::UnsupportedFacet)?
            }
            .ok_or(RuntimeError::UnsupportedFacet)?;
            counter.add(backing)?;
        }
        Ok(())
    }

    /// Authenticates and retains the complete independently installed original plan.
    ///
    /// # Errors
    /// Refuses documents above 8 MiB each, missing/overwide source rosters,
    /// corrupt content identities, noncanonical JSON or failed installed policy.
    pub fn install(
        evidence: ConformancePlanEvidence<'_>,
        authority: Rc<dyn ConformanceAdmissionAuthority>,
    ) -> Result<Self, EvidenceError> {
        if evidence.plan_bytes.len() > MAXIMUM_DOCUMENT_BYTES
            || evidence.refused_bytes.len() > MAXIMUM_DOCUMENT_BYTES
            || evidence.sources.is_empty()
            || evidence.sources.len() > MAXIMUM_SOURCE_OBJECTS
            || evidence.sources.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(failure(
                "collection document or source credit is unsupported",
            ));
        }
        for (reference, bytes) in [
            (evidence.plan_ref, evidence.plan_bytes),
            (evidence.refused_ref, evidence.refused_bytes),
        ] {
            reference
                .verify(bytes)
                .map_err(|error| failure(super::error::construction_diagnostic(&error)))?;
            let parsed =
                crucible_node_contract::canonical::parse_json(bytes, MAXIMUM_DOCUMENT_BYTES)
                    .map_err(|error| failure(super::error::construction_diagnostic(&error)))?;
            if crucible_node_contract::canonical::canonical_json(&parsed)
                .map_err(|error| failure(super::error::construction_diagnostic(&error)))?
                != bytes
            {
                return Err(failure("collection documents are not canonical originals"));
            }
        }
        authority.authenticate_collection_plan(evidence.borrowed())?;
        Ok(Self(Rc::new(Plan {
            plan_ref: evidence.plan_ref.clone(),
            plan_bytes: evidence.plan_bytes.to_vec(),
            refused_ref: evidence.refused_ref.clone(),
            refused_bytes: evidence.refused_bytes.to_vec(),
            world: evidence.world.clone(),
            sources: evidence.sources.to_vec(),
            authority,
        })))
    }

    /// Borrows the complete original plan/audit bytes without copying them.
    pub fn evidence(&self) -> ConformancePlanEvidence<'_> {
        ConformancePlanEvidence {
            plan_ref: &self.0.plan_ref,
            plan_bytes: &self.0.plan_bytes,
            refused_ref: &self.0.refused_ref,
            refused_bytes: &self.0.refused_bytes,
            world: &self.0.world,
            sources: &self.0.sources,
        }
    }

    /// Reauthenticates the current installed policy and every retained original body.
    ///
    /// # Errors
    /// Refuses revoked/changed host installation or original collection scope.
    pub fn reauthenticate(&self) -> Result<(), EvidenceError> {
        self.0
            .authority
            .authenticate_collection_plan(self.evidence())
    }

    /// Reauthenticates membership of the exact retained host authority object.
    ///
    /// Matching portable plan bytes or another policy object cannot satisfy this
    /// identity check. Success grants no ordinary execution permission.
    ///
    /// # Errors
    /// Refuses foreign host authority or revoked original plan/source scope.
    pub fn authenticate_authority(
        &self,
        authority: &dyn ConformanceAdmissionAuthority,
    ) -> Result<(), EvidenceError> {
        if !self.has_authority(authority) {
            return Err(failure("foreign retained collection authority"));
        }
        self.reauthenticate()
    }

    /// Counts this original plan's retained backing, excluding its authority.
    ///
    /// Actual document/source vector capacities and independently owned full
    /// reference strings are included together with the private Plan Rc header
    /// and inline value. The surrounding InstalledConformancePlan handle, any
    /// outer Rc/Box, and the borrowed authority backing are separate owners.
    /// This allocates nothing, extracts no graph, and grants no permission.
    ///
    /// Repeated views conservatively report the same private backing again;
    /// callers may deduplicate only an authenticated actual allocation identity,
    /// never equal plan bytes, source IDs or authority metadata.
    ///
    /// # Errors
    /// Refuses checked arithmetic overflow in actual retained allocation counts.
    pub fn retained_allocation_bytes_excluding_authority(&self) -> Result<usize, EvidenceError> {
        use crate::node_contract::NodeRuntime;
        let mut total = NodeRuntime::capture_shared_allocation_storage::<Plan>();
        let vector = self
            .0
            .sources
            .capacity()
            .checked_mul(std::mem::size_of::<ContentRef>())
            .ok_or_else(|| failure("original plan source slot storage overflow"))?;
        for bytes in [
            self.0.plan_bytes.capacity(),
            self.0.refused_bytes.capacity(),
            vector,
        ] {
            total = total
                .checked_add(bytes)
                .ok_or_else(|| failure("original plan buffer storage overflow"))?;
        }
        for reference in [&self.0.plan_ref, &self.0.refused_ref]
            .into_iter()
            .chain(&self.0.sources)
        {
            total = total
                .checked_add(
                    NodeRuntime::capture_reference_storage(reference)
                        .map_err(|_| failure("original plan reference storage overflow"))?,
                )
                .ok_or_else(|| failure("original plan reference aggregate overflow"))?;
        }
        total
            .checked_add(
                NodeRuntime::capture_hash_storage(&self.0.world)
                    .map_err(|_| failure("original plan world storage overflow"))?,
            )
            .ok_or_else(|| failure("original plan retained aggregate overflow"))
    }

    /// Observes this same installed plan with allocation-free bound failures.
    ///
    /// Counts the actual private Plan allocation, original byte/vector capacities
    /// and complete reference strings. Its borrowed authority remains a distinct
    /// owner. This performs no graph validation, serializer or authority callback.
    ///
    /// # Errors
    /// Returns `ResourceLimit` on checked arithmetic overflow without allocating
    /// an EvidenceError diagnostic. This data result grants no plan permission.
    pub fn retained_allocation_bytes_excluding_authority_precredit_data(
        &self,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        use crate::node_contract::NodeRuntime;
        let mut total = NodeRuntime::capture_shared_allocation_storage::<Plan>();
        let vector = self
            .0
            .sources
            .capacity()
            .checked_mul(std::mem::size_of::<ContentRef>())
            .ok_or(crate::node_contract::RuntimeError::ResourceLimit)?;
        for bytes in [
            self.0.plan_bytes.capacity(),
            self.0.refused_bytes.capacity(),
            vector,
        ] {
            total = total
                .checked_add(bytes)
                .ok_or(crate::node_contract::RuntimeError::ResourceLimit)?;
        }
        for reference in [&self.0.plan_ref, &self.0.refused_ref]
            .into_iter()
            .chain(&self.0.sources)
        {
            total = total
                .checked_add(NodeRuntime::capture_reference_storage(reference)?)
                .ok_or(crate::node_contract::RuntimeError::ResourceLimit)?;
        }
        total
            .checked_add(NodeRuntime::capture_hash_storage(&self.0.world)?)
            .ok_or(crate::node_contract::RuntimeError::ResourceLimit)
    }

    pub(crate) fn retained(&self) -> Self {
        Self(Rc::clone(&self.0))
    }

    // A source fixture must retain the very same installed authority, not merely
    // reproduce its portable plan bytes through a different policy object.
    // Trait vtables may be duplicated by code generation; object identity must
    // compare the retained authority data address rather than that metadata.
    pub(crate) fn has_authority(&self, authority: &dyn ConformanceAdmissionAuthority) -> bool {
        std::ptr::addr_eq(self.0.authority.as_ref(), authority)
    }

    pub(crate) fn same_original(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

impl ConformancePlanEvidence<'_> {
    fn borrowed(&self) -> ConformancePlanEvidence<'_> {
        ConformancePlanEvidence {
            plan_ref: self.plan_ref,
            plan_bytes: self.plan_bytes,
            refused_ref: self.refused_ref,
            refused_bytes: self.refused_bytes,
            world: self.world,
            sources: self.sources,
        }
    }
}

/// Retains a complete collection-only graph without an ordinary graph conversion.
///
/// World and descriptor bytes retain their existing formats. The collection
/// purpose stays in this nonserialized host capsule and cannot be reconstructed
/// from those bytes. Native/runtime ownership remains a separate requirement.
pub struct ConformanceGraph {
    pub(crate) graph: AdmittedGraph,
    pub(crate) plan: InstalledConformancePlan,
    descriptors: Vec<NodeDescriptor>,
    bindings: Vec<NodeBinding>,
    owners: Vec<OwnerBinding>,
}

impl ConformanceGraph {
    pub(crate) fn charge_original_retained_storage(
        &self,
        counter: &mut crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        let Self {
            graph,
            plan,
            descriptors,
            bindings,
            owners,
        } = self;
        graph.charge_original_retained_storage(counter)?;
        plan.charge_original_retained_storage(counter)?;
        counter.owned(descriptors)?;
        counter.owned(bindings)?;
        counter.owned(owners)
    }

    pub(crate) fn charge_original_retained_storage_precredit_data(
        &self,
        counter: &mut crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        let Self {
            graph,
            plan,
            descriptors,
            bindings,
            owners,
        } = self;
        graph.charge_original_retained_storage(counter)?;
        plan.charge_original_retained_storage_precredit_data(counter)?;
        counter.owned(descriptors)?;
        counter.owned(bindings)?;
        counter.owned(owners)
    }

    /// Borrows the original complete immutable world without its ordinary seal.
    pub fn world(&self) -> &WorldBinding {
        self.graph.world()
    }

    /// Borrows the original complete collection plan and refused audit.
    pub fn plan(&self) -> &InstalledConformancePlan {
        &self.plan
    }

    /// Reauthenticates the original complete world and installed collection policy.
    ///
    /// # Errors
    /// Refuses stale plan/source authority or changed complete collection scope.
    pub fn reauthenticate(&self) -> Result<(), EvidenceError> {
        self.plan.reauthenticate()?;
        self.plan
            .0
            .authority
            .authenticate_collection_world(self.plan.evidence(), self.request())?;
        for binding in &self.bindings {
            let identity = binding
                .compatibility
                .identity()
                .map_err(|error| failure(super::error::construction_diagnostic(&error)))?;
            self.plan.0.authority.authenticate_collection_node(
                self.plan.evidence(),
                QualificationClaim::Node {
                    binding: &binding.compatibility,
                    binding_hash: &identity,
                    qualification_refs: &binding.compatibility.qualification_refs,
                },
            )?;
        }
        self.authenticate_current_scope()
    }

    pub(crate) fn authenticate_quantized(&self) -> Result<(), EvidenceError> {
        self.reauthenticate()?;
        self.plan
            .0
            .authority
            .authenticate_collection_quantized(self.plan.evidence(), self.request())?;
        self.authenticate_current_scope()
    }

    pub(crate) fn authenticate_inputs(
        &self,
        batch: &crate::node_scheduling::RuntimeInputBatch,
    ) -> Result<(), EvidenceError> {
        self.authenticate_quantized()?;
        self.plan
            .0
            .authority
            .authenticate_collection_inputs(self.plan.evidence(), batch)?;
        self.authenticate_current_scope()
    }

    pub(crate) fn authenticate_exact_input_scope(
        &self,
        source: &crate::node_contract::HostSchedulingSource,
    ) -> Result<(), EvidenceError> {
        self.reauthenticate()?;
        source
            .authenticate_preparation_source(&self.plan.0.world)
            .map_err(|error| failure(error.reason))?;
        self.plan.0.authority.authenticate_collection_exact_inputs(
            self.plan.evidence(),
            self.request(),
            source,
        )?;
        self.authenticate_current_scope()
    }

    pub(crate) fn authenticate_complete_capture(
        &self,
        source: &crate::node_contract::HostSchedulingSource,
        runtime: &crate::node_contract::OriginalLineageRuntimeRecord,
        scheduling: &crate::node_scheduling::SchedulingSnapshot,
        capture_id: &crucible_node_contract::Id,
    ) -> Result<(), EvidenceError> {
        self.reauthenticate()?;
        source
            .authenticate_complete_preparation_source(&self.plan.0.world)
            .map_err(|error| failure(error.reason))?;
        source
            .authenticate_current()
            .map_err(|error| failure(error.reason))?;
        self.plan.0.authority.authenticate_collection_capture(
            self.plan.evidence(),
            self.request(),
            source,
            runtime,
            scheduling,
            capture_id,
        )?;
        source
            .authenticate_current()
            .map_err(|error| failure(error.reason))?;
        self.authenticate_current_scope()
    }

    pub(crate) fn authenticate_exact_inputs(
        &self,
        batch: &crate::node_scheduling::RuntimeInputBatch,
        source: &crate::node_contract::HostSchedulingSource,
    ) -> Result<(), EvidenceError> {
        self.authenticate_exact_input_scope(source)?;
        source
            .authenticate_input_batch(batch)
            .map_err(|error| failure(error.reason))?;
        self.plan
            .0
            .authority
            .authenticate_collection_inputs(self.plan.evidence(), batch)?;
        source
            .authenticate_input_batch(batch)
            .map_err(|error| failure(error.reason))?;
        self.authenticate_current_scope()
    }

    pub(crate) fn authenticate_operation(
        &self,
        node: &crucible_node_contract::Id,
        operation: &crucible_node_contract::Id,
        request: &crate::node_contract::OperationRequest,
    ) -> Result<(), EvidenceError> {
        self.reauthenticate()?;
        self.plan.0.authority.authenticate_collection_operation(
            self.plan.evidence(),
            node,
            operation,
            request,
        )?;
        // The case callback can revoke its installation while returning success.
        // The final installed revision also covers independently revoked world,
        // node and native-owner scope; a plan-only check cannot establish it.
        self.authenticate_current_scope()
    }

    pub(crate) fn authenticate_current_scope(&self) -> Result<(), EvidenceError> {
        self.plan.reauthenticate()?;
        self.plan
            .0
            .authority
            .authenticate_collection_current_scope(self.plan.evidence(), self.request())
    }

    fn request(&self) -> AdmissionRequest<'_> {
        AdmissionRequest {
            world: self.graph.world(),
            descriptors: &self.descriptors,
            bindings: &self.bindings,
            owners: &self.owners,
            requirements: self.graph.requirements(),
        }
    }
}

/// Seals only an independently authorized original collection world.
///
/// Every ordinary structural admission check remains. Node behavioral claims
/// and dormant Capture profiles use explicit installed collection callbacks;
/// all other claims are delegated unchanged. This returns neither an accepted
/// class, an ordinary graph nor active capture authority.
///
/// # Errors
/// Refuses wrong plan/world/source, failed default authority, missing ordinary
/// structural/schema/ownership evidence, or exhausted unchanged admission limits.
pub fn admit_conformance_graph(
    request: AdmissionRequest<'_>,
    plan: &InstalledConformancePlan,
    limits: AdmissionLimits,
) -> Result<ConformanceGraph, AdmissionError> {
    super::nodes::check_core(&request, limits)?;
    authenticate_original_scope(request, plan)?;
    let delegated = CollectionEvidence { plan };
    let mut graph = super::admit_graph_for_purpose(request, &delegated, limits, Some(plan))?;
    graph.collecting = true;
    Ok(ConformanceGraph {
        graph,
        plan: plan.retained(),
        descriptors: request.descriptors.to_vec(),
        bindings: request.bindings.to_vec(),
        owners: request.owners.to_vec(),
    })
}

// Admission callbacks may revoke the installation even after extension checks.
// The final call runs before retaining any returned graph or collection seal.
pub(super) fn authenticate_original_scope(
    request: AdmissionRequest<'_>,
    plan: &InstalledConformancePlan,
) -> Result<(), AdmissionError> {
    let checked = (|| {
        plan.reauthenticate()?;
        if request
            .world
            .identity()
            .map_err(|error| failure(super::error::construction_diagnostic(&error)))?
            != *plan.evidence().world
        {
            return Err(failure(
                "collection world differs from original refused plan",
            ));
        }
        plan.0
            .authority
            .authenticate_collection_world(plan.evidence(), request)?;
        plan.reauthenticate()?;
        plan.0
            .authority
            .authenticate_collection_current_scope(plan.evidence(), request)
    })();
    checked.map_err(|error| {
        super::error::refuse(
            AdmissionStage::Authenticate,
            AdmissionSubject::World,
            AdmissionCode::QualificationUnavailable,
            "current original source-installed collection plan",
            &error.message,
        )
    })
}

struct CollectionEvidence<'a> {
    plan: &'a InstalledConformancePlan,
}

impl AdmissionEvidence for CollectionEvidence<'_> {
    fn extension_registry(&self) -> Option<&InstalledExtensionRegistry> {
        self.plan.0.authority.extension_registry()
    }

    fn content(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        self.plan.0.authority.content(reference, maximum_bytes)
    }

    fn authenticate_implementation(
        &self,
        implementation: &crucible_node_contract::ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        self.plan
            .0
            .authority
            .authenticate_implementation(implementation)
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        self.plan.0.authority.authenticate_authority(binding)
    }

    fn authenticate_schema(
        &self,
        schema: &crucible_node_contract::SchemaRef,
    ) -> Result<(), EvidenceError> {
        self.plan.0.authority.authenticate_schema(schema)
    }

    fn qualify_capability(
        &self,
        world: &WorldBinding,
        binding: &NodeBinding,
        requirement: &NodeCapabilityRequirement,
    ) -> Result<(), EvidenceError> {
        self.plan
            .0
            .authority
            .qualify_capability(world, binding, requirement)
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        self.plan.reauthenticate()?;
        match claim {
            QualificationClaim::Node { .. } => self
                .plan
                .0
                .authority
                .authenticate_collection_node(self.plan.evidence(), claim),
            QualificationClaim::Capture { .. } => self
                .plan
                .0
                .authority
                .authenticate_collection_capture_profile(self.plan.evidence(), claim),
            _ => self.plan.0.authority.qualify(claim),
        }
    }
}

fn failure(message: impl Into<String>) -> EvidenceError {
    EvidenceError {
        message: message.into(),
    }
}

#[path = "conformance/host_initial_lifecycle.rs"]
mod host_initial_lifecycle;
pub use host_initial_lifecycle::{
    CompleteOriginalHostInitialLifecycleWindow, OriginalHostInitialLifecycleMemberScope,
    OriginalHostInitialLifecyclePolicy, OriginalHostInitialLifecycleScope,
    OriginalHostInitialLifecycleStorage,
};

/// Seals the same original four-owner graph with bounded failure diagnostics.
///
/// This runs every existing collecting admission check. It issues no memory,
/// native, readiness or execution action. Its concrete installed caller must
/// admit the complete prospective constructor/callback phase before entry.
/// Ordinary collecting admission retains its existing diagnostic behavior.
///
/// # Errors
/// Refuses another cardinality or any existing original graph/plan/schema gate.
/// Structured stage, subject, code and effect certainty remain unchanged.
pub fn admit_original_fixed_four_conformance_graph(
    request: AdmissionRequest<'_>,
    plan: &InstalledConformancePlan,
    limits: AdmissionLimits,
) -> Result<ConformanceGraph, AdmissionError> {
    let _diagnostic = super::error::OriginalConstructionDiagnosticScope::enter();
    if request.descriptors.len() != 4 || request.bindings.len() != 4 || request.owners.len() != 4 {
        return Err(super::error::refuse(
            AdmissionStage::Parse,
            AdmissionSubject::World,
            AdmissionCode::BoundMismatch,
            "four original nodes and owners",
            "another cardinality",
        ));
    }
    admit_conformance_graph(request, plan, limits)
}

impl ConformanceGraph {
    /// Observes this same complete graph's actual owning backing without callbacks.
    ///
    /// # Errors
    /// Refuses unknown authority/source owners, busy data or checked excess.
    pub fn original_retained_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        let mut counter =
            crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter::new(maximum);
        counter.add(std::mem::size_of::<Self>())?;
        self.charge_original_retained_storage_precredit_data(&mut counter)?;
        Ok(counter.bytes())
    }
}

pub(crate) use runtime_construction::original_runtime_construction_failure_reason;

#[path = "conformance/restoration_construction.rs"]
mod restoration_construction;
pub use restoration_construction::{
    OriginalRestorationConstructionInputs, OriginalRestorationNodeConstructionData,
    OriginalRestorationNodeInputs,
};

pub(crate) use restoration_construction::OriginalRestorationSigningConstructionInputs;

pub(crate) use restoration_construction::{
    OriginalRestorationMappingInputs, OriginalRestorationSigningInputs,
    OriginalRestorationTransactionClaim, OriginalRestorationTransactionInspection,
    OriginalRestorationTransactionPhase,
};

pub(crate) use restoration_construction::OriginalRestorationSigningCollector;
pub use restoration_construction::{
    CompleteOriginalRestorationTransactionTarget, CompleteOriginalRestorationWindow,
    OriginalRestorationConstructionPhase, OriginalRestorationConstructionPolicy,
    OriginalRestorationConstructionScope, OriginalRestorationConstructionStorage,
    OriginalRestorationMemberScope, OriginalRestorationNodeDispatch,
};

pub use restoration_construction::OriginalRestorationNodeContinuationInspection;

pub use restoration_construction::OriginalRestorationHostContinuationInspection;

pub use restoration_construction::{
    OriginalInstalledRestorationActivationClaim, OriginalInstalledRestorationActivationPhase,
};
pub(crate) use restoration_construction::{
    OriginalInstalledRestorationActivationSigningConstructionInputs,
    OriginalInstalledRestorationActivationSigningInputs,
};

pub use restoration_construction::OriginalRestorationCoordinatorConstructionData;

pub use restoration_construction::OriginalInstalledRestorationObservationClaim;
pub(crate) use restoration_construction::{
    OriginalInstalledRestorationObservationSigningConstructionInputs,
    OriginalInstalledRestorationObservationSigningInputs,
};

pub(crate) use restoration_construction::{
    OriginalRestoredSuffixCheckpointData, OriginalRestoredSuffixConstructionData,
    OriginalRestoredSuffixSeedClaim,
};

pub use restoration_construction::{
    OriginalRestoredInitialSchedulingAdmission, OriginalRestoredSchedulingObservationAdmission,
    OriginalRestoredSchedulingObservationClaim,
    OriginalRestoredSchedulingObservationConstructionData,
};

pub use restoration_construction::{
    OriginalRestoredProducerExecutionAdmission, OriginalRestoredProducerExecutionClaim,
    OriginalRestoredProducerExecutionConstructionData,
    OriginalRestoredProducerPublisherConstructionScope,
};

pub(crate) use restoration_construction::ProducerExecutionPhase;

pub use native_startup::CompleteOriginalRestoredSettledStartupAdmission;
pub(crate) use native_startup::OriginalRestoredSettledStartupMember;

pub use restoration_construction::OriginalRestoredInput17ConstructionData;

pub use restoration_construction::{
    OriginalRestoredCaptureClaim, OriginalRestoredCaptureRequestData,
};
pub(crate) use restoration_construction::{
    OriginalRestoredCaptureImportedOwnerInputs, OriginalRestoredCaptureSigningInputs,
};
