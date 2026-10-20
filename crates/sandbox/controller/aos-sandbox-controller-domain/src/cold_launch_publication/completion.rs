//! Compares actual Create Apply and Source Completing before the final Root ACK.
//!
//! Every parsed input stays borrowed from its genuine prepaid native owner.
//! This predicate performs no parsing, IO, account admission or capability
//! construction. Root independently captures and verifies C, Session and Source;
//! the installed issuer separately keeps its actual C23/Root/native originals.

use aos_sandbox_api::aos::sandbox::local::v1::{BrokerMethod, StorageResult};
use aos_sandbox_model::{BrokerAudience, ObjectDigest, ResourceDimension, ResourceVector};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerOutcomeDirectionV1, AuthenticatedBrokerRequestDirectionV1,
};
use aos_sandbox_protocol::domain_ledger::{
    effect_history::{CreateStoppedLifecycleReceiptDataV1, EffectLedgerRecord, EffectState,
        PublicMutationEffectHistoryV1, lifecycle_child_effect_commitment_v1},
    operation::OperationRecord,
    public_operation::OperationState,
    provisioning_resources::{ProvisioningModeDataV1, ProvisioningResourceRecordsV1,
        ProvisioningResourceRowKindV1},
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::continuation::ContinuationNativeReceiptDataV1;
use aos_sandbox_protocol::storage_inventory::ValidatedStorageInventory;
use sha2::{Digest as _, Sha256};

use crate::lifecycle::{LifecycleOperationV1, LifecycleRecordDigestV1, LifecyclePhaseV1,
    LifecycleIntentV1, LifecycleSemanticCommitFactV1,
    LifecycleResourceStateDigestV1, LifecycleIncarnationOriginV1};
use crate::publication::CurrentAuthorityPublicationV1;
use crate::runtime_authority::{RuntimeAuthorityBindingV1, RuntimeAuthorityStateV1};

/// Borrows actual pre-ACK models while the public operation remains pending.
///
/// None of these DATA fields admits a native role or authorizes completion.
/// Actual callers must first validate the complete Controller gate/binding/
/// publication/dispatch engines, both signed Session exchanges, and the full
/// Source schema/current-operation projection. Partial owners remain resident.
/// This value cannot authorize public success or a Start transition.
pub(crate) struct CreateStoppedPreAckSubjectsV1<'held> {
    pub(crate) receipt: CreateStoppedLifecycleReceiptDataV1<'held>,
    pub(crate) resources: ProvisioningResourceRecordsV1,
    pub(crate) original_root: ContinuationNativeReceiptDataV1<'held>,
    pub(crate) accepted: &'held PublicMutationEffectHistoryV1,
    pub(crate) lane: [u8; 16],
    pub(crate) parent_operation: OperationRecord,
    pub(crate) parent_effect: &'held EffectLedgerRecord,
    pub(crate) parent_projection: &'held aos_sandbox_protocol::public_api::projection::PublicProjectionRecordV1,
    pub(crate) request: &'held aos_sandbox_api::aos::sandbox::v1::CreateSandboxRequest,
    pub(crate) child_operation: OperationRecord,
    pub(crate) child: &'held EffectLedgerRecord,
    pub(crate) child_bytes: &'held [u8],
    pub(crate) binding: &'held RuntimeAuthorityBindingV1,
    pub(crate) publication: &'held CurrentAuthorityPublicationV1,
    pub(crate) source: &'held LifecycleOperationV1,
    pub(crate) source_record: LifecycleRecordDigestV1,
    pub(crate) apply: &'held AuthenticatedBrokerMethodOutcomeV1,
    pub(crate) apply_response: &'held StorageResult,
    pub(crate) inventory_exchange: &'held AuthenticatedBrokerMethodOutcomeV1,
    pub(crate) inventory: &'held ValidatedStorageInventory,
    pub(crate) admitted_plan: &'held [u8],
}

// Both phases consume the same actual parsed evidence. Their public C boundary
// differs, so only the historical branch can omit today's mutable projection.
pub(crate) struct CreateStoppedEvidenceSubjectsV2<'held> {
    pub(crate) receipt: CreateStoppedLifecycleReceiptDataV1<'held>,
    pub(crate) resources: ProvisioningResourceRecordsV1,
    pub(crate) original_root: ContinuationNativeReceiptDataV1<'held>,
    pub(crate) accepted: &'held PublicMutationEffectHistoryV1,
    pub(crate) lane: [u8; 16],
    pub(crate) parent_operation: OperationRecord,
    pub(crate) parent_effect: &'held EffectLedgerRecord,
    pub(crate) request: &'held aos_sandbox_api::aos::sandbox::v1::CreateSandboxRequest,
    pub(crate) child_operation: OperationRecord,
    pub(crate) child: &'held EffectLedgerRecord,
    pub(crate) child_bytes: &'held [u8],
    pub(crate) binding: &'held RuntimeAuthorityBindingV1,
    pub(crate) publication: &'held CurrentAuthorityPublicationV1,
    pub(crate) source: &'held LifecycleOperationV1,
    pub(crate) source_record: LifecycleRecordDigestV1,
    pub(crate) apply: &'held AuthenticatedBrokerMethodOutcomeV1,
    pub(crate) apply_response: &'held StorageResult,
    pub(crate) inventory_exchange: &'held AuthenticatedBrokerMethodOutcomeV1,
    pub(crate) inventory: &'held ValidatedStorageInventory,
    pub(crate) admitted_plan: &'held [u8],
}

#[derive(Clone, Copy)]
enum CreateStoppedComparisonPhaseV2<'held> {
    PreAck(&'held aos_sandbox_protocol::public_api::projection::PublicProjectionRecordV1),
    Historical {
        native: &'held crate::policy_compiler::create_storage_current::controller_readonly::native_read::RootCreateStoppedHistoricalOriginalV2,
        operation: &'held [u8],
        effect: &'held [u8],
    },
}

/// Compares historical Create evidence under its actual full native observer.
///
/// The Source subject is the immutable Completing record named by the receipt;
/// the enclosing paid Source reader must separately verify its genuine Terminal
/// successor and current accepted Start. Today's Sandbox projection is not
/// substituted for the historical atomic STOPPED member.
pub(crate) struct CreateStoppedHistoricalSubjectsV2<'held> {
    pub(crate) evidence: CreateStoppedEvidenceSubjectsV2<'held>,
    pub(crate) native: &'held crate::policy_compiler::create_storage_current::controller_readonly::native_read::RootCreateStoppedHistoricalOriginalV2,
    pub(crate) parent_operation_bytes: &'held [u8],
    pub(crate) parent_effect_bytes: &'held [u8],
}

/// Reports a failed exact historical completion comparison without authority.
#[derive(Debug, thiserror::Error)]
#[error("the actual Create workspace/publication/Source completion differs")]
pub(crate) struct CreateStoppedCompletionMismatchV1;

// This pure comparison has only fixed borrowed carriers, the canonical
// fixed-width resource row and hashing state. Parsed graph and native reader
// suppliers remain independent obligations before their owning constructors.
pub(crate) fn create_stopped_comparison_receiving_demand_v1() -> Option<ResourceVector> {
    create_stopped_selected_comparison_receiving_v2(
        std::mem::size_of::<CreateStoppedPreAckSubjectsV1<'static>>())
}

pub(crate) fn create_stopped_historical_comparison_receiving_demand_v2() -> Option<ResourceVector> {
    create_stopped_selected_comparison_receiving_v2(
        std::mem::size_of::<CreateStoppedHistoricalSubjectsV2<'static>>())
}

// Only these two closed codec-local callers select their actual input layout.
fn create_stopped_selected_comparison_receiving_v2(selected: usize) -> Option<ResourceVector> {
    let bytes = selected.checked_mul(2)?
        .checked_add(std::mem::size_of::<CreateStoppedEvidenceSubjectsV2<'static>>().checked_mul(2)?)?
        .checked_add(std::mem::size_of::<CreateStoppedComparisonPhaseV2<'static>>().checked_mul(2)?)?
        .checked_add(std::mem::size_of::<CreateWorkspaceSubjectsV1<'static>>().checked_mul(2)?)?
        .checked_add(aos_sandbox_protocol::domain_ledger::provisioning_resources::
            PROVISIONING_RESOURCE_ROW_BYTES_V1.checked_mul(2)?)?
        .checked_add(std::mem::size_of::<Sha256>().checked_mul(2)?)?
        .checked_add(aos_sandbox_protocol::domain_ledger::effect_history::
            CREATE_STOPPED_LIFECYCLE_RECEIPT_BYTES_V1.checked_mul(2)?)?;
    Some(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, u64::try_from(bytes).ok()?))
}

/// Requires actual pre-ACK evidence without completing either public observer.
///
/// Fresh native positions, original Root admission/currentness, independent
/// owed posts and all same-payer debit results remain the enclosing caller's
/// obligations. A positive pure comparison cannot substitute for them.
pub(crate) fn require_create_stopped_pre_ack_v1(
    value: CreateStoppedPreAckSubjectsV1<'_>,
) -> Result<(), CreateStoppedCompletionMismatchV1> {
    let phase = CreateStoppedComparisonPhaseV2::PreAck(value.parent_projection);
    require_create_stopped_evidence_v2(CreateStoppedEvidenceSubjectsV2 {
        receipt: value.receipt,
        resources: value.resources,
        original_root: value.original_root,
        accepted: value.accepted,
        lane: value.lane,
        parent_operation: value.parent_operation,
        parent_effect: value.parent_effect,
        request: value.request,
        child_operation: value.child_operation,
        child: value.child,
        child_bytes: value.child_bytes,
        binding: value.binding,
        publication: value.publication,
        source: value.source,
        source_record: value.source_record,
        apply: value.apply,
        apply_response: value.apply_response,
        inventory_exchange: value.inventory_exchange,
        inventory: value.inventory,
        admitted_plan: value.admitted_plan,
    }, phase)
}

pub(crate) fn require_create_stopped_historical_v2(
    value: CreateStoppedHistoricalSubjectsV2<'_>,
) -> Result<(), CreateStoppedCompletionMismatchV1> {
    require_create_stopped_evidence_v2(value.evidence, CreateStoppedComparisonPhaseV2::Historical {
        native: value.native,
        operation: value.parent_operation_bytes,
        effect: value.parent_effect_bytes,
    })
}

fn require_create_stopped_evidence_v2(
    value: CreateStoppedEvidenceSubjectsV2<'_>,
    phase: CreateStoppedComparisonPhaseV2<'_>,
) -> Result<(), CreateStoppedCompletionMismatchV1> {
    let invalid = || CreateStoppedCompletionMismatchV1;
    let fields = value.resources.fields_v1();
    value.receipt.require_resources_v1(value.resources).map_err(|_| invalid())?;
    // This receipt is durable evidence submitted TO Root, not an ACK of future
    // work. Public success and Source Terminal require the later genuine final
    // owner after Root160/EOF and all independently owed native posts.
    let EffectState::Applied { receipt: parent_receipt, .. } = value.parent_effect.state()
    else { return Err(invalid()); };
    let encoded_receipt = value.receipt.encode_v1(value.lane).map_err(|_| invalid())?;
    use aos_sandbox_protocol::public_api::{PublicOperationMethodV1,
        projection::PublicProjectionResourceV1};
    use aos_sandbox_api::aos::sandbox::v1::{DesiredLifecycle, SandboxPhase};
    let expected_parent_state = match phase {
        CreateStoppedComparisonPhaseV2::PreAck(_) => OperationState::Applying,
        CreateStoppedComparisonPhaseV2::Historical { .. } => OperationState::Succeeded,
    };
    if value.parent_operation.state() != expected_parent_state
        || value.parent_operation.effect_count() != 1
        || value.parent_operation.ownership_gated()
        || value.parent_operation.public_operation().is_none_or(|public|
            public.method() != PublicOperationMethodV1::CreateSandbox)
        || value.parent_effect.plan().public_mutation_method() != Some(PublicOperationMethodV1::CreateSandbox)
        || parent_receipt.as_bytes() != encoded_receipt.as_slice()
    {
        return Err(invalid());
    }
    match phase {
        CreateStoppedComparisonPhaseV2::PreAck(projection) => {
            let PublicProjectionResourceV1::Sandbox(sandbox) = projection.resource()
            else { return Err(invalid()); };
            let desired = sandbox.desired.as_option().ok_or_else(invalid)?;
            let observed = sandbox.observed.as_option().ok_or_else(invalid)?;
            if projection.operation() != fields.parent
                || projection.project() != fields.project
                || sandbox.sandbox_id.as_slice() != fields.sandbox.as_bytes()
                || sandbox.project_id.as_slice() != fields.project.as_bytes()
                || desired.lifecycle.as_known() != Some(DesiredLifecycle::DESIRED_LIFECYCLE_STOPPED)
                || desired.generation != 1
                || observed.phase.as_known() != Some(SandboxPhase::SANDBOX_PHASE_REQUESTED)
                || observed.desired_generation != 1
            {
                return Err(invalid());
            }
        }
        CreateStoppedComparisonPhaseV2::Historical { native, operation, effect } => {
            native.require_rows_v2(fields.parent, fields.project, fields.sandbox, operation, effect)
                .map_err(|_| invalid())?;
        }
    }
    let actual_root = value.receipt.root_closed_v1();
    let original_root = value.original_root;
    if actual_root.record != original_root.record
        || actual_root.latest_head != original_root.latest_head
        || actual_root.names != original_root.names
        || actual_root.after_next != original_root.after_next
        || actual_root.after_end != original_root.after_end
        || fields.mode != ProvisioningModeDataV1::CreateStopped
        || value.receipt.child_effect_v1() != lifecycle_child_effect_commitment_v1(value.child_bytes)
        || value.receipt.source_v1() != value.source_record.digest()
        || value.source.phase() != LifecyclePhaseV1::Completing
        || value.source.semantic_commit().is_none()
        || value.source.terminal_result().is_some()
        || value.source.finished_at().is_some()
 {
        return Err(invalid());
    }

    require_create_source_admission_data_v1(
        value.source, value.resources, value.accepted, value.request)?;
    require_create_source_semantic_v1(value.source, value.resources, value.binding)?;
    require_create_workspace_v1(CreateWorkspaceSubjectsV1 {
        resources: value.resources,
        child_operation: value.child_operation,
        child: value.child,
        binding: value.binding,
        publication: value.publication,
        apply: value.apply,
        apply_response: value.apply_response,
        inventory_exchange: value.inventory_exchange,
        inventory: value.inventory,
        admitted_plan: value.admitted_plan,
    })
}

/// Borrows the same real child, publication and signed workspace observations.
///
/// This pure DATA comparison cannot mint native custody or semantic completion.
pub(crate) struct CreateWorkspaceSubjectsV1<'held> {
    pub(crate) resources: ProvisioningResourceRecordsV1,
    pub(crate) child_operation: OperationRecord,
    pub(crate) child: &'held EffectLedgerRecord,
    pub(crate) binding: &'held RuntimeAuthorityBindingV1,
    pub(crate) publication: &'held CurrentAuthorityPublicationV1,
    pub(crate) apply: &'held AuthenticatedBrokerMethodOutcomeV1,
    pub(crate) apply_response: &'held StorageResult,
    pub(crate) inventory_exchange: &'held AuthenticatedBrokerMethodOutcomeV1,
    pub(crate) inventory: &'held ValidatedStorageInventory,
    pub(crate) admitted_plan: &'held [u8],
}

pub(crate) fn require_create_workspace_v1(
    value: CreateWorkspaceSubjectsV1<'_>,
) -> Result<(), CreateStoppedCompletionMismatchV1> {
    let invalid = || CreateStoppedCompletionMismatchV1;
    let fields = value.resources.fields_v1();
    let binding = value.binding;
    let manifest = binding.manifest().manifest();
    if value.child_operation.state() != OperationState::Succeeded
        || value.child_operation.effect_count() != 1 || !value.child_operation.ownership_gated()
        || value.child_operation.public_operation().is_some()
        || value.child_operation.runtime_intent_digest().is_none()
        || binding.state() != RuntimeAuthorityStateV1::Bound
        || binding.operation() != fields.publication_operation
        || binding.sandbox() != fields.sandbox || manifest.project() != fields.project
        || binding.manifest().digest() != fields.manifest || manifest.epoch() != fields.epoch
        || binding.source_draft_digest() != fields.source_draft
        || value.publication.manifest() != binding.manifest()
        || value.publication.digest() != binding.publication_digest()
        || value.publication.lease_digest() != binding.lease_digest()
        || value.publication.lease_generation() != binding.lease_generation() {
        return Err(invalid());
    }

    let authority = value.child.plan().authority().ok_or_else(invalid)?;
    let dispatch = value.child.dispatch().ok_or_else(invalid)?;
    let EffectState::Applied { receipt, .. } = value.child.state() else { return Err(invalid()); };
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = value.apply.result()
    else { return Err(invalid()); };
    let attempt = dispatch.attempt();
    let mut templates = value.publication.templates().iter().filter(|template|
        template.method() == BrokerMethod::BROKER_METHOD_STORAGE_APPLY
            && template.digest() == authority.template_digest()
            && template.canonical_plan() == value.admitted_plan);
    let template = templates.next().ok_or_else(invalid)?;
    if templates.next().is_some()
        || authority.operation_id() != fields.publication_operation || authority.step() != 0
        || authority.audience() != BrokerAudience::Storage
        || authority.method() != BrokerMethod::BROKER_METHOD_STORAGE_APPLY
        || authority.source_draft_digest() != fields.source_draft
        || value.child.plan().method() != Some(BrokerMethod::BROKER_METHOD_STORAGE_APPLY)
        || value.child.plan().request() != template.body_without_deadline()
        || ObjectDigest::from_bytes(Sha256::digest(template.canonical_plan()).into()) != fields.root_plan
        || dispatch.binding_digest() != authority.digest()
        || dispatch.publication_digest() != value.publication.digest()
        || attempt.template_digest() != authority.template_digest()
        || attempt.lease_digest() != value.publication.lease_digest()
        || attempt.lease_generation() != value.publication.lease_generation()
        || value.apply.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        || value.apply.request().direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend
        || value.apply.method() != BrokerMethod::BROKER_METHOD_STORAGE_APPLY
        || value.apply.request().method() != BrokerMethod::BROKER_METHOD_STORAGE_APPLY
        || value.apply.request().exact_body() != attempt.body()
        || receipt.as_bytes() != exact_body.as_slice() {
        return Err(invalid());
    }

    let inventory = value.inventory_exchange;
    if inventory.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        || inventory.request().direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend
        || inventory.method() != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
        || inventory.request().method() != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
        || !matches!(inventory.result(), AuthenticatedBrokerMethodResultV1::Success { .. })
        || inventory.request().session_binding() != value.apply.request().session_binding()
        || inventory.request().client_sequence() <= value.apply.request().client_sequence()
        || inventory.broker_sequence() <= value.apply.broker_sequence() {
        return Err(invalid());
    }
    require_create_workspace_inventory_data_v1(
        value.resources,
        binding,
        value.apply_response,
        value.inventory,
    )
}

/// Compares a separately authenticated inventory with the historical workspace.
///
/// The caller supplies the genuine parsed models and proves their provenance
/// independently. This comparison has no Session ordering or authorization
/// semantics; it cannot admit an inventory, revive an Apply, or complete a CAS.
pub(crate) fn require_create_workspace_inventory_data_v1(
    resources: ProvisioningResourceRecordsV1,
    binding: &RuntimeAuthorityBindingV1,
    apply_response: &StorageResult,
    inventory: &ValidatedStorageInventory,
) -> Result<(), CreateStoppedCompletionMismatchV1> {
    selected_create_workspace_inventory_data_v2(resources, binding, apply_response, inventory)
        .map(|_| ())
}

// This is the same immutable workspace relation as the unit-returning caller.
// Only actual authenticated/custody owners may attach provenance to the borrow.
pub(crate) fn selected_create_workspace_inventory_data_v2<'inventory>(
    resources: ProvisioningResourceRecordsV1,
    binding: &RuntimeAuthorityBindingV1,
    apply_response: &StorageResult,
    inventory: &'inventory ValidatedStorageInventory,
) -> Result<&'inventory aos_sandbox_protocol::storage_inventory::ValidatedStorageWorkspace,
    CreateStoppedCompletionMismatchV1>
{
    let invalid = || CreateStoppedCompletionMismatchV1;
    let fields = resources.fields_v1();
    let manifest = binding.manifest().manifest();
    let mut matching = inventory.workspaces().iter().filter(|workspace|
        crate::host_catalog_reconciliation::fence_matches_binding(workspace.fence(), binding));
    let workspace = matching.next().ok_or_else(invalid)?;
    if matching.next().is_some()
        || workspace.creation_operation_id() != fields.parent.as_bytes()
        || workspace.workspace_handle().as_slice() != apply_response.storage_handle.as_slice()
        || workspace.root_image() != manifest.root_view()
        || !apply_response.immutable_version_handle.is_empty()
        || workspace.resource_kernel_boot_id() != inventory.kernel_boot_id() {
        return Err(invalid());
    }
    Ok(workspace)
}

/// Prices the additional full Controller selector models before their decoders.
///
/// The same actual foreign Effect/publication/assignment suppliers used by
/// Core are joined with the sole provisioning-links validator's own complete
/// peak. Raw native/cold state and named selector maps remain separately paid;
/// this adds only bytes for models actually reachable from these namespaces.
pub(crate) fn create_stopped_controller_receiving_demand_v1(
    state: &std::collections::BTreeMap<(aos_sandbox_model::RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Option<ResourceVector> {
    use std::mem::size_of;
    let models = controller_selector_model_bytes_v1(state)?;
    let links = aos_sandbox_protocol::domain_ledger::provisioning_resources::
        provisioning_links_reached_receiving_bytes_v1(state, None)?;
    let runtime_rows = state.keys().filter(|(namespace, _)|
        *namespace == aos_sandbox_model::RecordNamespace::RuntimeAuthority).count();
    // Native wrapper values accompany their Core assignment graphs. Loading
    // all historical bindings can keep one current value beside the decoder.
    let runtime = runtime_rows.checked_mul(size_of::<RuntimeAuthorityBindingV1>())?
        .checked_mul(2)?;
    let fixed = size_of::<OperationRecord>().checked_mul(2)?
        .checked_add(size_of::<CurrentAuthorityPublicationV1>().checked_mul(2)?)?;
    let bytes = models.checked_add(links)?.checked_add(runtime)?.checked_add(fixed)?;
    let namespaces = controller_selector_namespace_entries_v1(state)?;
    Some(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, u64::try_from(bytes).ok()?)
        .with(ResourceDimension::MetadataEntries, u64::try_from(namespaces).ok()?))
}

// The existing Core phase and final Root selector immediately share this
// actual per-namespace recipe; neither copies a second decoder type census.
pub(crate) fn controller_selector_model_bytes_v1(
    state: &std::collections::BTreeMap<(aos_sandbox_model::RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Option<usize> {
    use aos_sandbox_model::RecordNamespace;
    let mut bytes = 0_usize;
    for ((namespace, _), value) in state {
        let model = match namespace {
            RecordNamespace::Effect => aos_sandbox_protocol::domain_ledger::effect_history::
                effect_decoding_receiving_bytes_v1(value.len()),
            RecordNamespace::AuthorityPublication | RecordNamespace::OwnershipGate =>
                aos_sandbox_protocol::publication::decoding_receiving_bytes_v1(value.len()),
            RecordNamespace::RuntimeAuthority => assignment_selector_model_bytes_v1(value.len()),
            _ => Some(0),
        }?;
        bytes = bytes.checked_add(model)?;
    }
    Some(bytes)
}

fn assignment_selector_model_bytes_v1(encoded: usize) -> Option<usize> {
    use aos_sandbox_model::format::assignment_capture::CanonicalAssignmentDecodeCaptureV1;
    let (dynamic, _) = CanonicalAssignmentDecodeCaptureV1::receiving_dynamic_footprint_v1(
        encoded, aos_sandbox_model::DecodeLimits::default(),
    )?;
    dynamic.checked_add(CanonicalAssignmentDecodeCaptureV1::receiving_construction_bytes_v1()?)?
        .checked_add(encoded.checked_mul(3)?)
}

// The old Core dynamic phase and Root final comparison use the same actual
// namespace-only recipe. Native cold maps and compiler selector maps are paid
// separately; this is only the newly reached typed decoder namespace plane.
pub(crate) fn controller_selector_namespace_entries_v1(
    state: &std::collections::BTreeMap<(aos_sandbox_model::RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Option<usize> {
    use aos_sandbox_model::RecordNamespace;
    state.iter().try_fold(0_usize, |entries, ((namespace, _), value)| {
        let reached = match namespace {
            RecordNamespace::AuthorityPublication | RecordNamespace::OwnershipGate =>
                aos_sandbox_protocol::publication::decoding_receiving_namespace_entries_v1(value.len())?,
            RecordNamespace::RuntimeAuthority =>
                aos_sandbox_protocol::publication::assignment_decoding_namespace_entries_v1(value.len())?,
            _ => 0,
        };
        entries.checked_add(reached)
    })
}

// Prices the same borrowed comparison carrier and fixed canonical row/hash
// scratch when Source derives its semantic witness before any receipt exists.
pub(crate) fn create_workspace_comparison_receiving_demand_v1() -> Option<ResourceVector> {
    let bytes = std::mem::size_of::<CreateWorkspaceSubjectsV1<'static>>().checked_mul(2)?
        .checked_add(aos_sandbox_protocol::domain_ledger::provisioning_resources::
            PROVISIONING_RESOURCE_ROW_BYTES_V1.checked_mul(2)?)?
        .checked_add(std::mem::size_of::<Sha256>().checked_mul(2)?)?;
    Some(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, u64::try_from(bytes).ok()?))
}

// Both the producer and independent Root comparison consume these same real
// resource/incarnation referents. This is only a pure DATA comparison.
pub(crate) fn require_create_source_semantic_v1(source: &LifecycleOperationV1,
    resources: ProvisioningResourceRecordsV1, binding: &RuntimeAuthorityBindingV1,
) -> Result<(), CreateStoppedCompletionMismatchV1> {
    require_create_source_semantic_manifest_v2(source, resources, binding.manifest())
}

/// Compares the same Source semantic resources to a protected historical manifest.
///
/// # Errors
/// Refuses missing or mismatched assignment/reservation facts, or a different
/// Created sandbox, incarnation, epoch or namespace generation.
pub(crate) fn require_create_source_semantic_manifest_v2(
    source: &LifecycleOperationV1,
    resources: ProvisioningResourceRecordsV1,
    canonical: &aos_sandbox_model::CanonicalAssignmentManifestV1,
) -> Result<(), CreateStoppedCompletionMismatchV1> {
    let invalid = || CreateStoppedCompletionMismatchV1;
    let fields = resources.fields_v1();
    let commit = source.method_semantic_commit().ok_or_else(invalid)?;
    let LifecycleSemanticCommitFactV1::DesiredState { assignments, reservations, .. } = commit.facts()
    else { return Err(invalid()); };
    let [assignment] = assignments.as_slice() else { return Err(invalid()); };
    let [reservation] = reservations.as_slice() else { return Err(invalid()); };
    let reserved_row = resources.encode_v1(ProvisioningResourceRowKindV1::Reservation);
    if assignment.sandbox() != fields.sandbox || assignment.assignment() != fields.assignment
        || assignment.epoch() != fields.epoch || reservation.reservation() != fields.reservation
        || reservation.revision() != fields.reservation_revision
        || reservation.state() != LifecycleResourceStateDigestV1::commit(&reserved_row) {
        return Err(invalid());
    }

    let manifest = canonical.manifest();
    let evidence = commit.evidence().incarnation().ok_or_else(invalid)?;
    if evidence.origin() != LifecycleIncarnationOriginV1::Created
        || evidence.fence().sandbox() != fields.sandbox
        || evidence.fence().incarnation() != manifest.incarnation()
        || evidence.fence().assignment_epoch() != manifest.epoch()
        || evidence.fence().namespace_generation() != manifest.namespace_generation()
    {
        return Err(invalid());
    }
    Ok(())
}


/// Compares the historical516 Source row to its canonical post-ACK successor.
///
/// This pure relation lends no ACK or Source authority. Actual consumers first
/// recover both records through the full protected Source schema/native owner.
pub(crate) fn require_create_terminal_source_v1(
    completing: &LifecycleOperationV1, record: LifecycleRecordDigestV1,
    terminal: &LifecycleOperationV1, inventory: ObjectDigest,
) -> Result<(), CreateStoppedCompletionMismatchV1> {
    require_create_terminal_source_inventory_v2(completing, record, terminal,
        crate::lifecycle::LifecycleInventoryDigestV1::commit(inventory.as_bytes()))
}

/// Compares the identical transition using its protected typed inventory digest.
///
/// The historical caller holds both records from full native Source replay;
/// this comparison lends no read interval, effect authority or native receipt.
///
/// # Errors
/// Refuses another predecessor, phase, progress, result, inventory or canonical
/// successor, including a nonreserved Completing or nonsuccessful terminal step.
pub(crate) fn require_create_terminal_source_inventory_v2(
    completing: &LifecycleOperationV1, record: LifecycleRecordDigestV1,
    terminal: &LifecycleOperationV1, inventory: crate::lifecycle::LifecycleInventoryDigestV1,
) -> Result<(), CreateStoppedCompletionMismatchV1> {
    let invalid=||CreateStoppedCompletionMismatchV1;
    if completing.phase()!=LifecyclePhaseV1::Completing
        || completing.method_semantic_commit().is_none()
        || completing.terminal_result().is_some() || completing.finished_at().is_some()
        || terminal.phase()!=LifecyclePhaseV1::Terminal
        || terminal.terminal_result()!=Some(crate::lifecycle::LifecycleTerminalResultV1::Succeeded)
        || terminal.finished_at().is_none() || terminal.predecessor_digest()!=Some(record)
        || terminal.forward_progress()!=completing.forward_progress().checked_add(1).ok_or_else(invalid)?
        || terminal.compensation_progress()!=completing.compensation_progress() {
        return Err(invalid());
    }
    let rebuilt=completing.successor(record,terminal.phase(),terminal.forward_progress(),
        terminal.compensation_progress(),terminal.steps().to_vec(),terminal.method_semantic_commit().cloned(),
        terminal.failure(),terminal.retry(),terminal.terminal_result(),terminal.finished_at()).map_err(|_|invalid())?;
    if &rebuilt!=terminal {return Err(invalid());}
    let ([old],[new])=(completing.steps(),terminal.steps()) else {return Err(invalid());};
    let (Some(before),Some(after))=(old.forward_attempts().last(),new.forward_attempts().last()) else {return Err(invalid());};
    if old.class()!=crate::lifecycle::LifecycleStepClassV1::PostCommitForward
        || old.domain()!=crate::lifecycle::LifecycleStepDomainV1::Controller
        || before.state()!=crate::lifecycle::LifecycleAttemptStateV1::Reserved
        || after.state()!=crate::lifecycle::LifecycleAttemptStateV1::Succeeded
        || after.inventory()!=Some(inventory) || new.inventory()!=Some(inventory)
        || after.result().is_none() || new.result()!=after.result() {
        return Err(invalid());
    }
    Ok(())
}

/// Joins the same immutable Source admission to its canonical accepted Create.
///
/// # Errors
/// Refuses another operation, target, caller, request, idempotency or accepted time.
pub(crate) fn require_create_source_admission_data_v1(
    source: &LifecycleOperationV1,
    resources: ProvisioningResourceRecordsV1,
    accepted: &PublicMutationEffectHistoryV1,
    request: &aos_sandbox_api::aos::sandbox::v1::CreateSandboxRequest,
) -> Result<(), CreateStoppedCompletionMismatchV1> {
    let fields = resources.fields_v1();
    if source.operation_id() != fields.parent || source.project() != fields.project
        || source.caller() != accepted.caller() || accepted.project() != fields.project
        || aos_sandbox_protocol::domain_ledger::provisioning_resources::
            provisioning_public_request_digest_v1(accepted.canonical_request()) != fields.public_request
        || source.idempotency() != crate::lifecycle::LifecycleIdempotencyDigestV1::
            commit(request.idempotency_key.as_slice())
        || !matches!(source.intent(), LifecycleIntentV1::Create { sandbox }
            if *sandbox == fields.sandbox)
        || u64::try_from(accepted.accepted_wall_seconds()).ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            != Some(source.accepted_at().get())
    {
        return Err(CreateStoppedCompletionMismatchV1);
    }
    Ok(())
}
