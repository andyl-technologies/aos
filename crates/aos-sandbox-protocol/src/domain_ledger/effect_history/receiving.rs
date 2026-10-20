//! Dominant BYTE geometry for the complete existing Effect decoder graph.
//!
//! The old complete decoder still selects every ordinary/Controller/FUSE/Nix/
//! Q04 branch. This supplier neither parses inputs nor authenticates history.
//! It bounds the actual finite model/container graph before those old engines
//! allocate; decoder limits and the genuine caller's cgroup remain backstops.

use std::mem::size_of;
use aos_proto::aos::sandbox::{v1 as wire, local::v1 as local};
use aos_sandbox_core::{CapabilityRecord, CapabilityDraft, Grant, Selector, PathName};
use aos_sandbox_core::model::{DirectoryEntry, Node, Extent, Xattr, AclEntry};
use super::{EffectLedgerRecord, EffectPlan, EffectState, PublicMutationEffectHistoryV1};

/// Returns conservative decoded-model bytes for one actual encoded Effect row.
///
/// Existing protobuf/JSON repeated entries require actual input tokens; raw text
/// cannot decode into more content bytes than its input. Three model planes
/// cover resident, constructor and old/new collection backing. JSON encoding
/// can escape a byte as six bytes (`\u00ff`); its three growth/output planes
/// are charged separately. Native/allocator bookkeeping is independently bounded
/// by the actual decoder and charged cgroup. No native FD or authority is made.
///
/// The finite wire type list is the transitive closure of the actual public
/// request union, checked public resource projections and historical Nix wire
/// records. It is layout DATA only: no format/parser or accepted-model factory.
/// `None` reports checked arithmetic overflow.
#[must_use]
pub fn effect_decoding_receiving_bytes_v1(encoded_bytes: usize) -> Option<usize> {
    let mut widest = 0;
    for width in model_widths() { widest = widest.max(width); }
    // JSON object values and the Nix portable record/active/used tables use
    // these actual key/value types. One node per actual input token is a
    // conservative bound; no whole-config maxima are multiplied together.
    use aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1 as nodes;
    let json = nodes::<String, serde_json::Value>(encoded_bytes)?;
    let records = nodes::<aos_sandbox_core::ObjectDescriptor, Vec<u8>>(encoded_bytes)?;
    let sets = nodes::<aos_sandbox_core::ObjectDescriptor, ()>(encoded_bytes)?.checked_mul(2)?;
    let maps = json.checked_add(records)?.checked_add(sets)?;
    let models = widest.checked_mul(encoded_bytes)?.checked_mul(3)?;
    let raw = encoded_bytes.checked_mul(6)?.checked_mul(3)?;
    let fixed = size_of::<EffectLedgerRecord>().checked_add(size_of::<EffectPlan>())?
        .checked_add(size_of::<EffectState>())?
        .checked_add(size_of::<PublicMutationEffectHistoryV1>())?
        .checked_mul(3)?;
    let publication = crate::publication::decoding_receiving_bytes_v1(encoded_bytes)?;
    models.checked_add(maps)?.checked_add(raw)?.checked_add(fixed)?
        .checked_add(publication)
}

fn model_widths() -> impl Iterator<Item = usize> {
    [
        // V7 holds the full history, exact source models and two authenticated
        // terminal originals while validating each current plan/lease. This
        // sum is a dominant byte width for that finite nested DATA graph,
        // including one container header per actual encoded token. It is not
        // namespace metadata or a native capability.
        size_of::<(
            crate::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
            crate::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
            crate::authenticated_session::stored_history::StoredBrokerSessionHistoryV1,
            crate::authenticated_session::historical_checkpoint::HistoricalSessionCheckpointV1,
            aos_sandbox_broker_session_protocol::BrokerSessionDurableRecordV1,
            aos_sandbox_broker_session_protocol::BrokerSessionDurableHistoryV1,
            aos_sandbox_core::ExecutionSpecV1,
            aos_sandbox_core::BrokerAuthorizationPlan,
            aos_sandbox_core::OwnershipLease,
            crate::execution_argument_receipt::ControllerArgumentReceiptDataV1,
            local::HostExecutionOutcomeV1,
            // The explicit physical companion additionally keeps its immutable
            // C18 anchor, original Storage traffic, signed60 and exact logical
            // registration alongside the already-decoded Host/source models.
            crate::controller_capture_admission::ControllerCaptureAdmissionAnchorDataV1,
            crate::authenticated_session::stored_history::StoredBrokerSessionHistoryV1,
            crate::authenticated_session::historical_checkpoint::HistoricalSessionCheckpointV1,
            aos_sandbox_broker_session_protocol::BrokerSessionDurableHistoryV1,
            crate::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
            crate::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
            aos_sandbox_core::ExecutionSpecV1,
            aos_sandbox_core::BrokerAuthorizationPlan,
            aos_sandbox_core::OwnershipLease,
        )>(),
        size_of::<crate::policy_data::PreparedPublisherPolicyRevisionV1>(),
        size_of::<aos_sandbox_core::model::Policy>(),
        size_of::<aos_sandbox_core::model::PolicyViewAction>(),
        size_of::<aos_sandbox_core::model::ExplanationReason>(),
        size_of::<aos_sandbox_core::model::ResourceProfile>(),
        size_of::<aos_sandbox_core::model::Limit>(),
        size_of::<aos_sandbox_core::FeatureRef>(),
        size_of::<aos_sandbox_core::ObjectDescriptor>(),
        size_of::<CapabilityRecord>(), size_of::<CapabilityDraft>(), size_of::<Grant>(),
        size_of::<Selector>(), size_of::<PathName>(), size_of::<DirectoryEntry>(),
        size_of::<Node>(), size_of::<Extent>(), size_of::<Xattr>(), size_of::<AclEntry>(),
        size_of::<buffa::UnknownField>(), size_of::<buffa::UnknownFieldData>(),
        size_of::<serde_json::Value>(), size_of::<(String, serde_json::Value)>(),
        size_of::<Vec<u8>>(), size_of::<[u8; 32]>(), size_of::<u64>(),
        size_of::<crate::public_api::request::DormantSandboxRequestKindV1>(),
        size_of::<crate::public_api::projection::PublicProjectionResourceV1>(),
        size_of::<crate::public_api::mutation_history::ControllerFuseAdmissionCarrierV1>(),
        size_of::<crate::public_api::mutation_history::NixStartAdmissionCarrierV2>(),
        size_of::<crate::nix_build::NixStoreObjectV2>(),
        size_of::<crate::nix_build::NixPortableObjectV2>(),
        size_of::<crate::nix_build::NixExpectedOutputV2>(),
        size_of::<local::AssignmentFence>(),
        size_of::<local::NixBuildRequestV2>(),
        size_of::<local::NixBuildResponseV2>(),
        size_of::<local::RequestHeader>(),
        size_of::<wire::AttachViewRequest>(),
        size_of::<wire::Attachment>(),
        size_of::<wire::AttachmentStatus>(),
        size_of::<wire::AttachmentStatusSet>(),
        size_of::<wire::AttenuateCapabilityRequest>(),
        size_of::<wire::CacheStatus>(),
        size_of::<wire::CancelExecutionRequest>(),
        size_of::<wire::CancelOperationRequest>(),
        size_of::<wire::Capability>(),
        size_of::<wire::Command>(),
        size_of::<wire::Condition>(),
        size_of::<wire::CreateExecutionRequest>(),
        size_of::<wire::CreateSandboxRequest>(),
        size_of::<wire::CreateSnapshotRequest>(),
        size_of::<wire::CreateViewRequest>(),
        size_of::<wire::DeleteSandboxRequest>(),
        size_of::<wire::DeleteSnapshotRequest>(),
        size_of::<wire::DetachViewRequest>(),
        size_of::<wire::DisclosureStatus>(),
        size_of::<wire::Duration>(),
        size_of::<wire::EnvironmentVariable>(),
        size_of::<wire::Execution>(),
        size_of::<wire::ExecutionControlRequest>(),
        size_of::<wire::ExecutionResult>(),
        size_of::<wire::ExecutionTerminalSignalV2>(),
        size_of::<wire::Feature>(),
        size_of::<wire::FilesystemView>(),
        size_of::<wire::ForkSnapshotRequest>(),
        size_of::<wire::GetAttachmentRequest>(),
        size_of::<wire::GetCacheStatusRequest>(),
        size_of::<wire::GetExecutionRequest>(),
        size_of::<wire::GetNodeCapabilitiesRequest>(),
        size_of::<wire::GetOperationRequest>(),
        size_of::<wire::GetPublicFeatureRegistryRequest>(),
        size_of::<wire::GetSandboxRequest>(),
        size_of::<wire::GetSnapshotRequest>(),
        size_of::<wire::GetViewRequest>(),
        size_of::<wire::GuardianStatus>(),
        size_of::<wire::InspectCapabilityRequest>(),
        size_of::<wire::ListAncestorsRequest>(),
        size_of::<wire::ListChildrenRequest>(),
        size_of::<wire::ListDescendantsRequest>(),
        size_of::<wire::ListExecutionsRequest>(),
        size_of::<wire::ListSandboxesRequest>(),
        size_of::<wire::ListSnapshotsRequest>(),
        size_of::<wire::ListViewsRequest>(),
        size_of::<wire::LogicalUsageStatus>(),
        size_of::<wire::MutationContext>(),
        size_of::<wire::ObjectDescriptor>(),
        size_of::<wire::OpenSshAccessEndpoint>(),
        size_of::<wire::OperatorRecoveryRequest>(),
        size_of::<wire::OwnershipStatus>(),
        size_of::<wire::OwnershipTransactionStatus>(),
        size_of::<wire::PinCacheObjectRequest>(),
        size_of::<wire::PlanCreateSandboxRequest>(),
        size_of::<wire::PlanSandboxPolicyRequest>(),
        size_of::<wire::RealizedRootStatus>(),
        size_of::<wire::ReleaseViewRequest>(),
        size_of::<wire::RenewCapabilityRequest>(),
        size_of::<wire::ReplaceAttachmentRequest>(),
        size_of::<wire::ResourceReference>(),
        size_of::<wire::RestoreSnapshotRequest>(),
        size_of::<wire::RevokeCapabilityRequest>(),
        size_of::<wire::Sandbox>(),
        size_of::<wire::SandboxDesiredState>(),
        size_of::<wire::SandboxLifecycleRequest>(),
        size_of::<wire::SandboxObservedState>(),
        size_of::<wire::SandboxTreePreorderState>(),
        size_of::<wire::Snapshot>(),
        size_of::<wire::Timestamp>(),
        size_of::<wire::UnpinCacheObjectRequest>(),
        size_of::<wire::UpdateSandboxPolicyRequest>(),
        size_of::<wire::WatchCursor>(),
        size_of::<wire::WatchRequest>(),
    ].into_iter()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entire_foreign_effect_graph_is_monotone_and_refuses_overflow() {
        let empty = effect_decoding_receiving_bytes_v1(0).unwrap();
        let small = effect_decoding_receiving_bytes_v1(128).unwrap();
        let large = effect_decoding_receiving_bytes_v1(4096).unwrap();

        assert!(empty < small);
        assert!(small < large);
        assert!(effect_decoding_receiving_bytes_v1(usize::MAX).is_none());
    }
}
