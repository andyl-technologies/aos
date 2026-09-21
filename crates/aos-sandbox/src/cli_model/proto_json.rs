//! Bounded ProtoJSON rendering from checked established-message projections.

use std::fmt;

use aos_proto::aos::sandbox::v1::{
    CacheStatus, ExecutionControlResult, ListAncestorsResponse, ListChildrenResponse,
    ListDescendantsRequest, ListDescendantsResponse, ListExecutionsResponse, ListSandboxesResponse,
    ListSnapshotsResponse, ListViewsResponse, OperatorRecoveryResult, PageInfo, PolicyPlan,
    PublicFeatureRegistry, SandboxTreePreorderState,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::controller_query::event::CheckedWatchEventV1;
use crate::controller_query::model::MAXIMUM_OPAQUE_RESPONSE_BYTES;
use crate::controller_query::portable_resource::{
    CheckedAttachmentResourceV1, CheckedCapabilityResourceV1, CheckedExecutionResourceV1,
    CheckedFilesystemViewResourceV1, CheckedNodeCapabilitiesV1, CheckedSnapshotResourceV1,
};
use crate::controller_query::resource::{
    CheckedOperationResourceV1, CheckedSandboxResourceV1, InvalidPublicResource,
};

/// Maximum bytes in one checked structured output document.
pub const MAXIMUM_PROTO_JSON_BYTES: usize = 16 * 1024 * 1024;
/// Maximum resources in one checked structured list document.
pub const MAXIMUM_PROTO_JSON_LIST_ITEMS: usize = 1_024;

/// Identifies the only schemas a structured renderer may emit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StructuredOutputSchemaV1 {
    /// Uses the established sandbox resource mapping.
    Sandbox,
    /// Uses the established operation resource mapping.
    Operation,
    /// Uses the established execution resource mapping.
    Execution,
    /// Uses the established filesystem-view resource mapping.
    FilesystemView,
    /// Uses the established attachment resource mapping.
    Attachment,
    /// Uses the established snapshot resource mapping.
    Snapshot,
    /// Uses the established capability resource mapping.
    Capability,
    /// Uses the established node-capabilities mapping.
    NodeCapabilities,
    /// Uses the established sandbox list-response mapping.
    SandboxList,
    /// Uses the established child list-response mapping.
    ChildrenList,
    /// Uses the established ancestor list-response mapping.
    AncestorsList,
    /// Uses the established descendant list-response mapping.
    DescendantsList,
    /// Uses the established execution list-response mapping.
    ExecutionList,
    /// Uses the established view list-response mapping.
    ViewList,
    /// Uses the established snapshot list-response mapping.
    SnapshotList,
    /// Uses the established public event mapping.
    Event,
    /// Uses the established sandbox-tree mapping.
    SandboxTree,
    /// Uses the established public feature-registry mapping.
    PublicFeatureRegistry,
    /// Uses the established cache-status mapping.
    CacheStatus,
    /// Uses the established policy-plan mapping.
    PolicyPlan,
    /// Uses the established execution-control-result mapping.
    ExecutionControlResult,
    /// Uses the established operator-recovery-result mapping.
    OperatorRecoveryResult,
    /// Emits a shell completion script as human text only.
    CompletionScript,
}

mod sealed {
    pub trait Sealed {}
}

/// Marks checked projections whose retained message has an established mapping.
pub trait EstablishedProtoJson: sealed::Sealed {
    /// Returns the output schema carried by this checked projection.
    fn output_schema(&self) -> StructuredOutputSchemaV1;

    /// Renders only the retained established generated message.
    #[doc(hidden)]
    fn render_established(&self) -> Result<String, serde_json::Error>;
}

macro_rules! established_resource {
    ($wrapper:ty, $schema:ident) => {
        impl sealed::Sealed for $wrapper {}

        impl EstablishedProtoJson for $wrapper {
            fn output_schema(&self) -> StructuredOutputSchemaV1 {
                StructuredOutputSchemaV1::$schema
            }

            fn render_established(&self) -> Result<String, serde_json::Error> {
                serde_json::to_string(self.as_proto())
            }
        }
    };
}

established_resource!(CheckedSandboxResourceV1, Sandbox);
established_resource!(CheckedOperationResourceV1, Operation);
established_resource!(CheckedExecutionResourceV1, Execution);
established_resource!(CheckedFilesystemViewResourceV1, FilesystemView);
established_resource!(CheckedAttachmentResourceV1, Attachment);
established_resource!(CheckedSnapshotResourceV1, Snapshot);
established_resource!(CheckedCapabilityResourceV1, Capability);
established_resource!(CheckedNodeCapabilitiesV1, NodeCapabilities);

/// Stores one semantically checked execution-control result.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedExecutionControlResultV1(ExecutionControlResult);

impl TryFrom<ExecutionControlResult> for CheckedExecutionControlResultV1 {
    type Error = InvalidProtoJson;

    fn try_from(value: ExecutionControlResult) -> Result<Self, Self::Error> {
        let operation = value
            .operation
            .as_option()
            .ok_or(InvalidProtoJson::InvalidResource)?;
        CheckedOperationResourceV1::try_from(operation.clone())
            .map_err(|_| InvalidProtoJson::InvalidResource)?;
        if value.execution_id.len() != 16
            || value.execution_id.iter().all(|byte| *byte == 0)
            || !(1..=3).contains(&value.action.to_i32())
            || value.compute_size(&mut buffa::SizeCache::new()) as usize > MAXIMUM_PROTO_JSON_BYTES
        {
            Err(InvalidProtoJson::InvalidResource)
        } else {
            Ok(Self(value))
        }
    }
}

impl sealed::Sealed for CheckedExecutionControlResultV1 {}

impl EstablishedProtoJson for CheckedExecutionControlResultV1 {
    fn output_schema(&self) -> StructuredOutputSchemaV1 {
        StructuredOutputSchemaV1::Operation
    }

    fn render_established(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.0.operation.as_option())
    }
}

impl CheckedExecutionControlResultV1 {
    /// Returns the checked established execution-control result.
    #[must_use]
    pub const fn as_proto(&self) -> &ExecutionControlResult {
        &self.0
    }
}

/// Stores one closed action-specific operator-recovery result.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedOperatorRecoveryResultV1(OperatorRecoveryResult);

impl TryFrom<OperatorRecoveryResult> for CheckedOperatorRecoveryResultV1 {
    type Error = InvalidProtoJson;

    fn try_from(value: OperatorRecoveryResult) -> Result<Self, Self::Error> {
        if value.resource_id.len() != 16
            || value.resource_id.iter().all(|byte| *byte == 0)
            || value.resource_version.len() != 32
            || value.resource_version.iter().all(|byte| *byte == 0)
            || !(1..=4).contains(&value.action.to_i32())
            || value.conditions.len() != 1
            || value.compute_size(&mut buffa::SizeCache::new()) as usize > MAXIMUM_PROTO_JSON_BYTES
        {
            return Err(InvalidProtoJson::InvalidResource);
        }
        crate::controller_query::resource::checked_conditions(&value.conditions)
            .map_err(|_| InvalidProtoJson::InvalidResource)?;
        let condition = &value.conditions[0];
        if condition.freshness.to_i32() != 1
            || condition.desired_generation == 0
            || condition.observation_sequence == 0
            || !condition.unsatisfied_features.is_empty()
        {
            return Err(InvalidProtoJson::InvalidResource);
        }
        Ok(Self(value))
    }
}

impl sealed::Sealed for CheckedOperatorRecoveryResultV1 {}

impl EstablishedProtoJson for CheckedOperatorRecoveryResultV1 {
    fn output_schema(&self) -> StructuredOutputSchemaV1 {
        StructuredOutputSchemaV1::OperatorRecoveryResult
    }

    fn render_established(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.0)
    }
}

impl CheckedOperatorRecoveryResultV1 {
    /// Returns the checked established operator-recovery result.
    #[must_use]
    pub const fn as_proto(&self) -> &OperatorRecoveryResult {
        &self.0
    }
}

/// Stores a bounded preorder descendant response without discarding node depth.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedSandboxTreeV1 {
    response: ListDescendantsResponse,
    continuation: Option<DormantSandboxTreeContinuationV1>,
}

impl CheckedSandboxTreeV1 {
    /// Checks one descendant page against the exact request that produced it.
    ///
    /// The returned public response replaces a nonterminal server token with a
    /// self-contained CLI continuation carrying the exact authenticated
    /// server-token/preorder-state pair.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidProtoJson::InvalidResource`] when the request is
    /// malformed or the response exceeds its root, depth, page-size, or
    /// expected-preorder binding.
    pub fn from_response(
        request: &ListDescendantsRequest,
        mut value: ListDescendantsResponse,
    ) -> Result<Self, InvalidProtoJson> {
        let root: [u8; 16] = request
            .sandbox_id
            .as_slice()
            .try_into()
            .map_err(|_| InvalidProtoJson::InvalidResource)?;
        if root == [0; 16]
            || !(1..=1_024).contains(&request.maximum_depth)
            || !(1..=1_024).contains(&request.page_size)
            || request.page_token.len() > MAXIMUM_OPAQUE_RESPONSE_BYTES
        {
            return Err(InvalidProtoJson::InvalidResource);
        }

        if !value.descendants.is_empty()
            || value.nodes.len() > MAXIMUM_PROTO_JSON_LIST_ITEMS
            || value.nodes.len() > request.page_size as usize
            || value.compute_size(&mut buffa::SizeCache::new()) as usize > MAXIMUM_PROTO_JSON_BYTES
        {
            return Err(InvalidProtoJson::InvalidResource);
        }
        validate_page(
            value
                .page
                .as_option()
                .ok_or(InvalidProtoJson::InvalidResource)?,
        )?;
        let before = checked_tree_preorder_state(
            value
                .preorder_before
                .as_option()
                .ok_or(InvalidProtoJson::InvalidResource)?,
        )?;
        let after = checked_tree_preorder_state(
            value
                .preorder_after
                .as_option()
                .ok_or(InvalidProtoJson::InvalidResource)?,
        )?;
        let expected_before = if request.page_token.is_empty() {
            if request.expected_preorder_before.as_option().is_some() {
                return Err(InvalidProtoJson::InvalidResource);
            }
            CheckedTreePreorderStateV1 {
                open_path: vec![root],
                emitted_nodes: 0,
                prefix_digest: sandbox_tree_preorder_seed_v1(root),
            }
        } else {
            checked_tree_preorder_state(
                request
                    .expected_preorder_before
                    .as_option()
                    .ok_or(InvalidProtoJson::InvalidResource)?,
            )?
        };
        if before != expected_before
            || before.open_path[0] != root
            || before.open_path[0] != after.open_path[0]
            || before.open_path.len() > request.maximum_depth as usize + 1
            || after.open_path.len() > request.maximum_depth as usize + 1
            || (value.nodes.is_empty()
                && (!value
                    .page
                    .as_option()
                    .is_some_and(|page| page.next_page_token.is_empty())
                    || before != after))
        {
            return Err(InvalidProtoJson::InvalidResource);
        }

        let mut open_path = before.open_path.clone();
        let mut prefix_digest = before.prefix_digest;
        let mut page_identities = Vec::with_capacity(value.nodes.len());
        for node in &value.nodes {
            let sandbox = node
                .sandbox
                .as_option()
                .ok_or(InvalidProtoJson::InvalidResource)?;
            let checked = CheckedSandboxResourceV1::try_from(sandbox.clone())?;
            let parent: [u8; 16] = node
                .parent_sandbox_id
                .as_slice()
                .try_into()
                .map_err(|_| InvalidProtoJson::InvalidResource)?;
            let sandbox_id = checked.sandbox_id();
            let depth =
                usize::try_from(node.depth).map_err(|_| InvalidProtoJson::InvalidResource)?;
            if !(1..=1_024).contains(&node.depth)
                || node.depth > request.maximum_depth
                || depth > open_path.len()
                || parent == [0; 16]
                || parent == sandbox_id
                || open_path.get(depth - 1) != Some(&parent)
                || open_path.contains(&sandbox_id)
                || page_identities.contains(&sandbox_id)
            {
                return Err(InvalidProtoJson::InvalidResource);
            }
            open_path.truncate(depth);
            open_path.push(sandbox_id);
            prefix_digest =
                sandbox_tree_preorder_advance_v1(prefix_digest, node.depth, parent, sandbox_id);
            page_identities.push(sandbox_id);
        }
        let emitted = before
            .emitted_nodes
            .checked_add(value.nodes.len() as u64)
            .ok_or(InvalidProtoJson::InvalidResource)?;
        if after.open_path != open_path
            || after.emitted_nodes != emitted
            || after.prefix_digest != prefix_digest
        {
            return Err(InvalidProtoJson::InvalidResource);
        }

        let server_page_token = value
            .page
            .as_option()
            .ok_or(InvalidProtoJson::InvalidResource)?
            .next_page_token
            .clone();
        let continuation = if server_page_token.is_empty() {
            None
        } else {
            Some(DormantSandboxTreeContinuationV1::new_checked(
                root,
                request.maximum_depth,
                request.page_size,
                server_page_token,
                value
                    .preorder_after
                    .as_option()
                    .ok_or(InvalidProtoJson::InvalidResource)?
                    .clone(),
            )?)
        };
        if let Some(continuation) = &continuation {
            value
                .page
                .as_option_mut()
                .ok_or(InvalidProtoJson::InvalidResource)?
                .next_page_token = continuation.encode_cli_token();
        }
        if value.compute_size(&mut buffa::SizeCache::new()) as usize > MAXIMUM_PROTO_JSON_BYTES {
            return Err(InvalidProtoJson::InvalidResource);
        }
        Ok(Self {
            response: value,
            continuation,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CheckedTreePreorderStateV1 {
    open_path: Vec<[u8; 16]>,
    emitted_nodes: u64,
    prefix_digest: [u8; 32],
}

const SANDBOX_TREE_CONTINUATION_MAGIC_V1: &[u8; 8] = b"AOSTPC01";
const SANDBOX_TREE_CONTINUATION_HEADER_BYTES_V1: usize = 40;
const SANDBOX_TREE_CONTINUATION_DIGEST_BYTES_V1: usize = 32;
const MAXIMUM_SANDBOX_TREE_CONTINUATION_BYTES_V1: usize = 128 * 1024;

/// Carries a server-issued page token with its exact preorder request state.
#[derive(Clone, Debug, PartialEq)]
pub struct DormantSandboxTreeContinuationV1 {
    root: [u8; 16],
    maximum_depth: u32,
    page_size: u32,
    server_page_token: Vec<u8>,
    preorder_before: SandboxTreePreorderState,
}

impl DormantSandboxTreeContinuationV1 {
    fn new_checked(
        root: [u8; 16],
        maximum_depth: u32,
        page_size: u32,
        server_page_token: Vec<u8>,
        preorder_before: SandboxTreePreorderState,
    ) -> Result<Self, InvalidProtoJson> {
        let checked = checked_tree_preorder_state(&preorder_before)?;
        if root == [0; 16]
            || !(1..=1_024).contains(&maximum_depth)
            || !(1..=1_024).contains(&page_size)
            || server_page_token.is_empty()
            || server_page_token.len() > MAXIMUM_OPAQUE_RESPONSE_BYTES
            || checked.open_path[0] != root
            || checked.open_path.len() > maximum_depth as usize + 1
            || checked.emitted_nodes == 0
        {
            return Err(InvalidProtoJson::InvalidResource);
        }
        Ok(Self {
            root,
            maximum_depth,
            page_size,
            server_page_token,
            preorder_before,
        })
    }

    /// Decodes a CLI token for one exact traversal request.
    ///
    /// The opaque server token authenticates the continuation at the server;
    /// the local frame commitment prevents accidentally mixing it with another
    /// root, depth, page size, or preorder state.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidProtoJson::InvalidResource`] for a malformed,
    /// noncanonical, oversized, or differently bound continuation.
    pub fn decode_cli_token(
        encoded: &[u8],
        expected_root: [u8; 16],
        expected_maximum_depth: u32,
        expected_page_size: u32,
    ) -> Result<Self, InvalidProtoJson> {
        if encoded.len()
            < SANDBOX_TREE_CONTINUATION_HEADER_BYTES_V1 + SANDBOX_TREE_CONTINUATION_DIGEST_BYTES_V1
            || encoded.len() > MAXIMUM_SANDBOX_TREE_CONTINUATION_BYTES_V1
            || encoded.get(..8) != Some(SANDBOX_TREE_CONTINUATION_MAGIC_V1.as_slice())
        {
            return Err(InvalidProtoJson::InvalidResource);
        }
        let root: [u8; 16] = encoded[8..24]
            .try_into()
            .map_err(|_| InvalidProtoJson::InvalidResource)?;
        let maximum_depth = u32::from_be_bytes(
            encoded[24..28]
                .try_into()
                .map_err(|_| InvalidProtoJson::InvalidResource)?,
        );
        let page_size = u32::from_be_bytes(
            encoded[28..32]
                .try_into()
                .map_err(|_| InvalidProtoJson::InvalidResource)?,
        );
        let token_length = u32::from_be_bytes(
            encoded[32..36]
                .try_into()
                .map_err(|_| InvalidProtoJson::InvalidResource)?,
        ) as usize;
        let state_length = u32::from_be_bytes(
            encoded[36..40]
                .try_into()
                .map_err(|_| InvalidProtoJson::InvalidResource)?,
        ) as usize;
        let token_end = SANDBOX_TREE_CONTINUATION_HEADER_BYTES_V1
            .checked_add(token_length)
            .ok_or(InvalidProtoJson::InvalidResource)?;
        let state_end = token_end
            .checked_add(state_length)
            .ok_or(InvalidProtoJson::InvalidResource)?;
        let frame_end = state_end
            .checked_add(SANDBOX_TREE_CONTINUATION_DIGEST_BYTES_V1)
            .ok_or(InvalidProtoJson::InvalidResource)?;
        if frame_end != encoded.len()
            || root != expected_root
            || maximum_depth != expected_maximum_depth
            || page_size != expected_page_size
        {
            return Err(InvalidProtoJson::InvalidResource);
        }
        let expected_digest: [u8; 32] = Sha256::new()
            .chain_update(b"aos.sandbox.tree-cli-continuation.v1\0")
            .chain_update(&encoded[..state_end])
            .finalize()
            .into();
        if encoded[state_end..] != expected_digest {
            return Err(InvalidProtoJson::InvalidResource);
        }
        let preorder_before =
            SandboxTreePreorderState::decode_from_slice(&encoded[token_end..state_end])
                .map_err(|_| InvalidProtoJson::InvalidResource)?;
        if preorder_before.encode_to_vec() != encoded[token_end..state_end] {
            return Err(InvalidProtoJson::InvalidResource);
        }
        Self::new_checked(
            root,
            maximum_depth,
            page_size,
            encoded[SANDBOX_TREE_CONTINUATION_HEADER_BYTES_V1..token_end].to_vec(),
            preorder_before,
        )
    }

    /// Encodes the exact server-token/preorder-state pair for CLI display.
    #[must_use]
    pub fn encode_cli_token(&self) -> Vec<u8> {
        let state = self.preorder_before.encode_to_vec();
        let mut encoded = Vec::with_capacity(
            SANDBOX_TREE_CONTINUATION_HEADER_BYTES_V1
                + self.server_page_token.len()
                + state.len()
                + SANDBOX_TREE_CONTINUATION_DIGEST_BYTES_V1,
        );
        encoded.extend_from_slice(SANDBOX_TREE_CONTINUATION_MAGIC_V1);
        encoded.extend_from_slice(&self.root);
        encoded.extend_from_slice(&self.maximum_depth.to_be_bytes());
        encoded.extend_from_slice(&self.page_size.to_be_bytes());
        encoded.extend_from_slice(&(self.server_page_token.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&(state.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&self.server_page_token);
        encoded.extend_from_slice(&state);
        let digest: [u8; 32] = Sha256::new()
            .chain_update(b"aos.sandbox.tree-cli-continuation.v1\0")
            .chain_update(&encoded)
            .finalize()
            .into();
        encoded.extend_from_slice(&digest);
        encoded
    }

    /// Returns the opaque server-issued token for the next request.
    #[must_use]
    pub fn server_page_token(&self) -> &[u8] {
        &self.server_page_token
    }

    /// Returns the exact preorder state authenticated with the server token.
    #[must_use]
    pub const fn preorder_before(&self) -> &SandboxTreePreorderState {
        &self.preorder_before
    }
}

/// Validates one exact descendant-pagination preorder continuation state.
///
/// # Errors
///
/// Returns [`InvalidProtoJson::InvalidResource`] for an invalid root/path,
/// duplicate identity, malformed prefix commitment, or invalid initial seed.
pub fn validate_sandbox_tree_preorder_state_v1(
    value: &SandboxTreePreorderState,
) -> Result<(), InvalidProtoJson> {
    checked_tree_preorder_state(value).map(|_| ())
}

fn checked_tree_preorder_state(
    value: &SandboxTreePreorderState,
) -> Result<CheckedTreePreorderStateV1, InvalidProtoJson> {
    if value.open_path.is_empty()
        || value.open_path.len() > 1_025
        || value.prefix_digest.len() != 32
        || value.prefix_digest.iter().all(|byte| *byte == 0)
    {
        return Err(InvalidProtoJson::InvalidResource);
    }
    let mut open_path = Vec::with_capacity(value.open_path.len());
    for identity in &value.open_path {
        let identity: [u8; 16] = identity
            .as_slice()
            .try_into()
            .map_err(|_| InvalidProtoJson::InvalidResource)?;
        if identity == [0; 16] || open_path.contains(&identity) {
            return Err(InvalidProtoJson::InvalidResource);
        }
        open_path.push(identity);
    }
    let prefix_digest: [u8; 32] = value
        .prefix_digest
        .as_slice()
        .try_into()
        .map_err(|_| InvalidProtoJson::InvalidResource)?;
    if (value.emitted_nodes == 0
        && (open_path.len() != 1 || prefix_digest != sandbox_tree_preorder_seed_v1(open_path[0])))
        || (value.emitted_nodes > 0 && open_path.len() == 1)
    {
        return Err(InvalidProtoJson::InvalidResource);
    }
    Ok(CheckedTreePreorderStateV1 {
        open_path,
        emitted_nodes: value.emitted_nodes,
        prefix_digest,
    })
}

/// Returns the initial prefix commitment for an empty descendant traversal.
#[must_use]
pub fn sandbox_tree_preorder_seed_v1(root: [u8; 16]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"aos.sandbox.tree-preorder-prefix.v1\0")
        .chain_update(root)
        .finalize()
        .into()
}

/// Advances a descendant preorder commitment by one exact tree edge.
#[must_use]
pub fn sandbox_tree_preorder_advance_v1(
    previous: [u8; 32],
    depth: u32,
    parent: [u8; 16],
    sandbox: [u8; 16],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"aos.sandbox.tree-preorder-node.v1\0")
        .chain_update(previous)
        .chain_update(depth.to_be_bytes())
        .chain_update(parent)
        .chain_update(sandbox)
        .finalize()
        .into()
}

impl sealed::Sealed for CheckedSandboxTreeV1 {}

impl EstablishedProtoJson for CheckedSandboxTreeV1 {
    fn output_schema(&self) -> StructuredOutputSchemaV1 {
        StructuredOutputSchemaV1::SandboxTree
    }

    fn render_established(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.response)
    }
}

impl CheckedSandboxTreeV1 {
    /// Returns the checked established sandbox-tree message.
    #[must_use]
    pub const fn as_proto(&self) -> &ListDescendantsResponse {
        &self.response
    }

    /// Returns the opaque next-page token and exact preorder state to carry with it.
    #[must_use]
    pub const fn continuation(&self) -> Option<&DormantSandboxTreeContinuationV1> {
        self.continuation.as_ref()
    }
}

/// Stores one checked public cache-status projection.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedCacheStatusV1(CacheStatus);

impl TryFrom<CacheStatus> for CheckedCacheStatusV1 {
    type Error = InvalidProtoJson;

    fn try_from(value: CacheStatus) -> Result<Self, Self::Error> {
        if value.domain_id.len() != 16
            || value.domain_id.iter().all(|byte| *byte == 0)
            || value.pinned_bytes > value.admitted_bytes
            || (value.pinned_objects == 0 && value.pinned_bytes != 0)
        {
            Err(InvalidProtoJson::InvalidResource)
        } else {
            Ok(Self(value))
        }
    }
}

impl sealed::Sealed for CheckedCacheStatusV1 {}

impl EstablishedProtoJson for CheckedCacheStatusV1 {
    fn output_schema(&self) -> StructuredOutputSchemaV1 {
        StructuredOutputSchemaV1::CacheStatus
    }

    fn render_established(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.0)
    }
}

impl CheckedCacheStatusV1 {
    /// Returns the checked established cache-status message.
    #[must_use]
    pub const fn as_proto(&self) -> &CacheStatus {
        &self.0
    }
}

/// Stores one canonical public feature registry.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedPublicFeatureRegistryV1(PublicFeatureRegistry);

impl TryFrom<PublicFeatureRegistry> for CheckedPublicFeatureRegistryV1 {
    type Error = InvalidProtoJson;

    fn try_from(value: PublicFeatureRegistry) -> Result<Self, Self::Error> {
        // Base v1 is a closed, complete registry. Accepting a validly digested
        // subset would let a responder silently hide required semantics.
        if value.features.len() != crate::controller_query::BASE_V1_FEATURE_REGISTRY_ENTRIES
            || value != crate::controller_query::public_feature_registry_v1()
        {
            return Err(InvalidProtoJson::InvalidResource);
        }
        Ok(Self(value))
    }
}

impl sealed::Sealed for CheckedPublicFeatureRegistryV1 {}

impl EstablishedProtoJson for CheckedPublicFeatureRegistryV1 {
    fn output_schema(&self) -> StructuredOutputSchemaV1 {
        StructuredOutputSchemaV1::PublicFeatureRegistry
    }

    fn render_established(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.0)
    }
}

impl CheckedPublicFeatureRegistryV1 {
    /// Returns the checked established feature-registry message.
    #[must_use]
    pub const fn as_proto(&self) -> &PublicFeatureRegistry {
        &self.0
    }
}

/// Stores one policy plan after closed reason-registry validation.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedPolicyPlanV1(PolicyPlan);

impl TryFrom<PolicyPlan> for CheckedPolicyPlanV1 {
    type Error = InvalidProtoJson;

    fn try_from(value: PolicyPlan) -> Result<Self, Self::Error> {
        if value.compute_size(&mut buffa::SizeCache::new()) as usize > MAXIMUM_PROTO_JSON_BYTES
            || value.plan_digest.len() != 32
            || value.plan_digest.iter().all(|byte| *byte == 0)
            || value.reasons.len() > crate::controller_query::MAXIMUM_RESOURCE_CONDITIONS
        {
            return Err(InvalidProtoJson::InvalidResource);
        }
        for descriptor in value
            .requested_policy
            .as_option()
            .into_iter()
            .chain(value.effective_policy.as_option())
            .chain(value.input_commitments.iter())
        {
            crate::controller_query::portable::CheckedObjectDescriptorV1::try_from(
                descriptor.clone(),
            )
            .map_err(|_| InvalidProtoJson::InvalidResource)?;
        }
        if value.requested_policy.as_option().is_none()
            || value.effective_policy.as_option().is_none()
            || crate::controller_query::portable::CheckedFeatureSetV1::try_from(
                value.required_features.clone(),
            )
            .is_err()
        {
            return Err(InvalidProtoJson::InvalidResource);
        }
        for reason in &value.reasons {
            let code = crate::controller_query::PublicPolicyReasonCodeV1::from_proto(
                reason.reason_code.to_i32(),
            )
            .map_err(|_| InvalidProtoJson::InvalidResource)?;
            if reason.code != code.stable_code()
                || reason.safe_message.is_empty()
                || reason.safe_message.len() > crate::controller_query::MAXIMUM_SAFE_MESSAGE_BYTES
                || reason.safe_message.chars().any(char::is_control)
            {
                return Err(InvalidProtoJson::InvalidResource);
            }
            let source = reason
                .source
                .as_option()
                .ok_or(InvalidProtoJson::InvalidResource)?
                .clone();
            crate::controller_query::portable::CheckedObjectDescriptorV1::try_from(source)
                .map_err(|_| InvalidProtoJson::InvalidResource)?;
        }
        if !value.reasons.windows(2).all(|pair| {
            (pair[0].reason_code.to_i32(), pair[0].code.as_str())
                < (pair[1].reason_code.to_i32(), pair[1].code.as_str())
        }) {
            return Err(InvalidProtoJson::InvalidResource);
        }
        Ok(Self(value))
    }
}

impl sealed::Sealed for CheckedPolicyPlanV1 {}

impl EstablishedProtoJson for CheckedPolicyPlanV1 {
    fn output_schema(&self) -> StructuredOutputSchemaV1 {
        StructuredOutputSchemaV1::PolicyPlan
    }

    fn render_established(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.0)
    }
}

impl CheckedPolicyPlanV1 {
    /// Returns the checked established policy-plan message.
    #[must_use]
    pub const fn as_proto(&self) -> &PolicyPlan {
        &self.0
    }
}

impl sealed::Sealed for CheckedWatchEventV1 {}

impl EstablishedProtoJson for CheckedWatchEventV1 {
    fn output_schema(&self) -> StructuredOutputSchemaV1 {
        StructuredOutputSchemaV1::Event
    }

    fn render_established(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self.as_proto())
    }
}

/// Reports failed, oversized, or structurally invalid established ProtoJSON.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidProtoJson {
    /// An established generated message failed deep public validation.
    #[error("established ProtoJSON source is not a valid public resource")]
    InvalidResource,
    /// Established serialization failed.
    #[error("established ProtoJSON serialization failed")]
    Serialization,
    /// The rendered document is empty or exceeds its byte ceiling.
    #[error("established ProtoJSON exceeds its output bound")]
    Size,
}

impl From<InvalidPublicResource> for InvalidProtoJson {
    fn from(_: InvalidPublicResource) -> Self {
        Self::InvalidResource
    }
}

/// Stores one compact document rendered from a checked established message.
#[derive(Clone, Eq, PartialEq)]
pub struct CheckedProtoJsonV1 {
    schema: StructuredOutputSchemaV1,
    rendered: String,
}

impl CheckedProtoJsonV1 {
    /// Serializes a closed-registry checked projection using its established mapping.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidProtoJson`] for serialization failure or size overflow.
    pub fn render<T: EstablishedProtoJson>(message: &T) -> Result<Self, InvalidProtoJson> {
        let rendered = message
            .render_established()
            .map_err(|_| InvalidProtoJson::Serialization)?;
        if rendered.is_empty() || rendered.len() > MAXIMUM_PROTO_JSON_BYTES {
            Err(InvalidProtoJson::Size)
        } else {
            Ok(Self {
                schema: message.output_schema(),
                rendered,
            })
        }
    }

    /// Returns the checked established schema carried by this document.
    #[must_use]
    pub const fn schema(&self) -> StructuredOutputSchemaV1 {
        self.schema
    }

    /// Returns the compact established ProtoJSON document.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.rendered
    }
}

impl fmt::Debug for CheckedProtoJsonV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CheckedProtoJsonV1")
            .field("schema", &self.schema)
            .field("redacted_bytes", &self.rendered.len())
            .finish_non_exhaustive()
    }
}

/// Stores one deeply checked established list or tree response.
#[derive(Clone, PartialEq)]
pub struct CheckedListProtoJsonV1 {
    schema: StructuredOutputSchemaV1,
    wire: CheckedListWireV1,
}

#[derive(Clone, PartialEq)]
enum CheckedListWireV1 {
    Sandboxes(ListSandboxesResponse),
    Children(ListChildrenResponse),
    Ancestors(ListAncestorsResponse),
    Executions(ListExecutionsResponse),
    Views(ListViewsResponse),
    Snapshots(ListSnapshotsResponse),
}

impl fmt::Debug for CheckedListProtoJsonV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CheckedListProtoJsonV1")
            .field("schema", &self.schema)
            .finish_non_exhaustive()
    }
}

macro_rules! checked_list_conversion {
    ($message:ty, $field:ident, $variant:ident, $wrapper:ty, $schema:expr) => {
        impl TryFrom<$message> for CheckedListProtoJsonV1 {
            type Error = InvalidProtoJson;

            fn try_from(value: $message) -> Result<Self, Self::Error> {
                if value.$field.len() > MAXIMUM_PROTO_JSON_LIST_ITEMS
                    || value.compute_size(&mut buffa::SizeCache::new()) as usize
                        > MAXIMUM_PROTO_JSON_BYTES
                {
                    return Err(InvalidProtoJson::InvalidResource);
                }
                let page = value
                    .page
                    .as_option()
                    .ok_or(InvalidProtoJson::InvalidResource)?;
                validate_page(page)?;
                if value.$field.is_empty() && !page.next_page_token.is_empty() {
                    return Err(InvalidProtoJson::InvalidResource);
                }
                for resource in &value.$field {
                    <$wrapper>::try_from(resource.clone())?;
                }
                Ok(Self {
                    schema: $schema,
                    wire: CheckedListWireV1::$variant(value),
                })
            }
        }
    };
}

checked_list_conversion!(
    ListSandboxesResponse,
    sandboxes,
    Sandboxes,
    CheckedSandboxResourceV1,
    StructuredOutputSchemaV1::SandboxList
);
checked_list_conversion!(
    ListChildrenResponse,
    children,
    Children,
    CheckedSandboxResourceV1,
    StructuredOutputSchemaV1::ChildrenList
);
checked_list_conversion!(
    ListAncestorsResponse,
    ancestors,
    Ancestors,
    CheckedSandboxResourceV1,
    StructuredOutputSchemaV1::AncestorsList
);
impl TryFrom<ListExecutionsResponse> for CheckedListProtoJsonV1 {
    type Error = InvalidProtoJson;

    fn try_from(mut value: ListExecutionsResponse) -> Result<Self, Self::Error> {
        if value.executions.len() > MAXIMUM_PROTO_JSON_LIST_ITEMS
            || value.compute_size(&mut buffa::SizeCache::new()) as usize > MAXIMUM_PROTO_JSON_BYTES
        {
            return Err(InvalidProtoJson::InvalidResource);
        }
        let page = value
            .page
            .as_option()
            .ok_or(InvalidProtoJson::InvalidResource)?;
        validate_page(page)?;
        if value.executions.is_empty() && !page.next_page_token.is_empty() {
            return Err(InvalidProtoJson::InvalidResource);
        }
        let checked = value
            .executions
            .drain(..)
            .map(CheckedExecutionResourceV1::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        value.executions = checked
            .into_iter()
            .map(CheckedExecutionResourceV1::into_proto)
            .collect();
        Ok(Self {
            schema: StructuredOutputSchemaV1::ExecutionList,
            wire: CheckedListWireV1::Executions(value),
        })
    }
}
checked_list_conversion!(
    ListViewsResponse,
    views,
    Views,
    CheckedFilesystemViewResourceV1,
    StructuredOutputSchemaV1::ViewList
);
checked_list_conversion!(
    ListSnapshotsResponse,
    snapshots,
    Snapshots,
    CheckedSnapshotResourceV1,
    StructuredOutputSchemaV1::SnapshotList
);

impl sealed::Sealed for CheckedListProtoJsonV1 {}

impl EstablishedProtoJson for CheckedListProtoJsonV1 {
    fn output_schema(&self) -> StructuredOutputSchemaV1 {
        self.schema
    }

    fn render_established(&self) -> Result<String, serde_json::Error> {
        match &self.wire {
            CheckedListWireV1::Sandboxes(value) => serde_json::to_string(value),
            CheckedListWireV1::Children(value) => serde_json::to_string(value),
            CheckedListWireV1::Ancestors(value) => serde_json::to_string(value),
            CheckedListWireV1::Executions(value) => serde_json::to_string(value),
            CheckedListWireV1::Views(value) => serde_json::to_string(value),
            CheckedListWireV1::Snapshots(value) => serde_json::to_string(value),
        }
    }
}

fn validate_page(value: &PageInfo) -> Result<(), InvalidProtoJson> {
    let revision_is_valid = !value.immutable_list_revision.is_empty()
        && value.immutable_list_revision.len() <= MAXIMUM_OPAQUE_RESPONSE_BYTES;
    let token_is_valid = value.next_page_token.len() <= MAXIMUM_OPAQUE_RESPONSE_BYTES;
    if revision_is_valid && token_is_valid {
        Ok(())
    } else {
        Err(InvalidProtoJson::InvalidResource)
    }
}
