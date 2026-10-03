//! Authorized sandbox adjacency and ancestor queries.

use std::collections::BTreeMap;

use aos_proto::aos::sandbox::v1::{
    ListAncestorsRequest, ListAncestorsResponse, ListChildrenRequest, ListChildrenResponse,
    ListDescendantsRequest, ListDescendantsResponse, SandboxTreeNode, SandboxTreePreorderState,
};
use aos_sandbox::cli_model::{
    PublicApiAuditMethodV1, sandbox_tree_preorder_advance_v1, sandbox_tree_preorder_seed_v1,
};
use aos_sandbox::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionQueryV1, PublicProjectionRecordV1,
    PublicProjectionResourceV1,
};
use aos_sandbox_core::{Operation, ResourceKind};
use connectrpc::{ConnectError, RequestContext, ServiceRequest, ServiceResult};

use super::CapabilityService;
use super::public_services::{
    exact_resource_id, list_query_binding, page_info, paginate, projection_mismatch, query_scope,
    resource_selector, response_with_query_binding,
};

const MAXIMUM_HIERARCHY_DEPTH: u32 = 1_024;

impl CapabilityService {
    pub(super) async fn list_children_response(
        &self,
        context: &RequestContext,
        request: ServiceRequest<'_, ListChildrenRequest>,
    ) -> ServiceResult<ListChildrenResponse> {
        let view = request.view();
        let parent_id = exact_resource_id(view.parent_sandbox_id, "parent sandbox")?;
        let read = self
            .read_public_projection(
                context,
                PublicApiAuditMethodV1::ListChildren,
                ResourceKind::Sandbox,
                Operation::MetadataRead,
                resource_selector(parent_id),
                request.bytes(),
                PublicProjectionQueryV1::Related {
                    kind: PublicProjectionKindV1::Sandbox,
                    scope_kind: PublicProjectionKindV1::Sandbox,
                    scope_id: parent_id,
                },
            )
            .await?;
        let (authorization, mut records) = read.into_parts();
        records.retain(|record| sandbox_parent(record) == Some(parent_id));
        let binding_scope = query_scope(&parent_id, view.page_size);
        let binding = list_query_binding(
            authorization,
            b"/aos.sandbox.v1.SandboxService/ListChildren",
            &binding_scope,
            b"immediate-children-v1",
            b"sandbox-public-v1",
        );
        let page = paginate(
            PublicProjectionKindV1::Sandbox,
            &parent_id,
            binding,
            view.page_size,
            view.page_token,
            records,
        )?;
        let page_info = page_info(&page);
        let children = sandbox_resources(page.records)?;

        response_with_query_binding(
            ListChildrenResponse {
                children,
                page: Some(page_info).into(),
                ..Default::default()
            },
            binding,
        )
    }

    pub(super) async fn list_ancestors_response(
        &self,
        context: &RequestContext,
        request: ServiceRequest<'_, ListAncestorsRequest>,
    ) -> ServiceResult<ListAncestorsResponse> {
        let view = request.view();
        let sandbox_id = exact_resource_id(view.sandbox_id, "sandbox")?;
        if !(1..=MAXIMUM_HIERARCHY_DEPTH).contains(&view.bounded_depth) {
            return Err(ConnectError::new(
                connectrpc::ErrorCode::InvalidArgument,
                "ancestor depth is outside the supported range",
            ));
        }
        let read = self
            .read_public_projection(
                context,
                PublicApiAuditMethodV1::ListAncestors,
                ResourceKind::Sandbox,
                Operation::MetadataRead,
                resource_selector(sandbox_id),
                request.bytes(),
                PublicProjectionQueryV1::Related {
                    kind: PublicProjectionKindV1::Sandbox,
                    scope_kind: PublicProjectionKindV1::Sandbox,
                    scope_id: sandbox_id,
                },
            )
            .await?;
        let (authorization, records) = read.into_parts();
        let mut by_id = records
            .into_iter()
            .map(|record| {
                let identity = sandbox_id_from_record(&record)?;
                Ok((identity, record))
            })
            .collect::<Result<BTreeMap<_, _>, ConnectError>>()?;
        let root = by_id.get(&sandbox_id).ok_or_else(projection_mismatch)?;
        let mut next = sandbox_parent(root);
        let mut ancestors = Vec::new();
        for _ in 0..view.bounded_depth {
            let Some(identity) = next else {
                break;
            };
            if ancestors.iter().any(|record: &PublicProjectionRecordV1| {
                record.resource().resource_id() == identity
            }) {
                return Err(projection_mismatch());
            }
            let record = by_id.remove(&identity).ok_or_else(projection_mismatch)?;
            next = sandbox_parent(&record);
            ancestors.push(record);
        }
        let mut scope = Vec::with_capacity(20);
        scope.extend_from_slice(&sandbox_id);
        scope.extend_from_slice(&view.bounded_depth.to_be_bytes());
        let binding_scope = query_scope(&scope, view.page_size);
        let binding = list_query_binding(
            authorization,
            b"/aos.sandbox.v1.SandboxService/ListAncestors",
            &binding_scope,
            b"nearest-first-bounded-ancestors-v1",
            b"sandbox-public-v1",
        );
        let page = paginate(
            PublicProjectionKindV1::Sandbox,
            &scope,
            binding,
            view.page_size,
            view.page_token,
            ancestors,
        )?;
        let page_info = page_info(&page);
        let ancestors = sandbox_resources(page.records)?;

        response_with_query_binding(
            ListAncestorsResponse {
                ancestors,
                page: Some(page_info).into(),
                ..Default::default()
            },
            binding,
        )
    }

    pub(super) async fn list_descendants_response(
        &self,
        context: &RequestContext,
        request: ServiceRequest<'_, ListDescendantsRequest>,
    ) -> ServiceResult<ListDescendantsResponse> {
        let body = request.bytes().to_vec();
        let request = request.to_owned_message();
        let root_id = exact_resource_id(&request.sandbox_id, "sandbox")?;
        if !(1..=MAXIMUM_HIERARCHY_DEPTH).contains(&request.maximum_depth) {
            return Err(ConnectError::new(
                connectrpc::ErrorCode::InvalidArgument,
                "descendant depth is outside the supported range",
            ));
        }
        let read = self
            .read_public_projection(
                context,
                PublicApiAuditMethodV1::ListDescendants,
                ResourceKind::Sandbox,
                Operation::MetadataRead,
                resource_selector(root_id),
                &body,
                PublicProjectionQueryV1::Related {
                    kind: PublicProjectionKindV1::Sandbox,
                    scope_kind: PublicProjectionKindV1::Sandbox,
                    scope_id: root_id,
                },
            )
            .await?;
        let (authorization, records) = read.into_parts();
        let entries = descendant_preorder(root_id, request.maximum_depth, records)?;
        let mut scope = Vec::with_capacity(24);
        scope.extend_from_slice(&root_id);
        scope.extend_from_slice(&request.maximum_depth.to_be_bytes());
        scope.extend_from_slice(&request.page_size.to_be_bytes());
        let binding = list_query_binding(
            authorization,
            b"/aos.sandbox.v1.SandboxService/ListDescendants",
            &scope,
            b"bounded-preorder-descendants-v1",
            b"sandbox-tree-public-v1",
        );
        let ordered = entries.iter().map(|entry| entry.record.clone()).collect();
        let page = paginate(
            PublicProjectionKindV1::Sandbox,
            &scope,
            binding,
            request.page_size,
            &request.page_token,
            ordered,
        )?;
        let page_info = page_info(&page);
        let start = page
            .records
            .first()
            .map(|record| {
                entries
                    .iter()
                    .position(|entry| {
                        entry.record.resource().resource_id() == record.resource().resource_id()
                    })
                    .ok_or_else(projection_mismatch)
            })
            .transpose()?
            .unwrap_or(0);
        let end = start
            .checked_add(page.records.len())
            .ok_or_else(projection_mismatch)?;
        let before = preorder_state(root_id, &entries[..start])?;
        if request.page_token.is_empty() {
            if request.expected_preorder_before.as_option().is_some() {
                return Err(invalid_preorder());
            }
        } else if request.expected_preorder_before.as_option() != Some(&before) {
            return Err(invalid_preorder());
        }
        let after = preorder_state(root_id, &entries[..end])?;
        let nodes = entries[start..end]
            .iter()
            .map(|entry| {
                let PublicProjectionResourceV1::Sandbox(sandbox) = entry.record.resource().clone()
                else {
                    return Err(projection_mismatch());
                };
                Ok(SandboxTreeNode {
                    sandbox: Some(sandbox).into(),
                    depth: entry.depth,
                    parent_sandbox_id: entry.parent.to_vec(),
                    ..Default::default()
                })
            })
            .collect::<Result<Vec<_>, ConnectError>>()?;

        response_with_query_binding(
            ListDescendantsResponse {
                descendants: Vec::new(),
                page: Some(page_info).into(),
                nodes,
                preorder_before: Some(before).into(),
                preorder_after: Some(after).into(),
                ..Default::default()
            },
            binding,
        )
    }
}

#[derive(Clone)]
struct DescendantEntryV1 {
    record: PublicProjectionRecordV1,
    depth: u32,
    parent: [u8; 16],
}

fn descendant_preorder(
    root_id: [u8; 16],
    maximum_depth: u32,
    records: Vec<PublicProjectionRecordV1>,
) -> Result<Vec<DescendantEntryV1>, ConnectError> {
    if !records
        .iter()
        .any(|record| record.resource().resource_id() == root_id)
    {
        return Err(projection_mismatch());
    }
    let mut children: BTreeMap<[u8; 16], Vec<PublicProjectionRecordV1>> = BTreeMap::new();
    for record in records {
        let identity = sandbox_id_from_record(&record)?;
        if identity == root_id {
            continue;
        }
        if let Some(parent) = sandbox_parent(&record) {
            children.entry(parent).or_default().push(record);
        }
    }
    for rows in children.values_mut() {
        rows.sort_by(|left, right| {
            left.resource()
                .resource_id()
                .cmp(right.resource().resource_id())
        });
    }

    let mut stack = Vec::new();
    if let Some(rows) = children.get(&root_id) {
        for record in rows.iter().rev() {
            stack.push((record.clone(), 1_u32, root_id));
        }
    }
    let mut visited = vec![root_id];
    let mut ordered = Vec::new();
    while let Some((record, depth, parent)) = stack.pop() {
        let identity = sandbox_id_from_record(&record)?;
        if visited.contains(&identity) || depth == 0 || depth > maximum_depth {
            return Err(projection_mismatch());
        }
        visited.push(identity);
        ordered.push(DescendantEntryV1 {
            record,
            depth,
            parent,
        });
        if depth < maximum_depth
            && let Some(rows) = children.get(&identity)
        {
            for child in rows.iter().rev() {
                stack.push((child.clone(), depth + 1, identity));
            }
        }
    }

    Ok(ordered)
}

fn preorder_state(
    root_id: [u8; 16],
    entries: &[DescendantEntryV1],
) -> Result<SandboxTreePreorderState, ConnectError> {
    let mut open_path = vec![root_id];
    let mut prefix_digest = sandbox_tree_preorder_seed_v1(root_id);
    for entry in entries {
        let identity = sandbox_id_from_record(&entry.record)?;
        let depth = usize::try_from(entry.depth).map_err(|_| projection_mismatch())?;
        if depth == 0 || depth > open_path.len() || open_path[depth - 1] != entry.parent {
            return Err(projection_mismatch());
        }
        open_path.truncate(depth);
        open_path.push(identity);
        prefix_digest =
            sandbox_tree_preorder_advance_v1(prefix_digest, entry.depth, entry.parent, identity);
    }

    Ok(SandboxTreePreorderState {
        open_path: open_path
            .into_iter()
            .map(|identity| identity.to_vec())
            .collect(),
        emitted_nodes: entries.len() as u64,
        prefix_digest: prefix_digest.to_vec(),
        ..Default::default()
    })
}

fn invalid_preorder() -> ConnectError {
    ConnectError::new(
        connectrpc::ErrorCode::InvalidArgument,
        "descendant preorder continuation is invalid",
    )
}

fn sandbox_id_from_record(record: &PublicProjectionRecordV1) -> Result<[u8; 16], ConnectError> {
    record
        .resource()
        .resource_id()
        .try_into()
        .map_err(|_| projection_mismatch())
}

fn sandbox_parent(record: &PublicProjectionRecordV1) -> Option<[u8; 16]> {
    let PublicProjectionResourceV1::Sandbox(sandbox) = record.resource() else {
        return None;
    };
    if sandbox.parent_sandbox_id.is_empty() {
        None
    } else {
        sandbox.parent_sandbox_id.as_slice().try_into().ok()
    }
}

fn sandbox_resources(
    records: Vec<PublicProjectionRecordV1>,
) -> Result<Vec<aos_proto::aos::sandbox::v1::Sandbox>, ConnectError> {
    records
        .into_iter()
        .map(|record| match record.resource().clone() {
            PublicProjectionResourceV1::Sandbox(sandbox) => Ok(sandbox),
            _ => Err(projection_mismatch()),
        })
        .collect()
}
