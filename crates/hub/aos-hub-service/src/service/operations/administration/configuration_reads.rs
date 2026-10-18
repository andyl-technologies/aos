//! Configuration reads in the administration capability.

use super::*;

impl RpcService {
    /// `InstanceService.GetInstanceSettings` — the full editable instance
    /// settings bundle (branding, footer, identity policy, serving defaults).
    ///
    /// The machine mirror of the `/-/instance` console: every field carries its
    /// effective value (a stored override or the documented default). Requires
    /// [`Permission::IamAdmin`] at the instance root, the same authority the
    /// console enforces.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::PermissionDenied`] when the caller is not an instance admin,
    /// and [`RpcError::Internal`] on database failure.
    pub async fn get_instance_settings(
        &self,
        auth: Option<&str>,
        _req: pb::GetInstanceSettingsRequest,
    ) -> Result<pb::GetInstanceSettingsResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        self.require_permission(&claims, Permission::IamAdmin, &Scope::root())
            .await?;
        let settings = self
            .db
            .instance_settings()
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::GetInstanceSettingsResponse {
            resource_version: instance_settings_digest(&settings)?,
            settings: Some(instance_settings_to_pb(&settings)),
        })
    }

    /// `RegistryConfigurationService.GetChangeset` — one change-set's revisions and diffs.
    ///
    /// Loads the change-set summary plus its revisions, each rendered with the
    /// field-level diff [`crate::config::semantic_diff`] produces (the
    /// terraform-plan review view). Reads require [`Permission::AuditRead`] on
    /// the change-set's recorded scope.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::NotFound`] for an unknown `change_id`,
    /// [`RpcError::PermissionDenied`] when the caller lacks `audit.read` on the
    /// change-set's scope, and [`RpcError::Internal`] on database failure.
    pub async fn get_changeset(
        &self,
        auth: Option<&str>,
        req: pb::GetChangesetRequest,
    ) -> Result<pb::GetChangesetResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let summary = self
            .db
            .changeset(&req.change_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("changeset"))?;
        self.require_permission(
            &claims,
            Permission::AuditRead,
            &Scope::parse(&summary.scope),
        )
        .await?;
        let change_id = crate::config::ChangeId(summary.change_id.clone());
        let revisions: Vec<pb::Revision> = crate::config::review(&self.db, &change_id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|(revision, diffs)| pb::Revision {
                object_type: revision.object_type,
                object_id: revision.object_id,
                op: revision.op.as_str().to_string(),
                diffs: diffs
                    .into_iter()
                    .map(|d| pb::FieldDiff {
                        field: d.field,
                        old: d.old.unwrap_or_default(),
                        new: d.new.unwrap_or_default(),
                    })
                    .collect(),
            })
            .collect();
        Ok(pb::GetChangesetResponse {
            changeset: Some(changeset_message(summary)),
            revisions,
        })
    }

    /// `GitService.ListChangeRequests` — the registry's draft git-backed change
    /// requests.
    ///
    /// Surfaces every change-set the hub recorded as a git-backed change request
    /// (one with a draft ref and commit), with each edited file's unified diff
    /// (computed from the recorded old/new file contents) and the `apr change
    /// merge` command a maintainer runs to promote it. Listing the change
    /// requests is an admin+ surface: the caller must hold
    /// [`Permission::AuditRead`] on the registry scope.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::NotFound`] for an unknown slug,
    /// [`RpcError::PermissionDenied`] when the caller lacks `audit.read`, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_change_requests(
        &self,
        auth: Option<&str>,
        req: pb::ListChangeRequestsRequest,
    ) -> Result<pb::ListChangeRequestsResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let registry = self.registry_or_not_found(&req.slug).await?;
        let scope = self.registry_scope(&registry).await?;
        self.require_permission(&claims, Permission::AuditRead, &scope)
            .await?;

        let upload_url = format!(
            "{}/{}",
            self.external_url.trim_end_matches('/'),
            registry.slug
        );
        let changesets = self
            .db
            .list_changesets(scope.as_str())
            .await
            .map_err(RpcError::internal)?;
        let mut change_requests = Vec::new();
        for cs in changesets.into_iter().filter(|cs| cs.git_ref.is_some()) {
            let file_diffs = self
                .db
                .list_revisions(&cs.change_id)
                .await
                .unwrap_or_default()
                .into_iter()
                .filter(|r| r.object_type == "registry_file")
                .map(|r| pb::FileDiff {
                    diff: crate::git::unified_diff(
                        &r.object_id,
                        r.old_json.as_deref().unwrap_or_default(),
                        r.new_json.as_deref().unwrap_or_default(),
                    ),
                    path: r.object_id,
                })
                .collect();
            change_requests.push(pb::ChangeRequest {
                merge_command: crate::git::merge_command(
                    &upload_url,
                    &crate::config::ChangeId(cs.change_id.clone()),
                ),
                change_id: cs.change_id,
                git_ref: cs.git_ref.unwrap_or_default(),
                git_commit: cs.git_commit.unwrap_or_default(),
                status: cs.status,
                summary: cs.summary.unwrap_or_default(),
                actor_label: cs.actor_label,
                created_at: cs.created_at,
                file_diffs,
            });
        }
        let (change_requests, next_page_token) =
            paginate(change_requests, req.page_size, &req.page_token)?;
        Ok(pb::ListChangeRequestsResponse {
            change_requests,
            next_page_token,
        })
    }
}
