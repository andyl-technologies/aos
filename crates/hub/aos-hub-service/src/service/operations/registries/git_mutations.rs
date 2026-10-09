//! Git mutations in the registries capability.

use super::*;

impl RpcService {
    /// `GitService.GitLog` — the committed commit log of a registry's tracked
    /// branch.
    ///
    /// Walks the verified HEAD commit's first-parent history through the
    /// committed git surface, newest first. Reads follow registry visibility:
    /// the caller must hold [`Permission::Read`] on the registry scope (a
    /// `public` registry's read is anonymous; see the access matrix). Each
    /// entry carries the `AOS-Change-Id` trailer when the commit was authored or
    /// promoted through the hub.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::NotFound`] for an unknown slug,
    /// [`RpcError::PermissionDenied`] when the caller cannot read the registry,
    /// [`RpcError::InvalidArgument`] for a malformed `page_token`, and
    /// [`RpcError::Internal`] on database or surface-read failure. A registry
    /// without an indexed HEAD returns an empty log.
    pub async fn git_log(
        &self,
        auth: Option<&str>,
        req: pb::GitLogRequest,
    ) -> Result<pb::GitLogResponse, RpcError> {
        let registry = self.registry_or_not_found(&req.slug).await?;
        self.require_read(auth, &registry).await?;
        // Validate the opaque cursor even when the registry has no HEAD. An
        // empty collection must obey the same pagination contract as a
        // populated one.
        let _ = paginate::<()>(Vec::new(), req.page_size, &req.page_token)?;
        let Some(head) = self
            .db
            .index_status(registry.id)
            .await
            .map_err(RpcError::internal)?
            .and_then(|status| status.last_indexed_commit)
        else {
            return Ok(pb::GitLogResponse {
                commits: Vec::new(),
                next_page_token: String::new(),
            });
        };
        let head = Oid::from_hex(&head).map_err(|error| RpcError::invalid(format!("{error:#}")))?;
        let fetch = crate::placement_read::TopologySurfaceFetch::for_verified_git_objects(
            Arc::clone(&self.db),
            Arc::clone(&self.surface),
            SurfaceTarget::Registry(registry.id),
        );
        let log = crate::git::commit_log(&fetch, head, crate::git::GIT_LOG_LIMIT)
            .await
            .map_err(RpcError::internal)?;
        let commits: Vec<pb::GitCommit> = log
            .into_iter()
            .map(|c| pb::GitCommit {
                oid: c.oid,
                parents: c.parents,
                message: c.message,
                author: c.author,
                when: c.when,
                change_id: c.change_id.unwrap_or_default(),
            })
            .collect();
        let (commits, next_page_token) = paginate(commits, req.page_size, &req.page_token)?;
        Ok(pb::GitLogResponse {
            commits,
            next_page_token,
        })
    }

    /// `GitService.GitDiff` — a textual diff of committed config files between
    /// commits.
    ///
    /// Diffs `registry.toml` and `keys.toml` between `from_oid` and `to_oid`
    /// (an empty `to_oid` defaults to the current HEAD; an empty `from_oid`
    /// renders the whole `to` tree as additions). Requires
    /// [`Permission::Read`] on the registry scope.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::NotFound`] for an unknown slug,
    /// [`RpcError::PermissionDenied`] when the caller cannot read the registry,
    /// [`RpcError::InvalidArgument`] for a malformed oid,
    /// [`RpcError::FailedPrecondition`] when no HEAD is available to default
    /// `to_oid`, and [`RpcError::Internal`] on database or surface-read failure.
    pub async fn git_diff(
        &self,
        auth: Option<&str>,
        req: pb::GitDiffRequest,
    ) -> Result<pb::GitDiffResponse, RpcError> {
        let registry = self.registry_or_not_found(&req.slug).await?;
        self.require_read(auth, &registry).await?;
        let from = if req.from_oid.is_empty() {
            None
        } else {
            Some(Oid::from_hex(&req.from_oid).map_err(|e| RpcError::invalid(format!("{e:#}")))?)
        };
        let to = if req.to_oid.is_empty() {
            self.head_commit(&registry).await?
        } else {
            Oid::from_hex(&req.to_oid).map_err(|e| RpcError::invalid(format!("{e:#}")))?
        };
        let fetch = crate::placement_read::TopologySurfaceFetch::for_verified_git_objects(
            Arc::clone(&self.db),
            Arc::clone(&self.surface),
            SurfaceTarget::Registry(registry.id),
        );
        let diff = crate::git::diff_config_files(&fetch, from, to)
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::GitDiffResponse { diff })
    }
}
