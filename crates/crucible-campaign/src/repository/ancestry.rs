//! Snapshot ancestry replay, command lookup, and lifecycle projection.

use super::*;

impl CampaignRepository {
    pub(super) fn insert_fact(
        &self,
        root: MerkleMapRoot,
        fact: &CampaignFact,
        content: ContentId,
    ) -> Result<MerkleMapRoot, CampaignRepositoryError> {
        self.merkle
            .insert(
                root.content_id(),
                map_key_content("accounting.fact", fact.id()?.content_id()),
                content,
            )
            .map_err(CampaignRepositoryError::from)
    }

    pub(super) fn find_command_result(
        &self,
        mut content_id: ContentId,
        request: &ControlRequest,
        replayed: bool,
    ) -> Result<CampaignCommandResult, CampaignRepositoryError> {
        let mut visited = BTreeSet::new();
        for _ in 0..MAX_SNAPSHOT_ANCESTRY {
            if !visited.insert(content_id) {
                return Err(integrity("snapshot-ancestry-cycle"));
            }
            let loaded = self.read_snapshot(content_id)?;
            if let Some(transition_content) = optional_child(&loaded.envelope, "transition") {
                let transition = self.read_fact(transition_content)?;
                if let CampaignFact::ControlRequested(candidate) = transition
                    && candidate.command == request.command
                {
                    if candidate != *request {
                        return Err(CampaignRepositoryError::CommandReuse);
                    }
                    return Ok(CampaignCommandResult {
                        prior_snapshot: request.expected_snapshot,
                        new_snapshot: CampaignSnapshotId::from_content_id(content_id)?,
                        replayed,
                    });
                }
            }
            let Some(parent) = optional_child(&loaded.envelope, "parent") else {
                return Err(integrity("command-index-entry-has-no-ancestry-transition"));
            };
            content_id = parent;
        }
        Err(integrity("snapshot-ancestry-limit"))
    }

    pub(super) fn find_branch_request_result(
        &self,
        mut content_id: ContentId,
        request: BranchRequestId,
    ) -> Result<Option<BranchRequestResult>, CampaignRepositoryError> {
        let mut visited = BTreeSet::new();
        for _ in 0..MAX_SNAPSHOT_ANCESTRY {
            if !visited.insert(content_id) {
                return Err(integrity("snapshot-ancestry-cycle"));
            }
            let loaded = self.read_snapshot(content_id)?;
            if let Some(transition_content) = optional_child(&loaded.envelope, "transition") {
                let transition = self.read_fact(transition_content)?;
                if transition == CampaignFact::BranchRequestIssued(request) {
                    let prior_snapshot = loaded
                        .snapshot
                        .parent()
                        .ok_or_else(|| integrity("branch-request-transition-has-no-parent"))?;
                    return Ok(Some(BranchRequestResult {
                        prior_snapshot,
                        new_snapshot: CampaignSnapshotId::from_content_id(content_id)?,
                        request,
                        replayed: true,
                    }));
                }
            }
            let Some(parent) = optional_child(&loaded.envelope, "parent") else {
                return Ok(None);
            };
            content_id = parent;
        }
        Err(integrity("snapshot-ancestry-limit"))
    }

    pub(super) fn mutation_command_exists(
        &self,
        mut content_id: ContentId,
        command: crate::CampaignCommandId,
    ) -> Result<bool, CampaignRepositoryError> {
        let mut visited = BTreeSet::new();
        for _ in 0..MAX_SNAPSHOT_ANCESTRY {
            if !visited.insert(content_id) {
                return Err(integrity("snapshot-ancestry-cycle"));
            }
            let loaded = self.read_snapshot(content_id)?;
            if let Some(transition_content) = optional_child(&loaded.envelope, "transition") {
                match self.read_fact(transition_content)? {
                    CampaignFact::ControlRequested(request) if request.command == command => {
                        return Ok(true);
                    }
                    CampaignFact::BranchRequestIssued(request) => {
                        let request = self.read_branch_request(request.content_id())?;
                        if request.cause() == BranchRequestCause::Operator(command) {
                            return Ok(true);
                        }
                    }
                    _ => {}
                }
            }
            let Some(parent) = optional_child(&loaded.envelope, "parent") else {
                return Ok(false);
            };
            content_id = parent;
        }
        Err(integrity("snapshot-ancestry-limit"))
    }

    pub(super) fn project_state(
        &self,
        mut content_id: ContentId,
    ) -> Result<ProjectedState, CampaignRepositoryError> {
        let mut actions = Vec::new();
        let mut visited = BTreeSet::new();
        for _ in 0..MAX_SNAPSHOT_ANCESTRY {
            if !visited.insert(content_id) {
                return Err(integrity("snapshot-ancestry-cycle"));
            }
            let loaded = self.read_snapshot(content_id)?;
            let parent_id = loaded.snapshot.parent();
            let parent_content = optional_child(&loaded.envelope, "parent");
            let transition_content = optional_child(&loaded.envelope, "transition");
            match (parent_id, parent_content, transition_content) {
                (None, None, None) => {
                    actions.reverse();
                    let mut projected = ProjectedState::new();
                    for action in &actions {
                        projected.apply(action)?;
                    }
                    return Ok(projected);
                }
                (Some(parent_id), Some(parent_content), Some(transition_content)) => {
                    self.read_snapshot(parent_content)?;
                    if CampaignSnapshotId::from_content_id(parent_content)? != parent_id {
                        return Err(integrity("parent-logical-id-mismatch"));
                    }
                    let transition = self.read_fact(transition_content)?;
                    match transition {
                        CampaignFact::ControlRequested(request) => {
                            if request.expected_snapshot != parent_id {
                                return Err(integrity("transition-precondition-parent-mismatch"));
                            }
                            actions.push(request.action);
                        }
                        CampaignFact::BranchRequestIssued(_) => {}
                        _ => {
                            return Err(integrity("snapshot-transition-type-is-not-implemented"));
                        }
                    }
                    content_id = parent_content;
                }
                _ => return Err(integrity("snapshot-parent-transition-shape")),
            }
        }
        Err(integrity("snapshot-ancestry-limit"))
    }

}
