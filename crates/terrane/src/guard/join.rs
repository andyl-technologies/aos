//! Authorizes explicit source joins and selects their base from verified ancestry.

use std::collections::BTreeSet;

use terrane_core::auth::Verb;
use terrane_core::identity::Digest;
use terrane_core::provenance::VerifiedHistory;
use terrane_core::refs::{CommitGraph, CommitParents, GraphError, MergePolicy};

use super::merge::MergeOperation;
use super::{AdmittedCommit, CommitRequest, Guard, denied, invalid};
use crate::store::{Clock, InvalidReason, Store, StoreErrorKind, StoreFailure};

#[derive(Clone, Copy)]
pub(crate) enum JoinKind {
    Merge,
    Fold,
}

pub(crate) struct JoinRequest<'a> {
    pub(crate) source: &'a str,
    pub(crate) request: CommitRequest,
    pub(crate) policies: &'a [MergePolicy],
    pub(crate) kind: JoinKind,
}

impl<S: Store, C: Clock> Guard<S, C> {
    pub(crate) async fn admit_join(
        &self,
        reference: &str,
        epoch: u64,
        join: JoinRequest<'_>,
    ) -> Result<(AdmittedCommit, Vec<Vec<u8>>), StoreFailure> {
        #[cfg(test)]
        let mut trace = crate::ref_advance::PhaseTrace::new(
            self.clock(),
            reference,
            None,
            None,
            "admit-join-entry",
        );
        let JoinRequest {
            source,
            mut request,
            policies,
            kind,
        } = join;
        if reference == source || !request.uploads.is_empty() {
            return Err(invalid());
        }
        let destination = self
            .authorize(
                reference,
                &request.token,
                Verb::Commit,
                &[],
                &request.surface,
            )
            .await?;
        #[cfg(test)]
        trace.mark("admit-join-destination-authorized");
        let current = destination
            .record()
            .cloned()
            .ok_or_else(|| denied(reference, Verb::Commit))?;
        let verb = match kind {
            JoinKind::Merge => Verb::Read,
            JoinKind::Fold => Verb::Fork,
        };
        let incoming = self
            .authorize(source, &request.token, verb, &[], &request.surface)
            .await?;
        let incoming = incoming
            .record()
            .cloned()
            .ok_or_else(|| denied(source, verb))?;
        #[cfg(test)]
        trace.mark("admit-join-source-authorized");
        let ours_history = self.verified_history(current.commit).await?;
        #[cfg(test)]
        trace.mark("admit-join-ours-history-verified");
        let theirs_history = self.verified_history(incoming.commit).await?;
        #[cfg(test)]
        trace.mark("admit-join-theirs-history-verified");
        let graph = ancestry(
            [&ours_history, &theirs_history],
            [current.commit, incoming.commit],
        )?;
        let base = match kind {
            JoinKind::Merge => graph
                .merge_base(current.commit, incoming.commit)
                .map_err(graph_failure)?,
            JoinKind::Fold => {
                let point = fork_point(source, incoming.commit, &theirs_history)?;
                if !graph
                    .is_ancestor(point, current.commit)
                    .map_err(graph_failure)?
                {
                    return Err(invalid());
                }
                point
            }
        };
        #[cfg(test)]
        trace.mark("admit-join-base-graph-selected");
        let base = self.verified_tree(base).await?;
        #[cfg(test)]
        trace.mark("admit-join-base-tree-verified");
        let ours = self.verified_tree(current.commit).await?;
        #[cfg(test)]
        trace.mark("admit-join-ours-tree-verified");
        let theirs = self.verified_tree(incoming.commit).await?;
        #[cfg(test)]
        trace.mark("admit-join-theirs-tree-verified");
        let paths = theirs
            .evidence
            .occurrences(self.config().min_chunk_size)?
            .into_iter()
            .map(|root| root.path)
            .collect::<Vec<_>>();
        for path in &paths {
            self.authorize(
                source,
                &request.token,
                verb,
                std::slice::from_ref(path),
                &request.surface,
            )
            .await?;
        }

        #[cfg(test)]
        trace.mark("admit-join-source-paths-authorized");
        let mut authorized = BTreeSet::new();
        if matches!(kind, JoinKind::Fold) {
            let changed_paths = {
                let base_tree = base
                    .evidence
                    .tree(base.evidence.root, self.config().min_chunk_size)?;
                let incoming_tree = theirs
                    .evidence
                    .tree(theirs.evidence.root, self.config().min_chunk_size)?;
                terrane_core::algebra::diff(&base_tree, &incoming_tree)
                    .into_iter()
                    .map(|change| change.path().to_vec())
                    .collect::<Vec<_>>()
            };
            for path in changed_paths {
                let mut absolute = vec![b'/'];
                absolute.extend(&path);
                match self
                    .authorize(
                        reference,
                        &request.token,
                        Verb::Commit,
                        &[absolute],
                        &request.surface,
                    )
                    .await
                {
                    Ok(_) => {
                        authorized.insert(path);
                    }
                    Err(failure) if matches!(failure.kind(), StoreErrorKind::Denied { .. }) => {}
                    Err(failure) => return Err(failure),
                }
            }
        }
        #[cfg(test)]
        trace.mark("admit-join-fold-paths-authorized");
        let operation = match kind {
            JoinKind::Merge => MergeOperation::Merge,
            JoinKind::Fold => MergeOperation::Fold(&authorized),
        };
        let prepared = self.recompute_merge(
            [&base.evidence, &ours.evidence, &theirs.evidence],
            [&ours_history, &theirs_history],
            [current.commit, incoming.commit],
            policies,
            request.commit,
            operation,
        )?;
        #[cfg(test)]
        trace.mark("admit-join-algebra-encoded");
        request.commit = prepared.commit;
        request.uploads = prepared.uploads;
        request.reference_records = self.existing_records(&base.evidence).await?;
        #[cfg(test)]
        trace.mark("admit-join-base-reference-records");

        request
            .reference_records
            .extend(self.existing_records(&ours.evidence).await?);
        #[cfg(test)]
        trace.mark("admit-join-ours-reference-records");

        request
            .reference_records
            .extend(self.existing_records(&theirs.evidence).await?);
        #[cfg(test)]
        trace.mark("admit-join-theirs-reference-records");

        let mut admitted = self
            .admit_inner(
                reference,
                epoch,
                request,
                None,
                None,
                Some((incoming.commit, theirs.evidence)),
            )
            .await?;
        #[cfg(test)]
        trace.mark("admit-join-candidate-admitted-signed");
        if admitted.expected.as_ref() != Some(&current) {
            return Err(invalid());
        }
        admitted.source_authorization = Some(super::admission::SourceAuthorization {
            reference: source.to_owned(),
            verb,
            paths,
            record: incoming,
        });
        Ok((admitted, prepared.excluded))
    }
}

fn graph_failure(error: GraphError) -> StoreFailure {
    StoreFailure::with_source(
        StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
        error,
    )
}

fn ancestry(
    histories: [&VerifiedHistory; 2],
    heads: [Digest; 2],
) -> Result<CommitGraph, StoreFailure> {
    let mut graph = CommitGraph::new();
    let mut pending = heads.to_vec();
    let mut seen = BTreeSet::new();
    while let Some(identity) = pending.pop() {
        if !seen.insert(identity) {
            continue;
        }
        let commit = histories
            .iter()
            .find_map(|history| history.commit(&identity))
            .ok_or_else(invalid)?;
        let parents = commit.commit().parents.clone();
        pending.extend(parents.iter().copied());
        graph
            .insert(CommitParents { identity, parents })
            .map_err(graph_failure)?;
    }
    Ok(graph)
}

fn fork_point(
    reference: &str,
    head: Digest,
    history: &VerifiedHistory,
) -> Result<Digest, StoreFailure> {
    let mut selected = head;
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(selected) {
            return Err(invalid());
        }
        let current = history.commit(&selected).ok_or_else(invalid)?;
        let context = current
            .commit()
            .profile_pair
            .commit_context
            .as_ref()
            .ok_or_else(invalid)?;
        if context.reference() != reference {
            return Ok(selected);
        }
        selected = *current.commit().parents.first().ok_or_else(invalid)?;
    }
}
