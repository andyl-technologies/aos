//! Recomputes ordered multiwriter merges from authenticated immutable inputs.

use std::collections::{BTreeMap, BTreeSet};

use terrane_core::algebra::{self, OperationDomains, Roots};
use terrane_core::identity::{Digest, IdentityKind};
use terrane_core::properties::{self, RootLayer};
use terrane_core::provenance::{Preset, Selector, TrustContext, VerifiedHistory};
use terrane_core::refs::{Commit, MergePolicy, RefRecord};
use terrane_core::tree_builder::Tree;

use super::{AdmittedCommit, CommitRequest, Guard, StagedUpload, TreeEvidence, invalid};
use crate::store::{Clock, Store, StoreFailure};

pub(crate) struct RebaseRequest {
    pub(crate) base: Digest,
    pub(crate) ours: RefRecord,
    pub(crate) theirs: Digest,
    pub(crate) terminal_secret: [u8; 32],
    pub(crate) token: Vec<u8>,
    pub(crate) surface: String,
}

pub(super) enum MergeOperation<'a> {
    Merge,
    Fold(&'a BTreeSet<Vec<u8>>),
}

pub(super) struct PreparedMerge {
    pub(super) commit: Commit,
    pub(super) uploads: Vec<StagedUpload>,
    pub(super) excluded: Vec<Vec<u8>>,
}

struct Forest<'a>(BTreeMap<Digest, Tree<'a>>);

impl<'a> Roots<'a> for Forest<'a> {
    fn resolve(&self, identity: &Digest) -> Option<&Tree<'a>> {
        self.0.get(identity)
    }
}

impl<S: Store, C: Clock> Guard<S, C> {
    pub(crate) async fn admit_rebase(
        &self,
        reference: &str,
        epoch: u64,
        rebase: RebaseRequest,
    ) -> Result<AdmittedCommit, StoreFailure> {
        #[cfg(test)]
        let mut trace = crate::ref_advance::PhaseTrace::new(
            self.clock(),
            reference,
            Some(rebase.theirs),
            None,
            "admit-rebase-entry",
        );
        let policy = rebase.ours.policy.as_ref().ok_or_else(invalid)?;
        if policy.multi_writer != Some(true) {
            return Err(invalid());
        }
        let policies = policy.merge_policies.as_deref().ok_or_else(invalid)?;
        let base = self.verified_tree(rebase.base).await?;
        #[cfg(test)]
        trace.mark("admit-rebase-base-tree-verified");
        let ours = self.verified_tree(rebase.ours.commit).await?;
        #[cfg(test)]
        trace.mark("admit-rebase-ours-tree-verified");
        let theirs = self.verified_tree(rebase.theirs).await?;
        #[cfg(test)]
        trace.mark("admit-rebase-theirs-tree-verified");
        let ours_history = self.verified_history(rebase.ours.commit).await?;
        #[cfg(test)]
        trace.mark("admit-rebase-ours-history-verified");
        let theirs_history = self.verified_history(rebase.theirs).await?;
        #[cfg(test)]
        trace.mark("admit-rebase-theirs-history-verified");
        let prepared = self.recompute_merge(
            [&base.evidence, &ours.evidence, &theirs.evidence],
            [&ours_history, &theirs_history],
            [rebase.ours.commit, rebase.theirs],
            policies,
            theirs.commit.commit().clone(),
            MergeOperation::Merge,
        )?;
        #[cfg(test)]
        trace.mark("admit-rebase-algebra-encoded");
        let mut records = self.existing_records(&base.evidence).await?;
        #[cfg(test)]
        trace.mark("admit-rebase-base-reference-records");
        records.extend(self.existing_records(&ours.evidence).await?);
        #[cfg(test)]
        trace.mark("admit-rebase-ours-reference-records");
        records.extend(self.existing_records(&theirs.evidence).await?);
        #[cfg(test)]
        trace.mark("admit-rebase-theirs-reference-records");
        let request = CommitRequest {
            commit: prepared.commit,
            uploads: prepared.uploads,
            token: rebase.token,
            terminal_secret: rebase.terminal_secret,
            surface: rebase.surface,
            reference_records: records,
            disclosures: Vec::new(),
        };
        let admitted = self
            .admit_inner(
                reference,
                epoch,
                request,
                None,
                None,
                Some((rebase.theirs, theirs.evidence)),
            )
            .await?;
        #[cfg(test)]
        trace.mark("admit-rebase-candidate-admitted-signed");
        if admitted.expected.as_ref() != Some(&rebase.ours) {
            return Err(invalid());
        }
        Ok(admitted)
    }

    /// Keeps every Rc-backed tree and trust evaluator inside a synchronous phase.
    pub(super) fn recompute_merge(
        &self,
        evidence: [&TreeEvidence; 3],
        histories: [&VerifiedHistory; 2],
        parents: [Digest; 2],
        policies: &[MergePolicy],
        mut commit: Commit,
        operation: MergeOperation<'_>,
    ) -> Result<PreparedMerge, StoreFailure> {
        #[cfg(test)]
        let mut trace = crate::ref_advance::PhaseTrace::new(
            self.clock(),
            commit
                .profile_pair
                .commit_context
                .as_ref()
                .map_or("<missing-signed-context>", |context| context.reference()),
            Some(parents[0]),
            None,
            "recompute-entry",
        );
        let minimum = self.config().min_chunk_size;
        let mut domains = OperationDomains::new();
        for input in evidence {
            for occurrence in input.occurrences(minimum)? {
                let layers = occurrence
                    .layers
                    .iter()
                    .map(|(properties, overrides)| RootLayer {
                        properties,
                        overrides,
                    })
                    .collect::<Vec<_>>();
                let effective = properties::resolve(&layers, self.defaults_for(input))
                    .map_err(|_| invalid())?;
                domains
                    .bind_resolved(occurrence.root, &effective)
                    .map_err(|_| invalid())?;
            }
        }
        #[cfg(test)]
        trace.mark("recompute-domains-resolved");
        let mut forest = Forest(BTreeMap::new());
        for input in evidence {
            for root in &input.roots {
                forest.0.insert(*root, input.tree(*root, minimum)?);
            }
        }
        #[cfg(test)]
        trace.mark("recompute-forest-built");
        let trusted = algebra::TrustContext::from_verified(vec![
            TrustContext::new(
                histories[0],
                parents[0],
                Selector::preset(Preset::Any),
                &self.config().storage_domain,
                None,
            )
            .map_err(|_| invalid())?,
            TrustContext::new(
                histories[1],
                parents[1],
                Selector::preset(Preset::Any),
                &self.config().storage_domain,
                None,
            )
            .map_err(|_| invalid())?,
        ])
        .map_err(|_| invalid())?;
        #[cfg(test)]
        trace.mark("recompute-trust-built");
        let policies = policies
            .iter()
            .map(|policy| match policy {
                MergePolicy::PreferOurs => algebra::MergePolicy::PreferOurs,
                MergePolicy::PreferTheirs => algebra::MergePolicy::PreferTheirs,
                MergePolicy::PreferTrusted => algebra::MergePolicy::PreferTrusted,
                MergePolicy::PreferNewer => algebra::MergePolicy::PreferNewer,
                MergePolicy::KeepConflict => algebra::MergePolicy::KeepConflict,
                MergePolicy::Error => algebra::MergePolicy::Error,
            })
            .collect::<Vec<_>>();
        let base = forest.resolve(&evidence[0].root).ok_or_else(invalid)?;
        let ours = forest.resolve(&evidence[1].root).ok_or_else(invalid)?;
        let theirs = forest.resolve(&evidence[2].root).ok_or_else(invalid)?;
        let (merged, excluded) = match operation {
            MergeOperation::Merge => (
                algebra::merge_with_domains(
                    base, ours, theirs, &policies, &trusted, &forest, &domains,
                )
                .map_err(|_| invalid())?,
                Vec::new(),
            ),
            MergeOperation::Fold(authorized) => {
                let folded = algebra::fold_with_domains(
                    base,
                    ours,
                    theirs,
                    parents,
                    &policies,
                    &trusted,
                    &forest,
                    |path, _| authorized.contains(path),
                    algebra::Retirement::Tag,
                    &domains,
                )
                .map_err(|_| invalid())?;
                (folded.merged, folded.excluded)
            }
        };
        #[cfg(test)]
        trace.mark("recompute-algebra-finished");
        merged.bind_commit(&mut commit, parents);
        let mut nodes = BTreeMap::new();
        for tree in std::iter::once(&merged.tree).chain(merged.derived_roots.iter()) {
            for node in tree.nodes() {
                nodes.insert(node.identity(), node.encoded().to_vec());
            }
        }
        #[cfg(test)]
        trace.mark("recompute-nodes-encoded");
        let uploads = nodes
            .into_values()
            .map(|bytes| StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes,
            })
            .collect();
        #[cfg(test)]
        trace.mark("recompute-upload-descriptors-built");
        Ok(PreparedMerge {
            commit,
            uploads,
            excluded,
        })
    }
}
