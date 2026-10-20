//! Recomputes ordered multiwriter merges from authenticated immutable inputs.

use std::collections::{BTreeMap, BTreeSet};

use terrane_format::algebra::{self, OperationDomains, Roots};
use terrane_format::identity::{Digest, IdentityKind};
use terrane_format::properties::{Defaults, RootLayer};
use terrane_format::provenance::{Preset, Selector, VerifiedHistory};
use terrane_format::refs::{Commit, MergePolicy, RefRecord};
use terrane_format::tree_builder::Tree;

use super::history::VerifiedTree;
#[cfg(test)]
use super::recorded_properties::ReadInterpretations;
use super::recorded_properties::SelectedReadInterpretation;
use super::{AdmittedCommit, CommitRequest, Guard, StagedUpload, TreeEvidence, invalid};
use crate::store::{Clock, Store, StoreFailure};

// Pairing checks ordinary input consistency only. Production supplies these
// pairs from VerifiedTrees; neither selection nor matching digests verifies them.
#[cfg(test)]
fn select_inputs(
    interpretations: &ReadInterpretations,
    pairs: [(Digest, Digest, &TreeEvidence); 3],
    parents: [Digest; 2],
) -> Result<[SelectedReadInterpretation; 3], StoreFailure> {
    select_input_pairs(pairs, parents, |view, root| {
        interpretations.select(view, root)
    })
}

// The owning Guard supplies its actual installed or completed view meaning.
// Exact input pairing remains independent of that ordinary selection.
fn select_input_pairs(
    pairs: [(Digest, Digest, &TreeEvidence); 3],
    parents: [Digest; 2],
    mut select: impl FnMut(Digest, Digest) -> Result<SelectedReadInterpretation, StoreFailure>,
) -> Result<[SelectedReadInterpretation; 3], StoreFailure> {
    if parents != [pairs[1].0, pairs[2].0]
        || pairs
            .iter()
            .any(|(_, root, evidence)| *root != evidence.root)
    {
        return Err(invalid());
    }

    Ok([
        select(pairs[0].0, pairs[0].1)?,
        select(pairs[1].0, pairs[1].1)?,
        select(pairs[2].0, pairs[2].1)?,
    ])
}

fn bind_occurrence_domains(
    domains: &mut OperationDomains,
    input: &TreeEvidence,
    selected: &SelectedReadInterpretation,
    defaults: Defaults<'_>,
    minimum: u64,
) -> Result<(), StoreFailure> {
    for occurrence in input.occurrences(minimum)? {
        let layers = occurrence
            .layers
            .iter()
            .map(|(properties, overrides)| RootLayer {
                properties,
                overrides,
            })
            .collect::<Vec<_>>();
        let effective = selected.resolve(&layers, defaults)?;
        domains
            .bind_resolved(occurrence.root, &effective)
            .map_err(|_| invalid())?;
    }
    Ok(())
}

/// Owns input identities and current credentials for a losing-writer rebase.
pub(crate) struct RebaseRequest {
    /// Identifies the supplied common baseline that merge replay must verify.
    pub(crate) base: Digest,
    /// Retains the exact destination head that admission must still expect.
    pub(crate) ours: RefRecord,
    /// Identifies the incoming commit whose history must be verified.
    pub(crate) theirs: Digest,
    /// Supplies the terminal signing key for the current operation token.
    pub(crate) terminal_secret: [u8; 32],
    /// Retains the current operation credentials for ordinary admission.
    pub(crate) token: Vec<u8>,
    /// Names the surface used for current authorization.
    pub(crate) surface: String,
}

/// Selects ordinary merge replay or fold replay with explicit root exclusions.
pub(super) enum MergeOperation<'a> {
    /// Replays an ordinary merge without fold exclusions.
    Merge,
    /// Replays a fold while retaining its independently authorized excluded roots.
    Fold(&'a BTreeSet<Vec<u8>>),
}

/// Retains unsigned canonical merge output before ordinary current admission.
pub(super) struct PreparedMerge {
    /// Retains the canonical proposed merge commit without admission authority.
    pub(super) commit: Commit,
    /// Retains rebuilt immutable metadata needed by the proposed merge.
    pub(super) uploads: Vec<StagedUpload>,
    /// Lists root scopes excluded by canonical fold replay.
    pub(super) excluded: Vec<Vec<u8>>,
}

struct Forest<'a>(BTreeMap<Digest, Tree<'a>>);

impl<'a> Roots<'a> for Forest<'a> {
    fn resolve(&self, identity: &Digest) -> Option<&Tree<'a>> {
        self.0.get(identity)
    }
}

impl<S: Store, C: Clock> Guard<S, C> {
    /// Replays and admits a losing-writer merge against its exact retained head.
    ///
    /// # Errors
    /// Rejects incompatible multi-writer policy or changed expected heads and
    /// preserves history, merge replay, current admission and storage failures.
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
            [&base, &ours, &theirs],
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
    ///
    /// All three checked original views select interpretation before occurrence
    /// resolution. Fold preprocessing retains the incoming original association.
    ///
    /// # Errors
    /// Rejects inconsistent input pairs, missing configured interpretations,
    /// invalid occurrence policy, ambiguous ownership or failed algebra replay.
    pub(super) fn recompute_merge(
        &self,
        inputs: [&VerifiedTree; 3],
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
        let pairs = inputs.map(|input| {
            (
                input.commit.identity(),
                input.commit.commit().tree,
                &input.evidence,
            )
        });
        let selected = select_input_pairs(pairs, parents, |view, root| {
            self.select_view(view, root, super::HistoryObservation::default())
        })?;
        let evidence = inputs.map(|input| &input.evidence);
        let mut domains = OperationDomains::new();
        for (input, interpretation) in evidence.iter().zip(&selected) {
            bind_occurrence_domains(
                &mut domains,
                input,
                interpretation,
                self.defaults_for(input),
                minimum,
            )?;
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
            selected[1].evaluator(
                histories[0],
                (pairs[1].0, pairs[1].1),
                Selector::preset(Preset::Any),
                &self.config().storage_domain,
                None,
            )?,
            selected[2].evaluator(
                histories[1],
                (pairs[2].0, pairs[2].1),
                Selector::preset(Preset::Any),
                &self.config().storage_domain,
                None,
            )?,
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

#[cfg(all(test, feature = "tokio", unix))]
#[path = "merge/recorded_tests.rs"]
mod recorded_tests;

// Preserve the pure contract selectors in profiles without native Tokio support.
#[cfg(all(test, not(all(feature = "tokio", unix))))]
#[path = "merge/recorded_tests/ordinary_contracts.rs"]
mod recorded_tests;
