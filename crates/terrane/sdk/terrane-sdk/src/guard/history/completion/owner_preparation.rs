//! Reuses successful canonical owner preparation within one pending view call.
//!
//! The borrowed immutable evidence fixes each owner's Tree use, including its
//! ordinary-compatibility classification. The borrowed selected inputs fix chunk
//! geometry, attribute revision and default scope. A retained owner says only
//! that its canonical Tree and namespace attribute formats passed; occurrence
//! policy, relationship completeness and all authority remain separate checks.
//! The signed-requirement check's canonical view-root Tree is consumed once at
//! its original attribute-validation position, without promoting partial work.

use std::collections::BTreeSet;

use terrane_format::identity::Digest;
use terrane_format::properties::Defaults;
use terrane_format::provenance::VerifiedCommit;
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::EntryKind;

use super::{SelectedInputs, malformed, requirements};
use crate::guard::TreeEvidence;
use crate::store::StoreFailure;

/// Borrows one preparation invocation's immutable inputs and successful owners.
pub(super) struct OwnerPreparation<'a> {
    evidence: &'a TreeEvidence,
    inputs: &'a SelectedInputs,
    successful: BTreeSet<Digest>,
    prepared_root: Option<Tree<'a>>,
    #[cfg(all(test, feature = "tokio", unix))]
    reuse: bool,
    /// Records actual Tree constructor attempts, including refusals.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(super) constructions: Vec<Digest>,
    /// Counts actual entries reached by the namespace attribute-format walk.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(super) entry_visits: usize,
}

impl<'a> OwnerPreparation<'a> {
    /// Borrows the sole evidence scope used by owner and occurrence preparation.
    pub(super) fn evidence(&self) -> &'a TreeEvidence {
        self.evidence
    }

    /// Borrows the sole selected interpretation and geometry for this invocation.
    pub(super) fn inputs(&self) -> &'a SelectedInputs {
        self.inputs
    }

    /// Starts an empty memo bound to one synchronous preparation invocation.
    pub(super) fn new(evidence: &'a TreeEvidence, inputs: &'a SelectedInputs) -> Self {
        Self {
            evidence,
            inputs,
            successful: BTreeSet::new(),
            prepared_root: None,
            #[cfg(all(test, feature = "tokio", unix))]
            reuse: true,
            #[cfg(all(test, feature = "tokio", unix))]
            constructions: Vec::new(),
            #[cfg(all(test, feature = "tokio", unix))]
            entry_visits: 0,
        }
    }

    /// Exercises the same preparation with every owner construction retained.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(super) fn without_reuse(evidence: &'a TreeEvidence, inputs: &'a SelectedInputs) -> Self {
        Self {
            reuse: false,
            ..Self::new(evidence, inputs)
        }
    }

    /// Checks signed requirements at their original position, retaining only the Tree.
    ///
    /// The private constructor uses this invocation's exact evidence and minimum.
    /// Successful requirement projection does not complete namespace attributes,
    /// occurrence policy, relationships or history.
    ///
    /// # Errors
    /// Preserves missing signed snapshots, canonical Tree failures and signed
    /// projection contradictions. A failed check never retains prepared data.
    pub(super) fn check_requirements(
        &mut self,
        commit: &VerifiedCommit,
        defaults: Defaults<'_>,
    ) -> Result<(), StoreFailure> {
        self.prepared_root = None;
        let selection = self.inputs.selection.clone();
        let tree = requirements::check(commit, defaults, selection, || {
            self.construct(self.evidence.root)
        })?;
        if self.reuse_enabled() {
            self.prepared_root = Some(tree);
        }
        Ok(())
    }

    fn reuse_enabled(&self) -> bool {
        #[cfg(all(test, feature = "tokio", unix))]
        {
            self.reuse
        }
        #[cfg(not(all(test, feature = "tokio", unix)))]
        {
            true
        }
    }

    /// Reconstructs a canonical owner only from this invocation's fixed inputs.
    fn construct(&mut self, root: Digest) -> Result<Tree<'a>, StoreFailure> {
        #[cfg(all(test, feature = "tokio", unix))]
        self.constructions.push(root);
        self.evidence.tree(root, self.inputs.minimum)
    }

    /// Checks canonical owner bytes and every nested namespace attribute format.
    ///
    /// # Errors
    /// Preserves absent or noncanonical Tree failures and malformed attribute
    /// refusals. Failed constructors and incomplete entry walks are never reused.
    pub(super) fn check(&mut self, root: Digest) -> Result<(), StoreFailure> {
        if self.reuse_enabled() && self.successful.contains(&root) {
            return Ok(());
        }

        // Only the view root can consume the earlier canonical reconstruction.
        // Taking it before attribute checks prevents a failed walk from reusing it.
        let prepared = if root == self.evidence.root {
            self.prepared_root.take()
        } else {
            None
        };
        let tree = match prepared {
            Some(tree) => tree,
            None => self.construct(root)?,
        };
        for item in tree.iter() {
            let mut entries = vec![&item.entry];
            while let Some(entry) = entries.pop() {
                #[cfg(all(test, feature = "tokio", unix))]
                {
                    self.entry_visits += 1;
                }
                terrane_format::indexing::carrier::validate_namespace_attributes(
                    self.inputs.registries.attribute_revision,
                    entry,
                )
                .map_err(malformed)?;
                if let EntryKind::Conflict { candidates, base } = &entry.kind {
                    entries.extend(candidates);
                    if let Some(Some(base)) = base {
                        entries.push(base);
                    }
                }
            }
        }

        // This proves only fixed immutable owner work. Each occurrence still
        // resolves its complete ordered layers before its policy is retained.
        self.successful.insert(root);
        Ok(())
    }
}
