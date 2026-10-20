//! Replays overlays from ordered, signed, fully checked contextual layer histories.
//!
//! Recipe roots determine decoding context only after the enclosing signature
//! is checked. Each paired parent still requires its own Original scope and
//! complete introduction and attribute-producer histories before recomputation.

use std::collections::BTreeMap;

use terrane_format::algebra::{OperationDomains, Recipe};
use terrane_format::identity::Digest;
use terrane_format::properties::RootLayer;
use terrane_format::refs::Commit;
use terrane_format::tree_format::TreeUse;

use super::{Guard, HistoryObservation, TreeEvidence, VerifiedTree, invalid};
use crate::store::{Clock, Store, StoreFailure};

/// Reports opt-in layer verification boundaries without changing its clock.
///
/// # Panics
/// Panics if enabled diagnostics cannot write to standard error.
#[cfg(all(test, feature = "std"))]
fn trace_layer_history(identity: Digest, phase: &'static str) {
    if std::env::var_os("TERRANE_INDEX_REBUILD_TRACE").is_some() {
        let process_at = crate::diagnostic_clock::tick();
        eprintln!(
            "overlay-history-subphase identity={identity:?} phase={phase} process_at={process_at:?}"
        );
    }
}

/// Retains the exact signed parent order paired with the recipe's root order.
pub(super) struct OverlayHistoryPlan {
    /// Exact ordered signed input identities paired with their recipe roots.
    pub(super) inputs: Vec<(Digest, Digest)>,
    recipe: Vec<u8>,
    baseline: Option<Digest>,
}

impl OverlayHistoryPlan {
    /// Recognizes a registered overlay without accepting any unsigned input history.
    ///
    /// # Errors
    /// Rejects malformed canonical recipe bytes and mismatched signed parent counts.
    pub(super) fn from_commit(commit: &Commit) -> Result<Option<Self>, StoreFailure> {
        let Some(bytes) = &commit.profile_pair.recipe else {
            return Ok(None);
        };
        let mut decoder = terrane_format::cbor::Decoder::new(bytes);
        decoder.map(bytes.len()).map_err(|_| invalid())?;
        if decoder.uint().map_err(|_| invalid())? != 1 {
            return Err(invalid());
        }
        if decoder.text(bytes.len()).map_err(|_| invalid())? != "overlay" {
            return Ok(None);
        }
        let decoded = Recipe::decode(bytes).map_err(|_| invalid())?;
        let roots = match decoded.as_recipe() {
            Recipe::Overlay(roots) | Recipe::OverlayWithDomains { roots, .. } => roots.to_vec(),
            _ => return Ok(None),
        };
        if roots.is_empty()
            || (commit.parents.len() != roots.len() && commit.parents.len() != roots.len() + 1)
        {
            return Err(invalid());
        }
        let baseline = (commit.parents.len() == roots.len() + 1).then(|| commit.parents[0]);
        Ok(Some(Self {
            inputs: commit.parents[commit.parents.len() - roots.len()..]
                .iter()
                .copied()
                .zip(roots)
                .collect(),
            recipe: bytes.clone(),
            baseline,
        }))
    }
}

impl<S: Store, C: Clock> Guard<S, C> {
    /// Authenticates a signed tree under the fixed overlay-layer decoding use.
    ///
    /// # Errors
    /// Preserves canonical metadata, signature, interpretation, Original and
    /// storage failures without completing history or granting current rights.
    #[cfg(all(feature = "std", feature = "tokio", unix))]
    pub(in crate::guard) async fn signed_overlay_layer_observed(
        &self,
        identity: Digest,
        observation: HistoryObservation<'_>,
    ) -> Result<VerifiedTree, StoreFailure> {
        self.signed_tree_for(identity, observation, TreeUse::OverlayLayer)
            .await
    }

    /// Authenticates one explicitly requested immutable layer and every dependency.
    ///
    /// # Errors
    /// Preserves malformed bytes, signatures, missing Original scopes, invalid
    /// introductions, independent attribute-producer and protected-control errors.
    pub(crate) async fn verified_overlay_layer_history_observed(
        &self,
        identity: Digest,
        observation: HistoryObservation<'_>,
    ) -> Result<(VerifiedTree, terrane_format::provenance::VerifiedHistory), StoreFailure> {
        #[cfg(all(feature = "std", feature = "tokio", unix))]
        if let Some(completed) = self.overlay_history_native(identity, observation).await? {
            return Ok(completed);
        }
        #[cfg(all(test, feature = "std"))]
        trace_layer_history(identity, "signed-layer-entry");
        let verified = self
            .signed_tree_for(identity, observation, TreeUse::OverlayLayer)
            .await?;
        #[cfg(all(test, feature = "std"))]
        trace_layer_history(identity, "signed-layer-return");

        let observation = observation.overlay_layer(identity, verified.evidence.root);
        #[cfg(all(test, feature = "std"))]
        trace_layer_history(identity, "full-history-entry");
        let history = self
            .verified_history_observed(identity, observation)
            .await?;
        #[cfg(all(test, feature = "std"))]
        trace_layer_history(identity, "full-history-return");

        Ok((verified, history))
    }

    /// Recomputes only after all exact signed inputs have completed their histories.
    ///
    /// # Errors
    /// Rejects missing or mismatched signed inputs, incompatible source policies,
    /// invalid index relationships and any recomputed recipe or output mismatch.
    pub(super) async fn verify_overlay_history_plan(
        &self,
        output: &TreeEvidence,
        plan: &OverlayHistoryPlan,
        evidence: &BTreeMap<Digest, TreeEvidence>,
        observation: HistoryObservation<'_>,
    ) -> Result<(), StoreFailure> {
        let (root, uploads) = {
            let mut domains = OperationDomains::new();
            let mut sources = Vec::new();
            for (commit, root) in &plan.inputs {
                let layer = evidence.get(commit).ok_or_else(invalid)?;
                if layer.root != *root {
                    return Err(invalid());
                }
                let interpretation = self.select_view(*commit, *root, observation)?;
                for occurrence in layer.occurrences(self.config().min_chunk_size)? {
                    let layers = occurrence
                        .layers
                        .iter()
                        .map(|(properties, overrides)| RootLayer {
                            properties,
                            overrides,
                        })
                        .collect::<Vec<_>>();
                    let effective = interpretation.resolve(&layers, self.defaults_for(layer))?;
                    domains
                        .bind_resolved(occurrence.root, &effective)
                        .map_err(|_| invalid())?;
                }
                sources.push((*commit, layer));
            }
            let decoded = Recipe::decode(&plan.recipe).map_err(|_| invalid())?;
            let has_domains = matches!(decoded.as_recipe(), Recipe::OverlayWithDomains { .. });
            if has_domains {
                decoded.bind_domains(&domains).map_err(|_| invalid())?;
            }
            let materialized = self.materialize_overlay_inputs(
                &sources,
                has_domains.then_some(&domains),
                observation,
            )?;
            if materialized.recipe != plan.recipe {
                return Err(invalid());
            }
            let root = materialized.root;
            let uploads = materialized
                .nodes
                .into_iter()
                .map(|(_, bytes)| crate::guard::StagedUpload::Meta {
                    kind: terrane_format::identity::IdentityKind::Node,
                    bytes,
                })
                .collect::<Vec<_>>();
            (root, uploads)
        };
        if output.usage != TreeUse::Ordinary {
            return Err(invalid());
        }
        let identity = output
            .commit
            .as_ref()
            .ok_or_else(invalid)?
            .identity()
            .map_err(|_| invalid())?;
        let verified = self.signed_tree(identity, observation).await?;
        let (interpretation, profile) =
            self.selected_view_profile(&verified.commit, observation)?;
        let previous = if let Some(baseline) = plan.baseline {
            let previous = evidence.get(&baseline).ok_or_else(invalid)?;
            let verified = self.signed_tree(baseline, observation).await?;
            let (interpretation, profile) =
                self.selected_view_profile(&verified.commit, observation)?;
            Some((previous, interpretation, profile))
        } else {
            None
        };
        let candidate =
            TreeEvidence::load_tree(self.store(), root, &uploads, self.config().min_chunk_size)
                .await?;
        let previous = previous
            .as_ref()
            .map(|(evidence, interpretation, profile)| {
                crate::guard::admission::index_writer::Previous {
                    evidence,
                    interpretation,
                    profile: profile.clone(),
                }
            });
        let sources = plan
            .inputs
            .iter()
            .map(|(identity, _)| {
                evidence
                    .get(identity)
                    .map(|source| (*identity, source))
                    .ok_or_else(invalid)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let completed = self
            .maintain_replayed_indexes(
                &candidate,
                &uploads,
                previous,
                crate::guard::admission::index_writer::OverlayIndexReplay {
                    profile: &profile,
                    interpretation: &interpretation,
                    sources: &sources,
                    observation,
                },
            )
            .await?;
        let expected = completed.map_or(root, |completed| completed.root);
        if expected != output.root {
            return Err(invalid());
        }
        Ok(())
    }
}
