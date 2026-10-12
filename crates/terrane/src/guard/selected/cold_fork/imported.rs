//! Qualifies imported used-view Originals under the actual held cold-fork Guard.
//!
//! Only Commit metadata is read. Selected whole-lineage evidence supplies the
//! completed ordinary contexts; native Original binders check the actual controls.

use super::*;
use crate::store::ContentStore;

/// Retains actual contexts and the same-holder control receipt until publication.
///
/// The private factory checks every context through the installed native binder.
/// Receipt ownership does not derive authority from a decoded lineage or pin.
pub(super) struct QualifiedImportedOriginals {
    originals: Vec<crate::guard::OriginalCommitContext>,
    retained: RetainedControls,
    authority: OriginalAuthority,
}

impl QualifiedImportedOriginals {
    /// Rechecks all captured contexts after subsequent metadata and protected reads.
    ///
    /// # Errors
    /// Preserves actual binder/control failures and rejects changed Original
    /// contexts, changed selection or any missing or additional consumed pin.
    pub(super) async fn revalidate<F, B, V, C>(
        &self,
        guard: &Guard<HeldBucket<'_, F, B, V, true>, C>,
        observed: &SelectedObservation<'_>,
        lineage: &CheckedLineage,
        current: &RetainedControls,
    ) -> Result<(), StoreFailure>
    where
        F: LocalFs + BucketBinding,
        B: Clock + BucketBinding,
        V: ContentValidator + BucketBinding,
        C: Clock,
    {
        observed.revalidate().await?;
        check_controls(&self.retained, current)?;
        // Publication may have installed a genuine superset containing the new
        // candidate Original. Preserve that receipt rather than replacing it
        // with source-only pins; the binder checks each captured context against
        // the currently installed same-holder receipt.
        let consumed = ConsumedResolver::new(guard, &self.authority)?;
        consumed.registration(&self.authority)?;
        let observation =
            crate::guard::HistoryObservation::held(observed.identity()).tracked(&consumed);
        for original in &self.originals {
            guard
                .revalidate_original_context(original, observation)
                .await?;
        }
        if consumed.finish()?.controls != lineage.controls {
            return Err(invalid());
        }
        observed.revalidate().await?;
        Ok(())
    }
}

/// Checks destination-owned imported dependencies using genuine retained Originals.
///
/// # Errors
/// Rejects foreign head/control owners, absent or changed native contexts,
/// malformed Commit metadata, invalid signatures or per-view root claims, changed
/// selected inputs and a consumed control set differing from the whole lineage.
pub(super) async fn qualify<F, B, V, C>(
    guard: &Guard<HeldBucket<'_, F, B, V, true>, C>,
    authority: &OriginalAuthority,
    observed: &SelectedObservation<'_>,
    lineage: &CheckedLineage,
    interpretations: &BTreeMap<[u8; 32], SelectedReadInterpretation>,
    retained: RetainedControls,
) -> Result<(OriginalAssociation, QualifiedImportedOriginals), StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    let registration = consumed_registration(authority);
    if lineage.original != registration
        || lineage.controls.iter().any(|pin| pin.owner != registration)
    {
        return Err(StoreFailure::new(StoreErrorKind::Unsupported));
    }

    // The existing private binder validates the actual owner and holder. Reuse
    // this genuine same-holder receipt instead of reacquiring retention.lock.
    guard.retain_original_controls(&retained)?;
    let consumed = ConsumedResolver::new(guard, authority)?;
    consumed.registration(authority)?;
    let observation =
        crate::guard::HistoryObservation::held(observed.identity()).tracked(&consumed);
    let mut originals = Vec::new();
    let mut head = None;
    for view in &lineage.used.views {
        let original = guard.original_commit(&view.view)?;
        guard
            .revalidate_original_context(&original, observation)
            .await?;

        // Commit metadata is allowed; no TreeEvidence, ordinary history walk,
        // TreeNode get/put or signed_tree/historical_roots call occurs here.
        let identity = TERRANE_V1
            .from_digest(IdentityKind::Commit, &view.view)
            .map_err(|_| invalid())?;
        // HeldBucket::get dispatches to get_held, which independently observes
        // its current catalog, verifies the container/body and rechecks that
        // observation. Keep the original source selection checked on both sides.
        observed.revalidate().await?;
        let bytes = guard.store().get(&identity, None).await?;
        observed.revalidate().await?;
        let commit = Commit::decode(&bytes).map_err(|_| invalid())?;
        let interpretations_used = lineage
            .used
            .view_interpretations
            .as_ref()
            .ok_or_else(invalid)?;
        let selected = interpretations_used
            .iter()
            .find(|context| context.view == view.view)
            .ok_or_else(invalid)?;
        selected
            .check_signed_view_data(&commit)
            .map_err(|_| invalid())?;
        let context = commit
            .profile_pair
            .commit_context
            .as_ref()
            .ok_or_else(invalid)?;
        let previous = commit
            .parents
            .first()
            .and_then(|parent| lineage.used.views.iter().find(|view| &view.view == parent));
        for claim in context.roots() {
            let mut witnessed = false;
            for occurrence in std::iter::once(view).chain(previous) {
                for root in &occurrence.roots {
                    if root.path == claim.path()
                        && occurrence_domain(
                            root,
                            occurrence,
                            &lineage.used.configuration,
                            interpretations.get(&occurrence.view).ok_or_else(invalid)?,
                        )? == claim.domain()
                    {
                        witnessed = true;
                    }
                }
            }
            if !witnessed {
                return Err(invalid());
            }
        }
        let roots = context
            .roots()
            .iter()
            .map(|claim| RequestRoot {
                path: claim.path(),
                domain: claim.domain(),
            })
            .collect::<Vec<_>>();
        let keys = original.historical_keys()?;
        let verified = provenance::verify_history(
            &commit,
            keys.as_deref().unwrap_or(guard.keys()),
            &roots,
            &[(original.baseline().reference(), original.baseline().epoch())],
        )
        .map_err(|_| invalid())?;
        if verified.identity() != view.view {
            return Err(invalid());
        }
        guard
            .revalidate_original_context(&original, observation)
            .await?;
        if view.view == lineage.commit_id {
            if original.baseline().authority() != authority {
                return Err(invalid());
            }
            head = Some(OriginalAssociation {
                commit: view.view,
                original_id: *original.baseline().authority().id(),
                ref_name: original.baseline().reference().to_owned(),
                epoch: original.baseline().epoch(),
            });
        }
        originals.push(original);
        observed.revalidate().await?;
    }
    if consumed.finish()?.controls != lineage.controls {
        return Err(invalid());
    }
    let qualified = QualifiedImportedOriginals {
        originals,
        retained,
        authority: authority.clone(),
    };
    // Recheck earlier contexts after the last metadata await as well as each
    // individual context after its own read. Exact pins must still be complete.
    qualified
        .revalidate(guard, observed, lineage, &qualified.retained)
        .await?;
    Ok((head.ok_or_else(invalid)?, qualified))
}
