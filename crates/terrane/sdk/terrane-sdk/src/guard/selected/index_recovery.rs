//! Stages one reconstructed auxiliary replacement before final owner publication.
//!
//! Each offer retains genuine current and Original inputs under actual native
//! exclusion. A loss transition ends this scope; no retained selection or source
//! lineage is reused by the next offer or the final signed publication.

#[cfg(feature = "tokio")]
use super::*;

/// Offers one independently reconstructed auxiliary Node under fresh authority.
///
/// The offer creates immutable data only. Its caller must discard all previous
/// source qualification and recapture it before final owner publication.
///
/// # Errors
/// Preserves current, producer, Original, physical-read and original-deadline
/// refusals, and rejects a changed whole source ref or nonauxiliary identity.
#[cfg(feature = "tokio")]
pub(crate) async fn prestage_one<F, B, V, C>(
    original: &crate::ref_advance::Coordinator<FileBucket<F, B, V>, C, F>,
    session: &crate::ref_advance::WriterSession,
    token: &[u8],
    surface: &str,
    replacement: &crate::guard::index_maintenance::Replacement,
    references: &crate::guard::ExistingOwnerReferences,
    started: std::time::Duration,
) -> Result<bool, crate::ref_advance::AdvanceError>
where
    F: LocalFs + BucketBinding + Sync,
    B: Clock + BucketBinding + Sync,
    V: ContentValidator + BucketBinding + Sync,
    C: Clock + Sync,
    FileBucket<F, B, V>: Sync,
{
    use crate::store::{ContentUpload, MetaUpload, RefStore};

    original.check_time(started)?;
    let concrete = original.guard();
    let holder = crate::bucket::held::SingleHeld::acquire(concrete.store()).await?;
    let clock = crate::guard::index_maintenance::retain_recovery_clock(concrete.clock())?;
    let guard = concrete.held_guard(holder.destination(), clock)?;
    let coordinator = crate::ref_advance::Coordinator::new(
        guard,
        original.timing(),
        crate::ref_advance::FsRef(concrete.store().fs()),
    );
    let held = coordinator.store();
    // Replacement staging retains effect preimages under this writable holder.
    // Ordinary DATA observations cannot authorize the native write.
    let observed = held.observe_publication_retained().await?;
    if held.ref_get(session.reference()).await?.as_ref() != session.record() {
        return Err(invalid().into());
    }
    let source = session.record().ok_or_else(invalid)?.commit;
    let purpose = crate::guard::index_maintenance::Purpose::for_source(source);
    let authority = concrete.configured_original_authority()?;
    let consumed = ConsumedResolver::new(coordinator.guard(), &authority)?;
    consumed.registration(&authority)?;
    let history = crate::guard::HistoryObservation::held(observed.identity())
        .tracked(&consumed)
        .maintenance(&purpose);
    let requests = coordinator
        .guard()
        .qualify_index_recovery_source(
            source,
            session.reference(),
            token,
            surface,
            replacement.digest(),
            history,
        )
        .await?;
    for request in &requests {
        consumed.operation(request)?;
    }
    let selected_reads = capture_selected_reads(held, &observed, &[session.reference()]).await?;
    let LocalControlInputs {
        mut exclusion,
        used,
        ..
    } = hold_consumed_controls(concrete, &authority, held, &observed, &consumed).await?;
    let controls = exclusion.retain_used(&used.controls).await?;
    coordinator.guard().retain_original_controls(&controls)?;
    let final_check =
        retain_final_check(coordinator.guard(), &requests, started, original.timing())?;
    let effect = GuardEffectContext {
        existing_reads: references.reads().cloned().collect(),
        final_check,
        controls: vec![controls],
        selected_reads,
        publication_original: None,
    };
    let context =
        meta_batch::ImmutableEffectContext::current_operation(effect, &observed, Vec::new());
    original.check_time(started)?;
    if held
        .index_auxiliary_placement(&observed, replacement.identity())
        .await?
        != Some(true)
    {
        return Ok(false);
    }
    let actual = held
        .put_contextual(
            ContentUpload::Meta(MetaUpload::new(
                terrane_format::identity::IdentityKind::Node,
                replacement.bytes(),
            )?),
            &context,
        )
        .await?;
    if &actual != replacement.identity() {
        return Err(invalid().into());
    }
    original.check_time(started)?;
    Ok(true)
}
