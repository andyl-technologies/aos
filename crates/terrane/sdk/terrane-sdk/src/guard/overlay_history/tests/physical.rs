//! Refuses changed original recipes and native closing decline before promotion.

use super::*;
use crate::store::{LocalFs, StoreErrorKind, TokioLocalFs};
use std::os::unix::fs::MetadataExt;
use terrane_format::gc::publication::evidence::ControlKind;

#[tokio::test]
async fn overlay_history_refuses_late_original_and_equal_byte_pack_replacement() -> TestResult {
    for original in [false, true] {
        let fixture = Fixture::open().await?;
        let holder = SingleHeld::acquire_read_only(fixture.guard().store()).await?;
        let source = holder.source();
        let selected = source.observe_publication_ordinary_retained().await?;
        let guard = fixture.guard().held_guard(holder.source(), TokioClock)?;
        let authority = fixture.guard().configured_original_authority()?;
        let baseline = ConsumedResolver::new(&guard, &authority)?;
        fixture.fs.reset();
        guard
            .verified_overlay_layer_history_observed(
                fixture.layer.commit,
                HistoryObservation::held(selected.identity()).tracked(&baseline),
            )
            .await?;
        let pack = fixture
            .fs
            .native_paths()
            .into_iter()
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "pack")
            })
            .ok_or("actual containing pack absent")?;
        let (path, bytes) = if original {
            let context = guard.original_commit(&fixture.layer.commit)?;
            let pin = crate::guard::publication_original_pins(&context)?
                .into_iter()
                .find(|pin| pin.kind == ControlKind::Association)
                .ok_or("actual association absent")?;
            let path = context.baseline().authority().control().join(pin.key);
            let bytes = TokioLocalFs.read_nofollow(&path).await?;
            *fixture.fs.after_data_replacement.lock().unwrap() = Some((pack, path.clone()));
            (path, bytes)
        } else {
            let bytes = TokioLocalFs.read_nofollow(&pack).await?;
            *fixture.fs.fault.lock().unwrap() = Some((pack.clone(), fs::Fault::ReplaceLeaf));
            (pack, bytes)
        };
        let old_inode = TokioLocalFs.symlink_metadata(&path).await?.ino();
        let consumed = ConsumedResolver::new(&guard, &authority)?;
        assert!(
            guard
                .verified_overlay_layer_history_observed(
                    fixture.layer.commit,
                    HistoryObservation::held(selected.identity()).tracked(&consumed)
                )
                .await
                .is_err()
        );
        assert!(
            consumed
                .observed_completed_view_contexts_for_tests()?
                .is_empty()
        );
        assert_eq!(TokioLocalFs.read_nofollow(&path).await?, bytes);
        assert_ne!(TokioLocalFs.symlink_metadata(&path).await?.ino(), old_inode);
        if original {
            assert!(fixture.fs.after_data_replacement.lock().unwrap().is_none());
        } else {
            assert!(fixture.fs.fault.lock().unwrap().is_none());
        }
        selected.revalidate().await?;
    }
    Ok(())
}

#[tokio::test]
async fn overlay_history_native_closing_decline_never_promotes_completion() -> TestResult {
    let fixture = Fixture::open().await?;
    let holder = SingleHeld::acquire_read_only(fixture.guard().store()).await?;
    let source = holder.source();
    let selected = source.observe_publication_ordinary_retained().await?;
    let guard = fixture.guard().held_guard(holder.source(), TokioClock)?;
    let authority = fixture.guard().configured_original_authority()?;
    let consumed = ConsumedResolver::new(&guard, &authority)?;
    fixture
        .fs
        .decline_closing
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let failure = guard
        .verified_overlay_layer_history_observed(
            fixture.layer.commit,
            HistoryObservation::held(selected.identity()).tracked(&consumed),
        )
        .await
        .err()
        .ok_or("declined close completed")?;
    assert_eq!(failure.kind(), &StoreErrorKind::Unsupported);
    assert!(
        !fixture
            .fs
            .decline_closing
            .load(std::sync::atomic::Ordering::SeqCst)
    );
    assert!(
        consumed
            .observed_completed_view_contexts_for_tests()?
            .is_empty()
    );
    let fresh = ConsumedResolver::new(&guard, &authority)?;
    guard
        .verified_overlay_layer_history_observed(
            fixture.layer.commit,
            HistoryObservation::held(selected.identity()).tracked(&fresh),
        )
        .await?;
    assert_eq!(fresh.observed_completed_view_contexts_for_tests()?.len(), 2);
    Ok(())
}
