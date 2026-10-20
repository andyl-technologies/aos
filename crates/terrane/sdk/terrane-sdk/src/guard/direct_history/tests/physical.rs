//! Refuses changed genuine Original records and actual native DATA incarnations.

use super::{
    Mode,
    fixture::{Fixture, REFERENCE, TestResult},
    fs::Fault,
};
use crate::store::{LocalFs, RefStore, TokioLocalFs};
use terrane_format::gc::publication::evidence::ControlKind;

#[tokio::test]
async fn direct_history_rechecks_target_and_ancestor_original_records() -> TestResult {
    for mode in [Mode::History, Mode::TreeAndHistory] {
        let fixture = Fixture::open().await?;
        mode.verify(&fixture).await?;
        for view in [fixture.base.commit, fixture.head.commit] {
            let original = fixture.guard().original_commit(&view)?;
            let pin = crate::guard::publication_original_pins(&original)?
                .into_iter()
                .find(|pin| pin.kind == ControlKind::Association)
                .ok_or("genuine association pin missing")?;
            let path = original.baseline().authority().control().join(pin.key);
            let archive = path.with_extension("direct-history-original");
            TokioLocalFs.rename(&path, &archive).await?;
            assert!(
                mode.verify(&fixture).await.is_err(),
                "{mode:?}: missing Original was cached"
            );
            TokioLocalFs.rename(&archive, &path).await?;
            mode.verify(&fixture).await?;

            let other_view = if view == fixture.base.commit {
                fixture.head.commit
            } else {
                fixture.base.commit
            };
            let other = fixture.guard().original_commit(&other_view)?;
            let other_pin = crate::guard::publication_original_pins(&other)?
                .into_iter()
                .find(|pin| pin.kind == ControlKind::Association)
                .ok_or("other genuine association missing")?;
            let bytes = TokioLocalFs.read_nofollow(&path).await?;
            let wrong = TokioLocalFs
                .read_nofollow(&other.baseline().authority().control().join(other_pin.key))
                .await?;
            tokio::fs::write(&path, wrong).await?;
            assert!(
                mode.verify(&fixture).await.is_err(),
                "{mode:?}: another actual commit association substituted"
            );
            tokio::fs::write(&path, bytes).await?;
            mode.verify(&fixture).await?;
        }
        assert_eq!(
            fixture.guard().store().ref_get(REFERENCE).await?,
            Some(fixture.current.clone())
        );
    }
    Ok(())
}

#[tokio::test]
async fn direct_history_closes_actual_pack_catalog_and_index_inputs() -> TestResult {
    for mode in [Mode::History, Mode::TreeAndHistory] {
        let fixture = Fixture::open().await?;

        // Each fresh positive walk must accept earlier equal-byte replacements.
        // Persistent body corruption runs last and needs no repair or restoration.
        for (artifact, fault) in [
            ("pack", Fault::Unavailable),
            ("pack", Fault::ReplaceLeaf),
            ("pack", Fault::ReplaceParent),
            ("containing index", Fault::ReplaceLeaf),
            ("catalog shard", Fault::ReplaceLeaf),
            ("pack", Fault::Corrupt),
        ] {
            fixture.fs.reset();
            mode.verify(&fixture).await?;
            let path = fixture
                .fs
                .native_paths()
                .into_iter()
                .find(|path| {
                    let relative = path.strip_prefix(fixture.guard().store().root()).ok();
                    match artifact {
                        "catalog shard" => {
                            relative.is_some_and(|key| key.starts_with("objects/index"))
                                && path.extension().is_some_and(|extension| extension == "idx")
                        }
                        "containing index" => {
                            relative.is_some_and(|key| key.starts_with("objects/pack"))
                                && path.extension().is_some_and(|extension| extension == "idx")
                        }
                        _ => path
                            .extension()
                            .is_some_and(|extension| extension == "pack"),
                    }
                })
                .ok_or("actual direct DATA artifact absent")?;
            *fixture.fs.fault.lock().unwrap() = Some((path, fault));
            assert!(
                mode.verify(&fixture).await.is_err(),
                "{mode:?}: changed {artifact} accepted"
            );
            assert!(
                fixture.fs.fault.lock().unwrap().is_none(),
                "fault must reach an actual request"
            );
            assert_eq!(
                fixture.guard().store().ref_get(REFERENCE).await?,
                Some(fixture.current.clone())
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn direct_history_closes_the_original_selected_guard_incarnation() -> TestResult {
    for mode in [Mode::History, Mode::TreeAndHistory] {
        let fixture = Fixture::open().await?;
        let (guard_path, guard_bytes) = {
            let holder =
                crate::bucket::held::SingleHeld::acquire_read_only(fixture.guard().store()).await?;
            let held = holder.source();
            let observed = held.observe_publication_ordinary_retained().await?;
            let record = held
                .selected_guard_snapshot_record_retained(&observed)
                .await?
                .ok_or("selected Guard absent")?;
            (
                record.path().to_owned(),
                record.bytes().ok_or("selected Guard body absent")?.to_vec(),
            )
        };
        fixture.fs.reset();
        mode.verify(&fixture).await?;
        let trigger = fixture
            .fs
            .native_paths()
            .into_iter()
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "pack")
            })
            .ok_or("direct pack trigger absent")?;
        *fixture.fs.after_data_replacement.lock().unwrap() = Some((trigger, guard_path.clone()));
        assert!(
            mode.verify(&fixture).await.is_err(),
            "{mode:?}: recaptured selected Guard was accepted"
        );
        assert!(fixture.fs.after_data_replacement.lock().unwrap().is_none());
        assert_eq!(TokioLocalFs.read_nofollow(&guard_path).await?, guard_bytes);
        assert_eq!(
            fixture.guard().store().ref_get(REFERENCE).await?,
            Some(fixture.current.clone())
        );
    }
    Ok(())
}
