//! Keeps historical Recorded inputs separate from actual current3 configuration.

use super::{
    Mode,
    fixture::{Fixture, TestResult},
};
use crate::guard::{Guard, RecordedNamespaceProfile, RecordedNamespaceProfiles};
use crate::store::{Clock, Store, TokioClock};
use std::time::{Duration, SystemTime};
use terrane_format::identity::Digest;
use terrane_format::properties::semantics::{RecordedContext, associations::RecordedAssociation};

fn originals<S: Store, C>(fixture: &Fixture, guard: &Guard<S, C>) -> TestResult {
    let source = fixture.guard();
    *guard
        .original_verifier
        .write()
        .map_err(|_| "caller verifier lock poisoned")? = source
        .original_verifier
        .read()
        .map_err(|_| "source verifier lock poisoned")?
        .clone();
    *guard
        .original_baselines
        .write()
        .map_err(|_| "caller baseline lock poisoned")? = source
        .original_baselines
        .read()
        .map_err(|_| "source baseline lock poisoned")?
        .clone();
    *guard
        .original_commits
        .write()
        .map_err(|_| "caller commit lock poisoned")? = source
        .original_commits
        .read()
        .map_err(|_| "source commit lock poisoned")?
        .clone();
    Ok(())
}

fn caller(
    fixture: &Fixture,
    rows: &[(Digest, Digest)],
) -> TestResult<Guard<super::fixture::Bucket, TokioClock>> {
    let context = RecordedContext::new(1, 3, &["direct-history-later-name"])?;
    let profiles = rows
        .iter()
        .map(|&(view, root)| {
            RecordedNamespaceProfile::new(RecordedAssociation::new(view, root, context.clone()), 1)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let source = fixture.guard();
    let mut guard = Guard::new_with_recorded_namespace_profiles(
        source.store().clone(),
        TokioClock,
        source.keys().to_vec(),
        source.config().clone(),
        RecordedNamespaceProfiles::new(profiles)?,
    );
    guard.configured_current = source.configured_current;
    originals(fixture, &guard)?;
    Ok(guard)
}

struct UnsampledClock;

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl Clock for UnsampledClock {
    fn now(&self) -> SystemTime {
        panic!("tokenless history sampled the later caller clock")
    }

    fn monotonic(&self) -> Duration {
        panic!("tokenless history sampled the later caller monotonic clock")
    }
}

#[tokio::test]
async fn direct_history_preserves_caller_profiles_and_uses_genuine_factory_clock() -> TestResult {
    let fixture = Fixture::open().await?;
    let base = fixture
        .guard()
        .verified_tree(fixture.base.commit)
        .await?
        .evidence
        .root;
    let target = fixture
        .guard()
        .verified_tree(fixture.head.commit)
        .await?
        .evidence
        .root;
    let good = caller(
        &fixture,
        &[(fixture.base.commit, base), (fixture.head.commit, target)],
    )?;
    assert_eq!(
        good.configured_current,
        crate::guard::history::completion::InterpretationSelection::Active
    );
    for mode in [Mode::History, Mode::TreeAndHistory] {
        let history = mode.verify_guard(&good, fixture.head.commit).await?;
        assert_eq!(history.commits().count(), 2);
        for (view, root) in [(fixture.base.commit, base), (fixture.head.commit, target)] {
            let verified = history.commit(&view).ok_or("historical view missing")?;
            assert_eq!(verified.commit().tree, root);
            let (selected, profile) = good.selected_view_context_for_tests(view, root)?;
            let terrane_format::properties::selected::Selection::Recorded(context) = selected
            else {
                panic!("historical selection was downgraded");
            };
            assert_eq!(context.revision(), 1);
            assert_eq!(context.current_revision(), 3);
            assert_eq!(profile.attribute_revision, 1);
            assert_eq!(profile.later_properties, ["direct-history-later-name"]);
        }
        let later = good.configuration_adapter(good.store().clone(), UnsampledClock);
        originals(&fixture, &later)?;
        assert_eq!(
            mode.verify_guard(&later, fixture.head.commit)
                .await?
                .commits()
                .count(),
            2
        );
        for rows in [
            vec![(fixture.head.commit, target)],
            vec![(fixture.base.commit, target), (fixture.head.commit, target)],
        ] {
            let refused = caller(&fixture, &rows)?;
            assert!(
                mode.verify_guard(&refused, fixture.head.commit)
                    .await
                    .is_err(),
                "{mode:?}: ancestor configuration was ignored"
            );
        }
        let mut issuer = caller(
            &fixture,
            &[(fixture.base.commit, base), (fixture.head.commit, target)],
        )?;
        issuer.keys.clear();
        assert!(
            mode.verify_guard(&issuer, fixture.head.commit)
                .await
                .is_err(),
            "{mode:?}: stale captured issuer inventory was substituted"
        );
    }
    Ok(())
}
