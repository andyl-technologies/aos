//! Verifies exact owned clock state without changing generic clock bounds.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture assertions intentionally panic."
)]

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

struct InjectedClock(Shared<AtomicU64>);

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl Clock for InjectedClock {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + self.monotonic()
    }

    fn monotonic(&self) -> Duration {
        Duration::from_secs(self.0.load(Ordering::SeqCst))
    }

    fn retain_native_clock(&self) -> std::io::Result<NativeEffectClock> {
        Ok(NativeEffectClock::from_native_clock(Self(Shared::clone(
            &self.0,
        ))))
    }
}

#[test]
fn retained_adapter_observes_the_exact_injected_clock_state() {
    let source = InjectedClock(Shared::new(AtomicU64::new(0)));
    let owned = source.retain_native_clock().unwrap();
    let retained = owned.retain_native_clock().unwrap();

    source.0.store(17, Ordering::SeqCst);

    assert_eq!(retained.monotonic(), Duration::from_secs(17));
    assert_eq!(owned.now(), source.now());
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn manual_collector_clock_keeps_sleep_unsupported() -> std::io::Result<()> {
    let source = gc_test_clock::TestClock::new(100);
    let retained = source.retain_native_clock()?;

    let error = retained.sleep(Duration::from_millis(1)).await.err();

    assert!(matches!(error, Some(error) if error.kind() == std::io::ErrorKind::Unsupported));
    assert_eq!(
        retained.now(),
        SystemTime::UNIX_EPOCH + Duration::from_secs(100)
    );
    assert_eq!(retained.monotonic(), Duration::ZERO);
    Ok(())
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn retained_collector_timer_advances_the_same_clock() -> std::io::Result<()> {
    let source = gc_test_clock::TestClock::new(100);
    let retained = source.retain_native_clock()?.retain_native_clock()?;
    source.enable_timer();
    let before_wall = retained.now();
    let before_ticks = retained.monotonic();
    let delay = Duration::from_millis(20);

    retained.sleep(delay).await?;

    assert!(retained.monotonic() >= before_ticks + delay);
    assert!(retained.now() >= before_wall + delay);
    let lower = source.monotonic();
    let observed = retained.monotonic();
    let upper = source.monotonic();
    assert!((lower..=upper).contains(&observed));
    Ok(())
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn collector_timer_exposes_regression_and_dropped_sleep() -> std::io::Result<()> {
    let source = gc_test_clock::TestClock::new(100);
    source.set(100, 1_000);
    source.enable_timer();
    let retained = source.retain_native_clock()?;
    retained.sleep(Duration::from_millis(20)).await?;
    let before_wall = retained.now();
    let before_ticks = retained.monotonic();

    source.set(99, 0);

    assert!(retained.now() < before_wall);
    assert!(retained.monotonic() < before_ticks);
    tokio::select! {
        result = retained.sleep(Duration::from_secs(60)) => {
            result?;
            panic!("long sleep completed before its actual timer");
        }
        () = tokio::time::sleep(Duration::from_millis(5)) => {}
    }
    assert!(retained.monotonic() < Duration::from_secs(60));
    retained.sleep(Duration::from_millis(1)).await?;
    Ok(())
}

#[cfg(feature = "send")]
#[test]
fn default_hook_preserves_send_not_sync_clock_implementations() {
    struct SendOnlyClock(std::cell::Cell<Duration>);

    #[async_trait::async_trait]
    impl Clock for SendOnlyClock {
        fn now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH + self.monotonic()
        }

        fn monotonic(&self) -> Duration {
            self.0.get()
        }
    }

    fn assert_send<T: Send>(_value: &T) {}
    let clock = SendOnlyClock(std::cell::Cell::new(Duration::ZERO));
    assert_send(&clock);

    assert!(matches!(clock.retain_native_clock(), Err(error)
        if error.kind() == std::io::ErrorKind::Unsupported));
}

#[cfg(not(feature = "send"))]
#[test]
fn local_adapter_retains_the_exact_rc_clock_state() {
    struct LocalClock(std::rc::Rc<std::cell::Cell<Duration>>);

    #[async_trait::async_trait(?Send)]
    impl Clock for LocalClock {
        fn now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH + self.monotonic()
        }

        fn monotonic(&self) -> Duration {
            self.0.get()
        }

        fn retain_native_clock(&self) -> std::io::Result<NativeEffectClock> {
            Ok(NativeEffectClock::from_native_clock(Self(self.0.clone())))
        }
    }

    let source = LocalClock(std::rc::Rc::new(std::cell::Cell::new(Duration::ZERO)));
    let retained = source.retain_native_clock().unwrap();

    source.0.set(Duration::from_secs(19));

    assert_eq!(retained.monotonic(), Duration::from_secs(19));
}
