//! Bounds cooperative original-owner polling without exposing a host clock.
//!
//! One notification deadline covers the entire polling action. Completion only
//! observes the same original child/custody; it never restarts semantic work.

#![cfg(test)]

use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::Duration;

pub(super) fn original_poll<T>(mut poll: impl FnMut() -> Option<T>) -> T {
    let expired = AtomicBool::new(false);
    let (stop, timer) = mpsc::channel();
    std::thread::scope(|scope| {
        let expired = &expired;
        scope.spawn(move || {
            if timer.recv_timeout(Duration::from_secs(3)).is_err() {
                expired.store(true, Ordering::Release);
            }
        });
        loop {
            assert!(
                !expired.load(Ordering::Acquire),
                "original operational deadline exhausted"
            );
            if let Some(result) = poll() {
                let _ = stop.send(());
                return result;
            }
            std::thread::yield_now();
        }
    })
}
