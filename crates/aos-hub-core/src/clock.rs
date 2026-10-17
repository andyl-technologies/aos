//! The wall clock, abstracted across deployment targets.
//!
//! The hub's `Database` writes (and JWT issuance/expiry) stamp Unix-second
//! timestamps. On a native build that is `std::time::SystemTime`; on the
//! Cloudflare Worker (`wasm32-unknown-unknown`) `SystemTime::now()` is
//! unavailable and panics, so this module reads the host JS clock through
//! `js_sys::Date::now()` instead (RFC-0004 Phase 5). Business timestamps use
//! [`now_unix_secs`]. The fallible internal observation
//! timestamp preserves Native microsecond precision and uses the same host clock
//! safely on the Worker; callers never branch on the target themselves.

/// The current Unix time in whole seconds.
///
/// On native targets this reads `std::time::SystemTime`; on
/// `wasm32-unknown-unknown` (the Worker) it reads the JS `Date.now()` clock.
/// A clock before the Unix epoch (impossible in practice) yields `0` rather
/// than panicking, matching the hub's prior `unix_now` behavior.
#[must_use]
pub fn now_unix_secs() -> i64 {
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
    #[cfg(target_arch = "wasm32")]
    {
        // `Date.now()` is milliseconds since the Unix epoch as an f64; the
        // Workers runtime provides it. Truncate to whole seconds.
        (js_sys::Date::now() / 1000.0) as i64
    }
}

/// Returns an observational Unix timestamp in microseconds when the clock is valid.
///
/// Native observations retain the system clock's microsecond precision. Worker
/// observations reflect the host JavaScript clock's millisecond resolution.
/// This timestamp supplies no clock qualification or execution authority.
#[must_use]
pub(crate) fn observation_unix_micros() -> Option<u128> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_micros())
    }
    #[cfg(target_arch = "wasm32")]
    {
        let millis = js_sys::Date::now();
        // JavaScript dates are bounded to this exact integer millisecond range.
        if !millis.is_finite() || !(0.0..=8_640_000_000_000_000.0).contains(&millis) {
            return None;
        }
        Some((millis as u128) * 1000)
    }
}

/// Returns an observational Unix timestamp in nanoseconds when the clock is valid.
///
/// Native observations retain the system clock's nanosecond precision. Worker
/// observations express the host JavaScript clock's millisecond resolution in
/// nanoseconds. This timestamp supplies no clock qualification or authority.
#[must_use]
pub(crate) fn observation_unix_nanos() -> Option<u128> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_nanos())
    }
    #[cfg(target_arch = "wasm32")]
    {
        observation_nanos_from_millis(js_sys::Date::now())
    }
}

/// Validates the exact JavaScript date range before converting timestamp units.
#[cfg(any(target_arch = "wasm32", test))]
fn observation_nanos_from_millis(millis: f64) -> Option<u128> {
    if !millis.is_finite()
        || !(0.0..=8_640_000_000_000_000.0).contains(&millis)
        || millis.fract() != 0.0
    {
        return None;
    }

    (millis as u128).checked_mul(1_000_000)
}

/// Suspends the current task for at least `duration` without blocking its
/// runtime thread.
///
/// Native deployments use Tokio's timer. Worker deployments use the host's
/// `setTimeout`, preserving identical long-poll behavior without assuming a
/// Tokio reactor in WebAssembly.
pub async fn sleep(duration: std::time::Duration) {
    #[cfg(not(target_arch = "wasm32"))]
    tokio::time::sleep(duration).await;

    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::{closure::Closure, JsCast as _, JsValue};
        use wasm_bindgen_futures::JsFuture;

        let millis = duration.as_millis().min(u32::MAX.into()) as u32;
        let promise = js_sys::Promise::new(&mut |resolve, reject| {
            let callback = Closure::once_into_js(move || {
                let _ = resolve.call0(&JsValue::NULL);
            });
            let result = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("setTimeout"))
                .and_then(|value| value.dyn_into::<js_sys::Function>())
                .and_then(|timer| {
                    timer
                        .call2(
                            &js_sys::global(),
                            &callback,
                            &JsValue::from_f64(f64::from(millis)),
                        )
                        .map(|_| ())
                });
            if let Err(error) = result {
                let _ = reject.call1(&JsValue::NULL, &error);
            }
        });
        let _ = JsFuture::from(promise).await;
    }
}

/// A stopwatch for render timing, abstracted across deployment targets.
///
/// On native this is `std::time::Instant`. On `wasm32-unknown-unknown`
/// `Instant::now()` **panics** (the bare wasm target has no monotonic clock),
/// which inside an `async` request handler aborts the future and surfaces on the
/// Workers runtime as "a hanging Promise was canceled" — so the Worker uses a
/// `Date.now()`-backed stopwatch instead. It measures render timing and bounded
/// request waits. A backwards step clamps elapsed time to zero; callers that
/// bound retries must also enforce an attempt ceiling independent of the clock.
#[cfg(not(target_arch = "wasm32"))]
pub use std::time::Instant;

/// A `Date.now()`-backed stopwatch (the Worker's [`Instant`] replacement).
#[cfg(target_arch = "wasm32")]
#[derive(Clone, Copy, Debug)]
pub struct Instant {
    /// `Date.now()` (ms since the Unix epoch) captured at construction.
    start_ms: f64,
}

#[cfg(target_arch = "wasm32")]
impl Instant {
    /// Start the stopwatch at the current `Date.now()`.
    #[must_use]
    pub fn now() -> Instant {
        Instant {
            start_ms: js_sys::Date::now(),
        }
    }

    /// Time elapsed since [`now`](Instant::now), clamped to non-negative.
    #[must_use]
    pub fn elapsed(&self) -> std::time::Duration {
        let ms = (js_sys::Date::now() - self.start_ms).max(0.0);
        std::time::Duration::from_millis(ms as u64)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    #[test]
    fn observation_timestamp_retains_native_microsecond_precision() {
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros();
        let observed = super::observation_unix_micros().unwrap();
        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros();

        assert!((before..=after).contains(&observed));
    }

    #[test]
    fn observation_timestamp_retains_native_nanosecond_precision() {
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let observed = super::observation_unix_nanos().unwrap();
        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        assert!((before..=after).contains(&observed));
    }

    #[test]
    fn observation_nanoseconds_validate_javascript_millisecond_range() {
        assert_eq!(super::observation_nanos_from_millis(0.0), Some(0));
        assert_eq!(super::observation_nanos_from_millis(1.0), Some(1_000_000));
        assert_eq!(
            super::observation_nanos_from_millis(8_640_000_000_000_000.0),
            Some(8_640_000_000_000_000_000_000)
        );

        for invalid in [
            f64::NAN,
            f64::NEG_INFINITY,
            f64::INFINITY,
            -1.0,
            0.5,
            8_640_000_000_000_001.0,
        ] {
            assert_eq!(super::observation_nanos_from_millis(invalid), None);
        }
    }
}
