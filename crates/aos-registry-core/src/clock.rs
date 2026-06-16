//! The wall clock, abstracted across deployment targets.
//!
//! The hub's `Database` writes (and JWT issuance/expiry) stamp Unix-second
//! timestamps. On a native build that is `std::time::SystemTime`; on the
//! Cloudflare Worker (`wasm32-unknown-unknown`) `SystemTime::now()` is
//! unavailable and panics, so this module reads the host JS clock through
//! `js_sys::Date::now()` instead (RFC-0004 Phase 5). Callers use the single
//! [`now_unix_secs`] entry point and never branch on the target themselves.

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
