//! Formats only the actual chronologically selected Root property archive.

use super::*;

struct FailureViewV2<'held> { client: &'held RootHostLaunchClientOriginalV1 }

pub(super) fn receiving_bytes_v2() -> Option<usize> {
    size_of::<FailureViewV2<'static>>().checked_add(
        size_of::<aos_systemd_client::FixedPid1PropertyFailureViewV1<'static>>())?.checked_mul(2)
}

pub(super) fn same_property_v2(marker: &aos_systemd_client::FixedPid1PropertyErrorV1,
    cause: Option<&(dyn Error + 'static)>,
) -> bool {
    cause.and_then(|cause| cause.downcast_ref::<aos_systemd_client::FixedPid1PropertyErrorV1>())
        .is_some_and(|actual| std::ptr::eq(marker, actual))
}

impl RootHostLaunchClientOriginalV1 {
    /// Borrows a renderer for the actual selected native Root failure.
    ///
    /// Formatting holds any original archive guard only for that call. Earlier
    /// financial, clock, framing and body errors retain precedence; no error,
    /// string, native object or policy is cloned or allocated here.
    #[doc(hidden)]
    #[must_use]
    pub fn failure_view_v2(&self) -> Option<impl std::fmt::Display + '_> {
        self.failure()?;
        Some(FailureViewV2 { client: self })
    }

    fn selected_property_view_v2(&self, marker: &aos_systemd_client::FixedPid1PropertyErrorV1)
        -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        if self.first.is_none() { return self.turns.property_failure_view_v2(marker); }
        let state = self.state.as_deref()?;
        for sample in [state.peer_before.as_deref(), state.peer_after.as_deref()]
            .into_iter().flatten() {
            if same_property_v2(marker, sample.failure()) {
                return sample.property_failure_view_v1();
            }
        }
        let chunk = state.chunk.as_ref()?;
        if same_property_v2(marker, chunk.failure(&state.received)) {
            chunk.property_failure_view_v1()
        } else { None }
    }
}

impl std::fmt::Display for FailureViewV2<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Some(cause) = self.client.failure() else {
            return formatter.write_str("the original Start Root failure is unavailable");
        };
        if let Some(marker) = cause.downcast_ref::<aos_systemd_client::FixedPid1PropertyErrorV1>() {
            if let Some(view) = self.client.selected_property_view_v2(marker) {
                return std::fmt::Debug::fmt(&view, formatter);
            }
        }
        std::fmt::Display::fmt(cause, formatter)
    }
}
