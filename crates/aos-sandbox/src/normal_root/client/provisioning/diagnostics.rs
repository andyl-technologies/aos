//! Renders only the selected original Root property failure under its guard.

use super::*;

struct RootStorageApplyClientFailureViewV1<'cause> {
    client: &'cause RootStorageApplyClientOriginalV1,
    receiving: &'cause crate::CreateProvisioningOriginalsV1,
}

pub(super) fn receiving_bytes_v1() -> Option<usize> {
    std::mem::size_of::<RootStorageApplyClientFailureViewV1<'static>>().checked_mul(2)?
        .checked_add(std::mem::size_of::<aos_systemd::FixedPid1PropertyFailureViewV1<'static>>()
            .checked_mul(2)?)
}

impl RootStorageApplyClientOriginalV1 {
    /// Borrows a renderer that locks only the selected original property row.
    ///
    /// A prior financial, clock, framing or Action cause suppresses a later
    /// property failure. Formatting borrows the actual archive under its guard;
    /// no native error is cloned, moved out or reconstructed, and no IO runs.
    #[doc(hidden)]
    #[must_use]
    pub fn failure_view_with_original_v1<'cause>(&'cause self,
        receiving: &'cause crate::CreateProvisioningOriginalsV1,
    ) -> Option<impl std::fmt::Display + 'cause> {
        self.failure_with_original_v1(receiving)?;
        Some(RootStorageApplyClientFailureViewV1 { client: self, receiving })
    }

    fn selected_property_failure_view_v1(&self)
        -> Option<aos_systemd::FixedPid1PropertyFailureViewV1<'_>> {
        let marker = self.failure()?.downcast_ref::<aos_systemd::FixedPid1PropertyErrorV1>()?;
        let sample = match self.first {
            Some(First::Before) => self.state.peer_before.as_deref(),
            Some(First::After) => self.state.peer_after.as_deref(),
            Some(First::Settlement) => {
                for sample in [self.state.peer_before.as_deref(), self.state.peer_after.as_deref()]
                    .into_iter().flatten() {
                    if same_property_marker_v1(marker, sample.failure()) {
                        return sample.property_failure_view_v1();
                    }
                }
                None
            }
            Some(First::Receive) => {
                return self.state.chunk.as_ref()?.property_failure_view_v1();
            }
            None => {
                return self.publication.property_failure_view_v1()
                    .or_else(|| self.final_property_failure_view_v1());
            }
            _ => None,
        }?;
        if same_property_marker_v1(marker, sample.failure()) {
            sample.property_failure_view_v1()
        } else { None }
    }
}

pub(super) fn same_property_marker_v1(marker: &aos_systemd::FixedPid1PropertyErrorV1,
    cause: Option<&(dyn Error + 'static)>,
) -> bool {
    cause.and_then(|cause| cause.downcast_ref::<aos_systemd::FixedPid1PropertyErrorV1>())
        .is_some_and(|other| std::ptr::eq(marker, other))
}

impl std::fmt::Display for RootStorageApplyClientFailureViewV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Some(selected) = self.client.failure_with_original_v1(self.receiving) else {
            return formatter.write_str("the original Root Apply failure is unavailable");
        };
        if let (Some(selected), Some(root)) = (
            selected.downcast_ref::<aos_systemd::FixedPid1PropertyErrorV1>(),
            self.client.failure().and_then(|cause|
                cause.downcast_ref::<aos_systemd::FixedPid1PropertyErrorV1>()),
        ) {
            if std::ptr::eq(selected, root) {
                if let Some(view) = self.client.selected_property_failure_view_v1() {
                    return std::fmt::Debug::fmt(&view, formatter);
                }
            }
        }
        std::fmt::Display::fmt(selected, formatter)
    }
}
