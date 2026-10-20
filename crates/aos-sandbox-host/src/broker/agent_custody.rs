//! Borrows actual entered runtime destinations for housekeeping deferral.
//!
//! This is negative-gating custody DATA. It supplies no currentness, readiness,
//! request admission, native ownership transfer or effect permission.

use std::sync::{Arc, Mutex};
use super::{HostBroker, argument_handoff::ArgumentStageOriginalV2};

/// Borrows an entered runtime stage, including partial or failed native custody.
///
/// Holding this view only defers optional proactive stale-session retirement.
/// The next selected request still needs its genuine financial phase and fresh
/// same-owner currentness before IO. No native owner or validation is exposed.
pub struct HostRuntimeNativeCustodyViewV2<'broker> {
    _stage: NativeCustodyBorrowV2<'broker>,
}

enum NativeCustodyBorrowV2<'broker> {
    Argument(&'broker Arc<Mutex<ArgumentStageOriginalV2>>),
    Launch(&'broker Arc<Mutex<super::launch_handoff::HostLaunchOriginalV2>>),
    Cleanup(&'broker Arc<Mutex<super::stop_cleanup::HostStopCleanupOriginalV1>>),
}

impl<C, S, W> HostBroker<C, S, W> {
    pub(crate) fn retained_runtime_native_custody_v2(&self)
        -> Option<HostRuntimeNativeCustodyViewV2<'_>>
    {
        // A stage is installed after real financial consumption and before its
        // first native preparation. Conservatively include empty/partial and
        // negative destinations; probing or locking them cannot authorize IO.
        self.stop_cleanup_original.as_ref().map(|original|HostRuntimeNativeCustodyViewV2 {
            _stage:NativeCustodyBorrowV2::Cleanup(original),
        }).or_else(||self.argument_stages.iter().find_map(|stage| {
            stage.as_ref().map(|stage| HostRuntimeNativeCustodyViewV2 { _stage: NativeCustodyBorrowV2::Argument(stage) })
        })).or_else(|| {
            let stage = self.launch_original.as_ref()?;
            // After positive scratch disposal the SAME occupied launch capsule
            // still owns its lease/request association and the service keeps
            // its actual Agent. Optional housekeeping must not create an
            // unpriced four-journal observation between admitted operations.
            Some(HostRuntimeNativeCustodyViewV2 {
                _stage: NativeCustodyBorrowV2::Launch(stage),
            })
        })
    }
}
