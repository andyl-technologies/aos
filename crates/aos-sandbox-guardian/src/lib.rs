//! Verifies and enforces one assignment's fail-stop ownership deadline.
//!
//! [`GuardianAuthority`] intersects a controller-signed Guardian plan with an
//! ownership-authority-signed lease. The plan's sole arm grant commits the
//! current host boot and the exact lease generation and digest. Admission
//! yields a pending state that must pass [`GuardianStateStore::commit`] before
//! [`ReadinessConfirmedGuardian`] can acknowledge readiness or wait on the absolute
//! `CLOCK_BOOTTIME` deadline.
//!
//! This foundation deliberately owns no network listener, capability, storage
//! handle, or general systemd API. Early freeze, kernel default-drop, renewal,
//! and controller delivery are separate work.

mod authority;
mod runtime;
mod state;

pub use authority::{
    GuardianArtifacts, GuardianAuthority, GuardianAuthorityError, GuardianPlanBinding,
    PendingGuardianState, ReadinessConfirmedGuardian,
};
pub use runtime::{GuardianRuntimeError, ReadyNotifier, run_from_environment};
pub use state::{
    DurablyPersistedGuardian, GuardianState, GuardianStateCodecError, GuardianStateStore,
    GuardianStateStoreError,
};
