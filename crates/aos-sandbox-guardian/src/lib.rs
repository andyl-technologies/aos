//! Verifies and enforces one assignment's fail-stop ownership deadline.
//!
//! [`GuardianAuthority`] intersects a controller-signed Guardian plan with an
//! ownership-authority-signed lease. The plan's sole arm grant commits the
//! current host boot and the exact lease generation and digest. Admission
//! yields a pending state that must pass [`GuardianStateStore::commit`] before
//! [`ReadinessConfirmedGuardian`] can acknowledge readiness or wait on the absolute
//! `CLOCK_BOOTTIME` deadline.
//!
//! This crate deliberately owns no network listener, capability, storage
//! handle, or general systemd API. A dormant fixed protected owner models
//! early freeze, kernel default-drop, renewal, expiry, and move-only controller
//! handoff; production timers, kernel effects, and controller delivery remain
//! separate work.

mod authority;
mod runtime;
mod state;

pub use aos_sandbox_core::GuardianPlanBinding;
pub use authority::{
    DormantGuardianActionV1, DormantGuardianEffectHandoffV1, DormantGuardianEffectStepV1,
    DormantGuardianProtectedCommitV1, DormantGuardianProtectedOwnerErrorV1,
    DormantGuardianProtectedOwnerV1, GuardianArtifacts, GuardianAssignmentClaim, GuardianAuthority,
    GuardianAuthorityError, PendingGuardianState, ReadinessConfirmedGuardian,
};
pub use runtime::{
    GuardianRuntimeError, PINNED_ACTIVATION_ARGUMENT, ReadyNotifier, exec_pinned_activation,
    run_from_environment,
};
pub use state::{
    DurablyPersistedGuardian, GuardianState, GuardianStateCodecError, GuardianStateStore,
    GuardianStateStoreError,
};
