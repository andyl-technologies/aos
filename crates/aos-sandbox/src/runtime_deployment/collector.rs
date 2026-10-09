//! Original fixed collector custody and passive specimen-image admission.
//!
//! The collector has exactly SYS_ADMIN|SYS_PTRACE within its separate reviewed
//! service and MAC principal. Its startup is not a current Host055 permit, a
//! production GuestPID1 observation or backend readiness. Resource creation and
//! launch must still be joined to the genuine publisher's held Prepared floor
//! cut; no scalar profile or historical row can make that authority here.

mod preparation;
mod service_policy;
mod startup;

pub use startup::{
    ProductionInstalledCollectorStartupCaptureV1, ProductionInstalledCollectorStartupPartsV1,
    ProductionInstalledCollectorStartupV1,
};

pub(super) const UNIT: &str = "aos-sandbox-installed-filter-collector.service";
pub(super) const SOCKET_UNIT: &str = "aos-sandbox-installed-filter-collector.socket";
pub(super) const SOCKET_PATH: &str = "/run/aos/sandbox/installed-filter-collector.sock";
pub(super) const CONTEXT: &str = "system_u:system_r:aos_installed_filter_collector_t:s0";
pub(super) const CONTROL_GROUP: &str =
    "/aos.slice/aos-control.slice/aos-sandbox-installed-filter-collector.service";
pub(super) const LISTENER_FD_NAME: &str = "aos-installed-filter-collector";
pub(super) const PID1_FD_NAME: &str = "aos-installed-filter-collector-pid1-image";
pub(super) const PROFILE_FD_NAME: &str = "aos-installed-filter-collector-startup-profile";
pub(super) const CAPABILITIES: u64 = (1 << 19) | (1 << 21);

/// Reports refusal of original fixed collector custody or specimen resources.
#[derive(Debug, thiserror::Error)]
pub enum InstalledCollectorStartupErrorV1 {
    /// The original fixed listener/PID1/profile table differs or is unavailable.
    #[error("installed collector original activation differs")]
    Activation,
    /// The bounded immutable fixed-purpose profile or image closure differs.
    #[error("installed collector immutable profile differs")]
    Profile,
    /// The retained immutable file or actual executable mapping differs.
    #[error("installed collector original immutable image differs")]
    Image,
    /// The original PID1 unit, invocation or live cgroup membership differs.
    #[error("installed collector original fixed-unit custody differs")]
    Service,
    /// Actual MAC, credentials, NNP or the exact two-capability state differs.
    #[error("installed collector actual confinement differs")]
    Confinement,
    /// The physical complete specimen root or independent signed binding differs.
    #[error("installed collector physical specimen template differs")]
    SpecimenRoot,
}
