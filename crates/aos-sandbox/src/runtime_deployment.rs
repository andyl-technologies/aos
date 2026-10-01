//! Retains the fixed deployment publisher's actual original startup custody.
//!
//! The deployment publisher is independent of runtime creation. Its initial
//! PID1/profile OpenFiles, immutable image and enforcing policy, fixed service
//! invocation and kernel cgroup remain local and are rechecked before use.
//! These prerequisites do not initialize NV, create a runtime journal, prove a
//! production guest filter stack or grant public backend readiness.

mod service_policy;
mod startup;
mod genesis;
mod preparation;
mod collector;
mod comparison;
mod invocation;

pub use startup::{
    ProductionRuntimeDeploymentStartupCaptureV1, ProductionRuntimeDeploymentStartupPartsV1,
    ProductionRuntimeDeploymentStartupV1,
};
pub use collector::{
    InstalledCollectorStartupErrorV1, ProductionInstalledCollectorStartupCaptureV1,
    ProductionInstalledCollectorStartupPartsV1, ProductionInstalledCollectorStartupV1,
};
pub use comparison::{
    HeldRuntimeDeploymentAppendComparisonV1, HeldRuntimeDeploymentMainComparisonV1,
    HeldRuntimeDeploymentPairComparisonV1,
    RuntimeDeploymentComparisonErrorV1, RuntimeDeploymentComparisonOriginsV1,
};
pub use crate::journal::RuntimeDeploymentNativeTransactionDataV1;
pub use invocation::{HostPhysicalInvocationErrorV1, HostPhysicalInvocationLeaseV1};

pub(crate) use genesis::VerifiedDeploymentGenesisV1;
pub(crate) use genesis::{
    DIRECTORY as MAIN_DIRECTORY_V1, GENESIS_KEY, MAIN_NAME, NAMESPACE,
    genesis_native_transaction_v1,
};
// Names the existing private role for the original Journal observer; no second
// literal or new role is introduced, and genesis.rs visibility stays unchanged.
pub(crate) const SIDECAR_NAME: &str = genesis::SIDECAR_NAME;
pub(crate) use preparation::{
    MAIN_LIMITS, require_native_step_binding_v1,
    require_current_deployment_rows_v1, require_deployment_main_v1,
    require_deployment_row_bound_v1,
    require_prospective_deployment_append_v1,
};

#[cfg(test)]
pub(crate) use preparation::tests::Fixture as DeploymentHistoryFixtureV1;

pub(crate) const UNIT: &str = "aos-sandbox-runtime-publisher.service";
pub(crate) const SOCKET_UNIT: &str = "aos-sandbox-runtime-publisher.socket";
pub(crate) const OWNER_CONTEXT: &str = "system_u:system_r:aos_runtime_deployment_publisher_t";
pub(crate) const HELPER_CONTEXT: &str = "system_u:system_r:aos_runtime_deployment_helper_t";
pub(crate) const CONTROL_GROUP: &str =
    "/aos.slice/aos-control.slice/aos-sandbox-runtime-publisher.service";
pub(crate) const LISTENER_FD_NAME: &str = "aos-runtime-deployment";
pub(crate) const PID1_FD_NAME: &str = "aos-runtime-deployment-pid1-image";
pub(crate) const PROFILE_FD_NAME: &str = "aos-runtime-deployment-startup-profile";
pub(crate) const SOCKET_PATH: &str = "/run/aos/sandbox/runtime-deployment.sock";

/// Reports rejection of the deployment-only publisher's actual startup.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeDeploymentStartupErrorV1 {
    /// The complete original listener and OpenFile role table differs.
    #[error("deployment publisher original startup roles differ")]
    Activation,
    /// The image-built bounded deployment profile differs.
    #[error("deployment publisher immutable startup profile differs")]
    Profile,
    /// An original immutable image or current executable mapping differs.
    #[error("deployment publisher actual immutable image differs")]
    Image,
    /// The genuine fixed PID1 unit, invocation or kernel cgroup differs.
    #[error("deployment publisher actual fixed-unit custody differs")]
    Service,
    /// The enforcing subject, credentials or empty capability state differs.
    #[error("deployment publisher actual confinement differs")]
    Confinement,
}
