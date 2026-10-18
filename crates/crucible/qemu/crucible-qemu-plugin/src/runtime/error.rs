//! Typed failures at live plugin registration and runtime publication boundaries.

use super::*;

/// An error produced while registering plugin-owned callbacks.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum OwnedCallbackRegistrationError {
    /// One or more required live callback adapters do not exist yet.
    #[error("required callback adapters are unavailable: {families}")]
    AdaptersUnavailable {
        /// Callback families that still need live QEMU-facing adapters.
        families: &'static str,
    },
    /// The live vCPU-boundary, sim-time, or network callback slice failed.
    #[error("live production callback registration failed: {source}")]
    LiveVcpuTime {
        /// Underlying capability, mapping, or dispatch-state failure.
        source: LiveVcpuTimeCallbackError,
    },
    /// The registrar did not prove every callback required by the selected mode.
    #[error(
        "owned callback registration mask is incomplete: required {required:#06x}, got {actual:#06x}"
    )]
    IncompleteRegistrationMask {
        /// Exact mask required by the launch arguments.
        required: u16,
        /// Mask actually installed by the registrar.
        actual: u16,
    },
}

/// A failure crossing from QEMU's raw install boundary into live registration.
#[derive(Debug, Error)]
pub(crate) enum PluginLiveBoundaryError {
    /// Raw ABI validation or deterministic capability resolution failed.
    #[error("QEMU plugin ABI validation failed: {0}")]
    Abi(#[from] crate::QemuPluginAbiError),
    /// The ordered live registration sequence failed.
    #[error("QEMU plugin live registration failed: {0}")]
    Runtime(#[from] PluginRuntimeInstallError),
}

/// An error produced while building or publishing the live plugin runtime.
#[derive(Debug, Error)]
pub enum PluginRuntimeInstallError {
    /// The original installing Source refused before owning plan decode.
    #[error("original installing Source refused: {source}")]
    StartupSource {
        /// Exact unformatted native status or missing compulsory entry point.
        source: crate::StartupSourceError,
    },
    /// The digest thread did not publish actual registered readiness.
    #[error("fingerprint worker readiness failed: {source}")]
    FingerprintWorkerReadiness {
        /// Same retained worker failure or missing original Setup authority.
        source: LiveVcpuTimeCallbackError,
    },
    /// The lifecycle-aware control stream could not be advanced safely.
    #[error("plugin control lifecycle failed: {source}")]
    ControlLifecycle {
        /// Underlying control lifecycle or frame I/O error.
        source: crucible_qemu_protocol::ControlLifecycleIoError,
    },
    /// The teardown worker could not bind its stable mapped node slot.
    #[error("binding plugin teardown slot failed: {source}")]
    TeardownSlot {
        /// Underlying mapped-region access error.
        source: crucible_qemu_shmem::MappedSetupRegionAccessError,
    },
    /// The lifecycle control worker thread could not be started.
    #[error("spawning plugin run-control worker failed: {source}")]
    ControlWorkerSpawn {
        /// Underlying host thread-creation error.
        source: std::io::Error,
    },
    /// The sole teardown worker thread could not be started.
    #[error("spawning plugin teardown worker failed: {source}")]
    TeardownWorkerSpawn {
        /// Underlying host thread-creation error.
        source: std::io::Error,
    },
    /// A typed registration step failed.
    #[error("live plugin registration failed: {source}")]
    Registration {
        /// Underlying fail-stop sequence error.
        source: PluginRegistrationSequenceError,
    },
    /// The complete required callback set was unavailable.
    #[error("live plugin callback registration failed at RegisterCallbacks: {source}")]
    OwnedCallbacks {
        /// Underlying callback registration error.
        source: OwnedCallbackRegistrationError,
    },
    /// Callback registration state was accessed after ownership was promoted.
    #[error("callback registration state was already promoted")]
    CallbackRegistrationAlreadyPromoted,
    /// Registered callback ownership was required before it was proven.
    #[error("callback registration proof is not available")]
    CallbackRegistrationProofUnavailable,
    /// Setup-time QEMU fault capability admission failed before guest start.
    #[error("live QEMU fault capability admission failed: {source}")]
    FaultCapabilityAdmission {
        /// Exact bridge or QEMU capability failure.
        source: LiveVcpuTimeCallbackError,
    },
    /// The fixed plugin resource manifest could not be represented.
    #[error("plugin resource manifest shape is not representable")]
    ResourceManifestShape,
    /// Actual process-lifetime actors could not be authenticated before native admission.
    #[error("plugin worker identity admission failed: {source}")]
    WorkerIdentityAdmission {
        /// Original startup supervision or actor registration failure.
        source: crate::ram_error::RamError,
    },
    /// QEMU rejected the fixed plugin resource manifest.
    #[error("QEMU rejected the plugin resource manifest with status {status}")]
    ResourceManifestRejected {
        /// Negative errno-style status returned by patched QEMU.
        status: i32,
    },
    /// QEMU rejected the process-lifetime callback-barrier registration.
    #[error("QEMU rejected the hot-fork callback barrier with status {status}")]
    HotForkBarrierRejected {
        /// Negative errno-style QEMU status.
        status: i32,
    },
    /// Native refused registration of the actual parent drain companion.
    #[error("parent park/drain companion registration refused ({status})")]
    ParentParkDrainRejected {
        /// Exact signed native registrar status.
        status: i32,
    },
    /// Native refused registration of the retained checkpoint pager owner.
    #[error("checkpoint pager registration refused ({status})")]
    CheckpointPagerRejected {
        /// Exact signed native registrar status.
        status: i32,
    },
    /// QEMU rejected fork-child runtime reconstruction registration.
    #[error("QEMU rejected the hot-fork child runtime with status {status}")]
    HotForkChildRuntimeRejected {
        /// Negative errno-style QEMU status.
        status: i32,
    },
    /// The callback failure could not be acknowledged to the host.
    #[error(
        "callback registration failed at RegisterCallbacks ({callback_source}); acknowledging that failure also failed: {ack_source}"
    )]
    CallbackFailureAck {
        /// Original callback registration failure.
        callback_source: Box<OwnedCallbackRegistrationError>,
        /// Underlying setup acknowledgement failure.
        ack_source: PluginSetupError,
    },
    /// Callback registration panicked after pinned userdata became observable.
    #[error("live plugin callback registration panicked at RegisterCallbacks")]
    CallbackRegistrationPanicked,
    /// Callback registration panicked and its failure acknowledgement also failed.
    #[error(
        "live plugin callback registration panicked; acknowledging that failure also failed: {ack_source}"
    )]
    CallbackPanicFailureAck {
        /// Underlying setup acknowledgement failure.
        ack_source: PluginSetupError,
    },
    /// A non-panic failure after callback registration could not be acknowledged.
    #[error(
        "post-registration failure ({failure}); acknowledging that failure also failed: {ack_source}"
    )]
    PostRegistrationFailureAck {
        /// Original post-registration failure diagnostic.
        failure: String,
        /// Underlying setup acknowledgement failure.
        ack_source: PluginSetupError,
    },
    /// Installation panicked after callback registration had begun.
    #[error("live plugin installation panicked after callback registration at {stage}")]
    PostRegistrationPanicked {
        /// Registration stage active when the panic was caught.
        stage: &'static str,
    },
    /// A post-registration panic and its failure acknowledgement both failed.
    #[error(
        "live plugin installation panicked after callback registration at {stage}; acknowledging that failure also failed: {ack_source}"
    )]
    PostRegistrationPanicFailureAck {
        /// Registration stage active when the panic was caught.
        stage: &'static str,
        /// Underlying setup acknowledgement failure.
        ack_source: PluginSetupError,
    },
    /// Another install owns, published, or irreversibly failed the singleton slot.
    #[error("the plugin runtime singleton is unavailable: installing, active, or failed")]
    RuntimeAlreadyReserved,
}
