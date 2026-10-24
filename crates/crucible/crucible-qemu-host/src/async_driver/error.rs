//! Errors produced by the bounded asynchronous QEMU driver.

use super::*;
use std::borrow::Cow;
use thiserror::Error;

/// Error returned by a host-I/O runtime adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuAsyncDriverRuntimeError {
    /// Operation being attempted.
    pub operation: &'static str,
    /// Authored text, borrowed for static diagnostics; typed refusals keep this empty.
    ///
    /// Formatting renders a retained typed cause directly unless a later
    /// combined diagnostic was explicitly saved here.
    pub message: Cow<'static, str>,
    detail: QemuAsyncDriverRuntimeErrorDetail,
    supervision_post: Option<crucible_host_resources::host_supervision::HostSupervisionError>,
}

impl std::fmt::Display for QemuAsyncDriverRuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.detail {
            QemuAsyncDriverRuntimeErrorDetail::HostSupervision(source)
                if self.message.is_empty() =>
            {
                write!(formatter, "{} failed: {source}", self.operation)
            }
            QemuAsyncDriverRuntimeErrorDetail::MappedRegionAccess(source)
                if self.message.is_empty() =>
            {
                write!(formatter, "{} failed: {source}", self.operation)
            }
            QemuAsyncDriverRuntimeErrorDetail::BoundaryAction(source)
                if self.message.is_empty() =>
            {
                write!(formatter, "{} failed: {source}", self.operation)
            }
            QemuAsyncDriverRuntimeErrorDetail::FaultTransport(source)
                if self.message.is_empty() =>
            {
                write!(formatter, "{} failed: {source}", self.operation)
            }
            QemuAsyncDriverRuntimeErrorDetail::FaultEvent(source) if self.message.is_empty() => {
                write!(formatter, "{} failed: {source}", self.operation)
            }
            QemuAsyncDriverRuntimeErrorDetail::NetworkRing(source) if self.message.is_empty() => {
                write!(formatter, "{} failed: {source}", self.operation)
            }
            QemuAsyncDriverRuntimeErrorDetail::NetworkOutputStop {
                sequence,
                source_slot,
                delivery_icount,
                stopped_slot,
                stopped_icount,
            } if self.message.is_empty() => write!(
                formatter,
                "{} failed: frame {sequence} from slot {source_slot} at {delivery_icount} does not match stopped slot {stopped_slot} at {stopped_icount}",
                self.operation,
            ),
            QemuAsyncDriverRuntimeErrorDetail::NodeSlot(source) if self.message.is_empty() => {
                write!(formatter, "{} failed: {source}", self.operation)
            }
            QemuAsyncDriverRuntimeErrorDetail::FingerprintSample(source)
                if self.message.is_empty() =>
            {
                write!(formatter, "{} failed: {source}", self.operation)
            }
            QemuAsyncDriverRuntimeErrorDetail::FaultResultStorage(requested, configured)
                if self.message.is_empty() =>
            {
                write!(
                    formatter,
                    "{} failed: cannot reserve {requested} QEMU fault-result bytes against limit {configured}",
                    self.operation,
                )
            }
            QemuAsyncDriverRuntimeErrorDetail::FaultEventStorage(
                current,
                requested,
                configured,
            ) if self.message.is_empty() => write!(
                formatter,
                "{} failed: cannot stage {requested} QEMU fault event records at current {current} against limit {configured}",
                self.operation,
            ),
            QemuAsyncDriverRuntimeErrorDetail::ResourceLimit(
                field,
                current,
                requested,
                configured,
                hard,
            ) if self.message.is_empty() => write!(
                formatter,
                "{} failed: cannot reserve {requested} units of `{field}` at current {current}; configured {configured}, hard {hard}",
                self.operation,
            ),
            _ => write!(formatter, "{} failed: {}", self.operation, self.message),
        }?;
        if let Some(post) = self.supervision_post {
            write!(
                formatter,
                "; independent host operation postcheck failed: {post}"
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for QemuAsyncDriverRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.detail {
            QemuAsyncDriverRuntimeErrorDetail::HostSupervision(source) => Some(source),
            QemuAsyncDriverRuntimeErrorDetail::MappedRegionAccess(source) => Some(source),
            QemuAsyncDriverRuntimeErrorDetail::BoundaryAction(source) => Some(source),
            QemuAsyncDriverRuntimeErrorDetail::FaultTransport(source) => Some(source),
            QemuAsyncDriverRuntimeErrorDetail::FaultEvent(source) => Some(source),
            QemuAsyncDriverRuntimeErrorDetail::NetworkRing(source) => Some(source),
            QemuAsyncDriverRuntimeErrorDetail::NodeSlot(source) => Some(source),
            QemuAsyncDriverRuntimeErrorDetail::FingerprintSample(source) => Some(source),
            _ => self.supervision_post.as_ref().map(|source| source as _),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum QemuAsyncDriverRuntimeErrorDetail {
    HostSupervision(crucible_host_resources::host_supervision::HostSupervisionError),
    MappedRegionAccess(crucible_qemu_shmem::MappedSetupRegionAccessError),
    BoundaryAction(crucible_qemu_protocol::boundary_action::ActionDecodeError),
    FaultTransport(crucible_qemu_shmem::FaultTransportError),
    FaultEvent(crucible_qemu_shmem::FaultEventError),
    NetworkRing(crucible_qemu_shmem::SpscRingError),
    NetworkOutputStop {
        sequence: u32,
        source_slot: u32,
        delivery_icount: u64,
        stopped_slot: u32,
        stopped_icount: u64,
    },
    NodeSlot(crucible_qemu_shmem::NodeSlotError),
    FingerprintSample(crucible_qemu_shmem::FingerprintSampleError),
    #[default]
    Message,
    FaultResultStorage(u32, u32),
    FaultEventStorage(u64, u64, u64),
    ResourceLimit(&'static str, u64, u64, u64, u64),
}

impl QemuAsyncDriverRuntimeError {
    /// Borrows authored text, returning an empty string for an unformatted cause.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Retains an action observation refusal without allocating diagnostic text.
    #[must_use]
    pub fn boundary_action(
        operation: &'static str,
        source: crucible_qemu_protocol::boundary_action::ActionDecodeError,
    ) -> Self {
        Self {
            operation,
            message: Cow::Borrowed(""),
            detail: QemuAsyncDriverRuntimeErrorDetail::BoundaryAction(source),
            supervision_post: None,
        }
    }

    /// Borrows the action cause independently of a later Original post.
    #[must_use]
    pub const fn boundary_action_source(
        &self,
    ) -> Option<&crucible_qemu_protocol::boundary_action::ActionDecodeError> {
        match &self.detail {
            QemuAsyncDriverRuntimeErrorDetail::BoundaryAction(source) => Some(source),
            _ => None,
        }
    }

    /// Retains a fault transport refusal without allocating diagnostic text.
    #[must_use]
    pub fn fault_transport(
        operation: &'static str,
        source: crucible_qemu_shmem::FaultTransportError,
    ) -> Self {
        Self {
            operation,
            message: Cow::Borrowed(""),
            detail: QemuAsyncDriverRuntimeErrorDetail::FaultTransport(source),
            supervision_post: None,
        }
    }

    /// Borrows the fault transport cause independently of a later Original post.
    #[must_use]
    pub const fn fault_transport_source(
        &self,
    ) -> Option<&crucible_qemu_shmem::FaultTransportError> {
        match &self.detail {
            QemuAsyncDriverRuntimeErrorDetail::FaultTransport(source) => Some(source),
            _ => None,
        }
    }

    /// Retains a fault event refusal without allocating diagnostic text.
    #[must_use]
    pub fn fault_event(
        operation: &'static str,
        source: crucible_qemu_shmem::FaultEventError,
    ) -> Self {
        Self {
            operation,
            message: Cow::Borrowed(""),
            detail: QemuAsyncDriverRuntimeErrorDetail::FaultEvent(source),
            supervision_post: None,
        }
    }

    /// Borrows the fault event cause independently of a later Original post.
    #[must_use]
    pub const fn fault_event_source(&self) -> Option<&crucible_qemu_shmem::FaultEventError> {
        match &self.detail {
            QemuAsyncDriverRuntimeErrorDetail::FaultEvent(source) => Some(source),
            _ => None,
        }
    }

    /// Retains a network ring refusal without allocating diagnostic text.
    #[must_use]
    pub fn network_ring(
        operation: &'static str,
        source: crucible_qemu_shmem::SpscRingError,
    ) -> Self {
        Self {
            operation,
            message: Cow::Borrowed(""),
            detail: QemuAsyncDriverRuntimeErrorDetail::NetworkRing(source),
            supervision_post: None,
        }
    }

    /// Borrows the ring cause independently of a later Original post.
    #[must_use]
    pub const fn network_ring_source(&self) -> Option<&crucible_qemu_shmem::SpscRingError> {
        match &self.detail {
            QemuAsyncDriverRuntimeErrorDetail::NetworkRing(source) => Some(source),
            _ => None,
        }
    }

    /// Retains the observed head and physical stop without consuming either.
    pub(crate) fn network_output_stop(
        frame: &crucible_qemu_shmem::FrameEntry,
        stopped_slot: u32,
        stopped_icount: u64,
    ) -> Self {
        Self {
            operation: "observe network output stop",
            message: Cow::Borrowed(""),
            detail: QemuAsyncDriverRuntimeErrorDetail::NetworkOutputStop {
                sequence: frame.seq,
                source_slot: frame.src_node,
                delivery_icount: frame.delivery_icount,
                stopped_slot,
                stopped_icount,
            },
            supervision_post: None,
        }
    }

    /// Returns the frame sequence, source slot and icount, then stopped slot and icount.
    ///
    /// These retained observations grant no frame ownership or completion authority.
    #[must_use]
    pub const fn network_output_stop_coordinates(&self) -> Option<(u32, u32, u64, u32, u64)> {
        match &self.detail {
            QemuAsyncDriverRuntimeErrorDetail::NetworkOutputStop {
                sequence,
                source_slot,
                delivery_icount,
                stopped_slot,
                stopped_icount,
            } => Some((
                *sequence,
                *source_slot,
                *delivery_icount,
                *stopped_slot,
                *stopped_icount,
            )),
            _ => None,
        }
    }

    /// Retains a node publication refusal without allocating diagnostic text.
    #[must_use]
    pub fn node_slot(operation: &'static str, source: crucible_qemu_shmem::NodeSlotError) -> Self {
        Self {
            operation,
            message: Cow::Borrowed(""),
            detail: QemuAsyncDriverRuntimeErrorDetail::NodeSlot(source),
            supervision_post: None,
        }
    }

    /// Borrows the node publication cause independently of a later Original post.
    #[must_use]
    pub const fn node_slot_source(&self) -> Option<&crucible_qemu_shmem::NodeSlotError> {
        match &self.detail {
            QemuAsyncDriverRuntimeErrorDetail::NodeSlot(source) => Some(source),
            _ => None,
        }
    }

    /// Retains a fingerprint refusal without allocating diagnostic text.
    #[must_use]
    pub fn fingerprint_sample(
        operation: &'static str,
        source: crucible_qemu_shmem::FingerprintSampleError,
    ) -> Self {
        Self {
            operation,
            message: Cow::Borrowed(""),
            detail: QemuAsyncDriverRuntimeErrorDetail::FingerprintSample(source),
            supervision_post: None,
        }
    }

    /// Borrows the fingerprint cause independently of a later Original post.
    #[must_use]
    pub const fn fingerprint_sample_source(
        &self,
    ) -> Option<&crucible_qemu_shmem::FingerprintSampleError> {
        match &self.detail {
            QemuAsyncDriverRuntimeErrorDetail::FingerprintSample(source) => Some(source),
            _ => None,
        }
    }

    /// Retains a mapped-region refusal without formatting another diagnostic.
    #[must_use]
    pub fn mapped_region_access(
        operation: &'static str,
        source: crucible_qemu_shmem::MappedSetupRegionAccessError,
    ) -> Self {
        Self {
            operation,
            message: Cow::Borrowed(""),
            detail: QemuAsyncDriverRuntimeErrorDetail::MappedRegionAccess(source),
            supervision_post: None,
        }
    }

    /// Borrows the original mapped-region refusal independently of a later post.
    #[must_use]
    pub const fn mapped_region_access_source(
        &self,
    ) -> Option<&crucible_qemu_shmem::MappedSetupRegionAccessError> {
        match &self.detail {
            QemuAsyncDriverRuntimeErrorDetail::MappedRegionAccess(source) => Some(source),
            _ => None,
        }
    }

    /// Retains a typed host operational deadline, cancellation, or ownership failure.
    #[must_use]
    pub fn operational_supervision(
        operation: &'static str,
        source: crucible_host_resources::host_supervision::HostSupervisionError,
    ) -> Self {
        Self {
            operation,
            // The typed cause already owns every diagnostic coordinate. Render
            // it only when requested; exhaustion must not format another String.
            message: Cow::Borrowed(""),
            detail: QemuAsyncDriverRuntimeErrorDetail::HostSupervision(source),
            supervision_post: None,
        }
    }

    /// Returns the host operational failure independently of guest verdicts.
    #[must_use]
    pub const fn operational_supervision_source(
        &self,
    ) -> Option<crucible_host_resources::host_supervision::HostSupervisionError> {
        match &self.detail {
            QemuAsyncDriverRuntimeErrorDetail::HostSupervision(source) => Some(*source),
            _ => None,
        }
    }

    /// Returns the first independently observed Original postcheck failure.
    ///
    /// The initiating adapter failure remains available through its original
    /// message, typed coordinates and source. This observation never completes
    /// the operation or returns any process, pending-quantum or Source custody.
    #[must_use]
    pub const fn operational_supervision_post(
        &self,
    ) -> Option<crucible_host_resources::host_supervision::HostSupervisionError> {
        self.supervision_post
    }

    pub(crate) const fn with_operational_supervision_post(
        mut self,
        source: crucible_host_resources::host_supervision::HostSupervisionError,
    ) -> Self {
        // Propagation must never overwrite an already retained post failure.
        if self.supervision_post.is_none() {
            self.supervision_post = Some(source);
        }
        self
    }

    /// Creates a runtime adapter error, borrowing static diagnostic text.
    ///
    /// Existing owned diagnostics move into the error without copying. This
    /// constructor supplies no funding for a dynamically formatted message.
    #[must_use]
    pub fn new(operation: &'static str, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            operation,
            message: message.into(),
            detail: QemuAsyncDriverRuntimeErrorDetail::Message,
            supervision_post: None,
        }
    }

    /// Creates an exact PREPARE result allocation failure.
    #[must_use]
    pub fn fault_result_storage(requested: usize, configured: usize) -> Self {
        Self {
            operation: "reserve fault preparation result",
            // This constructor is itself used after allocation refusal. Keep
            // its diagnostic storage empty so propagating typed LIMIT-2 never
            // attempts another heap allocation.
            message: Cow::Borrowed(""),
            detail: QemuAsyncDriverRuntimeErrorDetail::FaultResultStorage(
                u32::try_from(requested).unwrap_or(u32::MAX),
                u32::try_from(configured).unwrap_or(u32::MAX),
            ),
            supervision_post: None,
        }
    }

    /// Creates an allocation-free fault-event staging limit failure.
    #[must_use]
    pub fn fault_event_storage(current: usize, requested: usize, configured: usize) -> Self {
        Self {
            operation: "stage fault occurrence event",
            message: Cow::Borrowed(""),
            detail: QemuAsyncDriverRuntimeErrorDetail::FaultEventStorage(
                u64::try_from(current).unwrap_or(u64::MAX),
                u64::try_from(requested).unwrap_or(u64::MAX),
                u64::try_from(configured).unwrap_or(u64::MAX),
            ),
            supervision_post: None,
        }
    }

    /// Creates an allocation-free scenario resource-limit failure.
    #[must_use]
    pub const fn resource_limit(
        field: &'static str,
        current: u64,
        requested: u64,
        configured: u64,
        hard: u64,
    ) -> Self {
        Self {
            operation: "reserve host I/O resource",
            message: Cow::Borrowed(""),
            detail: QemuAsyncDriverRuntimeErrorDetail::ResourceLimit(
                field, current, requested, configured, hard,
            ),
            supervision_post: None,
        }
    }

    /// Returns an exact PREPARE result-storage refusal, when present.
    #[must_use]
    pub const fn fault_result_storage_coordinates(&self) -> Option<(u32, u32)> {
        match &self.detail {
            QemuAsyncDriverRuntimeErrorDetail::FaultResultStorage(requested, configured) => {
                Some((*requested, *configured))
            }
            _ => None,
        }
    }

    /// Returns an exact fault-event staging refusal, when present.
    #[must_use]
    pub const fn fault_event_storage_coordinates(&self) -> Option<(u64, u64, u64)> {
        match &self.detail {
            QemuAsyncDriverRuntimeErrorDetail::FaultEventStorage(
                current,
                requested,
                configured,
            ) => Some((*current, *requested, *configured)),
            _ => None,
        }
    }

    /// Returns an exact scenario resource refusal, when present.
    #[must_use]
    pub const fn resource_limit_coordinates(&self) -> Option<(&'static str, u64, u64, u64, u64)> {
        match &self.detail {
            QemuAsyncDriverRuntimeErrorDetail::ResourceLimit(
                field,
                current,
                requested,
                configured,
                hard,
            ) => Some((*field, *current, *requested, *configured, *hard)),
            _ => None,
        }
    }
}

/// Error returned by a node-step target adapter.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{operation} failed: {message}")]
pub struct QemuAsyncDriverTargetError {
    /// Operation being attempted.
    pub operation: &'static str,
    /// Deterministic failure detail.
    pub message: String,
}

impl QemuAsyncDriverTargetError {
    /// Creates a target adapter error.
    #[must_use]
    pub fn new(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            operation,
            message: message.into(),
        }
    }
}

/// Error returned by the bounded async driver.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QemuAsyncDriverError {
    /// A retained host service failed before a guest result could be committed.
    #[error("QEMU operational service failed: {0}")]
    OperationalHealth(#[source] QemuAsyncDriverHealthError),
    /// A host-I/O await timeout was zero.
    #[error("QEMU async driver wait {wait:?} has a zero timeout")]
    UnboundedAwait {
        /// Wait class with no timeout budget.
        wait: QemuAsyncWait,
    },
    /// A runtime adapter operation failed.
    #[error("QEMU async runtime failed: {0}")]
    Runtime(QemuAsyncDriverRuntimeError),
    /// A node-step target operation failed.
    #[error("QEMU async target failed: {0}")]
    Target(QemuAsyncDriverTargetError),
    /// A shared-memory channel operation failed.
    #[error("QEMU async shared-memory channel failed: {0}")]
    Channel(QemuNodeChannelError),
    /// A channel refused before the same retained Original independently refused.
    #[error(
        "QEMU async shared-memory channel failed: {source}; independent Original post: {original_after}"
    )]
    ChannelOriginalPost {
        /// Initiating channel failure, retaining its original diagnostic storage.
        #[source]
        source: QemuNodeChannelError,
        /// Independent observation of the same entered operation after return.
        original_after: crucible_host_resources::host_supervision::HostSupervisionError,
    },
    /// Lifecycle helper was asked to run the per-quantum completion wait.
    #[error("QEMU async lifecycle helper cannot await quantum completion")]
    LifecycleAdvanceWait,
    /// A non-shared-memory operation appeared in a quantum hot path.
    #[error("QEMU async quantum hot path used forbidden plane {plane:?}")]
    ForbiddenHotPathOperation {
        /// Forbidden operation plane.
        plane: QemuQuantumOperationPlane,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };
    use crucible_host_resources::test_support::TestAllocationObserver;

    #[test]
    fn actual_original_refusal_retains_typed_diagnostic_without_allocating()
    -> Result<(), Box<dyn std::error::Error>> {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let original = supervisor.begin(HostOperationClass::Quantum)?;
        supervisor.cancel()?;
        let source = original
            .wait_slice()
            .expect_err("actual Original is canceled");

        let (error, counts) = TestAllocationObserver::count(|| {
            QemuAsyncDriverRuntimeError::operational_supervision("quantum wait", source)
        });

        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(error.message.is_empty());
        assert_eq!(error.operational_supervision_source(), Some(source));
        assert_eq!(error.to_string(), format!("quantum wait failed: {source}"));
        assert_eq!(
            std::error::Error::source(&error).and_then(|cause| {
                cause.downcast_ref::<
                    crucible_host_resources::host_supervision::HostSupervisionError,
                >()
            }),
            Some(&source),
        );
        Ok(())
    }

    struct DiagnosticBuffer {
        bytes: [u8; 512],
        length: usize,
    }

    impl std::fmt::Write for DiagnosticBuffer {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            let end = self.length.checked_add(text.len()).ok_or(std::fmt::Error)?;
            self.bytes
                .get_mut(self.length..end)
                .ok_or(std::fmt::Error)?
                .copy_from_slice(text.as_bytes());
            self.length = end;
            Ok(())
        }
    }

    #[test]
    fn resource_refusals_render_saved_coordinates_without_allocating() {
        use std::fmt::Write as _;
        use crucible_host_resources::host_supervision::HostSupervisionError;

        for (mut error, expected) in [
            (
                QemuAsyncDriverRuntimeError::fault_result_storage(5, 7),
                "reserve fault preparation result failed: cannot reserve 5 QEMU fault-result bytes against limit 7",
            ),
            (
                QemuAsyncDriverRuntimeError::fault_event_storage(3, 5, 7),
                "stage fault occurrence event failed: cannot stage 5 QEMU fault event records at current 3 against limit 7",
            ),
            (
                QemuAsyncDriverRuntimeError::resource_limit("storage_request_bytes", 3, 5, 7, 11),
                "reserve host I/O resource failed: cannot reserve 5 units of `storage_request_bytes` at current 3; configured 7, hard 11",
            ),
        ] {
            let mut diagnostic = DiagnosticBuffer {
                bytes: [0; 512],
                length: 0,
            };

            let (result, counts) =
                TestAllocationObserver::count(|| write!(&mut diagnostic, "{error}"));

            result.unwrap();
            assert_eq!(counts.allocations, 0);
            assert_eq!(counts.reallocations, 0);
            assert_eq!(&diagnostic.bytes[..diagnostic.length], expected.as_bytes());
            assert!(error.message().is_empty());

            let detail = error.detail.clone();
            error = error.with_operational_supervision_post(HostSupervisionError::InvalidBudget);
            let expected_with_post = format!(
                "{expected}; independent host operation postcheck failed: invalid host operation budget"
            );
            diagnostic.length = 0;

            let (result, counts) =
                TestAllocationObserver::count(|| write!(&mut diagnostic, "{error}"));

            result.unwrap();
            assert_eq!(counts.allocations, 0);
            assert_eq!(counts.reallocations, 0);
            assert_eq!(
                &diagnostic.bytes[..diagnostic.length],
                expected_with_post.as_bytes()
            );
            assert_eq!(error.detail, detail);
            assert_eq!(
                error.operational_supervision_post(),
                Some(HostSupervisionError::InvalidBudget)
            );

            error.message = Cow::Borrowed("authored backend detail");
            assert_eq!(
                error.to_string(),
                format!(
                    "{} failed: authored backend detail; independent host operation postcheck failed: invalid host operation budget",
                    error.operation
                )
            );
        }
    }

    #[test]
    fn authored_runtime_diagnostic_keeps_its_actual_owned_text() {
        let message = String::from("actual adapter refusal");
        let pointer = message.as_ptr();

        let (error, counts) = TestAllocationObserver::count(|| {
            QemuAsyncDriverRuntimeError::new("adapter wait", message)
        });

        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert_eq!(error.message.as_ptr(), pointer);
        assert!(matches!(error.message, Cow::Owned(_)));
        assert_eq!(
            error.to_string(),
            "adapter wait failed: actual adapter refusal"
        );
        assert_eq!(error.operational_supervision_source(), None);
    }
}
