//! Closed, bounded-cardinality portable sandbox metric observations.
//!
//! This module defines metric names and validates samples. It deliberately
//! contains no recorder, exporter, global registry, or production
//! instrumentation.

use std::cmp::Ordering;
use std::collections::BTreeSet;

/// Maximum samples accepted in one portable observation batch.
pub const MAXIMUM_METRIC_OBSERVATIONS: usize = 4_096;
/// Maximum distinct project labels accepted in one batch.
pub const MAXIMUM_METRIC_PROJECTS: usize = 128;
/// Maximum distinct node labels accepted in one batch.
pub const MAXIMUM_METRIC_NODES: usize = 256;
/// Maximum labels attached to one metric sample.
pub const MAXIMUM_LABELS_PER_OBSERVATION: usize = 5;

/// Identifies every portable RFC-0021 metric family by its exact name.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SandboxMetricNameV1 {
    /// Counts sandboxes by phase.
    SandboxResources,
    /// Counts executions by phase.
    Executions,
    /// Counts reconciliation attempts.
    ReconcileAttempts,
    /// Observes reconciliation duration.
    ReconcileDuration,
    /// Counts reconciliation conflicts.
    ReconcileConflicts,
    /// Counts fencing failures.
    FencingFailures,
    /// Counts residual resources.
    ResidualResources,
    /// Observes ownership-lease renewal margin.
    LeaseRenewalMargin,
    /// Observes guardian containment latency after expiry or death.
    GuardianContainmentLatency,
    /// Counts stale cleanup denials.
    StaleCleanupDenials,
    /// Observes create-to-ready latency.
    CreateToReadyLatency,
    /// Observes execution start latency.
    ExecutionStartLatency,
    /// Observes freeze latency.
    FreezeLatency,
    /// Observes snapshot latency.
    SnapshotLatency,
    /// Observes resume latency.
    ResumeLatency,
    /// Observes delete latency.
    DeleteLatency,
    /// Counts active native attachments.
    NativeAttachments,
    /// Counts active FUSE attachments.
    FuseAttachments,
    /// Observes attachment replacement duration.
    AttachmentReplacementDuration,
    /// Observes attachment detach duration.
    AttachmentDetachDuration,
    /// Counts FUSE requests.
    FuseRequests,
    /// Counts FUSE queue-congestion observations.
    FuseQueueCongestion,
    /// Counts FUSE request errors.
    FuseErrors,
    /// Counts FUSE forget operations.
    FuseForgets,
    /// Counts open FUSE handles.
    FuseOpenHandles,
    /// Counts registered FUSE backing files.
    FuseRegisteredBackingFiles,
    /// Counts FUSE fallback bytes.
    FuseFallbackBytes,
    /// Counts FUSE worker restarts.
    FuseWorkerRestarts,
    /// Reports structural-index mapped bytes.
    StructuralIndexMappedBytes,
    /// Reports structural-index resident bytes.
    StructuralIndexResidentBytes,
    /// Counts structural-index nodes touched.
    StructuralIndexNodesTouched,
    /// Counts structural-index rebuilds.
    StructuralIndexRebuilds,
    /// Reports logical cache bytes.
    CacheLogicalBytes,
    /// Reports measurable physical cache residency.
    CachePhysicalResidentBytes,
    /// Reports objects by closed cache residency profile.
    CacheResidencyProfileObjects,
    /// Counts cache authorization leases.
    CacheAuthorizationLeases,
    /// Counts cache kernel pins.
    CacheKernelPins,
    /// Counts avoided duplicate cache realizations.
    CacheDuplicateAvoidance,
    /// Counts cache evictions.
    CacheEvictions,
    /// Reports cgroup CPU time.
    CgroupCpuNanoseconds,
    /// Reports cgroup memory bytes.
    CgroupMemoryBytes,
    /// Reports cgroup swap bytes.
    CgroupSwapBytes,
    /// Reports cgroup I/O bytes.
    CgroupIoBytes,
    /// Reports cgroup PID count.
    CgroupPids,
    /// Reports cgroup pressure stall time.
    CgroupPressureNanoseconds,
    /// Counts cgroup OOM events.
    CgroupOomEvents,
    /// Reports operation-scope CPU time.
    OperationCpuNanoseconds,
    /// Reports operation-scope memory bytes.
    OperationMemoryBytes,
    /// Reports operation-scope PID count.
    OperationPids,
    /// Reports operation-scope I/O bytes.
    OperationIoBytes,
    /// Reports operation-scope network bytes.
    OperationNetworkBytes,
    /// Reports operation-scope log bytes.
    OperationLogBytes,
    /// Reports operation-scope staging bytes.
    OperationStagingBytes,
    /// Counts operation cancellations.
    OperationCancellations,
    /// Reports operation output bytes.
    OperationOutputBytes,
    /// Reports ZFS ARC size.
    ZfsArcSizeBytes,
    /// Reports ZFS ARC metadata bytes.
    ZfsArcMetadataBytes,
    /// Reports ZFS ARC data bytes.
    ZfsArcDataBytes,
    /// Counts ZFS ARC hits.
    ZfsArcHits,
    /// Counts ZFS ARC misses.
    ZfsArcMisses,
    /// Reports ZFS ARC dirty bytes.
    ZfsArcDirtyBytes,
    /// Counts ZFS ARC reclaim events.
    ZfsArcReclaims,
    /// Reports the configured ZFS ARC maximum.
    ZfsArcConfiguredMaximumBytes,
    /// Reports ZFS ARC pressure interactions.
    ZfsArcPressureNanoseconds,
    /// Reports ZFS referenced bytes.
    ZfsReferencedBytes,
    /// Reports ZFS logical bytes.
    ZfsLogicalBytes,
    /// Counts ZFS quota failures.
    ZfsQuotaFailures,
    /// Counts ZFS snapshot holds.
    ZfsSnapshotHolds,
    /// Reports ZFS clone-lineage depth.
    ZfsCloneLineageDepth,
    /// Counts leaked or mismatched namespaces.
    ReconciliationNamespaceMismatches,
    /// Counts leaked or mismatched mounts.
    ReconciliationMountMismatches,
    /// Counts leaked or mismatched service-manager units.
    ReconciliationUnitMismatches,
    /// Counts leaked or mismatched datasets.
    ReconciliationDatasetMismatches,
    /// Counts leaked or mismatched leases.
    ReconciliationLeaseMismatches,
    /// Counts leaked or mismatched allocation records.
    ReconciliationAllocationMismatches,
}

impl SandboxMetricNameV1 {
    /// Returns the exact stable metric family name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SandboxResources => "aos_sandbox_resources",
            Self::Executions => "aos_sandbox_executions",
            Self::ReconcileAttempts => "aos_sandbox_reconcile_attempts_total",
            Self::ReconcileDuration => "aos_sandbox_reconcile_duration_nanoseconds",
            Self::ReconcileConflicts => "aos_sandbox_reconcile_conflicts_total",
            Self::FencingFailures => "aos_sandbox_fencing_failures_total",
            Self::ResidualResources => "aos_sandbox_residual_resources",
            Self::LeaseRenewalMargin => "aos_sandbox_lease_renewal_margin_nanoseconds",
            Self::GuardianContainmentLatency => {
                "aos_sandbox_guardian_containment_latency_nanoseconds"
            }
            Self::StaleCleanupDenials => "aos_sandbox_stale_cleanup_denials_total",
            Self::CreateToReadyLatency => "aos_sandbox_create_to_ready_latency_nanoseconds",
            Self::ExecutionStartLatency => "aos_sandbox_execution_start_latency_nanoseconds",
            Self::FreezeLatency => "aos_sandbox_freeze_latency_nanoseconds",
            Self::SnapshotLatency => "aos_sandbox_snapshot_latency_nanoseconds",
            Self::ResumeLatency => "aos_sandbox_resume_latency_nanoseconds",
            Self::DeleteLatency => "aos_sandbox_delete_latency_nanoseconds",
            Self::NativeAttachments => "aos_sandbox_native_attachments",
            Self::FuseAttachments => "aos_sandbox_fuse_attachments",
            Self::AttachmentReplacementDuration => {
                "aos_sandbox_attachment_replacement_duration_nanoseconds"
            }
            Self::AttachmentDetachDuration => "aos_sandbox_attachment_detach_duration_nanoseconds",
            Self::FuseRequests => "aos_sandbox_fuse_requests_total",
            Self::FuseQueueCongestion => "aos_sandbox_fuse_queue_congestion_total",
            Self::FuseErrors => "aos_sandbox_fuse_errors_total",
            Self::FuseForgets => "aos_sandbox_fuse_forgets_total",
            Self::FuseOpenHandles => "aos_sandbox_fuse_open_handles",
            Self::FuseRegisteredBackingFiles => "aos_sandbox_fuse_registered_backing_files",
            Self::FuseFallbackBytes => "aos_sandbox_fuse_fallback_bytes_total",
            Self::FuseWorkerRestarts => "aos_sandbox_fuse_worker_restarts_total",
            Self::StructuralIndexMappedBytes => "aos_sandbox_structural_index_mapped_bytes",
            Self::StructuralIndexResidentBytes => "aos_sandbox_structural_index_resident_bytes",
            Self::StructuralIndexNodesTouched => "aos_sandbox_structural_index_nodes_touched_total",
            Self::StructuralIndexRebuilds => "aos_sandbox_structural_index_rebuilds_total",
            Self::CacheLogicalBytes => "aos_sandbox_cache_logical_bytes",
            Self::CachePhysicalResidentBytes => "aos_sandbox_cache_physical_resident_bytes",
            Self::CacheResidencyProfileObjects => "aos_sandbox_cache_residency_profile_objects",
            Self::CacheAuthorizationLeases => "aos_sandbox_cache_authorization_leases",
            Self::CacheKernelPins => "aos_sandbox_cache_kernel_pins",
            Self::CacheDuplicateAvoidance => "aos_sandbox_cache_duplicate_avoidance_total",
            Self::CacheEvictions => "aos_sandbox_cache_evictions_total",
            Self::CgroupCpuNanoseconds => "aos_sandbox_cgroup_cpu_nanoseconds_total",
            Self::CgroupMemoryBytes => "aos_sandbox_cgroup_memory_bytes",
            Self::CgroupSwapBytes => "aos_sandbox_cgroup_swap_bytes",
            Self::CgroupIoBytes => "aos_sandbox_cgroup_io_bytes_total",
            Self::CgroupPids => "aos_sandbox_cgroup_pids",
            Self::CgroupPressureNanoseconds => "aos_sandbox_cgroup_pressure_nanoseconds_total",
            Self::CgroupOomEvents => "aos_sandbox_cgroup_oom_events_total",
            Self::OperationCpuNanoseconds => "aos_sandbox_operation_cpu_nanoseconds_total",
            Self::OperationMemoryBytes => "aos_sandbox_operation_memory_bytes",
            Self::OperationPids => "aos_sandbox_operation_pids",
            Self::OperationIoBytes => "aos_sandbox_operation_io_bytes_total",
            Self::OperationNetworkBytes => "aos_sandbox_operation_network_bytes_total",
            Self::OperationLogBytes => "aos_sandbox_operation_log_bytes_total",
            Self::OperationStagingBytes => "aos_sandbox_operation_staging_bytes",
            Self::OperationCancellations => "aos_sandbox_operation_cancellations_total",
            Self::OperationOutputBytes => "aos_sandbox_operation_output_bytes_total",
            Self::ZfsArcSizeBytes => "aos_sandbox_zfs_arc_size_bytes",
            Self::ZfsArcMetadataBytes => "aos_sandbox_zfs_arc_metadata_bytes",
            Self::ZfsArcDataBytes => "aos_sandbox_zfs_arc_data_bytes",
            Self::ZfsArcHits => "aos_sandbox_zfs_arc_hits_total",
            Self::ZfsArcMisses => "aos_sandbox_zfs_arc_misses_total",
            Self::ZfsArcDirtyBytes => "aos_sandbox_zfs_arc_dirty_bytes",
            Self::ZfsArcReclaims => "aos_sandbox_zfs_arc_reclaims_total",
            Self::ZfsArcConfiguredMaximumBytes => "aos_sandbox_zfs_arc_configured_maximum_bytes",
            Self::ZfsArcPressureNanoseconds => "aos_sandbox_zfs_arc_pressure_nanoseconds_total",
            Self::ZfsReferencedBytes => "aos_sandbox_zfs_referenced_bytes",
            Self::ZfsLogicalBytes => "aos_sandbox_zfs_logical_bytes",
            Self::ZfsQuotaFailures => "aos_sandbox_zfs_quota_failures_total",
            Self::ZfsSnapshotHolds => "aos_sandbox_zfs_snapshot_holds",
            Self::ZfsCloneLineageDepth => "aos_sandbox_zfs_clone_lineage_depth",
            Self::ReconciliationNamespaceMismatches => {
                "aos_sandbox_reconciliation_namespace_mismatches"
            }
            Self::ReconciliationMountMismatches => "aos_sandbox_reconciliation_mount_mismatches",
            Self::ReconciliationUnitMismatches => "aos_sandbox_reconciliation_unit_mismatches",
            Self::ReconciliationDatasetMismatches => {
                "aos_sandbox_reconciliation_dataset_mismatches"
            }
            Self::ReconciliationLeaseMismatches => "aos_sandbox_reconciliation_lease_mismatches",
            Self::ReconciliationAllocationMismatches => {
                "aos_sandbox_reconciliation_allocation_mismatches"
            }
        }
    }

    pub(crate) fn from_stable_name(value: &str) -> Option<Self> {
        ALL_SANDBOX_METRIC_NAMES_V1
            .iter()
            .copied()
            .find(|name| name.as_str() == value)
    }

    /// Returns the required numeric interpretation for this family.
    #[must_use]
    pub const fn value_kind(self) -> MetricValueKindV1 {
        match self {
            Self::ReconcileDuration
            | Self::LeaseRenewalMargin
            | Self::GuardianContainmentLatency
            | Self::CreateToReadyLatency
            | Self::ExecutionStartLatency
            | Self::FreezeLatency
            | Self::SnapshotLatency
            | Self::ResumeLatency
            | Self::DeleteLatency
            | Self::AttachmentReplacementDuration
            | Self::AttachmentDetachDuration => MetricValueKindV1::DurationNanoseconds,
            Self::ReconcileAttempts
            | Self::ReconcileConflicts
            | Self::FencingFailures
            | Self::StaleCleanupDenials
            | Self::FuseRequests
            | Self::FuseQueueCongestion
            | Self::FuseErrors
            | Self::FuseForgets
            | Self::FuseFallbackBytes
            | Self::FuseWorkerRestarts
            | Self::StructuralIndexNodesTouched
            | Self::StructuralIndexRebuilds
            | Self::CacheDuplicateAvoidance
            | Self::CacheEvictions
            | Self::CgroupCpuNanoseconds
            | Self::CgroupIoBytes
            | Self::CgroupPressureNanoseconds
            | Self::CgroupOomEvents
            | Self::OperationCpuNanoseconds
            | Self::OperationIoBytes
            | Self::OperationNetworkBytes
            | Self::OperationLogBytes
            | Self::OperationCancellations
            | Self::OperationOutputBytes
            | Self::ZfsArcHits
            | Self::ZfsArcMisses
            | Self::ZfsArcReclaims
            | Self::ZfsArcPressureNanoseconds
            | Self::ZfsQuotaFailures => MetricValueKindV1::Counter,
            _ => MetricValueKindV1::Gauge,
        }
    }

    /// Reports whether one bounded label key is legal for this family.
    #[must_use]
    pub const fn permits_label(self, key: MetricLabelKeyV1) -> bool {
        match key {
            MetricLabelKeyV1::Project => !matches!(
                self,
                Self::ZfsArcSizeBytes
                    | Self::ZfsArcMetadataBytes
                    | Self::ZfsArcDataBytes
                    | Self::ZfsArcHits
                    | Self::ZfsArcMisses
                    | Self::ZfsArcDirtyBytes
                    | Self::ZfsArcReclaims
                    | Self::ZfsArcConfiguredMaximumBytes
                    | Self::ZfsArcPressureNanoseconds
            ),
            MetricLabelKeyV1::Backend => !matches!(
                self,
                Self::LeaseRenewalMargin
                    | Self::GuardianContainmentLatency
                    | Self::StaleCleanupDenials
            ),
            MetricLabelKeyV1::Node => true,
            MetricLabelKeyV1::StatusClass => {
                self.is_operation_scope()
                    || matches!(
                        self,
                        Self::SandboxResources
                            | Self::Executions
                            | Self::ReconcileAttempts
                            | Self::ReconcileConflicts
                            | Self::FencingFailures
                            | Self::ResidualResources
                            | Self::ReconciliationNamespaceMismatches
                            | Self::ReconciliationMountMismatches
                            | Self::ReconciliationUnitMismatches
                            | Self::ReconciliationDatasetMismatches
                            | Self::ReconciliationLeaseMismatches
                            | Self::ReconciliationAllocationMismatches
                    )
            }
            MetricLabelKeyV1::CapabilityProfile => matches!(
                self,
                Self::SandboxResources
                    | Self::Executions
                    | Self::CreateToReadyLatency
                    | Self::ExecutionStartLatency
                    | Self::FreezeLatency
                    | Self::SnapshotLatency
                    | Self::ResumeLatency
                    | Self::DeleteLatency
                    | Self::NativeAttachments
                    | Self::FuseAttachments
                    | Self::CacheResidencyProfileObjects
            ),
        }
    }

    const fn is_operation_scope(self) -> bool {
        matches!(
            self,
            Self::OperationCpuNanoseconds
                | Self::OperationMemoryBytes
                | Self::OperationPids
                | Self::OperationIoBytes
                | Self::OperationNetworkBytes
                | Self::OperationLogBytes
                | Self::OperationStagingBytes
                | Self::OperationCancellations
                | Self::OperationOutputBytes
        )
    }
}

const ALL_SANDBOX_METRIC_NAMES_V1: &[SandboxMetricNameV1] = &[
    SandboxMetricNameV1::SandboxResources,
    SandboxMetricNameV1::Executions,
    SandboxMetricNameV1::ReconcileAttempts,
    SandboxMetricNameV1::ReconcileDuration,
    SandboxMetricNameV1::ReconcileConflicts,
    SandboxMetricNameV1::FencingFailures,
    SandboxMetricNameV1::ResidualResources,
    SandboxMetricNameV1::LeaseRenewalMargin,
    SandboxMetricNameV1::GuardianContainmentLatency,
    SandboxMetricNameV1::StaleCleanupDenials,
    SandboxMetricNameV1::CreateToReadyLatency,
    SandboxMetricNameV1::ExecutionStartLatency,
    SandboxMetricNameV1::FreezeLatency,
    SandboxMetricNameV1::SnapshotLatency,
    SandboxMetricNameV1::ResumeLatency,
    SandboxMetricNameV1::DeleteLatency,
    SandboxMetricNameV1::NativeAttachments,
    SandboxMetricNameV1::FuseAttachments,
    SandboxMetricNameV1::AttachmentReplacementDuration,
    SandboxMetricNameV1::AttachmentDetachDuration,
    SandboxMetricNameV1::FuseRequests,
    SandboxMetricNameV1::FuseQueueCongestion,
    SandboxMetricNameV1::FuseErrors,
    SandboxMetricNameV1::FuseForgets,
    SandboxMetricNameV1::FuseOpenHandles,
    SandboxMetricNameV1::FuseRegisteredBackingFiles,
    SandboxMetricNameV1::FuseFallbackBytes,
    SandboxMetricNameV1::FuseWorkerRestarts,
    SandboxMetricNameV1::StructuralIndexMappedBytes,
    SandboxMetricNameV1::StructuralIndexResidentBytes,
    SandboxMetricNameV1::StructuralIndexNodesTouched,
    SandboxMetricNameV1::StructuralIndexRebuilds,
    SandboxMetricNameV1::CacheLogicalBytes,
    SandboxMetricNameV1::CachePhysicalResidentBytes,
    SandboxMetricNameV1::CacheResidencyProfileObjects,
    SandboxMetricNameV1::CacheAuthorizationLeases,
    SandboxMetricNameV1::CacheKernelPins,
    SandboxMetricNameV1::CacheDuplicateAvoidance,
    SandboxMetricNameV1::CacheEvictions,
    SandboxMetricNameV1::CgroupCpuNanoseconds,
    SandboxMetricNameV1::CgroupMemoryBytes,
    SandboxMetricNameV1::CgroupSwapBytes,
    SandboxMetricNameV1::CgroupIoBytes,
    SandboxMetricNameV1::CgroupPids,
    SandboxMetricNameV1::CgroupPressureNanoseconds,
    SandboxMetricNameV1::CgroupOomEvents,
    SandboxMetricNameV1::OperationCpuNanoseconds,
    SandboxMetricNameV1::OperationMemoryBytes,
    SandboxMetricNameV1::OperationPids,
    SandboxMetricNameV1::OperationIoBytes,
    SandboxMetricNameV1::OperationNetworkBytes,
    SandboxMetricNameV1::OperationLogBytes,
    SandboxMetricNameV1::OperationStagingBytes,
    SandboxMetricNameV1::OperationCancellations,
    SandboxMetricNameV1::OperationOutputBytes,
    SandboxMetricNameV1::ZfsArcSizeBytes,
    SandboxMetricNameV1::ZfsArcMetadataBytes,
    SandboxMetricNameV1::ZfsArcDataBytes,
    SandboxMetricNameV1::ZfsArcHits,
    SandboxMetricNameV1::ZfsArcMisses,
    SandboxMetricNameV1::ZfsArcDirtyBytes,
    SandboxMetricNameV1::ZfsArcReclaims,
    SandboxMetricNameV1::ZfsArcConfiguredMaximumBytes,
    SandboxMetricNameV1::ZfsArcPressureNanoseconds,
    SandboxMetricNameV1::ZfsReferencedBytes,
    SandboxMetricNameV1::ZfsLogicalBytes,
    SandboxMetricNameV1::ZfsQuotaFailures,
    SandboxMetricNameV1::ZfsSnapshotHolds,
    SandboxMetricNameV1::ZfsCloneLineageDepth,
    SandboxMetricNameV1::ReconciliationNamespaceMismatches,
    SandboxMetricNameV1::ReconciliationMountMismatches,
    SandboxMetricNameV1::ReconciliationUnitMismatches,
    SandboxMetricNameV1::ReconciliationDatasetMismatches,
    SandboxMetricNameV1::ReconciliationLeaseMismatches,
    SandboxMetricNameV1::ReconciliationAllocationMismatches,
];

/// Identifies the closed numeric shape of a metric family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetricValueKindV1 {
    /// A cumulative monotone counter.
    Counter,
    /// A point-in-time unsigned gauge.
    Gauge,
    /// A duration sample in nanoseconds.
    DurationNanoseconds,
}

/// Carries one numeric metric value with an explicit interpretation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MetricValueV1 {
    /// A cumulative monotone counter value.
    Counter(u64),
    /// A point-in-time unsigned gauge value.
    Gauge(u64),
    /// A duration observation in nanoseconds.
    DurationNanoseconds(u64),
}

impl MetricValueV1 {
    const fn kind(self) -> MetricValueKindV1 {
        match self {
            Self::Counter(_) => MetricValueKindV1::Counter,
            Self::Gauge(_) => MetricValueKindV1::Gauge,
            Self::DurationNanoseconds(_) => MetricValueKindV1::DurationNanoseconds,
        }
    }

    /// Returns the unsigned metric value.
    #[must_use]
    pub const fn value(self) -> u64 {
        match self {
            Self::Counter(value) | Self::Gauge(value) | Self::DurationNanoseconds(value) => value,
        }
    }
}

/// Identifies the only legal portable metric label keys.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MetricLabelKeyV1 {
    /// A stable logical project identity.
    Project,
    /// A closed runtime or storage backend family.
    Backend,
    /// A stable logical node identity.
    Node,
    /// A coarse closed status class.
    StatusClass,
    /// A closed portable capability profile.
    CapabilityProfile,
}

/// Identifies a closed backend label.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MetricBackendV1 {
    /// The portable systemd-nspawn runtime backend.
    Nspawn,
    /// A native detached-mount attachment.
    NativeMount,
    /// A FUSE filesystem-view attachment.
    Fuse,
    /// The portable content cache.
    Cache,
    /// ZFS storage.
    Zfs,
    /// Controller-only work.
    Controller,
}

/// Identifies a bounded portable status label.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MetricStatusClassV1 {
    /// A sandbox is requested.
    SandboxRequested,
    /// A sandbox is preparing.
    SandboxPreparing,
    /// A sandbox is starting.
    SandboxStarting,
    /// A sandbox is ready.
    SandboxReady,
    /// A sandbox is freezing.
    SandboxFreezing,
    /// A sandbox is frozen.
    SandboxFrozen,
    /// A sandbox is stopping.
    SandboxStopping,
    /// A sandbox is stopped.
    SandboxStopped,
    /// A sandbox is hibernated.
    SandboxHibernated,
    /// A sandbox is deleting.
    SandboxDeleting,
    /// A sandbox is deleted.
    SandboxDeleted,
    /// A sandbox is in an error phase.
    SandboxError,
    /// A sandbox is lost.
    SandboxLost,
    /// An execution is requested.
    ExecutionRequested,
    /// An execution is admitted.
    ExecutionAdmitted,
    /// An execution is starting.
    ExecutionStarting,
    /// An execution is running.
    ExecutionRunning,
    /// An execution exited.
    ExecutionExited,
    /// An execution was canceled.
    ExecutionCanceled,
    /// An execution failed.
    ExecutionFailed,
    /// An execution was lost.
    ExecutionLost,
    /// Work is pending or preparing.
    Pending,
    /// Work is active and healthy.
    Ready,
    /// Work is explicitly degraded.
    Degraded,
    /// Work is blocked.
    Blocked,
    /// Authority is fenced or contained.
    Fenced,
    /// Residual cleanup remains.
    Residual,
    /// Work completed.
    Complete,
    /// Work failed.
    Failed,
    /// Inventory found an object with no durable owner.
    Leaked,
    /// Inventory found an object contradicting durable ownership.
    Mismatched,
    /// A sandbox lifecycle operation scope.
    OperationLifecycle,
    /// An execution operation scope.
    OperationExecution,
    /// A filesystem-view operation scope.
    OperationFilesystem,
    /// A snapshot operation scope.
    OperationSnapshot,
    /// A cache operation scope.
    OperationCache,
    /// A reconciliation operation scope.
    OperationReconciliation,
    /// A residual-cleanup operation scope.
    OperationCleanup,
}

impl MetricStatusClassV1 {
    const fn is_sandbox_phase(self) -> bool {
        matches!(
            self,
            Self::SandboxRequested
                | Self::SandboxPreparing
                | Self::SandboxStarting
                | Self::SandboxReady
                | Self::SandboxFreezing
                | Self::SandboxFrozen
                | Self::SandboxStopping
                | Self::SandboxStopped
                | Self::SandboxHibernated
                | Self::SandboxDeleting
                | Self::SandboxDeleted
                | Self::SandboxError
                | Self::SandboxLost
        )
    }

    const fn is_execution_phase(self) -> bool {
        matches!(
            self,
            Self::ExecutionRequested
                | Self::ExecutionAdmitted
                | Self::ExecutionStarting
                | Self::ExecutionRunning
                | Self::ExecutionExited
                | Self::ExecutionCanceled
                | Self::ExecutionFailed
                | Self::ExecutionLost
        )
    }

    const fn is_operation_class(self) -> bool {
        matches!(
            self,
            Self::OperationLifecycle
                | Self::OperationExecution
                | Self::OperationFilesystem
                | Self::OperationSnapshot
                | Self::OperationCache
                | Self::OperationReconciliation
                | Self::OperationCleanup
        )
    }
}

/// Identifies a closed portable capability-profile label.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MetricCapabilityProfileV1 {
    /// Only the required base-v1 semantics are active.
    BaseV1,
    /// Native mount semantics are active.
    NativeMountV1,
    /// FUSE fallback semantics are active.
    FuseFallbackV1,
    /// ZFS snapshot semantics are active.
    ZfsSnapshotV1,
    /// Metadata-prioritized cache residency is active.
    CacheMetadataV1,
    /// Balanced cache residency is active.
    CacheBalancedV1,
    /// Streaming cache residency is active.
    CacheStreamingV1,
}

impl MetricCapabilityProfileV1 {
    const fn is_cache_residency(self) -> bool {
        matches!(
            self,
            Self::CacheMetadataV1 | Self::CacheBalancedV1 | Self::CacheStreamingV1
        )
    }
}

/// Carries one closed metric label value.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MetricLabelValueV1 {
    /// A stable nonzero project identity.
    Project([u8; 16]),
    /// A closed backend.
    Backend(MetricBackendV1),
    /// A stable nonzero node identity.
    Node([u8; 16]),
    /// A coarse status class.
    StatusClass(MetricStatusClassV1),
    /// A portable capability profile.
    CapabilityProfile(MetricCapabilityProfileV1),
}

impl MetricLabelValueV1 {
    /// Returns the label key implied by this typed value.
    #[must_use]
    pub const fn key(self) -> MetricLabelKeyV1 {
        match self {
            Self::Project(_) => MetricLabelKeyV1::Project,
            Self::Backend(_) => MetricLabelKeyV1::Backend,
            Self::Node(_) => MetricLabelKeyV1::Node,
            Self::StatusClass(_) => MetricLabelKeyV1::StatusClass,
            Self::CapabilityProfile(_) => MetricLabelKeyV1::CapabilityProfile,
        }
    }

    fn has_valid_identity(self) -> bool {
        match self {
            Self::Project(value) | Self::Node(value) => value != [0; 16],
            _ => true,
        }
    }
}

/// Reports an invalid portable metric observation or batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidMetricObservation {
    /// A sample uses the wrong numeric kind for its metric family.
    #[error("metric value kind does not match its family")]
    ValueKind,
    /// Labels are illegal, duplicated, unordered, or carry a zero identity.
    #[error("metric labels are not canonical for their family")]
    Labels,
    /// The sample batch or its distinct identity labels exceed compiled bounds.
    #[error("metric observation cardinality exceeds its compiled bound")]
    Cardinality,
    /// Two samples use the same family and exact label set.
    #[error("metric observation batch contains a duplicate series")]
    DuplicateSeries,
}

/// Stores one validated portable metric sample.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableMetricObservationV1 {
    name: SandboxMetricNameV1,
    value: MetricValueV1,
    labels: Vec<MetricLabelValueV1>,
}

impl PortableMetricObservationV1 {
    /// Checks numeric shape, label allowlist, identity values, and ordering.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMetricObservation`] for a mismatched numeric kind,
    /// illegal label, duplicate key, unordered key, zero identity, or excess.
    pub fn new(
        name: SandboxMetricNameV1,
        value: MetricValueV1,
        labels: Vec<MetricLabelValueV1>,
    ) -> Result<Self, InvalidMetricObservation> {
        if value.kind() != name.value_kind() {
            return Err(InvalidMetricObservation::ValueKind);
        }
        if labels.len() > MAXIMUM_LABELS_PER_OBSERVATION
            || labels.iter().any(|label| {
                !label.has_valid_identity()
                    || !name.permits_label(label.key())
                    || !status_label_matches_family(name, *label)
            })
            || !labels.windows(2).all(|pair| pair[0].key() < pair[1].key())
            || !required_labels_are_present(name, &labels)
        {
            return Err(InvalidMetricObservation::Labels);
        }

        Ok(Self {
            name,
            value,
            labels,
        })
    }

    /// Returns the closed metric family.
    #[must_use]
    pub const fn name(&self) -> SandboxMetricNameV1 {
        self.name
    }

    /// Returns the checked numeric value.
    #[must_use]
    pub const fn value(&self) -> MetricValueV1 {
        self.value
    }

    /// Returns canonical labels in key order.
    #[must_use]
    pub fn labels(&self) -> &[MetricLabelValueV1] {
        &self.labels
    }
}

fn required_labels_are_present(name: SandboxMetricNameV1, labels: &[MetricLabelValueV1]) -> bool {
    let has_status = labels
        .iter()
        .any(|label| label.key() == MetricLabelKeyV1::StatusClass);
    let has_profile = labels
        .iter()
        .any(|label| label.key() == MetricLabelKeyV1::CapabilityProfile);
    let has_project = labels
        .iter()
        .any(|label| label.key() == MetricLabelKeyV1::Project);
    if name.is_operation_scope() {
        return has_project && has_status;
    }
    match name {
        SandboxMetricNameV1::SandboxResources | SandboxMetricNameV1::Executions => has_status,
        SandboxMetricNameV1::CacheResidencyProfileObjects => has_profile,
        SandboxMetricNameV1::ReconciliationNamespaceMismatches
        | SandboxMetricNameV1::ReconciliationMountMismatches
        | SandboxMetricNameV1::ReconciliationUnitMismatches
        | SandboxMetricNameV1::ReconciliationDatasetMismatches
        | SandboxMetricNameV1::ReconciliationLeaseMismatches
        | SandboxMetricNameV1::ReconciliationAllocationMismatches => has_status,
        _ => true,
    }
}

const fn status_label_matches_family(name: SandboxMetricNameV1, label: MetricLabelValueV1) -> bool {
    match (name, label) {
        (
            SandboxMetricNameV1::CacheResidencyProfileObjects,
            MetricLabelValueV1::CapabilityProfile(profile),
        ) => profile.is_cache_residency(),
        (SandboxMetricNameV1::SandboxResources, MetricLabelValueV1::StatusClass(status)) => {
            status.is_sandbox_phase()
        }
        (SandboxMetricNameV1::Executions, MetricLabelValueV1::StatusClass(status)) => {
            status.is_execution_phase()
        }
        (
            SandboxMetricNameV1::ReconciliationNamespaceMismatches
            | SandboxMetricNameV1::ReconciliationMountMismatches
            | SandboxMetricNameV1::ReconciliationUnitMismatches
            | SandboxMetricNameV1::ReconciliationDatasetMismatches
            | SandboxMetricNameV1::ReconciliationLeaseMismatches
            | SandboxMetricNameV1::ReconciliationAllocationMismatches,
            MetricLabelValueV1::StatusClass(status),
        ) => matches!(
            status,
            MetricStatusClassV1::Leaked | MetricStatusClassV1::Mismatched
        ),
        (name, MetricLabelValueV1::StatusClass(status)) if name.is_operation_scope() => {
            status.is_operation_class()
        }
        (_, MetricLabelValueV1::StatusClass(status)) => {
            !status.is_sandbox_phase()
                && !status.is_execution_phase()
                && !status.is_operation_class()
                && !matches!(
                    status,
                    MetricStatusClassV1::Leaked | MetricStatusClassV1::Mismatched
                )
        }
        _ => true,
    }
}

/// Stores a bounded canonical batch without installing an exporter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableMetricBatchV1(Vec<PortableMetricObservationV1>);

impl PortableMetricBatchV1 {
    /// Checks series ordering, uniqueness, and identity cardinality ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMetricObservation`] when the batch is oversized,
    /// unordered, duplicated, or contains too many distinct projects or nodes.
    pub fn new(
        observations: Vec<PortableMetricObservationV1>,
    ) -> Result<Self, InvalidMetricObservation> {
        if observations.len() > MAXIMUM_METRIC_OBSERVATIONS {
            return Err(InvalidMetricObservation::Cardinality);
        }
        if !observations
            .windows(2)
            .all(|pair| series_cmp(&pair[0], &pair[1]) == Ordering::Less)
        {
            return Err(
                if observations
                    .windows(2)
                    .any(|pair| series_cmp(&pair[0], &pair[1]) == Ordering::Equal)
                {
                    InvalidMetricObservation::DuplicateSeries
                } else {
                    InvalidMetricObservation::Labels
                },
            );
        }

        let mut projects = BTreeSet::new();
        let mut nodes = BTreeSet::new();
        for observation in &observations {
            for label in &observation.labels {
                match label {
                    MetricLabelValueV1::Project(value) => {
                        projects.insert(*value);
                    }
                    MetricLabelValueV1::Node(value) => {
                        nodes.insert(*value);
                    }
                    _ => {}
                }
            }
        }
        if projects.len() > MAXIMUM_METRIC_PROJECTS || nodes.len() > MAXIMUM_METRIC_NODES {
            return Err(InvalidMetricObservation::Cardinality);
        }

        Ok(Self(observations))
    }

    /// Returns canonical portable observations.
    #[must_use]
    pub fn as_slice(&self) -> &[PortableMetricObservationV1] {
        &self.0
    }
}

fn series_cmp(left: &PortableMetricObservationV1, right: &PortableMetricObservationV1) -> Ordering {
    (left.name, left.labels.as_slice()).cmp(&(right.name, right.labels.as_slice()))
}
