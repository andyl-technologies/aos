//! Protected Controller observability, redaction, and operator diagnostics.
//!
//! Checked public resources and bounded client-state reducers live in
//! `aos_sandbox_protocol::public_api`. This module retains protected journal
//! adapters and the distinct non-serializable operator projection.

pub mod metrics;
pub mod observability;
pub mod operator;
pub mod redaction;

pub use metrics::{
    InvalidMetricObservation, MAXIMUM_LABELS_PER_OBSERVATION, MAXIMUM_METRIC_NODES,
    MAXIMUM_METRIC_OBSERVATIONS, MAXIMUM_METRIC_PROJECTS, MetricBackendV1,
    MetricCapabilityProfileV1, MetricLabelKeyV1, MetricLabelValueV1, MetricStatusClassV1,
    MetricValueKindV1, MetricValueV1, PortableMetricBatchV1, PortableMetricObservationV1,
    SandboxMetricNameV1,
};
pub use observability::*;
pub use operator::{
    InvalidOperatorDiagnostics, MAXIMUM_OPERATOR_DIAGNOSTICS, MAXIMUM_OPERATOR_LOCAL_NAME_BYTES,
    OperatorDiagnosticKindV1, OperatorDiagnosticV1, OperatorDiagnosticValueV1,
    OperatorDiagnosticsV1, OperatorLocalIdentifierV1,
};
pub use redaction::{
    ControllerOperationQueryV1, ControllerSandboxQueryV1, InvalidControllerProjection,
    OperatorOperationProjectionV1, OperatorSandboxProjectionV1, PlacementAuthorityStateV1,
    project_operation_for_operator, project_sandbox_for_operator, redact_operation_for_public,
    redact_sandbox_for_public,
};
