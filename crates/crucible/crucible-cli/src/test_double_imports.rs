//! Imports used only by the gated local simulation backend and its tests.

use crucible_session::engine::{
    QuantumOutcome as ImportedQuantumOutcome, QuantumRequest as ImportedQuantumRequest,
};

pub(super) use crucible_session::{
    LiveSnapshot, LiveSnapshotView,
    engine::{SchedulerError as QErr, SearchFailureOracle},
    validation::resume_session_from_validation_dag,
};

pub(super) type QOut = ImportedQuantumOutcome;
pub(super) type QReq = ImportedQuantumRequest;
