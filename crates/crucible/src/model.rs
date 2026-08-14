//! Content-addressed execution-model vocabulary.
//!
//! This module owns the pure, content-addressed data contracts shared by the
//! scheduler, temporal graph, checkpoint cache, fault engine, assertions, and
//! event log. It deliberately contains no backend-specific driver state.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::num::NonZeroUsize;
use std::ops;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crucible_sim::{
    DECISION_RNG_LINK_STREAM_DOMAIN, DECISION_RNG_NAME_HASH_DOMAIN,
    DECISION_RNG_NODE_STREAM_DOMAIN, DecisionRng, DecisionStream,
};
use serde::de;
use serde::{Deserialize, Serialize};

use crate::backend::ExecutionFingerprint;
use crate::scheduler::{
    ControlOperation, ControlOperationKind, EventAttributeValue, EventDiagnosticPayload,
    EventLevel, EventLogCausalDivergencePoint, EventLogCausalProjection, EventLogCoverageFeedback,
    EventLogCoverageFeedbackConsumer, EventLogIcountStamp, EventSource, ScheduledEventPayload,
    SchedulerEventLogClass, SchedulerEventLogEntry, SchedulerEventLogPayload, SchedulerQuiescence,
    coverage_fingerprint_from_event_log, event_log_causal_projection,
    recorded_assertion_log_from_schedule_for_search,
};
use crate::trigger::{
    Action, AssertionQuantifierKind, BlackBoxHostOracle, Condition, ConditionEvaluationPass,
    ConditionLeaf, ConditionLeafOracle, Event, EventGraph, EventGraphError, FirePolicy,
    HostAssertionOracle, HostAssertionOutcome, HostAssertionOutcomeKind, HostAssertionViolation,
    LogLevel, ObservableEventPayload, OfflineAssertionChecker, RecordedAssertionLog,
    ResolvedCodePoint, ResolvedMemPlace, SearchScheduleNamedPredicateHostOracle,
    SearchScheduleNamedPredicateTruths,
};

mod canonical;
mod guest_assertion;

static LOCAL_DAG_STORE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The stable domain used for device-scoped decision streams ([IO-21]).
///
/// A device (block / 9p / network sub-node) draws its probabilistic effects from a
/// stream forked by name-hash in this fixed domain, so a device named `"disk"` and
/// a node named `"disk"` never collide and adding or renaming an unrelated device
/// never perturbs another device's draws ([DET-25]).
pub const DECISION_RNG_DEVICE_STREAM_DOMAIN: &str = "crucible.decision-rng.device-stream.v1";

/// Minimum one-way logical link latency in virtual nanoseconds.
pub const MIN_LINK_LATENCY: SimDuration = SimDuration { nanos: 1 };
const MAX_WORLD_ICOUNT_SHIFT: u8 = 62;
const MIN_WORLD_MEMORY_MIB: u32 = 1;
const MAX_LINK_LOSS_MILLIONTHS: u32 = 1_000_000;
const MAX_SCENARIO_FAMILY_SEEDS: u32 = 1_000_000;
const MAX_SCENARIO_FAMILY_TOPOLOGY_SIZE: u32 = 256;
const REPLAY_ORACLE_SEARCH_SAMPLING_DOMAIN: &[u8] = b"crucible.replay-oracle.search-sampling.v1";
const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x00000100000001b3;
const SEARCH_PRIORITY_SCORE_DOMAIN: &[u8] = b"crucible.search.strategy.priority.v1";
const COVERAGE_GUIDED_FUZZ_SAMPLE_DOMAIN: &str = "crucible.coverage-guided-fuzz.sample.v1";
const COVERAGE_GUIDED_FUZZ_OVERRIDE_DOMAIN: &str = "crucible.coverage-guided-fuzz.override.v1";
const FAILURE_SIGNATURE_DOMAIN: &str = "crucible.failure-signature.v1";
const FAILURE_SIGNATURE_KEY_DOMAIN: &str = "crucible.failure-signature.key.v1";
const FAILURE_CAUSAL_SLICE_DOMAIN: &str = "crucible.failure-signature.causal-slice.v1";
const FAILURE_FINDINGS_LEDGER_DOMAIN: &str = "crucible.failure-triage.findings-ledger.v1";
const FAILURE_TRIAGE_RESULT_IDENTITY_DOMAIN: &str = "crucible.failure-triage.result-identity.v1";
const FAILURE_TRIAGE_SIGNATURE_SELF_CHECK_DOMAIN: &str =
    "crucible.failure-triage.signature-self-check.v1";
const FAILURE_CLUSTERING_RESULT_DOMAIN: &str = "crucible.failure-triage.clustering-result.v1";
const FAILURE_SIGNATURE_MINIMIZATION_RESULT_DOMAIN: &str =
    "crucible.failure-triage.signature-preserving-minimization.v1";
const FAILURE_CLUSTER_REPORT_DOMAIN: &str = "crucible.failure-triage.cluster-report.v1";
const FAILURE_CLUSTER_REPORT_SET_DOMAIN: &str = "crucible.failure-triage.cluster-report-set.v1";
const FAILURE_TRIAGE_RESULT_DOMAIN: &str = "crucible.failure-triage.result.v1";
const FAILURE_TRIAGE_RESULT_DIFF_DOMAIN: &str = "crucible.failure-triage.result-diff.v1";
const FAILURE_COVERAGE_CLASS_ALGORITHM: &str = "crucible.failure-signature.coverage-class.top16.v1";
const SIGNATURE_POLICY_SCHEMA_VERSION: u16 = 1;
const GUIDANCE_SCORE_ONE_MICRO: u64 = 1_000_000;
const ADAPTIVE_CONFIRMED_FAILURE_REWARD: u64 = 1_000_000_000_000;

mod dag_store;

pub use dag_store::*;

mod binary_plan;
mod binary_state;
mod configuration;
mod debug;
mod engine;
mod exploration;
mod failure;
mod family;
mod fault_signal;
mod material;
mod materialized;
mod plan_properties;
mod reproduction;
mod runtime;
mod scenario;
mod store_artifacts;
mod temporal_graph;
mod time;
#[path = "model/toml.rs"]
mod toml_codec;
mod toml {
    pub(super) use super::toml_codec::{
        deserialize_u64_toml_number_or_string, serialize_u64_toml_number_or_string,
    };
    pub(super) use ::toml::*;
}
mod topology_faults;
mod validation;
mod workload;
mod world_faults;
mod world_network_policy;
mod world_storage_policy;

use binary_plan::*;
use binary_state::*;
pub use configuration::*;
pub use debug::*;
pub use engine::*;
pub use exploration::*;
use failure::failure_assertion_quantifier_label;
pub use failure::*;
pub use family::*;
pub use fault_signal::*;
use material::*;
pub use materialized::*;
pub use plan_properties::*;
pub use reproduction::*;
pub use runtime::*;
pub use scenario::*;
use store_artifacts::*;
pub use temporal_graph::*;
use temporal_graph::{debug_configuration_prefix, maps_equal_except_key};
pub use time::*;
use toml_codec::*;
pub use topology_faults::*;
use validation::*;
pub use workload::*;
pub use world_faults::*;
pub use world_network_policy::*;
pub use world_storage_policy::*;

mod store_error;
#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
#[path = "model/tests.rs"]
mod tests;
