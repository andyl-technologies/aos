//! Reusable bounded protocol probes for independent CNP/1 vendor peers.
//!
//! The runner exercises real framed streams with closed baseline request and
//! response decoding. It never creates host execution authority or qualifies
//! CPU fidelity, complete state capture, deterministic replay, or native
//! containment. Those claims require the independently admitted realized
//! provider and behavioral qualification suites in RFC-0025 chapter 08.
//!
//! Vendor plans use exact JSON binding objects to reference private inputs or
//! fields captured from prior replies:
//!
//! ```json
//! {"$binding": "provider-incarnation"}
//! ```
//!
//! Reports contain identities and verdicts, not control bodies or secrets.

mod plan;
mod report;
mod runner;
#[cfg(target_os = "linux")]
mod unix;

pub use plan::{CheckKind, Expectation, IdentityKind, ProbePlan, ProbeStep, ReplyAssertion};
pub use report::{CheckDisposition, CheckResult, ConformanceReport, EndpointMeasurement};
pub use runner::{ProbeConnector, ProbeSession, run};
#[cfg(target_os = "linux")]
pub use unix::{UnixProbeConnector, measure_executable};

/// Bounds a complete vendor plan before deserialization or execution.
pub const MAX_PLAN_BYTES: usize = 16 * 1024 * 1024;

/// Bounds the number of protocol exchanges and adversarial actions in a plan.
pub const MAX_PLAN_STEPS: usize = 4096;

const PLAN_VERSION: u32 = 1;
const REPORT_VERSION: u32 = 1;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
