//! Portable solve-request JSON contains allocation data, never executable paths.
//!
//! ```json
//! {"mode":"local_search","wall_time_millis":"30000","threads":"1","seed":null,"memory_bytes":"0","cpu_time_millis":"0","maximum_iterations":"0"}
//! ```

use dispatch_model::{Assignment, Problem, Quantity};
use serde::{Deserialize, Serialize};

use crate::{wire, ProtocolError};

/// Selects a search family while preserving the same allocation semantics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchMode {
    /// Requests the advertised assignment local-search engine.
    #[default]
    LocalSearch,
    /// Requests an explicitly supported mixed-integer search engine.
    Mip,
}

/// Represents exact original options for portable request import and export.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchRequestOptions {
    /// The selected search algorithm family.
    pub mode: SearchMode,
    /// Submission-to-terminal wall budget, including queue and verification.
    pub wall_time_millis: Quantity,
    /// Cooperative native thread setting, without CPU-entitlement authority.
    pub threads: Quantity,
    /// Explicit seed, when supported; this does not promise bit-identical replay.
    pub seed: Option<Quantity>,
    /// Cooperative native memory option, without an enforced-memory guarantee.
    pub memory_bytes: Quantity,
    /// Cooperative native CPU-time option, without an enforced quota.
    pub cpu_time_millis: Quantity,
    /// Explicit iteration limit, zero when not selected.
    pub maximum_iterations: Quantity,
}

impl Default for SearchRequestOptions {
    fn default() -> Self {
        Self {
            mode: SearchMode::LocalSearch,
            wall_time_millis: Quantity::new(30_000),
            threads: Quantity::new(1),
            seed: None,
            memory_bytes: Quantity::new(0),
            cpu_time_millis: Quantity::new(0),
            maximum_iterations: Quantity::new(0),
        }
    }
}

impl SearchRequestOptions {
    /// Converts portable options into the typed binary worker contract.
    ///
    /// # Errors
    ///
    /// Returns an error for zero budgets/threads or a thread count beyond u32.
    pub fn to_wire(&self) -> Result<wire::SolveOptions, ProtocolError> {
        let threads = u32::try_from(self.threads.get())
            .map_err(|_| ProtocolError::InvalidMessage("thread count exceeds u32".into()))?;
        if threads == 0 || self.wall_time_millis.get() == 0 {
            return Err(ProtocolError::InvalidMessage(
                "wall budget and thread count must be positive".into(),
            ));
        }
        Ok(wire::SolveOptions {
            mode: match self.mode {
                SearchMode::LocalSearch => wire::SearchMode::LocalSearch as i32,
                SearchMode::Mip => wire::SearchMode::Mip as i32,
            },
            wall_time_millis: self.wall_time_millis.get(),
            threads,
            seed: self.seed.map(Quantity::get),
            memory_bytes: self.memory_bytes.get(),
            cpu_time_millis: self.cpu_time_millis.get(),
            maximum_iterations: self.maximum_iterations.get(),
        })
    }

    /// Converts checked worker options into exact portable JSON fields.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown or unspecified modes and invalid settings.
    pub fn from_wire(options: &wire::SolveOptions) -> Result<Self, ProtocolError> {
        let mode = match wire::SearchMode::try_from(options.mode) {
            Ok(wire::SearchMode::LocalSearch) => SearchMode::LocalSearch,
            Ok(wire::SearchMode::Mip) => SearchMode::Mip,
            _ => {
                return Err(ProtocolError::InvalidMessage(
                    "unknown or unspecified search mode".into(),
                ))
            }
        };
        let result = Self {
            mode,
            wall_time_millis: Quantity::new(options.wall_time_millis),
            threads: Quantity::new(u64::from(options.threads)),
            seed: options.seed.map(Quantity::new),
            memory_bytes: Quantity::new(options.memory_bytes),
            cpu_time_millis: Quantity::new(options.cpu_time_millis),
            maximum_iterations: Quantity::new(options.maximum_iterations),
        };
        result.to_wire()?;
        Ok(result)
    }
}

/// Carries a portable immutable model and its independent search policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SolveRequest {
    /// Public request-schema version, currently the canonical string one.
    pub request_version: Quantity,
    /// Complete allocation observations, accounting, constraints, and objectives.
    pub problem: Problem,
    /// Logical backend identity resolved through trusted execution configuration.
    pub backend: String,
    /// Original requested search settings, before remaining-budget propagation.
    pub options: SearchRequestOptions,
    /// Optional candidate hint, independent of observed assignment and repair debt.
    pub hint: Option<Assignment>,
}

impl SolveRequest {
    /// Constructs a version-one Rebalancer request without execution configuration.
    pub fn new(problem: Problem, options: SearchRequestOptions, hint: Option<Assignment>) -> Self {
        Self {
            request_version: Quantity::new(1),
            problem,
            backend: "rebalancer".into(),
            options,
            hint,
        }
    }

    /// Checks version and search-policy metadata before backend resolution.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported version, absent backend, or bad options.
    /// Callers must additionally structurally validate the allocation problem.
    pub fn validate_metadata(&self) -> Result<(), ProtocolError> {
        if self.request_version.get() != 1 {
            return Err(ProtocolError::Negotiation(
                "unsupported portable request version".into(),
            ));
        }
        if self.backend.is_empty() {
            return Err(ProtocolError::InvalidMessage(
                "backend identity must be nonempty".into(),
            ));
        }
        self.options.to_wire()?;
        Ok(())
    }

    /// Returns binary options after checking the portable request metadata.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported versions or invalid search policy.
    pub fn wire_options(&self) -> Result<wire::SolveOptions, ProtocolError> {
        self.validate_metadata()?;
        self.options.to_wire()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::json::{from_slice, to_vec, JsonLimits};

    #[test]
    fn options_round_trip_exact_seeds_and_reject_numeric_json() {
        let options = SearchRequestOptions {
            seed: Some(Quantity::new(u64::MAX)),
            ..Default::default()
        };
        let bytes = to_vec(&options).unwrap();
        let imported: SearchRequestOptions = from_slice(&bytes, JsonLimits::default()).unwrap();
        assert_eq!(imported, options);
        assert_eq!(imported.to_wire().unwrap().seed, Some(u64::MAX));

        let bytes = String::from_utf8(bytes)
            .unwrap()
            .replace("\"threads\":\"1\"", "\"threads\":1");
        assert!(
            from_slice::<SearchRequestOptions>(bytes.as_bytes(), JsonLimits::default()).is_err()
        );
    }

    #[test]
    fn request_cannot_smuggle_launcher_paths_through_unknown_fields() {
        let options = to_vec(&SearchRequestOptions::default()).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&options).unwrap();
        value["executable"] = serde_json::Value::String("arbitrary".into());
        assert!(from_slice::<SearchRequestOptions>(
            &serde_json::to_vec(&value).unwrap(),
            JsonLimits::default()
        )
        .is_err());
    }
}
