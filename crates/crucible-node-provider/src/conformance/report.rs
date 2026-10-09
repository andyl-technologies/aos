//! Bounded protocol reports that preserve omissions without disclosing control data.

use std::collections::BTreeSet;

use crucible_node_contract::{ContentRef, HashRef, Id, U64, canonical};
use serde::{Deserialize, Serialize};

use crate::ProviderError;

use super::{CheckKind, REPORT_VERSION};

/// Records independently measured local transport and executable identity.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointMeasurement {
    /// Identifies the peer process returned by the actual OS transport.
    pub peer_pid: U64,
    /// Identifies the actual peer user's numeric OS identity.
    pub peer_uid: U64,
    /// Commits to the peer executable bytes read through its actual process.
    pub executable: ContentRef,
}

/// Reports one protocol case independently of behavioral qualification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckDisposition {
    /// The observed peer behavior satisfied the supplied independent oracle.
    Passed,
    /// The exchange or oracle failed; the native outcome may remain uncertain.
    Failed,
    /// An earlier failure prevented execution of this dependent case.
    NotExecuted,
}

/// Retains one result without retaining requests, payload bytes or secret fields.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckResult {
    /// Identifies the original independent case.
    pub case: Id,
    /// Names its narrow protocol obligation, absent for transport setup actions.
    pub check: Option<CheckKind>,
    /// Retains pass, failure or nonexecution distinctly.
    pub disposition: CheckDisposition,
    /// Commits to the outgoing request, absent for credential-bearing Hello.
    pub request_identity: Option<HashRef>,
    /// Commits to the original reply, absent for credential-bearing Hello.
    pub response_identity: Option<HashRef>,
    /// Reports a static failure reason without logging peer or secret data.
    pub diagnostic: String,
}

/// Binds measured endpoints and all case results to one protocol-only execution.
///
/// A successful report does not establish exact modeled-state preservation,
/// CPU accuracy, repeatability, physical pause or durable restart. A missing
/// required case remains visible; omission cannot produce a complete pass.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceReport {
    /// Selects report schema version one.
    pub schema_version: u32,
    /// Identifies this runner's fixed protocol-only interpretation.
    pub harness: String,
    /// Commits to the actual harness executable when measured by the CLI.
    pub harness_executable: Option<ContentRef>,
    /// Commits to the exact portable plan and its independent oracles.
    pub plan_identity: HashRef,
    /// Identifies the tested fixture revision.
    pub fixture: Id,
    /// Records actual independently measured endpoint identities per connection.
    pub endpoints: Vec<EndpointMeasurement>,
    /// Retains every attempted and unexecuted case in plan order.
    pub results: Vec<CheckResult>,
    /// Retains required obligations for which no successful case was observed.
    pub missing_checks: BTreeSet<CheckKind>,
    /// Confirms that no behavioral qualification authority was minted.
    pub protocol_only: bool,
}

impl ConformanceReport {
    /// Reports complete success only if all cases and required checks passed.
    pub fn passed(&self) -> bool {
        self.schema_version == REPORT_VERSION
            && self.protocol_only
            && self.missing_checks.is_empty()
            && !self.results.is_empty()
            && self
                .results
                .iter()
                .all(|case| case.disposition == CheckDisposition::Passed)
    }

    /// Encodes a portable canonical report without raw transcript bodies.
    ///
    /// # Errors
    /// Returns an error for serialization or canonical representation failure.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProviderError> {
        let value =
            serde_json::to_value(self).map_err(crucible_node_contract::ContractError::from)?;
        Ok(canonical::canonical_json(&value)?)
    }
}
