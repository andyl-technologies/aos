//! Retains versioned acceptance decisions and unchanged original coverage.
//!
//! ```text
//! AcceptanceV1 = original-claim | current-unit | required-classes | missing-IDs
//!              | accepted-or-refused
//! ```
//! Decoding this audit format never constructs qualification authority.

use std::{
    collections::BTreeSet,
    io::{self, Write},
};

use crucible_node_contract::{ContentRef, canonical};
use serde::{Deserialize, Serialize};

use super::{
    InstalledQualificationAuthority, QualificationClaim, QualificationClass, QualificationError,
    QualificationLimits, QualificationUnit, accept_claim, requirement_catalog,
};

/// Records a decision without granting admission or native custody.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AcceptanceDecision {
    /// Reports a successful historical evaluation, requiring fresh reauthentication.
    Accepted,
    /// Retains the original refusal diagnostic without filtering failed cases.
    Refused {
        /// Describes the failed evaluation under the installed policy.
        diagnostic: String,
    },
}

/// Retains complete original coverage and the exact evaluated host scope.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceRecord {
    /// Selects the closed `crucible.node-acceptance` audit format.
    pub format: String,
    /// Selects audit edition one.
    pub version: u16,
    /// Binds the exact original claim bytes retained separately by the owner.
    pub original_claim: ContentRef,
    /// Preserves every original row, case, disposition and predecessor reference.
    pub original: QualificationClaim,
    /// Binds the independently measured unit at evaluation time.
    pub evaluated_unit: QualificationUnit,
    /// Lists the actual required classes selected by installed host policy.
    pub required_classes: BTreeSet<QualificationClass>,
    /// Lists omitted normative obligations even when the original claim refuses.
    pub missing_requirements: BTreeSet<String>,
    /// Retains the historical evaluation, never an admission permit.
    pub decision: AcceptanceDecision,
}

/// Bounds source parsing and retained audit serialization independently.
#[derive(Clone, Copy, Debug)]
pub struct AcceptanceLimits {
    /// Applies original claim and evidence closure ceilings.
    pub qualification: QualificationLimits,
    /// Bounds the complete retained audit before serialization or decoding.
    pub maximum_record_bytes: usize,
}

impl Default for AcceptanceLimits {
    fn default() -> Self {
        Self {
            qualification: QualificationLimits::default(),
            maximum_record_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Borrows finite original bytes while owning their complete audit decision.
#[derive(Debug)]
pub struct EvaluatedAcceptance<'a> {
    original_bytes: &'a [u8],
    record: AcceptanceRecord,
}

impl EvaluatedAcceptance<'_> {
    /// Borrows the unchanged original bytes without copying them.
    pub fn original_bytes(&self) -> &[u8] {
        self.original_bytes
    }

    /// Borrows the retained decision, including refused or failed coverage.
    pub fn record(&self) -> &AcceptanceRecord {
        &self.record
    }
}

/// Evaluates an original claim while preserving all decodable refused audit rows.
///
/// # Errors
/// Rejects over-budget, corrupt, noncanonical or undecodable originals and audit
/// allocations exceeding their independent ceiling. Semantic and evidence
/// refusals are retained as decisions, not converted into incomplete success.
pub fn evaluate_acceptance<'a>(
    bytes: &'a [u8],
    reference: &ContentRef,
    current: &QualificationUnit,
    required: &BTreeSet<QualificationClass>,
    authority: &dyn InstalledQualificationAuthority,
    limits: AcceptanceLimits,
) -> Result<EvaluatedAcceptance<'a>, QualificationError> {
    if bytes.len() > limits.qualification.maximum_claim_bytes
        || reference.length.get() != bytes.len() as u64
        || canonical::content_ref(bytes, &reference.media_type)? != *reference
    {
        return Err(QualificationError::Refused(
            "original acceptance claim byte budget or integrity",
        ));
    }
    let value = canonical::parse_json(bytes, limits.qualification.maximum_claim_bytes)?;
    if canonical::canonical_json(&value)? != bytes {
        return Err(QualificationError::Refused(
            "noncanonical original acceptance claim",
        ));
    }
    let original: QualificationClaim =
        serde_json::from_value(value).map_err(crucible_node_contract::ContractError::from)?;
    current.validate()?;
    let (_, ids) = requirement_catalog()?;
    let missing_requirements: BTreeSet<String> = ids
        .into_iter()
        .filter(|id| {
            !original
                .requirements
                .iter()
                .any(|row| row.requirement == *id)
        })
        .map(str::to_owned)
        .collect();
    // JSON may expand one diagnostic control byte to six encoded bytes. Check
    // the exact borrowed report shape with that worst-case diagnostic before
    // cloning host metadata or invoking any installed evidence callback.
    let maximum_diagnostic = "\0".repeat(MAXIMUM_DIAGNOSTIC_BYTES);
    bounded(
        &ProspectiveRecord {
            format: "crucible.node-acceptance",
            version: 1,
            original_claim: reference,
            original: &original,
            evaluated_unit: current,
            required_classes: required,
            missing_requirements: &missing_requirements,
            decision: ProspectiveDecision::Refused {
                diagnostic: &maximum_diagnostic,
            },
        },
        limits.maximum_record_bytes,
    )?;
    let decision = match accept_claim(
        bytes,
        reference,
        current,
        required,
        authority,
        limits.qualification,
    ) {
        Ok(_) => AcceptanceDecision::Accepted,
        Err(error) => AcceptanceDecision::Refused {
            diagnostic: bounded_diagnostic(&error)?,
        },
    };
    let record = AcceptanceRecord {
        format: "crucible.node-acceptance".into(),
        version: 1,
        original_claim: reference.clone(),
        original,
        evaluated_unit: current.clone(),
        required_classes: required.clone(),
        missing_requirements,
        decision,
    };
    bounded(&record, limits.maximum_record_bytes)?;
    Ok(EvaluatedAcceptance {
        original_bytes: bytes,
        record,
    })
}

impl AcceptanceRecord {
    /// Decodes finite canonical audit data without constructing an accepted token.
    ///
    /// # Errors
    /// Rejects oversized, noncanonical, unknown or structurally invalid records.
    pub fn from_json(bytes: &[u8], maximum: usize) -> Result<Self, QualificationError> {
        let value = canonical::parse_json(bytes, maximum)?;
        if canonical::canonical_json(&value)? != bytes {
            return Err(QualificationError::Refused(
                "noncanonical acceptance record",
            ));
        }
        let record: Self =
            serde_json::from_value(value).map_err(crucible_node_contract::ContractError::from)?;
        if record.format != "crucible.node-acceptance" || record.version != 1 {
            return Err(QualificationError::Refused("unsupported acceptance record"));
        }
        Ok(record)
    }

    /// Serializes finite audit data after a nonretaining allocation preflight.
    ///
    /// # Errors
    /// Rejects records exceeding the byte ceiling or failing canonical encoding.
    pub fn canonical_bytes(&self, maximum: usize) -> Result<Vec<u8>, QualificationError> {
        bounded(self, maximum)?;
        Ok(canonical::canonical_json(
            &serde_json::to_value(self).map_err(crucible_node_contract::ContractError::from)?,
        )?)
    }

    pub(super) fn matches_original(
        &self,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<bool, QualificationError> {
        bounded(&self.original, maximum)?;
        let value = serde_json::to_value(&self.original)
            .map_err(crucible_node_contract::ContractError::from)?;
        Ok(canonical::canonical_json(&value)? == bytes)
    }
}

pub(super) fn bounded(value: &impl Serialize, maximum: usize) -> Result<(), QualificationError> {
    struct Budget {
        remaining: usize,
    }
    impl Write for Budget {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.remaining = self
                .remaining
                .checked_sub(bytes.len())
                .ok_or_else(|| io::Error::other("acceptance serialization ceiling"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Budget { remaining: maximum }, value)
        .map_err(|_| QualificationError::Refused("acceptance serialization ceiling"))
}

const MAXIMUM_DIAGNOSTIC_BYTES: usize = 4096;

// Mirrors the existing audit field names while borrowing every unbounded body.
// Its refused variant dominates the accepted variant's encoded extent.
#[derive(Serialize)]
struct ProspectiveRecord<'a> {
    format: &'a str,
    version: u16,
    original_claim: &'a ContentRef,
    original: &'a QualificationClaim,
    evaluated_unit: &'a QualificationUnit,
    required_classes: &'a BTreeSet<QualificationClass>,
    missing_requirements: &'a BTreeSet<String>,
    decision: ProspectiveDecision<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ProspectiveDecision<'a> {
    Refused { diagnostic: &'a str },
}

fn bounded_diagnostic(error: &QualificationError) -> Result<String, QualificationError> {
    use std::fmt::Write;

    struct Diagnostic(String);
    impl std::fmt::Write for Diagnostic {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            if self
                .0
                .len()
                .checked_add(text.len())
                .is_none_or(|length| length > MAXIMUM_DIAGNOSTIC_BYTES)
            {
                return Err(std::fmt::Error);
            }
            self.0.push_str(text);
            Ok(())
        }
    }
    let mut diagnostic = Diagnostic(String::new());
    write!(&mut diagnostic, "{error}")
        .map_err(|_| QualificationError::Refused("acceptance diagnostic ceiling"))?;
    Ok(diagnostic.0)
}
