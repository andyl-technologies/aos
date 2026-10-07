//! Original allocation custody for immutable measurement inputs and CBOR output.

use super::*;
use crucible::owned_decode::{DecodeAdmissionError, DecodeBudget, charge_bytes, reserve_vec};
use std::ops::Deref;

/// Flat original output loans retained with a complete measurement trace.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CrucibleMeasurementEventCustody {
    outputs: Vec<crucible::EventLogOutputCustody>,
    table: DecodeCustody,
}

impl CrucibleMeasurementEventCustody {
    pub(crate) fn new() -> Result<Self, crucible::EngineError> {
        let bank = crucible::owned_decode::require_current_child_budget()
            .map_err(|source| crucible::EngineError::ArtifactDecodeAdmission { source })?;
        let _scope = bank.enter();
        charge_bytes(std::mem::size_of::<Self>() as u64)
            .map_err(|source| crucible::EngineError::ArtifactDecodeAdmission { source })?;
        Ok(Self {
            outputs: Vec::new(),
            table: bank.custody(),
        })
    }

    pub(crate) fn retain(
        &mut self,
        output: crucible::EventLogOutputCustody,
    ) -> Result<(), crucible::EngineError> {
        let _scope = self.table.enter();
        if self.outputs.len() == self.outputs.capacity() {
            // Geometric growth bounds both simultaneous old/new table storage
            // and retained credits. A flat table also avoids recursive teardown.
            let target = self
                .outputs
                .capacity()
                .checked_mul(2)
                .map(|capacity| capacity.max(4))
                .ok_or_else(|| crucible::EngineError::ArtifactDecodeAdmission {
                    source: DecodeAdmissionError::new(std::io::Error::other(
                        "measurement output custody capacity overflow",
                    )),
                })?;
            let additional = target - self.outputs.len();
            reserve_vec(&mut self.outputs, additional)
                .map_err(|source| crucible::EngineError::ArtifactDecodeAdmission { source })?;
        }
        self.outputs.push(output);
        Ok(())
    }
}

/// Canonical replay-evidence bytes sharing their original allocation receipt.
///
/// Clones share immutable bytes. The final reader closes the bytes before the
/// original metadata credit, including after the encoding scope has returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrucibleMeasurementEvidenceBytes {
    body: Arc<EncodedEvidence>,
}

#[derive(Debug, PartialEq, Eq)]
struct EncodedEvidence {
    bytes: Vec<u8>,
    custody: DecodeCustody,
}

/// Derived guest and model samples retaining their original allocation credit.
#[derive(Debug)]
pub struct CrucibleMeasurementSamples {
    pub(super) samples: Vec<MeasurementRuntimeSample>,
    pub(super) custody: DecodeCustody,
}

impl Deref for CrucibleMeasurementSamples {
    type Target = [MeasurementRuntimeSample];

    fn deref(&self) -> &Self::Target {
        &self.samples
    }
}

impl CrucibleMeasurementSamples {
    /// Transfers the samples and credit together into an evaluation owner.
    ///
    /// The receiving owner must close all sample fields before its custody.
    #[must_use]
    pub fn into_parts(self) -> (Vec<MeasurementRuntimeSample>, DecodeCustody) {
        (self.samples, self.custody)
    }
}

impl CrucibleMeasurementEvidenceBytes {
    /// Borrows the complete canonical CBOR leaf.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.body.bytes
    }

    #[cfg(test)]
    pub(crate) fn fixture(bytes: &[u8]) -> Result<Self, CrucibleMeasurementError> {
        let child = require_current_child_budget().map_err(admission)?;
        let _scope = child.enter();
        charge_bytes((size_of::<EncodedEvidence>() + 2 * size_of::<usize>()) as u64)
            .map_err(admission)?;
        let mut copied = Vec::new();
        reserve_vec(&mut copied, bytes.len()).map_err(admission)?;
        copied.extend_from_slice(bytes);
        Ok(Self {
            body: Arc::new(EncodedEvidence {
                bytes: copied,
                custody: child.custody(),
            }),
        })
    }
}

impl Deref for CrucibleMeasurementEvidenceBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl AsRef<[u8]> for CrucibleMeasurementEvidenceBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

pub(super) fn encoding_error(error: &impl std::fmt::Display) -> CrucibleMeasurementError {
    let custody = match require_current_custody() {
        Ok(custody) => custody,
        Err(source) => return admission(source),
    };
    match crucible::owned_decode::display_string(error) {
        Ok(reason) => CrucibleMeasurementError::EvidenceEncoding { reason, custody },
        Err(source) => admission(source),
    }
}

pub(super) fn admission(source: DecodeAdmissionError) -> CrucibleMeasurementError {
    crucible::model::MeasurementEvaluationError::OriginalAdmission(source).into()
}

pub(super) fn admitted_body(
    body: ReplayEvidenceBody,
) -> Result<CrucibleMeasurementReplayEvidence, CrucibleMeasurementError> {
    charge_bytes((size_of::<ReplayEvidenceBody>() + 2 * size_of::<usize>()) as u64)
        .map_err(admission)?;
    Ok(CrucibleMeasurementReplayEvidence {
        body: Arc::new(body),
    })
}

pub(super) fn encode(
    evidence: &CrucibleMeasurementReplayEvidence,
    length: usize,
    custody: DecodeCustody,
) -> Result<CrucibleMeasurementEvidenceBytes, CrucibleMeasurementError> {
    charge_bytes((size_of::<EncodedEvidence>() + 2 * size_of::<usize>()) as u64)
        .map_err(admission)?;
    let mut bytes = Vec::new();
    reserve_vec(&mut bytes, length).map_err(admission)?;
    bytes.resize(length, 0);
    let mut remaining = bytes.as_mut_slice();
    ciborium::ser::into_writer(&EvidenceWireRef::from(evidence), &mut remaining)
        .map_err(|error| encoding_error(&error))?;
    if !remaining.is_empty() {
        return Err(CrucibleMeasurementError::NonCanonicalEvidence);
    }
    Ok(CrucibleMeasurementEvidenceBytes {
        body: Arc::new(EncodedEvidence { bytes, custody }),
    })
}

struct BudgetedEvidence(EvidenceWireV2);

impl<'de> Deserialize<'de> for BudgetedEvidence {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let budget = crucible::owned_decode::current_budget()
            .ok_or_else(|| de::Error::custom("measurement evidence requires original authority"))?;
        crucible::owned_decode::deserialize_with_budget(decoder, &budget).map(Self)
    }
}

pub(super) fn decode(
    bytes: &[u8],
    budget: &DecodeBudget,
) -> Result<EvidenceWireV2, CrucibleMeasurementError> {
    let result = ciborium::de::from_reader::<BudgetedEvidence, _>(bytes);
    budget.check().map_err(admission)?;
    result
        .map(|wire| wire.0)
        .map_err(|error| encoding_error(&error))
}

/// Covers the pinned parser's scalar growth and closed derived diagnostics.
pub(super) fn parser_peak(bytes: usize) -> Result<u64, CrucibleMeasurementError> {
    let bytes =
        u64::try_from(bytes).map_err(|error| admission(DecodeAdmissionError::new(error)))?;
    // Ciborium 0.2.2 appends consumed scalar bytes: capacity <= max(2*input,8),
    // and old/new allocations can overlap. Its tags/recursion are inline.
    // Derived diagnostic strings may escape each input byte to six characters;
    // 8192 covers the closed field/variant names and fixed numeric diagnostics.
    bytes
        .checked_mul(2)
        .map(|value| value.max(8))
        .and_then(|value| value.checked_mul(2))
        .and_then(|scalar| {
            bytes
                .checked_mul(6)
                .and_then(|value| value.checked_add(8192))
                .and_then(|value| value.checked_mul(4))
                .and_then(|diagnostics| scalar.checked_add(diagnostics))
        })
        .ok_or_else(|| {
            admission(DecodeAdmissionError::new(io::Error::other(
                "measurement CBOR parser bank overflow",
            )))
        })
}

pub(super) fn is_canonical(
    evidence: &CrucibleMeasurementReplayEvidence,
    expected: &[u8],
) -> Result<bool, CrucibleMeasurementError> {
    let mut comparison = Comparison {
        expected,
        position: 0,
        matches: true,
    };
    ciborium::ser::into_writer(&EvidenceWireRef::from(evidence), &mut comparison)
        .map_err(|error| encoding_error(&error))?;
    Ok(comparison.matches && comparison.position == expected.len())
}

struct Comparison<'a> {
    expected: &'a [u8],
    position: usize,
    matches: bool,
}

impl Write for Comparison<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let end = self
            .position
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("measurement comparison length overflow"))?;
        self.matches &= self.expected.get(self.position..end) == Some(bytes);
        self.position = end;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible::owned_decode::DecodeResourceAuthority;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Authority {
        used: Arc<AtomicU64>,
        maximum: u64,
    }
    struct Credit {
        used: Arc<AtomicU64>,
        bytes: u64,
    }

    impl Drop for Credit {
        fn drop(&mut self) {
            self.used.fetch_sub(self.bytes, Ordering::SeqCst);
        }
    }

    impl DecodeResourceAuthority for Authority {
        fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
            if self.used.load(Ordering::SeqCst) > self.maximum {
                return Err(DecodeAdmissionError::new(std::io::Error::other(
                    "original component accounting is invalid",
                )));
            }
            Ok(())
        }

        fn reserve(
            &self,
            bytes: u64,
        ) -> Result<crucible_cas::owned_decode::ResourceLoan, DecodeAdmissionError> {
            self.used
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                    used.checked_add(bytes).filter(|next| *next <= self.maximum)
                })
                .map_err(|_| {
                    DecodeAdmissionError::new(io::Error::other(
                        "finite evidence authority exhausted",
                    ))
                })?;
            Ok(crucible_cas::owned_decode::ResourceLoan::new(Credit {
                used: Arc::clone(&self.used),
                bytes,
            }))
        }
    }

    fn publication() -> Result<CrucibleMeasurementPublication, CrucibleMeasurementError> {
        evaluate_crucible_measurement_publication(
            ScenarioDefId::from_hash(CampaignHash::derive("fixture.scenario", b"custody")),
            ConfigurationId::from_hash(CampaignHash::derive("fixture.configuration", b"custody")),
            &MeasurementDefinitions::empty(),
            Vec::new(),
            MeasurementTerminalState {
                scenario_ready_at: None,
                at: VirtualTime { ticks: 0 },
                node_icounts: BTreeMap::new(),
                scheduler_quiescent: true,
            },
            MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
        )
    }

    #[test]
    fn cloned_evidence_and_bytes_keep_credit_until_the_final_reader()
    -> Result<(), Box<dyn std::error::Error>> {
        let authority = Arc::new(Authority {
            used: Arc::new(AtomicU64::new(0)),
            maximum: 1 << 20,
        });
        let budget = DecodeBudget::new(authority.clone(), authority.maximum)?;
        let scope = budget.enter();
        let (evidence, bytes, measurements) = publication()?.into_parts();
        let evidence_clone = evidence.clone();
        let bytes_clone = bytes.clone();
        let measurement_clone = measurements.clone();
        let charged = authority.used.load(Ordering::SeqCst);
        assert!(charged > 0);
        assert!(Arc::ptr_eq(&evidence.body, &evidence_clone.body));
        assert!(Arc::ptr_eq(&bytes.body, &bytes_clone.body));
        assert_eq!(authority.used.load(Ordering::SeqCst), charged);
        drop(scope);
        drop(budget);
        drop(evidence);
        drop(bytes);
        drop(measurements);
        assert!(authority.used.load(Ordering::SeqCst) > 0);
        assert!(
            CrucibleMeasurementReplayEvidence::from_canonical_bytes(bytes_clone.as_slice())
                .is_err()
        );
        let reentered = evidence_clone.body.custody.enter();
        let decoded =
            CrucibleMeasurementReplayEvidence::from_canonical_bytes(bytes_clone.as_slice())?;
        assert_eq!(decoded, evidence_clone);
        drop(decoded);
        drop(reentered);
        drop(evidence_clone);
        drop(bytes_clone);
        assert!(authority.used.load(Ordering::SeqCst) > 0);
        drop(measurement_clone);
        assert_eq!(authority.used.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn canonical_encoding_refuses_exhausted_original_credit_before_output()
    -> Result<(), Box<dyn std::error::Error>> {
        let authority = Arc::new(Authority {
            used: Arc::new(AtomicU64::new(0)),
            maximum: 1 << 20,
        });
        let budget = DecodeBudget::new(authority.clone(), authority.maximum)?;
        let scope = budget.enter();
        let (evidence, bytes, measurements) = publication()?.into_parts();
        drop(scope);
        drop(budget);
        drop(bytes);
        drop(measurements);
        let original = evidence.body.custody.enter();
        let held = authority.reserve(authority.maximum - authority.used.load(Ordering::SeqCst))?;
        assert!(matches!(
            evidence.canonical_bytes(),
            Err(CrucibleMeasurementError::Evaluation(
                crucible::model::MeasurementEvaluationError::OriginalAdmission(_)
            ))
        ));
        drop(held);
        drop(original);
        drop(evidence);
        assert_eq!(authority.used.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn flat_quantum_output_loans_survive_the_last_measurement_reader()
    -> Result<(), Box<dyn std::error::Error>> {
        let authority = Arc::new(Authority {
            used: Arc::new(AtomicU64::new(0)),
            maximum: 64 * 1024,
        });
        let original = DecodeBudget::new(authority.clone(), authority.maximum)?;
        let scope = original.enter();
        let mut outputs = CrucibleMeasurementEventCustody::new()?;
        for _ in 0..16 {
            let quantum = original.child()?;
            let _quantum_scope = quantum.enter();
            charge_bytes(1024)?;
            outputs.retain(crucible::EventLogOutputCustody::retain_current()?)?;
        }
        let final_reader = outputs.outputs[0].clone();

        drop(scope);
        drop(original);
        assert!(authority.used.load(Ordering::SeqCst) > 16 * 1024);
        drop(outputs);
        assert!(authority.used.load(Ordering::SeqCst) >= 1024);
        drop(final_reader);
        assert_eq!(authority.used.load(Ordering::SeqCst), 0);
        Ok(())
    }
}
