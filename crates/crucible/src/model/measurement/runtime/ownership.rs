//! Direct measurement output allocation under its original replay authority.

use super::*;
use crate::owned_decode::{charge_btree_entry, charge_bytes, display_string, reserve_vec};

pub(super) fn charge_shared_body<T>() -> Result<(), MeasurementEvaluationError> {
    charge_bytes((std::mem::size_of::<T>() + 2 * std::mem::size_of::<usize>()) as u64)
        .map_err(MeasurementEvaluationError::OriginalAdmission)
}

pub(super) fn reserve<T>(
    output: &mut Vec<T>,
    additional: usize,
) -> Result<(), MeasurementEvaluationError> {
    reserve_vec(output, additional).map_err(MeasurementEvaluationError::OriginalAdmission)
}

pub(super) fn tree_entry<K, V>() -> Result<(), MeasurementEvaluationError> {
    charge_btree_entry::<K, V>().map_err(MeasurementEvaluationError::OriginalAdmission)
}

pub(super) fn copy_measurement(
    value: &MeasurementId,
) -> Result<MeasurementId, MeasurementEvaluationError> {
    charge_bytes(value.as_str().len() as u64)
        .map_err(MeasurementEvaluationError::OriginalAdmission)?;
    Ok(value.clone())
}

pub(super) fn copy_metric(value: &MetricId) -> Result<MetricId, MeasurementEvaluationError> {
    charge_bytes(value.as_str().len() as u64)
        .map_err(MeasurementEvaluationError::OriginalAdmission)?;
    Ok(value.clone())
}

pub(super) fn copy_value(
    value: &MeasurementSampleValue,
) -> Result<MeasurementSampleValue, MeasurementEvaluationError> {
    Ok(match value {
        MeasurementSampleValue::Enumerated(value) => MeasurementSampleValue::Enumerated(
            display_string(value).map_err(MeasurementEvaluationError::OriginalAdmission)?,
        ),
        MeasurementSampleValue::SignedVector(value) => {
            let mut copied = Vec::new();
            reserve(&mut copied, value.len())?;
            copied.extend_from_slice(value);
            MeasurementSampleValue::SignedVector(copied)
        }
        MeasurementSampleValue::UnsignedVector(value) => {
            let mut copied = Vec::new();
            reserve(&mut copied, value.len())?;
            copied.extend_from_slice(value);
            MeasurementSampleValue::UnsignedVector(copied)
        }
        value => value.clone(),
    })
}

pub(super) fn aggregate_copy(
    value: Option<&MeasurementSampleValue>,
    aggregation: &'static str,
) -> Result<MeasurementAggregateValue, MeasurementEvaluationError> {
    let value = value.ok_or(MeasurementEvaluationError::EmptySamples { aggregation })?;
    Ok(copy_value(value)?.into())
}

pub(super) fn copy_node(value: &NodeId) -> Result<NodeId, MeasurementEvaluationError> {
    charge_bytes(value.name.len() as u64).map_err(MeasurementEvaluationError::OriginalAdmission)?;
    Ok(value.clone())
}

pub(super) fn encoding_error(error: &impl std::fmt::Display) -> MeasurementEvaluationError {
    let custody = match crate::owned_decode::require_current_custody() {
        Ok(custody) => custody,
        Err(source) => return MeasurementEvaluationError::OriginalAdmission(source),
    };
    match display_string(error) {
        Ok(reason) => MeasurementEvaluationError::CanonicalEncoding { reason, custody },
        Err(source) => MeasurementEvaluationError::OriginalAdmission(source),
    }
}

pub(super) fn unknown_target(
    kind: &'static str,
    id: &str,
) -> Result<MeasurementEvaluationError, MeasurementEvaluationError> {
    let custody = crate::owned_decode::require_current_custody()
        .map_err(MeasurementEvaluationError::OriginalAdmission)?;
    let id = display_string(id).map_err(MeasurementEvaluationError::OriginalAdmission)?;
    Ok(MeasurementEvaluationError::UnknownSampleTarget { kind, id, custody })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority};
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };

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
        ) -> Result<crate::owned_decode::ResourceLoan, DecodeAdmissionError> {
            self.used
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                    used.checked_add(bytes).filter(|next| *next <= self.maximum)
                })
                .map_err(|_| {
                    DecodeAdmissionError::new(std::io::Error::other(
                        "finite measurement authority exhausted",
                    ))
                })?;
            Ok(crate::owned_decode::ResourceLoan::new(Credit {
                used: Arc::clone(&self.used),
                bytes,
            }))
        }
    }

    fn empty_evaluation() -> Result<MeasurementEvaluation, MeasurementEvaluationError> {
        evaluate_measurements(
            &MeasurementDefinitions::empty(),
            &[],
            Vec::new(),
            &MeasurementTerminalState {
                scenario_ready_at: None,
                at: VirtualTime { ticks: 0 },
                node_icounts: BTreeMap::new(),
                scheduler_quiescent: true,
            },
        )
    }

    #[test]
    fn evaluation_clone_shares_body_and_closes_credit_after_the_final_reader()
    -> Result<(), Box<dyn std::error::Error>> {
        let authority = Arc::new(Authority {
            used: Arc::new(AtomicU64::new(0)),
            maximum: 1 << 20,
        });
        let budget = DecodeBudget::new(authority.clone(), authority.maximum)?;
        let scope = budget.enter();
        let evaluation = empty_evaluation()?;
        let copied = evaluation.clone();
        let charged = authority.used.load(Ordering::SeqCst);
        assert!(charged > 0);
        assert!(Arc::ptr_eq(&evaluation.body, &copied.body));
        assert_eq!(
            evaluation.canonical_bytes().as_ptr(),
            copied.canonical_bytes().as_ptr()
        );
        assert_eq!(authority.used.load(Ordering::SeqCst), charged);

        drop(scope);
        drop(budget);
        drop(evaluation);
        assert_eq!(authority.used.load(Ordering::SeqCst), charged);
        assert!(!copied.canonical_bytes().is_empty());
        drop(copied);
        assert_eq!(authority.used.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn evaluation_refuses_missing_or_exhausted_original_credit_before_output()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            empty_evaluation(),
            Err(MeasurementEvaluationError::OriginalAdmission(_))
        ));
        let authority = Arc::new(Authority {
            used: Arc::new(AtomicU64::new(0)),
            maximum: 1 << 20,
        });
        let budget = DecodeBudget::new(authority.clone(), authority.maximum)?;
        let scope = budget.enter();
        let held = authority.reserve(authority.maximum - authority.used.load(Ordering::SeqCst))?;
        assert!(matches!(
            empty_evaluation(),
            Err(MeasurementEvaluationError::OriginalAdmission(_))
        ));
        drop(held);
        drop(scope);
        drop(budget);
        assert_eq!(authority.used.load(Ordering::SeqCst), 0);
        Ok(())
    }
}
