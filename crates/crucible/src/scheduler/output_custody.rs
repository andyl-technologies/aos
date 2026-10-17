//! Original resource custody for retained scheduler append and quantum outputs.
//!
//! Loan bodies are immutable and cheap to share. Deep output copies use a new
//! child of the same authority; moving or combining outputs retains both source
//! loans until their corresponding entry, byte and text fields have closed.

use super::*;
use crate::owned_decode::{DecodeBudget, DecodeCustody, DecodeScope};

/// Retains original admission for event-log output storage.
///
/// Cloning this token shares loan ownership without copying event storage.
/// Its default value is reserved for outputs with no allocated event-log fields.
#[derive(Clone, Default)]
pub struct EventLogOutputCustody {
    bank: Option<Arc<OutputBank>>,
    array_custody: DecodeCustody,
}

struct OutputBank {
    _previous: Option<EventLogOutputCustody>,
    _addition: Option<EventLogOutputCustody>,
    _input: DecodeCustody,
    output: DecodeCustody,
}

impl EventLogOutputCustody {
    /// Retains the current original account for moved output fields.
    ///
    /// # Errors
    /// Refuses missing authority, exhausted original resources or prior refusal.
    pub fn retain_current() -> Result<Self, crate::EngineError> {
        let input = crate::owned_decode::require_current_custody().map_err(admission)?;
        let bank = crate::owned_decode::require_current_child_budget().map_err(admission)?;
        Self::from_budget(&bank, input)
    }

    /// Combines two original loans before combining their owned output fields.
    ///
    /// # Errors
    /// Refuses original admission before allocating the immutable loan body.
    pub fn combine(&self, addition: &Self) -> Result<Self, crate::EngineError> {
        let _original = self
            .enter_decode_scope()
            .or_else(|| addition.enter_decode_scope());
        let bank = crate::owned_decode::require_current_child_budget().map_err(admission)?;
        let _scope = bank.enter();
        reserve_bank()?;
        Ok(Self {
            bank: Some(Arc::new(OutputBank {
                _previous: Some(self.data_custody()),
                _addition: Some(addition.clone()),
                _input: crate::owned_decode::require_current_custody().map_err(admission)?,
                output: bank.custody(),
            })),
            array_custody: self.array_custody.clone(),
        })
    }

    fn data_custody(&self) -> Self {
        Self {
            bank: self.bank.clone(),
            array_custody: DecodeCustody::default(),
        }
    }

    pub(super) fn reserve_entries<T>(
        &mut self,
        entries: &mut Vec<T>,
        additional: usize,
    ) -> Result<(), crate::EngineError> {
        let _scope = self.enter_decode_scope();
        crate::owned_decode::grow_retained_vec(entries, additional, &mut self.array_custody)
            .map_err(admission)
    }

    /// Reenters the retained original account for an output conversion.
    #[must_use]
    pub fn enter_decode_scope(&self) -> Option<DecodeScope> {
        self.bank.as_ref().and_then(|bank| bank.output.enter())
    }

    pub(super) fn from_budget(
        bank: &DecodeBudget,
        input: DecodeCustody,
    ) -> Result<Self, crate::EngineError> {
        let _scope = bank.enter();
        reserve_bank()?;
        Ok(Self {
            bank: Some(Arc::new(OutputBank {
                _previous: None,
                _addition: None,
                _input: input,
                output: bank.custody(),
            })),
            array_custody: DecodeCustody::default(),
        })
    }
}

fn reserve_bank() -> Result<(), crate::EngineError> {
    crate::owned_decode::charge_bytes(
        (std::mem::size_of::<OutputBank>() + 2 * std::mem::size_of::<usize>()) as u64,
    )
    .map_err(admission)
}

fn admission(source: crate::owned_decode::DecodeAdmissionError) -> crate::EngineError {
    crate::EngineError::ArtifactDecodeAdmission { source }
}

impl fmt::Debug for EventLogOutputCustody {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("EventLogOutputCustody")
            .finish_non_exhaustive()
    }
}

// Physical custody is not part of deterministic scheduler output identity.
impl PartialEq for EventLogOutputCustody {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}
impl Eq for EventLogOutputCustody {}
impl std::hash::Hash for EventLogOutputCustody {
    fn hash<H: std::hash::Hasher>(&self, _state: &mut H) {}
}

#[cfg(test)]
mod tests;
