//! Finite original component journals owned by the authenticated native capsule.
//!
//! Correlation tokens borrow this exact journal; dropping a token never removes
//! a pending native obligation. Native errors and conflicting observations stay
//! retained independently of whether the transport remains usable.

use std::rc::Rc;

use crate::qmp::{
    QmpClient, QmpError, QmpKvmOriginalAckTransaction, QmpKvmOriginalReturnOperation,
    QmpKvmOriginalReturnRequest, QmpKvmOriginalReturnState, QmpKvmOriginalReturnsRequest,
    QmpKvmOriginalWindowRequest, QmpKvmOriginalWindowState, QmpKvmOriginalWindowTransaction,
    QmpTimeoutStream,
};

use super::{KvmComponentError, KvmComponentToken};

// Inline originals consume the finite reservation rather than allocating an
// ACK box after the native effect has already begun.
#[expect(
    clippy::large_enum_variant,
    reason = "inlined original receipts stay inside preallocated journal credit"
)]
pub(super) enum Original {
    Window(QmpKvmOriginalWindowTransaction),
    Ack(QmpKvmOriginalAckTransaction),
}

#[derive(Clone, Copy)]
pub(super) enum Observation {
    Window {
        state: Option<QmpKvmOriginalWindowState>,
        uncertain: bool,
    },
    Ack {
        state: Option<QmpKvmOriginalReturnState>,
        uncertain: bool,
    },
}

pub(super) struct Entry {
    pub(super) original: Original,
    attempts: usize,
}

pub(super) struct Journal<S: QmpTimeoutStream> {
    pub(super) qmp: QmpClient<S>,
    identity: Rc<()>,
    pub(super) entries: Vec<Entry>,
    pub(super) observations: Vec<(usize, Observation)>,
    maximum_entries: usize,
    maximum_attempts: usize,
}

pub(super) struct JournalReservation {
    identity: Rc<()>,
    entries: Vec<Entry>,
    observations: Vec<(usize, Observation)>,
    maximum_entries: usize,
    maximum_attempts: usize,
}

impl JournalReservation {
    pub(super) fn reserve(
        maximum_entries: usize,
        maximum_attempts: usize,
    ) -> Result<Self, KvmComponentError> {
        validate_limits(maximum_entries, maximum_attempts)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(maximum_entries)
            .map_err(|_| KvmComponentError::ResourceLimit)?;
        let mut observations = Vec::new();
        let maximum_observations = maximum_entries
            .checked_mul(maximum_attempts)
            .ok_or(KvmComponentError::ResourceLimit)?;
        observations
            .try_reserve_exact(maximum_observations)
            .map_err(|_| KvmComponentError::ResourceLimit)?;
        Ok(Self {
            identity: Rc::new(()),
            entries,
            observations,
            maximum_entries,
            maximum_attempts,
        })
    }

    pub(super) fn connect<S: QmpTimeoutStream>(self, qmp: QmpClient<S>) -> Journal<S> {
        Journal {
            qmp,
            identity: self.identity,
            entries: self.entries,
            observations: self.observations,
            maximum_entries: self.maximum_entries,
            maximum_attempts: self.maximum_attempts,
        }
    }
}

impl<S: QmpTimeoutStream> Journal<S> {
    pub(super) fn submit_window(
        &mut self,
        request: QmpKvmOriginalWindowRequest,
    ) -> Result<
        (
            KvmComponentToken,
            Result<QmpKvmOriginalWindowState, QmpError>,
        ),
        KvmComponentError,
    > {
        self.reserve_entry()?;
        let original = QmpKvmOriginalWindowTransaction::prepare(request)?;
        if self.entries.iter().any(|entry| {
            matches!(&entry.original, Original::Window(prior) if prior.original().operation == request.operation
                && prior.original().generation == request.generation)
        }) {
            return Err(KvmComponentError::Transition("original window was already retained"));
        }
        let token = self.retain(Original::Window(original));
        let entry = &mut self.entries[token.index];
        let Original::Window(original) = &mut entry.original else {
            return Err(KvmComponentError::ForeignToken);
        };
        let exchange = original.dispatch_once(&mut self.qmp);
        self.observations.push((
            token.index,
            Observation::Window {
                state: original.observation().copied(),
                uncertain: original.uncertain_effects(),
            },
        ));
        Ok((token, exchange))
    }

    pub(super) fn reconcile_window(
        &mut self,
        token: &KvmComponentToken,
    ) -> Result<QmpKvmOriginalWindowState, KvmComponentError> {
        let index = self.admit_attempt(token, true)?;
        let Original::Window(original) = &mut self.entries[index].original else {
            return Err(KvmComponentError::ForeignToken);
        };
        let result = original.reconcile(&mut self.qmp);
        self.observations.push((
            index,
            Observation::Window {
                state: original.observation().copied(),
                uncertain: original.uncertain_effects(),
            },
        ));
        Ok(result?)
    }

    pub(super) fn submit_ack(
        &mut self,
        generation: u64,
        record_index: u32,
    ) -> Result<
        (
            KvmComponentToken,
            Result<QmpKvmOriginalReturnState, QmpError>,
        ),
        KvmComponentError,
    > {
        self.reserve_entry()?;
        if self.entries.iter().any(|entry| {
            matches!(&entry.original, Original::Ack(prior)
                if prior.original().record_index == record_index)
        }) {
            return Err(KvmComponentError::Transition(
                "original ACK was already retained",
            ));
        }

        // Both observations come from this actual owned session. A caller cannot
        // supply a matching row or fabricated receipt to authorize a native ACK.
        let inventory =
            self.qmp
                .query_native_kvm_original_returns(&QmpKvmOriginalReturnsRequest {
                    generation,
                    first_record: record_index,
                    maximum_records: 1,
                })?;
        let identity =
            inventory
                .observed()
                .entries
                .first()
                .ok_or(KvmComponentError::Transition(
                    "original retained return is absent",
                ))?;
        let receipt =
            self.qmp
                .control_native_kvm_original_return(&QmpKvmOriginalReturnRequest {
                    operation: QmpKvmOriginalReturnOperation::Query,
                    record_index,
                    generation: identity.generation,
                    expected_invocation: identity.expected_invocation,
                })?;
        let original = QmpKvmOriginalAckTransaction::prepare(identity, &receipt)?;
        let token = self.retain(Original::Ack(original));
        let entry = &mut self.entries[token.index];
        let Original::Ack(original) = &mut entry.original else {
            return Err(KvmComponentError::ForeignToken);
        };
        let exchange = original.dispatch_once(&mut self.qmp);
        self.observations.push((
            token.index,
            Observation::Ack {
                state: original.latest().copied(),
                uncertain: original.uncertain_effects(),
            },
        ));
        Ok((token, exchange))
    }

    pub(super) fn reconcile_ack(
        &mut self,
        token: &KvmComponentToken,
    ) -> Result<QmpKvmOriginalReturnState, KvmComponentError> {
        let index = self.admit_attempt(token, false)?;
        let Original::Ack(original) = &mut self.entries[index].original else {
            return Err(KvmComponentError::ForeignToken);
        };
        let result = original.reconcile(&mut self.qmp);
        self.observations.push((
            index,
            Observation::Ack {
                state: original.latest().copied(),
                uncertain: original.uncertain_effects(),
            },
        ));
        Ok(result?)
    }

    pub(super) fn history(
        &self,
        token: &KvmComponentToken,
    ) -> Result<Vec<super::KvmComponentObservation>, KvmComponentError> {
        if !Rc::ptr_eq(&self.identity, &token.identity) || token.index >= self.entries.len() {
            return Err(KvmComponentError::ForeignToken);
        }
        let count = self
            .observations
            .iter()
            .filter(|(index, _)| *index == token.index)
            .count();
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(count)
            .map_err(|_| KvmComponentError::ResourceLimit)?;
        for (_, observation) in self
            .observations
            .iter()
            .filter(|(index, _)| *index == token.index)
        {
            retained.push(match observation {
                Observation::Window { state, uncertain } => {
                    super::KvmComponentObservation::Window {
                        state: *state,
                        uncertain: *uncertain,
                    }
                }
                Observation::Ack { state, uncertain } => super::KvmComponentObservation::Ack {
                    state: *state,
                    uncertain: *uncertain,
                },
            });
        }
        Ok(retained)
    }

    fn reserve_entry(&self) -> Result<(), KvmComponentError> {
        if self.entries.len() >= self.maximum_entries {
            return Err(KvmComponentError::ResourceLimit);
        }
        Ok(())
    }

    fn retain(&mut self, original: Original) -> KvmComponentToken {
        let token = KvmComponentToken {
            identity: Rc::clone(&self.identity),
            index: self.entries.len(),
        };
        self.entries.push(Entry {
            original,
            attempts: 1,
        });
        token
    }

    fn admit_attempt(
        &mut self,
        token: &KvmComponentToken,
        window: bool,
    ) -> Result<usize, KvmComponentError> {
        if !Rc::ptr_eq(&self.identity, &token.identity) {
            return Err(KvmComponentError::ForeignToken);
        }
        let entry = self
            .entries
            .get_mut(token.index)
            .ok_or(KvmComponentError::ForeignToken)?;
        if matches!(entry.original, Original::Window(_)) != window {
            return Err(KvmComponentError::ForeignToken);
        }
        if entry.attempts >= self.maximum_attempts {
            return Err(KvmComponentError::ResourceLimit);
        }
        entry.attempts += 1;
        Ok(token.index)
    }
}

pub(super) fn validate_limits(entries: usize, attempts: usize) -> Result<(), KvmComponentError> {
    if entries == 0
        || attempts == 0
        || attempts > 1024
        || entries
            .checked_mul(attempts)
            .is_none_or(|count| count > 65_536)
    {
        return Err(KvmComponentError::ResourceLimit);
    }
    Ok(())
}
