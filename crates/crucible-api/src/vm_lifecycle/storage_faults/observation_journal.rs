//! Owns globally sequenced storage-fault observation batches.

use super::*;

impl ProductionFaultObservationJournal {
    pub(super) fn ensure_capacity(&self, additional: usize) -> Result<(), DeviceRuntimeError> {
        self.observations
            .checked_add(additional)
            .filter(|count| *count <= HARD_STORAGE_FAULT_OBSERVATIONS)
            .map(|_count| ())
            .ok_or_else(|| {
                storage_error(
                    "record fault observations",
                    "fault observation journal exceeds its hard bound",
                )
            })
    }

    pub(in crate::vm_lifecycle) fn append(
        &mut self,
        sequence: u64,
        observations: Vec<FaultObservation>,
    ) -> Result<(), DeviceRuntimeError> {
        self.append_observation_batches(vec![(sequence, observations)])?;
        Ok(())
    }

    pub(in crate::vm_lifecycle) fn append_observation_batches(
        &mut self,
        batches: Vec<(u64, Vec<FaultObservation>)>,
    ) -> Result<(), DeviceRuntimeError> {
        let additional = batches
            .iter()
            .try_fold(0_usize, |count, (_, batch)| count.checked_add(batch.len()));
        let additional = additional.ok_or_else(|| {
            storage_error(
                "record fault observations",
                "fault observation batch count overflow",
            )
        })?;
        self.ensure_capacity(additional)?;
        self.observations += additional;
        for (sequence, observations) in batches {
            self.batches
                .entry(sequence)
                .or_default()
                .extend(observations);
        }
        Ok(())
    }

    pub(super) fn append_batches(
        &mut self,
        batches: Vec<(u64, FaultObservation)>,
    ) -> Result<(), DeviceRuntimeError> {
        self.ensure_capacity(batches.len())?;
        self.observations += batches.len();
        for (sequence, observation) in batches {
            self.batches.entry(sequence).or_default().push(observation);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn snapshot(&self) -> Vec<FaultObservation> {
        self.batches.values().flatten().cloned().collect()
    }

    pub(in crate::vm_lifecycle) fn drain_ready(&mut self, frontier: u64) -> Vec<FaultObservation> {
        let mut ready = Vec::new();
        for (sequence, observations) in &mut self.batches {
            let mut retained = Vec::new();
            for (index, observation) in std::mem::take(observations).into_iter().enumerate() {
                if observation.coordinate.virtual_nanos <= frontier {
                    ready.push((
                        observation.coordinate.virtual_nanos,
                        *sequence,
                        index,
                        observation,
                    ));
                } else {
                    retained.push(observation);
                }
            }
            *observations = retained;
        }
        self.batches
            .retain(|_sequence, observations| !observations.is_empty());
        self.observations = self.batches.values().map(Vec::len).sum();
        ready.sort_by_key(|(nanos, sequence, index, _observation)| (*nanos, *sequence, *index));
        ready
            .into_iter()
            .map(|(_nanos, _sequence, _index, observation)| observation)
            .collect()
    }

    pub(in crate::vm_lifecycle) fn validate(&self, next_sequence: u64) -> bool {
        let actual = self
            .batches
            .values()
            .try_fold(0_usize, |count, batch| count.checked_add(batch.len()));
        self.observations <= HARD_STORAGE_FAULT_OBSERVATIONS
            && actual == Some(self.observations)
            && self.batches.iter().all(|(sequence, batch)| {
                *sequence < next_sequence
                    && !batch.is_empty()
                    && batch.iter().all(|observation| {
                        observation.semantic_version == FAULT_RUNTIME_STATE_VERSION
                            && observation.evidence != ContentHash::default()
                    })
            })
    }

    pub(in crate::vm_lifecycle) fn contains_sequence(&self, sequence: u64) -> bool {
        self.batches.contains_key(&sequence)
    }

    pub(in crate::vm_lifecycle) fn rollback_sequence(
        &mut self,
        sequence: u64,
    ) -> Result<(), DeviceRuntimeError> {
        if let Some(observations) = self.batches.remove(&sequence) {
            self.observations = self
                .observations
                .checked_sub(observations.len())
                .ok_or_else(|| {
                    storage_error(
                        "roll back fault observations",
                        "fault observation journal count is inconsistent",
                    )
                })?;
        }
        Ok(())
    }
}
