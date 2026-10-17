//! Keeps original epoch bodies under the actual restored coordinator activation.

use super::*;
use crate::node_scheduling::{
    InputPayload, SavedReservation, SavedSchedulingEpoch, SchedulingSnapshot,
};

impl CausalScheduler {
    pub(crate) fn scheduling_epoch_evidence(
        &self,
        snapshot: &SchedulingSnapshot,
    ) -> Result<Option<crate::node_scheduling::SchedulingEpochEvidence>, SchedulingError> {
        let Some(rows) = &snapshot.original_epochs else {
            return Ok(None);
        };
        let original = self
            .restored_epochs
            .as_ref()
            .ok_or(SchedulingError::UnresolvedCustody)?;
        let objects = self.scheduling_epoch_objects(snapshot)?;
        Ok(Some(crate::node_scheduling::SchedulingEpochEvidence {
            rows: rows.clone(),
            policy: original.policy.clone(),
            objects: objects
                .into_iter()
                .filter(|body| body.reference != original.policy.reference)
                .collect(),
        }))
    }

    pub(super) fn retained_epoch_rows(
        &self,
        reservations: &[SavedReservation],
    ) -> Result<Option<Vec<SavedSchedulingEpoch>>, SchedulingError> {
        let Some(evidence) = &self.restored_epochs else {
            return Ok(None);
        };
        let boundary = self.activation.record().boundary;
        let mut rows = Vec::new();
        rows.try_reserve(evidence.rows.len())
            .map_err(|_| SchedulingError::InvalidSnapshot)?;
        let mut covered = BTreeSet::new();
        for saved in &evidence.rows {
            let mut row = saved.clone();
            row.reservations.retain(|inherited| {
                self.owners
                    .get(&inherited.position.owner)
                    .is_some_and(|owner| owner.cursor < boundary)
            });
            if row.reservations.is_empty() {
                continue;
            }
            for inherited in &row.reservations {
                if !reservations.contains(&inherited.reservation)
                    || self
                        .owners
                        .get(&inherited.position.owner)
                        .is_none_or(|owner| owner.cursor != inherited.position.position)
                    || !covered.insert(inherited.position.owner.clone())
                {
                    return Err(SchedulingError::UnresolvedCustody);
                }
            }
            rows.push(row);
        }
        if self
            .owners
            .iter()
            .any(|(owner, schedule)| schedule.cursor < boundary && !covered.contains(owner))
        {
            return Err(SchedulingError::UnresolvedCustody);
        }
        if rows.is_empty() {
            return Ok(None);
        }
        rows.sort_by(|left, right| left.scheduler.cmp(&right.scheduler));
        Ok(Some(rows))
    }

    pub(crate) fn scheduling_epoch_objects(
        &self,
        snapshot: &SchedulingSnapshot,
    ) -> Result<Vec<InputPayload>, SchedulingError> {
        let Some(rows) = &snapshot.original_epochs else {
            return Ok(Vec::new());
        };
        let evidence = self
            .restored_epochs
            .as_ref()
            .ok_or(SchedulingError::UnresolvedCustody)?;
        let mut references = BTreeSet::new();
        for row in rows {
            references.extend([
                row.coordinator.clone(),
                row.scheduler.clone(),
                row.runtime.clone(),
                row.policy.clone(),
            ]);
        }
        let mut objects = Vec::new();
        objects
            .try_reserve(references.len())
            .map_err(|_| SchedulingError::InvalidSnapshot)?;
        for reference in references {
            let body = if reference == evidence.policy.reference {
                &evidence.policy
            } else {
                evidence
                    .objects
                    .iter()
                    .find(|body| body.reference == reference)
                    .ok_or(SchedulingError::UnresolvedCustody)?
            };
            objects.push(body.clone());
        }
        Ok(objects)
    }
}
