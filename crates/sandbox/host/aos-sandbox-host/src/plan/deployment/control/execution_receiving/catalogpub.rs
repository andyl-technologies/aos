//! Adds a finite catalog preparation to the same consumed Control invoice.

use super::*;

impl HostExecutionReceivingV2 {
    pub(in crate::plan::deployment::control) fn completed_catalog_control_demand_data_v2(
        &self,
    ) -> Result<ResourceVector, Closed> {
        if !self.control_was_consumed() || !self.execution_admitted
            || self.active.is_some() || self.prepared.is_some()
            || self.flights.iter().any(|flight| flight.request.is_some()) {
            return Err(Closed);
        }
        let remaining = self.control_requirement.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(Closed)?;
        self.control_capacity.checked_sub(*remaining).map_err(|_| Closed)
    }

    pub(in crate::plan::deployment::control) fn admit_catalog_publication_v2(
        &mut self,
        additional: ResourceVector,
    ) -> Result<(), Closed> {
        // Publication is a control operation between execution flights. It
        // neither spends a Prepare/Accept/Launch slot nor repairs one.
        if !self.control_was_consumed()
            || !self.execution_admitted
            || self.active.is_some()
            || self.prepared.is_some()
            || self.flights.iter().any(|flight| flight.request.is_some())
        {
            self.closed = true;
            return Err(Closed);
        }
        self.account_control_preparation_v5(additional)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn original() -> HostExecutionReceivingV2 {
        let profile = ExecutionReceivingProfileV2 {
            prepare: [100; 22], accept: [100; 22], launch: [100; 22],
            boot_preparation: None,
        };
        let mut owner = HostExecutionReceivingV2::from_reserved_subdivisions(
            ResourceVector::new([400; 22]), profile, ResourceVector::new([100; 22]),
        ).unwrap();
        owner.execution_admitted = false;
        owner.consume_control_once(ResourceVector::ZERO).unwrap();
        owner.admit_execution_once().unwrap();
        owner
    }

    #[test]
    fn repeated_catalogs_preserve_same_control_spend_and_exhaustion() {
        let mut owner = original();
        let charged = owner.ledger.charged();
        let reached = ResourceVector::ZERO.with(D::StorageBytes, 17)
            .with(D::PublicationStagingBytes, 19).with(D::OutputBytes, 11);
        owner.admit_catalog_publication_v2(reached).unwrap();
        owner.admit_catalog_publication_v2(reached).unwrap();

        let remaining = owner.control_requirement.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(remaining.get(D::StorageBytes), 66);
        assert_eq!(remaining.get(D::PublicationStagingBytes), 62);
        assert_eq!(remaining.get(D::OutputBytes), 78);
        assert_eq!(owner.ledger.charged(), charged);
        assert!(owner.control_operation.as_ref().unwrap().is_consumed_current());

        assert!(owner.admit_catalog_publication_v2(
            ResourceVector::ZERO.with(D::PublicationStagingBytes, 63)).is_err());
        let refusal = *owner.control_requirement.as_ref().unwrap().as_ref().err().unwrap();
        assert!(owner.admit_catalog_publication_v2(ResourceVector::ZERO).is_err());
        assert_eq!(owner.control_requirement.as_ref().unwrap().as_ref().err(), Some(&refusal));
        assert_eq!(owner.ledger.charged(), charged);
    }

    #[test]
    fn active_execution_cannot_lend_catalog_publication_control() {
        let mut owner = original();
        owner.active = Some(Phase::Launch);

        assert!(owner.admit_catalog_publication_v2(ResourceVector::ZERO).is_err());
        assert!(owner.closed);
    }
}
