//! Shares the existing fixed-property archive below its actual role owners.
//!
//! The native worker/IO/decoder/disposal body remains Systemd's sole engine.
//! This adapter shares its lifetime gate and canonical immutable DATA views;
//! it owns no ledger, role admission, image authority or successful post proof.

use crate::profile_data::property_values::{PropertyPairV1, PropertyValuesV1};
use super::RootObservationErrorV1;

/// Retains the actual growth allocation error in its original J parent.
#[derive(Debug, thiserror::Error)]
pub enum FixedPropertyArchiveGrowthErrorV1 {
    #[error("Create continuation observer archive is closed")]
    Closed,
    #[error("Create continuation observer archive allocation failed")]
    Allocation(#[source] std::collections::TryReserveError),
}

/// Retains native property rows and the same monotone closure DATA.
///
/// The role prepays the archive and authorizes every fixed recipe itself.
/// Constructing this mechanical owner admits no observation or role.
pub struct FixedPropertyArchiveV1 {
    mechanical: aos_systemd_client::FixedPid1PropertyArchiveV1,
    lifetime: super::ObservationLifetimeV1,
}

impl FixedPropertyArchiveV1 {
    /// Prices one original Controller observer row and its existing slot header.
    ///
    /// # Errors
    /// Rejects unsupported or overflowing native/slot geometry.
    pub fn controller_observer_row_demand_v1(
    ) -> Result<aos_sandbox_model::ResourceVector, RootObservationErrorV1> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        use aos_systemd_client::ControllerPropertyObserverAttemptV1 as Observer;

        let maximum = Observer::MESSAGE_BYTES.checked_mul(Observer::INCOMING_MESSAGES)
            .ok_or(RootObservationErrorV1::Service)?;
        let rows = Self::observer_materialization_demand_v1(maximum)?;
        let custody = u64::try_from(Self::controller_observer_slot_bytes_v1())
            .map_err(|_| RootObservationErrorV1::Service)?;
        rows.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, custody))
            .map_err(|_| RootObservationErrorV1::Service)
    }

    /// Reports the actual native archive/lifetime slot header size as DATA.
    #[must_use]
    pub const fn controller_observer_slot_bytes_v1() -> usize {
        crate::controller_receiving::profile::ControllerSelfProfileOriginalV1::original_observer_slot_bytes_v1()
    }

    /// Reports the actual native archive/lifetime slot alignment as DATA.
    #[must_use]
    pub const fn controller_observer_slot_alignment_v1() -> usize {
        crate::controller_receiving::profile::ControllerSelfProfileOriginalV1::original_observer_slot_alignment_v1()
    }

    /// Prices the existing complete PID1 observer materialization.
    ///
    /// # Errors
    /// Rejects invalid or overflowing native receiver geometry.
    pub fn observer_materialization_demand_v1(
        materialized_bytes: usize,
    ) -> Result<aos_sandbox_model::ResourceVector, RootObservationErrorV1> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        use aos_systemd_client::FixedPid1PropertyArchiveV1 as Archive;

        let shape = Archive::geometry_v1(materialized_bytes)
            .map_err(|_| RootObservationErrorV1::Service)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, shape.memory_bytes)
            .with(D::OpenFiles, shape.open_files)
            .with(D::MetadataEntries, shape.metadata_entries)
            .with(D::NetworkBytes, shape.wire_io_bytes)
            .with(D::PublicationStagingBytes, shape.memory_bytes)
            .with(D::LogBytes, shape.maximum_log_bytes)
            .with(D::OutputBytes, shape.memory_bytes))
    }

    /// Computes the bounded count of complete rows across all dimensions.
    ///
    /// # Errors
    /// Rejects an empty row or an unrepresentable count.
    pub fn receiving_capacity_data_v1(
        remaining: aos_sandbox_model::ResourceVector,
        per_slot: aos_sandbox_model::ResourceVector,
    ) -> Result<usize, RootObservationErrorV1> {
        use aos_sandbox_model::ResourceDimension as D;

        let mut capacity = None;
        for dimension in D::ALL {
            let demand = per_slot.get(dimension);
            if demand != 0 {
                let count = remaining.get(dimension) / demand;
                capacity = Some(capacity.map_or(count, |previous: u64| previous.min(count)));
            }
        }
        usize::try_from(capacity.ok_or(RootObservationErrorV1::Service)?)
            .map_err(|_| RootObservationErrorV1::Service)
    }

    /// Multiplies complete row requirements with checked all-dimension arithmetic.
    ///
    /// # Errors
    /// Rejects an unrepresentable row count or product.
    pub fn multiply_receiving_demand_data_v1(
        vector: aos_sandbox_model::ResourceVector,
        count: usize,
    ) -> Result<aos_sandbox_model::ResourceVector, RootObservationErrorV1> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

        let count = u64::try_from(count).map_err(|_| RootObservationErrorV1::Service)?;
        let mut result = ResourceVector::ZERO;
        for dimension in D::ALL {
            let amount = vector.get(dimension).checked_mul(count)
                .ok_or(RootObservationErrorV1::Service)?;
            result = result.with(dimension, amount);
        }
        Ok(result)
    }


    /// Creates the existing default bounded native archive without IO.
    pub fn new(
        maximum: usize,
        lifetime: super::ObservationLifetimeV1,
    ) -> Self {
        use aos_systemd_client::ControllerPropertyObserverAttemptV1 as Observer;

        Self::with_materialization_limit(
            maximum, lifetime, Observer::MESSAGE_BYTES * Observer::INCOMING_MESSAGES,
        )
    }

    // DATA sizing never constructs a genuine interval. The original caller
    // prepays this same receiver before this private role adapter is entered.
    /// Creates empty native row custody at the already-paid byte limit.
    pub fn with_materialization_limit(
        maximum: usize,
        lifetime: super::ObservationLifetimeV1,
        materialization_limit: usize,
    ) -> Self {
        Self {
            mechanical: aos_systemd_client::FixedPid1PropertyArchiveV1::with_materialization_limit(
                maximum, materialization_limit,
            ),
            lifetime,
        }
    }

    /// Prepares the actual bounded native archive once.
    ///
    /// # Errors
    /// Keeps the original native preparation failure in the archive.
    pub fn prepare(&mut self) -> Result<(), RootObservationErrorV1> {
        self.mechanical.prepare_once().map_err(|_| RootObservationErrorV1::Service)
    }

    // This remains reachable only after the genuine same-J increment paid
    // every new row/backing; the lower mechanism issues no financial grant.
    /// Borrows the actual archived worker cause under its native guard.
    ///
    /// This diagnostic view performs no observation, admission or retirement.
    /// Its cause cannot outlive the guard or the same archive's borrowed owner.
    #[must_use]
    pub fn failure_view(&self) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        self.mechanical.failure_view()
    }

    /// Grows mechanical row storage after the role's independent payment.
    ///
    /// # Errors
    /// Returns the actual allocation error or closed lifetime diagnostic.
    pub fn grow_rows(
        &mut self,
        maximum: usize,
    ) -> Result<(), FixedPropertyArchiveGrowthErrorV1> {
        if !self.lifetime.is_open() {
            return Err(FixedPropertyArchiveGrowthErrorV1::Closed);
        }
        self.mechanical.grow_rows(maximum).map_err(|error| match error {
            aos_systemd_client::FixedPid1PropertyGrowthErrorV1::Closed => FixedPropertyArchiveGrowthErrorV1::Closed,
            aos_systemd_client::FixedPid1PropertyGrowthErrorV1::Allocation(cause) => {
                FixedPropertyArchiveGrowthErrorV1::Allocation(cause)
            }
        })
    }

    /// Disposes only complete positive joined native rows.
    ///
    /// # Errors
    /// Refuses an unfinished or negative row and preserves its whole custody.
    pub fn settle_positive_once(&mut self) -> Result<(), RootObservationErrorV1> {
        self.mechanical.settle_positive_once().map_err(|_| RootObservationErrorV1::Service)
    }

    /// Observes bounded property DATA using the existing native row engine.
    ///
    /// # Errors
    /// Refuses a closed lifetime, oversized recipe or native/property failure.
    /// The actual row remains in the archive on every negative result.
    pub fn read(
        &mut self,
        unit_name: &'static str,
        pid: u32,
        properties: &'static [&'static str],
    ) -> Result<PropertyPairV1, RootObservationErrorV1> {
        if !self.lifetime.is_open() || properties.len() > super::ROOT_PEER_PROPERTIES_V1.len() {
            return Err(RootObservationErrorV1::Service);
        }
        let (service, unit) = self.mechanical.read(unit_name, pid, properties, crate::profile_data::delivery::UNIT_PROPERTIES)
            .map_err(|_| RootObservationErrorV1::Service)?;
        Ok((PropertyValuesV1::retained_owned(service), PropertyValuesV1::retained_owned(unit)))
    }
}

/// Reports the existing fixed-property resident/traffic geometry as DATA.
///
/// This preserves the upper recipe's separate task admission. The actual
/// role must price its worker concurrency independently before native IO.
///
/// # Errors
/// Refuses invalid or overflowing fixed-property geometry.
pub fn fixed_property_observer_demand_v1(
    materialized_bytes: usize,
) -> Result<aos_sandbox_model::ResourceVector, RootObservationErrorV1> {
    use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
    use aos_systemd_client::FixedPid1PropertyArchiveV1 as Archive;

    let shape = Archive::fixed_property_geometry_v1(materialized_bytes)
        .map_err(|_| RootObservationErrorV1::Service)?;
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, shape.memory_bytes)
        .with(D::OpenFiles, shape.open_files)
        .with(D::MetadataEntries, shape.metadata_entries)
        .with(D::NetworkBytes, shape.wire_io_bytes)
        .with(D::PublicationStagingBytes, shape.memory_bytes)
        .with(D::LogBytes, shape.maximum_log_bytes)
        .with(D::OutputBytes, shape.memory_bytes))
}

/// Prices the same growing fixed archive row including old/new entry backing.
///
/// This pure geometry creates no observer, lifetime, financial or role grant.
///
/// # Errors
/// Refuses checked row geometry or representation overflow.
pub fn growing_fixed_property_archive_demand_v1(
    materialized_bytes: usize,
) -> Result<aos_sandbox_model::ResourceVector, RootObservationErrorV1> {
    use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

    let row = fixed_property_observer_demand_v1(materialized_bytes)?;
    let backing = aos_systemd_client::FixedPid1PropertyArchiveV1::entry_bytes_v1()
        .checked_mul(2)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(RootObservationErrorV1::Service)?;
    row.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, backing)
        .with(D::PublicationStagingBytes, backing).with(D::OutputBytes, backing))
        .map_err(|_| RootObservationErrorV1::Service)
}
