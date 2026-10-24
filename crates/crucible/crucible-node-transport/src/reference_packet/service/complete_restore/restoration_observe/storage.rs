//! Keeps independently quoted once-observation axes as inert fixed DATA.

use super::*;

/// Names independent SDK, native and extra Source evidence observation demand.
///
/// Only the defining pre-Prepare producer constructs this fixed Copy row. A
/// genuine Window binds and admits it with all other live owners before issuing
/// its once observation claim. Copying or comparing this DATA grants no effect.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OriginalInstalledRestorationObservationConstructionData {
    pub(super) controller: *const (),
    pub(super) native: PacketRestorationActivationAllocationRow,
    pub(super) host_retained: usize,
    pub(super) host_transient: usize,
    pub(super) host_scratch: usize,
    pub(super) source_evidence_retained: usize,
    pub(super) source_evidence_transient: usize,
    pub(super) source_evidence_scratch: usize,
    pub(super) requested: usize,
    pub(super) scratch: usize,
}

impl OriginalInstalledRestorationObservationConstructionData {
    /// Compares every defining fixed axis and the actual Controller identity.
    ///
    /// # Errors
    /// Refuses a changed owner pointer, native/Host/evidence axis or total.
    /// Equal totals never substitute for full fixed correspondence.
    pub fn authenticate_same_construction_data(&self, other: &Self) -> Result<(), ProviderError> {
        if self != other {
            return Err(invalid());
        }
        Ok(())
    }

    /// Checks this DATA's defining Controller pointer without issuing a claim.
    ///
    /// # Errors
    /// Refuses a missing/different actual pointer or unavailable whole demand.
    pub(crate) fn authenticate_controller_data(
        &self,
        controller: *const (),
    ) -> Result<(), ProviderError> {
        if self.controller.is_null() || self.controller != controller || self.requested == 0 {
            return Err(invalid());
        }
        Ok(())
    }

    /// Returns the independently admitted native observation row.
    pub fn native_allocation_data(&self) -> PacketRestorationActivationAllocationRow {
        self.native
    }

    /// Returns the whole independent Host and native construction demand.
    ///
    /// Extra Source evidence axes are exposed separately and are added by its
    /// genuine producer alongside its own raw/typed/MAC/semantic owners.
    pub fn requested_bytes_data(&self) -> usize {
        self.requested
    }

    /// Returns actual fixed prospective producer and row wrapper demand.
    pub fn counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    /// Returns independent retained SDK original, terminal and content demand.
    pub fn host_retained_requested_bytes_data(&self) -> usize {
        self.host_retained
    }

    /// Returns full simultaneous SDK assignment, canonical and exchange work.
    pub fn host_maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.host_transient
    }

    /// Returns fixed SDK borrowed, conversion, result and owner views.
    pub fn host_declared_counter_scratch_bytes_data(&self) -> usize {
        self.host_scratch
    }

    /// Returns additional independent Source-owned native evidence backing.
    pub fn source_evidence_retained_requested_bytes_data(&self) -> usize {
        self.source_evidence_retained
    }

    /// Returns Source evidence decode/revalidation overlap beside retained owners.
    pub fn source_evidence_maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.source_evidence_transient
    }

    /// Returns actual defining evidence decoder and raw-walk result headers.
    pub fn source_evidence_counter_scratch_bytes_data(&self) -> usize {
        self.source_evidence_scratch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observation_data_full_correspondence_refuses_equal_total_changed_axes() {
        let row = OriginalInstalledRestorationObservationConstructionData {
            controller: std::ptr::null(),
            native: PacketRestorationActivationAllocationRow {
                retained_requested_bytes: U64::new(10),
                maximum_simultaneous_transient_bytes: U64::new(20),
                declared_counter_scratch_bytes: U64::new(30),
            },
            host_retained: 40,
            host_transient: 50,
            host_scratch: 60,
            source_evidence_retained: 70,
            source_evidence_transient: 80,
            source_evidence_scratch: 90,
            requested: 100,
            scratch: 110,
        };
        row.authenticate_same_construction_data(&row).unwrap();
        let changed = OriginalInstalledRestorationObservationConstructionData {
            native: PacketRestorationActivationAllocationRow {
                retained_requested_bytes: U64::new(11),
                maximum_simultaneous_transient_bytes: U64::new(19),
                ..row.native
            },
            ..row
        };
        assert_eq!(
            row.native.requested_bytes_data().unwrap(),
            changed.native.requested_bytes_data().unwrap()
        );
        assert!(row.authenticate_same_construction_data(&changed).is_err());
        let changed = OriginalInstalledRestorationObservationConstructionData {
            host_retained: 41,
            host_transient: 49,
            ..row
        };
        assert!(row.authenticate_same_construction_data(&changed).is_err());
        let changed = OriginalInstalledRestorationObservationConstructionData {
            source_evidence_retained: 71,
            source_evidence_transient: 79,
            ..row
        };
        assert!(row.authenticate_same_construction_data(&changed).is_err());
        assert!(row.authenticate_controller_data(std::ptr::null()).is_err());
    }
}

/// Borrows every portable fixed field of the original DATA row.
///
/// The representation has no decoder, owned identity copy or conversion back
/// to a live construction row. Process-private Controller identity is omitted.
pub struct OriginalInstalledRestorationObservationHistoricalData<'a> {
    original: &'a OriginalInstalledRestorationObservationConstructionData,
}

impl OriginalInstalledRestorationObservationConstructionData {
    /// Lends all fixed historical axes without allocating or authenticating them.
    pub fn historical_data(&self) -> OriginalInstalledRestorationObservationHistoricalData<'_> {
        OriginalInstalledRestorationObservationHistoricalData { original: self }
    }

    /// Names the complete borrowed fixed-row historical projection views.
    pub fn historical_counter_scratch_data() -> usize {
        std::mem::size_of::<&PacketRestorationActivationAllocationRow>()
            + std::mem::size_of::<OriginalInstalledRestorationObservationHistoricalData<'static>>()
            + std::mem::size_of::<&OriginalInstalledRestorationObservationConstructionData>()
            + 10 * std::mem::size_of::<&usize>()
    }
}

impl serde::Serialize for OriginalInstalledRestorationObservationHistoricalData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let OriginalInstalledRestorationObservationConstructionData {
            controller: _,
            native,
            host_retained,
            host_transient,
            host_scratch,
            source_evidence_retained,
            source_evidence_transient,
            source_evidence_scratch,
            requested,
            scratch,
        } = self.original;
        let mut state = serializer
            .serialize_struct("OriginalInstalledRestorationObservationHistoricalData", 10)?;
        state.serialize_field(
            "schema",
            "source-private.restoration-observation-construction/1",
        )?;
        state.serialize_field("native", &(native))?;
        state.serialize_field("host_retained", &(host_retained))?;
        state.serialize_field("host_transient", &(host_transient))?;
        state.serialize_field("host_scratch", &(host_scratch))?;
        state.serialize_field("source_evidence_retained", &(source_evidence_retained))?;
        state.serialize_field("source_evidence_transient", &(source_evidence_transient))?;
        state.serialize_field("source_evidence_scratch", &(source_evidence_scratch))?;
        state.serialize_field("requested", &(requested))?;
        state.serialize_field("scratch", &(scratch))?;
        state.end()
    }
}

#[cfg(test)]
mod historical_tests {
    use super::*;

    #[test]
    fn historical_observation_preserves_every_axis_but_never_the_controller() {
        let row = OriginalInstalledRestorationObservationConstructionData {
            controller: std::ptr::null(),
            native: PacketRestorationActivationAllocationRow {
                retained_requested_bytes: U64::new(10),
                maximum_simultaneous_transient_bytes: U64::new(20),
                declared_counter_scratch_bytes: U64::new(30),
            },
            host_retained: 40,
            host_transient: 50,
            host_scratch: 60,
            source_evidence_retained: 70,
            source_evidence_transient: 80,
            source_evidence_scratch: 90,
            requested: 100,
            scratch: 110,
        };
        let actual = serde_json::to_value(row.historical_data()).unwrap();
        assert_eq!(actual.as_object().unwrap().len(), 10);
        assert!(actual.get("controller").is_none());
        assert_eq!(actual["native"]["retained_requested_bytes"], "10");
        for (key, expected) in [
            ("host_retained", 40),
            ("host_transient", 50),
            ("host_scratch", 60),
            ("source_evidence_retained", 70),
            ("source_evidence_transient", 80),
            ("source_evidence_scratch", 90),
            ("requested", 100),
            ("scratch", 110),
        ] {
            assert_eq!(actual[key], expected);
        }
        let changed = OriginalInstalledRestorationObservationConstructionData {
            source_evidence_scratch: 91,
            ..row
        };
        assert_ne!(
            actual,
            serde_json::to_value(changed.historical_data()).unwrap()
        );
        assert!(row.authenticate_controller_data(std::ptr::null()).is_err());
    }
}
