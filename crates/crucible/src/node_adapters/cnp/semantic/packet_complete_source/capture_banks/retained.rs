//! Observes actual capture-bank and original protocol-owner allocations.
//!
//! Byte banks are counted independently of the SDK association metadata. The
//! latter includes partially retained issuer/codec/Hello owners on refusal, not
//! merely the completed snapshot case. Repeated shared views receive no credit.

use super::super::retained_values::sum;
use super::*;

impl PacketCompleteCaptureBanks {
    fn retained_requested_storage_data(&self, maximum: usize) -> Result<usize, OperationFailure> {
        let mut bytes = sum([self.facts()?.total_bytes], maximum)?;
        for reservation in std::iter::once(&self.semantic)
            .chain(self.ancestry.iter())
            .chain(std::iter::once(&self.journal))
            .chain(self.native_banks.iter().flatten())
            .chain(self.native_after_bank.iter())
        {
            bytes = sum(
                [
                    bytes,
                    reservation.retained_metadata_requested_storage_data()?,
                ],
                maximum,
            )?;
        }

        // These byte vectors already appear in facts(). Their independently
        // cloned ContentRefs retain dynamic backing outside those vectors.
        for object in self
            .ancestry_record
            .iter()
            .chain(self.native_objects.iter().flatten())
            .chain(self.native_after_object.iter())
        {
            bytes = sum(
                [
                    bytes,
                    NodeRuntime::capture_reference_storage(&object.reference).map_err(unknown)?,
                ],
                maximum,
            )?;
        }

        let metadata = match (
            &self.protocol,
            &self.settled_protocol,
            &self.protocol_payload,
        ) {
            (Some(reservation), None, None) => reservation
                .original_retained_metadata_facts()
                .map_err(unknown)?,
            (None, Some(snapshot), None) => snapshot
                .original_retained_metadata_facts()
                .map_err(unknown)?,
            (None, None, Some((owner, _))) => {
                owner.original_retained_metadata_facts().map_err(unknown)?
            }
            _ => {
                return Err(refused(
                    "retained capture protocol owner association differs",
                ));
            }
        };
        sum(
            [
                bytes,
                PacketCompleteSemanticSource::complete_retained_metadata_storage_data(
                    &metadata, maximum,
                )?,
            ],
            maximum,
        )
    }
}

impl PacketCompleteSemanticSource {
    /// Reports actual retained capture-bank storage and SDK association metadata.
    ///
    /// The containing slots are already part of the source's actual root Rc
    /// allocation. Every present byte, literal, record and alias bank is counted
    /// at its actual capacity, including a partially populated protocol issuer.
    /// Returned object references and issuer/codec/Hello backing are additional
    /// terms. Shared metadata views are conservatively repeated across owners.
    ///
    /// This data observer requires the original creator, without requiring a
    /// retired Child to remain live. It does not assert complete capture-bank
    /// selection, local journal completion or a whole allocation admission.
    /// Native/controller/executable owners and a semantic snapshot moved out of
    /// these banks belong to their actual separate owners.
    ///
    /// # Errors
    /// Refuses foreign origin, absent or borrowed banks, inconsistent moved
    /// owner slots, unsupported SDK metadata or aggregate requested storage
    /// exceeding the supplied observation bound.
    pub fn original_complete_capture_bank_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        self.ensure_origin()?;
        let banks = self
            .capture_banks
            .try_borrow()
            .map_err(|_| refused("retained capture banks already borrowed"))?;
        banks
            .as_ref()
            .ok_or_else(|| refused("retained capture banks absent"))?
            .retained_requested_storage_data(maximum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn original_banks() -> PacketCompleteCaptureBanks {
        fn bank() -> CnpSemanticSnapshotReservation {
            CnpSemanticSnapshotReservation::reserve(1024, 65536).unwrap()
        }
        PacketCompleteCaptureBanks {
            semantic: bank(),
            ancestry: Some(bank()),
            ancestry_record: None,
            journal: bank(),
            protocol: Some(ProtocolSnapshotReservation::reserve_complete(4096, 4096, 4).unwrap()),
            settled_protocol: None,
            protocol_payload: None,
            native_banks: [Some(bank()), Some(bank()), Some(bank())],
            native_objects: [None, None, None],
            native_after_bank: None,
            native_after_object: None,
        }
    }

    #[test]
    fn moving_return_bytes_also_retains_independent_reference_storage() {
        let mut banks = original_banks();
        let before = banks.retained_requested_storage_data(usize::MAX).unwrap();
        let reference = crucible_node_contract::canonical::content_ref(
            b"x",
            "application/vnd.source-owned.return-bank-test+json",
        )
        .unwrap();
        banks.native_objects[0] = Some(
            crate::node_adapters::cnp::semantic::semantic_snapshot::record_original_bytes(
                &mut banks.native_banks[0],
                &reference,
                b"x",
            )
            .unwrap(),
        );

        let actual = banks.retained_requested_storage_data(usize::MAX).unwrap();
        let object = banks.native_objects[0].as_ref().unwrap();
        let reference_bytes = NodeRuntime::capture_reference_storage(&object.reference).unwrap();
        assert!(reference_bytes > 0);
        assert_eq!(actual, before + reference_bytes);
        assert_eq!(
            banks.retained_requested_storage_data(actual).unwrap(),
            actual
        );
        assert!(banks.retained_requested_storage_data(actual - 1).is_err());
    }

    #[test]
    fn conflicting_moved_return_slots_refuse_without_dropping_either_owner() {
        let mut banks = original_banks();
        banks.native_objects[0] = Some(InputPayload {
            reference: crucible_node_contract::canonical::content_ref(b"x", "text/plain").unwrap(),
            bytes: Vec::with_capacity(2048),
        });

        let original_capacity = banks.native_objects[0].as_ref().unwrap().bytes.capacity();
        assert!(banks.retained_requested_storage_data(usize::MAX).is_err());
        assert!(banks.native_banks[0].is_some());
        assert_eq!(
            banks.native_objects[0].as_ref().unwrap().bytes.capacity(),
            original_capacity
        );
    }
}
