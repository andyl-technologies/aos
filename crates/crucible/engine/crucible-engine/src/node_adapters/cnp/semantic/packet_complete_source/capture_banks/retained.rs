//! Observes actual capture-bank and original protocol-owner allocations.
//!
//! Byte banks are counted independently of the SDK association metadata. The
//! latter includes partially retained issuer/codec/Hello owners on refusal, not
//! merely the completed snapshot case. Repeated shared views receive no credit.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError;

impl PacketCompleteCaptureBanks {
    #[cfg(test)]
    fn retained_requested_storage_data(&self, maximum: usize) -> Result<usize, OperationFailure> {
        self.retained_requested_storage_data_with_error::<OperationFailure>(maximum)
    }

    pub(in crate::node_adapters::cnp::semantic) fn retained_requested_storage_data_with_error<
        E: StorageError,
    >(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        let mut bytes = super::super::retained_values::sum_with_error::<E, _>(
            [self.facts_with_error::<E>()?.total_bytes],
            maximum,
        )?;
        for reservation in self
            .semantic
            .iter()
            .chain(self.ancestry.iter())
            .chain(self.journal.iter())
            .chain(self.native_banks.iter().flatten())
            .chain(self.native_after_bank.iter())
        {
            bytes = super::super::retained_values::sum_with_error::<E, _>(
                [bytes, E::reservation_metadata(reservation)?],
                maximum,
            )?;
        }

        // These byte vectors already appear in facts(). Their independently
        // cloned ContentRefs retain dynamic backing outside those vectors.
        for object in self
            .ancestry_record
            .iter()
            .chain(self.journal_record.iter())
            .chain(self.native_objects.iter().flatten())
            .chain(self.native_after_object.iter())
        {
            bytes = super::super::retained_values::sum_with_error::<E, _>(
                [
                    bytes,
                    NodeRuntime::capture_reference_storage(&object.reference)
                        .map_err(E::unknown)?,
                ],
                maximum,
            )?;
        }

        if let Some(snapshot) = &self.semantic_snapshot {
            bytes = super::super::retained_values::sum_with_error::<E, _>(
                [bytes, E::snapshot_metadata(snapshot, maximum)?],
                maximum,
            )?;
        }
        use crucible_node_transport::retained_metadata::RetainedCaptureProtocolData;
        for response in self.capture_response.iter().chain(
            self.confirmation_response
                .iter()
                .map(|(response, _)| response),
        ) {
            let metadata = RetainedCaptureProtocolData::Response(response)
                .observe_retained_metadata()
                .map_err(E::unknown)?;
            bytes = super::super::retained_values::sum_with_error::<E, _>(
                [
                    bytes,
                    PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<E>(
                        &metadata, maximum,
                    )?,
                ],
                maximum,
            )?;
        }
        if let Some((_, receipt)) = &self.confirmation_response {
            let metadata = RetainedCaptureProtocolData::AfterConfirmation(receipt)
                .observe_retained_metadata()
                .map_err(E::unknown)?;
            bytes = super::super::retained_values::sum_with_error::<E, _>(
                [
                    bytes,
                    PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<E>(
                        &metadata, maximum,
                    )?,
                ],
                maximum,
            )?;
        }

        if self.protocol_detached {
            if self.protocol.is_some()
                || self.settled_protocol.is_some()
                || self.protocol_payload.is_some()
            {
                return Err(E::refused(
                    "detached original host owner remains duplicated",
                ));
            }
            return Ok(bytes);
        }
        let metadata = match (
            &self.protocol,
            &self.settled_protocol,
            &self.protocol_payload,
        ) {
            (Some(reservation), None, None) => reservation
                .original_retained_metadata_facts()
                .map_err(E::unknown)?,
            (None, Some(snapshot), None) => snapshot
                .original_retained_metadata_facts()
                .map_err(E::unknown)?,
            (None, None, Some((owner, _))) => owner
                .original_retained_metadata_facts()
                .map_err(E::unknown)?,
            _ => {
                return Err(E::refused(
                    "retained capture protocol owner association differs",
                ));
            }
        };
        super::super::retained_values::sum_with_error::<E, _>(
            [
                bytes,
                PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<E>(
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
        self.original_complete_capture_bank_storage_data_with_error::<OperationFailure>(maximum)
    }

    pub(in crate::node_adapters::cnp::semantic) fn original_complete_capture_bank_storage_data_with_error<
        E: StorageError,
    >(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        self.storage_origin_with_error::<E>()?;
        let banks = self
            .capture_banks
            .try_borrow()
            .map_err(|_| E::refused("retained capture banks already borrowed"))?;
        banks
            .as_ref()
            .ok_or_else(|| E::refused("retained capture banks absent"))?
            .retained_requested_storage_data_with_error::<E>(maximum)
    }
}

// crucible-lint: allow panic-shortcut -- Bank ownership controls panic only on broken test invariants.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "checks actual retained bank ownership and exact admission boundaries"
)]
mod tests {
    use super::*;

    fn original_banks() -> PacketCompleteCaptureBanks {
        fn bank() -> CnpSemanticSnapshotReservation {
            CnpSemanticSnapshotReservation::reserve(1024, 65536).unwrap()
        }
        PacketCompleteCaptureBanks {
            protocol_detached: false,
            transferred: false,
            semantic: Some(bank()),
            semantic_snapshot: None,
            ancestry: Some(bank()),
            ancestry_record: None,
            journal: Some(bank()),
            journal_record: None,
            capture_response: None,
            confirmation_response: None,
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
        let reference = crucible_node_format::canonical::content_ref(
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
    fn moved_journal_retains_same_bank_and_reference_until_final_validation() {
        let mut banks = original_banks();
        let before = banks.retained_requested_storage_data(usize::MAX).unwrap();
        let original_capacity = banks.journal.as_ref().unwrap().allocated_bytes();
        crate::node_adapters::cnp::semantic::semantic_snapshot::record_component(
            &mut banks.journal,
            &"actual original journal",
        )
        .unwrap();
        let record = crate::node_adapters::cnp::semantic::semantic_snapshot::take_component(
            &mut banks.journal,
            "application/vnd.source-owned.packet-native-settled-journal.v12+json",
        )
        .unwrap();
        banks.journal_record = Some(record);

        let record = banks.journal_record.as_ref().unwrap();
        assert!(banks.journal.is_none());
        assert_eq!(record.bytes.capacity(), original_capacity);
        let expected = before + NodeRuntime::capture_reference_storage(&record.reference).unwrap();
        assert_eq!(
            banks.retained_requested_storage_data(expected).unwrap(),
            expected
        );
        assert!(banks.retained_requested_storage_data(expected - 1).is_err());
        assert_eq!(
            banks.journal_record.as_ref().unwrap().bytes.capacity(),
            original_capacity
        );
    }

    #[test]
    fn retained_capture_error_counts_actual_spare_backing_on_refusal() {
        let mut banks = original_banks();
        let before = banks.retained_requested_storage_data(usize::MAX).unwrap();
        let mut message = String::with_capacity(113);
        message.push_str("actual original uncertain response");
        let capacity = message.capacity();
        banks.capture_response = Some(ResponseBody {
            shape: ResponseShape::Error {
                operation_state: crucible_node_transport::bodies::OperationState::Unknown,
                error: crucible_node_transport::bodies::ErrorRecord {
                    code: "OUTCOME_UNKNOWN".into(),
                    message,
                    effect: crucible_node_transport::bodies::EffectCertainty::Unknown,
                    retryable: false,
                    details: Default::default(),
                },
                extensions: Default::default(),
            },
            result: None,
        });

        let after = banks.retained_requested_storage_data(usize::MAX).unwrap();
        assert!(after >= before + capacity);
        assert_eq!(banks.retained_requested_storage_data(after).unwrap(), after);
        assert!(banks.retained_requested_storage_data(after - 1).is_err());
        assert!(banks.capture_response.is_some());
    }

    #[test]
    fn conflicting_moved_return_slots_refuse_without_dropping_either_owner() {
        let mut banks = original_banks();
        banks.native_objects[0] = Some(InputPayload {
            reference: crucible_node_format::canonical::content_ref(b"x", "text/plain").unwrap(),
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
