//! Counts every initialized Producer owner, including rejected proof partials.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::{
    sum_with_error, value_storage_with_error,
};
use crucible_node_transport::reference_packet::service::complete_restore::activation::restoration_activation_retained_native_evidence_data;

impl ProducerProgressAttempt {
    pub(super) fn new_data(
        row: OriginalRestoredProducerExecutionConstructionData,
        slot: usize,
        previous: [u8; 32],
    ) -> Self {
        Self {
            row,
            slot,
            admission: None,
            authorization: None,
            arguments: None,
            begin_body: None,
            poll_body: None,
            retire_body: None,
            observe_body: None,
            begin: None,
            poll: None,
            retire: None,
            observe: None,
            uploads: Vec::new(),
            upload_bodies: Vec::new(),
            request_ids: Vec::new(),
            record_values: std::array::from_fn(|_| None),
            record_canonical: std::array::from_fn(|_| Vec::new()),
            completed_record: None,
            completed_producer: None,
            completed_measurement: None,
            outcome: None,
            report_value: None,
            report_bytes: Vec::new(),
            report_reference: None,
            durable_root: RefCell::new(None),
            consumption: None,
            consumption_value: None,
            checkpoint_record: None,
            checkpoint_producer: None,
            checkpoint_measurement: None,
            scheduling: None,
            previous,
            signature: None,
            stage: Cell::new(Stage::Started),
        }
    }

    pub(super) fn authenticate_admission_data(
        &self,
        original: &OperationAdmission,
    ) -> Result<(), RuntimeError> {
        let retained = self
            .admission
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !retained.token().same_authority(original.token())
            || retained.request() != original.request()
            || !retained.activation().same_authority(original.activation())
            || retained.inputs().is_some()
            || original.inputs().is_some()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(super) fn producer_data(&self) -> Result<&PacketNativeRecord, RuntimeError> {
        match self.completed_producer.as_ref() {
            Some(PacketNative5UnderlyingRecord::Producer(record)) => Ok(record),
            _ => Err(RuntimeError::InvalidReceipt),
        }
    }

    pub(super) fn checkpoint_producer_data(&self) -> Result<&PacketNativeRecord, RuntimeError> {
        match self.checkpoint_producer.as_ref() {
            Some(PacketNative5UnderlyingRecord::Producer(record)) => Ok(record),
            _ => Err(RuntimeError::InvalidReceipt),
        }
    }

    fn heap_data<E: StorageError>(&self, maximum: usize) -> Result<usize, E> {
        let Self {
            row: _,
            slot: _,
            admission,
            authorization,
            arguments,
            begin_body,
            poll_body,
            retire_body,
            observe_body,
            begin,
            poll,
            retire,
            observe,
            uploads,
            upload_bodies,
            request_ids,
            record_values,
            record_canonical,
            completed_record,
            completed_producer,
            completed_measurement,
            outcome,
            report_value,
            report_bytes,
            report_reference,
            durable_root,
            consumption,
            consumption_value,
            checkpoint_record,
            checkpoint_producer,
            checkpoint_measurement,
            scheduling,
            previous: _,
            signature: _,
            stage: _,
        } = self;
        let mut bytes = sum_with_error::<E, _>(
            [
                uploads
                    .capacity()
                    .checked_mul(size_of::<Option<OriginalRestoredSuffixHostAttempt>>())
                    .ok_or_else(|| E::limit("Producer SDK bank"))?,
                upload_bodies
                    .capacity()
                    .checked_mul(size_of::<UploadBody>())
                    .ok_or_else(|| E::limit("Producer typed upload bank"))?,
                request_ids
                    .capacity()
                    .checked_mul(size_of::<Id>())
                    .ok_or_else(|| E::limit("Producer request IDs"))?,
                report_bytes.capacity(),
            ],
            maximum,
        )?;
        if let Some(original) = admission {
            bytes = sum_with_error::<E, _>(
                [
                    bytes,
                    admission_storage_data(original, maximum)
                        .map_err(|_| E::limit("Producer admission"))?,
                ],
                maximum,
            )?;
        }
        for id in request_ids {
            bytes = sum_with_error::<E, _>([bytes, id.allocated_capacity()], maximum)?;
        }
        for payload in [authorization, consumption].into_iter().flatten() {
            bytes = sum_with_error::<E, _>(
                [
                    bytes,
                    payload.bytes.capacity(),
                    NodeRuntime::capture_reference_storage(&payload.reference)
                        .map_err(|_| E::limit("Producer payload ref"))?,
                ],
                maximum,
            )?;
        }
        for typed in arguments
            .as_ref()
            .map(PacketRestoredProducerTypedOwnerData::Arguments)
            .into_iter()
            .chain(
                begin_body
                    .as_ref()
                    .map(PacketRestoredProducerTypedOwnerData::Begin),
            )
            .chain(
                poll_body
                    .as_ref()
                    .map(PacketRestoredProducerTypedOwnerData::Poll),
            )
            .chain(
                retire_body
                    .as_ref()
                    .map(PacketRestoredProducerTypedOwnerData::Retire),
            )
            .chain(
                observe_body
                    .as_ref()
                    .map(PacketRestoredProducerTypedOwnerData::Observe),
            )
        {
            bytes = sum_with_error::<E, _>(
                [
                    bytes,
                    metadata_data::<E>(
                        &typed.retained_metadata_data().map_err(E::unknown)?,
                        maximum,
                    )?,
                ],
                maximum,
            )?;
        }
        for body in upload_bodies {
            let next = upload_body_heap_data::<E>(body, maximum)?;
            bytes = sum_with_error::<E, _>([bytes, next], maximum)?;
        }
        for sdk in [begin, poll, retire, observe]
            .into_iter()
            .chain(uploads.iter())
            .flatten()
        {
            bytes = sum_with_error::<E, _>(
                [
                    bytes,
                    metadata_data::<E>(
                        &sdk.retained_metadata_data().map_err(E::unknown)?,
                        maximum,
                    )?,
                ],
                maximum,
            )?;
        }
        for value in record_values
            .iter()
            .chain(std::iter::once(report_value))
            .chain(std::iter::once(consumption_value))
            .flatten()
        {
            bytes = sum_with_error::<E, _>(
                [bytes, value_storage_with_error::<E>(value, 0, maximum)?],
                maximum,
            )?;
        }
        for bank in record_canonical {
            bytes = sum_with_error::<E, _>([bytes, bank.capacity()], maximum)?;
        }
        for (record, underlying) in [
            (completed_record, completed_producer),
            (checkpoint_record, checkpoint_producer),
        ] {
            if let Some(record) = record {
                bytes = sum_with_error::<E, _>(
                    [
                        bytes,
                        metadata_data::<E>(
                            &restoration_activation_retained_native_evidence_data(
                                record,
                                underlying.as_ref(),
                            )
                            .map_err(E::unknown)?,
                            maximum,
                        )?,
                    ],
                    maximum,
                )?;
            } else if underlying.is_some() {
                return Err(E::unknown("Producer model missing owning record"));
            }
        }
        let root = durable_root
            .try_borrow()
            .map_err(|_| E::unknown("Producer durable root borrowed"))?;
        for reference in [
            completed_measurement,
            report_reference,
            checkpoint_measurement,
            &*root,
        ]
        .into_iter()
        .flatten()
        {
            bytes = sum_with_error::<E, _>(
                [
                    bytes,
                    NodeRuntime::capture_reference_storage(reference)
                        .map_err(|_| E::limit("Producer full reference"))?,
                ],
                maximum,
            )?;
        }
        if let Some(actual) = outcome {
            bytes = sum_with_error::<E, _>(
                [
                    bytes,
                    outcome_storage_data(actual, maximum)
                        .map_err(|_| E::limit("Producer outcome"))?,
                ],
                maximum,
            )?;
        }
        if let Some(actual) = scheduling {
            bytes = sum_with_error::<E, _>(
                [
                    bytes,
                    NodeRuntime::capture_scheduling_observation_storage_data(actual, maximum)
                        .map_err(|_| E::limit("Producer scheduling"))?,
                ],
                maximum,
            )?;
        }
        Ok(bytes)
    }
}

fn metadata_data<E: StorageError>(
    facts: &crucible_node_transport::retained_metadata::RetainedProtocolMetadataFacts,
    maximum: usize,
) -> Result<usize, E> {
    PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<E>(facts, maximum)
}

fn value_map_data<E: StorageError>(map: &Extensions, maximum: usize) -> Result<usize, E> {
    let tree = NodeRuntime::capture_protocol_tree_storage(
        1,
        map.len(),
        size_of::<(String, serde_json::Value)>(),
        std::mem::align_of::<(String, serde_json::Value)>(),
        maximum,
    )
    .map_err(|_| E::limit("Producer extension map"))?;
    let mut bytes = tree;
    for (key, value) in map {
        bytes = sum_with_error::<E, _>(
            [
                bytes,
                key.capacity(),
                value_storage_with_error::<E>(value, 0, maximum)?,
            ],
            maximum,
        )?;
    }
    Ok(bytes)
}

pub(super) fn admission_storage_data(
    original: &OperationAdmission,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    if original.inputs().is_some() {
        return Err(RuntimeError::UnsupportedFacet);
    }
    let world = original
        .activation()
        .retained_requested_storage_data(maximum)?;
    let mut bytes = sum_with_error::<RuntimeError, _>(
        [
            original.token().operation().allocated_capacity(),
            NodeRuntime::capture_route_storage_data(original.token().route(), maximum)?,
            world.independent_bytes(),
        ],
        maximum,
    )?;
    for shared in world.shared_allocations() {
        bytes = sum_with_error::<RuntimeError, _>([bytes, shared.requested_bytes()], maximum)?;
    }
    Ok(bytes)
}

fn outcome_storage_data(outcome: &OperationOutcome, maximum: usize) -> Result<usize, RuntimeError> {
    // The defining Runtime walker prices full actual Outcome children without serialization.
    NodeRuntime::original_outcome_requested_storage_data(outcome, maximum)
}

impl ProducerProgressHistory {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn retained_heap_bytes_with_error<
        E: StorageError,
    >(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        let mut bytes = self
            .attempts
            .capacity()
            .checked_mul(size_of::<ProducerProgressAttempt>())
            .filter(|bytes| *bytes <= maximum)
            .ok_or_else(|| E::limit("Producer attempt bank"))?;
        for attempt in &self.attempts {
            bytes = sum_with_error::<E, _>([bytes, attempt.heap_data::<E>(maximum)?], maximum)?;
        }
        Ok(bytes)
    }
}

fn upload_body_heap_data<E: StorageError>(body: &UploadBody, maximum: usize) -> Result<usize, E> {
    Ok(match body {
        UploadBody::Begin(body) => sum_with_error::<E, _>(
            [
                body.transfer_id.allocated_capacity(),
                NodeRuntime::capture_reference_storage(&body.content)
                    .map_err(|_| E::limit("Producer blob ref"))?,
                value_map_data::<E>(&body.extensions, maximum)?,
            ],
            maximum,
        )?,
        UploadBody::Chunk(body) => sum_with_error::<E, _>(
            [
                body.transfer_id.allocated_capacity(),
                body.bytes.allocation_capacity(),
                value_map_data::<E>(&body.extensions, maximum)?,
            ],
            maximum,
        )?,
        UploadBody::Finish(body) => sum_with_error::<E, _>(
            [
                body.transfer_id.allocated_capacity(),
                value_map_data::<E>(&body.extensions, maximum)?,
            ],
            maximum,
        )?,
    })
}

pub(super) fn counter_scratch_data() -> usize {
    use std::iter::{Chain, Flatten, Once};
    use std::{option, slice};
    type Typed = PacketRestoredProducerTypedOwnerData<'static>;
    type First = Chain<option::IntoIter<Typed>, option::IntoIter<Typed>>;
    type Second = Chain<First, option::IntoIter<Typed>>;
    type Third = Chain<Second, option::IntoIter<Typed>>;
    type Fourth = Chain<Third, option::IntoIter<Typed>>;
    type Sdk = OriginalRestoredSuffixHostAttempt;
    type SdkChain =
        Chain<std::array::IntoIter<&'static Option<Sdk>, 4>, slice::Iter<'static, Option<Sdk>>>;
    type Values = Chain<
        Chain<
            slice::Iter<'static, Option<serde_json::Value>>,
            Once<&'static Option<serde_json::Value>>,
        >,
        Once<&'static Option<serde_json::Value>>,
    >;
    size_of::<First>()
        + size_of::<Second>()
        + size_of::<Third>()
        + size_of::<Fourth>()
        + size_of::<option::IntoIter<Typed>>()
        + size_of::<SdkChain>()
        + size_of::<Flatten<SdkChain>>()
        + size_of::<Values>()
        + size_of::<Flatten<Values>>()
        + size_of::<
            Chain<
                slice::Iter<'static, Option<serde_json::Value>>,
                Once<&'static Option<serde_json::Value>>,
            >,
        >()
        + size_of::<Once<&'static Option<serde_json::Value>>>()
        + size_of::<
            [(
                &Option<PacketNativeRestoredRecord>,
                &Option<PacketNative5UnderlyingRecord>,
            ); 2],
        >()
        + size_of::<
            std::array::IntoIter<
                (
                    &Option<PacketNativeRestoredRecord>,
                    &Option<PacketNative5UnderlyingRecord>,
                ),
                2,
            >,
        >()
        + size_of::<[&Option<ContentRef>; 4]>()
        + size_of::<std::array::IntoIter<&Option<ContentRef>, 4>>()
        + size_of::<Flatten<std::array::IntoIter<&Option<ContentRef>, 4>>>()
        + size_of::<[&Option<crate::node_scheduling::InputPayload>; 2]>()
        + size_of::<std::array::IntoIter<&Option<crate::node_scheduling::InputPayload>, 2>>()
        + size_of::<Flatten<std::array::IntoIter<&Option<crate::node_scheduling::InputPayload>, 2>>>(
        )
        + size_of::<std::slice::Iter<'static, UploadBody>>()
        + size_of::<std::slice::Iter<'static, Id>>()
        + size_of::<crucible_node_transport::retained_metadata::RetainedProtocolMetadataFacts>()
        + size_of::<
            Result<
                crucible_node_transport::retained_metadata::RetainedProtocolMetadataFacts,
                crucible_node_transport::ProviderError,
            >,
        >()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<&OperationAdmission>()
        + size_of::<crate::node_contract::RetainedCoreOwnerStorage<'static>>()
        + size_of::<Result<crate::node_contract::RetainedCoreOwnerStorage<'static>, RuntimeError>>()
        + size_of::<std::collections::btree_map::Iter<'static, String, serde_json::Value>>()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "pure retained-owner DATA controls assert checked refusal boundaries"
)]
mod tests {
    use super::*;

    #[test]
    fn producer_history_spare_capacity_is_retained_at_exact_and_one_short() {
        let mut history = ProducerProgressHistory::new();
        history.attempts = Vec::with_capacity(7);
        let expected = history.attempts.capacity() * size_of::<ProducerProgressAttempt>();
        assert!(history.is_used_data());
        assert_eq!(
            history
                .retained_heap_bytes_with_error::<RuntimeError>(expected)
                .unwrap(),
            expected
        );
        assert!(
            history
                .retained_heap_bytes_with_error::<RuntimeError>(expected - 1)
                .is_err()
        );
        assert!(history.attempts.is_empty());
    }

    #[test]
    fn producer_blob_partial_counts_actual_payload_spare_capacity() {
        let mut bytes = Vec::with_capacity(173);
        bytes.extend_from_slice(b"retained partial");
        let body = UploadBody::Chunk(BlobChunkRequest {
            transfer_id: Id::new("real-owned-partial").unwrap(),
            offset: U64::new(0),
            bytes: Bytes::new(bytes),
            extensions: Extensions::new(),
        });
        let extent = upload_body_heap_data::<RuntimeError>(&body, usize::MAX).unwrap();
        assert!(extent >= 173 + "real-owned-partial".len());
        assert_eq!(
            upload_body_heap_data::<RuntimeError>(&body, extent).unwrap(),
            extent
        );
        assert!(upload_body_heap_data::<RuntimeError>(&body, extent - 1).is_err());
        let UploadBody::Chunk(retained) = body else {
            unreachable!()
        };
        assert_eq!(retained.bytes.as_slice(), b"retained partial");
    }

    #[test]
    fn producer_use_or_busy_owner_excludes_reserved_prebirth() {
        let mut slot = None;
        OriginalAckPeerAssociation::reserve_into(256, &mut slot).unwrap();
        let original = slot.as_ref().unwrap();
        original.authenticate_reserved_prebirth_data().unwrap();
        {
            let _busy = original.producer_progress.borrow_mut();
            assert!(original.authenticate_reserved_prebirth_data().is_err());
        }
        original.producer_progress.borrow_mut().failed = true;
        assert!(original.authenticate_reserved_prebirth_data().is_err());
    }
}
