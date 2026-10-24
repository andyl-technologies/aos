//! Retains the real post-confirmation Controller and final Journal17 objects.
//!
//! Both encoders run after the four native bodies have passed their defining
//! validator, under the same armed Source read. Their independently admitted
//! banks survive encoding, identity and final-census refusals. Neither a journal
//! nor its cached JSON can issue Capture or fresh installation authority.

use super::{construction_quote::sum, encoding_extent};
use crate::{
    node_adapters::cnp::semantic::packet_complete_source::retained_values::value_storage_with_error,
    node_contract::{NodeRuntime, RuntimeError},
};
use crucible_node_format::{ContentRef, canonical};
use crucible_node_transport::{
    client::{
        OriginalCompletedRestoredSettledCaptureData, OriginalRestoredSettledCaptureConstructionData,
    },
    protocol_snapshot::restored_journal17::{
        PacketRestoredSettledAncestry17, PacketRestoredSettledHistoryCut17,
        PacketRestoredSettledJournal17Objects, PacketRestoredSettledJournal17View,
        RESTORED_SETTLED_JOURNAL17_SCHEMA,
    },
    retained_metadata::serialization_storage::original_json_value_storage_extent_data,
};
use serde::Serialize;
use serde_json::Value;
use std::{
    io::{self, Write},
    mem::size_of,
};

const JSON_MEDIA: &str = "application/json";
const DIGEST_SHAPE: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const DECIMAL_SHAPE: &str = "18446744073709551615";

/// Records finite output geometry without constructing future proof objects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FinalizationStorage {
    pub(super) controller_encoded: usize,
    pub(super) journal_encoded: usize,
    pub(super) proof_encoded: usize,
    pub(super) retained: usize,
    pub(super) transient: usize,
    pub(super) scratch: usize,
}

// These private serializers describe only closed encoded extents. They never
// escape the counting pass or become ContentRef, Envelope or journal DATA.
#[derive(Serialize)]
struct HashShape {
    algorithm: &'static str,
    domain: &'static str,
    digest: &'static str,
}

#[derive(Serialize)]
struct ReferenceShape<'a> {
    hash: HashShape,
    length: &'static str,
    media_type: &'a str,
}

fn reference_shape(media_type: &str) -> ReferenceShape<'_> {
    ReferenceShape {
        hash: HashShape {
            algorithm: "blake3-256",
            domain: "cnp.blob.v1",
            digest: DIGEST_SHAPE,
        },
        length: DECIMAL_SHAPE,
        media_type,
    }
}

#[derive(Serialize)]
struct ObjectsShape<'a> {
    snapshot: ReferenceShape<'a>,
    before: ReferenceShape<'a>,
    control: ReferenceShape<'a>,
    anchor: ReferenceShape<'a>,
    after: ReferenceShape<'a>,
    host_protocol: ReferenceShape<'a>,
    semantic: ReferenceShape<'a>,
    runtime_object: ReferenceShape<'a>,
    coordinator_checkpoint: ReferenceShape<'a>,
}

#[derive(Serialize)]
struct CutShape<'a> {
    prefix: ReferenceShape<'a>,
    next_sequence: &'static str,
}

#[derive(Serialize)]
struct JournalShape<'a, Ancestry: ?Sized> {
    ancestry: &'a Ancestry,
    capture_request: (),
    capture_terminal: (),
    confirmation_request: (),
    confirmation_terminal: (),
    history_cut: CutShape<'a>,
    objects: ObjectsShape<'a>,
    schema: &'static str,
}

impl FinalizationStorage {
    pub(super) fn quote_data<Ancestry: Serialize + ?Sized>(
        controller_baseline: usize,
        sdk: &OriginalRestoredSettledCaptureConstructionData,
        ancestry: &Ancestry,
        frame: usize,
        proof_encoded: usize,
        maximum: usize,
    ) -> Result<Self, RuntimeError> {
        use crucible_node_transport::{
            protocol_snapshot::restored_journal17::RESTORED_SETTLED_SEMANTIC17_MEDIA,
            reference_packet::service::complete_restore::settled_recapture::COORDINATOR_CHECKPOINT17_MEDIA,
        };
        if frame == 0 || proof_encoded == 0 {
            return Err(RuntimeError::ResourceLimit);
        }
        let controller_encoded = sum(
            &[
                controller_baseline,
                sdk.maximum_controller_history_encoded_growth_bytes_data(),
            ],
            maximum,
        )?;
        let shape = JournalShape {
            ancestry,
            capture_request: (),
            capture_terminal: (),
            confirmation_request: (),
            confirmation_terminal: (),
            history_cut: CutShape {
                prefix: reference_shape(JSON_MEDIA),
                next_sequence: DECIMAL_SHAPE,
            },
            objects: ObjectsShape {
                snapshot: reference_shape(JSON_MEDIA),
                before: reference_shape(JSON_MEDIA),
                control: reference_shape(JSON_MEDIA),
                anchor: reference_shape(JSON_MEDIA),
                after: reference_shape(JSON_MEDIA),
                host_protocol: reference_shape(JSON_MEDIA),
                semantic: reference_shape(RESTORED_SETTLED_SEMANTIC17_MEDIA),
                runtime_object: reference_shape(
                    "application/vnd.crucible.runtime-original-lineage+json;version=7",
                ),
                coordinator_checkpoint: reference_shape(COORDINATOR_CHECKPOINT17_MEDIA),
            },
            schema: RESTORED_SETTLED_JOURNAL17_SCHEMA,
        };
        // Replace exactly four JSON nulls with complete assigned Envelope
        // encodings. The actual SDK enforces this frame ceiling in both
        // directions; field order does not change canonical encoded length.
        let fixed = encoding_extent::canonical_encoded_extent_data(&shape, maximum)?
            .checked_sub(4 * b"null".len())
            .ok_or(RuntimeError::ResourceLimit)?;
        let journal_encoded = sum(
            &[
                fixed,
                frame.checked_mul(4).ok_or(RuntimeError::ResourceLimit)?,
            ],
            maximum,
        )?;
        let controller = original_json_value_storage_extent_data(controller_encoded)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let journal = original_json_value_storage_extent_data(journal_encoded)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        // The journal's owned typed references coexist with its DOM. Their
        // string backing is bounded by their encoded spelling, independently
        // of the separately charged fixed typed headers.
        let retained = sum(
            &[
                controller.value_dom_requested_bytes,
                controller_encoded,
                journal.value_dom_requested_bytes,
                journal_encoded,
                journal_encoded,
                proof_encoded,
                size_of::<FinalizationOwners>(),
                size_of::<PacketRestoredSettledJournal17Objects>(),
                size_of::<PacketRestoredSettledHistoryCut17>(),
                3 * ("blake3-256".len()
                    + "cnp.blob.v1".len()
                    + DIGEST_SHAPE.len()
                    + JSON_MEDIA.len()),
            ],
            maximum,
        )?;
        let transient = sum(
            &[
                // Custom Bytes serializers allocate a base64 String before the
                // Value serializer sees it. Each independently bounded encoded
                // output covers that string, separately from generic DOM/JCS work.
                controller_encoded,
                journal_encoded,
                controller
                    .canonical_pass_requested_bytes()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                journal
                    .canonical_pass_requested_bytes()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            ],
            maximum,
        )?;
        let scratch = sum(
            &[
                Self::counter_scratch_data(),
                controller.declared_counter_scratch_bytes,
                journal.declared_counter_scratch_bytes,
                encoding_extent::counter_scratch_data(),
            ],
            maximum,
        )?;
        sum(&[retained, transient, scratch], maximum)?;
        Ok(Self {
            controller_encoded,
            journal_encoded,
            proof_encoded,
            retained,
            transient,
            scratch,
        })
    }

    pub(super) fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<JournalShape<'static, PacketRestoredSettledAncestry17>>()
            + size_of::<ReferenceShape<'static>>()
            + size_of::<HashShape>()
            + size_of::<Result<Self, RuntimeError>>()
            + size_of::<Option<usize>>()
            + Component::counter_scratch_data()
    }
}

struct Component {
    started: bool,
    completed: bool,
    value: Option<Value>,
    bytes: Vec<u8>,
    reference: Option<ContentRef>,
}

impl Component {
    const fn empty() -> Self {
        Self {
            started: false,
            completed: false,
            value: None,
            bytes: Vec::new(),
            reference: None,
        }
    }

    fn encode_data<T: Serialize + ?Sized>(
        &mut self,
        value: &T,
        encoded: usize,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        if self.started {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.started = true;
        encoding_extent::canonical_encoded_extent_data(value, encoded)?;
        self.value = Some(serde_json::to_value(value).map_err(|_| RuntimeError::InvalidReceipt)?);
        self.retained_storage_data(maximum)?;

        self.bytes
            .try_reserve_exact(encoded)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if self.bytes.capacity() > encoded {
            return Err(RuntimeError::ResourceLimit);
        }
        self.retained_storage_data(maximum)?;
        let mut writer = BoundedWriter {
            bytes: &mut self.bytes,
            maximum: encoded,
        };
        canonical::canonical_json_to_writer(
            self.value.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
            &mut writer,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        self.reference = Some(
            canonical::content_ref(&self.bytes, JSON_MEDIA)
                .map_err(|_| RuntimeError::InvalidReceipt)?,
        );
        self.retained_storage_data(maximum)?;
        self.completed = true;
        Ok(())
    }

    fn payload_data(&self) -> Result<(&ContentRef, &[u8]), RuntimeError> {
        if !self.completed {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok((
            self.reference
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            &self.bytes,
        ))
    }

    fn retained_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let Self {
            started: _,
            completed: _,
            value,
            bytes,
            reference,
        } = self;
        let value = value.as_ref().map_or(Ok(0), |value| {
            value_storage_with_error::<RuntimeError>(value, 0, maximum)
        })?;
        let reference = reference
            .as_ref()
            .map_or(Ok(0), NodeRuntime::capture_reference_storage)?;
        sum(&[bytes.capacity(), value, reference], maximum)
    }

    fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<BoundedWriter<'static>>()
            + size_of::<PacketRestoredSettledJournal17View<'static>>()
            + size_of::<Result<(&'static ContentRef, &'static [u8]), RuntimeError>>()
            + size_of::<Result<Value, serde_json::Error>>()
            + size_of::<Result<(), crucible_node_format::ContractError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<usize, io::Error>>()
    }
}

struct BoundedWriter<'a> {
    bytes: &'a mut Vec<u8>,
    maximum: usize,
}

impl Write for BoundedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes
            .len()
            .checked_add(bytes.len())
            .filter(|length| *length <= self.maximum && *length <= self.bytes.capacity())
            .ok_or(io::ErrorKind::OutOfMemory)?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Owns completed-output banks independently of the native decoder's caches.
pub(super) struct FinalizationOwners {
    pub(super) started: bool,
    pub(super) completed: bool,
    controller: Component,
    journal: Component,
    pub(super) objects: Option<PacketRestoredSettledJournal17Objects>,
    pub(super) history_cut: Option<PacketRestoredSettledHistoryCut17>,
    proof: Vec<u8>,
    proof_reference: Option<ContentRef>,
}

impl FinalizationOwners {
    pub(super) const fn empty() -> Self {
        Self {
            started: false,
            completed: false,
            controller: Component::empty(),
            journal: Component::empty(),
            objects: None,
            history_cut: None,
            proof: Vec::new(),
            proof_reference: None,
        }
    }

    pub(super) fn encode_controller_data<T: Serialize + ?Sized>(
        &mut self,
        history: &T,
        proof_reference: &ContentRef,
        proof: &[u8],
        storage: &FinalizationStorage,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        if self.started || proof.len() != storage.proof_encoded {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.started = true;
        proof_reference
            .verify(proof)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        self.proof_reference = Some(proof_reference.clone());
        self.proof
            .try_reserve_exact(proof.len())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if self.proof.capacity() > storage.proof_encoded {
            return Err(RuntimeError::ResourceLimit);
        }
        self.proof.extend_from_slice(proof);
        self.retained_storage_data(storage.retained.min(maximum))?;
        self.controller
            .encode_data(history, storage.controller_encoded, maximum)?;
        self.retained_storage_data(storage.retained.min(maximum))?;
        Ok(())
    }

    pub(super) fn encode_journal_data(
        &mut self,
        ancestry: &PacketRestoredSettledAncestry17,
        sdk: &OriginalCompletedRestoredSettledCaptureData<'_>,
        storage: &FinalizationStorage,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        self.controller.payload_data()?;
        let capture = sdk.capture_pair_data();
        let confirmation = sdk.confirmation_pair_data();
        let view = PacketRestoredSettledJournal17View {
            ancestry,
            capture_request: capture.0,
            capture_terminal: capture.1,
            confirmation_request: confirmation.0,
            confirmation_terminal: confirmation.1,
            history_cut: self
                .history_cut
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            objects: self
                .objects
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            schema: RESTORED_SETTLED_JOURNAL17_SCHEMA,
        };
        self.journal
            .encode_data(&view, storage.journal_encoded, maximum)?;
        self.retained_storage_data(storage.retained.min(maximum))?;
        self.completed = true;
        Ok(())
    }

    pub(super) fn controller_data(&self) -> Result<(&ContentRef, &[u8]), RuntimeError> {
        self.controller.payload_data()
    }

    pub(super) fn journal_data(&self) -> Result<(&ContentRef, &[u8]), RuntimeError> {
        if !self.completed {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.journal.payload_data()
    }

    pub(super) fn proof_data(&self) -> Result<(&ContentRef, &[u8]), RuntimeError> {
        if !self.completed {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok((
            self.proof_reference
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            &self.proof,
        ))
    }

    pub(super) fn retained_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let Self {
            started: _,
            completed: _,
            controller,
            journal,
            objects,
            history_cut,
            proof,
            proof_reference,
        } = self;
        let mut total = sum(
            &[
                controller.retained_storage_data(maximum)?,
                journal.retained_storage_data(maximum)?,
                proof.capacity(),
            ],
            maximum,
        )?;
        if let Some(reference) = proof_reference {
            total = sum(
                &[total, NodeRuntime::capture_reference_storage(reference)?],
                maximum,
            )?;
        }
        if let Some(objects) = objects {
            let PacketRestoredSettledJournal17Objects {
                snapshot,
                before,
                control,
                anchor,
                after,
                host_protocol,
                semantic,
                runtime_object,
                coordinator_checkpoint,
            } = objects;
            for reference in [
                snapshot,
                before,
                control,
                anchor,
                after,
                host_protocol,
                semantic,
                runtime_object,
                coordinator_checkpoint,
            ] {
                total = sum(
                    &[total, NodeRuntime::capture_reference_storage(reference)?],
                    maximum,
                )?;
            }
        }
        if let Some(cut) = history_cut {
            total = sum(
                &[total, NodeRuntime::capture_reference_storage(&cut.prefix)?],
                maximum,
            )?;
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn undersized_component_spends_its_once_slot_before_any_output_dom() {
        let mut owner = Component::empty();
        let value = json!({"retained": "complete body"});
        let encoded = encoding_extent::canonical_encoded_extent_data(&value, 4096).unwrap();

        assert!(owner.encode_data(&value, encoded - 1, 65_536).is_err());
        assert!(owner.started);
        assert!(!owner.completed);
        assert!(owner.value.is_none());
        assert!(owner.bytes.is_empty());
        assert!(matches!(
            owner.encode_data(&value, encoded, 65_536),
            Err(RuntimeError::OutstandingObligations)
        ));
    }

    #[test]
    fn bounded_component_preserves_exact_canonical_output() {
        let mut owner = Component::empty();
        let value = json!({"z": "escaped\"\n λ", "a": [1, 0.000_001, -0.0]});
        let expected = canonical::canonical_json(&value).unwrap();

        owner.encode_data(&value, expected.len(), 65_536).unwrap();

        let (reference, bytes) = owner.payload_data().unwrap();
        assert_eq!(bytes, expected);
        assert_eq!(owner.bytes.capacity(), expected.len());
        reference.verify(bytes).unwrap();
    }

    #[test]
    fn bounded_writer_refusal_retains_the_original_prefix_and_capacity() {
        let mut bytes = Vec::with_capacity(4);
        let capacity = bytes.capacity();
        let mut writer = BoundedWriter {
            bytes: &mut bytes,
            maximum: 4,
        };

        writer.write_all(b"cut").unwrap();
        assert!(writer.write_all(b"17").is_err());

        assert_eq!(bytes, b"cut");
        assert_eq!(bytes.capacity(), capacity);
    }

    #[test]
    fn final_journal_and_scope_loan_stay_closed_before_whole_completion() {
        let mut owner = FinalizationOwners::empty();
        owner
            .controller
            .encode_data(&json!({"completed": true}), 18, 65_536)
            .unwrap();

        assert!(owner.controller_data().is_ok());
        assert!(matches!(
            owner.journal_data(),
            Err(RuntimeError::OutstandingObligations)
        ));
        assert!(matches!(
            owner.proof_data(),
            Err(RuntimeError::OutstandingObligations)
        ));
    }

    #[test]
    fn defining_reference_shape_bounds_actual_full_content_reference() {
        let reference = canonical::content_ref(b"actual retained DATA", JSON_MEDIA).unwrap();
        let actual = encoding_extent::canonical_encoded_extent_data(&reference, 4096).unwrap();
        let upper =
            encoding_extent::canonical_encoded_extent_data(&reference_shape(JSON_MEDIA), 4096)
                .unwrap();

        assert!(upper >= actual);
        assert_eq!(
            upper - actual,
            DECIMAL_SHAPE.len() - reference.length.get().to_string().len()
        );
    }
}
