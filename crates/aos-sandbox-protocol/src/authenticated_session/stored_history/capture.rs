//! Retains portable stored-history codec DATA through nested failure boundaries.
//!
//! These captures do not establish a current journal, authenticated endpoint,
//! floor, payer or resource grant. Fully checked pure scratch is disposed only
//! where its ordinary last borrower completes; failed partials remain resident.

use super::*;
use aos_sandbox_broker_session_protocol::durable::history::BrokerSessionDurableHistoryDecodeCaptureV1;
use super::super::historical_checkpoint::{
    HistoricalSessionCheckpointDecodeCaptureV1, HistoricalSessionCheckpointEncodeCaptureV1,
    HistoricalSessionCheckpointVerifyCaptureV1,
};

/// Retains one stored carrier's checkpoint, model and canonical equality backing.
#[derive(Default)]
pub struct StoredBrokerSessionHistoryDecodeCaptureV1 {
    canonical_key: Option<Vec<u8>>,
    checkpoint: HistoricalSessionCheckpointDecodeCaptureV1,
    stored: Option<StoredBrokerSessionHistoryV1>,
    canonical: StoredBrokerSessionHistoryEncodeCaptureV1,
    result: Option<Result<(), StoredBrokerSessionHistoryErrorV1>>,
    attempted: bool,
    closed: Option<StoredBrokerSessionHistoryErrorV1>,
}

/// Retains one stored carrier encode's history, verification and output leaves.
#[derive(Default)]
pub struct StoredBrokerSessionHistoryEncodeCaptureV1 {
    history: BrokerSessionDurableHistoryDecodeCaptureV1,
    verify: HistoricalSessionCheckpointVerifyCaptureV1,
    checkpoint: HistoricalSessionCheckpointEncodeCaptureV1,
    checkpoint_bytes: Option<Vec<u8>>,
    encoded: Option<Vec<u8>>,
    result: Option<Result<(), StoredBrokerSessionHistoryErrorV1>>,
    attempted: bool,
    closed: Option<StoredBrokerSessionHistoryErrorV1>,
}

macro_rules! accessors {
    ($capture:ty, $output:ty, $field:ident, $borrow:ident, $take:ident) => {
        impl $capture {
            /// Constructs an empty once-only comparison capture.
            #[must_use]
            pub fn new() -> Self { Self::default() }

            /// Borrows the first actual codec error or a later closed refusal.
            #[must_use]
            pub fn failure(&self) -> Option<&StoredBrokerSessionHistoryErrorV1> {
                self.result.as_ref().and_then(|result| result.as_ref().err())
                    .or(self.closed.as_ref())
            }

            /// Borrows a completely validated output before its once-only move.
            #[must_use]
            pub fn $borrow(&self) -> Option<&$output> {
                if self.failure().is_none() && matches!(self.result, Some(Ok(()))) {
                    self.$field.as_ref()
                } else { None }
            }

            /// Moves a completely validated output without cloning any backing.
            ///
            /// # Errors
            /// Returns the first failure or rejects absent/closed/already moved output.
            pub fn $take(&mut self) -> Result<$output, StoredBrokerSessionHistoryErrorV1> {
                if let Some(error) = self.failure() { return Err(*error); }
                if !matches!(self.result, Some(Ok(()))) {
                    return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
                }
                self.$field.take().ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)
            }

            /// Returns this concrete inline owner extent, excluding heap storage.
            #[must_use]
            pub const fn inline_bytes_v1() -> usize { std::mem::size_of::<Self>() }

            /// Returns one additional materialized constructor-carrier extent.
            ///
            /// This is passive DATA, excluding the resident owner, dynamic
            /// buffers and lower constructor temporaries supplied separately.
            #[must_use]
            pub const fn construction_bytes_v1() -> usize { std::mem::size_of::<Self>() }
        }
    };
}

accessors!(StoredBrokerSessionHistoryDecodeCaptureV1, StoredBrokerSessionHistoryV1,
    stored, stored, take_stored_once);
accessors!(StoredBrokerSessionHistoryEncodeCaptureV1, Vec<u8>,
    encoded, encoded_vec, take_encoded_once);

impl StoredBrokerSessionHistoryEncodeCaptureV1 {
    /// Borrows the canonical output without copying its bytes.
    #[must_use]
    pub fn encoded(&self) -> Option<&[u8]> { self.encoded_vec().map(Vec::as_slice) }
}

impl StoredBrokerSessionHistoryV1 {
    /// Decodes through the ordinary codec while keeping reached partial DATA.
    ///
    /// # Errors
    /// Returns the ordinary stored-carrier error. Reentry closes this capture
    /// without overwriting the first result or disposing any earlier output.
    pub fn decode_retaining(key: &[u8], value: &[u8], capture: &mut StoredBrokerSessionHistoryDecodeCaptureV1)
        -> Result<(), StoredBrokerSessionHistoryErrorV1>
    {
        if capture.attempted {
            capture.closed = Some(StoredBrokerSessionHistoryErrorV1::Invalid);
            return Err(*capture.failure().unwrap_or(&StoredBrokerSessionHistoryErrorV1::Invalid));
        }
        capture.attempted = true;
        match decode_engine(key, value, Some(capture)) {
            Ok(stored) => {
                capture.stored = Some(stored);
                capture.result = Some(Ok(()));
                Ok(())
            }
            Err(error) => {
                capture.result = Some(Err(error));
                Err(error)
            }
        }
    }

    /// Encodes through the shared view engine, retaining reached nested DATA.
    ///
    /// # Errors
    /// Returns the ordinary stored-carrier error or rejects a repeated attempt.
    pub fn encode_retaining(&self, capture: &mut StoredBrokerSessionHistoryEncodeCaptureV1)
        -> Result<(), StoredBrokerSessionHistoryErrorV1>
    {
        self.as_view().encode_retaining(capture)
    }
}

impl StoredBrokerSessionHistoryViewV1<'_> {
    /// Encodes through the shared engine while retaining its reached partials.
    ///
    /// # Errors
    /// Returns the ordinary stored-carrier error. Reentry keeps the first result
    /// and closes subsequent positive access to this capture.
    pub fn encode_retaining(&self, capture: &mut StoredBrokerSessionHistoryEncodeCaptureV1)
        -> Result<(), StoredBrokerSessionHistoryErrorV1>
    {
        self.encode_for_purpose_retaining_v2(capture, StoredBrokerSessionPurposeDataV2::Ordinary)
    }

    fn encode_for_purpose_retaining_v2(&self, capture: &mut StoredBrokerSessionHistoryEncodeCaptureV1,
        purpose: StoredBrokerSessionPurposeDataV2,
    ) -> Result<(), StoredBrokerSessionHistoryErrorV1> {
        if capture.attempted {
            capture.closed = Some(StoredBrokerSessionHistoryErrorV1::Invalid);
            return Err(*capture.failure().unwrap_or(&StoredBrokerSessionHistoryErrorV1::Invalid));
        }
        capture.attempted = true;
        match encode_engine(self, Some(capture), purpose) {
            Ok(encoded) => {
                capture.encoded = Some(encoded);
                capture.result = Some(Ok(()));
                Ok(())
            }
            Err(error) => {
                capture.result = Some(Err(error));
                Err(error)
            }
        }
    }
}

pub(super) fn decode_engine(key: &[u8], value: &[u8], mut capture: Option<&mut StoredBrokerSessionHistoryDecodeCaptureV1>)
    -> Result<StoredBrokerSessionHistoryV1, StoredBrokerSessionHistoryErrorV1>
{
    if value.len() < VALUE_FIXED_BYTES_V2
        || value.len()
            > VALUE_FIXED_BYTES_V3
                .checked_add(BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES)
                .and_then(|size| size.checked_add(historical_checkpoint::MAXIMUM_BYTES))
                .ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)?
        || value.get(..8) != Some(VALUE_MAGIC.as_slice())
    {
        return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
    }
    let version = read_u16(value, 8)?;
    if !matches!(version, VALUE_VERSION_V2 | VALUE_VERSION_V3) {
        return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
    }
    let protocol = decode_protocol(read_u8(value, 10)?)?;
    let endpoint = decode_endpoint(read_u8(value, 11)?)?;
    let (purpose, key_protocol) = classify_protocol_key_v2(key)?;
    if key_protocol != protocol { return Err(StoredBrokerSessionHistoryErrorV1::Invalid); }
    if let Some(capture) = capture.as_deref_mut() {
        capture.canonical_key = Some(protocol_key_for_purpose_v2(protocol, purpose));
        if capture.canonical_key.as_deref() != Some(key) {
            return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
        }
        // Equality is the original final borrower of the exact key backing.
        drop(capture.canonical_key.take());
    } else if key != protocol_key_for_purpose_v2(protocol, purpose) {
        return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
    }
    let generation = read_u64(value, 12)?;
    let stable_endpoint_identity = read_array(value, 20)?;
    let endpoint_publication = read_array(value, 52)?;
    let current_catalog = read_array(value, 84)?;
    let current_head = read_array(value, 116)?;
    let history_length = usize::try_from(read_u32(value, 148)?)
        .map_err(|_| StoredBrokerSessionHistoryErrorV1::Invalid)?;
    let history_end = 152usize
        .checked_add(history_length)
        .ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)?;
    let (mut checkpoint_capture, stored_capture, canonical_capture) = match capture {
        Some(capture) => (Some(&mut capture.checkpoint), Some(&mut capture.stored),
            Some(&mut capture.canonical)),
        None => (None, None, None),
    };
    let (checkpoint, digest_start) = if version == VALUE_VERSION_V3 {
        let length = usize::try_from(read_u32(value, history_end)?)
            .map_err(|_| StoredBrokerSessionHistoryErrorV1::Invalid)?;
        if length == 0 || length > historical_checkpoint::MAXIMUM_BYTES {
            return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
        }
        let start = history_end
            .checked_add(4)
            .ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)?;
        let end = start
            .checked_add(length)
            .ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)?;
        let input = value.get(start..end)
            .ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)?;
        let checkpoint = match checkpoint_capture.as_deref_mut() {
            Some(capture) => {
                HistoricalSessionCheckpointV1::decode_retaining(input, capture)?;
                None
            }
            None => Some(HistoricalSessionCheckpointV1::decode(input)?),
        };
        (checkpoint, end)
    } else {
        (None, history_end)
    };
    let digest_end = digest_start
        .checked_add(VALUE_DIGEST_BYTES)
        .ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)?;
    if history_length == 0
        || history_length > BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES
        || digest_end != value.len()
        || read_array::<32>(value, digest_start)?
            != value_digest(&value[..digest_start], version)
    {
        return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
    }
    let history = value
        .get(152..history_end)
        .ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)?
        .to_vec();
    let checkpoint = if version == VALUE_VERSION_V3 {
        match checkpoint_capture {
            Some(capture) => Some(capture.take_checkpoint_once()?),
            None => checkpoint,
        }
    } else { checkpoint };
    let mut local_stored = None;
    let stored = stored_capture.unwrap_or(&mut local_stored);
    *stored = Some(StoredBrokerSessionHistoryV1 {
        protocol,
        endpoint,
        generation,
        stable_endpoint_identity,
        endpoint_publication,
        current_catalog,
        current_head,
        history,
        checkpoint,
    });
    let complete = stored.as_ref().ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)?;
    match canonical_capture {
        Some(capture) => {
            complete.as_view().encode_for_purpose_retaining_v2(capture, purpose)?;
            if capture.encoded() != Some(value) {
                return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
            }
            // Equality is the original final borrower of this encoding.
            drop(capture.take_encoded_once()?);
        }
        None => {
            if encode_engine(&complete.as_view(), None, purpose)? != value {
                return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
            }
        }
    }
    stored.take().ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)
}

pub(super) fn encode_engine(view: &StoredBrokerSessionHistoryViewV1<'_>, capture: Option<&mut StoredBrokerSessionHistoryEncodeCaptureV1>, purpose: StoredBrokerSessionPurposeDataV2)
    -> Result<Vec<u8>, StoredBrokerSessionHistoryErrorV1>
{
    let (mut history_capture, verify_capture, encode_capture, bytes_capture,
        output_capture) = match capture {
        Some(capture) => (
            Some(&mut capture.history),
            Some(&mut capture.verify),
            Some(&mut capture.checkpoint),
            Some(&mut capture.checkpoint_bytes),
            Some(&mut capture.encoded),
        ),
        None => (None, None, None, None, None),
    };
    let model_local;
    let model = match history_capture.as_deref_mut() {
        Some(capture) => {
            BrokerSessionDurableHistoryV1::decode_retaining(view.history, capture)
                .map_err(|_| StoredBrokerSessionHistoryErrorV1::Invalid)?;
            capture.history().ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)?
        }
        None => {
            model_local = BrokerSessionDurableHistoryV1::decode(view.history)
                .map_err(|_| StoredBrokerSessionHistoryErrorV1::Invalid)?;
            &model_local
        }
    };
    let head = model
        .head()
        .map_err(|_| StoredBrokerSessionHistoryErrorV1::Invalid)?;
    if let Some(checkpoint) = view.checkpoint {
        let mut verify_capture = verify_capture;
        let transcript_local;
        let transcript = match verify_capture.as_deref_mut() {
            Some(capture) => {
                checkpoint.verify_retaining(capture)?;
                capture.transcript().ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)?
            }
            None => {
                transcript_local = checkpoint.verify()?;
                &transcript_local
            }
        };
        let recover_profile = aos_sandbox_broker_session_protocol::profile::
            is_storage_operator_recover_transcript_v1(transcript);
        let stop_cleanup_profile = aos_sandbox_broker_session_protocol::profile::
            is_host_stop_cleanup_transcript_v1(transcript);
        let no_apply_cleanup_profile = aos_sandbox_broker_session_protocol::profile::
            is_host_no_apply_cleanup_transcript_v1(transcript);
        let profile_matches = match purpose {
            StoredBrokerSessionPurposeDataV2::Ordinary =>
                !recover_profile && !stop_cleanup_profile && !no_apply_cleanup_profile,
            StoredBrokerSessionPurposeDataV2::OperatorRecoverInventory => recover_profile,
            StoredBrokerSessionPurposeDataV2::HostStopCleanup => stop_cleanup_profile,
            StoredBrokerSessionPurposeDataV2::HostNoApplyCleanup => no_apply_cleanup_profile,
        };
        if !profile_matches {
            return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
        }
        if purpose != StoredBrokerSessionPurposeDataV2::Ordinary {
            // This remains historical DATA. The same existing signature and
            // traffic engine validates the complete readonly prefix; no token
            // or fact about the interrupted ordinary head is produced.
            aos_sandbox_broker_session_protocol::verify_historical_traffic_records_v1(
                model.records(), transcript, checkpoint.context(),
            ).map_err(|_| StoredBrokerSessionHistoryErrorV1::Invalid)?;
            for record in model.records() {
                let request = aos_sandbox_broker_session_protocol::decode_canonical_request_v1(record.request_packet())
                    .map_err(|_| StoredBrokerSessionHistoryErrorV1::Invalid)?;
                use aos_proto::aos::sandbox::local::v1::BrokerMethod as Method;
                let authorized = request.message().authorization.as_option().is_some();
                let allowed = match purpose {
                    StoredBrokerSessionPurposeDataV2::OperatorRecoverInventory =>
                        record.method() == Method::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
                            && !authorized,
                    StoredBrokerSessionPurposeDataV2::HostStopCleanup => match record.method() {
                        Method::BROKER_METHOD_HOST_APPLY_RUNTIME => authorized
                            && crate::decode_canonical_live_host_stop_cleanup_envelope_data_v1(
                                &request.message().body).is_ok(),
                        Method::BROKER_METHOD_HOST_INVENTORY_RUNTIME => !authorized,
                        _ => false,
                    },
                    StoredBrokerSessionPurposeDataV2::HostNoApplyCleanup => !authorized
                        && matches!(record.method(),
                            Method::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2
                            | Method::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2),
                    StoredBrokerSessionPurposeDataV2::Ordinary => false,
                };
                if !allowed {
                    return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
                }
            }
        }
        if transcript.protocol() != view.protocol
            || model.records().iter().any(|record| {
                record.session_binding() != transcript.session_binding()
                    || record.protected_bindings().protected_context()
                        != checkpoint.context().protected_context_digest()
                    || record.protected_bindings().endpoint_publication()
                        != view.endpoint_publication
            })
        {
            return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
        }
        if let Some(capture) = verify_capture {
            // The complete history/transcript predicate is the final borrower.
            drop(capture.take_transcript_once()?);
        }
    }
    let required_protocol = match purpose {
        StoredBrokerSessionPurposeDataV2::Ordinary => None,
        StoredBrokerSessionPurposeDataV2::OperatorRecoverInventory => Some(BrokerSessionProtocolV1::Storage),
        StoredBrokerSessionPurposeDataV2::HostStopCleanup
        | StoredBrokerSessionPurposeDataV2::HostNoApplyCleanup => Some(BrokerSessionProtocolV1::Host),
    };
    if required_protocol.is_some_and(|protocol| view.protocol != protocol || view.checkpoint.is_none())
    {
        return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
    }
    if view.generation == 0
        || view.endpoint_publication.iter().all(|byte| *byte == 0)
        || view.stable_endpoint_identity.iter().all(|byte| *byte == 0)
        || view.current_catalog.iter().all(|byte| *byte == 0)
        || model.head_commitment() != view.current_head
        || head.protocol() != view.protocol
        || head.endpoint() != view.endpoint
    {
        return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
    }
    let history_length = u32::try_from(view.history.len())
        .map_err(|_| StoredBrokerSessionHistoryErrorV1::Invalid)?;
    let mut checkpoint_local = None;
    let checkpoint = bytes_capture.unwrap_or(&mut checkpoint_local);
    *checkpoint = match (view.checkpoint, encode_capture) {
        (Some(checkpoint), Some(capture)) => {
            checkpoint.encode_retaining(capture)?;
            Some(capture.take_encoded_once()?)
        }
        (Some(checkpoint), None) => Some(checkpoint.encode()?),
        (None, _) => None,
    };
    let checkpoint_length = checkpoint.as_ref().map_or(0, Vec::len);
    let version = if checkpoint.is_some() {
        VALUE_VERSION_V3
    } else {
        VALUE_VERSION_V2
    };
    let capacity = VALUE_FIXED_BYTES_V3
        .checked_add(view.history.len())
        .and_then(|size| size.checked_add(checkpoint_length))
        .ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)?;
    if view.history.len() > BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES
        || checkpoint_length > historical_checkpoint::MAXIMUM_BYTES
    {
        return Err(StoredBrokerSessionHistoryErrorV1::Invalid);
    }
    let mut output_local = None;
    let output = output_capture.unwrap_or(&mut output_local);
    *output = Some(Vec::with_capacity(capacity));
    let value = output.as_mut().ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)?;
    value.extend_from_slice(VALUE_MAGIC);
    value.extend_from_slice(&version.to_be_bytes());
    value.push(protocol_code(view.protocol));
    value.push(endpoint_code(view.endpoint));
    value.extend_from_slice(&view.generation.to_be_bytes());
    value.extend_from_slice(&view.stable_endpoint_identity);
    value.extend_from_slice(&view.endpoint_publication);
    value.extend_from_slice(&view.current_catalog);
    value.extend_from_slice(&view.current_head);
    value.extend_from_slice(&history_length.to_be_bytes());
    value.extend_from_slice(view.history);
    if let Some(checkpoint) = checkpoint.as_ref() {
        let length = u32::try_from(checkpoint.len())
            .map_err(|_| StoredBrokerSessionHistoryErrorV1::Invalid)?;
        value.extend_from_slice(&length.to_be_bytes());
        value.extend_from_slice(&checkpoint);
    }
    // The checkpoint's exact append is its original final borrower.
    drop(checkpoint.take());
    let digest = value_digest(&value, version);
    value.extend_from_slice(&digest);
    if let Some(capture) = history_capture {
        // The fully encoded carrier is complete; the ordinary local model
        // would be destroyed as this function returns its output.
        drop(capture.take_history_once()
            .map_err(|_| StoredBrokerSessionHistoryErrorV1::Invalid)?);
    }
    output.take().ok_or(StoredBrokerSessionHistoryErrorV1::Invalid)
}

impl StoredBrokerSessionHistoryDecodeCaptureV1 {
    /// Bounds fixed retained field/control cells, excluding dynamic model storage.
    #[must_use]
    pub fn receiving_metadata_cells_v1() -> Option<usize> {
        7usize.checked_add(HistoricalSessionCheckpointDecodeCaptureV1::receiving_metadata_cells_v1()?)?
            .checked_add(StoredBrokerSessionHistoryEncodeCaptureV1::receiving_metadata_cells_v1()?)
    }
}

impl StoredBrokerSessionHistoryEncodeCaptureV1 {
    /// Bounds fixed retained field/control cells, excluding dynamic model storage.
    #[must_use]
    pub fn receiving_metadata_cells_v1() -> Option<usize> {
        8usize.checked_add(BrokerSessionDurableHistoryDecodeCaptureV1::receiving_metadata_cells_v1()?)?
            .checked_add(HistoricalSessionCheckpointVerifyCaptureV1::receiving_metadata_cells_v1()?)?
            .checked_add(HistoricalSessionCheckpointEncodeCaptureV1::receiving_metadata_cells_v1()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_history_refusal_keeps_the_actual_outer_history_backing() {
        // The outer portable framing/digest is valid. Its nested history is
        // deliberately malformed comparison DATA, with no session authority.
        let history = b"malformed-nested-history";
        let mut value = vec![0; 152];
        value[..8].copy_from_slice(VALUE_MAGIC);
        value[8..10].copy_from_slice(&VALUE_VERSION_V2.to_be_bytes());
        value[10] = protocol_code(BrokerSessionProtocolV1::Storage);
        value[11] = endpoint_code(BrokerSessionDurableEndpointV1::Client);
        value[12..20].copy_from_slice(&1u64.to_be_bytes());
        value[20..52].fill(1);
        value[52..84].fill(2);
        value[84..116].fill(3);
        value[116..148].fill(4);
        value[148..152].copy_from_slice(&(history.len() as u32).to_be_bytes());
        value.extend_from_slice(history);
        let digest = value_digest(&value, VALUE_VERSION_V2);
        value.extend_from_slice(&digest);
        let key = canonical_protocol_key_v1(BrokerSessionProtocolV1::Storage);
        let ordinary_error = StoredBrokerSessionHistoryV1::decode(&key, &value).unwrap_err();
        let mut capture = StoredBrokerSessionHistoryDecodeCaptureV1::new();

        let retained_error = StoredBrokerSessionHistoryV1::decode_retaining(
            &key, &value, &mut capture,
        ).unwrap_err();

        assert_eq!(retained_error, ordinary_error);
        assert_eq!(capture.failure(), Some(&ordinary_error));
        assert!(capture.stored().is_none());
        assert!(capture.canonical.history.failure().is_some());
        let raw = &capture.stored.as_ref().unwrap().history;
        assert_eq!(raw, history);
        let pointer = raw.as_ptr();

        assert!(StoredBrokerSessionHistoryV1::decode_retaining(&key, &[], &mut capture).is_err());
        assert_eq!(capture.stored.as_ref().unwrap().history.as_ptr(), pointer);
        assert!(capture.take_stored_once().is_err());
    }
}

#[cfg(test)]
mod key_capture_tests {
    use super::*;

    #[test]
    fn wrong_keys_keep_the_actual_classifier_refusal_before_canonical_materialization() {
        // Strict purpose/role classification now precedes canonical-key
        // materialization. Neither refused key reaches that later allocation.
        let mut value = vec![0; VALUE_FIXED_BYTES_V2];
        value[..8].copy_from_slice(VALUE_MAGIC);
        value[8..10].copy_from_slice(&VALUE_VERSION_V2.to_be_bytes());
        value[10] = protocol_code(BrokerSessionProtocolV1::Storage);
        value[11] = endpoint_code(BrokerSessionDurableEndpointV1::Client);
        let wrong_role = canonical_protocol_key_v1(BrokerSessionProtocolV1::Host);

        for key in [b"wrong-key".as_slice(), wrong_role.as_slice()] {
            let ordinary = StoredBrokerSessionHistoryV1::decode(key, &value).unwrap_err();
            let mut capture = StoredBrokerSessionHistoryDecodeCaptureV1::new();
            let retained = StoredBrokerSessionHistoryV1::decode_retaining(
                key, &value, &mut capture,
            ).unwrap_err();

            assert_eq!(retained, ordinary);
            assert_eq!(capture.failure(), Some(&ordinary));
            assert!(capture.canonical_key.is_none());
            assert!(capture.stored().is_none());
            assert!(StoredBrokerSessionHistoryV1::decode_retaining(b"", &[], &mut capture).is_err());
            assert_eq!(capture.failure(), Some(&ordinary));
            assert!(capture.canonical_key.is_none());
            assert!(capture.take_stored_once().is_err());
        }
    }
}
