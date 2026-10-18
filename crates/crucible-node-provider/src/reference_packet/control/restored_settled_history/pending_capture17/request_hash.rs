//! Keeps the separately admitted normative request-hash construction sticky.
//!
//! Canonical DOM/sort/escaped-string/output phases allocate independently of
//! the pending Control count. This owner preserves its initialized DOM, output
//! prefix and completed HashRef through refusal; it grants no native action.

use super::*;
use crate::reference_packet::control::capture::StartupRequestIdentity;
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;

/// Borrows the actual original and its complete independent hash-phase demand.
pub(crate) struct NativePendingCapture17RequestHashStorageData<'a> {
    original: &'a Envelope,
    serialization: NativeSerializationStorageData,
    row: PacketNativeStartupAllocationRow,
}

impl NativePendingCapture17RequestHashStorageData<'_> {
    /// Returns distinct retained/transient/fixed work axes, never permission.
    pub(crate) fn row_data(&self) -> PacketNativeStartupAllocationRow {
        self.row
    }
}

/// Retains every completed owning hash phase beside the prospective draft.
pub(crate) struct NativePendingCapture17RequestHashAttempt {
    original_identity: Option<[u8; 32]>,
    dom: Option<Value>,
    canonical: Vec<u8>,
    hash: Option<HashRef>,
    complete: bool,
}

impl NativePendingCapture17RequestHashAttempt {
    pub(super) fn completed_data(&self, original: &Envelope) -> Result<&HashRef, ProviderError> {
        if !self.complete || self.original_identity != Some(exact_original_identity_data(original)?)
        {
            return Err(refused());
        }
        self.hash.as_ref().ok_or_else(refused)
    }
}

struct CanonicalBank<'a> {
    bytes: &'a mut Vec<u8>,
    maximum: usize,
}
impl Write for CanonicalBank<'_> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let length = self
            .bytes
            .len()
            .checked_add(input.len())
            .filter(|length| *length <= self.maximum && *length <= self.bytes.capacity())
            .ok_or(io::ErrorKind::OutOfMemory)?;
        self.bytes.extend_from_slice(input);
        debug_assert_eq!(self.bytes.len(), length);
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl PacketControl {
    /// Quotes the existing exact twelve-field normative original projection.
    ///
    /// This walk borrows already-encoded Envelope Value fields, not custom Bytes.
    /// Caller must prepay this fixed visitor before invoking it. The returned
    /// row covers the complete later owning phase before its first allocation.
    /// # Errors
    /// Refuses another request class, overflow or the independent maximum.
    pub(crate) fn quote_pending_capture17_request_hash_data<'a>(
        original: &'a Envelope,
        maximum: usize,
    ) -> Result<NativePendingCapture17RequestHashStorageData<'a>, ProviderError> {
        if original.message != MessageKind::Request || original.method != Method::Begin {
            return Err(refused());
        }
        let serialization = actual_serialization_storage_data(
            &StartupRequestIdentity(original),
            Default::default(),
            maximum,
        )?;
        let retained = sum(&[
            size_of::<NativePendingCapture17RequestHashAttempt>(),
            serialization.retained_value_backing_bytes,
            serialization.maximum_encoded_bytes,
            "blake3-256".len() + "cnp.request.v1".len() + 64,
        ])?;
        // Full-original identity runs before the owning canonical phase. Its
        // conservative old U64 formatter bank remains independently named.
        let transient = serialization.requested_total()?.max(20);
        let quantity = |bytes| u64::try_from(bytes).map(U64::new).map_err(|_| exhausted());
        let row = PacketNativeStartupAllocationRow {
            retained_requested_bytes: quantity(retained)?,
            maximum_simultaneous_transient_bytes: quantity(transient)?,
            declared_counter_scratch_bytes: quantity(
                Self::pending_capture17_request_hash_counter_scratch_data(),
            )?,
        };
        if usize::try_from(row.requested_peak_data()?).map_err(|_| exhausted())? > maximum {
            return Err(exhausted());
        }
        Ok(NativePendingCapture17RequestHashStorageData {
            original,
            serialization,
            row,
        })
    }

    /// Completes one hash in the actual caller's sticky retained destination.
    ///
    /// Caller independently admits the complete returned row first. This DATA
    /// comparison never converts a row into a grant. The actual original stays
    /// borrowed by the ephemeral storage only; the retained owner binds complete
    /// literal identity without a self-reference. That identity conveys no currency.
    /// # Errors
    /// Refuses an existing attempt, changed row, short allocation, canonical
    /// failure or invalid hash; all initialized owners remain in destination.
    pub(crate) fn complete_pending_capture17_request_hash_into_data(
        storage: &NativePendingCapture17RequestHashStorageData<'_>,
        destination: &mut Option<NativePendingCapture17RequestHashAttempt>,
    ) -> Result<(), ProviderError> {
        if destination.is_some() {
            return Err(refused());
        }
        *destination = Some(NativePendingCapture17RequestHashAttempt {
            original_identity: None,
            dom: None,
            canonical: Vec::new(),
            hash: None,
            complete: false,
        });
        let actual = Self::quote_pending_capture17_request_hash_data(
            storage.original,
            usize::try_from(storage.row.requested_peak_data()?).map_err(|_| exhausted())?,
        )?;
        if actual.row != storage.row
            || actual.serialization.maximum_encoded_bytes
                != storage.serialization.maximum_encoded_bytes
        {
            return Err(refused());
        }
        let attempt = destination.as_mut().ok_or_else(refused)?;
        attempt.original_identity = Some(exact_original_identity_data(storage.original)?);
        attempt
            .canonical
            .try_reserve_exact(storage.serialization.maximum_encoded_bytes)
            .map_err(|_| exhausted())?;
        attempt.dom = Some(
            serde_json::to_value(StartupRequestIdentity(storage.original))
                .map_err(crucible_node_contract::ContractError::from)?,
        );
        canonical::canonical_json_to_writer(
            attempt.dom.as_ref().ok_or_else(refused)?,
            &mut CanonicalBank {
                bytes: &mut attempt.canonical,
                maximum: storage.serialization.maximum_encoded_bytes,
            },
        )?;
        attempt.hash = Some(canonical::hash("cnp.request.v1", &attempt.canonical)?);
        attempt.complete = true;
        Ok(())
    }

    /// Names only actual fixed hash quote/attempt/canonical/identity views.
    pub(crate) fn pending_capture17_request_hash_counter_scratch_data() -> usize {
        size_of::<NativePendingCapture17RequestHashStorageData<'static>>()
            + size_of::<NativePendingCapture17RequestHashAttempt>()
            + size_of::<Option<NativePendingCapture17RequestHashAttempt>>()
            + size_of::<StartupRequestIdentity<'static>>()
            + field_view_bytes(|value: &'static Envelope| {
                let Envelope { protocol, message, session_id, incarnation_id, node_id, execution_owner_id, capture_owner_id, request_id, operation_id, sequence, method, body, extensions } = value;
                (protocol, message, session_id, incarnation_id, node_id, execution_owner_id, capture_owner_id, request_id, operation_id, sequence, method, body, extensions)
            })
            + size_of::<CanonicalBank<'static>>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + size_of::<[u8; 64]>()
            + size_of::<Option<[u8; 32]>>()
            + original_identity_counter_scratch_data()
            + size_of::<[usize; 4]>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<Value, serde_json::Error>>()
            + size_of::<Result<HashRef, crucible_node_contract::ContractError>>()
            + crate::retained_metadata::serialization_storage::original_serialization_counter_scratch_data()
            + canonical::canonical_number_counter_scratch_bytes_data()
    }
}

// This complete Envelope transcript includes sequence and every retained raw
// body/extension Value. It is distinct from the normative request hash and from
// Source MAC transcripts. DATA equality never establishes actual Boot ownership.
struct OriginalIdentity(blake3::Hasher);
impl Write for OriginalIdentity {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn exact_original_identity_data(original: &Envelope) -> Result<[u8; 32], ProviderError> {
    let mut sink = OriginalIdentity(blake3::Hasher::new_derive_key(
        "source-private.pending-capture-control-original/17",
    ));
    serde_json::to_writer(&mut sink, original).map_err(|_| refused())?;
    Ok(*sink.0.finalize().as_bytes())
}

pub(super) fn original_identity_counter_scratch_data() -> usize {
    size_of::<OriginalIdentity>()
        + size_of::<serde_json::Serializer<&'static mut OriginalIdentity>>()
        + size_of::<blake3::Hash>()
        + size_of::<Result<[u8; 32], ProviderError>>()
        + size_of::<[u8; 20]>()
        + size_of::<u64>()
        + size_of::<usize>() * 2
        + size_of::<&str>()
        + size_of::<Result<&str, std::str::Utf8Error>>()
        + size_of::<String>()
}

// These controls exercise owning DATA phases, without Source/native admission.
#[cfg(test)]
mod tests {
    use super::*;

    fn original() -> Envelope {
        let mut original = crate::envelope::tests::request();
        original.method = Method::Begin;
        original
    }

    #[test]
    fn exact_complete_hash_demand_admits_and_one_short_refuses() -> Result<(), ProviderError> {
        let original = original();
        let storage =
            PacketControl::quote_pending_capture17_request_hash_data(&original, usize::MAX)?;
        let exact =
            usize::try_from(storage.row_data().requested_peak_data()?).map_err(|_| exhausted())?;
        assert!(PacketControl::quote_pending_capture17_request_hash_data(&original, exact).is_ok());
        assert!(
            PacketControl::quote_pending_capture17_request_hash_data(&original, exact - 1).is_err()
        );
        Ok(())
    }

    #[test]
    fn each_short_axis_keeps_actual_attempt_sticky_before_owning_work() -> Result<(), ProviderError>
    {
        let original = original();
        let valid =
            PacketControl::quote_pending_capture17_request_hash_data(&original, usize::MAX)?;
        for axis in 0..3 {
            let mut storage =
                PacketControl::quote_pending_capture17_request_hash_data(&original, usize::MAX)?;
            let quantity = match axis {
                0 => &mut storage.row.retained_requested_bytes,
                1 => &mut storage.row.maximum_simultaneous_transient_bytes,
                _ => &mut storage.row.declared_counter_scratch_bytes,
            };
            *quantity = U64::new(quantity.get() - 1);
            let mut destination = None;

            assert!(
                PacketControl::complete_pending_capture17_request_hash_into_data(
                    &storage,
                    &mut destination
                )
                .is_err()
            );

            let actual = destination.as_ref().ok_or_else(refused)?;
            assert!(!actual.complete);
            assert!(actual.original_identity.is_none());
            assert!(actual.dom.is_none());
            assert!(actual.canonical.is_empty());
            assert!(actual.hash.is_none());
            assert!(
                PacketControl::complete_pending_capture17_request_hash_into_data(
                    &valid,
                    &mut destination
                )
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn actual_bounded_canonical_writer_preserves_prefix_without_growth() -> Result<(), ProviderError>
    {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(5).map_err(|_| exhausted())?;
        let capacity = bytes.capacity();
        let mut writer = CanonicalBank {
            bytes: &mut bytes,
            maximum: 5,
        };
        writer.write_all(b"abc").map_err(|_| exhausted())?;

        assert!(writer.write_all(b"def").is_err());

        assert_eq!(bytes, b"abc");
        assert_eq!(bytes.capacity(), capacity);
        Ok(())
    }
}
