//! Commits complete Controller-view literals by direction for signed17 actions.
//!
//! Native prefix preparation may reserve all outgoing slots before receiving any
//! ACK; the SDK records those sends/ACKs interleaved. This private proof format
//! preserves exact complete literals and each direction's order, without claiming
//! a shared cross-direction chronology from either actor's allocation order.
//! Snapshot journals and causal original/response/ACK joins remain independent.
//!
//! ```json
//! {"frame_count":"1","incoming":[],"incoming_count":"0","next_sequence":"5","outgoing":[{"complete":true,"framed_hex":"000000027b7d","transferred":"6"}],"outgoing_count":"1","schema":"source-private.controller-directional-literal-prefix/17"}
//! ```

use super::*;
use crucible_node_contract::{ContentRef, HashRef, U64};
use std::{
    io::{self, Write},
    mem::size_of,
};

const SCHEMA: &str = "source-private.controller-directional-literal-prefix/17";
const DOMAIN: &str = "cnp.blob.v1";
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Contains a fixed commitment derived from one actual complete literal-bank cut.
///
/// Its private constructor performs the same bounded two-pass writer used by
/// the ordinary ContentRef producer. It grants no Source read or action rights.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalRestoredInput17LiteralPrefixIdentityData {
    digest: [u8; 32],
    encoded_length: u64,
    incoming: usize,
    outgoing: usize,
    next_sequence: U64,
}

impl OriginalRestoredInput17LiteralPrefixIdentityData {
    /// Returns the full digest without allocating a HashRef or hexadecimal text.
    pub const fn digest_data(&self) -> [u8; 32] {
        self.digest
    }
    /// Returns the exact encoded length of the committed private JSON format.
    pub const fn encoded_length_data(&self) -> u64 {
        self.encoded_length
    }
    /// Returns the actual combined slot count in the verified cut.
    pub const fn frame_count_data(&self) -> usize {
        self.incoming + self.outgoing
    }
    /// Returns the Controller-view complete incoming count.
    pub const fn incoming_count_data(&self) -> usize {
        self.incoming
    }
    /// Returns the Controller-view complete outgoing count.
    pub const fn outgoing_count_data(&self) -> usize {
        self.outgoing
    }
    /// Returns the independently checked actual next SDK sequence.
    pub const fn next_sequence_data(&self) -> U64 {
        self.next_sequence
    }

    /// Compares an ordinary full reference without constructing owned strings.
    ///
    /// # Errors
    /// Refuses a changed algorithm/domain/media/length or full lowercase digest.
    pub fn authenticate_reference_data(&self, reference: &ContentRef) -> Result<(), ProviderError> {
        if reference.hash.algorithm != "blake3-256"
            || reference.hash.domain != DOMAIN
            || reference.media_type != "application/json"
            || reference.length.get() != self.encoded_length
            || reference.hash.digest.len() != 64
        {
            return Err(refused());
        }
        for (hex, byte) in reference
            .hash
            .digest
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .zip(self.digest)
        {
            if hex[0] != HEX[usize::from(byte >> 4)] || hex[1] != HEX[usize::from(byte & 15)] {
                return Err(refused());
            }
        }
        Ok(())
    }

    /// Names the writer's actual fixed hash/framing/counter and borrowed views.
    pub fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<CountWriter>()
            + size_of::<HashWriter<'static>>()
            + size_of::<[u8; 256]>()
            + size_of::<[u8; 20]>()
            + size_of::<[u8; 4]>()
            + size_of::<[u8; 8]>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + size_of::<OriginalFrame<'static>>()
            + size_of::<Option<OriginalFrame<'static>>>()
            + size_of::<Result<usize, io::Error>>()
            + size_of::<Result<(), io::Error>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<[usize; 8]>()
            + size_of::<Option<usize>>()
            + size_of::<[bool; 2]>()
            + size_of::<std::slice::Iter<'static, [u8; 2]>>()
            + size_of::<std::array::IntoIter<u8, 32>>()
    }
}

/// Owns the ordinary reference of that same fixed literal-bank commitment.
pub struct OriginalRestoredInput17LiteralPrefixData {
    reference: ContentRef,
    identity: OriginalRestoredInput17LiteralPrefixIdentityData,
}

impl OriginalRestoredInput17LiteralPrefixData {
    /// Borrows the complete ordinary content identity of the private prefix.
    pub fn reference_data(&self) -> &ContentRef {
        &self.reference
    }
    /// Returns the exact complete total cut count.
    pub const fn frame_count_data(&self) -> usize {
        self.identity.frame_count_data()
    }
    /// Returns the actual supplied saved SDK frontier.
    pub const fn next_sequence_data(&self) -> U64 {
        self.identity.next_sequence
    }
    /// Returns the independently constructed fixed identity of this same prefix.
    pub const fn identity_data(&self) -> OriginalRestoredInput17LiteralPrefixIdentityData {
        self.identity
    }
    /// Counts the retained full reference's independently owned child backing.
    ///
    /// # Errors
    /// Refuses exhausted metadata traversal or checked counters.
    pub fn retained_metadata_data(
        &self,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        observer.observe(&self.reference)?;
        Ok(observer.finish())
    }
    /// Names the actual fixed identity/reference/formatter views before allocation.
    pub fn counter_scratch_data() -> usize {
        OriginalRestoredInput17LiteralPrefixIdentityData::counter_scratch_data()
            + OriginalNative5FrameHistory::original_canonical_reference_counter_scratch_data()
            + size_of::<Self>()
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<ContentRef>()
            + size_of::<HashRef>()
            + size_of::<[u8; 64]>()
    }
}

impl OriginalNative5FrameHistory<'_> {
    /// Borrows a fixed identity of the actual complete SDK-direction prefix.
    ///
    /// This allocates no reference strings, DOM, DTO or encoded bank. The Source
    /// independently checks the supplied frontier against its actual completed
    /// SDK cache and signs the corresponding assigned request under a real read.
    ///
    /// # Errors
    /// Refuses stale actors, zero/missing/partial cuts, malformed framing,
    /// unpublished slots, arithmetic overflow or the encoded-prefix ceiling.
    pub fn restored_input17_prefix_identity_data(
        &self,
        next: U64,
        maximum: usize,
    ) -> Result<OriginalRestoredInput17LiteralPrefixIdentityData, ProviderError> {
        self.actor.ensure_current()?;
        self.authority.ensure_live()?;
        let identity = identity_data(&self.original, None, next, maximum, false)?;
        self.actor.ensure_current()?;
        self.authority.ensure_live()?;
        Ok(identity)
    }

    /// Builds an ordinary reference only after its Source independently admits it.
    ///
    /// # Errors
    /// Refuses the same invalid actual cuts and bounds as the fixed identity loan.
    pub fn restored_input17_prefix_data(
        &self,
        next: U64,
        maximum: usize,
    ) -> Result<OriginalRestoredInput17LiteralPrefixData, ProviderError> {
        self.prefix_at_cut_data(None, next, maximum)
    }

    /// References an exact retained historical cut without renewing its frontier.
    ///
    /// # Errors
    /// Refuses a zero/missing/partial historical cut, stale actor or short bound.
    pub fn restored_input17_prefix_at_cut_data(
        &self,
        cut: usize,
        next: U64,
        maximum: usize,
    ) -> Result<OriginalRestoredInput17LiteralPrefixData, ProviderError> {
        if cut == 0 {
            return Err(refused());
        }
        self.prefix_at_cut_data(Some(cut), next, maximum)
    }

    fn prefix_at_cut_data(
        &self,
        cut: Option<usize>,
        next: U64,
        maximum: usize,
    ) -> Result<OriginalRestoredInput17LiteralPrefixData, ProviderError> {
        self.actor.ensure_current()?;
        self.authority.ensure_live()?;
        let identity = identity_data(&self.original, cut, next, maximum, false)?;
        let mut text = String::new();
        text.try_reserve_exact(64).map_err(|_| credit())?;
        for byte in identity.digest {
            text.push(char::from(HEX[usize::from(byte >> 4)]));
            text.push(char::from(HEX[usize::from(byte & 15)]));
        }
        let reference = ContentRef {
            hash: HashRef {
                algorithm: "blake3-256".into(),
                domain: DOMAIN.into(),
                digest: text,
            },
            length: U64::new(identity.encoded_length),
            media_type: "application/json".into(),
        };
        identity.authenticate_reference_data(&reference)?;
        self.actor.ensure_current()?;
        self.authority.ensure_live()?;
        Ok(OriginalRestoredInput17LiteralPrefixData {
            reference,
            identity,
        })
    }

    /// Verifies Controller-view literals before the actual native incoming slot.
    ///
    /// The defining private native action scope authenticates the actual bank,
    /// slot and same original before invoking this DATA check. Directions are
    /// inverted; no current or later reserved slot belongs to the commitment.
    ///
    /// # Errors
    /// Refuses a stale actor, invalid exact cut, partial/unpublished old slot,
    /// wrong complete literal/reference/frontier, overflow or a short bound.
    pub(crate) fn authenticate_native_restored_input17_prefix_at_cut_data(
        &self,
        cut: usize,
        next: U64,
        reference: &ContentRef,
        maximum: usize,
    ) -> Result<(), ProviderError> {
        self.actor.ensure_current()?;
        self.authority.ensure_live()?;
        if cut == 0 {
            return Err(refused());
        }
        identity_data(&self.original, Some(cut), next, maximum, true)?
            .authenticate_reference_data(reference)?;
        self.actor.ensure_current()?;
        self.authority.ensure_live()
    }
}

fn identity_data(
    bank: &OriginalFrameReservation,
    cut: Option<usize>,
    next: U64,
    maximum: usize,
    flip: bool,
) -> Result<OriginalRestoredInput17LiteralPrefixIdentityData, ProviderError> {
    if next.get() == 0 || maximum == 0 {
        return Err(refused());
    }
    let mut count = CountWriter { bytes: 0, maximum };
    let (incoming, outgoing) = write_prefix(bank, cut, next, flip, &mut count)?;
    let length = u64::try_from(count.bytes).map_err(|_| credit())?;
    let mut hash = blake3::Hasher::new();
    hash.update(b"CNP/1\0");
    hash.update(&(DOMAIN.len() as u32).to_be_bytes());
    hash.update(DOMAIN.as_bytes());
    hash.update(&length.to_be_bytes());
    let repeated = write_prefix(bank, cut, next, flip, &mut HashWriter(&mut hash))?;
    if repeated != (incoming, outgoing) {
        return Err(refused());
    }
    Ok(OriginalRestoredInput17LiteralPrefixIdentityData {
        digest: *hash.finalize().as_bytes(),
        encoded_length: length,
        incoming,
        outgoing,
        next_sequence: next,
    })
}

fn write_prefix(
    bank: &OriginalFrameReservation,
    cut: Option<usize>,
    next: U64,
    flip: bool,
    writer: &mut impl Write,
) -> Result<(usize, usize), ProviderError> {
    let mut incoming = 0usize;
    let mut outgoing = 0usize;
    let mut total = 0usize;
    for frame in bank.frames().take(cut.unwrap_or(usize::MAX)) {
        validate_frame(&frame)?;
        let source_incoming = matches!(frame.direction, FrameDirection::Incoming) ^ flip;
        if source_incoming {
            incoming = incoming.checked_add(1).ok_or_else(credit)?;
        } else {
            outgoing = outgoing.checked_add(1).ok_or_else(credit)?;
        }
        total = total.checked_add(1).ok_or_else(credit)?;
    }
    if total == 0 || cut.is_some_and(|cut| cut != total) {
        return Err(refused());
    }
    write(writer, b"{\"frame_count\":\"")?;
    decimal(total, writer)?;
    write(writer, b"\",\"incoming\":[")?;
    write_direction(bank, cut, flip, true, writer)?;
    write(writer, b"],\"incoming_count\":\"")?;
    decimal(incoming, writer)?;
    write(writer, b"\",\"next_sequence\":\"")?;
    write_decimal(next.get(), writer)?;
    write(writer, b"\",\"outgoing\":[")?;
    write_direction(bank, cut, flip, false, writer)?;
    write(writer, b"],\"outgoing_count\":\"")?;
    decimal(outgoing, writer)?;
    write(writer, b"\",\"schema\":\"")?;
    write(writer, SCHEMA.as_bytes())?;
    write(writer, b"\"}")?;
    Ok((incoming, outgoing))
}

fn write_direction(
    bank: &OriginalFrameReservation,
    cut: Option<usize>,
    flip: bool,
    incoming: bool,
    writer: &mut impl Write,
) -> Result<(), ProviderError> {
    let mut first = true;
    for frame in bank.frames().take(cut.unwrap_or(usize::MAX)) {
        if (matches!(frame.direction, FrameDirection::Incoming) ^ flip) != incoming {
            continue;
        }
        if !first {
            write(writer, b",")?;
        }
        first = false;
        write(writer, b"{\"complete\":true,\"framed_hex\":\"")?;
        write_hex(frame.bytes, writer)?;
        write(writer, b"\",\"transferred\":\"")?;
        decimal(frame.transferred, writer)?;
        write(writer, b"\"}")?;
    }
    Ok(())
}

fn validate_frame(frame: &OriginalFrame<'_>) -> Result<(), ProviderError> {
    let header: [u8; 4] = frame
        .bytes
        .get(..4)
        .ok_or_else(refused)?
        .try_into()
        .map_err(|_| refused())?;
    if !frame.complete
        || frame.transferred != frame.bytes.len()
        || usize::try_from(u32::from_be_bytes(header))
            .map_err(|_| credit())?
            .checked_add(4)
            != Some(frame.bytes.len())
    {
        return Err(refused());
    }
    Ok(())
}

struct CountWriter {
    bytes: usize,
    maximum: usize,
}
impl Write for CountWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|bytes| *bytes <= self.maximum)
            .ok_or_else(|| io::Error::from(io::ErrorKind::OutOfMemory))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct HashWriter<'a>(&'a mut blake3::Hasher);
impl Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn write_hex(bytes: &[u8], writer: &mut impl Write) -> Result<(), ProviderError> {
    let mut buffer = [0u8; 256];
    for chunk in bytes.chunks(buffer.len() / 2) {
        for (index, byte) in chunk.iter().copied().enumerate() {
            buffer[index * 2] = HEX[usize::from(byte >> 4)];
            buffer[index * 2 + 1] = HEX[usize::from(byte & 15)];
        }
        write(writer, &buffer[..chunk.len() * 2])?;
    }
    Ok(())
}
fn decimal(value: usize, writer: &mut impl Write) -> Result<(), ProviderError> {
    write_decimal(u64::try_from(value).map_err(|_| credit())?, writer)
}
fn write_decimal(mut value: u64, writer: &mut impl Write) -> Result<(), ProviderError> {
    let mut digits = [0u8; 20];
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + u8::try_from(value % 10).map_err(|_| credit())?;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    write(writer, &digits[start..])
}
fn write(writer: &mut impl Write, bytes: &[u8]) -> Result<(), ProviderError> {
    writer.write_all(bytes).map_err(|_| credit())
}
fn refused() -> ProviderError {
    ProviderError::Correlation("directional signed17 literal prefix")
}
fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("directional signed17 literal prefix")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_contract::canonical;

    // Actual reservation/canonical-envelope DATA only. No actor, native child,
    // Source read, action claim or successful simulated operation is fabricated.
    fn wire(method: Method, sequence: u64, response: bool, role: &str) -> Vec<u8> {
        let mut envelope = crate::envelope::tests::request();
        envelope.method = method;
        envelope.sequence = U64::new(sequence);
        envelope.message = if response {
            MessageKind::Response
        } else {
            MessageKind::Request
        };
        envelope.body = serde_json::json!({"literal_test_role":role})
            .as_object()
            .unwrap()
            .clone();
        canonical::canonical_json(&serde_json::to_value(envelope).unwrap()).unwrap()
    }

    fn append(
        bank: &mut OriginalFrameReservation,
        direction: FrameDirection,
        body: &[u8],
        sent: bool,
    ) -> usize {
        let slot = bank.begin(direction, body.len() + 4).unwrap();
        bank.append(slot, &u32::try_from(body.len()).unwrap().to_be_bytes())
            .unwrap();
        bank.append(slot, body).unwrap();
        if direction == FrameDirection::Incoming || sent {
            finish(bank, slot);
        }
        slot
    }

    fn finish(bank: &mut OriginalFrameReservation, slot: usize) {
        let frame = bank.frame(slot).unwrap();
        if frame.direction == FrameDirection::Outgoing {
            bank.advance(slot, frame.bytes.len()).unwrap();
        }
        bank.finish(slot).unwrap();
    }

    fn banks() -> (OriginalFrameReservation, OriginalFrameReservation) {
        let original = wire(Method::Observe, 3, false, "observe");
        let provider = [
            wire(Method::Observe, 3, true, "terminal"),
            wire(Method::BlobBegin, 4, false, "begin"),
            wire(Method::BlobChunk, 5, false, "chunk"),
            wire(Method::BlobFinish, 6, false, "finish"),
        ];
        let acknowledgements = [
            wire(Method::BlobBegin, 4, true, "begin-ack"),
            wire(Method::BlobChunk, 5, true, "chunk-ack"),
            wire(Method::BlobFinish, 6, true, "finish-ack"),
        ];
        let mut host = OriginalFrameReservation::reserve(65536, 16).unwrap();
        let mut native = OriginalFrameReservation::reserve(65536, 16).unwrap();
        append(&mut host, FrameDirection::Outgoing, &original, true);
        append(&mut native, FrameDirection::Incoming, &original, true);

        // The defining native preparation reserves the complete outgoing plan
        // before its first send. ACKs are subsequently appended as IO completes.
        let slots = provider
            .iter()
            .map(|body| append(&mut native, FrameDirection::Outgoing, body, false))
            .collect::<Vec<_>>();
        finish(&mut native, slots[0]);
        append(&mut host, FrameDirection::Incoming, &provider[0], true);
        for index in 0..3 {
            finish(&mut native, slots[index + 1]);
            append(
                &mut host,
                FrameDirection::Incoming,
                &provider[index + 1],
                true,
            );
            append(
                &mut host,
                FrameDirection::Outgoing,
                &acknowledgements[index],
                true,
            );
            append(
                &mut native,
                FrameDirection::Incoming,
                &acknowledgements[index],
                true,
            );
        }
        (host, native)
    }

    fn reference(identity: OriginalRestoredInput17LiteralPrefixIdentityData) -> ContentRef {
        let digest = identity
            .digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        ContentRef {
            hash: HashRef {
                algorithm: "blake3-256".into(),
                domain: DOMAIN.into(),
                digest,
            },
            length: U64::new(identity.encoded_length),
            media_type: "application/json".into(),
        }
    }

    #[test]
    fn actual_reserved_native_plan_and_interleaved_sdk_acks_have_one_directional_commitment() {
        let (host, mut native) = banks();
        let sdk = identity_data(&host, None, U64::new(7), usize::MAX, false).unwrap();
        let native_cut = native.frames().count();
        let current = wire(Method::Observe, 7, false, "next-signed17-original");
        append(&mut native, FrameDirection::Incoming, &current, true);
        let paired =
            identity_data(&native, Some(native_cut), U64::new(7), usize::MAX, true).unwrap();
        assert_eq!(paired, sdk);
        assert_eq!(sdk.frame_count_data(), 8);
        assert_eq!(
            (sdk.incoming_count_data(), sdk.outgoing_count_data()),
            (4, 4)
        );
        paired.authenticate_reference_data(&reference(sdk)).unwrap();
        assert_ne!(
            identity_data(&native, None, U64::new(7), usize::MAX, true).unwrap(),
            sdk
        );
        assert_ne!(
            identity_data(&native, Some(native_cut), U64::new(7), usize::MAX, false).unwrap(),
            sdk
        );
        assert_ne!(
            identity_data(&native, Some(native_cut - 1), U64::new(7), usize::MAX, true).unwrap(),
            sdk
        );
        assert_ne!(
            identity_data(&native, Some(native_cut), U64::new(8), usize::MAX, true).unwrap(),
            sdk
        );
    }

    #[test]
    fn reserved_or_unpublished_claimed_slots_and_duplicate_or_missing_literals_cannot_match() {
        let (host, mut native) = banks();
        let sdk = identity_data(&host, None, U64::new(7), usize::MAX, false).unwrap();
        let old_cut = native.frames().count();
        let duplicate = wire(Method::BlobFinish, 6, true, "finish-ack");
        append(&mut native, FrameDirection::Incoming, &duplicate, true);
        assert_ne!(
            identity_data(&native, None, U64::new(7), usize::MAX, true).unwrap(),
            sdk
        );
        assert_eq!(
            identity_data(&native, Some(old_cut), U64::new(7), usize::MAX, true).unwrap(),
            sdk
        );
        let unsent = wire(Method::BlobBegin, 8, false, "reserved-unsent");
        append(&mut native, FrameDirection::Outgoing, &unsent, false);
        assert!(identity_data(&native, None, U64::new(9), usize::MAX, true).is_err());
        assert!(identity_data(&native, Some(old_cut + 2), U64::new(9), usize::MAX, true).is_err());
        assert!(identity_data(&host, Some(99), U64::new(7), usize::MAX, false).is_err());
        assert!(identity_data(&host, Some(0), U64::new(7), usize::MAX, false).is_err());
    }

    #[test]
    fn actual_directional_body_matches_canonical_content_hash_and_exact_encoded_boundary() {
        let (host, _) = banks();
        let mut bytes = Vec::new();
        write_prefix(&host, None, U64::new(7), false, &mut bytes).unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(bytes, canonical::canonical_json(&value).unwrap());
        assert_eq!(value["schema"], SCHEMA);
        assert_eq!(value["incoming"].as_array().unwrap().len(), 4);
        assert_eq!(value["outgoing"].as_array().unwrap().len(), 4);
        let identity = identity_data(&host, None, U64::new(7), bytes.len(), false).unwrap();
        identity
            .authenticate_reference_data(
                &canonical::content_ref(&bytes, "application/json").unwrap(),
            )
            .unwrap();
        assert!(identity_data(&host, None, U64::new(7), bytes.len() - 1, false).is_err());
        let mut changed = reference(identity);
        changed.length = U64::new(changed.length.get() + 1);
        assert!(identity.authenticate_reference_data(&changed).is_err());
    }
}

// This is a distinct incoming-request cut. The ordinary history lender keeps
// its HostSettled predicate, which correctly refuses any outstanding request.
impl<S: ProviderStream> Connection<S> {
    /// Verifies a pre-original commitment under this exact incoming Observe17.
    ///
    /// This borrowed transport check issues no Source/native action permission.
    /// The defining scope separately authenticates the real Boot/index/Rc, MAC,
    /// newest owning checkpoint and its complete independent prospective row.
    ///
    /// # Errors
    /// Refuses changed actor/admission, another incoming request, partial bank,
    /// wrong literal slot/frontier, changed full commitment or a short bound.
    pub(crate) fn authenticate_native_observation17_literal_prefix_data(
        &self,
        original: &Envelope,
        slot: usize,
        next: U64,
        reference: &ContentRef,
        maximum: usize,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        self.guard
            .authenticate_incoming_observation17_cut_data(original)?;
        self.authenticate_original_restored_suffix_observation_literal_data(original, slot)?;
        if original.sequence != next || slot == 0 || self.fenced {
            return Err(refused());
        }
        let bank = self
            .original_frames
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| refused())?;
        if !bank.complete() {
            return Err(refused());
        }
        identity_data(&bank, Some(slot), next, maximum, true)?
            .authenticate_reference_data(reference)?;
        self.guard
            .authenticate_incoming_observation17_cut_data(original)?;
        self.protocol_owner.ensure_current()?;
        self.authority.ensure_live()
    }
}
