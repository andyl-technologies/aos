//! Bounded decoded literal history data, without source or adoption permission.
//!
//! The source-private frame format is an eight-element JSON tuple containing
//! limits, lifetime counts, exact capacities, raw bytes and slot descriptions.
//! Its decoder charges both complete banks before allocating either one. The
//! result cannot be installed on a connection or used as a capture issuer.
//!
//! For example, a complete outgoing frame with no request ID is encoded as:
//!
//! ```json
//! [64,1,0,1,64,2,[0,0,0,2,123,125],[["outgoing",0,6,6,true,null]]]
//! ```

use super::*;

/// Retains decoded frame-bank data without authenticating an original issuer.
///
/// Raw bytes, capacities, lifetime slots and request IDs remain exact. A source
/// factory must separately authenticate the signed captured body, actual source
/// and target actors, codec and complete settlement before any installation.
pub struct DecodedOriginalFrameData {
    bank: OriginalFrameReservation,
}

impl DecodedOriginalFrameData {
    /// Decodes one complete bounded source-private frame tuple into data banks.
    ///
    /// Allocation admission precedes all byte/slot copies. No envelope is
    /// replayed, no lifetime credit is refunded and no native permission is
    /// created. The input remains borrowed and unchanged on every refusal.
    ///
    /// # Errors
    /// Refuses oversized input, insufficient complete allocation allowance,
    /// invalid capacities/slots/counts, truncated or trailing data, incomplete
    /// frame I/O, or allocation refusal. This does not verify a signed source.
    pub fn decode(bytes: &[u8], maximum_allocation: usize) -> Result<Self, ProviderError> {
        if bytes.len() > MAX_ORIGINAL_FRAME_BYTES || maximum_allocation == 0 {
            return Err(ProviderError::ResourceExhausted(
                "decoded original frame credit",
            ));
        }
        let bank = FrameCursor::new(bytes).bank(maximum_allocation)?;
        Ok(Self { bank })
    }

    /// Reports complete actual byte and descriptor allocation of these data banks.
    pub fn allocated_bytes(&self) -> usize {
        self.bank.allocated_bytes()
    }

    /// Borrows decoded literal slots without making their bytes authoritative.
    pub fn frames(&self) -> impl Iterator<Item = OriginalFrame<'_>> {
        self.bank.frames()
    }

    /// Copies decoded data into an empty bank with identical precharged capacities.
    ///
    /// This creates historical data only. Connection installers require an
    /// unused source-owned bank and will refuse this populated data bank. The
    /// complete source/restoration gate is a separate mandatory conjunction.
    ///
    /// # Errors
    /// Refuses a used bank or any differing limit/allocation before copying.
    pub fn copy_to_reserved_data_bank(
        &self,
        target: &mut OriginalFrameReservation,
    ) -> Result<(), ProviderError> {
        self.bank.copy_into_empty(target)
    }
}

// This cursor recognizes only this private tuple's grammar. It never delegates
// malformed tokens to serde's scratch-allocating string or ignored-value parser.
struct FrameCursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> FrameCursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn invalid() -> ProviderError {
        ProviderError::Frame("invalid bounded original frame data")
    }

    fn whitespace(&mut self) {
        while self
            .input
            .get(self.position)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            self.position += 1;
        }
    }

    fn take(&mut self, byte: u8) -> bool {
        self.whitespace();
        if self.input.get(self.position) == Some(&byte) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn require(&mut self, byte: u8) -> Result<(), ProviderError> {
        if self.take(byte) {
            Ok(())
        } else {
            Err(Self::invalid())
        }
    }

    fn literal(&mut self, literal: &[u8]) -> bool {
        self.whitespace();
        if self.input[self.position..].starts_with(literal) {
            self.position += literal.len();
            true
        } else {
            false
        }
    }

    fn number(&mut self) -> Result<usize, ProviderError> {
        self.whitespace();
        let first = *self.input.get(self.position).ok_or_else(Self::invalid)?;
        if !first.is_ascii_digit() {
            return Err(Self::invalid());
        }
        self.position += 1;
        let mut number = usize::from(first - b'0');
        while let Some(byte) = self
            .input
            .get(self.position)
            .filter(|byte| byte.is_ascii_digit())
        {
            if first == b'0' {
                return Err(Self::invalid());
            }
            number = number
                .checked_mul(10)
                .and_then(|number| number.checked_add(usize::from(*byte - b'0')))
                .ok_or_else(Self::invalid)?;
            self.position += 1;
        }
        Ok(number)
    }

    fn field_number(&mut self) -> Result<usize, ProviderError> {
        self.require(b',')?;
        self.number()
    }

    fn byte(&mut self) -> Result<u8, ProviderError> {
        u8::try_from(self.number()?).map_err(|_| Self::invalid())
    }

    fn request(&mut self) -> Result<Option<([u8; 128], usize)>, ProviderError> {
        if self.literal(b"null") {
            return Ok(None);
        }
        self.require(b'[')?;
        let mut bytes = [0; 128];
        let mut length = 0;
        if self.take(b']') {
            return Err(Self::invalid());
        }
        loop {
            if length == bytes.len() {
                return Err(Self::invalid());
            }
            bytes[length] = self.byte()?;
            length += 1;
            if self.take(b']') {
                break;
            }
            self.require(b',')?;
        }
        std::str::from_utf8(&bytes[..length]).map_err(|_| Self::invalid())?;
        Ok(Some((bytes, length)))
    }

    fn bank(
        &mut self,
        maximum_allocation: usize,
    ) -> Result<OriginalFrameReservation, ProviderError> {
        self.require(b'[')?;
        let maximum_bytes = self.number()?;
        let maximum_frames = self.field_number()?;
        let incoming = self.field_number()?;
        let outgoing = self.field_number()?;
        let byte_capacity = self.field_number()?;
        let slot_capacity = self.field_number()?;
        let charge = slot_capacity
            .checked_mul(std::mem::size_of::<Slot>())
            .and_then(|descriptors| descriptors.checked_add(byte_capacity))
            .ok_or_else(Self::invalid)?;
        if !(4..=MAX_ORIGINAL_FRAME_BYTES).contains(&maximum_bytes)
            || !(1..=MAX_ORIGINAL_FRAMES_PER_DIRECTION).contains(&maximum_frames)
            || incoming > maximum_frames
            || outgoing > maximum_frames
            || byte_capacity < maximum_bytes
            || byte_capacity > MAX_ORIGINAL_FRAME_BYTES
            || slot_capacity < maximum_frames * 2
            || slot_capacity > MAX_ORIGINAL_FRAMES_PER_DIRECTION * 2
            || charge > maximum_allocation
        {
            return Err(ProviderError::ResourceExhausted(
                "original frame allocation credit",
            ));
        }

        // Only these two explicitly admitted banks allocate. All parsing state,
        // including a request ID, is fixed stack storage independent of input.
        let mut bytes = Vec::new();
        let mut slots = Vec::new();
        bytes
            .try_reserve_exact(byte_capacity)
            .map_err(|_| ProviderError::ResourceExhausted("original frame byte allocation"))?;
        slots.try_reserve_exact(slot_capacity).map_err(|_| {
            ProviderError::ResourceExhausted("original frame descriptor allocation")
        })?;
        if bytes.capacity() != byte_capacity || slots.capacity() != slot_capacity {
            return Err(Self::invalid());
        }
        self.require(b',')?;
        self.require(b'[')?;
        if !self.take(b']') {
            loop {
                if bytes.len() == maximum_bytes {
                    return Err(Self::invalid());
                }
                bytes.push(self.byte()?);
                if self.take(b']') {
                    break;
                }
                self.require(b',')?;
            }
        }

        self.require(b',')?;
        self.require(b'[')?;
        let mut actual_incoming = 0;
        let mut actual_outgoing = 0;
        let mut end = 0;
        if !self.take(b']') {
            loop {
                if slots.len() == slot_capacity {
                    return Err(Self::invalid());
                }
                self.require(b'[')?;
                let direction = if self.literal(b"\"incoming\"") {
                    actual_incoming += 1;
                    FrameDirection::Incoming
                } else if self.literal(b"\"outgoing\"") {
                    actual_outgoing += 1;
                    FrameDirection::Outgoing
                } else {
                    return Err(Self::invalid());
                };
                let start = self.field_number()?;
                let length = self.field_number()?;
                let transferred = self.field_number()?;
                self.require(b',')?;
                if !self.literal(b"true") {
                    return Err(Self::invalid());
                }
                self.require(b',')?;
                let request = self.request()?;
                self.require(b']')?;

                let next = start
                    .checked_add(length)
                    .filter(|next| *next <= bytes.len())
                    .ok_or_else(Self::invalid)?;
                if start != end
                    || length < 5
                    || transferred != length
                    || actual_incoming > maximum_frames
                    || actual_outgoing > maximum_frames
                {
                    return Err(Self::invalid());
                }
                let header: [u8; 4] = bytes[start..start + 4]
                    .try_into()
                    .map_err(|_| Self::invalid())?;
                if u32::from_be_bytes(header) as usize != length - 4 {
                    return Err(Self::invalid());
                }
                slots.push(Slot {
                    direction,
                    start,
                    length,
                    transferred,
                    complete: true,
                    request,
                });
                end = next;
                if self.take(b']') {
                    break;
                }
                self.require(b',')?;
            }
        }
        self.require(b']')?;
        self.whitespace();
        if self.position != self.input.len()
            || end != bytes.len()
            || actual_incoming != incoming
            || actual_outgoing != outgoing
        {
            return Err(Self::invalid());
        }
        Ok(OriginalFrameReservation {
            bytes,
            slots,
            maximum_bytes,
            maximum_frames,
            incoming,
            outgoing,
        })
    }
}

#[cfg(test)]
// Byte-bank fixtures deliberately panic on lost capacities, counters or originals.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn original() -> OriginalFrameReservation {
        let mut bank = OriginalFrameReservation::reserve(4096, 8).unwrap();
        let bytes = b"\0\0\0\x02{}";
        bank.bytes.extend_from_slice(bytes);
        bank.slots.push(Slot {
            direction: FrameDirection::Outgoing,
            start: 0,
            length: bytes.len(),
            transferred: bytes.len(),
            complete: true,
            request: Some((
                {
                    let mut id = [0; 128];
                    id[..8].copy_from_slice(b"original");
                    id
                },
                8,
            )),
        });
        bank.outgoing = 1;
        bank
    }

    #[test]
    fn native5_decoded_frames_preserve_exact_capacities_ids_and_nonrenewing_counts() {
        let original = original();
        let bytes = serde_json::to_vec(&original.protocol_view()).unwrap();
        let data = DecodedOriginalFrameData::decode(&bytes, original.allocated_bytes()).unwrap();
        assert_eq!(data.allocated_bytes(), original.allocated_bytes());
        assert_eq!(
            serde_json::to_vec(&data.bank.protocol_view()).unwrap(),
            bytes
        );
        let mut target = OriginalFrameReservation::reserve(4096, 8).unwrap();
        data.copy_to_reserved_data_bank(&mut target).unwrap();
        assert_eq!(serde_json::to_vec(&target.protocol_view()).unwrap(), bytes);
        assert!(data.copy_to_reserved_data_bank(&mut target).is_err());
        assert_eq!(serde_json::to_vec(&target.protocol_view()).unwrap(), bytes);
        assert_eq!(data.frames().next().unwrap().bytes, b"\0\0\0\x02{}");
    }

    #[test]
    fn native5_decoded_frames_refuse_complete_credit_before_reading_byte_array() {
        let original = original();
        let bytes = serde_json::to_vec(&original.protocol_view()).unwrap();
        assert!(DecodedOriginalFrameData::decode(&bytes, original.allocated_bytes() - 1).is_err());
        let mut changed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        changed[4] = serde_json::json!(usize::MAX);
        assert!(
            DecodedOriginalFrameData::decode(&serde_json::to_vec(&changed).unwrap(), usize::MAX)
                .is_err()
        );
        assert_eq!(
            serde_json::to_vec(&original.protocol_view()).unwrap(),
            bytes
        );
    }

    #[test]
    fn native5_decoded_frames_refuse_changed_counts_headers_partial_io_and_slot_extents() {
        let original = original();
        let bytes = serde_json::to_vec(&original.protocol_view()).unwrap();
        for change in 0..5 {
            let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            match change {
                0 => value[3] = serde_json::json!(2),
                1 => value[6][3] = serde_json::json!(3),
                2 => value[7][0][3] = serde_json::json!(5),
                3 => value[7][0][1] = serde_json::json!(1),
                _ => value[7][0][5] = serde_json::json!(vec![b'x'; 129]),
            }
            assert!(
                DecodedOriginalFrameData::decode(
                    &serde_json::to_vec(&value).unwrap(),
                    original.allocated_bytes()
                )
                .is_err()
            );
        }
        assert_eq!(
            serde_json::to_vec(&original.protocol_view()).unwrap(),
            bytes
        );
    }

    #[test]
    fn native5_decoded_frames_malformed_tokens_have_no_dynamic_parser_scratch() {
        let original = original();
        let encoded = serde_json::to_vec(&original.protocol_view()).unwrap();
        let allowance = original.allocated_bytes();
        let large_escaped = "\\u0061".repeat(16 * 1024);
        let malformed_number = format!("[\"{large_escaped}\",8,0,1,4096,16,[],[]]");
        assert!(DecodedOriginalFrameData::decode(malformed_number.as_bytes(), allowance).is_err());

        let text = std::str::from_utf8(&encoded).unwrap();
        let escaped_direction = text.replace("\"outgoing\"", &format!("\"{large_escaped}\""));
        assert!(DecodedOriginalFrameData::decode(escaped_direction.as_bytes(), allowance).is_err());
        let malformed_byte = text.replace("[0,0,0,2,123,125]", &format!("[\"{large_escaped}\"]"));
        assert_ne!(malformed_byte, text);
        assert!(DecodedOriginalFrameData::decode(malformed_byte.as_bytes(), allowance).is_err());
        let extra = format!(
            "{},{{\"tail\":[{}]}}]",
            &text[..text.len() - 1],
            "[".repeat(4096)
        );
        assert!(DecodedOriginalFrameData::decode(extra.as_bytes(), allowance).is_err());
        assert_eq!(
            serde_json::to_vec(&original.protocol_view()).unwrap(),
            encoded
        );
    }

    #[test]
    fn native5_decoded_frames_accept_whitespace_and_refuse_noninteger_and_extra_tokens() {
        let original = original();
        let encoded = serde_json::to_vec(&original.protocol_view()).unwrap();
        let allowance = original.allocated_bytes();
        let text = std::str::from_utf8(&encoded).unwrap();
        let spaced = format!(" \n{}\t", text.replace(',', ", \n"));
        let data = DecodedOriginalFrameData::decode(spaced.as_bytes(), allowance).unwrap();
        assert_eq!(
            serde_json::to_vec(&data.bank.protocol_view()).unwrap(),
            encoded
        );
        for first in [
            "-1",
            "01",
            "1e3",
            "1.0",
            "184467440737095516160",
            "null",
            "[]",
        ] {
            let changed = text.replacen("4096", first, 1);
            assert!(DecodedOriginalFrameData::decode(changed.as_bytes(), allowance).is_err());
        }
        for suffix in ["{}", "[[]]", "\"\\u0061\"", "true"] {
            let changed = format!("{text}{suffix}");
            assert!(DecodedOriginalFrameData::decode(changed.as_bytes(), allowance).is_err());
        }
    }
}
