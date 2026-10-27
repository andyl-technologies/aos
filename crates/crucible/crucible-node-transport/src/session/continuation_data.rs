//! Settled correlation reconstruction as data, without connection permission.
//!
//! The tagged source-private version-six tuple retains scope, both sequence
//! counters, credit, all three empty correlation maps, extensions, failure and
//! previous-install state. Pending Capture is refused here: its exact owning
//! source settlement must supply a distinct verified transition.
//!
//! A settled, unused guard with no extensions has this source-private form:
//!
//! ```json
//! ["source-private.correlations/6","session-old","incarnation-old","2","2",8,{},{},{},[],false,false]
//! ```

use super::*;

const MAXIMUM_ENCODED_DATA: usize = 16 * 1024;
const COMPLETE_METADATA_CREDIT: usize = 64 * 1024;

/// Owns decoded settled correlation data without an authenticated source issuer.
///
/// The bounded logical data omits arbitrary callbacks and confers no connection,
/// source, Capture, native settlement or Ready authority. A real connection's
/// private guard cannot be obtained or replaced through this data interface.
pub struct DecodedSettledCorrelationData {
    session: Id,
    incarnation: Id,
    next_received: u64,
    next_sent: u64,
    maximum_requests: usize,
    extensions: Vec<String>,
    continuation_installed: bool,
}

impl DecodedSettledCorrelationData {
    /// Decodes settled scalar correlation state under finite metadata credit.
    ///
    /// A fixed 64-KiB allowance admits two IDs, at most 64 extension strings of
    /// at most 128 bytes, and their exact precharged vector/string capacities.
    /// A borrowed fixed-state cursor validates all grammar before owning copies;
    /// no parser scratch or BTree nodes are allocated.
    /// This is a conservative data-decoder allowance, not exact captured nested
    /// allocator geometry. Admission precedes owning copies.
    ///
    /// # Errors
    /// Refuses low credit, oversized/unsupported data, failed or pending state,
    /// invalid counters/credit, excess extensions, or trailing data.
    pub fn decode(bytes: &[u8], maximum_metadata: usize) -> Result<Self, ProviderError> {
        if bytes.len() > MAXIMUM_ENCODED_DATA || maximum_metadata < COMPLETE_METADATA_CREDIT {
            return Err(ProviderError::ResourceExhausted(
                "settled correlation data credit",
            ));
        }
        let mut cursor = DataCursor::new(bytes);
        let borrowed = cursor.data()?;
        let charge = std::mem::size_of::<Self>()
            .checked_add(borrowed.session.len() + borrowed.incarnation.len())
            .and_then(|n| n.checked_add(borrowed.extension_bytes))
            .and_then(|n| n.checked_add(borrowed.extension_count * std::mem::size_of::<String>()))
            .ok_or(ProviderError::ResourceExhausted("settled metadata extent"))?;
        if charge > maximum_metadata {
            return Err(ProviderError::ResourceExhausted("settled metadata extent"));
        }

        // The complete borrowed grammar and capacity charge pass before any
        // owning string or vector is constructed. No serde scratch/tree exists.
        let mut extensions = Vec::new();
        extensions
            .try_reserve_exact(borrowed.extension_count)
            .map_err(|_| ProviderError::ResourceExhausted("settled extension allocation"))?;
        if extensions.capacity() != borrowed.extension_count {
            return Err(ProviderError::ResourceExhausted(
                "settled extension capacity",
            ));
        }
        let mut entries = DataCursor::new(borrowed.extensions);
        entries.require(b'[')?;
        if !entries.take(b']') {
            loop {
                extensions.push(owned_string(entries.string()?)?);
                if entries.take(b']') {
                    break;
                }
                entries.require(b',')?;
            }
        }
        Ok(Self {
            session: Id::new(owned_string(borrowed.session)?)?,
            incarnation: Id::new(owned_string(borrowed.incarnation)?)?,
            next_received: borrowed.next_received,
            next_sent: borrowed.next_sent,
            maximum_requests: borrowed.maximum_requests,
            extensions,
            continuation_installed: borrowed.continuation_installed,
        })
    }

    /// Applies exact counters and credit to an unused plain data guard once.
    ///
    /// The target retains its new scope IDs. The caller separately retains the
    /// old raw envelopes/frame history; this method never rewrites or replays
    /// them. It acts only on a public standalone correlation guard, not a real
    /// connection's private guard. Full source-gated SDK installation is closed.
    ///
    /// # Errors
    /// Refuses used targets, unchanged scope, differing credit or extensions.
    /// Every refusal leaves both source data and target guard unchanged.
    pub fn apply_to_fresh_data_guard(
        &self,
        target: &mut CorrelationGuard,
    ) -> Result<(), ProviderError> {
        if !target.unused()
            || target.session == self.session
            || target.incarnation == self.incarnation
            || target.maximum_requests != self.maximum_requests
            || !target.extensions.iter().eq(self.extensions.iter())
        {
            return Err(ProviderError::Correlation(
                "settled continuation target differs or used",
            ));
        }
        target.next_received = self.next_received;
        target.next_sent = self.next_sent;
        // Even an empty source with both counters at two consumes this one-shot
        // data installation; a second application cannot refund or reset credit.
        target.continuation_installed = true;
        Ok(())
    }

    /// Reports the original saved installation flag without issuing a permit.
    pub fn original_continuation_installed(&self) -> bool {
        self.continuation_installed
    }
}

fn owned_string(value: &str) -> Result<String, ProviderError> {
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| ProviderError::ResourceExhausted("settled string allocation"))?;
    if owned.capacity() != value.len() {
        return Err(ProviderError::ResourceExhausted("settled string capacity"));
    }
    owned.push_str(value);
    Ok(owned)
}

struct BorrowedData<'a> {
    session: &'a str,
    incarnation: &'a str,
    next_received: u64,
    next_sent: u64,
    maximum_requests: usize,
    extensions: &'a [u8],
    extension_count: usize,
    extension_bytes: usize,
    continuation_installed: bool,
}

struct DataCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DataCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn invalid() -> ProviderError {
        ProviderError::Correlation("invalid bounded settled correlation data")
    }

    fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.offset)
            .is_some_and(|b| matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.offset += 1;
        }
    }

    fn take(&mut self, byte: u8) -> bool {
        self.whitespace();
        if self.bytes.get(self.offset) == Some(&byte) {
            self.offset += 1;
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

    fn literal(&mut self, value: &[u8]) -> bool {
        self.whitespace();
        if self.bytes[self.offset..].starts_with(value) {
            self.offset += value.len();
            true
        } else {
            false
        }
    }

    fn boolean(&mut self) -> Result<bool, ProviderError> {
        if self.literal(b"true") {
            Ok(true)
        } else if self.literal(b"false") {
            Ok(false)
        } else {
            Err(Self::invalid())
        }
    }

    fn string(&mut self) -> Result<&'a str, ProviderError> {
        self.require(b'"')?;
        let start = self.offset;
        while let Some(&byte) = self.bytes.get(self.offset) {
            if byte == b'"' {
                let value = std::str::from_utf8(&self.bytes[start..self.offset])
                    .map_err(|_| Self::invalid())?;
                self.offset += 1;
                return Ok(value);
            }
            // Selected IDs/features serialize without escapes. Unsupported
            // escaped spellings are refused as data, never decoded into scratch.
            if byte == b'\\' || byte < 0x20 || self.offset - start == 128 {
                return Err(Self::invalid());
            }
            self.offset += 1;
        }
        Err(Self::invalid())
    }

    fn number(&mut self) -> Result<u64, ProviderError> {
        self.whitespace();
        let first = *self.bytes.get(self.offset).ok_or_else(Self::invalid)?;
        if !first.is_ascii_digit() {
            return Err(Self::invalid());
        }
        self.offset += 1;
        let mut result = u64::from(first - b'0');
        while let Some(&byte) = self.bytes.get(self.offset).filter(|b| b.is_ascii_digit()) {
            if first == b'0' {
                return Err(Self::invalid());
            }
            result = result
                .checked_mul(10)
                .and_then(|n| n.checked_add(u64::from(byte - b'0')))
                .ok_or_else(Self::invalid)?;
            self.offset += 1;
        }
        Ok(result)
    }

    fn identifier(&mut self) -> Result<&'a str, ProviderError> {
        let value = self.string()?;
        let mut bytes = value.bytes();
        if !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
            || !bytes.all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
        {
            return Err(Self::invalid());
        }
        Ok(value)
    }

    fn counter(&mut self) -> Result<u64, ProviderError> {
        self.require(b',')?;
        let token = self.string()?;
        if token.is_empty() || token.starts_with('0') || !token.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Self::invalid());
        }
        let value = token.parse::<u64>().map_err(|_| Self::invalid())?;
        if value < 2 {
            return Err(Self::invalid());
        }
        Ok(value)
    }

    fn data(&mut self) -> Result<BorrowedData<'a>, ProviderError> {
        self.require(b'[')?;
        if self.string()? != "source-private.correlations/6" {
            return Err(Self::invalid());
        }
        self.require(b',')?;
        let session = self.identifier()?;
        self.require(b',')?;
        let incarnation = self.identifier()?;
        let next_received = self.counter()?;
        let next_sent = self.counter()?;
        self.require(b',')?;
        let maximum_requests = usize::try_from(self.number()?).map_err(|_| Self::invalid())?;
        if !(1..=MAX_OUTSTANDING_REQUESTS).contains(&maximum_requests) {
            return Err(Self::invalid());
        }
        for _ in 0..3 {
            self.require(b',')?;
            self.require(b'{')?;
            self.require(b'}')?;
        }
        self.require(b',')?;
        self.whitespace();
        let start = self.offset;
        self.require(b'[')?;
        let mut extension_count = 0;
        let mut extension_bytes = 0;
        let mut previous = None;
        if !self.take(b']') {
            loop {
                let value = self.string()?;
                if value.is_empty() || extension_count == 64 || previous.is_some_and(|p| p >= value)
                {
                    return Err(Self::invalid());
                }
                extension_count += 1;
                extension_bytes += value.len();
                previous = Some(value);
                if self.take(b']') {
                    break;
                }
                self.require(b',')?;
            }
        }
        let extensions = &self.bytes[start..self.offset];
        self.require(b',')?;
        if self.boolean()? {
            return Err(Self::invalid());
        }
        self.require(b',')?;
        let continuation_installed = self.boolean()?;
        self.require(b']')?;
        self.whitespace();
        if self.offset != self.bytes.len() {
            return Err(Self::invalid());
        }
        Ok(BorrowedData {
            session,
            incarnation,
            next_received,
            next_sent,
            maximum_requests,
            extensions,
            extension_count,
            extension_bytes,
            continuation_installed,
        })
    }
}

#[cfg(test)]
// Plain guard fixtures deliberately panic on missing one-shot/counter invariants.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn guard(scope: &str) -> CorrelationGuard {
        CorrelationGuard::new(
            Id::new(format!("session-{scope}")).unwrap(),
            Id::new(format!("incarnation-{scope}")).unwrap(),
            8,
            BTreeSet::new(),
        )
        .unwrap()
    }

    #[test]
    fn native5_settled_correlation_data_preserves_sequences_credit_and_fresh_scope_once() {
        let mut original = guard("old");
        original.next_received = 19;
        original.next_sent = 23;
        let bytes = serde_json::to_vec(&original.protocol_view()).unwrap();
        let data = DecodedSettledCorrelationData::decode(&bytes, COMPLETE_METADATA_CREDIT).unwrap();
        let mut target = guard("fresh");
        data.apply_to_fresh_data_guard(&mut target).unwrap();
        assert_eq!(target.next_received, 19);
        assert_eq!(target.next_sent, 23);
        assert_eq!(target.maximum_requests, 8);
        assert_eq!(target.session.as_str(), "session-fresh");
        assert_eq!(target.incarnation.as_str(), "incarnation-fresh");
        let before = serde_json::to_vec(&target.protocol_view()).unwrap();
        assert!(data.apply_to_fresh_data_guard(&mut target).is_err());
        assert_eq!(serde_json::to_vec(&target.protocol_view()).unwrap(), before);
        assert_eq!(
            serde_json::to_vec(&original.protocol_view()).unwrap(),
            bytes
        );
    }

    #[test]
    fn native5_settled_empty_correlation_data_install_still_consumes_once() {
        let original = guard("old");
        let data = DecodedSettledCorrelationData::decode(
            &serde_json::to_vec(&original.protocol_view()).unwrap(),
            COMPLETE_METADATA_CREDIT,
        )
        .unwrap();
        let mut target = guard("fresh");
        data.apply_to_fresh_data_guard(&mut target).unwrap();
        assert!(!target.unused());
        assert!(data.apply_to_fresh_data_guard(&mut target).is_err());
        let next = DecodedSettledCorrelationData::decode(
            &serde_json::to_vec(&target.protocol_view()).unwrap(),
            COMPLETE_METADATA_CREDIT,
        )
        .unwrap();
        assert!(next.original_continuation_installed());
    }

    #[test]
    fn native5_settled_correlation_pending_or_failed_data_and_replacement_refuse() {
        let original = guard("old");
        let mut body = serde_json::to_value(original.protocol_view()).unwrap();
        body[7] = serde_json::json!({"capture":{"large":"not copied"}});
        assert!(
            DecodedSettledCorrelationData::decode(
                &serde_json::to_vec(&body).unwrap(),
                COMPLETE_METADATA_CREDIT
            )
            .is_err()
        );
        let bytes = serde_json::to_vec(&original.protocol_view()).unwrap();
        assert!(
            DecodedSettledCorrelationData::decode(&bytes, COMPLETE_METADATA_CREDIT - 1).is_err()
        );
        let data = DecodedSettledCorrelationData::decode(&bytes, COMPLETE_METADATA_CREDIT).unwrap();
        let mut same = guard("old");
        let before = serde_json::to_vec(&same.protocol_view()).unwrap();
        assert!(data.apply_to_fresh_data_guard(&mut same).is_err());
        assert_eq!(serde_json::to_vec(&same.protocol_view()).unwrap(), before);
        let mut wrong = guard("fresh");
        wrong.maximum_requests = 7;
        assert!(data.apply_to_fresh_data_guard(&mut wrong).is_err());
        let mut failed = serde_json::to_value(original.protocol_view()).unwrap();
        failed[10] = serde_json::json!(true);
        assert!(
            DecodedSettledCorrelationData::decode(
                &serde_json::to_vec(&failed).unwrap(),
                COMPLETE_METADATA_CREDIT
            )
            .is_err()
        );
    }

    #[test]
    fn native5_settled_correlation_malformed_strings_and_pending_keys_have_no_parser_scratch() {
        let original = guard("old");
        let encoded = serde_json::to_vec(&original.protocol_view()).unwrap();
        let text = std::str::from_utf8(&encoded).unwrap();
        let escaped = "\\u0061".repeat(1024);
        let changed = text.replace("\"session-old\"", &format!("\"{escaped}\""));
        assert!(
            DecodedSettledCorrelationData::decode(changed.as_bytes(), COMPLETE_METADATA_CREDIT)
                .is_err()
        );
        for invalid in ["", "bad id", "-leading", "é"] {
            let changed = text.replace("session-old", invalid);
            assert!(
                DecodedSettledCorrelationData::decode(changed.as_bytes(), COMPLETE_METADATA_CREDIT)
                    .is_err()
            );
        }
        let pending = text.replacen("{}", &format!("{{\"{escaped}\":[]}}"), 1);
        assert!(
            DecodedSettledCorrelationData::decode(pending.as_bytes(), COMPLETE_METADATA_CREDIT)
                .is_err()
        );
        let roster = text.replace("[],false", &format!("[\"{escaped}\"],false"));
        assert_ne!(roster, text);
        assert!(
            DecodedSettledCorrelationData::decode(roster.as_bytes(), COMPLETE_METADATA_CREDIT)
                .is_err()
        );
        assert_eq!(
            serde_json::to_vec(&original.protocol_view()).unwrap(),
            encoded
        );
    }

    #[test]
    fn native5_settled_correlation_maximum_roster_and_ids_use_exact_precharged_capacities() {
        let mut original = guard("old");
        original.session = Id::new("s".repeat(128)).unwrap();
        original.incarnation = Id::new("i".repeat(128)).unwrap();
        original.next_received = u64::MAX;
        original.next_sent = u64::MAX;
        original.extensions = (0..64)
            .map(|n| format!("{n:03}{}", "a".repeat(125)))
            .collect();
        let bytes = serde_json::to_vec(&original.protocol_view()).unwrap();
        let data = DecodedSettledCorrelationData::decode(&bytes, COMPLETE_METADATA_CREDIT).unwrap();
        assert_eq!(data.extensions.len(), 64);
        assert_eq!(data.extensions.capacity(), 64);
        assert!(
            data.extensions
                .iter()
                .all(|s| s.len() == 128 && s.capacity() == 128)
        );
        assert_eq!(data.next_received, u64::MAX);
        assert_eq!(data.next_sent, u64::MAX);
        let actual = std::mem::size_of::<DecodedSettledCorrelationData>()
            + data.session.as_str().len()
            + data.incarnation.as_str().len()
            + data.extensions.capacity() * std::mem::size_of::<String>()
            + data.extensions.iter().map(String::capacity).sum::<usize>();
        assert!(actual < COMPLETE_METADATA_CREDIT);
        let mut target = guard("fresh");
        target.extensions = original.extensions.clone();
        data.apply_to_fresh_data_guard(&mut target).unwrap();
        assert_eq!(target.next_received, u64::MAX);
        assert_eq!(target.next_sent, u64::MAX);
        let after = serde_json::to_vec(&target.protocol_view()).unwrap();
        assert!(data.apply_to_fresh_data_guard(&mut target).is_err());
        assert_eq!(serde_json::to_vec(&target.protocol_view()).unwrap(), after);
        original.extensions.insert("z".repeat(128));
        let excess = serde_json::to_vec(&original.protocol_view()).unwrap();
        assert!(DecodedSettledCorrelationData::decode(&excess, COMPLETE_METADATA_CREDIT).is_err());
    }
}
