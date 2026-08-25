//! Versioned guest selectable registration and choice request/reply messages.
//!
//! The selectable ABI is architecture-independent and uses only fixed-width
//! little-endian headers, checked byte ranges, and owned byte strings. Request
//! messages reserve their complete mutable reply buffer on the wire so a guest
//! transport can lend one exact range to the host without native pointers or a
//! second ambient allocation.
//!
//! ```text
//! SelectableRegisterV1 (56-byte header)
//! 0   u16 version              12  u64 sequence
//! 2   u16 kind = 1             20  range selectable_id
//! 4   u16 header_len           28  range domain
//! 6   u16 flags = 0            36  range default_value
//! 8   u32 total_len            44  range semantic_tags
//!                              52  u16 tag_count
//!                              54  u16 reserved = 0
//!
//! SelectionRequestV1 (48-byte header)
//! 0   u16 version              12  u64 sequence
//! 2   u16 kind = 2             20  range selectable_id
//! 4   u16 header_len           28  range instance_key
//! 6   u16 flags                36  range narrowed_domain or zero
//! 8   u32 total_buffer_len     44  u32 request_end
//!
//! SelectionReplyV1 (96-byte header)
//! 0   u16 version              12  u64 sequence
//! 2   u16 kind = 3             20  u16 status
//! 4   u16 header_len           22  u16 reserved = 0
//! 6   u16 flags = 0            24  [u8; 32] opportunity id
//! 8   u32 total_len
//!                              56  [u8; 32] domain id
//!                              88  range selected_value or zero
//! ```

use thiserror::Error;

/// Current guest selectable message version.
pub const SELECTABLE_PROTOCOL_VERSION: u16 = 1;
/// Rule for regenerating the selectable ABI golden-vector corpus.
pub const SELECTABLE_GOLDEN_VECTOR_REGENERATION_RULE: &str = "Regenerate every guest selectable register/request/reply golden vector whenever SELECTABLE_PROTOCOL_VERSION changes.";
/// Wire kind for one selectable registration.
pub const SELECTABLE_MESSAGE_KIND_REGISTER: u16 = 1;
/// Wire kind for one reply-bearing selection request.
pub const SELECTABLE_MESSAGE_KIND_REQUEST: u16 = 2;
/// Wire kind for one selection reply.
pub const SELECTABLE_MESSAGE_KIND_REPLY: u16 = 3;
/// Maximum bytes in one complete register, request buffer, or reply message.
pub const SELECTABLE_MESSAGE_MAX_BYTES: usize = 4_608;
/// Maximum bytes in one canonical selectable or instance identifier.
pub const SELECTABLE_IDENTIFIER_MAX_BYTES: usize = 128;
/// Maximum semantic tags on one selectable registration.
pub const SELECTABLE_SEMANTIC_TAG_MAX_COUNT: usize = 32;
/// Byte width of content-derived opportunity and domain identifiers.
pub const SELECTABLE_DIGEST_BYTES: usize = 32;
/// Fixed header bytes in a selectable registration.
pub const SELECTABLE_REGISTER_HEADER_BYTES: usize = 56;
/// Fixed header bytes in a selection request.
pub const SELECTION_REQUEST_HEADER_BYTES: usize = 48;
/// Fixed header bytes in a selection reply.
pub const SELECTION_REPLY_HEADER_BYTES: usize = 96;

const REQUEST_FLAG_NARROWED_DOMAIN: u16 = 1;

/// Closed selectable message-kind vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SelectableMessageKind {
    /// Setup-time selectable registration.
    Register,
    /// Runtime reply-bearing choice request.
    Request,
    /// Host selection or typed rejection reply.
    Reply,
}

impl SelectableMessageKind {
    /// Returns the stable wire value.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        match self {
            Self::Register => SELECTABLE_MESSAGE_KIND_REGISTER,
            Self::Request => SELECTABLE_MESSAGE_KIND_REQUEST,
            Self::Reply => SELECTABLE_MESSAGE_KIND_REPLY,
        }
    }

    /// Parses one stable wire value.
    #[must_use]
    pub const fn from_wire_value(value: u16) -> Option<Self> {
        match value {
            SELECTABLE_MESSAGE_KIND_REGISTER => Some(Self::Register),
            SELECTABLE_MESSAGE_KIND_REQUEST => Some(Self::Request),
            SELECTABLE_MESSAGE_KIND_REPLY => Some(Self::Reply),
            _ => None,
        }
    }
}

/// Decodes the common version/kind prefix without allocating message fields.
///
/// # Errors
///
/// Returns [`SelectableProtocolError`] when the prefix is truncated, the
/// version is unsupported, or the kind is outside the closed vocabulary.
pub fn decode_selectable_message_kind(
    bytes: &[u8],
) -> Result<SelectableMessageKind, SelectableProtocolError> {
    let version = read_u16(bytes, 0, "version")?;
    if version != SELECTABLE_PROTOCOL_VERSION {
        return Err(SelectableProtocolError::UnsupportedVersion {
            expected: SELECTABLE_PROTOCOL_VERSION,
            actual: version,
        });
    }
    let actual = read_u16(bytes, 2, "kind")?;
    SelectableMessageKind::from_wire_value(actual)
        .ok_or(SelectableProtocolError::UnknownMessageKind { actual })
}

/// One guest selectable declaration registered during setup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectableRegister {
    sequence: u64,
    selectable_id: String,
    domain: Vec<u8>,
    default_value: Vec<u8>,
    semantic_tags: Vec<String>,
}

impl SelectableRegister {
    /// Builds one canonical selectable registration.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableProtocolError`] when an identifier is invalid, a
    /// byte field is empty, tags are not strictly ordered, or the encoded
    /// message would exceed [`SELECTABLE_MESSAGE_MAX_BYTES`].
    pub fn new(
        sequence: u64,
        selectable_id: impl Into<String>,
        domain: Vec<u8>,
        default_value: Vec<u8>,
        semantic_tags: Vec<String>,
    ) -> Result<Self, SelectableProtocolError> {
        let value = Self {
            sequence,
            selectable_id: selectable_id.into(),
            domain,
            default_value,
            semantic_tags,
        };
        value.validate()?;
        Ok(value)
    }

    /// Decodes one canonical selectable registration.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableProtocolError`] when the fixed header, ranges,
    /// identifiers, tag sequence, or aggregate byte bound is invalid.
    pub fn decode(bytes: &[u8]) -> Result<Self, SelectableProtocolError> {
        let header = Header::decode(
            bytes,
            SelectableMessageKind::Register,
            SELECTABLE_REGISTER_HEADER_BYTES,
        )?;
        require_zero("flags", u64::from(header.flags))?;
        let sequence = read_u64(bytes, 12, "sequence")?;
        let selectable = read_range(bytes, 20, "selectable_id")?;
        let domain = read_range(bytes, 28, "domain")?;
        let default_value = read_range(bytes, 36, "default_value")?;
        let tags = read_range(bytes, 44, "semantic_tags")?;
        let tag_count = usize::from(read_u16(bytes, 52, "tag_count")?);
        require_zero("reserved", u64::from(read_u16(bytes, 54, "reserved")?))?;
        require_dense_ranges(
            header.header_len,
            header.total_len,
            &[selectable, domain, default_value, tags],
        )?;

        let selectable_id = decode_identifier(bytes, selectable, "selectable_id")?;
        let domain = nonempty_bytes(bytes, domain, "domain")?.to_vec();
        let default_value = nonempty_bytes(bytes, default_value, "default_value")?.to_vec();
        let semantic_tags = decode_tags(bytes, tags, tag_count)?;
        Self::new(
            sequence,
            selectable_id,
            domain,
            default_value,
            semantic_tags,
        )
    }

    /// Encodes this registration into its canonical v1 byte representation.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableProtocolError`] if fields were made invalid through
    /// a future internal construction path or the message exceeds its bound.
    pub fn encode(&self) -> Result<Vec<u8>, SelectableProtocolError> {
        self.validate()?;
        let tags_len = self.semantic_tags.iter().try_fold(0usize, |total, tag| {
            total
                .checked_add(2)
                .and_then(|value| value.checked_add(tag.len()))
                .ok_or(SelectableProtocolError::LengthOverflow)
        })?;
        let total_len = SELECTABLE_REGISTER_HEADER_BYTES
            .checked_add(self.selectable_id.len())
            .and_then(|value| value.checked_add(self.domain.len()))
            .and_then(|value| value.checked_add(self.default_value.len()))
            .and_then(|value| value.checked_add(tags_len))
            .ok_or(SelectableProtocolError::LengthOverflow)?;
        require_total_bound(total_len)?;

        let mut bytes = vec![0; SELECTABLE_REGISTER_HEADER_BYTES];
        write_header(
            &mut bytes,
            SelectableMessageKind::Register,
            SELECTABLE_REGISTER_HEADER_BYTES,
            total_len,
            0,
        )?;
        write_u64(&mut bytes, 12, self.sequence);
        append_range(&mut bytes, 20, self.selectable_id.as_bytes())?;
        append_range(&mut bytes, 28, &self.domain)?;
        append_range(&mut bytes, 36, &self.default_value)?;

        let tags_start = bytes.len();
        for tag in &self.semantic_tags {
            let len = u16::try_from(tag.len()).map_err(|_error| {
                SelectableProtocolError::IdentifierTooLong {
                    field: "semantic_tag",
                    len: tag.len(),
                    max_len: SELECTABLE_IDENTIFIER_MAX_BYTES,
                }
            })?;
            bytes.extend_from_slice(&len.to_le_bytes());
            bytes.extend_from_slice(tag.as_bytes());
        }
        write_range(&mut bytes, 44, tags_start, tags_len)?;
        write_u16(&mut bytes, 52, self.semantic_tags.len() as u16);
        debug_assert_eq!(bytes.len(), total_len);
        Ok(bytes)
    }

    /// Returns the protocol sequence retained across checkpoint/replay.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the canonical selectable identifier.
    #[must_use]
    pub fn selectable_id(&self) -> &str {
        &self.selectable_id
    }

    /// Returns the opaque canonical domain bytes.
    #[must_use]
    pub fn domain(&self) -> &[u8] {
        &self.domain
    }

    /// Returns the opaque canonical default-value bytes.
    #[must_use]
    pub fn default_value(&self) -> &[u8] {
        &self.default_value
    }

    /// Returns the strictly ordered semantic tags.
    #[must_use]
    pub fn semantic_tags(&self) -> &[String] {
        &self.semantic_tags
    }

    fn validate(&self) -> Result<(), SelectableProtocolError> {
        validate_identifier("selectable_id", &self.selectable_id)?;
        require_nonempty("domain", &self.domain)?;
        require_nonempty("default_value", &self.default_value)?;
        validate_tags(&self.semantic_tags)?;
        let _ = self.encode_len()?;
        Ok(())
    }

    fn encode_len(&self) -> Result<usize, SelectableProtocolError> {
        let tags_len = self.semantic_tags.iter().try_fold(0usize, |total, tag| {
            total
                .checked_add(2 + tag.len())
                .ok_or(SelectableProtocolError::LengthOverflow)
        })?;
        let len = SELECTABLE_REGISTER_HEADER_BYTES
            .checked_add(self.selectable_id.len())
            .and_then(|value| value.checked_add(self.domain.len()))
            .and_then(|value| value.checked_add(self.default_value.len()))
            .and_then(|value| value.checked_add(tags_len))
            .ok_or(SelectableProtocolError::LengthOverflow)?;
        require_total_bound(len)?;
        Ok(len)
    }
}

/// One reply-bearing guest choice request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectionRequest {
    sequence: u64,
    selectable_id: String,
    instance_key: String,
    narrowed_domain: Option<Vec<u8>>,
    reply_capacity: usize,
}

impl SelectionRequest {
    /// Builds one request with an exact zero-filled mutable reply reservation.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableProtocolError`] when identifiers are invalid, the
    /// narrowed domain is empty, the reply capacity cannot contain the request
    /// or a minimal reply, or the aggregate bound is exceeded.
    pub fn new(
        sequence: u64,
        selectable_id: impl Into<String>,
        instance_key: impl Into<String>,
        narrowed_domain: Option<Vec<u8>>,
        reply_capacity: usize,
    ) -> Result<Self, SelectableProtocolError> {
        let value = Self {
            sequence,
            selectable_id: selectable_id.into(),
            instance_key: instance_key.into(),
            narrowed_domain,
            reply_capacity,
        };
        value.validate()?;
        Ok(value)
    }

    /// Decodes one request and validates its zero-filled reply reservation.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableProtocolError`] for malformed headers, ranges,
    /// flags, identifiers, nonzero reservation bytes, or size violations.
    pub fn decode(bytes: &[u8]) -> Result<Self, SelectableProtocolError> {
        let header = Header::decode(
            bytes,
            SelectableMessageKind::Request,
            SELECTION_REQUEST_HEADER_BYTES,
        )?;
        let sequence = read_u64(bytes, 12, "sequence")?;
        let selectable = read_range(bytes, 20, "selectable_id")?;
        let instance = read_range(bytes, 28, "instance_key")?;
        let narrowed = read_range(bytes, 36, "narrowed_domain")?;
        let request_end = read_u32(bytes, 44, "request_end")? as usize;
        let flags = header.flags;
        if flags & !REQUEST_FLAG_NARROWED_DOMAIN != 0 {
            return Err(SelectableProtocolError::UnknownFlags { flags });
        }

        let narrowed_present = flags & REQUEST_FLAG_NARROWED_DOMAIN != 0;
        let ranges = if narrowed_present {
            if narrowed.is_empty() {
                return Err(SelectableProtocolError::EmptyField {
                    field: "narrowed_domain",
                });
            }
            vec![selectable, instance, narrowed]
        } else {
            if !narrowed.is_zero() {
                return Err(SelectableProtocolError::UnexpectedRange {
                    field: "narrowed_domain",
                });
            }
            vec![selectable, instance]
        };
        require_dense_ranges(header.header_len, request_end, &ranges)?;
        if request_end > header.total_len {
            return Err(SelectableProtocolError::RequestEndOutOfRange {
                request_end,
                total_len: header.total_len,
            });
        }
        if bytes[request_end..].iter().any(|byte| *byte != 0) {
            return Err(SelectableProtocolError::NonzeroReplyReservation);
        }

        let selectable_id = decode_identifier(bytes, selectable, "selectable_id")?;
        let instance_key = decode_identifier(bytes, instance, "instance_key")?;
        let narrowed_domain =
            narrowed_present.then(|| bytes[narrowed.start..narrowed.end()].to_vec());
        Self::new(
            sequence,
            selectable_id,
            instance_key,
            narrowed_domain,
            header.total_len,
        )
    }

    /// Encodes this request and its complete zero-filled reply reservation.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableProtocolError`] when the request is invalid or a
    /// length cannot fit its fixed-width field.
    pub fn encode(&self) -> Result<Vec<u8>, SelectableProtocolError> {
        let request_end = self.validate()?;
        let mut bytes = vec![0; SELECTION_REQUEST_HEADER_BYTES];
        write_header(
            &mut bytes,
            SelectableMessageKind::Request,
            SELECTION_REQUEST_HEADER_BYTES,
            self.reply_capacity,
            if self.narrowed_domain.is_some() {
                REQUEST_FLAG_NARROWED_DOMAIN
            } else {
                0
            },
        )?;
        write_u64(&mut bytes, 12, self.sequence);
        append_range(&mut bytes, 20, self.selectable_id.as_bytes())?;
        append_range(&mut bytes, 28, self.instance_key.as_bytes())?;
        if let Some(domain) = &self.narrowed_domain {
            append_range(&mut bytes, 36, domain)?;
        }
        write_u32_value(&mut bytes, 44, request_end)?;
        bytes.resize(self.reply_capacity, 0);
        Ok(bytes)
    }

    /// Returns the exact request/reply sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the canonical selectable identifier.
    #[must_use]
    pub fn selectable_id(&self) -> &str {
        &self.selectable_id
    }

    /// Returns the semantic runtime instance key.
    #[must_use]
    pub fn instance_key(&self) -> &str {
        &self.instance_key
    }

    /// Returns the optional opaque canonical narrowed-domain bytes.
    #[must_use]
    pub fn narrowed_domain(&self) -> Option<&[u8]> {
        self.narrowed_domain.as_deref()
    }

    /// Returns the exact mutable buffer capacity lent for the reply.
    #[must_use]
    pub const fn reply_capacity(&self) -> usize {
        self.reply_capacity
    }

    fn validate(&self) -> Result<usize, SelectableProtocolError> {
        validate_identifier("selectable_id", &self.selectable_id)?;
        validate_identifier("instance_key", &self.instance_key)?;
        if let Some(domain) = &self.narrowed_domain {
            require_nonempty("narrowed_domain", domain)?;
        }
        let request_end = SELECTION_REQUEST_HEADER_BYTES
            .checked_add(self.selectable_id.len())
            .and_then(|value| value.checked_add(self.instance_key.len()))
            .and_then(|value| value.checked_add(self.narrowed_domain.as_ref().map_or(0, Vec::len)))
            .ok_or(SelectableProtocolError::LengthOverflow)?;
        require_total_bound(self.reply_capacity)?;
        if self.reply_capacity < request_end || self.reply_capacity < SELECTION_REPLY_HEADER_BYTES {
            return Err(SelectableProtocolError::ReplyCapacityTooSmall {
                capacity: self.reply_capacity,
                minimum: request_end.max(SELECTION_REPLY_HEADER_BYTES),
            });
        }
        Ok(request_end)
    }
}

/// Closed status vocabulary for one selection reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SelectionReplyStatus {
    /// A value was selected and is present in the reply.
    Selected,
    /// The requested selectable is not registered in the frozen catalog.
    UnknownSelectable,
    /// The instance key violates the selectable's runtime contract.
    InvalidInstance,
    /// The offered narrowed domain is malformed or broadens the declaration.
    InvalidNarrowedDomain,
    /// No admissible value exists for the opportunity.
    NoAdmissibleValue,
    /// The authority needed to choose a value is temporarily unavailable.
    Unavailable,
}

impl SelectionReplyStatus {
    /// Returns the stable little-endian wire value.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        match self {
            Self::Selected => 0,
            Self::UnknownSelectable => 1,
            Self::InvalidInstance => 2,
            Self::InvalidNarrowedDomain => 3,
            Self::NoAdmissibleValue => 4,
            Self::Unavailable => 5,
        }
    }

    /// Parses one stable wire value.
    #[must_use]
    pub const fn from_wire_value(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Selected),
            1 => Some(Self::UnknownSelectable),
            2 => Some(Self::InvalidInstance),
            3 => Some(Self::InvalidNarrowedDomain),
            4 => Some(Self::NoAdmissibleValue),
            5 => Some(Self::Unavailable),
            _ => None,
        }
    }
}

/// One sequence-bound host reply to a guest selection request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectionReply {
    sequence: u64,
    status: SelectionReplyStatus,
    opportunity_id: [u8; SELECTABLE_DIGEST_BYTES],
    domain_id: [u8; SELECTABLE_DIGEST_BYTES],
    selected_value: Option<Vec<u8>>,
}

impl SelectionReply {
    /// Builds one successful selected-value reply.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableProtocolError`] when the value is empty or the
    /// encoded reply exceeds the protocol bound.
    pub fn selected(
        sequence: u64,
        opportunity_id: [u8; SELECTABLE_DIGEST_BYTES],
        domain_id: [u8; SELECTABLE_DIGEST_BYTES],
        selected_value: Vec<u8>,
    ) -> Result<Self, SelectableProtocolError> {
        let value = Self {
            sequence,
            status: SelectionReplyStatus::Selected,
            opportunity_id,
            domain_id,
            selected_value: Some(selected_value),
        };
        value.validate()?;
        Ok(value)
    }

    /// Builds one typed rejection without selected-value bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableProtocolError`] when `status` is
    /// [`SelectionReplyStatus::Selected`].
    pub fn rejected(
        sequence: u64,
        status: SelectionReplyStatus,
        opportunity_id: [u8; SELECTABLE_DIGEST_BYTES],
        domain_id: [u8; SELECTABLE_DIGEST_BYTES],
    ) -> Result<Self, SelectableProtocolError> {
        let value = Self {
            sequence,
            status,
            opportunity_id,
            domain_id,
            selected_value: None,
        };
        value.validate()?;
        Ok(value)
    }

    /// Decodes one canonical selection reply.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableProtocolError`] for malformed headers, status,
    /// selected-value shape, reserved fields, or aggregate bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, SelectableProtocolError> {
        let header = Header::decode(
            bytes,
            SelectableMessageKind::Reply,
            SELECTION_REPLY_HEADER_BYTES,
        )?;
        require_zero("flags", u64::from(header.flags))?;
        let sequence = read_u64(bytes, 12, "sequence")?;
        let status_value = read_u16(bytes, 20, "status")?;
        let status = SelectionReplyStatus::from_wire_value(status_value).ok_or(
            SelectableProtocolError::UnknownReplyStatus {
                status: status_value,
            },
        )?;
        require_zero("reserved", u64::from(read_u16(bytes, 22, "reserved")?))?;
        let opportunity_id = read_digest(bytes, 24, "opportunity_id")?;
        let domain_id = read_digest(bytes, 56, "domain_id")?;
        let selected = read_range(bytes, 88, "selected_value")?;

        let selected_value = if status == SelectionReplyStatus::Selected {
            require_dense_ranges(header.header_len, header.total_len, &[selected])?;
            Some(nonempty_bytes(bytes, selected, "selected_value")?.to_vec())
        } else {
            if !selected.is_zero() {
                return Err(SelectableProtocolError::UnexpectedRange {
                    field: "selected_value",
                });
            }
            if header.total_len != header.header_len {
                return Err(SelectableProtocolError::NonCanonicalRangeLayout);
            }
            None
        };
        let value = Self {
            sequence,
            status,
            opportunity_id,
            domain_id,
            selected_value,
        };
        value.validate()?;
        Ok(value)
    }

    /// Encodes this reply into its canonical v1 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableProtocolError`] if the status/value combination is
    /// invalid or the message exceeds its aggregate byte bound.
    pub fn encode(&self) -> Result<Vec<u8>, SelectableProtocolError> {
        self.validate()?;
        let total_len = SELECTION_REPLY_HEADER_BYTES
            .checked_add(self.selected_value.as_ref().map_or(0, Vec::len))
            .ok_or(SelectableProtocolError::LengthOverflow)?;
        let mut bytes = vec![0; SELECTION_REPLY_HEADER_BYTES];
        write_header(
            &mut bytes,
            SelectableMessageKind::Reply,
            SELECTION_REPLY_HEADER_BYTES,
            total_len,
            0,
        )?;
        write_u64(&mut bytes, 12, self.sequence);
        write_u16(&mut bytes, 20, self.status.wire_value());
        bytes[24..56].copy_from_slice(&self.opportunity_id);
        bytes[56..88].copy_from_slice(&self.domain_id);
        if let Some(selected) = &self.selected_value {
            append_range(&mut bytes, 88, selected)?;
        }
        Ok(bytes)
    }

    /// Returns the exact request/reply sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the closed reply status.
    #[must_use]
    pub const fn status(&self) -> SelectionReplyStatus {
        self.status
    }

    /// Returns the fixed-width choice-opportunity identifier.
    #[must_use]
    pub const fn opportunity_id(&self) -> &[u8; SELECTABLE_DIGEST_BYTES] {
        &self.opportunity_id
    }

    /// Returns the fixed-width offered-domain identifier.
    #[must_use]
    pub const fn domain_id(&self) -> &[u8; SELECTABLE_DIGEST_BYTES] {
        &self.domain_id
    }

    /// Returns the selected canonical value bytes on success.
    #[must_use]
    pub fn selected_value(&self) -> Option<&[u8]> {
        self.selected_value.as_deref()
    }

    fn validate(&self) -> Result<(), SelectableProtocolError> {
        match (self.status, &self.selected_value) {
            (SelectionReplyStatus::Selected, Some(value)) => {
                require_nonempty("selected_value", value)?
            }
            (SelectionReplyStatus::Selected, None) => {
                return Err(SelectableProtocolError::SelectedValueMissing);
            }
            (_, Some(_)) => return Err(SelectableProtocolError::RejectedValuePresent),
            (_, None) => {}
        }
        let len = SELECTION_REPLY_HEADER_BYTES
            .checked_add(self.selected_value.as_ref().map_or(0, Vec::len))
            .ok_or(SelectableProtocolError::LengthOverflow)?;
        require_total_bound(len)
    }
}

#[derive(Clone, Copy)]
struct Header {
    header_len: usize,
    total_len: usize,
    flags: u16,
}

impl Header {
    fn decode(
        bytes: &[u8],
        expected_kind: SelectableMessageKind,
        expected_header_len: usize,
    ) -> Result<Self, SelectableProtocolError> {
        require_total_bound(bytes.len())?;
        if bytes.len() < expected_header_len {
            return Err(SelectableProtocolError::Truncated {
                field: "header",
                needed: expected_header_len,
                remaining: bytes.len(),
            });
        }
        let version = read_u16(bytes, 0, "version")?;
        if version != SELECTABLE_PROTOCOL_VERSION {
            return Err(SelectableProtocolError::UnsupportedVersion {
                expected: SELECTABLE_PROTOCOL_VERSION,
                actual: version,
            });
        }
        let kind = read_u16(bytes, 2, "kind")?;
        if kind != expected_kind.wire_value() {
            return Err(SelectableProtocolError::UnexpectedMessageKind {
                expected: expected_kind,
                actual: kind,
            });
        }
        let header_len = usize::from(read_u16(bytes, 4, "header_len")?);
        if header_len != expected_header_len {
            return Err(SelectableProtocolError::HeaderLengthMismatch {
                expected: expected_header_len,
                actual: header_len,
            });
        }
        let flags = read_u16(bytes, 6, "flags")?;
        let total_len = read_u32(bytes, 8, "total_len")? as usize;
        if total_len != bytes.len() {
            return Err(SelectableProtocolError::TotalLengthMismatch {
                declared: total_len,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            header_len,
            total_len,
            flags,
        })
    }
}

#[derive(Clone, Copy)]
struct ByteRange {
    start: usize,
    len: usize,
}

impl ByteRange {
    const fn is_zero(self) -> bool {
        self.start == 0 && self.len == 0
    }

    const fn is_empty(self) -> bool {
        self.len == 0
    }

    fn end(self) -> usize {
        self.start.saturating_add(self.len)
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), SelectableProtocolError> {
    if value.is_empty() {
        return Err(SelectableProtocolError::EmptyField { field });
    }
    if value.len() > SELECTABLE_IDENTIFIER_MAX_BYTES {
        return Err(SelectableProtocolError::IdentifierTooLong {
            field,
            len: value.len(),
            max_len: SELECTABLE_IDENTIFIER_MAX_BYTES,
        });
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
    }) {
        return Err(SelectableProtocolError::InvalidIdentifier {
            field,
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn validate_tags(tags: &[String]) -> Result<(), SelectableProtocolError> {
    if tags.len() > SELECTABLE_SEMANTIC_TAG_MAX_COUNT {
        return Err(SelectableProtocolError::TooManySemanticTags {
            count: tags.len(),
            max_count: SELECTABLE_SEMANTIC_TAG_MAX_COUNT,
        });
    }
    let mut previous: Option<&str> = None;
    for tag in tags {
        validate_identifier("semantic_tag", tag)?;
        if previous.is_some_and(|value| value >= tag.as_str()) {
            return Err(SelectableProtocolError::NonCanonicalSemanticTagOrder);
        }
        previous = Some(tag);
    }
    Ok(())
}

fn decode_tags(
    bytes: &[u8],
    range: ByteRange,
    count: usize,
) -> Result<Vec<String>, SelectableProtocolError> {
    if count > SELECTABLE_SEMANTIC_TAG_MAX_COUNT {
        return Err(SelectableProtocolError::TooManySemanticTags {
            count,
            max_count: SELECTABLE_SEMANTIC_TAG_MAX_COUNT,
        });
    }
    let mut offset = range.start;
    let end = range.end();
    let mut tags = Vec::with_capacity(count);
    for _ in 0..count {
        let len = usize::from(read_u16_bounded(bytes, offset, "semantic_tag.length", end)?);
        offset = offset
            .checked_add(2)
            .ok_or(SelectableProtocolError::LengthOverflow)?;
        let tag_end = offset
            .checked_add(len)
            .ok_or(SelectableProtocolError::LengthOverflow)?;
        if tag_end > end {
            return Err(SelectableProtocolError::RangeOutOfBounds {
                field: "semantic_tag",
            });
        }
        let tag = std::str::from_utf8(&bytes[offset..tag_end])
            .map_err(|_error| SelectableProtocolError::InvalidUtf8 {
                field: "semantic_tag",
            })?
            .to_owned();
        tags.push(tag);
        offset = tag_end;
    }
    if offset != end {
        return Err(SelectableProtocolError::TagCountMismatch);
    }
    validate_tags(&tags)?;
    Ok(tags)
}

fn decode_identifier(
    bytes: &[u8],
    range: ByteRange,
    field: &'static str,
) -> Result<String, SelectableProtocolError> {
    let raw = nonempty_bytes(bytes, range, field)?;
    let value = std::str::from_utf8(raw)
        .map_err(|_error| SelectableProtocolError::InvalidUtf8 { field })?
        .to_owned();
    validate_identifier(field, &value)?;
    Ok(value)
}

fn nonempty_bytes<'a>(
    bytes: &'a [u8],
    range: ByteRange,
    field: &'static str,
) -> Result<&'a [u8], SelectableProtocolError> {
    if range.is_empty() {
        return Err(SelectableProtocolError::EmptyField { field });
    }
    bytes
        .get(range.start..range.end())
        .ok_or(SelectableProtocolError::RangeOutOfBounds { field })
}

fn require_nonempty(field: &'static str, value: &[u8]) -> Result<(), SelectableProtocolError> {
    if value.is_empty() {
        Err(SelectableProtocolError::EmptyField { field })
    } else {
        Ok(())
    }
}

fn require_total_bound(len: usize) -> Result<(), SelectableProtocolError> {
    if len > SELECTABLE_MESSAGE_MAX_BYTES {
        Err(SelectableProtocolError::MessageTooLarge {
            len,
            max_len: SELECTABLE_MESSAGE_MAX_BYTES,
        })
    } else {
        Ok(())
    }
}

fn require_zero(field: &'static str, value: u64) -> Result<(), SelectableProtocolError> {
    if value == 0 {
        Ok(())
    } else {
        Err(SelectableProtocolError::NonzeroReserved { field, value })
    }
}

fn require_dense_ranges(
    header_len: usize,
    end: usize,
    ranges: &[ByteRange],
) -> Result<(), SelectableProtocolError> {
    let mut expected = header_len;
    for range in ranges {
        if range.start != expected {
            return Err(SelectableProtocolError::NonCanonicalRangeLayout);
        }
        expected = range
            .start
            .checked_add(range.len)
            .ok_or(SelectableProtocolError::LengthOverflow)?;
        if expected > end {
            return Err(SelectableProtocolError::NonCanonicalRangeLayout);
        }
    }
    if expected != end {
        return Err(SelectableProtocolError::NonCanonicalRangeLayout);
    }
    Ok(())
}

fn write_header(
    bytes: &mut [u8],
    kind: SelectableMessageKind,
    header_len: usize,
    total_len: usize,
    flags: u16,
) -> Result<(), SelectableProtocolError> {
    require_total_bound(total_len)?;
    write_u16(bytes, 0, SELECTABLE_PROTOCOL_VERSION);
    write_u16(bytes, 2, kind.wire_value());
    write_u16(
        bytes,
        4,
        u16::try_from(header_len).map_err(|_error| SelectableProtocolError::LengthOverflow)?,
    );
    write_u16(bytes, 6, flags);
    write_u32_value(bytes, 8, total_len)
}

fn append_range(
    bytes: &mut Vec<u8>,
    header_offset: usize,
    value: &[u8],
) -> Result<(), SelectableProtocolError> {
    let start = bytes.len();
    bytes.extend_from_slice(value);
    write_range(bytes, header_offset, start, value.len())
}

fn write_range(
    bytes: &mut [u8],
    header_offset: usize,
    start: usize,
    len: usize,
) -> Result<(), SelectableProtocolError> {
    write_u32_value(bytes, header_offset, start)?;
    write_u32_value(bytes, header_offset + 4, len)
}

fn write_u32_value(
    bytes: &mut [u8],
    offset: usize,
    value: usize,
) -> Result<(), SelectableProtocolError> {
    let value = u32::try_from(value).map_err(|_error| SelectableProtocolError::LengthOverflow)?;
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_range(
    bytes: &[u8],
    offset: usize,
    field: &'static str,
) -> Result<ByteRange, SelectableProtocolError> {
    let start = read_u32(bytes, offset, field)? as usize;
    let len = read_u32(bytes, offset + 4, field)? as usize;
    let range = ByteRange { start, len };
    if range.end() > bytes.len() {
        return Err(SelectableProtocolError::RangeOutOfBounds { field });
    }
    Ok(range)
}

fn read_digest(
    bytes: &[u8],
    offset: usize,
    field: &'static str,
) -> Result<[u8; SELECTABLE_DIGEST_BYTES], SelectableProtocolError> {
    let raw = bytes.get(offset..offset + SELECTABLE_DIGEST_BYTES).ok_or(
        SelectableProtocolError::Truncated {
            field,
            needed: SELECTABLE_DIGEST_BYTES,
            remaining: bytes.len().saturating_sub(offset),
        },
    )?;
    let mut digest = [0; SELECTABLE_DIGEST_BYTES];
    digest.copy_from_slice(raw);
    Ok(digest)
}

fn read_u16(
    bytes: &[u8],
    offset: usize,
    field: &'static str,
) -> Result<u16, SelectableProtocolError> {
    read_u16_bounded(bytes, offset, field, bytes.len())
}

fn read_u16_bounded(
    bytes: &[u8],
    offset: usize,
    field: &'static str,
    end: usize,
) -> Result<u16, SelectableProtocolError> {
    if offset.checked_add(2).is_none_or(|value| value > end) {
        return Err(SelectableProtocolError::Truncated {
            field,
            needed: 2,
            remaining: end.saturating_sub(offset),
        });
    }
    Ok(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]))
}

fn read_u32(
    bytes: &[u8],
    offset: usize,
    field: &'static str,
) -> Result<u32, SelectableProtocolError> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or(SelectableProtocolError::Truncated {
            field,
            needed: 4,
            remaining: bytes.len().saturating_sub(offset),
        })?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64(
    bytes: &[u8],
    offset: usize,
    field: &'static str,
) -> Result<u64, SelectableProtocolError> {
    let raw = bytes
        .get(offset..offset + 8)
        .ok_or(SelectableProtocolError::Truncated {
            field,
            needed: 8,
            remaining: bytes.len().saturating_sub(offset),
        })?;
    let mut fixed = [0; 8];
    fixed.copy_from_slice(raw);
    Ok(u64::from_le_bytes(fixed))
}

/// Stable error returned by selectable message construction or decoding.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SelectableProtocolError {
    /// A fixed field or header is truncated.
    #[error("selectable field {field} needs {needed} bytes with only {remaining} remaining")]
    Truncated {
        /// Field being decoded.
        field: &'static str,
        /// Required bytes.
        needed: usize,
        /// Available bytes.
        remaining: usize,
    },
    /// The message used an unsupported protocol version.
    #[error("selectable protocol version {actual} does not match expected {expected}")]
    UnsupportedVersion {
        /// Supported version.
        expected: u16,
        /// Observed version.
        actual: u16,
    },
    /// The decoder was invoked for a different message kind.
    #[error("selectable message kind {actual} does not match expected {expected:?}")]
    UnexpectedMessageKind {
        /// Expected closed kind.
        expected: SelectableMessageKind,
        /// Observed wire kind.
        actual: u16,
    },
    /// The common prefix carried a kind outside the closed vocabulary.
    #[error("selectable message kind {actual} is unknown")]
    UnknownMessageKind {
        /// Unknown wire kind.
        actual: u16,
    },
    /// The fixed header length is not canonical.
    #[error("selectable header length {actual} does not match expected {expected}")]
    HeaderLengthMismatch {
        /// Expected header bytes.
        expected: usize,
        /// Observed header bytes.
        actual: usize,
    },
    /// The declared total length differs from the supplied buffer.
    #[error("selectable total length {declared} does not match actual {actual}")]
    TotalLengthMismatch {
        /// Header-declared bytes.
        declared: usize,
        /// Supplied bytes.
        actual: usize,
    },
    /// The complete bounded message is too large.
    #[error("selectable message length {len} exceeds maximum {max_len}")]
    MessageTooLarge {
        /// Observed bytes.
        len: usize,
        /// Maximum bytes.
        max_len: usize,
    },
    /// Length arithmetic overflowed.
    #[error("selectable message length arithmetic overflowed")]
    LengthOverflow,
    /// A byte range points outside the supplied message.
    #[error("selectable field {field} range is outside the message")]
    RangeOutOfBounds {
        /// Range field.
        field: &'static str,
    },
    /// Variable fields are not contiguous and canonically ordered.
    #[error("selectable variable fields are not in canonical dense order")]
    NonCanonicalRangeLayout,
    /// A field that must omit its range supplied one.
    #[error("selectable field {field} supplied a range when it must be absent")]
    UnexpectedRange {
        /// Range field.
        field: &'static str,
    },
    /// An opaque or identifier field is empty.
    #[error("selectable field {field} must not be empty")]
    EmptyField {
        /// Empty field.
        field: &'static str,
    },
    /// An identifier exceeds its byte bound.
    #[error("selectable identifier {field} length {len} exceeds maximum {max_len}")]
    IdentifierTooLong {
        /// Identifier field.
        field: &'static str,
        /// Observed bytes.
        len: usize,
        /// Maximum bytes.
        max_len: usize,
    },
    /// An identifier contains a noncanonical byte.
    #[error("selectable identifier {field} is not canonical: {value}")]
    InvalidIdentifier {
        /// Identifier field.
        field: &'static str,
        /// Rejected value.
        value: String,
    },
    /// A string is not UTF-8.
    #[error("selectable field {field} is not valid UTF-8")]
    InvalidUtf8 {
        /// String field.
        field: &'static str,
    },
    /// A reserved fixed field is nonzero.
    #[error("selectable reserved field {field} is nonzero: {value}")]
    NonzeroReserved {
        /// Reserved field.
        field: &'static str,
        /// Observed value.
        value: u64,
    },
    /// A flags field contains an unknown bit.
    #[error("selection request flags contain unknown bits {flags:#x}")]
    UnknownFlags {
        /// Observed flags.
        flags: u16,
    },
    /// Too many semantic tags were supplied.
    #[error("selectable semantic tag count {count} exceeds maximum {max_count}")]
    TooManySemanticTags {
        /// Observed tags.
        count: usize,
        /// Maximum tags.
        max_count: usize,
    },
    /// Semantic tags are not strictly increasing.
    #[error("selectable semantic tags are not in strictly increasing order")]
    NonCanonicalSemanticTagOrder,
    /// The tag count does not consume the exact tag byte range.
    #[error("selectable semantic tag count does not match the tag byte range")]
    TagCountMismatch,
    /// The request end lies outside its reply buffer.
    #[error("selection request end {request_end} exceeds buffer length {total_len}")]
    RequestEndOutOfRange {
        /// End of request-owned bytes.
        request_end: usize,
        /// Total mutable buffer bytes.
        total_len: usize,
    },
    /// The reserved reply buffer contains nonzero bytes before delivery.
    #[error("selection request reply reservation is not zero-filled")]
    NonzeroReplyReservation,
    /// The mutable reply buffer cannot contain the request and minimal reply.
    #[error("selection reply capacity {capacity} is smaller than required {minimum}")]
    ReplyCapacityTooSmall {
        /// Supplied buffer bytes.
        capacity: usize,
        /// Minimum required bytes.
        minimum: usize,
    },
    /// A reply status is outside the closed vocabulary.
    #[error("selection reply status {status} is unknown")]
    UnknownReplyStatus {
        /// Unknown wire status.
        status: u16,
    },
    /// A successful reply omitted the selected value.
    #[error("successful selection reply omitted its selected value")]
    SelectedValueMissing,
    /// A rejected reply incorrectly carried a selected value.
    #[error("rejected selection reply carried a selected value")]
    RejectedValuePresent,
}

#[cfg(test)]
mod tests;
