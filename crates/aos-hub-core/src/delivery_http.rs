//! Portable HTTP semantics for RFC-0012 delivery routes.
//!
//! This module is the protocol kernel shared by the native Hub and the Worker.
//! It deliberately contains no framework, clock, storage, or platform types:
//! adapters parse their request headers into these types, run
//! [`evaluate_request`], and translate the resulting typed decision back into
//! their HTTP runtime.
//!
//! The kernel owns method admission, entity-tag conditions, second-precision
//! date conditions, one-range byte serving, response metadata derivation,
//! origin-header filtering, sanitized origin failure classification, and the
//! fixed redirect/direct-miss responses. HTTP-date parsing and formatting are
//! implemented here without platform dependencies, so both adapters accept the
//! same three wire formats and emit identical IMF-fixdate bytes.

use std::fmt;

use thiserror::Error;
use url::Url;

use crate::delivery::CanonicalRoutePath;

/// Cache policy for a publicly readable immutable object.
pub const PUBLIC_IMMUTABLE_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";
/// Cache policy for a publicly readable mutable object.
pub const PUBLIC_MUTABLE_CACHE_CONTROL: &str = "public, max-age=60, must-revalidate";
/// Cache policy for a response whose authorization is private to the client.
pub const PRIVATE_CACHE_CONTROL: &str = "private, no-store";
/// Referrer policy for responses that disclose a temporary bearer capability.
pub const REDIRECT_REFERRER_POLICY: &str = "no-referrer";
/// Cache policy for a public terminal/error response with no reusable body.
pub const PUBLIC_TERMINAL_CACHE_CONTROL: &str = "no-store";

const MIN_HTTP_TIMESTAMP: i64 = -2_208_988_800;
const MAX_HTTP_TIMESTAMP: i64 = 253_402_300_799;

/// An HTTP delivery method accepted by the machine-data plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryMethod {
    /// Retrieve representation metadata and, unless suppressed by a decision,
    /// its body.
    Get,
    /// Retrieve the same metadata as `GET` without a response body.
    Head,
}

impl DeliveryMethod {
    /// Parses an HTTP method admitted by a delivery route.
    ///
    /// # Errors
    ///
    /// Returns [`MethodError`] for every method other than exact uppercase
    /// `GET` and `HEAD`.
    pub fn parse(method: &str) -> Result<Self, MethodError> {
        match method {
            "GET" => Ok(Self::Get),
            "HEAD" => Ok(Self::Head),
            _ => Err(MethodError),
        }
    }
}

/// A method that the read-only delivery data plane does not accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("delivery routes accept only GET and HEAD")]
pub struct MethodError;

/// A second-precision HTTP date expressed relative to the Unix epoch.
///
/// Adapters are responsible for accepting the three HTTP-date wire formats and
/// converting them to this value. An invalid request date is ignored by
/// omitting its condition; it is never replaced with an epoch default. Negative
/// values retain valid pre-epoch dates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HttpTimestamp(i64);

impl HttpTimestamp {
    /// Constructs a representable HTTP timestamp from whole Unix seconds.
    ///
    /// # Errors
    ///
    /// Returns [`HttpDateError::OutOfRange`] outside years 1900 through 9999,
    /// the range accepted and emitted by this shared HTTP-date profile.
    pub const fn from_unix_seconds(seconds: i64) -> Result<Self, HttpDateError> {
        if seconds < MIN_HTTP_TIMESTAMP || seconds > MAX_HTTP_TIMESTAMP {
            return Err(HttpDateError::OutOfRange);
        }
        Ok(Self(seconds))
    }

    /// Returns the whole Unix-second value.
    #[must_use]
    pub const fn unix_seconds(self) -> i64 {
        self.0
    }

    /// Parses IMF-fixdate, obsolete RFC 850, or ANSI C `asctime` HTTP-date.
    ///
    /// The parser is strict ASCII and verifies weekday/date agreement. RFC 850
    /// two-digit years more than 50 years after `now` are interpreted as the
    /// most recent year with the same suffix, as required by HTTP semantics.
    ///
    /// # Errors
    ///
    /// Returns [`HttpDateError`] for invalid grammar, calendar values, weekday
    /// mismatch, or a date outside the representable profile.
    pub fn parse_http_date(value: &str, now: Self) -> Result<Self, HttpDateError> {
        parse_http_date(value.as_bytes(), now)
    }

    /// Formats this timestamp as canonical IMF-fixdate.
    #[must_use]
    pub fn to_http_date(self) -> String {
        let (year, month, day, hour, minute, second, weekday) = split_timestamp(self.0);
        format!(
            "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
            SHORT_WEEKDAYS[weekday],
            day,
            MONTHS[(month - 1) as usize],
            year,
            hour,
            minute,
            second
        )
    }
}

/// An invalid or unrepresentable HTTP date.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HttpDateError {
    /// The value did not match one of HTTP's three date grammars.
    #[error("HTTP date has invalid syntax")]
    InvalidSyntax,
    /// The calendar date or clock time does not exist.
    #[error("HTTP date has an invalid calendar value")]
    InvalidCalendar,
    /// The named weekday disagrees with the calendar date.
    #[error("HTTP date weekday does not match its calendar date")]
    WeekdayMismatch,
    /// The date lies outside years 1900 through 9999.
    #[error("HTTP date is outside the representable range")]
    OutOfRange,
}

/// A verified `Last-Modified` validator and its `If-Range` strength.
///
/// HTTP dates have one-second resolution. A date is strong enough for
/// `If-Range` only when publication metadata proves the representation cannot
/// change twice within that second; ordinary date preconditions do not require
/// that additional guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LastModifiedValidator {
    timestamp: HttpTimestamp,
    strong_for_if_range: bool,
}

impl LastModifiedValidator {
    /// Constructs a verified last-modified validator.
    #[must_use]
    pub const fn new(timestamp: HttpTimestamp, strong_for_if_range: bool) -> Self {
        Self {
            timestamp,
            strong_for_if_range,
        }
    }

    /// Returns the second-precision last-modified time.
    #[must_use]
    pub const fn timestamp(self) -> HttpTimestamp {
        self.timestamp
    }

    /// Returns whether this date is a strong validator for `If-Range`.
    #[must_use]
    pub const fn is_strong_for_if_range(self) -> bool {
        self.strong_for_if_range
    }
}

/// A syntactically valid HTTP entity tag.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntityTag {
    weak: bool,
    opaque: Vec<u8>,
}

impl EntityTag {
    /// Parses one entity tag from a UTF-8 Rust string without changing its wire
    /// bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EntityTagError`] when `value` is not one complete canonical
    /// entity tag.
    pub fn parse(value: &str) -> Result<Self, EntityTagError> {
        Self::parse_bytes(value.as_bytes())
    }

    /// Parses one byte-correct RFC 9110 entity tag.
    ///
    /// Empty opaque tags are valid. Each opaque byte must be `0x21`,
    /// `0x23..=0x7e`, or `0x80..=0xff`; this preserves RFC `obs-text` without
    /// forcing arbitrary header bytes through UTF-8. Lowercase `w/`, controls,
    /// whitespace outside the quotes, and a bare quote are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`EntityTagError`] when `value` is not one complete entity tag.
    pub fn parse_bytes(value: &[u8]) -> Result<Self, EntityTagError> {
        let (weak, quoted) = if let Some(rest) = value.strip_prefix(b"W/") {
            (true, rest)
        } else {
            (false, value)
        };
        if quoted.len() < 2 || !quoted.starts_with(b"\"") || !quoted.ends_with(b"\"") {
            return Err(EntityTagError::InvalidSyntax);
        }
        let opaque = &quoted[1..quoted.len() - 1];
        if !opaque
            .iter()
            .copied()
            .all(|byte| byte == 0x21 || (0x23..=0x7e).contains(&byte) || byte >= 0x80)
        {
            return Err(EntityTagError::InvalidOpaqueValue);
        }
        Ok(Self {
            weak,
            opaque: opaque.to_vec(),
        })
    }

    /// Returns whether this validator is weak.
    #[must_use]
    pub const fn is_weak(&self) -> bool {
        self.weak
    }

    /// Returns the tag's unquoted opaque value.
    #[must_use]
    pub fn opaque(&self) -> &[u8] {
        &self.opaque
    }

    /// Serializes the exact entity-tag wire bytes.
    #[must_use]
    pub fn to_header_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.opaque.len() + if self.weak { 4 } else { 2 });
        if self.weak {
            bytes.extend_from_slice(b"W/");
        }
        bytes.push(b'"');
        bytes.extend_from_slice(&self.opaque);
        bytes.push(b'"');
        bytes
    }

    /// Compares two tags using the strong entity-tag comparison function.
    #[must_use]
    pub fn strongly_eq(&self, other: &Self) -> bool {
        !self.weak && !other.weak && self.opaque == other.opaque
    }

    /// Compares two tags using the weak entity-tag comparison function.
    #[must_use]
    pub fn weakly_eq(&self, other: &Self) -> bool {
        self.opaque == other.opaque
    }
}

/// An invalid HTTP entity tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EntityTagError {
    /// The weak marker or surrounding quotes were missing or malformed.
    #[error("entity tag has invalid syntax")]
    InvalidSyntax,
    /// The quoted opaque value contained a byte outside the supported grammar.
    #[error("entity tag contains an invalid opaque byte")]
    InvalidOpaqueValue,
}

/// The wildcard or entity-tag list carried by `If-Match`/`If-None-Match`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntityTagCondition {
    /// Match any current representation.
    Any,
    /// Match one of the listed validators.
    Tags(Vec<EntityTag>),
}

impl EntityTagCondition {
    /// Parses one complete wildcard or comma-separated entity-tag condition.
    ///
    /// Optional horizontal whitespace is accepted around list delimiters, but
    /// not inside a tag. A wildcard cannot be mixed into a tag list.
    ///
    /// # Errors
    ///
    /// Returns [`EntityTagConditionError`] for an empty list, an invalid tag,
    /// a trailing comma, or a wildcard combined with other members.
    pub fn parse(value: &str) -> Result<Self, EntityTagConditionError> {
        Self::parse_bytes(value.as_bytes())
    }

    /// Parses a byte-correct wildcard or comma-separated entity-tag condition.
    ///
    /// # Errors
    ///
    /// Returns [`EntityTagConditionError`] under the same conditions as
    /// [`Self::parse`].
    pub fn parse_bytes(value: &[u8]) -> Result<Self, EntityTagConditionError> {
        let value = trim_ows_bytes(value);
        if value == b"*" {
            return Ok(Self::Any);
        }
        if value.is_empty() {
            return Err(EntityTagConditionError::Empty);
        }

        let bytes = value;
        let mut index = 0;
        let mut tags = Vec::new();
        loop {
            skip_ows(bytes, &mut index);
            if index >= bytes.len() {
                return Err(EntityTagConditionError::EmptyMember);
            }
            let start = index;
            if bytes[index..].starts_with(b"W/") {
                index += 2;
            }
            if bytes.get(index) != Some(&b'"') {
                return Err(EntityTagConditionError::InvalidTag);
            }
            index += 1;
            while let Some(byte) = bytes.get(index).copied() {
                if byte == b'"' {
                    break;
                }
                if !(byte == 0x21 || (0x23..=0x7e).contains(&byte) || byte >= 0x80) {
                    return Err(EntityTagConditionError::InvalidTag);
                }
                index += 1;
            }
            if bytes.get(index) != Some(&b'"') {
                return Err(EntityTagConditionError::InvalidTag);
            }
            index += 1;
            let tag = EntityTag::parse_bytes(&value[start..index])
                .map_err(|_| EntityTagConditionError::InvalidTag)?;
            tags.push(tag);
            skip_ows(bytes, &mut index);
            if index == bytes.len() {
                break;
            }
            if bytes[index] != b',' {
                return Err(EntityTagConditionError::InvalidSeparator);
            }
            index += 1;
            if trim_ows_bytes(&value[index..]).is_empty() {
                return Err(EntityTagConditionError::EmptyMember);
            }
        }
        Ok(Self::Tags(tags))
    }

    fn matches_strongly(&self, current: Option<&EntityTag>) -> bool {
        match (self, current) {
            (Self::Any, Some(_)) => true,
            (Self::Tags(tags), Some(current)) => {
                tags.iter().any(|candidate| candidate.strongly_eq(current))
            }
            (_, None) => false,
        }
    }

    fn matches_weakly(&self, current: Option<&EntityTag>) -> bool {
        match (self, current) {
            (Self::Any, Some(_)) => true,
            (Self::Tags(tags), Some(current)) => {
                tags.iter().any(|candidate| candidate.weakly_eq(current))
            }
            (_, None) => false,
        }
    }

    /// Serializes a canonical byte-correct condition field value.
    #[must_use]
    pub fn to_header_bytes(&self) -> Vec<u8> {
        match self {
            Self::Any => b"*".to_vec(),
            Self::Tags(tags) => {
                let mut value = Vec::new();
                for (index, tag) in tags.iter().enumerate() {
                    if index > 0 {
                        value.extend_from_slice(b", ");
                    }
                    value.extend_from_slice(&tag.to_header_bytes());
                }
                value
            }
        }
    }
}

/// An invalid `If-Match` or `If-None-Match` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EntityTagConditionError {
    /// The field value was empty.
    #[error("entity-tag condition cannot be empty")]
    Empty,
    /// A list member was empty, including after a trailing comma.
    #[error("entity-tag condition contains an empty member")]
    EmptyMember,
    /// A list member was not a valid entity tag.
    #[error("entity-tag condition contains an invalid tag")]
    InvalidTag,
    /// Members were not separated by a comma and optional whitespace.
    #[error("entity-tag condition has an invalid separator")]
    InvalidSeparator,
}

/// A validator carried by `If-Range`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IfRangeCondition {
    /// An entity-tag validator. Weak tags are syntactically retained but never
    /// satisfy `If-Range`, which requires strong comparison.
    EntityTag(EntityTag),
    /// A parsed HTTP-date validator at Unix-second precision.
    Date(HttpTimestamp),
}

impl IfRangeCondition {
    fn matches(&self, representation: &VerifiedRepresentation) -> bool {
        match self {
            Self::EntityTag(candidate) => candidate.strongly_eq(&representation.etag),
            Self::Date(date) => representation.last_modified.is_some_and(|last_modified| {
                last_modified.is_strong_for_if_range() && last_modified.timestamp() <= *date
            }),
        }
    }

    /// Serializes the canonical byte-correct field value.
    #[must_use]
    pub fn to_header_bytes(&self) -> Vec<u8> {
        match self {
            Self::EntityTag(tag) => tag.to_header_bytes(),
            Self::Date(date) => date.to_http_date().into_bytes(),
        }
    }
}

/// Preconditions supplied with a delivery request.
///
/// Field coexistence is intentional: [`evaluate_request`] applies RFC 9110's
/// precedence rules, including ignoring `If-Unmodified-Since` when `If-Match`
/// is present and ignoring `If-Modified-Since` when `If-None-Match` is present.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestPreconditions {
    /// The parsed `If-Match` value.
    if_match: Option<EntityTagCondition>,
    /// The parsed `If-Unmodified-Since` value.
    if_unmodified_since: Option<HttpTimestamp>,
    /// The parsed `If-None-Match` value.
    if_none_match: Option<EntityTagCondition>,
    /// The parsed `If-Modified-Since` value.
    if_modified_since: Option<HttpTimestamp>,
    /// The parsed `If-Range` value.
    if_range: Option<IfRangeCondition>,
}

impl RequestPreconditions {
    /// Constructs an effective parsed conditional contract.
    ///
    /// # Errors
    ///
    /// Returns [`RequestPreconditionsError::EmptyEntityTagList`] if either tag
    /// condition was programmatically constructed with no list members.
    pub fn new(
        if_match: Option<EntityTagCondition>,
        if_unmodified_since: Option<HttpTimestamp>,
        if_none_match: Option<EntityTagCondition>,
        if_modified_since: Option<HttpTimestamp>,
        if_range: Option<IfRangeCondition>,
    ) -> Result<Self, RequestPreconditionsError> {
        if [&if_match, &if_none_match].iter().any(|condition| {
            matches!(condition, Some(EntityTagCondition::Tags(tags)) if tags.is_empty())
        }) {
            return Err(RequestPreconditionsError::EmptyEntityTagList);
        }
        Ok(Self {
            if_match,
            if_unmodified_since,
            if_none_match,
            if_modified_since,
            if_range,
        })
    }
}

/// An invalid programmatically assembled conditional contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RequestPreconditionsError {
    /// `If-Match` or `If-None-Match` contained an empty tag list.
    #[error("entity-tag condition list cannot be empty")]
    EmptyEntityTagList,
}

/// A validated single byte-range request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingleByteRange {
    /// An inclusive `start-end` interval.
    Closed {
        /// The zero-based first byte.
        start: u64,
        /// The zero-based inclusive last byte.
        end: u64,
    },
    /// Every available byte from `start` onward.
    From {
        /// The zero-based first byte.
        start: u64,
    },
    /// At most the final `length` bytes.
    Suffix {
        /// The requested suffix length. Zero is syntactically valid but never
        /// satisfiable.
        length: u64,
    },
}

impl SingleByteRange {
    /// Parses one single-range `bytes=` field with an ASCII case-insensitive
    /// range unit.
    ///
    /// Leading and trailing optional whitespace around the whole field is
    /// accepted. Multiple ranges, internal whitespace, non-decimal numbers,
    /// overflow, and a closed interval whose start exceeds its end are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`ByteRangeError`] when the unit or single-range grammar is
    /// invalid.
    pub fn parse(value: &str) -> Result<Self, ByteRangeError> {
        let value = trim_ows(value);
        let (unit, spec) = value
            .split_once('=')
            .ok_or(ByteRangeError::UnsupportedUnit)?;
        if !unit.eq_ignore_ascii_case("bytes") {
            return Err(ByteRangeError::UnsupportedUnit);
        }
        if spec.is_empty() {
            return Err(ByteRangeError::Empty);
        }
        if spec.contains(',') {
            return Err(ByteRangeError::MultipleRanges);
        }
        if spec.bytes().any(|byte| byte == b' ' || byte == b'\t') {
            return Err(ByteRangeError::InternalWhitespace);
        }
        let (first, last) = spec.split_once('-').ok_or(ByteRangeError::MissingDash)?;
        if last.contains('-') {
            return Err(ByteRangeError::InvalidNumber);
        }
        match (first.is_empty(), last.is_empty()) {
            (true, true) => Err(ByteRangeError::Empty),
            (true, false) => Ok(Self::Suffix {
                length: parse_u64(last)?,
            }),
            (false, true) => Ok(Self::From {
                start: parse_u64(first)?,
            }),
            (false, false) => {
                let start = parse_u64(first)?;
                let end = parse_u64(last)?;
                if start > end {
                    return Err(ByteRangeError::Reversed);
                }
                Ok(Self::Closed { start, end })
            }
        }
    }

    /// Resolves this range against a complete representation length.
    #[must_use]
    pub fn resolve(self, complete_length: u64) -> RangeResolution {
        if complete_length == 0 {
            return RangeResolution::Unsatisfiable { complete_length };
        }
        let last_available = complete_length - 1;
        let resolved = match self {
            Self::Closed { start, end } if start <= end && start < complete_length => ByteRange {
                start,
                end: end.min(last_available),
            },
            Self::From { start } if start < complete_length => ByteRange {
                start,
                end: last_available,
            },
            Self::Suffix { length } if length > 0 => ByteRange {
                start: complete_length.saturating_sub(length),
                end: last_available,
            },
            _ => return RangeResolution::Unsatisfiable { complete_length },
        };
        RangeResolution::Partial(resolved)
    }

    /// Serializes the canonical `Range` field value.
    #[must_use]
    pub fn to_header_value(self) -> String {
        match self {
            Self::Closed { start, end } => format!("bytes={start}-{end}"),
            Self::From { start } => format!("bytes={start}-"),
            Self::Suffix { length } => format!("bytes=-{length}"),
        }
    }
}

/// A malformed or unsupported byte-range field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ByteRangeError {
    /// The range unit was not ASCII case-insensitive `bytes`.
    #[error("delivery supports only the bytes range unit")]
    UnsupportedUnit,
    /// The byte-range specifier was empty.
    #[error("byte range cannot be empty")]
    Empty,
    /// More than one range was requested.
    #[error("delivery supports exactly one byte range")]
    MultipleRanges,
    /// Whitespace occurred inside the range specifier.
    #[error("byte range cannot contain internal whitespace")]
    InternalWhitespace,
    /// The required range dash was absent.
    #[error("byte range is missing its dash")]
    MissingDash,
    /// A bound was non-decimal or exceeded `u64`.
    #[error("byte range contains an invalid number")]
    InvalidNumber,
    /// A closed range began after it ended.
    #[error("byte range start exceeds its end")]
    Reversed,
}

/// An inclusive resolved byte interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    /// The zero-based first byte.
    start: u64,
    /// The zero-based inclusive last byte.
    end: u64,
}

impl ByteRange {
    /// Returns the zero-based first byte.
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Returns the zero-based inclusive last byte.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.end
    }

    /// Returns the number of bytes in the interval.
    #[must_use]
    pub const fn length(self) -> u64 {
        self.end - self.start + 1
    }

    /// Serializes the exact resolved `Range` request field value.
    #[must_use]
    pub fn to_header_value(self) -> String {
        format!("bytes={}-{}", self.start, self.end)
    }
}

/// The result of applying a valid range to a representation length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeResolution {
    /// Serve the resolved interval with status 206.
    Partial(ByteRange),
    /// Return status 416 and advertise the complete length.
    Unsatisfiable {
        /// The representation's complete byte length.
        complete_length: u64,
    },
}

/// A read-only typed `Content-Range` response value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentRange(ContentRangeKind);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentRangeKind {
    Satisfied {
        start: u64,
        end: u64,
        complete_length: u64,
    },
    Unsatisfied {
        complete_length: u64,
    },
}

impl ContentRange {
    const fn satisfied(start: u64, end: u64, complete_length: u64) -> Self {
        Self(ContentRangeKind::Satisfied {
            start,
            end,
            complete_length,
        })
    }

    const fn unsatisfied(complete_length: u64) -> Self {
        Self(ContentRangeKind::Unsatisfied { complete_length })
    }

    /// Returns the satisfied byte interval, or `None` for `bytes */length`.
    #[must_use]
    pub const fn interval(self) -> Option<ByteRange> {
        match self.0 {
            ContentRangeKind::Satisfied { start, end, .. } => Some(ByteRange { start, end }),
            ContentRangeKind::Unsatisfied { .. } => None,
        }
    }

    /// Returns the complete representation length.
    #[must_use]
    pub const fn complete_length(self) -> u64 {
        match self.0 {
            ContentRangeKind::Satisfied {
                complete_length, ..
            }
            | ContentRangeKind::Unsatisfied { complete_length } => complete_length,
        }
    }
}

impl fmt::Display for ContentRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ContentRangeKind::Satisfied {
                start,
                end,
                complete_length,
            } => write!(formatter, "bytes {start}-{end}/{complete_length}"),
            ContentRangeKind::Unsatisfied { complete_length } => {
                write!(formatter, "bytes */{complete_length}")
            }
        }
    }
}

/// Whether verified content is immutable or mutable after publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentMutability {
    /// The path and content identity never change after publication.
    Immutable,
    /// The path is a pointer or index that can change.
    Mutable,
}

/// Whether a response is safe for shared public caches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponsePrivacy {
    /// The route and surface permit anonymous public caching.
    Public,
    /// The response depends on client authorization.
    Private,
}

/// Route/request response policy independent of representation existence.
///
/// This value is selected before object lookup, so private 404, 412, 416, 421,
/// redirect, and origin-failure outcomes cannot accidentally inherit a public
/// default from absent representation metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponsePolicy {
    privacy: ResponsePrivacy,
}

impl ResponsePolicy {
    /// Constructs a response policy from the already-authorized route privacy.
    #[must_use]
    pub const fn new(privacy: ResponsePrivacy) -> Self {
        Self { privacy }
    }

    /// Returns the selected response privacy.
    #[must_use]
    pub const fn privacy(self) -> ResponsePrivacy {
        self.privacy
    }

    /// Returns the cache policy for a terminal response without representation
    /// metadata.
    #[must_use]
    pub const fn terminal_cache_control(self) -> &'static str {
        match self.privacy {
            ResponsePrivacy::Private => PRIVATE_CACHE_CONTROL,
            ResponsePrivacy::Public => PUBLIC_TERMINAL_CACHE_CONTROL,
        }
    }
}

/// A closed terminal response class shared by every protocol rejection/failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalResponseKind {
    /// A request header failed shared parsing.
    MalformedHeader,
    /// The Range field failed shared parsing.
    MalformedRange,
    /// The method is not supported by delivery.
    MethodNotAllowed,
    /// No acceptable client authentication was supplied.
    Unauthenticated,
    /// The authenticated principal is not authorized.
    Forbidden,
    /// No eligible representation exists.
    NotFound,
    /// A validator selected 304.
    NotModified,
    /// A request precondition selected 412.
    PreconditionFailed,
    /// A valid range was unsatisfiable.
    RangeNotSatisfiable {
        /// The known complete representation length.
        complete_length: u64,
    },
    /// A direct route reached Hub.
    MisdirectedRequest,
    /// An origin failure was sanitized.
    BadGateway,
    /// An unexpected internal failure was sanitized.
    InternalServerError,
}

/// One policy-bearing terminal response for every non-body outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalResponse {
    kind: TerminalResponseKind,
    policy: ResponsePolicy,
}

impl TerminalResponse {
    /// Constructs a terminal response from a closed reason and route policy.
    #[must_use]
    pub const fn new(kind: TerminalResponseKind, policy: ResponsePolicy) -> Self {
        Self { kind, policy }
    }

    /// Returns the closed terminal reason.
    #[must_use]
    pub const fn kind(self) -> TerminalResponseKind {
        self.kind
    }

    /// Returns the exact HTTP status.
    #[must_use]
    pub const fn status_code(self) -> u16 {
        match self.kind {
            TerminalResponseKind::MalformedHeader | TerminalResponseKind::MalformedRange => 400,
            TerminalResponseKind::MethodNotAllowed => 405,
            TerminalResponseKind::Unauthenticated => 401,
            TerminalResponseKind::Forbidden => 403,
            TerminalResponseKind::NotFound => 404,
            TerminalResponseKind::NotModified => 304,
            TerminalResponseKind::PreconditionFailed => 412,
            TerminalResponseKind::RangeNotSatisfiable { .. } => 416,
            TerminalResponseKind::MisdirectedRequest => 421,
            TerminalResponseKind::BadGateway => 502,
            TerminalResponseKind::InternalServerError => 500,
        }
    }

    /// Returns the route/request privacy-safe cache policy.
    #[must_use]
    pub const fn cache_control(self) -> &'static str {
        self.policy.terminal_cache_control()
    }

    /// Returns a fixed non-sensitive response message.
    #[must_use]
    pub const fn public_message(self) -> &'static str {
        match self.kind {
            TerminalResponseKind::MalformedHeader => "malformed request header",
            TerminalResponseKind::MalformedRange => "malformed range",
            TerminalResponseKind::MethodNotAllowed => "method not allowed",
            TerminalResponseKind::Unauthenticated => "authentication required",
            TerminalResponseKind::Forbidden => "forbidden",
            TerminalResponseKind::NotFound => "not found",
            TerminalResponseKind::NotModified => "not modified",
            TerminalResponseKind::PreconditionFailed => "precondition failed",
            TerminalResponseKind::RangeNotSatisfiable { .. } => "range not satisfiable",
            TerminalResponseKind::MisdirectedRequest => "misdirected request",
            TerminalResponseKind::BadGateway => "origin unavailable",
            TerminalResponseKind::InternalServerError => "internal server error",
        }
    }

    /// Returns the derived unsatisfied `Content-Range` for status 416.
    #[must_use]
    pub const fn content_range(self) -> Option<ContentRange> {
        match self.kind {
            TerminalResponseKind::RangeNotSatisfiable { complete_length } => {
                Some(ContentRange::unsatisfied(complete_length))
            }
            _ => None,
        }
    }
}

impl MethodError {
    /// Converts method rejection into the shared policy-bearing response.
    #[must_use]
    pub const fn terminal_response(self, policy: ResponsePolicy) -> TerminalResponse {
        TerminalResponse::new(TerminalResponseKind::MethodNotAllowed, policy)
    }
}

impl ByteRangeError {
    /// Converts malformed range syntax into the shared policy-bearing response.
    #[must_use]
    pub const fn terminal_response(self, policy: ResponsePolicy) -> TerminalResponse {
        TerminalResponse::new(TerminalResponseKind::MalformedRange, policy)
    }
}

/// Marks a shared request-header parsing failure safe to expose only as 400.
pub trait HeaderParseFailure {}

impl HeaderParseFailure for EntityTagError {}
impl HeaderParseFailure for EntityTagConditionError {}
impl HeaderParseFailure for HttpDateError {}
impl HeaderParseFailure for ConnectionOptionsError {}

/// Converts any shared malformed-header error to the one policy-bearing 400.
#[must_use]
pub fn malformed_header_response<E: HeaderParseFailure>(
    _error: E,
    policy: ResponsePolicy,
) -> TerminalResponse {
    TerminalResponse::new(TerminalResponseKind::MalformedHeader, policy)
}

/// Verified representation metadata used to derive client response headers.
///
/// The fields are private so adapters cannot accidentally substitute mutable
/// origin headers after verification. Immutable content requires a strong ETag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRepresentation {
    complete_length: u64,
    etag: EntityTag,
    last_modified: Option<LastModifiedValidator>,
    content_type: String,
    mutability: ContentMutability,
}

impl VerifiedRepresentation {
    /// Constructs metadata after object identity and size verification.
    ///
    /// `content_type` must satisfy the HTTP media-type grammar, including valid
    /// token or quoted parameter values and header-safe bytes. Immutable
    /// representations require a strong ETag so range resumption cannot be
    /// authorized by a weak validator.
    ///
    /// # Errors
    ///
    /// Returns [`RepresentationMetadataError`] for a weak immutable validator
    /// or a response-splitting/invalid content type.
    pub fn new(
        complete_length: u64,
        etag: EntityTag,
        last_modified: Option<LastModifiedValidator>,
        content_type: impl Into<String>,
        mutability: ContentMutability,
    ) -> Result<Self, RepresentationMetadataError> {
        let content_type = content_type.into();
        if !is_media_type(&content_type) {
            return Err(RepresentationMetadataError::InvalidContentType);
        }
        if mutability == ContentMutability::Immutable && etag.is_weak() {
            return Err(RepresentationMetadataError::WeakImmutableEtag);
        }
        Ok(Self {
            complete_length,
            etag,
            last_modified,
            content_type,
            mutability,
        })
    }

    /// Returns the complete representation length.
    #[must_use]
    pub const fn complete_length(&self) -> u64 {
        self.complete_length
    }

    /// Returns the verified entity tag.
    #[must_use]
    pub const fn etag(&self) -> &EntityTag {
        &self.etag
    }

    /// Returns the verified last-modified timestamp, when one is known.
    #[must_use]
    pub const fn last_modified(&self) -> Option<HttpTimestamp> {
        match self.last_modified {
            Some(last_modified) => Some(last_modified.timestamp()),
            None => None,
        }
    }

    /// Returns the verified content type.
    #[must_use]
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    /// Returns the verified content mutability.
    #[must_use]
    pub const fn mutability(&self) -> ContentMutability {
        self.mutability
    }

    /// Derives the only permitted cache policy from verified properties and
    /// the independently selected route/request response policy.
    #[must_use]
    pub const fn cache_control(&self, policy: ResponsePolicy) -> &'static str {
        match (policy.privacy, self.mutability) {
            (ResponsePrivacy::Private, _) => PRIVATE_CACHE_CONTROL,
            (ResponsePrivacy::Public, ContentMutability::Immutable) => {
                PUBLIC_IMMUTABLE_CACHE_CONTROL
            }
            (ResponsePrivacy::Public, ContentMutability::Mutable) => PUBLIC_MUTABLE_CACHE_CONTROL,
        }
    }
}

/// A canonical storage-relative object path selected by topology mapping.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalOriginObjectPath(String);

impl CanonicalOriginObjectPath {
    /// Parses a nonempty storage-relative path without aliases or traversal.
    ///
    /// # Errors
    ///
    /// Returns [`OriginObjectPathError`] for an absolute path, empty/dot
    /// segment, backslash, query/fragment, control byte, or non-NFC text.
    pub fn parse(value: &str) -> Result<Self, OriginObjectPathError> {
        if value.is_empty() {
            return Err(OriginObjectPathError::Empty);
        }
        if value.starts_with('/') {
            return Err(OriginObjectPathError::Absolute);
        }
        if value.contains('?') || value.contains('#') {
            return Err(OriginObjectPathError::QueryOrFragment);
        }
        if value
            .bytes()
            .any(|byte| byte == b'\\' || byte.is_ascii_control())
        {
            return Err(OriginObjectPathError::UnsafeByte);
        }
        if value
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        {
            return Err(OriginObjectPathError::UnsafeSegment);
        }
        use unicode_normalization::UnicodeNormalization as _;
        if value.nfc().collect::<String>() != value {
            return Err(OriginObjectPathError::NonCanonicalUnicode);
        }
        Ok(Self(value.to_string()))
    }

    /// Returns the canonical storage-relative path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An invalid mapped origin object path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OriginObjectPathError {
    /// The mapped path was empty.
    #[error("origin object path cannot be empty")]
    Empty,
    /// The mapped path was absolute.
    #[error("origin object path must be storage-relative")]
    Absolute,
    /// A query or fragment was present.
    #[error("origin object path cannot contain a query or fragment")]
    QueryOrFragment,
    /// A control byte or backslash was present.
    #[error("origin object path contains an unsafe byte")]
    UnsafeByte,
    /// An empty or dot segment was present.
    #[error("origin object path contains an unsafe segment")]
    UnsafeSegment,
    /// Unicode was not in its canonical NFC representation.
    #[error("origin object path must be NFC-normalized")]
    NonCanonicalUnicode,
}

/// Proof that one exact object is present and publication-eligible.
///
/// There is deliberately no negative value. Absence is decided before an
/// origin is opened and therefore cannot be passed to origin success/status
/// validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExactPublicationEligibility {
    presence_revision: u64,
    publication_generation: u64,
}

impl ExactPublicationEligibility {
    /// Constructs a proof from nonzero exact-presence and publication revisions.
    ///
    /// # Errors
    ///
    /// Returns [`ExactPublicationEligibilityError`] if either revision is zero.
    pub fn new(
        presence_revision: u64,
        publication_generation: u64,
    ) -> Result<Self, ExactPublicationEligibilityError> {
        if presence_revision == 0 {
            return Err(ExactPublicationEligibilityError::ZeroPresenceRevision);
        }
        if publication_generation == 0 {
            return Err(ExactPublicationEligibilityError::ZeroPublicationGeneration);
        }
        Ok(Self {
            presence_revision,
            publication_generation,
        })
    }

    /// Returns the exact presence revision.
    #[must_use]
    pub const fn presence_revision(self) -> u64 {
        self.presence_revision
    }

    /// Returns the publication generation that made the object eligible.
    #[must_use]
    pub const fn publication_generation(self) -> u64 {
        self.publication_generation
    }
}

/// An invalid exact publication-eligibility proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ExactPublicationEligibilityError {
    /// Exact presence revision zero is not observed state.
    #[error("exact presence revision must be nonzero")]
    ZeroPresenceRevision,
    /// Publication generation zero is not an eligible watermark.
    #[error("publication generation must be nonzero")]
    ZeroPublicationGeneration,
}

/// Invalid supposedly verified response metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RepresentationMetadataError {
    /// Immutable content was assigned a weak entity tag.
    #[error("immutable content requires a strong ETag")]
    WeakImmutableEtag,
    /// The content type was not a safe RFC media type with valid parameters.
    #[error("content type is not a valid safe HTTP media type")]
    InvalidContentType,
}

/// The complete protocol decision for one `GET` or `HEAD` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestDecision {
    /// Serve the complete representation with status 200.
    ServeFull {
        /// The admitted request method.
        method: DeliveryMethod,
    },
    /// Serve one interval with status 206.
    ServePartial {
        /// The resolved inclusive byte range.
        range: ByteRange,
    },
    /// Return status 304 without a body.
    NotModified,
    /// Return status 412 without reading the origin body.
    PreconditionFailed,
    /// Return status 416 with an unsatisfied `Content-Range` value.
    RangeNotSatisfiable {
        /// The complete representation length.
        complete_length: u64,
    },
    /// Return an ordinary status 404 for an absent representation.
    NotFound,
}

impl RequestDecision {
    /// Returns the HTTP status code for this decision.
    #[must_use]
    pub const fn status_code(self) -> u16 {
        match self {
            Self::ServeFull { .. } => 200,
            Self::ServePartial { .. } => 206,
            Self::NotModified => 304,
            Self::PreconditionFailed => 412,
            Self::RangeNotSatisfiable { .. } => 416,
            Self::NotFound => 404,
        }
    }

    /// Returns whether a response body may be streamed for this decision.
    #[must_use]
    pub const fn sends_body(self) -> bool {
        matches!(
            self,
            Self::ServeFull {
                method: DeliveryMethod::Get
            } | Self::ServePartial { .. }
        )
    }
}

/// An opaque evaluated response coupled to its policy and object context.
///
/// A representation-bearing decision can be created only by evaluating a
/// [`DeliveryObjectContext`]. Metadata derivation therefore cannot accept an
/// unrelated representation argument.
#[derive(Debug)]
pub struct EvaluatedResponse<'a> {
    decision: RequestDecision,
    context: Option<&'a DeliveryObjectContext>,
    policy: ResponsePolicy,
    method: DeliveryMethod,
    preconditions: RequestPreconditions,
    effective_range: Option<SingleByteRange>,
}

impl<'a> EvaluatedResponse<'a> {
    /// Returns the protocol outcome without exposing a metadata constructor.
    #[must_use]
    pub const fn decision(&self) -> RequestDecision {
        self.decision
    }

    /// Returns the response policy selected before lookup.
    #[must_use]
    pub const fn policy(&self) -> ResponsePolicy {
        self.policy
    }

    /// Returns the coupled object context when one exists.
    #[must_use]
    pub const fn context(&self) -> Option<&'a DeliveryObjectContext> {
        self.context
    }

    /// Returns the exact request method.
    #[must_use]
    pub const fn method(&self) -> DeliveryMethod {
        self.method
    }

    /// Returns the shared parsed conditional contract.
    #[must_use]
    pub const fn preconditions(&self) -> &RequestPreconditions {
        &self.preconditions
    }

    /// Returns the effective range contract; HEAD always returns `None`.
    #[must_use]
    pub const fn effective_range(&self) -> Option<SingleByteRange> {
        self.effective_range
    }

    /// Derives read-only allowlisted response metadata from the coupled state.
    #[must_use]
    pub fn response_metadata(&self) -> DerivedResponseMetadata<'a> {
        let representation = self.context.map(DeliveryObjectContext::representation);
        let mut metadata = DerivedResponseMetadata::terminal(self.policy);
        match self.decision {
            RequestDecision::ServeFull { .. } => {
                if let Some(representation) = representation {
                    metadata =
                        DerivedResponseMetadata::for_representation(representation, self.policy);
                    metadata.content_length = Some(representation.complete_length);
                }
            }
            RequestDecision::ServePartial { range } => {
                if let Some(representation) = representation {
                    metadata =
                        DerivedResponseMetadata::for_representation(representation, self.policy);
                    metadata.content_length = Some(range.length());
                    metadata.content_range = Some(ContentRange::satisfied(
                        range.start,
                        range.end,
                        representation.complete_length,
                    ));
                }
            }
            RequestDecision::NotModified => {
                if let Some(representation) = representation {
                    metadata =
                        DerivedResponseMetadata::for_representation(representation, self.policy);
                }
            }
            RequestDecision::RangeNotSatisfiable { complete_length } => {
                metadata.accept_ranges = true;
                metadata.content_range = Some(ContentRange::unsatisfied(complete_length));
            }
            RequestDecision::PreconditionFailed | RequestDecision::NotFound => {}
        }
        metadata
    }

    /// Returns the shared terminal response for a non-body outcome.
    #[must_use]
    pub const fn terminal_response(&self) -> Option<TerminalResponse> {
        let kind = match self.decision {
            RequestDecision::ServeFull { .. } | RequestDecision::ServePartial { .. } => {
                return None;
            }
            RequestDecision::NotModified => TerminalResponseKind::NotModified,
            RequestDecision::PreconditionFailed => TerminalResponseKind::PreconditionFailed,
            RequestDecision::RangeNotSatisfiable { complete_length } => {
                TerminalResponseKind::RangeNotSatisfiable { complete_length }
            }
            RequestDecision::NotFound => TerminalResponseKind::NotFound,
        };
        Some(TerminalResponse::new(kind, self.policy))
    }
}

/// Applies RFC precondition precedence, range gating, and `GET`/`HEAD` rules.
///
/// `HEAD` ignores `Range` and `If-Range`, but evaluates every ordinary
/// precondition exactly as the corresponding `GET`. `If-Range` is evaluated
/// only after all ordinary preconditions pass. An absent representation can
/// still produce 412 for `If-Match`; otherwise it produces an ordinary 404.
#[must_use]
fn evaluate_request(
    method: DeliveryMethod,
    preconditions: &RequestPreconditions,
    range: Option<SingleByteRange>,
    representation: Option<&VerifiedRepresentation>,
) -> RequestDecision {
    let current_etag = representation.map(VerifiedRepresentation::etag);

    if let Some(if_match) = &preconditions.if_match {
        if !if_match.matches_strongly(current_etag) {
            return RequestDecision::PreconditionFailed;
        }
    } else if let (Some(since), Some(last_modified)) = (
        preconditions.if_unmodified_since,
        representation.and_then(VerifiedRepresentation::last_modified),
    ) {
        if last_modified > since {
            return RequestDecision::PreconditionFailed;
        }
    }

    if let Some(if_none_match) = &preconditions.if_none_match {
        if if_none_match.matches_weakly(current_etag) {
            return RequestDecision::NotModified;
        }
    } else if let (Some(since), Some(last_modified)) = (
        preconditions.if_modified_since,
        representation.and_then(VerifiedRepresentation::last_modified),
    ) {
        if last_modified <= since {
            return RequestDecision::NotModified;
        }
    }

    let Some(representation) = representation else {
        return RequestDecision::NotFound;
    };
    if method == DeliveryMethod::Head {
        return RequestDecision::ServeFull { method };
    }
    let Some(range) = range else {
        return RequestDecision::ServeFull { method };
    };
    if preconditions
        .if_range
        .as_ref()
        .is_some_and(|condition| !condition.matches(representation))
    {
        return RequestDecision::ServeFull { method };
    }
    match range.resolve(representation.complete_length) {
        RangeResolution::Partial(range) => RequestDecision::ServePartial { range },
        RangeResolution::Unsatisfiable { complete_length } => {
            RequestDecision::RangeNotSatisfiable { complete_length }
        }
    }
}

/// Evaluates one verified representation with the shared conditional/range kernel.
///
/// This entry point is for protocol-specific delivery surfaces, such as signed
/// disk images, that already proved exact publication eligibility separately
/// and therefore do not need a full [`DeliveryObjectContext`]. It preserves
/// the same precondition precedence, `HEAD` behavior, and range resolution as
/// ordinary delivery routes.
#[must_use]
pub fn evaluate_verified_representation(
    method: DeliveryMethod,
    preconditions: &RequestPreconditions,
    range: Option<SingleByteRange>,
    representation: &VerifiedRepresentation,
) -> RequestDecision {
    evaluate_request(method, preconditions, range, Some(representation))
}

impl DeliveryObjectContext {
    /// Evaluates a request while retaining this exact object context.
    #[must_use]
    pub fn evaluate<'a>(
        &'a self,
        method: DeliveryMethod,
        preconditions: &RequestPreconditions,
        range: Option<SingleByteRange>,
        policy: ResponsePolicy,
    ) -> EvaluatedResponse<'a> {
        EvaluatedResponse {
            decision: evaluate_request(method, preconditions, range, Some(self.representation())),
            context: Some(self),
            policy,
            method,
            preconditions: preconditions.clone(),
            effective_range: if method == DeliveryMethod::Head {
                None
            } else {
                range
            },
        }
    }
}

/// Evaluates a request after exact lookup proved that no representation exists.
#[must_use]
pub fn evaluate_absent_request(
    method: DeliveryMethod,
    preconditions: &RequestPreconditions,
    range: Option<SingleByteRange>,
    policy: ResponsePolicy,
) -> EvaluatedResponse<'static> {
    EvaluatedResponse {
        decision: evaluate_request(method, preconditions, range, None),
        context: None,
        policy,
        method,
        preconditions: preconditions.clone(),
        effective_range: if method == DeliveryMethod::Head {
            None
        } else {
            range
        },
    }
}

/// Response metadata derived exclusively from a verified representation.
///
/// These are the only content/cache fields an adapter may emit for a proxied
/// object. `last_modified` remains typed seconds for adapter-local HTTP-date
/// formatting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedResponseMetadata<'a> {
    accept_ranges: bool,
    content_range: Option<ContentRange>,
    content_length: Option<u64>,
    content_type: Option<&'a str>,
    etag: Option<&'a EntityTag>,
    last_modified: Option<HttpTimestamp>,
    cache_control: Option<&'static str>,
}

impl<'a> DerivedResponseMetadata<'a> {
    fn terminal(policy: ResponsePolicy) -> Self {
        Self {
            accept_ranges: false,
            content_range: None,
            content_length: None,
            content_type: None,
            etag: None,
            last_modified: None,
            cache_control: Some(policy.terminal_cache_control()),
        }
    }

    fn for_representation(
        representation: &'a VerifiedRepresentation,
        policy: ResponsePolicy,
    ) -> Self {
        Self {
            accept_ranges: true,
            content_range: None,
            content_length: None,
            content_type: Some(representation.content_type()),
            etag: Some(representation.etag()),
            last_modified: representation.last_modified(),
            cache_control: Some(representation.cache_control(policy)),
        }
    }

    /// Returns whether to emit `Accept-Ranges: bytes`.
    #[must_use]
    pub const fn accepts_byte_ranges(&self) -> bool {
        self.accept_ranges
    }

    /// Returns the derived typed `Content-Range`, when required.
    #[must_use]
    pub const fn content_range(&self) -> Option<ContentRange> {
        self.content_range
    }

    /// Returns the selected response length or would-be HEAD body length.
    #[must_use]
    pub const fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    /// Returns the verified content type.
    #[must_use]
    pub const fn content_type(&self) -> Option<&'a str> {
        self.content_type
    }

    /// Returns the verified entity tag.
    #[must_use]
    pub const fn etag(&self) -> Option<&'a EntityTag> {
        self.etag
    }

    /// Returns the verified last-modified timestamp.
    #[must_use]
    pub const fn last_modified(&self) -> Option<HttpTimestamp> {
        self.last_modified
    }

    /// Returns the derived cache-control value.
    #[must_use]
    pub const fn cache_control(&self) -> Option<&'static str> {
        self.cache_control
    }
}

/// An origin response field whose value may be checked against verified data.
///
/// A candidate is not automatically safe to forward. Adapters parse it, compare
/// it with [`VerifiedRepresentation`] and the selected range, and emit the
/// derived value from [`DerivedResponseMetadata`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginMetadataField {
    /// `Accept-Ranges`.
    AcceptRanges,
    /// `Content-Range`.
    ContentRange,
    /// `Content-Length`.
    ContentLength,
    /// `Content-Type`.
    ContentType,
    /// `ETag`.
    Etag,
    /// `Last-Modified`.
    LastModified,
    /// `Cache-Control`.
    CacheControl,
}

/// Why an origin response header must not reach the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginHeaderStripReason {
    /// The field is hop-by-hop, including a token nominated by `Connection`.
    HopByHop,
    /// The field carries an origin authentication challenge or credential.
    OriginAuthentication,
    /// The field attempts to set client state.
    SetCookie,
    /// The field attempts to redirect the client to an origin location.
    Location,
    /// The field name is invalid HTTP token syntax.
    InvalidName,
    /// The field is not in the verified metadata allowlist.
    NotAllowlisted,
}

/// The disposition of one origin response header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginHeaderDisposition {
    /// Parse and verify this metadata candidate, then emit the derived value.
    Verify(OriginMetadataField),
    /// Drop the header for the stated reason.
    Strip(OriginHeaderStripReason),
}

/// Canonical field names nominated by origin `Connection` headers.
///
/// Parsing lives in the shared kernel so native and Worker adapters cannot
/// disagree about dynamically declared hop-by-hop fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConnectionOptions(Vec<String>);

impl ConnectionOptions {
    /// Parses all origin `Connection` field values as comma-separated tokens.
    ///
    /// Names are normalized to lowercase ASCII. Empty members and invalid HTTP
    /// token bytes fail closed instead of allowing a nominated header through.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionOptionsError`] when any field value contains an
    /// empty or invalid option.
    pub fn parse(values: &[&str]) -> Result<Self, ConnectionOptionsError> {
        let mut options = Vec::new();
        for value in values {
            for member in value.split(',') {
                let member = trim_ows(member);
                if member.is_empty() {
                    return Err(ConnectionOptionsError::EmptyOption);
                }
                if !is_http_token(member) {
                    return Err(ConnectionOptionsError::InvalidOption);
                }
                let normalized = member.to_ascii_lowercase();
                if !options.contains(&normalized) {
                    options.push(normalized);
                }
            }
        }
        Ok(Self(options))
    }

    fn contains(&self, name: &str) -> bool {
        self.0
            .iter()
            .any(|option| option.eq_ignore_ascii_case(name))
    }
}

/// An invalid origin `Connection` header value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ConnectionOptionsError {
    /// A field value began or ended with a comma or contained `,,`.
    #[error("Connection header contains an empty option")]
    EmptyOption,
    /// An option was not valid HTTP token syntax.
    #[error("Connection header contains an invalid option")]
    InvalidOption,
}

/// Classifies an origin response header without trusting its value.
///
/// `connection_options` take priority over the metadata allowlist, preventing
/// a malicious origin from nominating `Content-Length` or another normally
/// checked field as hop-by-hop.
#[must_use]
pub fn classify_origin_response_header(
    name: &str,
    connection_options: &ConnectionOptions,
) -> OriginHeaderDisposition {
    if !is_http_token(name) {
        return OriginHeaderDisposition::Strip(OriginHeaderStripReason::InvalidName);
    }
    if connection_options.contains(name) || is_standard_hop_by_hop(name) {
        return OriginHeaderDisposition::Strip(OriginHeaderStripReason::HopByHop);
    }
    if name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("www-authenticate")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("authentication-info")
        || name.eq_ignore_ascii_case("proxy-authentication-info")
    {
        return OriginHeaderDisposition::Strip(OriginHeaderStripReason::OriginAuthentication);
    }
    if name.eq_ignore_ascii_case("set-cookie") || name.eq_ignore_ascii_case("set-cookie2") {
        return OriginHeaderDisposition::Strip(OriginHeaderStripReason::SetCookie);
    }
    if name.eq_ignore_ascii_case("location") || name.eq_ignore_ascii_case("content-location") {
        return OriginHeaderDisposition::Strip(OriginHeaderStripReason::Location);
    }
    let field = if name.eq_ignore_ascii_case("accept-ranges") {
        OriginMetadataField::AcceptRanges
    } else if name.eq_ignore_ascii_case("content-range") {
        OriginMetadataField::ContentRange
    } else if name.eq_ignore_ascii_case("content-length") {
        OriginMetadataField::ContentLength
    } else if name.eq_ignore_ascii_case("content-type") {
        OriginMetadataField::ContentType
    } else if name.eq_ignore_ascii_case("etag") {
        OriginMetadataField::Etag
    } else if name.eq_ignore_ascii_case("last-modified") {
        OriginMetadataField::LastModified
    } else if name.eq_ignore_ascii_case("cache-control") {
        OriginMetadataField::CacheControl
    } else {
        return OriginHeaderDisposition::Strip(OriginHeaderStripReason::NotAllowlisted);
    };
    OriginHeaderDisposition::Verify(field)
}

/// A failure observed while opening or streaming one selected origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginFailure {
    /// The connection failed before response headers were received.
    ConnectBeforeHeaders,
    /// The request timed out before response headers were received.
    TimeoutBeforeHeaders,
    /// The origin returned an HTTP status.
    Status {
        /// The origin status code.
        status: u16,
    },
    /// An independently detected exact-presence mismatch.
    ExactPresenceMismatch,
    /// Bytes or metadata failed verified integrity checks.
    VerifiedCorruption,
    /// A transport or integrity failure occurred after client response headers
    /// or body bytes had been sent.
    AfterResponseStarted,
}

/// A sanitized action for an origin failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginFailureDisposition {
    /// Try another eligible placement before sending response headers; expose a
    /// generic 502 if all eligible attempts fail.
    RetryAnotherPlacement,
    /// Return a generic 502 without exposing origin status, body, or headers.
    SanitizedBadGateway,
    /// Abort the already-started response; never splice a second origin.
    AbortStartedResponse,
}

/// The sanitized interpretation of an origin HTTP response status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginStatusDisposition {
    /// Accept a complete representation response with status 200.
    AcceptFull {
        /// The exact presence/publication proof authorizing this origin read.
        eligibility: ExactPublicationEligibility,
    },
    /// Accept a partial representation response with status 206, subject to
    /// independent `Content-Range`, length, and validator verification.
    AcceptPartial {
        /// The exact presence/publication proof authorizing this origin read.
        eligibility: ExactPublicationEligibility,
    },
    /// Treat the status as a typed origin failure.
    Failure(OriginFailureDisposition),
}

/// The body status expected from the selected origin read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginBodyExpectation {
    /// The Hub requested the complete representation and expects status 200.
    Full,
    /// The Hub requested the selected byte interval and expects status 206.
    Partial,
}

impl OriginFailureDisposition {
    /// Returns the final client status when this disposition can begin a new
    /// response, or `None` when an already-started stream must be aborted.
    #[must_use]
    pub const fn client_status(self) -> Option<u16> {
        match self {
            Self::RetryAnotherPlacement | Self::SanitizedBadGateway => Some(502),
            Self::AbortStartedResponse => None,
        }
    }

    /// Returns the fixed public error text, without origin details.
    #[must_use]
    pub const fn public_message(self) -> Option<&'static str> {
        match self {
            Self::RetryAnotherPlacement | Self::SanitizedBadGateway => Some("origin unavailable"),
            Self::AbortStartedResponse => None,
        }
    }

    /// Returns the shared terminal response after retries are exhausted.
    ///
    /// An already-started response cannot emit replacement headers.
    #[must_use]
    pub const fn terminal_response(self, policy: ResponsePolicy) -> Option<TerminalResponse> {
        match self {
            Self::AbortStartedResponse => None,
            Self::RetryAnotherPlacement | Self::SanitizedBadGateway => Some(TerminalResponse::new(
                TerminalResponseKind::BadGateway,
                policy,
            )),
        }
    }
}

/// Classifies origin failure without leaking origin details or retrying an
/// in-progress response.
#[must_use]
pub const fn classify_origin_failure(failure: OriginFailure) -> OriginFailureDisposition {
    match failure {
        OriginFailure::ConnectBeforeHeaders
        | OriginFailure::TimeoutBeforeHeaders
        | OriginFailure::ExactPresenceMismatch
        | OriginFailure::VerifiedCorruption => OriginFailureDisposition::RetryAnotherPlacement,
        OriginFailure::Status { status: 404 } => OriginFailureDisposition::RetryAnotherPlacement,
        OriginFailure::Status {
            status: 429 | 502 | 503 | 504,
            ..
        } => OriginFailureDisposition::RetryAnotherPlacement,
        OriginFailure::AfterResponseStarted => OriginFailureDisposition::AbortStartedResponse,
        OriginFailure::Status { .. } => OriginFailureDisposition::SanitizedBadGateway,
    }
}

/// Classifies an origin HTTP status before any client response is started.
///
/// A 200 is accepted only for a complete read and a 206 only for a ranged read;
/// a mismatch is verified corruption and may retry before response start. Hub
/// computes conditional outcomes itself, so origin redirects, 304, 416, and all
/// other unexpected statuses are never forwarded. The mandatory coupled object
/// context makes every origin 404 an exact-presence mismatch; ordinary absence
/// is decided before origin selection. Retryable status classes become a
/// generic 502 if failover is exhausted.
#[must_use]
pub const fn classify_origin_status(
    status: u16,
    expected: OriginBodyExpectation,
    context: &DeliveryObjectContext,
) -> OriginStatusDisposition {
    let eligibility = context.eligibility();
    match (status, expected) {
        (200, OriginBodyExpectation::Full) => OriginStatusDisposition::AcceptFull { eligibility },
        (206, OriginBodyExpectation::Partial) => {
            OriginStatusDisposition::AcceptPartial { eligibility }
        }
        (200 | 206, _) => {
            OriginStatusDisposition::Failure(OriginFailureDisposition::RetryAnotherPlacement)
        }
        _ => OriginStatusDisposition::Failure(classify_origin_failure(OriginFailure::Status {
            status,
        })),
    }
}

/// A non-secret pin to the only placement credential an origin request may use.
///
/// The adapter resolves this tuple to a secret internally. Client credentials
/// never inhabit this type and therefore cannot be confused with placement
/// authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementAuthBoundary {
    placement_id: String,
    binding_capability_id: String,
    binding_revision: u64,
}

impl PlacementAuthBoundary {
    /// Constructs an exact placement/binding capability revision pin.
    ///
    /// # Errors
    ///
    /// Returns [`PlacementAuthBoundaryError`] for an unsafe/empty stable id or
    /// revision zero.
    pub fn new(
        placement_id: impl Into<String>,
        binding_capability_id: impl Into<String>,
        binding_revision: u64,
    ) -> Result<Self, PlacementAuthBoundaryError> {
        let placement_id = placement_id.into();
        let binding_capability_id = binding_capability_id.into();
        if !is_stable_reference(&placement_id) {
            return Err(PlacementAuthBoundaryError::InvalidPlacementId);
        }
        if !is_stable_reference(&binding_capability_id) {
            return Err(PlacementAuthBoundaryError::InvalidCapabilityId);
        }
        if binding_revision == 0 {
            return Err(PlacementAuthBoundaryError::ZeroRevision);
        }
        Ok(Self {
            placement_id,
            binding_capability_id,
            binding_revision,
        })
    }

    /// Returns the pinned placement id.
    #[must_use]
    pub fn placement_id(&self) -> &str {
        &self.placement_id
    }

    /// Returns the pinned binding capability id.
    #[must_use]
    pub fn binding_capability_id(&self) -> &str {
        &self.binding_capability_id
    }

    /// Returns the exact pinned binding capability revision.
    #[must_use]
    pub const fn binding_revision(&self) -> u64 {
        self.binding_revision
    }
}

/// The fully coupled topology/publication/representation boundary for one read.
///
/// Native and Worker adapters must obtain this value after route mapping,
/// placement selection, exact-presence lookup, and publication-watermark
/// validation. Every origin request and redirect attestation consumes this
/// single context, preventing placement A, capability B, object C, or metadata
/// D from being combined after independent lookups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryObjectContext {
    request_path: CanonicalRoutePath,
    origin_object_path: CanonicalOriginObjectPath,
    authorization: PlacementAuthBoundary,
    eligibility: ExactPublicationEligibility,
    representation: VerifiedRepresentation,
    redirect_boundary: RedirectBoundaryRequirement,
}

/// The external network boundary a redirect capability must preserve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectBoundaryRequirement {
    /// No private-network proof is required for this route.
    Unrestricted,
    /// The capability must remain inside this exact private-network revision.
    PrivateNetwork(PrivateNetworkBoundaryRequirement),
}

impl DeliveryObjectContext {
    /// Couples one already-validated delivery object boundary.
    #[must_use]
    pub const fn new(
        request_path: CanonicalRoutePath,
        origin_object_path: CanonicalOriginObjectPath,
        authorization: PlacementAuthBoundary,
        eligibility: ExactPublicationEligibility,
        representation: VerifiedRepresentation,
        redirect_boundary: RedirectBoundaryRequirement,
    ) -> Self {
        Self {
            request_path,
            origin_object_path,
            authorization,
            eligibility,
            representation,
            redirect_boundary,
        }
    }

    /// Returns the canonical inbound request path.
    #[must_use]
    pub const fn request_path(&self) -> &CanonicalRoutePath {
        &self.request_path
    }

    /// Returns the mapped storage-relative object path.
    #[must_use]
    pub const fn origin_object_path(&self) -> &CanonicalOriginObjectPath {
        &self.origin_object_path
    }

    /// Returns the pinned placement authorization boundary.
    #[must_use]
    pub const fn authorization(&self) -> &PlacementAuthBoundary {
        &self.authorization
    }

    /// Returns the exact-presence/publication eligibility proof.
    #[must_use]
    pub const fn eligibility(&self) -> ExactPublicationEligibility {
        self.eligibility
    }

    /// Returns the verified representation metadata coupled to this object.
    #[must_use]
    pub const fn representation(&self) -> &VerifiedRepresentation {
        &self.representation
    }

    /// Returns the redirect network-boundary requirement selected by the route.
    #[must_use]
    pub const fn redirect_boundary(&self) -> &RedirectBoundaryRequirement {
        &self.redirect_boundary
    }
}

/// An invalid placement authorization boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PlacementAuthBoundaryError {
    /// The placement id is empty or outside the canonical stable-id profile.
    #[error("placement id is not a canonical stable reference")]
    InvalidPlacementId,
    /// The capability id is empty or outside the canonical stable-id profile.
    #[error("binding capability id is not a canonical stable reference")]
    InvalidCapabilityId,
    /// Revision zero cannot identify an observed immutable capability revision.
    #[error("binding capability revision must be nonzero")]
    ZeroRevision,
}

/// A derived outbound origin request field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginRequestHeader {
    /// A normalized exact `Range` value selected by Hub.
    Range(String),
    /// A canonical byte-correct `If-Match` value.
    IfMatch(Vec<u8>),
    /// A canonical `If-Unmodified-Since` value.
    IfUnmodifiedSince(String),
    /// A canonical byte-correct `If-None-Match` value.
    IfNoneMatch(Vec<u8>),
    /// A canonical `If-Modified-Since` value.
    IfModifiedSince(String),
    /// A canonical byte-correct `If-Range` value.
    IfRange(Vec<u8>),
    /// Resolve placement-scoped authorization internally; this is never a
    /// client-supplied `Authorization` value.
    PlacementAuthorization(PlacementAuthBoundary),
}

/// A complete safe outbound origin request contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundOriginRequest {
    method: DeliveryMethod,
    headers: Vec<OriginRequestHeader>,
    object: DeliveryObjectContext,
}

impl OutboundOriginRequest {
    /// Derives the only headers permitted on a proxied origin read.
    ///
    /// The range comes from Hub's resolved response decision rather than an
    /// unvalidated client string. Conditional fields are reserialized from
    /// shared parsed types, and authorization is a non-secret placement pin.
    /// Cookies, client authorization, proxy fields, forwarded identity, and all
    /// other client headers have no representation in the result.
    ///
    /// # Errors
    ///
    /// Returns [`OutboundOriginRequestError::NoOriginRead`] for a terminal
    /// 304/404/412/416 outcome.
    pub fn derive(response: &EvaluatedResponse<'_>) -> Result<Self, OutboundOriginRequestError> {
        let (method, range) = match response.decision() {
            RequestDecision::ServeFull { method } => (method, None),
            RequestDecision::ServePartial { range } => (DeliveryMethod::Get, Some(range)),
            RequestDecision::NotModified
            | RequestDecision::PreconditionFailed
            | RequestDecision::RangeNotSatisfiable { .. }
            | RequestDecision::NotFound => return Err(OutboundOriginRequestError::NoOriginRead),
        };
        let context = response
            .context()
            .ok_or(OutboundOriginRequestError::MissingObjectContext)?;
        let mut headers = Vec::new();
        if let Some(range) = range {
            headers.push(OriginRequestHeader::Range(range.to_header_value()));
        }
        let preconditions = response.preconditions();
        if let Some(condition) = &preconditions.if_match {
            headers.push(OriginRequestHeader::IfMatch(condition.to_header_bytes()));
        }
        if let Some(date) = preconditions.if_unmodified_since {
            headers.push(OriginRequestHeader::IfUnmodifiedSince(date.to_http_date()));
        }
        if let Some(condition) = &preconditions.if_none_match {
            headers.push(OriginRequestHeader::IfNoneMatch(
                condition.to_header_bytes(),
            ));
        }
        if let Some(date) = preconditions.if_modified_since {
            headers.push(OriginRequestHeader::IfModifiedSince(date.to_http_date()));
        }
        if range.is_some() {
            if let Some(condition) = &preconditions.if_range {
                headers.push(OriginRequestHeader::IfRange(condition.to_header_bytes()));
            }
        }
        headers.push(OriginRequestHeader::PlacementAuthorization(
            context.authorization().clone(),
        ));
        Ok(Self {
            method,
            headers,
            object: context.clone(),
        })
    }

    /// Returns the exact origin method.
    #[must_use]
    pub const fn method(&self) -> DeliveryMethod {
        self.method
    }

    /// Returns the closed ordered outbound header contract.
    #[must_use]
    pub fn headers(&self) -> &[OriginRequestHeader] {
        &self.headers
    }

    /// Returns the exact coupled object/topology/publication boundary to open.
    #[must_use]
    pub const fn object(&self) -> &DeliveryObjectContext {
        &self.object
    }
}

/// A response decision that must not open an origin body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OutboundOriginRequestError {
    /// Hub has already selected a terminal conditional/range/absence outcome.
    #[error("request decision does not permit an origin read")]
    NoOriginRead,
    /// An origin read was requested without a coupled eligible object context.
    #[error("origin request requires an eligible delivery object context")]
    MissingObjectContext,
}

/// A client request field eligible for shared parsing, never direct forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientRequestMetadataField {
    /// `Range`.
    Range,
    /// `If-Match`.
    IfMatch,
    /// `If-Unmodified-Since`.
    IfUnmodifiedSince,
    /// `If-None-Match`.
    IfNoneMatch,
    /// `If-Modified-Since`.
    IfModifiedSince,
    /// `If-Range`.
    IfRange,
}

/// Why a client request field cannot be copied to an origin request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientRequestHeaderStripReason {
    /// A static or `Connection`-nominated hop-by-hop field.
    HopByHop,
    /// Client authorization, cookies, or proxy authorization.
    ClientCredential,
    /// Forwarded network, proxy, or external-identity assertions.
    ForwardedIdentity,
    /// The field name is invalid HTTP token syntax.
    InvalidName,
    /// The field is outside the conditional/range parsing allowlist.
    NotAllowlisted,
}

/// The disposition of one inbound client field at the origin boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientRequestHeaderDisposition {
    /// Parse into the named shared type and later reserialize canonically.
    Parse(ClientRequestMetadataField),
    /// Drop the field for the stated reason.
    Strip(ClientRequestHeaderStripReason),
}

/// Classifies a client request header at the outbound origin boundary.
#[must_use]
pub fn classify_client_request_header(
    name: &str,
    connection_options: &ConnectionOptions,
) -> ClientRequestHeaderDisposition {
    if !is_http_token(name) {
        return ClientRequestHeaderDisposition::Strip(ClientRequestHeaderStripReason::InvalidName);
    }
    if connection_options.contains(name) || is_standard_hop_by_hop(name) {
        return ClientRequestHeaderDisposition::Strip(ClientRequestHeaderStripReason::HopByHop);
    }
    if ["authorization", "proxy-authorization", "cookie", "cookie2"]
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(name))
    {
        return ClientRequestHeaderDisposition::Strip(
            ClientRequestHeaderStripReason::ClientCredential,
        );
    }
    if name.eq_ignore_ascii_case("forwarded")
        || name.eq_ignore_ascii_case("via")
        || name.eq_ignore_ascii_case("x-real-ip")
        || name.to_ascii_lowercase().starts_with("x-forwarded-")
        || name.to_ascii_lowercase().starts_with("cf-")
        || name.eq_ignore_ascii_case("true-client-ip")
    {
        return ClientRequestHeaderDisposition::Strip(
            ClientRequestHeaderStripReason::ForwardedIdentity,
        );
    }
    let field = if name.eq_ignore_ascii_case("range") {
        ClientRequestMetadataField::Range
    } else if name.eq_ignore_ascii_case("if-match") {
        ClientRequestMetadataField::IfMatch
    } else if name.eq_ignore_ascii_case("if-unmodified-since") {
        ClientRequestMetadataField::IfUnmodifiedSince
    } else if name.eq_ignore_ascii_case("if-none-match") {
        ClientRequestMetadataField::IfNoneMatch
    } else if name.eq_ignore_ascii_case("if-modified-since") {
        ClientRequestMetadataField::IfModifiedSince
    } else if name.eq_ignore_ascii_case("if-range") {
        ClientRequestMetadataField::IfRange
    } else {
        return ClientRequestHeaderDisposition::Strip(
            ClientRequestHeaderStripReason::NotAllowlisted,
        );
    };
    ClientRequestHeaderDisposition::Parse(field)
}

/// A canonical, header-safe presigned HTTPS `Location` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalPresignedLocation(String);

impl CanonicalPresignedLocation {
    /// Parses a canonical absolute HTTPS capability URL.
    ///
    /// URL parsing libraries can discard C0 whitespace or normalize input. This
    /// constructor rejects every C0/DEL byte and requires the parser's canonical
    /// serialization to equal the original byte-for-byte, so the value checked
    /// here is exactly the value emitted in `Location` and signed by the origin.
    ///
    /// # Errors
    ///
    /// Returns [`CanonicalPresignedLocationError`] for unsafe bytes, any
    /// normalization discrepancy, non-HTTPS/userinfo/fragment/port-zero URLs,
    /// or an absent host.
    pub fn parse(value: impl Into<String>) -> Result<Self, CanonicalPresignedLocationError> {
        let value = value.into();
        if value.bytes().any(|byte| byte <= 0x1f || byte == 0x7f) {
            return Err(CanonicalPresignedLocationError::UnsafeByte);
        }
        let parsed = Url::parse(&value).map_err(|_| CanonicalPresignedLocationError::InvalidUrl)?;
        if parsed.scheme() != "https"
            || parsed.host().is_none()
            || parsed.port() == Some(0)
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(CanonicalPresignedLocationError::InvalidUrl);
        }
        if parsed.as_str() != value {
            return Err(CanonicalPresignedLocationError::NonCanonical);
        }
        Ok(Self(value))
    }

    /// Returns the exact canonical header value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An invalid presigned `Location` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CanonicalPresignedLocationError {
    /// A C0 control, CR/LF, or DEL byte was present.
    #[error("presigned Location contains an unsafe control byte")]
    UnsafeByte,
    /// The URL was not a safe absolute HTTPS URL.
    #[error("presigned Location is not a safe absolute HTTPS URL")]
    InvalidUrl,
    /// URL canonicalization would change the original header bytes.
    #[error("presigned Location must already be in canonical URL form")]
    NonCanonical,
}

/// A required private-network boundary revision for a redirect capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateNetworkBoundaryRequirement {
    boundary_id: String,
    revision: u64,
}

impl PrivateNetworkBoundaryRequirement {
    /// Constructs a required stable boundary/revision pair.
    ///
    /// # Errors
    ///
    /// Returns [`PrivateNetworkBoundaryError`] for an invalid id or revision zero.
    pub fn new(
        boundary_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, PrivateNetworkBoundaryError> {
        let boundary_id = boundary_id.into();
        if !is_stable_reference(&boundary_id) {
            return Err(PrivateNetworkBoundaryError::InvalidId);
        }
        if revision == 0 {
            return Err(PrivateNetworkBoundaryError::ZeroRevision);
        }
        Ok(Self {
            boundary_id,
            revision,
        })
    }

    /// Returns the stable boundary id.
    #[must_use]
    pub fn boundary_id(&self) -> &str {
        &self.boundary_id
    }

    /// Returns the exact required boundary revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

/// Evidence reported by the presigner/private-network reconciler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateNetworkBoundaryEvidence {
    /// The observed stable boundary id.
    pub boundary_id: String,
    /// The observed immutable boundary revision.
    pub revision: u64,
    /// Whether reconciliation verified the exact revision.
    pub verified: bool,
    /// The time through which the observation remains valid.
    pub valid_through: HttpTimestamp,
}

/// An invalid private-network boundary requirement or proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PrivateNetworkBoundaryError {
    /// The stable boundary id is invalid.
    #[error("private-network boundary id is invalid")]
    InvalidId,
    /// Revision zero is not an observed immutable revision.
    #[error("private-network boundary revision must be nonzero")]
    ZeroRevision,
}

/// Untrusted claims returned by a presigner before shared verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresignedCapabilityEvidence {
    /// The candidate canonical location.
    pub location: CanonicalPresignedLocation,
    /// The claimed expiry.
    pub expires_at: HttpTimestamp,
    /// The claimed exact method.
    pub method: DeliveryMethod,
    /// The claimed exact canonical inbound request path.
    pub request_path: CanonicalRoutePath,
    /// The claimed mapped origin object path.
    pub origin_object_path: CanonicalOriginObjectPath,
    /// The claimed placement binding capability and revision.
    pub authorization: PlacementAuthBoundary,
    /// The claimed unchanged conditional contract.
    pub preconditions: RequestPreconditions,
    /// The claimed effective range contract.
    pub range: Option<SingleByteRange>,
    /// Whether the provider completed presigning successfully.
    pub presign_succeeded: bool,
    /// Whether the returned capability signature was verified.
    pub signature_verified: bool,
    /// The observed private-network proof, when one is required.
    pub private_network: Option<PrivateNetworkBoundaryEvidence>,
}

/// A private proof that a presigned capability matches one evaluated object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresignedCapabilityAttestation {
    location: CanonicalPresignedLocation,
    expires_at: HttpTimestamp,
    method: DeliveryMethod,
    request_path: CanonicalRoutePath,
    origin_object_path: CanonicalOriginObjectPath,
    authorization: PlacementAuthBoundary,
    eligibility: ExactPublicationEligibility,
    representation: VerifiedRepresentation,
    preconditions: RequestPreconditions,
    range: Option<SingleByteRange>,
    private_network: Option<PrivateNetworkBoundaryRequirement>,
    status: PresignedCapabilityStatus,
}

/// The only status carried by a successfully verified capability attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresignedCapabilityStatus {
    /// Presigning succeeded and the resulting signature was verified.
    PresignedAndSignatureVerified,
}

impl PresignedCapabilityAttestation {
    /// Verifies presigner claims against one opaque evaluated object response.
    ///
    /// HEAD's effective range is always `None`, regardless of a client Range
    /// field. A private-network requirement additionally needs an exact verified
    /// boundary revision whose observation remains valid through capability
    /// expiry.
    ///
    /// # Errors
    ///
    /// Returns [`PresignedCapabilityAttestationError`] for terminal/absent
    /// responses, expired or overlong capability lifetimes, unsuccessful or
    /// unverified presigning, any object/method/placement/conditional/range
    /// claim mismatch, or missing/stale private-network proof.
    pub fn verify(
        evidence: PresignedCapabilityEvidence,
        response: &EvaluatedResponse<'_>,
        now: HttpTimestamp,
    ) -> Result<Self, PresignedCapabilityAttestationError> {
        if !matches!(
            response.decision(),
            RequestDecision::ServeFull { .. } | RequestDecision::ServePartial { .. }
        ) {
            return Err(PresignedCapabilityAttestationError::TerminalRequest);
        }
        let context = response
            .context()
            .ok_or(PresignedCapabilityAttestationError::MissingObjectContext)?;
        let ttl = evidence
            .expires_at
            .unix_seconds()
            .checked_sub(now.unix_seconds())
            .ok_or(PresignedCapabilityAttestationError::InvalidExpiry)?;
        if !(1..=300).contains(&ttl) {
            return Err(PresignedCapabilityAttestationError::InvalidExpiry);
        }
        if !evidence.presign_succeeded {
            return Err(PresignedCapabilityAttestationError::PresignFailed);
        }
        if !evidence.signature_verified {
            return Err(PresignedCapabilityAttestationError::SignatureUnverified);
        }
        if evidence.method != response.method()
            || &evidence.request_path != context.request_path()
            || &evidence.origin_object_path != context.origin_object_path()
            || &evidence.authorization != context.authorization()
            || evidence.preconditions != *response.preconditions()
            || evidence.range != response.effective_range()
        {
            return Err(PresignedCapabilityAttestationError::ClaimMismatch);
        }
        let verified_network = match (context.redirect_boundary(), evidence.private_network) {
            (RedirectBoundaryRequirement::Unrestricted, None) => None,
            (RedirectBoundaryRequirement::PrivateNetwork(required), Some(observed))
                if observed.verified
                    && observed.boundary_id == required.boundary_id
                    && observed.revision == required.revision
                    && observed.valid_through >= evidence.expires_at =>
            {
                Some(required.clone())
            }
            _ => return Err(PresignedCapabilityAttestationError::PrivateNetworkMismatch),
        };
        Ok(Self {
            location: evidence.location,
            expires_at: evidence.expires_at,
            method: evidence.method,
            request_path: context.request_path().clone(),
            origin_object_path: evidence.origin_object_path,
            authorization: evidence.authorization,
            eligibility: context.eligibility(),
            representation: context.representation().clone(),
            preconditions: evidence.preconditions,
            range: evidence.range,
            private_network: verified_network,
            status: PresignedCapabilityStatus::PresignedAndSignatureVerified,
        })
    }

    /// Returns the canonical header-safe `Location` value.
    #[must_use]
    pub const fn location(&self) -> &CanonicalPresignedLocation {
        &self.location
    }

    /// Returns the exact capability expiry.
    #[must_use]
    pub const fn expires_at(&self) -> HttpTimestamp {
        self.expires_at
    }

    /// Returns the exact signed method.
    #[must_use]
    pub const fn method(&self) -> DeliveryMethod {
        self.method
    }

    /// Returns the exact canonical inbound request path.
    #[must_use]
    pub const fn request_path(&self) -> &CanonicalRoutePath {
        &self.request_path
    }

    /// Returns the exact mapped origin object path.
    #[must_use]
    pub const fn origin_object_path(&self) -> &CanonicalOriginObjectPath {
        &self.origin_object_path
    }

    /// Returns the exact placement binding capability/revision pin.
    #[must_use]
    pub const fn authorization(&self) -> &PlacementAuthBoundary {
        &self.authorization
    }

    /// Returns the exact presence/publication proof used for selection.
    #[must_use]
    pub const fn eligibility(&self) -> ExactPublicationEligibility {
        self.eligibility
    }

    /// Returns the exact verified representation metadata used for evaluation.
    #[must_use]
    pub const fn representation(&self) -> &VerifiedRepresentation {
        &self.representation
    }

    /// Returns the unchanged parsed conditional contract.
    #[must_use]
    pub const fn preconditions(&self) -> &RequestPreconditions {
        &self.preconditions
    }

    /// Returns the effective signed range; HEAD is always `None`.
    #[must_use]
    pub const fn range(&self) -> Option<SingleByteRange> {
        self.range
    }

    /// Returns the exact verified private-network requirement, when applicable.
    #[must_use]
    pub const fn private_network(&self) -> Option<&PrivateNetworkBoundaryRequirement> {
        self.private_network.as_ref()
    }

    /// Returns proof that presigning and signature verification both succeeded.
    #[must_use]
    pub const fn status(&self) -> PresignedCapabilityStatus {
        self.status
    }
}

/// A failed presigned capability attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PresignedCapabilityAttestationError {
    /// Hub had already selected a terminal response.
    #[error("terminal request cannot produce a redirect capability")]
    TerminalRequest,
    /// The response was not coupled to an eligible object context.
    #[error("redirect capability requires an eligible object context")]
    MissingObjectContext,
    /// Expiry was not 1 through 300 seconds after verification time.
    #[error("redirect capability expiry must be 1 through 300 seconds in the future")]
    InvalidExpiry,
    /// The provider did not complete presigning.
    #[error("origin presigning did not succeed")]
    PresignFailed,
    /// The returned capability signature was not verified.
    #[error("origin capability signature was not verified")]
    SignatureUnverified,
    /// A method/object/placement/condition/range claim differed from evaluation.
    #[error("presigned capability claims do not match the evaluated request")]
    ClaimMismatch,
    /// The required private-network revision was absent, stale, or mismatched.
    #[error("presigned capability lacks a valid private-network boundary proof")]
    PrivateNetworkMismatch,
}

/// A validated Hub-authorized redirect built only from an attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedRedirectDecision(PresignedCapabilityAttestation);

impl AuthorizedRedirectDecision {
    /// Constructs a redirect from an already verified capability attestation.
    #[must_use]
    pub const fn from_attestation(attestation: PresignedCapabilityAttestation) -> Self {
        Self(attestation)
    }

    /// Returns the complete verified attestation.
    #[must_use]
    pub const fn attestation(&self) -> &PresignedCapabilityAttestation {
        &self.0
    }

    /// Returns HTTP status 307.
    #[must_use]
    pub const fn status_code(&self) -> u16 {
        307
    }

    /// Returns `private, no-store` for every bearer-capability response.
    #[must_use]
    pub const fn cache_control(&self) -> &'static str {
        PRIVATE_CACHE_CONTROL
    }

    /// Returns the fixed no-referrer policy.
    #[must_use]
    pub const fn referrer_policy(&self) -> &'static str {
        REDIRECT_REFERRER_POLICY
    }
}

fn trim_ows(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

fn trim_ows_bytes(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn skip_ows(bytes: &[u8], index: &mut usize) {
    while bytes
        .get(*index)
        .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
    {
        *index += 1;
    }
}

fn parse_u64(value: &str) -> Result<u64, ByteRangeError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ByteRangeError::InvalidNumber);
    }
    value
        .parse::<u64>()
        .map_err(|_| ByteRangeError::InvalidNumber)
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_media_type(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || value != value.trim()
        || bytes
            .iter()
            .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
    {
        return false;
    }
    let mut index = 0;
    if !consume_token(bytes, &mut index) || bytes.get(index) != Some(&b'/') {
        return false;
    }
    index += 1;
    if !consume_token(bytes, &mut index) {
        return false;
    }
    while index < bytes.len() {
        skip_ows(bytes, &mut index);
        if bytes.get(index) != Some(&b';') {
            return false;
        }
        index += 1;
        skip_ows(bytes, &mut index);
        if !consume_token(bytes, &mut index) || bytes.get(index) != Some(&b'=') {
            return false;
        }
        index += 1;
        if bytes.get(index) == Some(&b'"') {
            if !consume_quoted_string(bytes, &mut index) {
                return false;
            }
        } else if !consume_token(bytes, &mut index) {
            return false;
        }
    }
    true
}

fn consume_token(bytes: &[u8], index: &mut usize) -> bool {
    let start = *index;
    while bytes.get(*index).is_some_and(|byte| is_tchar(*byte)) {
        *index += 1;
    }
    *index > start
}

fn consume_quoted_string(bytes: &[u8], index: &mut usize) -> bool {
    if bytes.get(*index) != Some(&b'"') {
        return false;
    }
    *index += 1;
    while let Some(byte) = bytes.get(*index).copied() {
        match byte {
            b'"' => {
                *index += 1;
                return true;
            }
            b'\\' => {
                *index += 1;
                if !bytes
                    .get(*index)
                    .is_some_and(|escaped| *escaped == b'\t' || (0x20..=0x7e).contains(escaped))
                {
                    return false;
                }
                *index += 1;
            }
            b'\t' | b' ' | 0x21 | 0x23..=0x5b | 0x5d..=0x7e | 0x80..=0xff => *index += 1,
            _ => return false,
        }
    }
    false
}

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_stable_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn is_standard_hop_by_hop(name: &str) -> bool {
    [
        "connection",
        "keep-alive",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ]
    .iter()
    .any(|candidate| candidate.eq_ignore_ascii_case(name))
}

const SHORT_WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const LONG_WEEKDAYS: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn parse_http_date(value: &[u8], now: HttpTimestamp) -> Result<HttpTimestamp, HttpDateError> {
    let parsed = if value.len() == 29 && value.get(3..5) == Some(b", ") {
        parse_imf_fixdate(value)?
    } else if value.iter().position(|byte| *byte == b',').is_some() {
        parse_rfc850_date(value, now)?
    } else {
        parse_asctime_date(value)?
    };
    build_http_timestamp(parsed)
}

fn parse_imf_fixdate(value: &[u8]) -> Result<ParsedHttpDate, HttpDateError> {
    if value.len() != 29
        || value.get(3..5) != Some(b", ")
        || value.get(7) != Some(&b' ')
        || value.get(11) != Some(&b' ')
        || value.get(16) != Some(&b' ')
        || value.get(19) != Some(&b':')
        || value.get(22) != Some(&b':')
        || value.get(25..29) != Some(b" GMT")
    {
        return Err(HttpDateError::InvalidSyntax);
    }
    Ok(ParsedHttpDate {
        weekday: parse_name(&value[0..3], &SHORT_WEEKDAYS)?,
        day: parse_decimal(&value[5..7])? as u8,
        month: parse_name(&value[8..11], &MONTHS)? as u8 + 1,
        year: parse_decimal(&value[12..16])? as i32,
        hour: parse_decimal(&value[17..19])? as u8,
        minute: parse_decimal(&value[20..22])? as u8,
        second: parse_decimal(&value[23..25])? as u8,
    })
}

fn parse_rfc850_date(value: &[u8], now: HttpTimestamp) -> Result<ParsedHttpDate, HttpDateError> {
    let comma = value
        .iter()
        .position(|byte| *byte == b',')
        .ok_or(HttpDateError::InvalidSyntax)?;
    if comma < 6 || value.get(comma + 1) != Some(&b' ') {
        return Err(HttpDateError::InvalidSyntax);
    }
    let tail = &value[comma + 2..];
    if tail.len() != 22
        || tail.get(2) != Some(&b'-')
        || tail.get(6) != Some(&b'-')
        || tail.get(9) != Some(&b' ')
        || tail.get(12) != Some(&b':')
        || tail.get(15) != Some(&b':')
        || tail.get(18..22) != Some(b" GMT")
    {
        return Err(HttpDateError::InvalidSyntax);
    }
    let short_year = parse_decimal(&tail[7..9])? as i32;
    let (now_year, ..) = split_timestamp(now.0);
    let mut year = now_year.div_euclid(100) * 100 + short_year;
    let candidate_seconds = calendar_seconds(
        year,
        parse_name(&tail[3..6], &MONTHS)? as u8 + 1,
        parse_decimal(&tail[0..2])? as u8,
        parse_decimal(&tail[10..12])? as u8,
        parse_decimal(&tail[13..15])? as u8,
        parse_decimal(&tail[16..18])? as u8,
    )?;
    if candidate_seconds > timestamp_after_calendar_years(now, 50)? {
        year -= 100;
    }
    Ok(ParsedHttpDate {
        weekday: parse_name(&value[..comma], &LONG_WEEKDAYS)?,
        day: parse_decimal(&tail[0..2])? as u8,
        month: parse_name(&tail[3..6], &MONTHS)? as u8 + 1,
        year,
        hour: parse_decimal(&tail[10..12])? as u8,
        minute: parse_decimal(&tail[13..15])? as u8,
        second: parse_decimal(&tail[16..18])? as u8,
    })
}

fn parse_asctime_date(value: &[u8]) -> Result<ParsedHttpDate, HttpDateError> {
    if value.len() != 24
        || value.get(3) != Some(&b' ')
        || value.get(7) != Some(&b' ')
        || value.get(10) != Some(&b' ')
        || value.get(13) != Some(&b':')
        || value.get(16) != Some(&b':')
        || value.get(19) != Some(&b' ')
    {
        return Err(HttpDateError::InvalidSyntax);
    }
    let day = match value.get(8) {
        Some(b' ') => parse_decimal(&value[9..10])?,
        Some(byte) if byte.is_ascii_digit() => parse_decimal(&value[8..10])?,
        _ => return Err(HttpDateError::InvalidSyntax),
    };
    Ok(ParsedHttpDate {
        weekday: parse_name(&value[0..3], &SHORT_WEEKDAYS)?,
        day: day as u8,
        month: parse_name(&value[4..7], &MONTHS)? as u8 + 1,
        year: parse_decimal(&value[20..24])? as i32,
        hour: parse_decimal(&value[11..13])? as u8,
        minute: parse_decimal(&value[14..16])? as u8,
        second: parse_decimal(&value[17..19])? as u8,
    })
}

#[derive(Debug, Clone, Copy)]
struct ParsedHttpDate {
    weekday: usize,
    year: i32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

fn build_http_timestamp(parsed: ParsedHttpDate) -> Result<HttpTimestamp, HttpDateError> {
    let seconds = calendar_seconds(
        parsed.year,
        parsed.month,
        parsed.day,
        parsed.hour,
        parsed.minute,
        parsed.second,
    )?;
    let days = days_from_civil(parsed.year, parsed.month, parsed.day);
    let weekday = (days + 4).rem_euclid(7) as usize;
    if weekday != parsed.weekday {
        return Err(HttpDateError::WeekdayMismatch);
    }
    HttpTimestamp::from_unix_seconds(seconds)
}

fn calendar_seconds(
    year: i32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
) -> Result<i64, HttpDateError> {
    if !(1900..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(HttpDateError::InvalidCalendar);
    }
    Ok(days_from_civil(year, month, day) * 86_400
        + i64::from(hour) * 3_600
        + i64::from(minute) * 60
        + i64::from(second))
}

fn timestamp_after_calendar_years(
    timestamp: HttpTimestamp,
    years: i32,
) -> Result<i64, HttpDateError> {
    let (year, month, day, hour, minute, second, _) = split_timestamp(timestamp.0);
    let target_year = year.checked_add(years).ok_or(HttpDateError::OutOfRange)?;
    if target_year > 9999 {
        return Ok(i64::MAX);
    }
    if target_year < 1900 {
        return Ok(i64::MIN);
    }
    let target_day = day.min(days_in_month(target_year, month));
    calendar_seconds(target_year, month, target_day, hour, minute, second)
}

fn parse_name(value: &[u8], names: &[&str]) -> Result<usize, HttpDateError> {
    names
        .iter()
        .position(|name| value == name.as_bytes())
        .ok_or(HttpDateError::InvalidSyntax)
}

fn parse_decimal(value: &[u8]) -> Result<u32, HttpDateError> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err(HttpDateError::InvalidSyntax);
    }
    value.iter().try_fold(0_u32, |number, byte| {
        number
            .checked_mul(10)
            .and_then(|number| number.checked_add(u32::from(*byte - b'0')))
            .ok_or(HttpDateError::InvalidSyntax)
    })
}

fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

fn days_from_civil(year: i32, month: u8, day: u8) -> i64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn split_timestamp(seconds: i64) -> (i32, u8, u8, u8, u8, u8, usize) {
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    (
        year,
        month,
        day,
        (seconds_of_day / 3_600) as u8,
        (seconds_of_day % 3_600 / 60) as u8,
        (seconds_of_day % 60) as u8,
        (days + 4).rem_euclid(7) as usize,
    )
}

fn civil_from_days(days: i64) -> (i32, u8, u8) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year as i32, month as u8, day as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(value: &str) -> EntityTag {
        EntityTag::parse(value).expect("test entity tag must be valid")
    }

    fn timestamp(seconds: i64) -> HttpTimestamp {
        HttpTimestamp::from_unix_seconds(seconds).expect("test timestamp must be representable")
    }

    fn representation(etag: &str, modified: Option<i64>, length: u64) -> VerifiedRepresentation {
        VerifiedRepresentation::new(
            length,
            tag(etag),
            modified.map(|seconds| LastModifiedValidator::new(timestamp(seconds), true)),
            "application/octet-stream",
            ContentMutability::Mutable,
        )
        .expect("test metadata must be valid")
    }

    fn object_context(representation: VerifiedRepresentation) -> DeliveryObjectContext {
        DeliveryObjectContext::new(
            CanonicalRoutePath::parse_raw_target("/cache/object")
                .expect("test request path must be canonical"),
            CanonicalOriginObjectPath::parse("nar/object")
                .expect("test origin path must be canonical"),
            PlacementAuthBoundary::new("placement-1", "binding-capability-1", 1)
                .expect("test authorization must be valid"),
            ExactPublicationEligibility::new(1, 1).expect("test eligibility must be valid"),
            representation,
            RedirectBoundaryRequirement::Unrestricted,
        )
    }

    #[test]
    fn methods_are_closed_to_get_and_head() {
        assert_eq!(DeliveryMethod::parse("GET"), Ok(DeliveryMethod::Get));
        assert_eq!(DeliveryMethod::parse("HEAD"), Ok(DeliveryMethod::Head));
        for rejected in ["get", "POST", "PUT", "OPTIONS", ""] {
            assert_eq!(DeliveryMethod::parse(rejected), Err(MethodError));
        }
    }

    #[test]
    fn http_date_three_format_vectors_share_one_timestamp_and_output() {
        let now = timestamp(1_785_542_400); // 2026-08-01T00:00:00Z
        let expected = timestamp(784_111_777);
        for input in [
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
        ] {
            assert_eq!(HttpTimestamp::parse_http_date(input, now), Ok(expected));
        }
        assert_eq!(expected.to_http_date(), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(
            HttpTimestamp::parse_http_date("Mon, 06 Nov 1994 08:49:37 GMT", now),
            Err(HttpDateError::WeekdayMismatch)
        );
        for invalid in [
            "Sun, 31 Feb 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 24:49:37 GMT",
            "sun, 06 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 08:49:37 UTC",
            "",
        ] {
            assert!(HttpTimestamp::parse_http_date(invalid, now).is_err());
        }
        assert_eq!(
            HttpTimestamp::from_unix_seconds(MIN_HTTP_TIMESTAMP - 1),
            Err(HttpDateError::OutOfRange)
        );
        assert_eq!(
            HttpTimestamp::from_unix_seconds(MAX_HTTP_TIMESTAMP + 1),
            Err(HttpDateError::OutOfRange)
        );
        assert_eq!(
            timestamp(MIN_HTTP_TIMESTAMP).to_http_date(),
            "Mon, 01 Jan 1900 00:00:00 GMT"
        );
        assert_eq!(
            timestamp(MAX_HTTP_TIMESTAMP).to_http_date(),
            "Fri, 31 Dec 9999 23:59:59 GMT"
        );
    }

    #[test]
    fn rfc850_two_digit_year_uses_the_fifty_year_rule() {
        let now = HttpTimestamp::parse_http_date(
            "Sat, 01 Aug 2026 00:00:00 GMT",
            timestamp(1_785_542_400),
        )
        .expect("now must parse");
        assert_eq!(
            HttpTimestamp::parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT", now)
                .expect("date must parse")
                .to_http_date(),
            "Sun, 06 Nov 1994 08:49:37 GMT"
        );
        let noon = HttpTimestamp::parse_http_date("Sat, 01 Aug 2026 12:00:00 GMT", now)
            .expect("comparison time must parse");
        assert_eq!(
            HttpTimestamp::parse_http_date("Saturday, 01-Aug-76 12:00:00 GMT", noon)
                .expect("exactly fifty years is not remapped")
                .to_http_date(),
            "Sat, 01 Aug 2076 12:00:00 GMT"
        );
        assert_eq!(
            HttpTimestamp::parse_http_date("Sunday, 01-Aug-76 12:00:01 GMT", noon)
                .expect("one second beyond fifty years is remapped")
                .to_http_date(),
            "Sun, 01 Aug 1976 12:00:01 GMT"
        );
    }

    #[test]
    fn entity_tags_preserve_and_compare_strength() {
        let strong = tag("\"same\"");
        let weak = tag("W/\"same\"");
        assert_eq!(strong.to_header_bytes(), b"\"same\"");
        assert_eq!(weak.to_header_bytes(), b"W/\"same\"");
        assert!(!strong.is_weak());
        assert!(weak.is_weak());
        assert!(!strong.strongly_eq(&weak));
        assert!(strong.weakly_eq(&weak));
        assert_eq!(tag("\"\"").opaque(), b"");

        for rejected in ["same", "w/\"same\"", " \"same\"", "\"a b\""] {
            assert!(EntityTag::parse(rejected).is_err(), "accepted {rejected:?}");
        }
        let obs_text = EntityTag::parse_bytes(b"\"\x80\xff\"").expect("obs-text is valid");
        assert_eq!(obs_text.opaque(), b"\x80\xff");
        assert_eq!(obs_text.to_header_bytes(), b"\"\x80\xff\"");
        assert_eq!(
            EntityTag::parse_bytes(b"\"\x7f\""),
            Err(EntityTagError::InvalidOpaqueValue)
        );
    }

    #[test]
    fn tag_condition_parser_handles_commas_inside_tags() {
        let condition =
            EntityTagCondition::parse(" W/\"old\" , \"a,b\" ").expect("condition must parse");
        let EntityTagCondition::Tags(tags) = condition else {
            panic!("expected a tag list");
        };
        assert_eq!(tags, vec![tag("W/\"old\""), tag("\"a,b\"")]);
        assert_eq!(
            EntityTagCondition::parse_bytes(b"W/\"\x80\", \"ascii\"")
                .expect("obs-text condition parses")
                .to_header_bytes(),
            b"W/\"\x80\", \"ascii\""
        );
        assert_eq!(EntityTagCondition::parse("*"), Ok(EntityTagCondition::Any));

        for rejected in ["", "*, \"x\"", "\"x\",", ",\"x\"", "\"x\" \"y\""] {
            assert!(
                EntityTagCondition::parse(rejected).is_err(),
                "accepted {rejected:?}"
            );
        }
        assert_eq!(
            RequestPreconditions::new(
                None,
                None,
                Some(EntityTagCondition::Tags(Vec::new())),
                None,
                None,
            ),
            Err(RequestPreconditionsError::EmptyEntityTagList)
        );
    }

    #[test]
    fn byte_range_parser_is_single_and_overflow_safe() {
        assert_eq!(
            SingleByteRange::parse("bytes=0-499"),
            Ok(SingleByteRange::Closed { start: 0, end: 499 })
        );
        assert_eq!(
            SingleByteRange::parse("ByTeS=0-499"),
            Ok(SingleByteRange::Closed { start: 0, end: 499 })
        );
        assert_eq!(
            SingleByteRange::parse("bytes=500-"),
            Ok(SingleByteRange::From { start: 500 })
        );
        assert_eq!(
            SingleByteRange::parse("\tbytes=-500 "),
            Ok(SingleByteRange::Suffix { length: 500 })
        );
        assert_eq!(
            SingleByteRange::parse("bytes=0-1,4-5"),
            Err(ByteRangeError::MultipleRanges)
        );
        for rejected in [
            "bytes=",
            "bytes=-",
            "bytes=2-1",
            "bytes=0 -1",
            "bytes=0-1-2",
            "bytes=18446744073709551616-",
            "items=0-1",
        ] {
            assert!(
                SingleByteRange::parse(rejected).is_err(),
                "accepted {rejected:?}"
            );
        }
    }

    #[test]
    fn ranges_resolve_to_exact_206_or_416_intervals() {
        let vectors = [
            (
                SingleByteRange::Closed { start: 0, end: 499 },
                1_000,
                RangeResolution::Partial(ByteRange { start: 0, end: 499 }),
            ),
            (
                SingleByteRange::Closed {
                    start: 900,
                    end: 1_500,
                },
                1_000,
                RangeResolution::Partial(ByteRange {
                    start: 900,
                    end: 999,
                }),
            ),
            (
                SingleByteRange::From { start: 500 },
                1_000,
                RangeResolution::Partial(ByteRange {
                    start: 500,
                    end: 999,
                }),
            ),
            (
                SingleByteRange::Suffix { length: 500 },
                1_000,
                RangeResolution::Partial(ByteRange {
                    start: 500,
                    end: 999,
                }),
            ),
            (
                SingleByteRange::Suffix { length: 2_000 },
                1_000,
                RangeResolution::Partial(ByteRange { start: 0, end: 999 }),
            ),
            (
                SingleByteRange::From { start: 1_000 },
                1_000,
                RangeResolution::Unsatisfiable {
                    complete_length: 1_000,
                },
            ),
            (
                SingleByteRange::Suffix { length: 0 },
                1_000,
                RangeResolution::Unsatisfiable {
                    complete_length: 1_000,
                },
            ),
            (
                SingleByteRange::From { start: 0 },
                0,
                RangeResolution::Unsatisfiable { complete_length: 0 },
            ),
        ];
        for (requested, length, expected) in vectors {
            assert_eq!(requested.resolve(length), expected);
        }
    }

    #[test]
    fn content_range_vectors_are_canonical() {
        assert_eq!(
            ContentRange::satisfied(10, 19, 100).to_string(),
            "bytes 10-19/100"
        );
        assert_eq!(ContentRange::unsatisfied(100).to_string(), "bytes */100");
    }

    #[test]
    fn if_match_is_strong_and_suppresses_unmodified_since() {
        let current = representation("\"v2\"", Some(200), 100);
        let weak_match = RequestPreconditions {
            if_match: Some(EntityTagCondition::parse("W/\"v2\"").expect("valid condition")),
            if_unmodified_since: Some(timestamp(999)),
            ..RequestPreconditions::default()
        };
        assert_eq!(
            evaluate_request(DeliveryMethod::Get, &weak_match, None, Some(&current)),
            RequestDecision::PreconditionFailed
        );

        let strong_match = RequestPreconditions {
            if_match: Some(EntityTagCondition::parse("\"v2\"").expect("valid condition")),
            if_unmodified_since: Some(timestamp(0)),
            ..RequestPreconditions::default()
        };
        assert_eq!(
            evaluate_request(DeliveryMethod::Get, &strong_match, None, Some(&current)),
            RequestDecision::ServeFull {
                method: DeliveryMethod::Get
            }
        );
    }

    #[test]
    fn if_none_match_is_weak_and_suppresses_modified_since() {
        let current = representation("W/\"v2\"", Some(200), 100);
        let weak_match = RequestPreconditions {
            if_none_match: Some(EntityTagCondition::parse("\"v2\"").expect("valid condition")),
            if_modified_since: Some(timestamp(0)),
            ..RequestPreconditions::default()
        };
        assert_eq!(
            evaluate_request(DeliveryMethod::Head, &weak_match, None, Some(&current)),
            RequestDecision::NotModified
        );

        let no_match = RequestPreconditions {
            if_none_match: Some(EntityTagCondition::parse("\"other\"").expect("valid condition")),
            if_modified_since: Some(timestamp(999)),
            ..RequestPreconditions::default()
        };
        assert_eq!(
            evaluate_request(DeliveryMethod::Get, &no_match, None, Some(&current)),
            RequestDecision::ServeFull {
                method: DeliveryMethod::Get
            }
        );
    }

    #[test]
    fn date_preconditions_use_second_precision_and_ordering() {
        let current = representation("\"v2\"", Some(200), 100);
        for since in [199, 200] {
            let request = RequestPreconditions {
                if_unmodified_since: Some(timestamp(since)),
                ..RequestPreconditions::default()
            };
            let expected = if since < 200 {
                RequestDecision::PreconditionFailed
            } else {
                RequestDecision::ServeFull {
                    method: DeliveryMethod::Get,
                }
            };
            assert_eq!(
                evaluate_request(DeliveryMethod::Get, &request, None, Some(&current)),
                expected
            );
        }
        for since in [199, 200] {
            let request = RequestPreconditions {
                if_modified_since: Some(timestamp(since)),
                ..RequestPreconditions::default()
            };
            let expected = if since < 200 {
                RequestDecision::ServeFull {
                    method: DeliveryMethod::Get,
                }
            } else {
                RequestDecision::NotModified
            };
            assert_eq!(
                evaluate_request(DeliveryMethod::Get, &request, None, Some(&current)),
                expected
            );
        }
    }

    #[test]
    fn not_modified_and_precondition_failed_precede_range() {
        let current = representation("\"v2\"", Some(200), 100);
        let unsatisfiable = Some(SingleByteRange::From { start: 100 });
        let not_modified = RequestPreconditions {
            if_none_match: Some(EntityTagCondition::Any),
            ..RequestPreconditions::default()
        };
        assert_eq!(
            evaluate_request(
                DeliveryMethod::Get,
                &not_modified,
                unsatisfiable,
                Some(&current)
            ),
            RequestDecision::NotModified
        );
        let failed = RequestPreconditions {
            if_match: Some(EntityTagCondition::parse("\"old\"").expect("valid condition")),
            ..RequestPreconditions::default()
        };
        assert_eq!(
            evaluate_request(DeliveryMethod::Get, &failed, unsatisfiable, Some(&current)),
            RequestDecision::PreconditionFailed
        );
    }

    #[test]
    fn if_range_requires_strong_tag_or_nonolder_date() {
        let current = representation("\"v2\"", Some(200), 100);
        let range = Some(SingleByteRange::Closed { start: 10, end: 19 });
        let vectors = [
            (
                IfRangeCondition::EntityTag(tag("\"v2\"")),
                RequestDecision::ServePartial {
                    range: ByteRange { start: 10, end: 19 },
                },
            ),
            (
                IfRangeCondition::EntityTag(tag("W/\"v2\"")),
                RequestDecision::ServeFull {
                    method: DeliveryMethod::Get,
                },
            ),
            (
                IfRangeCondition::EntityTag(tag("\"old\"")),
                RequestDecision::ServeFull {
                    method: DeliveryMethod::Get,
                },
            ),
            (
                IfRangeCondition::Date(timestamp(199)),
                RequestDecision::ServeFull {
                    method: DeliveryMethod::Get,
                },
            ),
            (
                IfRangeCondition::Date(timestamp(200)),
                RequestDecision::ServePartial {
                    range: ByteRange { start: 10, end: 19 },
                },
            ),
        ];
        for (if_range, expected) in vectors {
            let request = RequestPreconditions {
                if_range: Some(if_range),
                ..RequestPreconditions::default()
            };
            assert_eq!(
                evaluate_request(DeliveryMethod::Get, &request, range, Some(&current)),
                expected
            );
        }

        let weak_date_metadata = VerifiedRepresentation::new(
            100,
            tag("\"v2\""),
            Some(LastModifiedValidator::new(timestamp(200), false)),
            "application/octet-stream",
            ContentMutability::Mutable,
        )
        .expect("test metadata must be valid");
        let weak_date_request = RequestPreconditions {
            if_range: Some(IfRangeCondition::Date(timestamp(200))),
            ..RequestPreconditions::default()
        };
        assert_eq!(
            evaluate_request(
                DeliveryMethod::Get,
                &weak_date_request,
                range,
                Some(&weak_date_metadata)
            ),
            RequestDecision::ServeFull {
                method: DeliveryMethod::Get
            }
        );
    }

    #[test]
    fn head_ignores_range_but_preserves_complete_length() {
        let context = object_context(representation("\"v2\"", Some(200), 100));
        let response = context.evaluate(
            DeliveryMethod::Head,
            &RequestPreconditions::default(),
            Some(SingleByteRange::Closed { start: 10, end: 19 }),
            ResponsePolicy::new(ResponsePrivacy::Public),
        );
        assert_eq!(
            response.decision(),
            RequestDecision::ServeFull {
                method: DeliveryMethod::Head
            }
        );
        assert_eq!(response.effective_range(), None);
        assert!(!response.decision().sends_body());
        assert_eq!(response.response_metadata().content_length(), Some(100));
    }

    #[test]
    fn absent_representation_respects_if_match_then_returns_404() {
        let required = RequestPreconditions {
            if_match: Some(EntityTagCondition::Any),
            ..RequestPreconditions::default()
        };
        assert_eq!(
            evaluate_request(DeliveryMethod::Get, &required, None, None),
            RequestDecision::PreconditionFailed
        );
        let absent_allowed = RequestPreconditions {
            if_none_match: Some(EntityTagCondition::Any),
            ..RequestPreconditions::default()
        };
        assert_eq!(
            evaluate_request(DeliveryMethod::Get, &absent_allowed, None, None),
            RequestDecision::NotFound
        );
    }

    #[test]
    fn response_metadata_is_derived_for_200_206_304_and_416() {
        let context = object_context(representation("\"v2\"", Some(200), 100));
        let partial_response = context.evaluate(
            DeliveryMethod::Get,
            &RequestPreconditions::default(),
            Some(SingleByteRange::Closed { start: 10, end: 19 }),
            ResponsePolicy::new(ResponsePrivacy::Public),
        );
        let partial = partial_response.response_metadata();
        assert!(partial.accepts_byte_ranges());
        assert_eq!(partial.content_length(), Some(10));
        assert_eq!(
            partial.content_range().map(|value| value.to_string()),
            Some("bytes 10-19/100".to_string())
        );
        assert_eq!(partial.etag(), Some(context.representation().etag()));
        assert_eq!(partial.cache_control(), Some(PUBLIC_MUTABLE_CACHE_CONTROL));

        let not_modified_response = context.evaluate(
            DeliveryMethod::Get,
            &RequestPreconditions {
                if_none_match: Some(EntityTagCondition::Any),
                ..RequestPreconditions::default()
            },
            None,
            ResponsePolicy::new(ResponsePrivacy::Public),
        );
        let not_modified = not_modified_response.response_metadata();
        assert_eq!(not_modified.content_length(), None);
        assert_eq!(not_modified.etag(), Some(context.representation().etag()));

        let unsatisfied_response = context.evaluate(
            DeliveryMethod::Get,
            &RequestPreconditions::default(),
            Some(SingleByteRange::From { start: 100 }),
            ResponsePolicy::new(ResponsePrivacy::Private),
        );
        let unsatisfied = unsatisfied_response.response_metadata();
        assert_eq!(unsatisfied.content_length(), None);
        assert_eq!(
            unsatisfied.content_range().map(|value| value.to_string()),
            Some("bytes */100".to_string())
        );
        assert_eq!(unsatisfied.cache_control(), Some(PRIVATE_CACHE_CONTROL));
    }

    #[test]
    fn decision_status_and_body_matrix_is_closed() {
        let vectors = [
            (
                RequestDecision::ServeFull {
                    method: DeliveryMethod::Get,
                },
                200,
                true,
            ),
            (
                RequestDecision::ServeFull {
                    method: DeliveryMethod::Head,
                },
                200,
                false,
            ),
            (
                RequestDecision::ServePartial {
                    range: ByteRange { start: 0, end: 0 },
                },
                206,
                true,
            ),
            (RequestDecision::NotModified, 304, false),
            (RequestDecision::PreconditionFailed, 412, false),
            (
                RequestDecision::RangeNotSatisfiable { complete_length: 0 },
                416,
                false,
            ),
            (RequestDecision::NotFound, 404, false),
        ];
        for (decision, status, sends_body) in vectors {
            assert_eq!(decision.status_code(), status);
            assert_eq!(decision.sends_body(), sends_body);
        }
    }

    #[test]
    fn private_terminal_outcomes_never_inherit_public_caching() {
        let policy = ResponsePolicy::new(ResponsePrivacy::Private);
        let absent = evaluate_absent_request(
            DeliveryMethod::Get,
            &RequestPreconditions::default(),
            None,
            policy,
        );
        assert_eq!(
            absent
                .terminal_response()
                .expect("absence is terminal")
                .cache_control(),
            PRIVATE_CACHE_CONTROL
        );
        let context = object_context(representation("\"current\"", Some(784_111_777), 42));
        let full = context.evaluate(
            DeliveryMethod::Get,
            &RequestPreconditions::default(),
            None,
            policy,
        );
        assert_eq!(
            full.response_metadata().cache_control(),
            Some(PRIVATE_CACHE_CONTROL)
        );
        for disposition in [
            OriginFailureDisposition::RetryAnotherPlacement,
            OriginFailureDisposition::SanitizedBadGateway,
            OriginFailureDisposition::AbortStartedResponse,
        ] {
            if let Some(terminal) = disposition.terminal_response(policy) {
                assert_eq!(terminal.cache_control(), PRIVATE_CACHE_CONTROL);
            }
        }
        assert_eq!(
            TerminalResponse::new(TerminalResponseKind::MisdirectedRequest, policy).cache_control(),
            PRIVATE_CACHE_CONTROL
        );
    }

    #[test]
    fn one_terminal_response_type_covers_every_rejection_boundary() {
        let policy = ResponsePolicy::new(ResponsePrivacy::Private);
        let vectors = [
            (TerminalResponseKind::MalformedHeader, 400),
            (TerminalResponseKind::MalformedRange, 400),
            (TerminalResponseKind::MethodNotAllowed, 405),
            (TerminalResponseKind::Unauthenticated, 401),
            (TerminalResponseKind::Forbidden, 403),
            (TerminalResponseKind::NotFound, 404),
            (TerminalResponseKind::NotModified, 304),
            (TerminalResponseKind::PreconditionFailed, 412),
            (
                TerminalResponseKind::RangeNotSatisfiable {
                    complete_length: 10,
                },
                416,
            ),
            (TerminalResponseKind::MisdirectedRequest, 421),
            (TerminalResponseKind::BadGateway, 502),
            (TerminalResponseKind::InternalServerError, 500),
        ];
        for (kind, status) in vectors {
            let terminal = TerminalResponse::new(kind, policy);
            assert_eq!(terminal.status_code(), status);
            assert_eq!(terminal.cache_control(), PRIVATE_CACHE_CONTROL);
            assert!(!terminal.public_message().is_empty());
        }
        assert_eq!(
            MethodError.terminal_response(policy).kind(),
            TerminalResponseKind::MethodNotAllowed
        );
        assert_eq!(
            ByteRangeError::MultipleRanges
                .terminal_response(policy)
                .kind(),
            TerminalResponseKind::MalformedRange
        );
        assert_eq!(
            malformed_header_response(EntityTagError::InvalidSyntax, policy).kind(),
            TerminalResponseKind::MalformedHeader
        );
        assert_eq!(
            TerminalResponse::new(
                TerminalResponseKind::RangeNotSatisfiable {
                    complete_length: 10,
                },
                policy,
            )
            .content_range()
            .map(|value| value.to_string()),
            Some("bytes */10".to_string())
        );
    }

    #[test]
    fn cache_control_is_closed_over_verified_privacy_and_mutability() {
        let strong = tag("\"hash\"");
        let vectors = [
            (
                ContentMutability::Immutable,
                ResponsePrivacy::Public,
                PUBLIC_IMMUTABLE_CACHE_CONTROL,
            ),
            (
                ContentMutability::Mutable,
                ResponsePrivacy::Public,
                PUBLIC_MUTABLE_CACHE_CONTROL,
            ),
            (
                ContentMutability::Immutable,
                ResponsePrivacy::Private,
                PRIVATE_CACHE_CONTROL,
            ),
            (
                ContentMutability::Mutable,
                ResponsePrivacy::Private,
                PRIVATE_CACHE_CONTROL,
            ),
        ];
        for (mutability, privacy, expected) in vectors {
            let metadata =
                VerifiedRepresentation::new(1, strong.clone(), None, "text/plain", mutability)
                    .expect("metadata must be valid");
            assert_eq!(
                metadata.cache_control(ResponsePolicy::new(privacy)),
                expected
            );
        }
        assert_eq!(
            VerifiedRepresentation::new(
                1,
                tag("W/\"hash\""),
                None,
                "text/plain",
                ContentMutability::Immutable,
            ),
            Err(RepresentationMetadataError::WeakImmutableEtag)
        );
        for valid in [
            "text/plain",
            "application/octet-stream",
            "text/html; charset=utf-8",
            "application/x.test+json; profile=full; note=\"quoted value\"",
        ] {
            assert!(VerifiedRepresentation::new(
                1,
                strong.clone(),
                None,
                valid,
                ContentMutability::Immutable,
            )
            .is_ok());
        }
        for invalid in [
            "",
            " text/plain",
            "text/plain\r\nx-bad: yes",
            "text/é",
            "text",
            "text/",
            "/plain",
            "text /plain",
            "text/plain;",
            "text/plain; charset",
            "text/plain; charset =utf-8",
            "text/plain; charset=\"unterminated",
        ] {
            assert!(VerifiedRepresentation::new(
                1,
                strong.clone(),
                None,
                invalid,
                ContentMutability::Immutable,
            )
            .is_err());
        }
    }

    #[test]
    fn origin_headers_are_allowlisted_and_connection_tokens_win() {
        let none = ConnectionOptions::default();
        let length_is_hop_by_hop = ConnectionOptions::parse(&["keep-alive, Content-Length"])
            .expect("connection options must parse");
        assert_eq!(
            classify_origin_response_header("ETag", &none),
            OriginHeaderDisposition::Verify(OriginMetadataField::Etag)
        );
        assert_eq!(
            classify_origin_response_header("Content-Length", &length_is_hop_by_hop),
            OriginHeaderDisposition::Strip(OriginHeaderStripReason::HopByHop)
        );
        for header in [
            "Connection",
            "Keep-Alive",
            "Proxy-Connection",
            "TE",
            "Trailer",
            "Transfer-Encoding",
            "Upgrade",
        ] {
            assert_eq!(
                classify_origin_response_header(header, &none),
                OriginHeaderDisposition::Strip(OriginHeaderStripReason::HopByHop),
                "header {header}"
            );
        }
        for header in [
            "Authorization",
            "Proxy-Authorization",
            "WWW-Authenticate",
            "Proxy-Authenticate",
            "Authentication-Info",
        ] {
            assert_eq!(
                classify_origin_response_header(header, &none),
                OriginHeaderDisposition::Strip(OriginHeaderStripReason::OriginAuthentication),
                "header {header}"
            );
        }
        for header in ["Set-Cookie", "Set-Cookie2"] {
            assert_eq!(
                classify_origin_response_header(header, &none),
                OriginHeaderDisposition::Strip(OriginHeaderStripReason::SetCookie)
            );
        }
        for header in ["Location", "Content-Location"] {
            assert_eq!(
                classify_origin_response_header(header, &none),
                OriginHeaderDisposition::Strip(OriginHeaderStripReason::Location)
            );
        }
        assert_eq!(
            classify_origin_response_header("X-Origin-Debug", &none),
            OriginHeaderDisposition::Strip(OriginHeaderStripReason::NotAllowlisted)
        );
        assert_eq!(
            classify_origin_response_header("bad header", &none),
            OriginHeaderDisposition::Strip(OriginHeaderStripReason::InvalidName)
        );
        assert_eq!(
            ConnectionOptions::parse(&["close,", "upgrade"]),
            Err(ConnectionOptionsError::EmptyOption)
        );
        assert_eq!(
            ConnectionOptions::parse(&["bad option"]),
            Err(ConnectionOptionsError::InvalidOption)
        );
    }

    #[test]
    fn outbound_origin_boundary_strips_client_authority_and_derives_safe_fields() {
        let none = ConnectionOptions::default();
        for header in ["Authorization", "Proxy-Authorization", "Cookie", "Cookie2"] {
            assert_eq!(
                classify_client_request_header(header, &none),
                ClientRequestHeaderDisposition::Strip(
                    ClientRequestHeaderStripReason::ClientCredential
                )
            );
        }
        for header in [
            "Forwarded",
            "X-Forwarded-For",
            "X-Forwarded-Client-Cert",
            "X-Real-IP",
            "CF-Connecting-IP",
            "True-Client-IP",
            "Via",
        ] {
            assert_eq!(
                classify_client_request_header(header, &none),
                ClientRequestHeaderDisposition::Strip(
                    ClientRequestHeaderStripReason::ForwardedIdentity
                ),
                "header {header}"
            );
        }
        for (header, field) in [
            ("Range", ClientRequestMetadataField::Range),
            ("If-Match", ClientRequestMetadataField::IfMatch),
            (
                "If-Unmodified-Since",
                ClientRequestMetadataField::IfUnmodifiedSince,
            ),
            ("If-None-Match", ClientRequestMetadataField::IfNoneMatch),
            (
                "If-Modified-Since",
                ClientRequestMetadataField::IfModifiedSince,
            ),
            ("If-Range", ClientRequestMetadataField::IfRange),
        ] {
            assert_eq!(
                classify_client_request_header(header, &none),
                ClientRequestHeaderDisposition::Parse(field)
            );
        }
        assert_eq!(
            classify_client_request_header("Host", &none),
            ClientRequestHeaderDisposition::Strip(ClientRequestHeaderStripReason::NotAllowlisted)
        );

        let boundary = PlacementAuthBoundary::new("placement-1", "binding-capability-2", 9)
            .expect("boundary must be valid");
        let preconditions = RequestPreconditions {
            if_match: Some(EntityTagCondition::parse("\"current\"").expect("condition parses")),
            if_unmodified_since: Some(timestamp(784_111_777)),
            if_none_match: Some(
                EntityTagCondition::parse_bytes(b"W/\"\x80\"").expect("condition parses"),
            ),
            if_modified_since: Some(timestamp(784_111_777)),
            if_range: Some(IfRangeCondition::EntityTag(tag("\"current\""))),
        };
        let context = DeliveryObjectContext::new(
            CanonicalRoutePath::parse_raw_target("/cache/object").expect("request path must parse"),
            CanonicalOriginObjectPath::parse("nar/object").expect("origin path must parse"),
            boundary.clone(),
            ExactPublicationEligibility::new(3, 4).expect("eligibility must parse"),
            representation("\"current\"", Some(784_111_777), 100),
            RedirectBoundaryRequirement::Unrestricted,
        );
        let response = context.evaluate(
            DeliveryMethod::Get,
            &preconditions,
            Some(SingleByteRange::Closed { start: 10, end: 19 }),
            ResponsePolicy::new(ResponsePrivacy::Private),
        );
        let request =
            OutboundOriginRequest::derive(&response).expect("partial response opens origin");
        assert_eq!(request.method(), DeliveryMethod::Get);
        assert_eq!(request.object(), &context);
        assert_eq!(
            request.headers(),
            &[
                OriginRequestHeader::Range("bytes=10-19".to_string()),
                OriginRequestHeader::IfMatch(b"\"current\"".to_vec()),
                OriginRequestHeader::IfUnmodifiedSince("Sun, 06 Nov 1994 08:49:37 GMT".to_string()),
                OriginRequestHeader::IfNoneMatch(b"W/\"\x80\"".to_vec()),
                OriginRequestHeader::IfModifiedSince("Sun, 06 Nov 1994 08:49:37 GMT".to_string()),
                OriginRequestHeader::IfRange(b"\"current\"".to_vec()),
                OriginRequestHeader::PlacementAuthorization(boundary),
            ]
        );
        assert_eq!(
            OutboundOriginRequest::derive(&context.evaluate(
                DeliveryMethod::Get,
                &RequestPreconditions {
                    if_none_match: Some(EntityTagCondition::Any),
                    ..RequestPreconditions::default()
                },
                None,
                ResponsePolicy::new(ResponsePrivacy::Private),
            )),
            Err(OutboundOriginRequestError::NoOriginRead)
        );
        for invalid in [
            PlacementAuthBoundary::new("", "cap", 1),
            PlacementAuthBoundary::new("placement", "client secret", 1),
            PlacementAuthBoundary::new("placement", "cap", 0),
        ] {
            assert!(invalid.is_err());
        }
    }

    #[test]
    fn origin_failures_have_closed_retry_and_sanitization_rules() {
        for failure in [
            OriginFailure::ConnectBeforeHeaders,
            OriginFailure::TimeoutBeforeHeaders,
            OriginFailure::ExactPresenceMismatch,
            OriginFailure::VerifiedCorruption,
            OriginFailure::Status { status: 404 },
            OriginFailure::Status { status: 429 },
            OriginFailure::Status { status: 502 },
            OriginFailure::Status { status: 503 },
            OriginFailure::Status { status: 504 },
        ] {
            let disposition = classify_origin_failure(failure);
            assert_eq!(disposition, OriginFailureDisposition::RetryAnotherPlacement);
            assert_eq!(disposition.client_status(), Some(502));
            assert_eq!(disposition.public_message(), Some("origin unavailable"));
        }
        for status in [200, 206, 301, 307, 400, 401, 403, 500, 505] {
            assert_eq!(
                classify_origin_failure(OriginFailure::Status { status }),
                OriginFailureDisposition::SanitizedBadGateway,
                "origin status {status}"
            );
        }
        assert_eq!(
            classify_origin_failure(OriginFailure::AfterResponseStarted),
            OriginFailureDisposition::AbortStartedResponse
        );
    }

    #[test]
    fn origin_statuses_accept_only_verified_body_response_classes() {
        let eligibility =
            ExactPublicationEligibility::new(9, 11).expect("eligibility proof must be valid");
        let context = DeliveryObjectContext::new(
            CanonicalRoutePath::parse_raw_target("/cache/object").expect("request path must parse"),
            CanonicalOriginObjectPath::parse("nar/object").expect("origin path must parse"),
            PlacementAuthBoundary::new("placement", "capability", 2).expect("boundary must parse"),
            eligibility,
            representation("\"object\"", Some(784_111_777), 100),
            RedirectBoundaryRequirement::Unrestricted,
        );
        assert_eq!(
            classify_origin_status(200, OriginBodyExpectation::Full, &context),
            OriginStatusDisposition::AcceptFull { eligibility }
        );
        assert_eq!(
            classify_origin_status(206, OriginBodyExpectation::Partial, &context),
            OriginStatusDisposition::AcceptPartial { eligibility }
        );
        assert_eq!(
            classify_origin_status(404, OriginBodyExpectation::Partial, &context),
            OriginStatusDisposition::Failure(OriginFailureDisposition::RetryAnotherPlacement)
        );
        for (status, expected) in [
            (200, OriginBodyExpectation::Partial),
            (206, OriginBodyExpectation::Full),
        ] {
            assert_eq!(
                classify_origin_status(status, expected, &context),
                OriginStatusDisposition::Failure(OriginFailureDisposition::RetryAnotherPlacement)
            );
        }
        for status in [301, 304, 307, 400, 401, 403, 416, 500] {
            assert_eq!(
                classify_origin_status(status, OriginBodyExpectation::Full, &context),
                OriginStatusDisposition::Failure(OriginFailureDisposition::SanitizedBadGateway),
                "origin status {status}"
            );
        }
        for status in [429, 502, 503, 504] {
            assert_eq!(
                classify_origin_status(status, OriginBodyExpectation::Full, &context),
                OriginStatusDisposition::Failure(OriginFailureDisposition::RetryAnotherPlacement),
                "origin status {status}"
            );
        }
    }

    #[test]
    fn redirect_capability_and_direct_miss_metadata_is_safe() {
        let boundary = PlacementAuthBoundary::new("placement-1", "binding:capability-2", 7)
            .expect("boundary must be valid");
        let path = CanonicalRoutePath::parse_raw_target("/cache/nar/object.nar.zst")
            .expect("path must be canonical");
        let origin_path = CanonicalOriginObjectPath::parse("nar/object.nar.zst")
            .expect("origin path must be canonical");
        let eligibility =
            ExactPublicationEligibility::new(8, 9).expect("eligibility must be valid");
        let preconditions = RequestPreconditions {
            if_none_match: Some(
                EntityTagCondition::parse("\"different\"").expect("condition must parse"),
            ),
            if_range: Some(IfRangeCondition::EntityTag(tag("\"current\""))),
            ..RequestPreconditions::default()
        };
        let range = Some(SingleByteRange::Closed { start: 10, end: 19 });
        let network = PrivateNetworkBoundaryRequirement::new("corp-vpn", 12)
            .expect("network requirement must be valid");
        let context = DeliveryObjectContext::new(
            path.clone(),
            origin_path.clone(),
            boundary.clone(),
            eligibility,
            representation("\"current\"", Some(784_111_777), 100),
            RedirectBoundaryRequirement::PrivateNetwork(network.clone()),
        );
        let response = context.evaluate(
            DeliveryMethod::Get,
            &preconditions,
            range,
            ResponsePolicy::new(ResponsePrivacy::Private),
        );
        let now = timestamp(784_111_777);
        let expires_at = timestamp(784_112_077);
        let evidence_for = |expires_at: HttpTimestamp,
                            presign_succeeded: bool,
                            signature_verified: bool,
                            network_valid_through: HttpTimestamp| {
            PresignedCapabilityEvidence {
                location: CanonicalPresignedLocation::parse(
                    "https://objects.example/object?signature=unchanged%2Bbytes",
                )
                .expect("location must be canonical"),
                expires_at,
                method: DeliveryMethod::Get,
                request_path: path.clone(),
                origin_object_path: origin_path.clone(),
                authorization: boundary.clone(),
                preconditions: preconditions.clone(),
                range,
                presign_succeeded,
                signature_verified,
                private_network: Some(PrivateNetworkBoundaryEvidence {
                    boundary_id: "corp-vpn".to_string(),
                    revision: 12,
                    verified: true,
                    valid_through: network_valid_through,
                }),
            }
        };
        let evidence = evidence_for(expires_at, true, true, expires_at);
        let attestation = PresignedCapabilityAttestation::verify(evidence, &response, now)
            .expect("capability evidence must match");
        let decision = AuthorizedRedirectDecision::from_attestation(attestation);
        assert_eq!(decision.status_code(), 307);
        assert_eq!(decision.cache_control(), "private, no-store");
        assert_eq!(decision.referrer_policy(), "no-referrer");
        let attestation = decision.attestation();
        assert_eq!(
            attestation.location().as_str(),
            "https://objects.example/object?signature=unchanged%2Bbytes"
        );
        assert_eq!(attestation.expires_at(), expires_at);
        assert_eq!(attestation.method(), DeliveryMethod::Get);
        assert_eq!(attestation.request_path(), &path);
        assert_eq!(attestation.origin_object_path(), &origin_path);
        assert_eq!(attestation.authorization(), &boundary);
        assert_eq!(attestation.eligibility(), eligibility);
        assert_eq!(attestation.representation(), context.representation());
        assert_eq!(attestation.preconditions(), &preconditions);
        assert_eq!(attestation.range(), range);
        assert_eq!(attestation.private_network(), Some(&network));
        assert_eq!(
            attestation.status(),
            PresignedCapabilityStatus::PresignedAndSignatureVerified
        );
        assert_eq!(
            PresignedCapabilityAttestation::verify(
                evidence_for(expires_at, false, true, expires_at),
                &response,
                now,
            ),
            Err(PresignedCapabilityAttestationError::PresignFailed)
        );
        assert_eq!(
            PresignedCapabilityAttestation::verify(
                evidence_for(expires_at, true, false, expires_at),
                &response,
                now,
            ),
            Err(PresignedCapabilityAttestationError::SignatureUnverified)
        );
        assert_eq!(
            PresignedCapabilityAttestation::verify(
                evidence_for(
                    expires_at,
                    true,
                    true,
                    timestamp(expires_at.unix_seconds() - 1),
                ),
                &response,
                now,
            ),
            Err(PresignedCapabilityAttestationError::PrivateNetworkMismatch)
        );
        assert_eq!(
            PresignedCapabilityAttestation::verify(
                evidence_for(timestamp(now.unix_seconds() + 301), true, true, expires_at),
                &response,
                now,
            ),
            Err(PresignedCapabilityAttestationError::InvalidExpiry)
        );

        for url in [
            "http://objects.example/object",
            "https://user@objects.example/object",
            "https://objects.example/object#fragment",
            "HTTPS://objects.example/object",
            "https://OBJECTS.example/object",
            "https://objects.example",
            "\thttps://objects.example/object",
            "https://objects.example/object\0suffix",
            "https://objects.example/object\r\nlocation: https://evil.example/",
        ] {
            assert!(
                CanonicalPresignedLocation::parse(url).is_err(),
                "accepted {url:?}"
            );
        }

        let head_response = context.evaluate(
            DeliveryMethod::Head,
            &RequestPreconditions::default(),
            range,
            ResponsePolicy::new(ResponsePrivacy::Private),
        );
        assert_eq!(head_response.effective_range(), None);
        let head_evidence = PresignedCapabilityEvidence {
            location: CanonicalPresignedLocation::parse("https://objects.example/object")
                .expect("location must be canonical"),
            expires_at: timestamp(now.unix_seconds() + 30),
            method: DeliveryMethod::Head,
            request_path: path.clone(),
            origin_object_path: origin_path.clone(),
            authorization: boundary.clone(),
            preconditions: RequestPreconditions::default(),
            range: None,
            presign_succeeded: true,
            signature_verified: true,
            private_network: Some(PrivateNetworkBoundaryEvidence {
                boundary_id: "corp-vpn".to_string(),
                revision: 12,
                verified: true,
                valid_through: timestamp(now.unix_seconds() + 30),
            }),
        };
        let mut head_with_range = head_evidence.clone();
        head_with_range.range = range;
        assert_eq!(
            PresignedCapabilityAttestation::verify(head_with_range, &head_response, now),
            Err(PresignedCapabilityAttestationError::ClaimMismatch)
        );
        let head_attestation =
            PresignedCapabilityAttestation::verify(head_evidence, &head_response, now)
                .expect("HEAD ignores the client Range and attests no range");
        assert_eq!(head_attestation.range(), None);

        let mismatched_evidence = PresignedCapabilityEvidence {
            location: CanonicalPresignedLocation::parse("https://objects.example/object")
                .expect("location must be canonical"),
            expires_at: timestamp(now.unix_seconds() + 30),
            method: DeliveryMethod::Get,
            request_path: path,
            origin_object_path: origin_path,
            authorization: boundary,
            preconditions,
            range: None,
            presign_succeeded: true,
            signature_verified: true,
            private_network: None,
        };
        assert_eq!(
            PresignedCapabilityAttestation::verify(mismatched_evidence, &response, now),
            Err(PresignedCapabilityAttestationError::ClaimMismatch)
        );
        assert_eq!(
            TerminalResponse::new(
                TerminalResponseKind::MisdirectedRequest,
                ResponsePolicy::new(ResponsePrivacy::Private),
            )
            .cache_control(),
            PRIVATE_CACHE_CONTROL
        );
    }
}
