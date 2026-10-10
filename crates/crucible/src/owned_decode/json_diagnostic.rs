//! Retains a closed slice parser's actual diagnostic before returning credit.
//!
//! The private Serde error is never exposed through a source/downcast or owning
//! conversion. Its supported Display paths borrow their message; Debug uses
//! the same presentation rather than Serde's allocating ErrorCode formatter.

use std::fmt;

use super::json_profiles::ClosedJsonProfile;
use super::{DecodeAdmissionError, DecodeBudget, DecodeCustody, DecodeScratch};

/// Retains the actual JSON error and its original diagnostic purpose.
///
/// The field order is a lifetime requirement: Serde's message and ErrorImpl
/// close before the scratch credit, and original custody closes last. Neither
/// ownership extraction nor a raw error borrow is part of this API.
pub struct PaidJsonError {
    error: serde_json::Error,
    _diagnostic: DecodeScratch,
    _custody: DecodeCustody,
}

impl PaidJsonError {
    /// Returns the actual error's one-based source line.
    #[must_use]
    pub fn line(&self) -> usize {
        self.error.line()
    }

    /// Returns the actual error's source column.
    #[must_use]
    pub fn column(&self) -> usize {
        self.error.column()
    }

    /// Returns the actual syntax, data or EOF classification.
    #[must_use]
    pub fn classify(&self) -> serde_json::error::Category {
        self.error.classify()
    }

    /// Returns whether the error originated in IO.
    ///
    /// The supported slice profiles contain no IO-producing visitor.
    #[must_use]
    pub fn is_io(&self) -> bool {
        self.error.is_io()
    }

    /// Returns whether the input has invalid JSON syntax.
    #[must_use]
    pub fn is_syntax(&self) -> bool {
        self.error.is_syntax()
    }

    /// Returns whether a typed input value was refused.
    #[must_use]
    pub fn is_data(&self) -> bool {
        self.error.is_data()
    }

    /// Returns whether the input ended before its JSON value was complete.
    #[must_use]
    pub fn is_eof(&self) -> bool {
        self.error.is_eof()
    }
}

impl fmt::Display for PaidJsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error, formatter)
    }
}

impl fmt::Debug for PaidJsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Serde's Debug calls ErrorCode::to_string. Display does not allocate
        // for the sealed slice profiles, including their fixed custom errors.
        write!(formatter, "PaidJsonError({self})")
    }
}

impl std::error::Error for PaidJsonError {}

/// Retains an allocation-free refusal before a supported parser can be born.
pub struct JsonProfileRefusal {
    message: &'static str,
    _custody: DecodeCustody,
}

impl fmt::Display for JsonProfileRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl fmt::Debug for JsonProfileRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for JsonProfileRefusal {}

/// Separates an original admission refusal from a paid JSON diagnostic.
#[derive(Debug, thiserror::Error)]
pub enum ClosedJsonError {
    /// The same original refused before or during typed decoding.
    #[error("{0}")]
    Admission(#[from] DecodeAdmissionError),
    /// The slice parser produced its original retained diagnostic.
    #[error("{0}")]
    Json(#[from] PaidJsonError),
    /// The supported layout or checked diagnostic extent was unavailable.
    #[error("{0}")]
    Profile(#[from] JsonProfileRefusal),
}

pub(super) struct PreparedDiagnostic {
    credit: DecodeScratch,
    custody: DecodeCustody,
}

impl PreparedDiagnostic {
    pub(super) fn prepare<'input, T: ClosedJsonProfile<'input>>(
        budget: &DecodeBudget,
        bytes: &[u8],
    ) -> Result<Self, ClosedJsonError> {
        // This concrete ErrorImpl geometry comes from the pinned unmodified
        // serde_json 1.0.150 normal compiler and allocator call on x86_64 Linux.
        // Other target layouts must be independently bound before entry.
        if !cfg!(all(
            target_arch = "x86_64",
            target_os = "linux",
            target_pointer_width = "64"
        )) {
            return Err(Self::refusal(
                budget,
                "closed JSON target layout is unsupported",
            ));
        }
        let extent = reservation_extent::<T>(bytes)
            .ok_or_else(|| Self::refusal(budget, "closed JSON diagnostic extent overflow"))?;
        let credit = budget.reserve_scratch_bytes(extent)?;
        Ok(Self {
            credit,
            custody: budget.custody(),
        })
    }

    pub(super) fn retain(self, error: serde_json::Error) -> PaidJsonError {
        PaidJsonError {
            error,
            _diagnostic: self.credit,
            _custody: self.custody,
        }
    }

    pub(super) fn refusal(budget: &DecodeBudget, message: &'static str) -> ClosedJsonError {
        JsonProfileRefusal {
            message,
            _custody: budget.custody(),
        }
        .into()
    }
}

// These are the pinned Serde templates reachable from the closed DTO roster.
// Summing their literal pieces and labels conservatively covers any single
// message, including an unknown-field list and generated struct expectation.
const MESSAGE_PIECES: &[&str] = &[
    "invalid type: ",
    ", expected ",
    "invalid value: ",
    "invalid length ",
    "unknown variant `",
    "`, there are no variants",
    "`, expected ",
    "unknown field `",
    "`, there are no fields",
    "missing field `",
    "duplicate field `",
    "`",
    "one of ",
    ", ",
    " or ",
    "string \"",
    "\"",
    "integer `",
    "boolean `true`",
    "boolean `false`",
    "floating point `",
    "character `",
    "unit value",
    "Option value",
    "option",
    "sequence",
    "a sequence",
    "map",
    "a map",
    "a string",
    "a borrowed string",
    "field identifier",
    "variant identifier",
    "u32",
    "u64",
    "usize",
    "struct ",
    "enum ",
    " with ",
    " elements",
    "an array of length ",
    "a canonical record-typed content identity",
    "a canonical lowercase 64-character campaign identity",
    "campaign identity is not canonical lowercase hexadecimal",
    "campaign object is invalid: ",
    "typed content identity is malformed",
    "typed content identity has the wrong record type",
    "content identity has the wrong object kind or schema version",
    "original decoded metadata admission refused",
    "18446744073709551615",
    "-9223372036854775808",
    "18446744073709551615",
    "EOF while parsing an object",
    "control character (\\u0000-\\u001F) found while parsing a string",
    " at line ",
    " column ",
    "18446744073709551615",
    "18446744073709551615",
];

pub(super) fn diagnostic_extent(bytes: &[u8], labels: &[&str]) -> Option<u64> {
    let literals = MESSAGE_PIECES
        .iter()
        .try_fold(0_u64, |total, piece| total.checked_add(piece.len() as u64))?;
    let fixed = labels.iter().try_fold(literals, |total, label| {
        // Backticks and a comma-space are the actual OneOf label punctuation.
        total.checked_add(debug_bytes(label)?)?.checked_add(4)
    })?;
    // A floating Unexpected can appear even when the expected field is an
    // integer. The pinned formatter's complete scalar output fits its actual
    // 24-byte zmij::Buffer; this is a formatter extent, not an input multiplier.
    let length = fixed
        .checked_add(24)?
        .checked_add(input_debug_bytes(bytes)?)?;
    // Arguments::estimated_capacity is at most twice its literal-piece sum.
    // RawVec growth/shrink retains at most max(initial, 2*length, 8) + length.
    let initial = literals.checked_mul(2)?;
    let capacity = initial.max(length.checked_mul(2)?).max(8);
    let error_impl_bytes = 40_u64;
    error_impl_bytes
        .checked_mul(2)?
        .checked_add(capacity)?
        .checked_add(length)
}

fn debug_bytes(value: &str) -> Option<u64> {
    value.chars().try_fold(0_u64, |total, character| {
        character.escape_debug().try_fold(total, |total, escaped| {
            total.checked_add(escaped.len_utf8() as u64)
        })
    })
}

pub(super) fn input_debug_bytes(mut bytes: &[u8]) -> Option<u64> {
    let whole = bytes;
    let mut total = 2_u64;
    while !bytes.is_empty() {
        match std::str::from_utf8(bytes) {
            Ok(valid) => {
                total = total.checked_add(debug_bytes(valid)?)?;
                break;
            }
            Err(error) => {
                let valid = std::str::from_utf8(&bytes[..error.valid_up_to()]).ok()?;
                total = total.checked_add(debug_bytes(valid)?)?;
                let Some(invalid_length) = error.error_len() else {
                    break;
                };
                bytes = &bytes[error.valid_up_to() + invalid_length..];
            }
        }
    }
    // IgnoredAny may skip invalid raw UTF-8 before a later valid diagnostic.
    // This count is not a UTF-8 validator and does not change parser ordering.
    for escape in whole.windows(6) {
        if escape.starts_with(b"\\u") && escape[2..].iter().all(u8::is_ascii_hexdigit) {
            total = total.checked_add("\\u{10ffff}".len() as u64)?;
        }
    }
    Some(total)
}

pub(super) fn reservation_extent<'input, T: ClosedJsonProfile<'input>>(
    bytes: &[u8],
) -> Option<u64> {
    diagnostic_extent(bytes, T::DIAGNOSTIC_LABELS)
        .and_then(|extent| extent.checked_add(std::mem::size_of::<ClosedJsonError>() as u64))
        .and_then(|extent| extent.checked_add(std::mem::size_of::<PreparedDiagnostic>() as u64))
        .and_then(|extent| {
            extent.checked_add(
                std::mem::size_of::<super::serde_budget::AdmissionRelayPrefix>() as u64,
            )
        })
}

/// Returns the concrete diagnostic and holder request for allocator controls.
///
/// This test-only calculation grants no credit and exposes no account. It is
/// the same checked calculation used before the controlled parser is born.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn closed_json_diagnostic_extent_for_test<'input, T: ClosedJsonProfile<'input>>(
    bytes: &[u8],
) -> Option<u64> {
    reservation_extent::<T>(bytes)
}
