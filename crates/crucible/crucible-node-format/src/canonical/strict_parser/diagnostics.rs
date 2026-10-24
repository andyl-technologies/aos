//! Closes the strict parser's actual diagnostic vocabulary and text extent.
//!
//! One roster supplies every parser reason and its maximum literal width.
//! Caller-owned error storage, serde string errors and formatting controls are
//! separate from this allocation-free DATA declaration.

use std::mem::size_of;

macro_rules! reasons {
    ($($variant:ident => $text:literal),+ $(,)?) => {
        #[derive(Clone, Copy)]
        pub(in super::super) enum Reason {
            $($variant,)+
        }

        impl Reason {
            pub(super) const fn text(self) -> &'static str {
                match self {
                    $(Self::$variant => $text,)+
                }
            }
        }

        const MAXIMUM_REASON_BYTES: usize = {
            let mut maximum = 0usize;
            $(if $text.len() > maximum { maximum = $text.len(); })+
            maximum
        };
    };
}

reasons! {
    DepthRestriction => "require a nesting limit between 1 and 64",
    ByteRestriction => "frame exceeds admitted byte limit",
    TrailingContent => "trailing JSON content",
    ExpectedValue => "expected JSON value",
    NestingLimit => "JSON nesting limit exceeded",
    ArrayLimit => "array exceeds 65536 elements",
    DuplicateKey => "duplicate object key",
    ExpectedColon => "expected object colon",
    ArrayPunctuation => "expected array comma or close",
    ObjectPunctuation => "expected object comma or close",
    InvalidLiteral => "invalid JSON literal",
    ExpectedString => "expected JSON string",
    UnterminatedString => "unterminated JSON string",
    IntegerPart => "invalid integer part",
    FractionDigits => "missing fractional digits",
    ExponentDigits => "missing exponent digits",
    NumberEncoding => "invalid number encoding",
    FiniteNumber => "invalid finite number",
    NonfiniteNumber => "nonfinite number",
}

/// Bounds the actual strict parser's owned reason text before String growth.
///
/// Each cursor-bearing reason uses the same closed literal followed by the
/// actual ` at byte ` suffix and a decimal usize. Limit checks use a shorter
/// unformatted literal. This excludes serde string-decoder errors and supplies
/// no allocation admission, error heap layout or parsing authority.
pub const STRICT_JSON_DIAGNOSTIC_TEXT_BYTES_DATA: usize =
    MAXIMUM_REASON_BYTES + " at byte ".len() + usize::MAX.ilog10() as usize + 1;

/// Names actual reason selection and borrowed text conversion controls.
pub(in super::super) const fn counter_scratch_data() -> usize {
    size_of::<Reason>() * 2 + size_of::<&str>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContractError, canonical};

    #[test]
    fn actual_strict_diagnostics_fit_the_closed_reason_and_cursor_extent() {
        for raw in [
            b"".as_slice(),
            b"[",
            b"{\"k\":0,\"k\":1}",
            b"01",
            b"1e999",
            b"true false",
        ] {
            let error = canonical::parse_json(raw, raw.len()).unwrap_err();
            let ContractError::Invalid { reason, .. } = error else {
                panic!("strict fixture must produce its owned grammar reason");
            };
            assert!(reason.len() <= STRICT_JSON_DIAGNOSTIC_TEXT_BYTES_DATA);
        }
        let mut cursor = super::super::CursorState {
            cursor: usize::MAX,
            maximum_depth: 64,
        };
        let parser = super::super::Parser {
            bytes: &[],
            state: &mut cursor,
        };
        let ContractError::Invalid { reason, .. } = parser.error(Reason::NestingLimit) else {
            panic!("the strict grammar error keeps its original owned reason");
        };
        assert_eq!(
            reason,
            format!("JSON nesting limit exceeded at byte {}", usize::MAX)
        );
        assert!(reason.len() <= STRICT_JSON_DIAGNOSTIC_TEXT_BYTES_DATA);
    }
}
