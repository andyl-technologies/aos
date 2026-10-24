//! Borrows ordered JSON field spans for independently bounded DATA readers.
//!
//! The cursor shares the defining historical reader's lexical scanner. It
//! allocates no tree, owns no input bytes, and creates no protocol or restoration
//! authority. Callers enforce their own input extent, canonical grammar, field
//! roster, primitive value rules and content/provenance checks.
//!
//! ```text
//! {"schema":"example/1","members":[1,2]}
//! ```

use super::owned11::OriginalOwned11Fields;
use crate::ProviderError;

/// Borrows one ordered object or array without constructing decoded owners.
///
/// A cursor checks delimiters, field order, nested span balance and the complete
/// consumed extent. It does not validate arbitrary primitive JSON values; their
/// defining field reader remains responsible for interpretation. Object names
/// consumed by [`Self::named`] must be complete unescaped UTF-8 strings.
pub struct BorrowedJsonFields<'a> {
    fields: OriginalOwned11Fields<'a>,
}

impl<'a> BorrowedJsonFields<'a> {
    /// Borrows an object whose outer delimiters occupy the full supplied span.
    ///
    /// # Errors
    /// Refuses missing object delimiters or bytes outside those delimiters.
    pub fn object(input: &'a [u8]) -> Result<Self, ProviderError> {
        Ok(Self {
            fields: OriginalOwned11Fields::object(input)?,
        })
    }

    /// Borrows an array whose outer delimiters occupy the full supplied span.
    ///
    /// # Errors
    /// Refuses missing array delimiters or bytes outside those delimiters.
    pub fn array(input: &'a [u8]) -> Result<Self, ProviderError> {
        Ok(Self {
            fields: OriginalOwned11Fields::array(input)?,
        })
    }

    /// Advances to the next array element's exact borrowed byte span.
    ///
    /// # Errors
    /// Refuses malformed separators, empty elements, unbalanced or truncated
    /// nested spans, or nesting beyond the defining fixed scanner stack.
    pub fn next_value(&mut self) -> Result<Option<&'a [u8]>, ProviderError> {
        self.fields.next_value()
    }

    /// Advances to an exactly named field in the defining object's order.
    ///
    /// # Errors
    /// Refuses a missing, reordered, escaped or different name, malformed
    /// separators, or invalid nested spans. It never skips unknown fields.
    pub fn named(&mut self, name: &str) -> Result<&'a [u8], ProviderError> {
        self.fields.named(name)
    }

    /// Requires that every element or field has already been consumed.
    ///
    /// # Errors
    /// Refuses an extra field or element, malformed closing syntax, or an
    /// incomplete nested span. Successfully finishing issues no validation seal.
    pub fn finish(&mut self) -> Result<(), ProviderError> {
        self.fields.finish()
    }
}

/// Counts the defining fixed cursor, scanner and result-view headers.
///
/// Input backing, enclosing schema walks and compiler frames are independent
/// caller obligations. This number creates no allocation allowance.
pub fn counter_scratch_data() -> usize {
    std::mem::size_of::<BorrowedJsonFields<'static>>()
        + std::mem::size_of::<Result<BorrowedJsonFields<'static>, ProviderError>>()
        + OriginalOwned11Fields::counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordered_nested_fields_lend_the_original_literal_spans() {
        let input = br#"{"schema":"example/1","members":[1,{"nested":"a,b:c"}]}"#;
        let mut fields = BorrowedJsonFields::object(input).unwrap();
        assert_eq!(fields.named("schema").unwrap(), br#""example/1""#);
        let members = fields.named("members").unwrap();
        let start = input.iter().position(|byte| *byte == b'[').unwrap();
        let expected = &input[start..input.len() - 1];
        assert_eq!(members, expected);
        assert_eq!(members.as_ptr(), expected.as_ptr());
        fields.finish().unwrap();

        let mut members = BorrowedJsonFields::array(members).unwrap();
        assert_eq!(members.next_value().unwrap().unwrap(), b"1");
        assert_eq!(
            members.next_value().unwrap().unwrap(),
            br#"{"nested":"a,b:c"}"#
        );
        members.finish().unwrap();
    }

    #[test]
    fn unknown_fields_and_malformed_nested_spans_cannot_finish() {
        let mut fields = BorrowedJsonFields::object(br#"{"known":1,"extra":2}"#).unwrap();
        assert_eq!(fields.named("known").unwrap(), b"1");
        assert!(fields.finish().is_err());
        let mut fields = BorrowedJsonFields::object(br#"{"extra":1,"known":2}"#).unwrap();
        assert!(fields.named("known").is_err());
        for input in [b"[[1}]".as_slice(), b"[\"unterminated]", b"[1,]"] {
            let mut array = BorrowedJsonFields::array(input).unwrap();
            assert!(array.next_value().is_err() || array.finish().is_err());
        }
    }

    #[test]
    fn outer_delimiters_and_fixed_counter_are_explicit() {
        assert!(BorrowedJsonFields::array(b"[1]extra").is_err());
        assert!(BorrowedJsonFields::object(b" {\"known\":1}").is_err());
        assert!(counter_scratch_data() >= 128);
    }
}
