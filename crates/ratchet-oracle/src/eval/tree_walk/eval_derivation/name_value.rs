//! Derivation name extraction and validation helpers.

use super::*;

impl TreeWalk {
    pub(super) fn derivation_name_value(
        &mut self,
        id: IrId,
        span: Span,
        attrs_id: IrId,
        attrs_span: Span,
        entries: &[AttrEntry],
    ) -> Result<String, TreeWalkError> {
        for entry in entries {
            let key = self.symbols.resolve(entry.key).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidSymbol {
                        id: attrs_id,
                        symbol: entry.key,
                    },
                    attrs_span,
                )
            })?;
            if key != NAME_ATTR {
                continue;
            }

            let value = self.force_value(attrs_id, attrs_span, entry.value)?;
            if value.tag() != ValueTag::String {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: attrs_id,
                        expected: "string",
                        actual: value.tag(),
                    },
                    attrs_span,
                ));
            }
            let string = self.heap.get_string_view(value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: attrs_id,
                        source,
                    },
                    attrs_span,
                )
            })?;
            if string.has_context() {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::StringContextNotAllowed {
                        id: attrs_id,
                        op: "derivationStrict",
                    },
                    attrs_span,
                ));
            }
            let bytes = Self::copy_bytes_for_node(attrs_id, attrs_span, string.bytes())?;
            let name = Self::derivation_utf8_string(id, span, "derivation name", &bytes)?;
            Self::validate_derivation_strict_name(id, span, &name)?;
            return Ok(name);
        }

        Err(self.missing_derivation_strict_attr(id, span, NAME_ATTR))
    }

    pub(super) fn validate_derivation_strict_name(
        id: IrId,
        span: Span,
        name: &str,
    ) -> Result<(), TreeWalkError> {
        if let Some(reason) = Self::derivation_strict_name_error_reason(name) {
            return Err(Self::invalid_derivation_strict_name_error(id, span, reason));
        }

        Ok(())
    }

    pub(super) fn derivation_strict_name_error_reason(name: &str) -> Option<String> {
        if name.is_empty() {
            return Some("name must not be empty".to_owned());
        }
        if name.len() > DERIVATION_NAME_MAX_LEN {
            return Some(format!(
                "name '{name}' must be no longer than {DERIVATION_NAME_MAX_LEN} characters"
            ));
        }
        if name == "." || name == ".." {
            return Some(format!("name '{name}' is not valid"));
        }
        if name.starts_with(".-") {
            return Some(format!(
                "name '{name}' is not valid: first dash-separated component must not be '.'"
            ));
        }
        if name.starts_with("..-") {
            return Some(format!(
                "name '{name}' is not valid: first dash-separated component must not be '..'"
            ));
        }
        for character in name.chars() {
            if !Self::is_derivation_name_char(character) {
                return Some(format!(
                    "name '{name}' contains illegal character '{}'",
                    character
                ));
            }
        }

        None
    }

    pub(super) fn is_derivation_name_char(character: char) -> bool {
        character.is_ascii() && Self::is_derivation_name_byte(character as u8)
    }

    pub(super) fn is_derivation_name_byte(byte: u8) -> bool {
        matches!(
            byte,
            b'0'..=b'9'
                | b'a'..=b'z'
                | b'A'..=b'Z'
                | b'+'
                | b'-'
                | b'.'
                | b'_'
                | b'?'
                | b'='
        )
    }

    pub(super) fn validate_derivation_strict_name_suffix(
        id: IrId,
        span: Span,
        name: &str,
    ) -> Result<(), TreeWalkError> {
        if name.ends_with(DERIVATION_EXTENSION) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::DerivationStrict {
                    id,
                    message: format!(
                        "derivation names are allowed to end in '{DERIVATION_EXTENSION}' only if they produce a single derivation file"
                    ),
                },
                span,
            ));
        }

        Ok(())
    }

    pub(super) fn invalid_derivation_strict_name_error(
        id: IrId,
        span: Span,
        reason: String,
    ) -> TreeWalkError {
        TreeWalkError::new(
            TreeWalkErrorKind::DerivationStrict {
                id,
                message: format!(
                    "invalid derivation name: {reason}. Please pass a different 'name'."
                ),
            },
            span,
        )
    }
}
