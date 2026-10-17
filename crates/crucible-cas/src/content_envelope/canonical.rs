//! Borrowed canonical envelope emission for encoding, identity and verification.
//!
//! One emitter preserves the fixed-width framing and sorted child order. Hash
//! and comparison consumers retain no image or child-identity strings; the
//! ordinary byte exporter alone owns and admits its returned vector.

use super::*;

impl ContentEnvelope {
    pub(super) fn emit_canonical(&self, emit: &mut dyn FnMut(&[u8])) {
        emit(MAGIC);
        emit(&ENVELOPE_VERSION.to_be_bytes());
        emit(&(self.schema_name.len() as u16).to_be_bytes());
        emit(self.schema_name.as_bytes());
        emit(&self.schema_version.to_be_bytes());
        emit(&(self.children.len() as u32).to_be_bytes());
        for child in &self.children {
            emit(&(child.role.len() as u16).to_be_bytes());
            emit(child.role.as_bytes());
            child.id.with_encoded_text(|encoded| {
                emit(&(encoded.len() as u16).to_be_bytes());
                emit(encoded);
            });
        }
        emit(&(self.body.len() as u64).to_be_bytes());
        emit(&self.body);
    }

    pub(super) fn matches_canonical_bytes(&self, bytes: &[u8]) -> bool {
        let mut remaining = bytes;
        let mut matches = true;
        self.emit_canonical(&mut |chunk| {
            if remaining.starts_with(chunk) {
                remaining = &remaining[chunk.len()..];
            } else {
                matches = false;
            }
        });
        matches && remaining.is_empty()
    }
}

#[cfg(test)]
mod tests;
