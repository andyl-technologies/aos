//! Byte-oriented Nix strings.
//!
//! Nix strings are byte strings, not Rust `str` values. Each string also carries
//! an immutable [`StringContext`]: the set of store-path dependencies that
//! `derivationStrict` later turns into `.drv` input edges. The context types are
//! Nix-language-specific and live in the Nix dialect
//! ([`aos_nix_dialect::string_context`]); this module re-exports them and layers
//! the generic string value [`NixString`] on top, adding the engine-local
//! structural hash used as a hash-cons key.

use crate::cache::HotXxh3Hash;

pub use aos_nix_dialect::string_context::{
    ContextElement, ContextKind, NixStringError, StringContext, try_clone_bytes,
};

/// A Nix byte string with its dependency context.
///
/// Derived equality and hashing include both the raw bytes and the full context.
/// That matches representation identity and future hash-cons keys; the eventual
/// Nix language equality operator belongs in the evaluator layer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct NixString {
    bytes: Vec<u8>,
    context: StringContext,
}

impl NixString {
    /// Creates a string from bytes and an already-normalized context.
    pub fn new(bytes: Vec<u8>, context: StringContext) -> Self {
        Self { bytes, context }
    }

    /// Creates a context-free string from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            context: StringContext::empty(),
        }
    }

    /// Returns the string's raw bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the string's context.
    pub const fn context(&self) -> &StringContext {
        &self.context
    }

    /// Returns the byte length of this string.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether this string has no bytes.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns whether this string carries any context elements.
    pub fn has_context(&self) -> bool {
        !self.context.is_empty()
    }

    /// Returns this string's in-process structural hash.
    ///
    /// The hash covers both bytes and context. It is only an accelerator for
    /// evaluator-local cons tables; callers must still confirm equality because
    /// xxh3 is not collision-free and is not a Nix-observable hash.
    pub fn structural_hash_xxh3(&self) -> HotXxh3Hash {
        HotXxh3Hash::for_hashable(self)
    }

    /// Concatenates two strings and unions their contexts.
    ///
    /// # Errors
    ///
    /// Returns [`NixStringError::StringLengthOverflow`] if the combined byte
    /// length overflows `usize`. Returns
    /// [`NixStringError::ByteAllocationFailed`],
    /// [`NixStringError::ContextAllocationFailed`], or
    /// [`NixStringError::ContextLengthOverflow`] if the resulting string or
    /// context cannot be built.
    pub fn concat(&self, other: &Self) -> Result<Self, NixStringError> {
        let len = self.bytes.len().checked_add(other.bytes.len()).ok_or(
            NixStringError::StringLengthOverflow {
                left: self.bytes.len(),
                right: other.bytes.len(),
            },
        )?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| NixStringError::ByteAllocationFailed { len })?;
        bytes.extend_from_slice(&self.bytes);
        bytes.extend_from_slice(&other.bytes);

        Ok(Self {
            bytes,
            context: self.context.union(&other.context)?,
        })
    }

    /// Appends `other`'s bytes and context to this string in place.
    ///
    /// This is the accumulator form of [`concat`](Self::concat): rather than
    /// allocating a fresh result, it grows the receiver's byte buffer (amortized,
    /// so folding many fragments stays linear rather than re-copying the running
    /// prefix each step) and folds `other`'s context into the receiver's. When
    /// `other` carries no context the union is skipped entirely, leaving the
    /// receiver's context buffer untouched. The observable bytes and context are
    /// identical to `*self = self.concat(other)?`.
    ///
    /// # Errors
    ///
    /// Returns [`NixStringError::StringLengthOverflow`] if the combined byte
    /// length overflows `usize`, [`NixStringError::ByteAllocationFailed`] if the
    /// byte buffer cannot grow, or [`NixStringError::ContextAllocationFailed`] /
    /// [`NixStringError::ContextLengthOverflow`] if the context union fails.
    pub fn append_in_place(&mut self, other: &Self) -> Result<(), NixStringError> {
        let additional = other.bytes.len();
        self.bytes
            .len()
            .checked_add(additional)
            .ok_or(NixStringError::StringLengthOverflow {
                left: self.bytes.len(),
                right: additional,
            })?;
        self.bytes
            .try_reserve(additional)
            .map_err(|_| NixStringError::ByteAllocationFailed { len: additional })?;
        self.bytes.extend_from_slice(&other.bytes);
        if !other.context.is_empty() {
            self.context = self.context.union(&other.context)?;
        }
        Ok(())
    }

    /// Returns a byte substring while preserving the whole string context.
    ///
    /// `start` and `len` are byte offsets. Out-of-range starts produce an empty
    /// byte string with the original context, and oversized lengths are clamped
    /// to the available bytes.
    ///
    /// # Errors
    ///
    /// Returns [`NixStringError::ByteAllocationFailed`] or
    /// [`NixStringError::ContextAllocationFailed`] if the substring or context
    /// copy cannot be reserved.
    pub fn substring_preserve_context(
        &self,
        start: usize,
        len: usize,
    ) -> Result<Self, NixStringError> {
        let start = start.min(self.bytes.len());
        let end = start.saturating_add(len).min(self.bytes.len());
        let source = &self.bytes[start..end];
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(source.len())
            .map_err(|_| NixStringError::ByteAllocationFailed { len: source.len() })?;
        bytes.extend_from_slice(source);

        Ok(Self {
            bytes,
            context: self.context.try_clone_context()?,
        })
    }

    /// Returns the same bytes with an empty string context.
    ///
    /// # Errors
    ///
    /// Returns [`NixStringError::ByteAllocationFailed`] if the string bytes
    /// cannot be copied.
    pub fn discard_context(&self) -> Result<Self, NixStringError> {
        Ok(Self {
            bytes: try_clone_bytes(&self.bytes)?,
            context: StringContext::empty(),
        })
    }

    /// Consumes the string and returns the same bytes with an empty context.
    pub fn into_context_free(self) -> Self {
        Self {
            bytes: self.bytes,
            context: StringContext::empty(),
        }
    }

    /// Consumes the string and returns its byte storage and context.
    pub fn into_parts(self) -> (Vec<u8>, StringContext) {
        (self.bytes, self.context)
    }
}

impl From<Vec<u8>> for NixString {
    fn from(bytes: Vec<u8>) -> Self {
        Self::from_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opaque(path: &[u8]) -> ContextElement {
        ContextElement::opaque_path(path.to_vec()).expect("opaque context builds")
    }

    fn output(path: &[u8], name: &[u8]) -> ContextElement {
        ContextElement::single_output(path.to_vec(), name.to_vec()).expect("output context builds")
    }

    fn deep(path: &[u8]) -> ContextElement {
        ContextElement::deep_derivation(path.to_vec()).expect("deep context builds")
    }

    fn singleton(element: ContextElement) -> StringContext {
        StringContext::singleton(element).expect("singleton context builds")
    }

    #[test]
    fn string_length_is_byte_length() {
        let string = NixString::from_bytes(vec![b'a', 0xff, 0xf0, 0x9f, 0x92, 0xa9]);

        assert_eq!(string.len(), 6);
        assert_eq!(string.bytes(), &[b'a', 0xff, 0xf0, 0x9f, 0x92, 0xa9]);
        assert!(!string.has_context());
    }

    #[test]
    fn concat_unions_contexts_and_concatenates_bytes() {
        let left = NixString::new(b"hello ".to_vec(), singleton(opaque(b"/nix/store/source")));
        let right = NixString::new(
            b"world".to_vec(),
            singleton(output(b"/nix/store/pkg.drv", b"out")),
        );

        let concat = left.concat(&right).expect("concat succeeds");

        assert_eq!(concat.bytes(), b"hello world");
        assert_eq!(concat.context().len(), 2);
        assert!(concat.context().contains(&opaque(b"/nix/store/source")));
        assert!(
            concat
                .context()
                .contains(&output(b"/nix/store/pkg.drv", b"out"))
        );
    }

    #[test]
    fn append_in_place_matches_concat() {
        let cases = [
            (
                NixString::from_bytes(b"a".to_vec()),
                NixString::from_bytes(b"bc".to_vec()),
            ),
            (
                NixString::new(b"x".to_vec(), singleton(opaque(b"/nix/store/l"))),
                NixString::from_bytes(b"y".to_vec()),
            ),
            (
                NixString::from_bytes(b"x".to_vec()),
                NixString::new(b"y".to_vec(), singleton(opaque(b"/nix/store/r"))),
            ),
            (
                NixString::new(b"x".to_vec(), singleton(opaque(b"/nix/store/l"))),
                NixString::new(
                    b"y".to_vec(),
                    singleton(output(b"/nix/store/pkg.drv", b"out")),
                ),
            ),
        ];
        for (left, right) in cases {
            let expected = left.concat(&right).expect("concat succeeds");
            let mut accumulator = left;
            accumulator
                .append_in_place(&right)
                .expect("append succeeds");
            assert_eq!(accumulator, expected);
        }
    }

    #[test]
    fn identical_bytes_with_different_contexts_remain_distinct() {
        let with_source = NixString::new(
            b"/nix/store/pkg".to_vec(),
            singleton(opaque(b"/nix/store/source")),
        );
        let with_output = NixString::new(
            b"/nix/store/pkg".to_vec(),
            singleton(output(b"/nix/store/pkg.drv", b"out")),
        );

        assert_eq!(with_source.bytes(), with_output.bytes());
        assert_ne!(with_source, with_output);
    }

    #[test]
    fn structural_hash_covers_bytes_and_context() {
        let context = singleton(opaque(b"/nix/store/source"));
        let first = NixString::new(b"/nix/store/pkg".to_vec(), context.clone());
        let identical = NixString::new(b"/nix/store/pkg".to_vec(), context);
        let different_bytes = NixString::new(
            b"/nix/store/other".to_vec(),
            singleton(opaque(b"/nix/store/source")),
        );
        let different_context = NixString::new(
            b"/nix/store/pkg".to_vec(),
            singleton(output(b"/nix/store/pkg.drv", b"out")),
        );

        assert_eq!(
            first.structural_hash_xxh3(),
            identical.structural_hash_xxh3()
        );
        assert_ne!(
            first.structural_hash_xxh3(),
            different_bytes.structural_hash_xxh3()
        );
        assert_ne!(
            first.structural_hash_xxh3(),
            different_context.structural_hash_xxh3()
        );
    }

    #[test]
    fn substring_preserves_whole_context() {
        let context = singleton(output(b"/nix/store/pkg.drv", b"out"));
        let string = NixString::new(b"abcdef".to_vec(), context.clone());

        let middle = string
            .substring_preserve_context(2, 3)
            .expect("substring succeeds");
        let beyond = string
            .substring_preserve_context(99, 1)
            .expect("substring succeeds");

        assert_eq!(middle.bytes(), b"cde");
        assert_eq!(middle.context(), &context);
        assert!(beyond.bytes().is_empty());
        assert_eq!(beyond.context(), &context);
    }

    #[test]
    fn discard_context_clears_only_context() {
        let string = NixString::new(
            b"/nix/store/pkg".to_vec(),
            singleton(output(b"/nix/store/pkg.drv", b"out")),
        );

        let discarded = string.discard_context().expect("discard succeeds");

        assert_eq!(discarded.bytes(), b"/nix/store/pkg");
        assert!(!discarded.has_context());
    }

    #[test]
    fn into_context_free_reuses_bytes_and_drops_context() {
        let string = NixString::new(b"drv".to_vec(), singleton(deep(b"/nix/store/pkg.drv")));

        let discarded = string.into_context_free();

        assert_eq!(discarded.bytes(), b"drv");
        assert!(!discarded.has_context());
    }
}
