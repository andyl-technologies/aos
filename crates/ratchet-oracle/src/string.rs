//! Byte-oriented Nix strings.
//!
//! Nix strings are byte strings, not Rust `str` values. Each string also carries
//! an immutable [`StringContext`]: the set of store-path dependencies that
//! `derivationStrict` later turns into `.drv` input edges. The context types are
//! Nix-language-specific and live in the Nix dialect
//! ([`aos_nix_dialect::string_context`]); this module re-exports them and layers
//! the generic string value [`NixString`] on top, adding the engine-local
//! structural hash used as a hash-cons key.

use std::hash::{Hash, Hasher};

use crate::cache::HotXxh3Hash;
use crate::heap::flat::FlatBytes;

pub use aos_nix_dialect::string_context::{
    ContextElement, ContextKind, NixStringError, StringContext, try_clone_bytes,
};

/// The byte storage behind one [`NixString`].
///
/// RFC-0007 doc 30 stage FV-1b: strings interned into the evaluator heap's
/// flat object store keep their bytes *inline* in the flat allocation, behind
/// a [`FlatBytes`] witness, instead of a per-string `Vec` allocation. Every
/// other string — evaluator temporaries, cache payloads, shared-mode slot
/// payloads — keeps the owned `Vec`. The variant is invisible through the
/// public API: `bytes()` is the only reader and all equality/hash/clone
/// behavior is defined over the byte slice, so the two representations are
/// observationally identical.
///
/// A clone always deep-copies into [`NixStringBytes::Owned`]: the witness is
/// valid only inside the flat store's payload, so no flat-backed string can
/// escape the store by cloning.
#[derive(Debug)]
enum NixStringBytes {
    /// Bytes owned by a process-allocator `Vec`.
    Owned(Vec<u8>),
    /// Bytes inlined in a flat-object allocation (heap-resident strings only).
    Flat(FlatBytes),
}

impl NixStringBytes {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Owned(bytes) => bytes,
            Self::Flat(bytes) => bytes.as_slice(),
        }
    }
}

/// A Nix byte string with its dependency context.
///
/// Equality and hashing include both the raw bytes and the full context, and
/// are defined over the byte *slice* so they are independent of the storage
/// representation (see [`NixStringBytes`]); the slice-based hash is
/// bit-identical to the previous derived `Vec<u8>` hash, keeping structural
/// hash-cons keys stable. The eventual Nix language equality operator belongs
/// in the evaluator layer.
pub struct NixString {
    bytes: NixStringBytes,
    context: StringContext,
}

impl Eq for NixString {}

impl std::fmt::Debug for NixString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Keep the pre-FV-1b derived shape (bytes rendered as a byte list)
        // regardless of the storage representation.
        f.debug_struct("NixString")
            .field("bytes", &self.bytes.as_slice())
            .field("context", &self.context)
            .finish()
    }
}

impl Clone for NixString {
    fn clone(&self) -> Self {
        // Deep-copy into owned storage: a flat-backed string must never
        // propagate its inline-bytes witness outside the flat store payload.
        Self {
            bytes: NixStringBytes::Owned(self.bytes.as_slice().to_vec()),
            context: self.context.clone(),
        }
    }
}

impl Default for NixString {
    fn default() -> Self {
        Self::from_bytes(Vec::new())
    }
}

impl PartialEq for NixString {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.as_slice() == other.bytes.as_slice() && self.context == other.context
    }
}

impl Hash for NixString {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Matches the previous `#[derive(Hash)]` over `Vec<u8>` exactly:
        // `Vec<T>` hashing delegates to the `[T]` slice impl.
        self.bytes.as_slice().hash(state);
        self.context.hash(state);
    }
}

impl NixString {
    /// Creates a string from bytes and an already-normalized context.
    pub fn new(bytes: Vec<u8>, context: StringContext) -> Self {
        Self {
            bytes: NixStringBytes::Owned(bytes),
            context,
        }
    }

    /// Creates a context-free string from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes: NixStringBytes::Owned(bytes),
            context: StringContext::empty(),
        }
    }

    /// Creates a string over flat-object inline bytes (doc 30 FV-1b).
    ///
    /// Only the evaluator heap's flat store constructs these: the witness is
    /// valid exactly as long as the flat allocation that carries the string,
    /// and every escape path (clone, [`NixString::into_parts`]) deep-copies
    /// back into owned storage.
    pub fn from_flat_bytes(bytes: FlatBytes, context: StringContext) -> Self {
        Self {
            bytes: NixStringBytes::Flat(bytes),
            context,
        }
    }

    /// Returns the string's raw bytes.
    /// Returns whether the byte storage is an owned `Vec` (RFC-0007 doc 31
    /// §1 heap-image capture: over-threshold strings keep their moved owned
    /// buffer, which must serialize as a payload segment — the dumped `Vec`
    /// header would otherwise restore dangling).
    #[cfg(feature = "candidate_c_value")]
    pub(crate) fn has_owned_bytes(&self) -> bool {
        matches!(&self.bytes, NixStringBytes::Owned(_))
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Returns the string's context.
    pub const fn context(&self) -> &StringContext {
        &self.context
    }

    /// Returns the byte length of this string.
    pub fn len(&self) -> usize {
        self.bytes.as_slice().len()
    }

    /// Returns whether this string has no bytes.
    pub fn is_empty(&self) -> bool {
        self.bytes.as_slice().is_empty()
    }

    /// Rebases the inline byte-run witness by `delta` bytes.
    ///
    /// The heap-image restore path (RFC-0007 doc 31 §1 decision 6) copies a flat
    /// string's bytes into a reservation mapped at a new base, then shifts its
    /// `Flat` witness by `delta = new_base − old_base`. `Owned` strings carry no
    /// arena witness and are unchanged. The `Arc`-backed string context is not an
    /// arena interior and is rebuilt separately by the stage-2 context-collapse
    /// path ([`NixString::with_replaced_context`]), not shifted here. Reads/writes
    /// no byte.
    #[cfg(feature = "candidate_c_value")]
    pub fn rebase_witnesses(&mut self, delta: isize) {
        if let NixStringBytes::Flat(bytes) = &mut self.bytes {
            bytes.rebase(delta);
        }
    }

    /// Returns whether this string carries any context elements.
    pub fn has_context(&self) -> bool {
        !self.context.is_empty()
    }

    /// Returns a copy of this string over the same byte storage but carrying
    /// `context` (RFC-0007 doc 31 §1 stage-2 context collapse).
    ///
    /// Unlike [`Clone`], this preserves a `Flat` witness rather than deep-copying
    /// to owned bytes: heap-image restore rebases the flat witness in place, then
    /// reconstructs the string with a rebuilt context so the whole payload can be
    /// written over the stale `Arc`-backed context without dropping it. The
    /// returned value therefore shares the same flat allocation and must be
    /// written straight back into that allocation's store payload.
    #[cfg(feature = "candidate_c_value")]
    pub fn with_replaced_context(&self, context: StringContext) -> Self {
        let bytes = match &self.bytes {
            NixStringBytes::Flat(bytes) => NixStringBytes::Flat(*bytes),
            NixStringBytes::Owned(bytes) => NixStringBytes::Owned(bytes.clone()),
        };
        Self { bytes, context }
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
        let left = self.bytes.as_slice();
        let right = other.bytes.as_slice();
        let len =
            left.len()
                .checked_add(right.len())
                .ok_or(NixStringError::StringLengthOverflow {
                    left: left.len(),
                    right: right.len(),
                })?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| NixStringError::ByteAllocationFailed { len })?;
        bytes.extend_from_slice(left);
        bytes.extend_from_slice(right);

        Ok(Self {
            bytes: NixStringBytes::Owned(bytes),
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
        let additional = other.bytes.as_slice().len();
        self.len()
            .checked_add(additional)
            .ok_or(NixStringError::StringLengthOverflow {
                left: self.len(),
                right: additional,
            })?;
        // Flat-backed strings are immutable heap payloads; an accumulator is
        // always owned. Materialize defensively so the invariant is local.
        let bytes = self.owned_bytes_mut(additional)?;
        bytes
            .try_reserve(additional)
            .map_err(|_| NixStringError::ByteAllocationFailed { len: additional })?;
        bytes.extend_from_slice(other.bytes.as_slice());
        if !other.context.is_empty() {
            self.context = self.context.union(&other.context)?;
        }
        Ok(())
    }

    /// Returns the owned byte buffer, materializing flat-backed storage.
    ///
    /// `additional` sizes the reservation when a flat-backed string must be
    /// copied into owned storage before mutation.
    fn owned_bytes_mut(&mut self, additional: usize) -> Result<&mut Vec<u8>, NixStringError> {
        if let NixStringBytes::Flat(flat) = &self.bytes {
            let source = flat.as_slice();
            let len = source.len().saturating_add(additional);
            let mut owned = Vec::new();
            owned
                .try_reserve_exact(len)
                .map_err(|_| NixStringError::ByteAllocationFailed { len })?;
            owned.extend_from_slice(source);
            self.bytes = NixStringBytes::Owned(owned);
        }
        match &mut self.bytes {
            NixStringBytes::Owned(bytes) => Ok(bytes),
            // Unreachable: the flat arm above just replaced the storage.
            NixStringBytes::Flat(flat) => {
                Err(NixStringError::ByteAllocationFailed { len: flat.len() })
            }
        }
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
        let slice = self.bytes.as_slice();
        let start = start.min(slice.len());
        let end = start.saturating_add(len).min(slice.len());
        let source = &slice[start..end];
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(source.len())
            .map_err(|_| NixStringError::ByteAllocationFailed { len: source.len() })?;
        bytes.extend_from_slice(source);

        Ok(Self {
            bytes: NixStringBytes::Owned(bytes),
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
            bytes: NixStringBytes::Owned(try_clone_bytes(self.bytes.as_slice())?),
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
    ///
    /// Flat-backed strings (doc 30 FV-1b) copy their inline bytes into a
    /// fresh `Vec`: byte storage handed to a caller always owns its bytes.
    pub fn into_parts(self) -> (Vec<u8>, StringContext) {
        let bytes = match self.bytes {
            NixStringBytes::Owned(bytes) => bytes,
            NixStringBytes::Flat(flat) => flat.as_slice().to_vec(),
        };
        (bytes, self.context)
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
