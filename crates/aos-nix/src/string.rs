//! Byte-oriented Nix strings and string contexts.
//!
//! Nix strings are byte strings, not Rust `str` values. Each string also carries
//! an immutable context: the set of store-path dependencies that
//! `derivationStrict` later turns into `.drv` input edges. The Phase-1 baseline
//! stores context elements as a sorted, deduplicated vector of raw byte paths
//! and deriving-path kinds. Later interned bitsets must preserve this canonical
//! element set and the propagation rules exercised here.

use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use thiserror::Error;
use xxhash_rust::xxh3::Xxh3;

/// The deriving-path kind carried by a string-context element.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ContextKind {
    /// A plain store path dependency.
    OpaquePath,
    /// One named output of a derivation path.
    SingleOutput,
    /// A derivation and its full build closure.
    DeepDerivation,
}

/// One element in a Nix string context.
///
/// Elements are ordered by raw path bytes, then by [`ContextKind`], then by
/// output name for [`ContextKind::SingleOutput`]. The path syntax is validated
/// by store-path aware layers; this type only enforces the structural invariant
/// that paths are non-empty.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextElement {
    path: Vec<u8>,
    kind: ContextKind,
    output: Option<Vec<u8>>,
}

impl ContextElement {
    /// Creates an opaque store-path context element.
    ///
    /// # Errors
    ///
    /// Returns [`NixStringError::EmptyContextPath`] when `path` is empty.
    pub fn opaque_path(path: Vec<u8>) -> Result<Self, NixStringError> {
        if path.is_empty() {
            return Err(NixStringError::EmptyContextPath);
        }

        Ok(Self {
            path,
            kind: ContextKind::OpaquePath,
            output: None,
        })
    }

    /// Creates a single-output derivation context element.
    ///
    /// # Errors
    ///
    /// Returns [`NixStringError::EmptyContextPath`] when `path` is empty.
    pub fn single_output(path: Vec<u8>, output: Vec<u8>) -> Result<Self, NixStringError> {
        if path.is_empty() {
            return Err(NixStringError::EmptyContextPath);
        }

        Ok(Self {
            path,
            kind: ContextKind::SingleOutput,
            output: Some(output),
        })
    }

    /// Creates a deep derivation context element.
    ///
    /// # Errors
    ///
    /// Returns [`NixStringError::EmptyContextPath`] when `path` is empty.
    pub fn deep_derivation(path: Vec<u8>) -> Result<Self, NixStringError> {
        if path.is_empty() {
            return Err(NixStringError::EmptyContextPath);
        }

        Ok(Self {
            path,
            kind: ContextKind::DeepDerivation,
            output: None,
        })
    }

    /// Returns the deriving-path kind for this element.
    pub const fn kind(&self) -> ContextKind {
        self.kind
    }

    /// Returns the raw store path bytes carried by this element.
    pub fn path(&self) -> &[u8] {
        &self.path
    }

    /// Returns the output name for a single-output element.
    pub fn output(&self) -> Option<&[u8]> {
        self.output.as_deref()
    }

    fn try_clone_element(&self) -> Result<Self, NixStringError> {
        let path = try_clone_bytes(&self.path)?;
        let output = self.output.as_deref().map(try_clone_bytes).transpose()?;
        Ok(Self {
            path,
            kind: self.kind,
            output,
        })
    }
}

/// An immutable Nix string context.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct StringContext {
    elements: Vec<ContextElement>,
}

impl StringContext {
    /// Creates an empty string context.
    pub const fn empty() -> Self {
        Self {
            elements: Vec::new(),
        }
    }

    /// Creates a string context from unsorted elements.
    ///
    /// Exact duplicate context elements are removed. Distinct deriving-path
    /// kinds or output names for the same path remain distinct, because
    /// `derivationStrict` observes those differences when building input edges.
    pub fn new(mut elements: Vec<ContextElement>) -> Self {
        elements.sort_unstable();
        elements.dedup();
        Self { elements }
    }

    /// Creates a context containing one element.
    ///
    /// # Errors
    ///
    /// Returns [`NixStringError::ContextAllocationFailed`] if the context
    /// storage cannot be reserved.
    pub fn singleton(element: ContextElement) -> Result<Self, NixStringError> {
        let mut elements = Vec::new();
        elements
            .try_reserve_exact(1)
            .map_err(|_| NixStringError::ContextAllocationFailed { len: 1 })?;
        elements.push(element);
        Ok(Self { elements })
    }

    /// Returns the number of context elements.
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Returns whether this context is empty.
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Returns all context elements in canonical order.
    pub fn elements(&self) -> &[ContextElement] {
        &self.elements
    }

    /// Iterates context elements in canonical order.
    pub fn iter(&self) -> std::slice::Iter<'_, ContextElement> {
        self.elements.iter()
    }

    /// Returns whether this context contains `element`.
    pub fn contains(&self, element: &ContextElement) -> bool {
        self.elements.binary_search(element).is_ok()
    }

    /// Returns the set union of two contexts.
    ///
    /// # Errors
    ///
    /// Returns [`NixStringError::ContextLengthOverflow`] if the combined context
    /// length overflows `usize`. Returns
    /// [`NixStringError::ContextAllocationFailed`] or
    /// [`NixStringError::ByteAllocationFailed`] if the union cannot reserve its
    /// storage.
    pub fn union(&self, other: &Self) -> Result<Self, NixStringError> {
        let capacity =
            self.len()
                .checked_add(other.len())
                .ok_or(NixStringError::ContextLengthOverflow {
                    left: self.len(),
                    right: other.len(),
                })?;
        let mut elements = Vec::new();
        elements
            .try_reserve_exact(capacity)
            .map_err(|_| NixStringError::ContextAllocationFailed { len: capacity })?;

        let mut left = 0;
        let mut right = 0;
        while left < self.elements.len() && right < other.elements.len() {
            match self.elements[left].cmp(&other.elements[right]) {
                Ordering::Less => {
                    elements.push(self.elements[left].try_clone_element()?);
                    left += 1;
                }
                Ordering::Equal => {
                    elements.push(self.elements[left].try_clone_element()?);
                    left += 1;
                    right += 1;
                }
                Ordering::Greater => {
                    elements.push(other.elements[right].try_clone_element()?);
                    right += 1;
                }
            }
        }
        for element in &self.elements[left..] {
            elements.push(element.try_clone_element()?);
        }
        for element in &other.elements[right..] {
            elements.push(element.try_clone_element()?);
        }

        Ok(Self { elements })
    }

    fn try_clone_context(&self) -> Result<Self, NixStringError> {
        let mut elements = Vec::new();
        elements
            .try_reserve_exact(self.elements.len())
            .map_err(|_| NixStringError::ContextAllocationFailed {
                len: self.elements.len(),
            })?;
        for element in &self.elements {
            elements.push(element.try_clone_element()?);
        }
        Ok(Self { elements })
    }
}

impl<'a> IntoIterator for &'a StringContext {
    type Item = &'a ContextElement;
    type IntoIter = std::slice::Iter<'a, ContextElement>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

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
    pub fn structural_hash_xxh3(&self) -> u64 {
        let mut hasher = Xxh3::new();
        self.hash(&mut hasher);
        hasher.finish()
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

/// A string or string-context construction failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum NixStringError {
    /// A context element was constructed with no store-path bytes.
    #[error("string context path is empty")]
    EmptyContextPath,
    /// The resulting byte string would be too large to address.
    #[error("string byte length overflow: {left} + {right}")]
    StringLengthOverflow {
        /// The left-hand string length.
        left: usize,
        /// The right-hand string length.
        right: usize,
    },
    /// The resulting context would be too large to address.
    #[error("string context length overflow: {left} + {right}")]
    ContextLengthOverflow {
        /// The left-hand context length.
        left: usize,
        /// The right-hand context length.
        right: usize,
    },
    /// Byte storage could not be reserved.
    #[error("failed to reserve string byte storage for {len} bytes")]
    ByteAllocationFailed {
        /// The requested byte capacity.
        len: usize,
    },
    /// Context element storage could not be reserved.
    #[error("failed to reserve string context storage for {len} elements")]
    ContextAllocationFailed {
        /// The requested context element capacity.
        len: usize,
    },
}

fn try_clone_bytes(bytes: &[u8]) -> Result<Vec<u8>, NixStringError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(bytes.len())
        .map_err(|_| NixStringError::ByteAllocationFailed { len: bytes.len() })?;
    cloned.extend_from_slice(bytes);
    Ok(cloned)
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
    fn context_element_constructors_validate_structure() {
        assert_eq!(
            ContextElement::opaque_path(Vec::new()).expect_err("empty path is invalid"),
            NixStringError::EmptyContextPath
        );
        ContextElement::single_output(b"/nix/store/a.drv".to_vec(), Vec::new())
            .expect("empty output names are accepted by C++ Nix string contexts");

        let element = output(b"/nix/store/a.drv", b"dev");
        assert_eq!(element.kind(), ContextKind::SingleOutput);
        assert_eq!(element.path(), b"/nix/store/a.drv");
        assert_eq!(element.output(), Some(b"dev".as_slice()));
    }

    #[test]
    fn context_is_sorted_and_deduplicated_without_collapsing_kinds() {
        let opaque = opaque(b"/nix/store/a");
        let output = output(b"/nix/store/a.drv", b"out");
        let deep = deep(b"/nix/store/a.drv");
        let context = StringContext::new(vec![
            deep.clone(),
            opaque.clone(),
            output.clone(),
            output.clone(),
        ]);

        assert_eq!(context.elements(), &[opaque, output, deep]);
        assert_eq!(context.len(), 3);
    }

    #[test]
    fn context_union_merges_canonical_sets() {
        let source = opaque(b"/nix/store/source");
        let out = output(b"/nix/store/pkg.drv", b"out");
        let dev = output(b"/nix/store/pkg.drv", b"dev");
        let left = StringContext::new(vec![out.clone(), source.clone()]);
        let right = StringContext::new(vec![dev.clone(), out.clone()]);

        let union = left.union(&right).expect("context union succeeds");

        assert!(union.contains(&out));
        assert!(union.contains(&dev));
        assert_eq!(union.elements(), &[dev, out, source]);
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
