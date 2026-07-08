//! Nix string contexts: the dialect-owned dependency sets carried by strings.
//!
//! Nix strings are byte strings that also carry an immutable context: the set of
//! store-path dependencies that `derivationStrict` later turns into `.drv` input
//! edges. The context is a Nix-language-specific concept, so it lives in the Nix
//! dialect rather than the language-agnostic engine. The Phase-1 baseline stores
//! context elements as a sorted, deduplicated vector of raw byte paths and
//! deriving-path kinds. Later interned bitsets must preserve this canonical
//! element set and the propagation rules exercised here.
//!
//! The generic string *value* (the bytes plus a [`StringContext`]) lives in the
//! engine alongside its hash-cons machinery; this module owns only the context
//! and the shared error type both layers report.

use std::cmp::Ordering;
use std::hash::Hash;
use std::sync::Arc;

use thiserror::Error;

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
///
/// The path and output bytes are held behind [`Arc`]s so cloning an element
/// during context unions is an O(1) reference-count bump.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextElement {
    path: Arc<[u8]>,
    kind: ContextKind,
    output: Option<Arc<[u8]>>,
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
            path: path.into(),
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
            path: path.into(),
            kind: ContextKind::SingleOutput,
            output: Some(output.into()),
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
            path: path.into(),
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
        Ok(self.clone())
    }
}

/// An immutable Nix string context.
///
/// The canonical element set is the sorted, deduplicated vector of
/// [`ContextElement`]s, held behind an [`Arc`] so the pervasive cloning of
/// strings during evaluation shares the context structurally (copy-on-write):
/// [`Clone`] is an O(1) reference-count bump, and the constructors that change
/// the set ([`StringContext::new`], [`StringContext::union`], …) allocate a
/// fresh `Arc` rather than mutating shared storage. Equality, ordering, and
/// hashing remain content-based (they deref through the `Arc`), so this is a
/// representation change only — the observable canonical element set and the
/// propagation rules are unchanged.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct StringContext {
    elements: Arc<[ContextElement]>,
}

impl StringContext {
    /// Creates an empty string context.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Creates a string context from unsorted elements.
    ///
    /// Exact duplicate context elements are removed. Distinct deriving-path
    /// kinds or output names for the same path remain distinct, because
    /// `derivationStrict` observes those differences when building input edges.
    pub fn new(mut elements: Vec<ContextElement>) -> Self {
        elements.sort_unstable();
        elements.dedup();
        Self {
            elements: elements.into(),
        }
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
        Ok(Self {
            elements: elements.into(),
        })
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
        // Unions with an empty or identical context are pervasive (every
        // string clone unions with the empty context); resolve them with an
        // O(1) `Arc` bump instead of deep-cloning every element.
        if other.is_empty() || Arc::ptr_eq(&self.elements, &other.elements) {
            return Ok(self.clone());
        }
        if self.is_empty() {
            return Ok(other.clone());
        }
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

        Ok(Self {
            elements: elements.into(),
        })
    }

    /// Returns a clone of this context.
    ///
    /// The context is immutable and stored behind an [`Arc`], so this shares the
    /// canonical element set (an O(1) reference-count bump) rather than
    /// reallocating it — observationally identical to a deep copy. The fallible
    /// signature is retained for source compatibility with the pre-copy-on-write
    /// representation; it never returns `Err`.
    ///
    /// # Errors
    ///
    /// Never returns an error in the copy-on-write representation.
    pub fn try_clone_context(&self) -> Result<Self, NixStringError> {
        Ok(self.clone())
    }
}

impl<'a> IntoIterator for &'a StringContext {
    type Item = &'a ContextElement;
    type IntoIter = std::slice::Iter<'a, ContextElement>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
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

/// Returns a fallible deep clone of `bytes` that surfaces allocation failure.
///
/// # Errors
///
/// Returns [`NixStringError::ByteAllocationFailed`] if the byte storage cannot
/// be reserved.
pub fn try_clone_bytes(bytes: &[u8]) -> Result<Vec<u8>, NixStringError> {
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
}
