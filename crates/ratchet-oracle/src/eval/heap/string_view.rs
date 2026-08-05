//! Allocation-free read views over ordinary and packed strings and paths.
//!
//! The evaluator frequently needs only byte and context-presence queries.
//! This boundary lets those paths consume a packed string/path record without
//! rebuilding a compatibility [`NixString`] or allocating context objects.

use crate::string::{
    ContextElement, ContextKind, NixString, NixStringError, StringContext, try_clone_bytes,
};

#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
use super::packed_string_lane::{
    PackedContextElementView, PackedNixStringView, PackedStringContextIter, PackedStringContextView,
};

/// A borrowed string or path backed by the flat heap or a packed generation.
#[derive(Clone, Copy, Debug)]
pub(crate) enum EvalStringView<'a> {
    /// An ordinary flat-heap string or path.
    Flat(&'a NixString),
    /// A validated packed string or path record.
    #[cfg(any(
        feature = "compact_destination_probe",
        feature = "evacuation_plan_probe"
    ))]
    Packed(PackedNixStringView<'a>),
}

impl<'a> EvalStringView<'a> {
    /// Borrows an ordinary flat string or path.
    pub(crate) const fn flat(string: &'a NixString) -> Self {
        Self::Flat(string)
    }

    /// Wraps a validated packed string or path view.
    #[cfg(any(
        feature = "compact_destination_probe",
        feature = "evacuation_plan_probe"
    ))]
    pub(crate) const fn packed(string: PackedNixStringView<'a>) -> Self {
        Self::Packed(string)
    }

    /// Returns the exact byte string.
    pub(crate) fn bytes(self) -> &'a [u8] {
        match self {
            Self::Flat(string) => string.bytes(),
            #[cfg(any(
                feature = "compact_destination_probe",
                feature = "evacuation_plan_probe"
            ))]
            Self::Packed(string) => string.bytes(),
        }
    }

    /// Returns the byte length.
    pub(crate) fn len(self) -> usize {
        self.bytes().len()
    }

    /// Returns whether the byte string is empty.
    pub(crate) fn is_empty(self) -> bool {
        self.bytes().is_empty()
    }

    /// Returns whether the dependency context is nonempty.
    pub(crate) fn has_context(self) -> bool {
        !self.context().is_empty()
    }

    /// Returns an allocation-free view of the canonical dependency context.
    pub(crate) fn context(self) -> EvalStringContextView<'a> {
        match self {
            Self::Flat(string) => EvalStringContextView::Flat(string.context()),
            #[cfg(any(
                feature = "compact_destination_probe",
                feature = "evacuation_plan_probe"
            ))]
            Self::Packed(string) => EvalStringContextView::Packed(string.context()),
        }
    }

    /// Copies this view into an owned compatibility string.
    ///
    /// This boundary is intended only for operations that semantically produce
    /// a new owned string. Read-only consumers should continue using the view
    /// directly so packed storage remains allocation-free.
    ///
    /// # Errors
    ///
    /// Returns [`NixStringError`] when byte or context storage cannot be
    /// reserved, or when a malformed context element cannot be reconstructed.
    pub(crate) fn try_to_owned(self) -> Result<NixString, NixStringError> {
        Ok(NixString::new(
            try_clone_bytes(self.bytes())?,
            self.context().try_to_owned()?,
        ))
    }
}

/// A borrowed canonical context backed by ordinary or packed storage.
#[derive(Clone, Copy, Debug)]
pub(crate) enum EvalStringContextView<'a> {
    /// An ordinary immutable string context.
    Flat(&'a StringContext),
    /// A validated packed string context.
    #[cfg(any(
        feature = "compact_destination_probe",
        feature = "evacuation_plan_probe"
    ))]
    Packed(PackedStringContextView<'a>),
}

impl<'a> EvalStringContextView<'a> {
    /// Returns the number of canonical context elements.
    pub(crate) fn len(self) -> usize {
        match self {
            Self::Flat(context) => context.len(),
            #[cfg(any(
                feature = "compact_destination_probe",
                feature = "evacuation_plan_probe"
            ))]
            Self::Packed(context) => context.len(),
        }
    }

    /// Returns whether the context is empty.
    pub(crate) fn is_empty(self) -> bool {
        self.len() == 0
    }

    /// Iterates normalized context elements in canonical order.
    pub(crate) fn iter(self) -> EvalStringContextIter<'a> {
        let inner = match self {
            Self::Flat(context) => EvalStringContextIterInner::Flat(context.iter()),
            #[cfg(any(
                feature = "compact_destination_probe",
                feature = "evacuation_plan_probe"
            ))]
            Self::Packed(context) => EvalStringContextIterInner::Packed(context.iter()),
        };
        EvalStringContextIter { inner }
    }

    /// Copies this canonical view into an owned compatibility context.
    ///
    /// Flat contexts retain their shared backing through an O(1) clone.
    /// Packed contexts reconstruct only the owned result requested by the
    /// caller; the packed generation itself remains registry-free.
    ///
    /// # Errors
    ///
    /// Returns [`NixStringError`] when element or byte storage cannot be
    /// reserved, or when a malformed element cannot be reconstructed.
    pub(crate) fn try_to_owned(self) -> Result<StringContext, NixStringError> {
        if let Self::Flat(context) = self {
            return Ok(context.clone());
        }
        let mut elements = Vec::new();
        elements
            .try_reserve_exact(self.len())
            .map_err(|_| NixStringError::ContextAllocationFailed { len: self.len() })?;
        for element in self.iter() {
            let path = try_clone_bytes(element.path())?;
            let owned = match element.kind() {
                ContextKind::OpaquePath => ContextElement::opaque_path(path),
                ContextKind::DeepDerivation => ContextElement::deep_derivation(path),
                ContextKind::SingleOutput => ContextElement::single_output(
                    path,
                    try_clone_bytes(element.output().unwrap_or_default())?,
                ),
            }?;
            elements.push(owned);
        }
        Ok(StringContext::new(elements))
    }
}

/// One representation-neutral borrowed context element.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EvalContextElementView<'a> {
    kind: ContextKind,
    path: &'a [u8],
    output: Option<&'a [u8]>,
}

impl<'a> EvalContextElementView<'a> {
    /// Returns the deriving-path kind.
    pub(crate) const fn kind(self) -> ContextKind {
        self.kind
    }

    /// Returns the exact store-path bytes.
    pub(crate) const fn path(self) -> &'a [u8] {
        self.path
    }

    /// Returns the output bytes for `SingleOutput`.
    pub(crate) const fn output(self) -> Option<&'a [u8]> {
        self.output
    }
}

/// An allocation-free iterator over either context representation.
#[derive(Clone, Debug)]
pub(crate) struct EvalStringContextIter<'a> {
    inner: EvalStringContextIterInner<'a>,
}

#[derive(Clone, Debug)]
enum EvalStringContextIterInner<'a> {
    Flat(std::slice::Iter<'a, ContextElement>),
    #[cfg(any(
        feature = "compact_destination_probe",
        feature = "evacuation_plan_probe"
    ))]
    Packed(PackedStringContextIter<'a>),
}

impl<'a> Iterator for EvalStringContextIter<'a> {
    type Item = EvalContextElementView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            EvalStringContextIterInner::Flat(elements) => elements.next().map(flat_context_element),
            #[cfg(any(
                feature = "compact_destination_probe",
                feature = "evacuation_plan_probe"
            ))]
            EvalStringContextIterInner::Packed(elements) => {
                elements.next().map(packed_context_element)
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = match &self.inner {
            EvalStringContextIterInner::Flat(elements) => elements.len(),
            #[cfg(any(
                feature = "compact_destination_probe",
                feature = "evacuation_plan_probe"
            ))]
            EvalStringContextIterInner::Packed(elements) => elements.len(),
        };
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for EvalStringContextIter<'_> {}

fn flat_context_element(element: &ContextElement) -> EvalContextElementView<'_> {
    EvalContextElementView {
        kind: element.kind(),
        path: element.path(),
        output: element.output(),
    }
}

#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
fn packed_context_element(element: PackedContextElementView<'_>) -> EvalContextElementView<'_> {
    EvalContextElementView {
        kind: element.kind(),
        path: element.path(),
        output: element.output(),
    }
}

#[cfg(all(
    test,
    any(
        feature = "compact_destination_probe",
        feature = "evacuation_plan_probe"
    )
))]
mod tests {
    use super::*;
    use crate::eval::heap::packed_string_lane::{
        PackedStringLaneCapacities, PackedStringLaneDirectBuilder,
    };
    use crate::string::{ContextElement, StringContext};

    #[test]
    fn flat_and_packed_views_match_bytes_lengths_and_context_presence() {
        let context = StringContext::new(vec![
            ContextElement::opaque_path(b"/nix/store/source".to_vec())
                .expect("test context element builds"),
            ContextElement::single_output(b"/nix/store/pkg.drv".to_vec(), Vec::new())
                .expect("test output context element builds"),
            ContextElement::deep_derivation(b"/nix/store/deep.drv".to_vec())
                .expect("test deep context element builds"),
        ]);
        let string = NixString::new(vec![0, 0xff, b'x'], context.clone());
        let mut builder = PackedStringLaneDirectBuilder::try_new(PackedStringLaneCapacities {
            strings: 1,
            contexts: 1,
            context_elements: context.len(),
            bytes: string.len()
                + context
                    .iter()
                    .map(|element| element.path().len() + element.output().map_or(0, <[u8]>::len))
                    .sum::<usize>(),
            ..PackedStringLaneCapacities::default()
        })
        .expect("packed string builder reserves");
        let context = builder
            .append_context(&context)
            .expect("packed context appends");
        let reference = builder
            .append_string(&string, context)
            .expect("packed string appends");
        let lane = builder.finish().expect("packed string lane finalizes");
        let flat = EvalStringView::flat(&string);
        let packed = EvalStringView::packed(
            lane.string(reference)
                .expect("packed string coordinate resolves"),
        );

        assert_eq!(flat.bytes(), packed.bytes());
        assert_eq!(flat.len(), packed.len());
        assert_eq!(flat.is_empty(), packed.is_empty());
        assert_eq!(flat.has_context(), packed.has_context());
        assert_eq!(flat.context().len(), packed.context().len());
        assert_eq!(
            flat.context().iter().collect::<Vec<_>>(),
            packed.context().iter().collect::<Vec<_>>()
        );
    }
}
