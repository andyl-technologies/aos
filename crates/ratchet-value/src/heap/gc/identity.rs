//! Canonical identities for Candidate-C indexed runtime objects.
//!
//! [`GcObjectIdentity`] names an object by its checked Candidate-C
//! `(kind, domain, index)` word. Unlike [`super::GcHeapAddress`], it is not a
//! native address and cannot be dereferenced. The thunk `FORCED` shortcut is
//! normalized away because it is mutable state on one object, not part of the
//! object's identity.

use crate::heap::{ArenaDomainId, ArenaIndex};
use crate::value::ValueTag;
use crate::value::compressed::{CompressedValueKind, CompressedValueWord};

/// A canonical `(kind, domain, index)` identity for one indexed runtime object.
///
/// This type deliberately has the same one-word layout as
/// [`CompressedValueWord`]. It accepts boxed scalar cells as well as ordinary
/// heap objects, but rejects inline integers, booleans, and null.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct GcObjectIdentity {
    word: CompressedValueWord,
}

const _: () = {
    assert!(std::mem::size_of::<GcObjectIdentity>() == 8);
    assert!(std::mem::align_of::<GcObjectIdentity>() == 8);
};

impl GcObjectIdentity {
    /// Derives canonical object identity from a checked Candidate-C word.
    ///
    /// Returns `None` for inline integers, booleans, and null because they do
    /// not name an arena object. A forced thunk and its unforced form produce
    /// the same identity.
    #[inline]
    pub fn from_word(word: CompressedValueWord) -> Option<Self> {
        word.arena_domain()?;
        word.arena_index()?;
        Some(Self {
            word: word.without_forced_bit(),
        })
    }

    /// Returns the canonical encoded `(kind, domain, index)` bits.
    #[inline]
    pub const fn raw(self) -> u64 {
        self.word.raw()
    }

    /// Returns the indexed representation kind.
    #[inline]
    pub fn kind(self) -> CompressedValueKind {
        self.word.kind()
    }

    /// Returns the semantic runtime tag for the indexed object.
    #[inline]
    pub fn tag(self) -> ValueTag {
        self.word.semantic_tag()
    }

    /// Returns the reservation or packed logical domain.
    ///
    /// A constructed identity always returns `Some`; the optional return type
    /// preserves the checked compressed-word accessor without an unreachable
    /// panic.
    #[inline]
    pub fn domain(self) -> Option<ArenaDomainId> {
        self.word.arena_domain()
    }

    /// Returns the byte offset or packed lane coordinate.
    ///
    /// A constructed identity always returns `Some`; the optional return type
    /// preserves the checked compressed-word accessor without an unreachable
    /// panic.
    #[inline]
    pub fn index(self) -> Option<ArenaIndex> {
        self.word.arena_index()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(raw: u32) -> ArenaDomainId {
        ArenaDomainId::from_raw(raw).expect("test domain is valid")
    }

    #[test]
    fn identity_is_one_word() {
        assert_eq!(std::mem::size_of::<GcObjectIdentity>(), 8);
        assert_eq!(std::mem::align_of::<GcObjectIdentity>(), 8);
    }

    #[test]
    fn identity_exposes_kind_domain_index_and_tag() {
        let domain = domain(17);
        let index = ArenaIndex::new(41);
        let word =
            CompressedValueWord::heap(domain, ValueTag::Attrs, index).expect("attrs is indexed");
        let identity = GcObjectIdentity::from_word(word).expect("attrs names an object");

        assert_eq!(identity.kind(), CompressedValueKind::Attrs);
        assert_eq!(identity.tag(), ValueTag::Attrs);
        assert_eq!(identity.domain(), Some(domain));
        assert_eq!(identity.index(), Some(index));
        assert_eq!(identity.raw(), word.raw());
    }

    #[test]
    fn boxed_scalars_have_object_identity_but_inline_values_do_not() {
        let domain = domain(23);
        let index = ArenaIndex::new(96);

        for word in [
            CompressedValueWord::boxed_int(domain, index),
            CompressedValueWord::boxed_float(domain, index),
        ] {
            let identity = GcObjectIdentity::from_word(word).expect("boxed scalar is indexed");
            assert_eq!(identity.domain(), Some(domain));
            assert_eq!(identity.index(), Some(index));
        }

        assert!(GcObjectIdentity::from_word(CompressedValueWord::null()).is_none());
        assert!(GcObjectIdentity::from_word(CompressedValueWord::boolean(true)).is_none());
        assert!(
            GcObjectIdentity::from_word(
                CompressedValueWord::inline_int(7).expect("small integer is inline")
            )
            .is_none()
        );
    }

    #[test]
    fn forced_thunk_state_does_not_change_object_identity() {
        let domain = domain(31);
        let index = ArenaIndex::new(128);
        let thunk =
            CompressedValueWord::heap(domain, ValueTag::Thunk, index).expect("thunk is indexed");
        let forced = thunk.with_forced_bit().expect("thunk accepts forced bit");

        assert_ne!(thunk, forced);
        assert_eq!(
            GcObjectIdentity::from_word(thunk),
            GcObjectIdentity::from_word(forced)
        );
        assert_eq!(
            GcObjectIdentity::from_word(forced)
                .expect("forced thunk is indexed")
                .raw(),
            thunk.raw()
        );
    }

    #[test]
    fn kind_participates_in_identity_for_shared_lane_coordinates() {
        let domain = domain(47);
        let index = ArenaIndex::new(0);
        let list =
            CompressedValueWord::heap(domain, ValueTag::List, index).expect("list is indexed");
        let attrs =
            CompressedValueWord::heap(domain, ValueTag::Attrs, index).expect("attrs is indexed");

        assert_ne!(
            GcObjectIdentity::from_word(list),
            GcObjectIdentity::from_word(attrs)
        );
    }

    #[cfg(feature = "candidate_c_value")]
    #[test]
    fn value_identity_normalizes_forced_state_without_changing_raw_equality() {
        let domain = domain(53);
        let thunk_word = CompressedValueWord::heap(domain, ValueTag::Thunk, ArenaIndex::new(256))
            .expect("thunk is indexed");
        let thunk = crate::value::Value::from_word(thunk_word);
        let forced = thunk.with_forced_bit().expect("thunk accepts forced bit");

        assert!(!thunk.raw_eq(forced));
        assert_eq!(thunk.object_identity(), forced.object_identity());
    }
}
