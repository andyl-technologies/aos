//! Generic runtime value representation: tagged values, hash-consing, lists,
//! and the bump heap.
//!
//! This is the `ratchet-value` crate — the value-representation layer of the
//! RFC-0007 §1.1 crate topology, extracted from the former `aos-nix`
//! `value`/`list`/`heap` modules (Phase 1b). It carries no Nix-dialect
//! knowledge and depends on no other workspace crate.
//!
//! The RFC §1.1 reserves this crate as the eventual home of the NaN-boxed,
//! pointer-tagged, hash-consed value representation (an UNSAFE band). The
//! current pointer-tagging support is still a safe layout helper. The Tier-A
//! arena now owns its `mmap`/`munmap` boundary here, so unsafe code stays
//! confined to the runtime-value crate under explicit `// SAFETY:` comments.
#![deny(unsafe_op_in_unsafe_fn)]

// Re-exported so the moved `attrs` module's `crate::syntax::Symbol` path keeps
// resolving without rewriting it (attrs needs the interned-symbol type).
pub use aos_nix_syntax as syntax;

pub mod attrs;
pub mod hashcons;
pub mod heap;
pub mod list;
pub mod value;
