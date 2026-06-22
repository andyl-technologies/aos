//! Generic runtime value representation: tagged values, lists, and the bump heap.
//!
//! This is the `ratchet-value` crate — the value-representation layer of the
//! RFC-0007 §1.1 crate topology, extracted from the former `aos-nix`
//! `value`/`list`/`heap` modules (Phase 1b). It carries no Nix-dialect
//! knowledge and depends on no other workspace crate.
//!
//! The RFC §1.1 reserves this crate as the eventual home of the NaN-boxed,
//! hash-consed value representation (an UNSAFE band). Until that lands there is
//! no `unsafe` here, so the crate keeps `#![forbid(unsafe_code)]`; the attribute
//! relaxes to the per-block `// SAFETY:` discipline when the bit-twiddling
//! representation arrives.
#![forbid(unsafe_code)]

pub mod heap;
pub mod list;
pub mod value;
