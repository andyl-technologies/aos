//! `ratchet-jit` -- the future unsafe execution-tier boundary for RFC-0007.
//!
//! This crate is the landing zone for the Cranelift baseline JIT and later
//! optimized native tiers. It intentionally starts with safe, address-free
//! metadata adapters only: [`abi`] mirrors the frozen runtime-call signatures
//! from `ratchet-core`, and [`symbols`] mirrors the stable runtime-symbol
//! manifest from `ratchet-core`. Runtime-symbol candidate reports currently
//! remain in `ratchet-oracle`; a later shared metadata layer can move them below
//! both crates without making the JIT crate depend on the safe oracle stack.
//!
//! Actual `unsafe extern "C"` wrappers, raw function-pointer calls, Cranelift
//! module construction, and `JITBuilder::symbol` registration are future work
//! inside this crate. Unsafe blocks are allowed only behind the crate-level
//! `unsafe_op_in_unsafe_fn` discipline and must carry local `// SAFETY:`
//! invariants when those later slices land.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod abi;
pub mod symbols;

pub use abi::{JitRuntimeAbiInventory, jit_runtime_abi_inventory};
pub use symbols::{JitRuntimeSymbolInventory, jit_runtime_symbol_inventory};
