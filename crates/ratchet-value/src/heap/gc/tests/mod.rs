//! Unit tests for the generational-GC planning surface (RFC-0007 §2 split, #9).
//!
//! Move-only extraction of the trailing `#[cfg(test)] mod tests` from `gc.rs`,
//! de-indented; no test was changed.

use super::*;

fn address(bits: usize) -> GcHeapAddress {
    GcHeapAddress::new(bits).expect("aligned address")
}

mod part_1;
mod part_2;
mod part_3;
mod part_4;
mod part_5;
