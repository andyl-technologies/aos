//! Shares physical native-worker custody without lending operation authority.
//!
//! Role-specific controls retain their inputs, effects and typed failures. These
//! helpers only preserve native output fields, synchronous Arc borrows and the
//! ordinary Arc allocation/destruction sequence under the actual Source owner.
// SPDX-License-Identifier: GPL-2.0-only

pub(super) mod owner;
pub(super) mod scope;
pub(super) mod shared;
