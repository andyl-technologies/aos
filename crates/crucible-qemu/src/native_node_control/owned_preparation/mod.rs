//! Retains original QEMU initial custody under the common reserved world slot.
//!
//! An installed factory validates the exact graph and constructor before native
//! allocation. The reservation then takes the unique initial Session, including
//! its actual Child and durable journals. Drop transfers that complete capsule
//! into the same common supervisor. Source-qualified Ready and ordinary operation
//! conversion require a later native complete-domain preparation issuer.

// SPDX-License-Identifier: Apache-2.0

mod binding;
mod custody;
mod guard;
mod launch;

pub use launch::QemuInitialLaunching;

pub use binding::QemuInitialInstallationQualification;
pub use guard::{
    QemuInitialPreparation, QemuInitialPreparationFailure, QemuInitialReservation,
    QemuInitialReservationFailure,
};

/// Selects the common fixed-prefix implementation without registering capability.
pub const QEMU_PREFIX_IMPLEMENTATION: &str = "qemu/fixed-prefix-native-process-v1";

fn refusal(reason: impl Into<String>) -> crucible::node_contract::OperationFailure {
    crucible::node_contract::OperationFailure {
        effects: crucible::node_contract::EffectKnowledge::None,
        reason: reason.into(),
    }
}

fn uncertain(reason: impl Into<String>) -> crucible::node_contract::OperationFailure {
    crucible::node_contract::OperationFailure {
        effects: crucible::node_contract::EffectKnowledge::Unknown,
        reason: reason.into(),
    }
}

#[cfg(test)]
// crucible-lint: allow rust-allow -- These custody controls panic on failed fixture invariants.
// crucible-lint: allow panic-shortcut -- Only test setup and custody assertions use unwrap.
#[allow(clippy::unwrap_used)]
mod tests;
