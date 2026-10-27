//! Keeps native Source genesis integration fixtures beside their real owners.

#[cfg(test)]
use aos_sandbox_ledger_replay::source_signer_data::source_genesis_readback::*;
#[cfg(test)]
use aos_sandbox_ledger_replay::source_signer_data::source_hold_readback::PinnedSourceHoldReadbackSignerV1;
#[cfg(test)]
use aos_sandbox_model::{ObjectDigest, ProjectId};
#[cfg(test)]
use ed25519_dalek::{Signer as _, SigningKey};

#[cfg(all(test, target_os = "linux"))]
#[path = "source_genesis_readback/tests.rs"]
mod tests;

#[cfg(test)]
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;
