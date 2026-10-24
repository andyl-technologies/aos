//! Admits the five existing fixed credentials through one native startup writer.
//!
//! This owner reborrows the same journal and its actual selected funding loan
//! or explicit ordinary purpose. Each admission keeps its original claim,
//! semantic checks, one commit and exact readback. It exposes no general writer.

mod binding;
mod deployment;
mod error;
mod fixed;
#[cfg(any(test, feature = "test-fixtures"))]
mod fixture;
#[cfg(any(test, feature = "test-fixtures"))]
pub use fixture::RootStartupFixedAdmissionFixtureV1;
mod fixed_profile;
mod geometry;
mod pins;
mod transaction;

pub use error::RootStartupCredentialErrorV1;
pub use binding::RootStartupBindingReadErrorV1;

use super::RootStartupJournalOriginalV1;
use aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1;
use ed25519_dalek::VerifyingKey;

#[derive(Clone, Copy)]
pub(super) struct StartupSignerPinsV1 {
    deployment_generation: u64,
    deployment_key: VerifyingKey,
    project_generation: u64,
    project_key: VerifyingKey,
}

/// Reborrows the actual fixed startup journal and its matching original purpose.
///
/// Only the genuine owner's selected or ordinary factory constructs this writer.
/// Its optional internal loan is checked against that owner's explicit backend;
/// absence never changes a selected owner into an ordinary one.
pub struct RootStartupCredentialWriterV1<'borrow> {
    journal: &'borrow mut RootStartupJournalOriginalV1,
    original: Option<RootJournalFinancialBorrowV1<'borrow>>,
}

impl<'borrow> RootStartupCredentialWriterV1<'borrow> {
    pub(super) fn new(
        journal: &'borrow mut RootStartupJournalOriginalV1,
        original: Option<RootJournalFinancialBorrowV1<'borrow>>,
    ) -> Self {
        Self { journal, original }
    }

    fn admitted_signer_pins_v1(&self) -> Result<StartupSignerPinsV1, RootStartupCredentialErrorV1> {
        self.journal
            .signer_pins
            .ok_or_else(|| super::super::PolicyNativeJournalErrorV1::boundary().into())
    }
}

pub(super) fn binding_read_control_bytes_v1() -> Option<usize> {
    binding::read_control_bytes_v1()
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<usize>>().checked_mul(3)?))
}
