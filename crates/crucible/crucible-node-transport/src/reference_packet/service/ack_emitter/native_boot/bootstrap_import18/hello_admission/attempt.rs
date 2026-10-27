//! Spends original SDK admission before quote, constructor or terminal work.
//!
//! This fixed owner exists before private receipt. It retains the original cut
//! and independently quoted row; the registrar retains the actual SDK lease and
//! diagnostic. Neither state can retry after any refusal.

use crate::ProviderError;
use crate::operational_time::OperationalDeadline;
use crate::protocol_snapshot::ProtocolCaptureOwner;
use std::mem::size_of;

/// Retains the physical admission occurrence without allocating or issuing a lease.
pub(in super::super) struct Attempt {
    owner: ProtocolCaptureOwner,
    cut: Option<OperationalDeadline>,
    stage: Stage,
    row: Option<[usize; 3]>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Empty,
    Inspecting,
    Quoted,
    Complete,
    Failed,
}

const _: fn(&Attempt) = |value| {
    let Attempt {
        owner: _,
        cut: _,
        stage: _,
        row: _,
    } = value;
};

impl Attempt {
    /// Initializes the fixed occurrence before any private or public read.
    pub(in super::super) fn empty_data() -> Self {
        Self {
            owner: ProtocolCaptureOwner::new(),
            cut: None,
            stage: Stage::Empty,
            row: None,
        }
    }

    /// Spends the occurrence before a fallible guard or admission callback.
    ///
    /// # Errors
    /// Refuses foreign creator custody or a previously spent occurrence.
    pub(super) fn start_data(&mut self, cut: OperationalDeadline) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.stage != Stage::Empty {
            return Err(refused());
        }

        self.stage = Stage::Inspecting;
        self.cut = Some(cut);
        Ok(())
    }

    /// Stores the independently derived row before allocating SDK construction.
    ///
    /// # Errors
    /// Refuses expired/substituted custody, another stage or an occupied quote.
    pub(super) fn quote_data(
        &mut self,
        row: [usize; 3],
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        self.guard(cut)?;
        if self.stage != Stage::Inspecting || self.row.is_some() {
            return Err(refused());
        }

        self.row = Some(row);
        self.stage = Stage::Quoted;
        Ok(())
    }

    /// Checks the same admitted occurrence before invoking the actual SDK.
    ///
    /// # Errors
    /// Refuses another stage, absent quote or original custody/cut mismatch.
    pub(super) fn quoted_data(&self, cut: OperationalDeadline) -> Result<(), ProviderError> {
        self.guard(cut)?;
        if self.stage != Stage::Quoted || self.row.is_none() {
            return Err(refused());
        }
        Ok(())
    }

    /// Completes after the live selected lease and terminal census both pass.
    ///
    /// # Errors
    /// Refuses an incomplete quote or stale original custody/cut.
    pub(super) fn complete_data(&mut self, cut: OperationalDeadline) -> Result<(), ProviderError> {
        self.quoted_data(cut)?;
        self.stage = Stage::Complete;
        Ok(())
    }

    /// Refuses this occurrence while retaining its physical row and cut.
    pub(super) fn refuse_data(&mut self) {
        self.stage = Stage::Failed;
    }

    /// Checks completion without creating or cloning a registration lease.
    ///
    /// # Errors
    /// Refuses incomplete/refused construction or stale original custody/cut.
    pub(super) fn completed_data(&self, cut: OperationalDeadline) -> Result<(), ProviderError> {
        self.guard(cut)?;
        if self.stage != Stage::Complete || self.row.is_none() {
            return Err(refused());
        }
        Ok(())
    }

    fn guard(&self, cut: OperationalDeadline) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.cut != Some(cut) || cut.is_expired() {
            return Err(refused());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(in super::super) fn row_fixture_data(&self) -> Option<[usize; 3]> {
        self.row
    }

    /// Names the actual physical owner, stage and fixed quote/cut controls.
    pub(super) fn counter_scratch_data() -> usize {
        size_of::<&Self>() * 2
            + size_of::<&mut Self>() * 2
            + size_of::<ProtocolCaptureOwner>()
            + size_of::<OperationalDeadline>() * 2
            + size_of::<Option<OperationalDeadline>>()
            + size_of::<Stage>() * 2
            + size_of::<[usize; 3]>()
            + size_of::<Option<[usize; 3]>>()
            + size_of::<Result<(), ProviderError>>() * 3
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original import18 SDK admission occurrence refused")
}
