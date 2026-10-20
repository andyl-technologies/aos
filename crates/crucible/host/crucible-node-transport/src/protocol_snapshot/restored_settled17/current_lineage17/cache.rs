//! Retains the bounded signed lineage selected from an authenticated full walk.
//!
//! Each slot owns its actual typed pending child before its first allocation.
//! Successful fields and residual child-attempt banks survive every later error.
//! No imported heap, transport, token or native host capsule is reconstructed.

use super::*;
use crate::{
    protocol_snapshot::{
        owned11::typed::Native17Build,
        restored_settled17::{
            current_stages::{CurrentActivation17, CurrentFirstObservation17},
            historical_auth::HistoricalRestorationStages17,
        },
    },
    retained_metadata::{MetadataObserver, ObserveMetadata},
};
pub(crate) use fields::*;

/// Owns one selected DTO and every partial child used to construct it.
pub(crate) struct LineageSlot17<T: Native17Build> {
    child: T::Attempt,
    value: Option<T>,
    started: bool,
    failed: bool,
}

impl<T: Native17Build> Default for LineageSlot17<T> {
    fn default() -> Self {
        Self {
            child: Default::default(),
            value: None,
            started: false,
            failed: false,
        }
    }
}

impl<T: Native17Build> LineageSlot17<T> {
    fn read<'rows>(
        &mut self,
        loan: &BorrowedLineageField17<'_, 'rows, T>,
        ledger: &mut Ledger<'rows, '_, '_>,
    ) -> Result<(), ProviderError> {
        if self.started || self.failed || self.value.is_some() {
            return Err(invalid());
        }
        self.started = true;
        self.failed = true;

        loan.read_target17_into_data(ledger, &mut self.child)?;

        self.value = T::take_output_data(&mut self.child);
        if self.value.is_none() {
            return Err(invalid());
        }
        self.failed = false;
        Ok(())
    }

    pub(crate) fn value_data(&self) -> Result<&T, ProviderError> {
        if self.failed {
            return Err(invalid());
        }
        self.value.as_ref().ok_or_else(invalid)
    }

    fn observe(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        T::observe_attempt_data(&self.child, observer)?;
        if let Some(value) = &self.value {
            T::observe_output_data(value, observer)?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct LineageFields17 {
    boot: BootLineage17Fields,
    prepare: PrepareLineage17Fields,
    commit: CommitLineage17Fields,
    arm: LineageSlot17<CurrentActivation17>,
    world: LineageSlot17<CurrentActivation17>,
    first_observation: LineageSlot17<CurrentFirstObservation17>,
    capture: CaptureLineage17Fields,
    registration: RegistrationLineage17Fields,
}

impl LineageFields17 {
    fn observe(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        self.boot.observe(observer)?;
        self.prepare.observe(observer)?;
        self.commit.observe(observer)?;
        self.arm.observe(observer)?;
        self.world.observe(observer)?;
        self.first_observation.observe(observer)?;
        self.capture.observe(observer)?;
        self.registration.observe(observer)
    }
}

/// Owns only needed signed evidence and future-affecting numeric once facts.
pub(crate) struct CurrentNativeLineage17Data {
    fields: LineageFields17,
    private_key: [u8; 32],
    boot_group: usize,
    policy_group: usize,
    suffix_maximum_originals: U64,
    pub(crate) reserve_ledger: crate::protocol_snapshot::restored_suffix_history::HistoricalRestoredSuffixLedger,
    pub(crate) reserve_carrier: crate::reference_packet::service::native_startup::PacketRestoredSettledNativeCarrierData,
    pub(crate) reserve_existing_rows: crate::reference_packet::service::native_startup::PacketRestoredSettledNativeExistingRowsData,
    pub(crate) current_action: Option<(usize, usize, u64, bool, bool)>,
    pub(crate) reserve_failed: bool,
    registration_identity_group: Option<usize>,
}

impl CurrentNativeLineage17Data {
    /// Returns the actual same-pass registration identity, never a role label.
    ///
    /// # Errors
    /// Refuses an occurrence without a retained original Capture registration.
    pub(crate) fn current_capture_registration_identity_group17_data(
        &self,
    ) -> Result<usize, ProviderError> {
        self.registration_identity_group.ok_or_else(invalid)
    }

    pub(crate) fn private_key_data(&self) -> &[u8; 32] {
        &self.private_key
    }

    pub(crate) fn boot_group_data(&self) -> usize {
        self.boot_group
    }

    pub(crate) fn policy_group_data(&self) -> usize {
        self.policy_group
    }

    pub(crate) fn restored_suffix_maximum_originals_data(&self) -> U64 {
        self.suffix_maximum_originals
    }

    pub(crate) fn boot_data(&self) -> &BootLineage17Fields {
        &self.fields.boot
    }

    pub(crate) fn prepare_data(&self) -> &PrepareLineage17Fields {
        &self.fields.prepare
    }

    pub(crate) fn commit_data(&self) -> &CommitLineage17Fields {
        &self.fields.commit
    }

    pub(crate) fn capture_data(&self) -> &CaptureLineage17Fields {
        &self.fields.capture
    }

    pub(crate) fn registration_data(&self) -> &RegistrationLineage17Fields {
        &self.fields.registration
    }

    /// Borrows the actual three typed stages consumed by historical MAC checks.
    ///
    /// # Errors
    /// Refuses an absent or incomplete stage; uploads remain immutable evidence.
    pub(crate) fn restoration_stages17_data(
        &self,
    ) -> Result<HistoricalRestorationStages17<'_>, ProviderError> {
        Ok(HistoricalRestorationStages17 {
            arm: self.fields.arm.value_data()?,
            world: self.fields.world.value_data()?,
            first_observation: self.fields.first_observation.value_data()?,
        })
    }

    pub(crate) fn observe_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.fields.observe(observer)
    }
}

/// Retains nested signed field allocations after any construction failure.
#[derive(Default)]
pub(crate) struct CurrentNativeLineage17ReadAttempt {
    started: bool,
    failed: bool,
    fields: LineageFields17,
    completed: Option<CurrentNativeLineage17Data>,
}

impl CurrentNativeLineage17ReadAttempt {
    pub(crate) fn completed_data(&self) -> Result<&CurrentNativeLineage17Data, ProviderError> {
        if self.failed {
            return Err(invalid());
        }
        self.completed.as_ref().ok_or_else(invalid)
    }

    pub(crate) fn take_completed_data(
        &mut self,
    ) -> Result<CurrentNativeLineage17Data, ProviderError> {
        if self.failed {
            return Err(invalid());
        }
        self.completed.take().ok_or_else(invalid)
    }

    pub(crate) fn observe_attempt_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.fields.observe(observer)?;
        if let Some(data) = &self.completed {
            data.observe_metadata_data(observer)?;
        }
        Ok(())
    }
}

impl<'rows> BorrowedCurrentBootLineage17<'_, 'rows> {
    /// Prices only the actual selected typed lineage fields from checked rows.
    ///
    /// # Errors
    /// Refuses an active target suspension, changed field extent or target demand
    /// above the enclosing bound. The full closed/depth walk precedes this call.
    pub(crate) fn preflight_owned_lineage17_data(
        &self,
        ledger: &mut Ledger<'rows, '_, '_>,
    ) -> Result<(), ProviderError> {
        BootLineage17Fields::preflight(self, ledger)?;
        if let Some(loan) = &self.prepare {
            PrepareLineage17Fields::preflight(loan, ledger)?;
        }
        if let Some(loan) = &self.commit {
            CommitLineage17Fields::preflight(loan, ledger)?;
        }
        for loan in self.stages.activation.iter().flatten() {
            loan.owner.preflight_target17_data(ledger)?;
        }
        if let Some(loan) = &self.stages.first_observation {
            loan.owner.preflight_target17_data(ledger)?;
        }
        if let Some(loan) = self
            .reserve
            .current
            .as_ref()
            .and_then(|current| current.capture.as_ref())
        {
            CaptureLineage17Fields::preflight(loan, ledger)?;
            if let Some(registration) = &loan.registration {
                RegistrationLineage17Fields::preflight(registration, ledger)?;
            }
        }
        let _ = self.restored_suffix_maximum_originals_data()?;
        Ok(())
    }

    /// Retains selected typed owners before every fallible nested allocation.
    ///
    /// # Errors
    /// Refuses attempt reuse, malformed selected fields, exhausted demand or a
    /// changed exact row endpoint. Every completed child remains in `attempt`.
    pub(crate) fn read_owned_lineage17_into_data(
        &self,
        ledger: &mut Ledger<'rows, '_, '_>,
        attempt: &mut CurrentNativeLineage17ReadAttempt,
    ) -> Result<(), ProviderError> {
        if attempt.started || attempt.failed || attempt.completed.is_some() {
            return Err(invalid());
        }
        attempt.started = true;
        attempt.failed = true;

        attempt.fields.boot.read(self, ledger)?;
        if let Some(loan) = &self.prepare {
            attempt.fields.prepare.read(loan, ledger)?;
        }
        if let Some(loan) = &self.commit {
            attempt.fields.commit.read(loan, ledger)?;
        }
        if let Some(loan) = &self.stages.activation[0] {
            attempt.fields.arm.read(&loan.owner, ledger)?;
        }
        if let Some(loan) = &self.stages.activation[1] {
            attempt.fields.world.read(&loan.owner, ledger)?;
        }
        if let Some(loan) = &self.stages.first_observation {
            attempt.fields.first_observation.read(&loan.owner, ledger)?;
        }
        if let Some(loan) = self
            .reserve
            .current
            .as_ref()
            .and_then(|current| current.capture.as_ref())
        {
            attempt.fields.capture.read(loan, ledger)?;
            if let Some(registration) = &loan.registration {
                attempt.fields.registration.read(registration, ledger)?;
            }
        }
        let private_key = self.data.private_key.key32_data()?;
        let suffix_maximum_originals = self.restored_suffix_maximum_originals_data()?;
        attempt.completed = Some(CurrentNativeLineage17Data {
            fields: std::mem::take(&mut attempt.fields),
            private_key,
            boot_group: self.group,
            policy_group: self.policy_group,
            suffix_maximum_originals,
            reserve_ledger: self.reserve.ledger,
            reserve_carrier: self.reserve.carrier,
            reserve_existing_rows: self.reserve.existing_rows,
            current_action: self.reserve.current.as_ref().map(|current| {
                (
                    current.index,
                    current.group,
                    current.ordinal,
                    current.decoded,
                    current.failed,
                )
            }),
            reserve_failed: self.reserve.failed,
            registration_identity_group: self
                .reserve
                .current
                .as_ref()
                .and_then(|current| current.capture.as_ref())
                .and_then(|capture| capture.registration.as_ref())
                .map(|registration| registration.identity_group),
        });
        attempt.failed = false;
        Ok(())
    }
}

impl<'rows, T: Native17Build> BorrowedLineageField17<'_, 'rows, T> {
    pub(crate) fn preflight_target17_data(
        &self,
        ledger: &mut Ledger<'rows, '_, '_>,
    ) -> Result<(), ProviderError> {
        if !ledger.has_native17_targets_data() || ledger.native17_targets_suspended_data() {
            return Err(invalid());
        }
        let original_rows = std::mem::replace(&mut ledger.rows, self.starting_rows_data());
        let result = T::preflight_data(self.raw_data(), ledger)
            .and_then(|()| self.authenticate_end_data(ledger));
        ledger.rows = original_rows;
        result
    }

    pub(crate) fn read_target17_into_data(
        &self,
        ledger: &mut Ledger<'rows, '_, '_>,
        attempt: &mut T::Attempt,
    ) -> Result<(), ProviderError> {
        if !ledger.has_native17_targets_data() || ledger.native17_targets_suspended_data() {
            return Err(invalid());
        }
        let original_rows = std::mem::replace(&mut ledger.rows, self.starting_rows_data());
        let result = T::read_into_data(self.raw_data(), ledger, attempt)
            .and_then(|()| self.authenticate_end_data(ledger));
        ledger.rows = original_rows;
        result
    }
}

mod fields;
