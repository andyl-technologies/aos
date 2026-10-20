//! Prices Source's one private credential capture from its original ledger.
//!
//! The scalar is the compiled upper owner's representation size, not an input
//! budget, account, ceiling, path, key or receiving grant. Actual credential
//! files and the signing key remain private to the Source executable.

use std::error::Error;

use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_broker::receiving::RepresentationDemandDebitV1 as _;
use super::currentness::SourceCurrentnessSampleV1;
use super::{CLOSED, SourceReceivingClosedV1, SourceSignerServiceOriginalV1};

const CREDENTIAL_DIRECTORY: &str = "/run/credentials/aos-sandbox-source-signerd.service";
const SEED_NAME: &str = "source-hold-signing-seed";
const PIN_NAME: &str = "source-hold-public-key";

#[derive(Default)]
pub(super) struct SourceCredentialReceivingV1 {
    entered: bool,
    demand: Option<Result<ResourceVector, AccountingError>>,
    physical: Option<Result<(), AccountingError>>,
    before: SourceCurrentnessSampleV1,
    before_result: Option<Result<(), SourceReceivingClosedV1>>,
    after: SourceCurrentnessSampleV1,
    after_result: Option<Result<(), SourceReceivingClosedV1>>,
    closed: Option<SourceReceivingClosedV1>,
}

impl SourceCredentialReceivingV1 {
    pub(super) fn physical_demand(&self) -> Option<ResourceVector> {
        self.demand.as_ref().and_then(|result| result.as_ref().ok()).copied()
    }

    pub(super) fn complete(&self) -> bool {
        self.closed.is_none() && matches!(self.before_result, Some(Ok(())))
            && matches!(self.after_result, Some(Ok(())))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        failure(&self.demand).or_else(|| failure(&self.physical))
            .or_else(|| self.before.failure())
            .or_else(|| failure(&self.before_result))
            .or_else(|| self.after.failure())
            .or_else(|| failure(&self.after_result))
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}

impl SourceSignerServiceOriginalV1 {
    /// Prices the sole fixed private Source credential capture once.
    ///
    /// The sole compiled consumer supplies its checked representation size;
    /// Native derives the fixed files, buffers and currentness recipe. The
    /// actual original remains the only ledger spender. No account is handed
    /// out, and no key, caller pathname or resource vector is accepted.
    ///
    /// # Errors
    /// Retains arithmetic, reservation or actual original-currentness failure.
    /// Reentry permanently closes the same original instead of resampling it.
    pub fn reserve_source_credential_capture_once_v1(
        &mut self,
        upper_resident_bytes: usize,
    ) -> Result<(), SourceReceivingClosedV1> {
        if self.first.is_some() || self.credential_receiving.entered
            || !matches!(self.common.final_binding, Some(Ok(())))
        {
            self.credential_receiving.closed.get_or_insert(CLOSED);
            return Err(self.fail(super::Failure::Credential));
        }
        self.credential_receiving.entered = true;
        if self.require_permanent_fd_coverage_v1().is_err() {
            self.credential_receiving.closed.get_or_insert(CLOSED);
            return Err(self.fail(super::Failure::Credential));
        }
        self.credential_receiving.demand = Some(credential_demand(upper_resident_bytes));
        let demand = match self.credential_receiving.demand.as_ref() {
            Some(Ok(demand)) => *demand,
            _ => return Err(self.fail(super::Failure::Credential)),
        };
        let permanent = self.common.permanent_open_files()?;
        self.credential_receiving.physical = Some(self.common.fixed_startup_demand()
            .and_then(|native| native.checked_add(demand))
            .and_then(|total| super::require_descriptor_shape(total.get(D::OpenFiles), permanent)));
        if !matches!(self.credential_receiving.physical, Some(Ok(()))) {
            return Err(self.fail(super::Failure::Credential));
        }
        if self.common.representation.as_mut().ok_or(CLOSED)?.reserve(demand.with(D::OpenFiles, 0)).is_err() {
            return Err(self.fail(super::Failure::Accounting));
        }

        let anchor = self.common.cgroup.as_ref().ok_or(CLOSED)?;
        let initial_info = self.common.membership.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(CLOSED)?;
        let initial_identity = self.common.process_before.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(CLOSED)?;
        self.credential_receiving.before_result = Some(self.credential_receiving.before.observe_once(
            &mut self.common.process, anchor, &self.common.limits, initial_info, initial_identity,
        ));
        if !matches!(self.credential_receiving.before_result, Some(Ok(()))) {
            self.fail(super::Failure::Credential);
            // Both samples were paid. Retain the independent post even though
            // no credential read may follow this refused before observation.
            let _ = self.post_source_credential_capture_once_v1();
            return Err(CLOSED);
        }
        Ok(())
    }

    /// Posts the same original after the already paid private credential read.
    ///
    /// The consumer calls this even if its own retained read failed. A refused
    /// entered before-sample posts internally, without a credential read. A
    /// funding refusal enters neither sample. This accepts no success assertion
    /// or new funding and never clears the original first cause.
    ///
    /// # Errors
    /// Retains original currentness/process failure and refuses absent/reentry.
    pub fn post_source_credential_capture_once_v1(&mut self) -> Result<(), SourceReceivingClosedV1> {
        if !self.credential_receiving.entered
            || self.credential_receiving.before_result.is_none()
            || self.credential_receiving.after_result.is_some()
        {
            self.credential_receiving.closed.get_or_insert(CLOSED);
            return Err(self.fail(super::Failure::Credential));
        }
        let anchor = self.common.cgroup.as_ref().ok_or(CLOSED)?;
        let initial_info = self.common.membership.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(CLOSED)?;
        let initial_identity = self.common.process_before.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(CLOSED)?;
        self.credential_receiving.after_result = Some(self.credential_receiving.after.observe_once(
            &mut self.common.process, anchor, &self.common.limits, initial_info, initial_identity,
        ));
        if !self.credential_receiving.complete() || self.credential_receiving.failure().is_some() {
            return Err(self.fail(super::Failure::Credential));
        }
        Ok(())
    }

}

fn credential_demand(resident: usize) -> Result<ResourceVector, AccountingError> {
    let overflow = AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
    let paths = CREDENTIAL_DIRECTORY.len().checked_add(1 + SEED_NAME.len())
        .and_then(|length| length.checked_mul(2)).ok_or(overflow)?;
    // The two fixed reads run sequentially. Their transient converted paths
    // share one byte peak; original Files and read outcomes stay retained.
    let directory = std::path::Path::new(CREDENTIAL_DIRECTORY);
    let joined_paths = aos_sandbox_linux::credential::FixedRoleCredentialReadV1::
        joined_path_receiving_bytes_v1(directory, SEED_NAME)
        .and_then(|seed| Some(seed.max(aos_sandbox_linux::credential::FixedRoleCredentialReadV1::
            joined_path_receiving_bytes_v1(directory, PIN_NAME)?))).ok_or(overflow)?;
    let memory = resident.checked_add(32 + 80)
        .and_then(|bytes| bytes.checked_add(joined_paths))
        .and_then(|bytes| bytes.checked_add(paths))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ed25519_dalek::SigningKey>()))
        .ok_or(overflow)?;
    let memory = u64::try_from(memory).map_err(|_| overflow)?;

    // The two sample structs are already inline in the paid Native original.
    // Their dynamic control/name buffers are distinct before/after debts. All
    // actual FD slots stay under the parent's permanently charged coverage.
    let sample = SourceCurrentnessSampleV1::dynamic_demand()?;
    let samples = ResourceVector::ZERO
        .with(D::MemoryBytes, sample.get(D::MemoryBytes).checked_mul(2).ok_or(overflow)?)
        .with(D::MetadataEntries, sample.get(D::MetadataEntries).checked_mul(2).ok_or(overflow)?)
        .with(D::OpenFiles, sample.get(D::OpenFiles).checked_mul(2).ok_or(overflow)?);
    let actual = ResourceVector::ZERO.with(D::MemoryBytes, memory)
        .with(D::MetadataEntries, 6).with(D::OpenFiles, 2)
        .checked_add(samples)?;
    // The sole caller first requires the actual F3 permanent coverage. Keep
    // the full physical geometry above; only that same original covers slots.
    Ok(actual)
}

fn failure<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}
