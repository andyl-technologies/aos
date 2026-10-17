//! Lifetime administrative I/O credit shared by setup and staged control.
//!
//! One constructor owns one budget for the original socket actor. Every physical
//! attempt, including interrupted and empty attempts, spends credit. Reads charge
//! their actual retained bytes; writes charge the entire offered prefix before
//! the syscall, so partial writes and interruption cannot refund offered credit.
//! This bookkeeping confers no source ownership or Ready authority.

use super::StagedControlProfile;

/// Reports the first nonrenewing administrative-budget refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdministrativeIoError {
    /// The original selected profile fails constructor geometry validation.
    #[error("invalid selected administrative profile")]
    Profile,
    /// The original absolute first deadline has expired.
    #[error("original administrative deadline expired")]
    Deadline,
    /// The selected lifetime attempt allowance has been exhausted.
    #[error("original administrative attempt allowance exhausted")]
    Attempts,
    /// The selected lifetime byte allowance has been exhausted.
    #[error("original administrative byte allowance exhausted")]
    Bytes,
    /// A read has not been settled or an invalid extent was supplied.
    #[error("administrative attempt settlement does not match its original offer")]
    Settlement,
}

/// Copies actual lifetime administrative counters without changing allowances.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdministrativeIoCounters {
    /// Counts all physically offered read attempts, including empty attempts.
    pub read_attempts: u64,
    /// Counts actual read bytes retained by the original actor.
    pub read_bytes: u64,
    /// Counts all physically offered write attempts, including interruptions.
    pub write_attempts: u64,
    /// Counts every offered write byte before its syscall without refunds.
    pub offered_write_bytes: u64,
}

/// Retains a constructor's single finite setup-and-staged I/O allowance.
///
/// The actor retains this object across setup, descriptor handover and staged
/// execution. It has no cloning, replacement, reset or refund operation. The
/// actor separately authenticates its original PID, socket and native callback.
pub struct AdministrativeIoBudget {
    read_attempt_limit: u64,
    read_byte_limit: u64,
    write_attempt_limit: u64,
    write_byte_limit: u64,
    deadline_monotonic_ns: u64,
    counters: AdministrativeIoCounters,
    pending_read: Option<usize>,
    refusal: Option<AdministrativeIoError>,
}

impl AdministrativeIoBudget {
    /// Constructs the original lifetime budget from the full selected profile.
    ///
    /// # Errors
    /// Rejects a profile whose complete constructor geometry is invalid.
    pub fn new(profile: &StagedControlProfile) -> Result<Self, AdministrativeIoError> {
        profile
            .validate()
            .map_err(|_| AdministrativeIoError::Profile)?;
        let profile = &profile.compute;
        Ok(Self {
            read_attempt_limit: profile.administrative_read_attempt_limit,
            read_byte_limit: profile.administrative_read_byte_limit,
            write_attempt_limit: profile.administrative_write_attempt_limit,
            write_byte_limit: profile.administrative_write_byte_limit,
            deadline_monotonic_ns: profile.deadline_monotonic_ns,
            counters: AdministrativeIoCounters {
                read_attempts: 0,
                read_bytes: 0,
                write_attempts: 0,
                offered_write_bytes: 0,
            },
            pending_read: None,
            refusal: None,
        })
    }

    /// Charges one read attempt and returns its bounded offered byte extent.
    ///
    /// The caller retains actual bytes and calls [`Self::finish_read`] after
    /// exactly one physical syscall, including zero after EINTR or EAGAIN.
    ///
    /// # Errors
    /// Retains the first exhausted deadline, attempt, byte or settlement refusal.
    pub fn offer_read(
        &mut self,
        requested: usize,
        now_monotonic_ns: u64,
    ) -> Result<usize, AdministrativeIoError> {
        self.check(now_monotonic_ns)?;
        if requested == 0 || self.pending_read.is_some() {
            return self.refuse(AdministrativeIoError::Settlement);
        }
        if self.counters.read_attempts == self.read_attempt_limit {
            return self.refuse(AdministrativeIoError::Attempts);
        }
        let remaining = self.read_byte_limit - self.counters.read_bytes;
        if remaining == 0 {
            return self.refuse(AdministrativeIoError::Bytes);
        }
        let offered = requested.min(usize::try_from(remaining).unwrap_or(usize::MAX));
        self.counters.read_attempts += 1;
        self.pending_read = Some(offered);
        Ok(offered)
    }

    /// Charges the actual retained bytes of the same original read offer.
    ///
    /// # Errors
    /// Rejects absent offers or a count larger than its original bounded extent.
    /// The refusal remains sticky and never renews attempts or consumed bytes.
    pub fn finish_read(&mut self, actual: usize) -> Result<(), AdministrativeIoError> {
        if let Some(error) = self.refusal {
            return Err(error);
        }
        let Some(offered) = self.pending_read.take() else {
            return self.refuse(AdministrativeIoError::Settlement);
        };
        if actual > offered {
            return self.refuse(AdministrativeIoError::Settlement);
        }
        self.counters.read_bytes += actual as u64;
        Ok(())
    }

    /// Charges one write attempt and its entire offered prefix before the syscall.
    ///
    /// # Errors
    /// Retains the first exhausted deadline, attempt, byte or invalid-extent
    /// refusal. Partial, interrupted and empty writes never refund this debit.
    pub fn offer_write(
        &mut self,
        requested: usize,
        now_monotonic_ns: u64,
    ) -> Result<usize, AdministrativeIoError> {
        self.check(now_monotonic_ns)?;
        if requested == 0 {
            return self.refuse(AdministrativeIoError::Settlement);
        }
        if self.counters.write_attempts == self.write_attempt_limit {
            return self.refuse(AdministrativeIoError::Attempts);
        }
        let remaining = self.write_byte_limit - self.counters.offered_write_bytes;
        if remaining == 0 {
            return self.refuse(AdministrativeIoError::Bytes);
        }
        let offered = requested.min(usize::try_from(remaining).unwrap_or(usize::MAX));
        self.counters.write_attempts += 1;
        self.counters.offered_write_bytes += offered as u64;
        Ok(offered)
    }

    /// Copies original counters without changing or settling any credit.
    pub const fn counters(&self) -> AdministrativeIoCounters {
        self.counters
    }

    fn check(&mut self, now: u64) -> Result<(), AdministrativeIoError> {
        if let Some(error) = self.refusal {
            return Err(error);
        }
        if now >= self.deadline_monotonic_ns {
            return self.refuse(AdministrativeIoError::Deadline);
        }
        Ok(())
    }

    fn refuse<T>(&mut self, error: AdministrativeIoError) -> Result<T, AdministrativeIoError> {
        Err(*self.refusal.get_or_insert(error))
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- Finite constructor credit controls fail on invariant violations.
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn setup_and_staged_reads_share_empty_attempts_and_retained_byte_credit() {
        let profile = super::super::tests::profile();
        let mut budget = AdministrativeIoBudget::new(&profile).unwrap();
        assert_eq!(budget.offer_read(13, 0), Ok(13));
        budget.finish_read(3).unwrap();
        for _ in 1..profile.compute.administrative_read_attempt_limit {
            budget.offer_read(1024, 0).unwrap();
            budget.finish_read(0).unwrap();
        }
        assert_eq!(budget.counters().read_bytes, 3);
        assert_eq!(
            budget.offer_read(1, 0),
            Err(AdministrativeIoError::Attempts)
        );
        assert_eq!(
            budget.offer_read(1, 0),
            Err(AdministrativeIoError::Attempts)
        );
    }

    #[test]
    fn writes_charge_complete_offers_before_partial_or_interrupted_syscalls() {
        let profile = super::super::tests::profile();
        let mut budget = AdministrativeIoBudget::new(&profile).unwrap();
        assert_eq!(budget.offer_write(13, 0), Ok(13));
        assert_eq!(budget.counters().offered_write_bytes, 13);
        // A partial or interrupted physical send has no refund operation.
        assert_eq!(
            budget.offer_write(usize::MAX, 0),
            Ok(profile.compute.administrative_write_byte_limit as usize - 13)
        );
        assert_eq!(
            budget.counters().offered_write_bytes,
            profile.compute.administrative_write_byte_limit
        );
        assert_eq!(budget.offer_write(1, 0), Err(AdministrativeIoError::Bytes));
    }

    #[test]
    fn outstanding_read_cannot_be_reoffered_or_over_settled() {
        let profile = super::super::tests::profile();
        let mut budget = AdministrativeIoBudget::new(&profile).unwrap();
        budget.offer_read(4, 0).unwrap();
        assert_eq!(
            budget.offer_read(4, 0),
            Err(AdministrativeIoError::Settlement)
        );
        assert_eq!(
            budget.finish_read(0),
            Err(AdministrativeIoError::Settlement)
        );

        let mut budget = AdministrativeIoBudget::new(&profile).unwrap();
        budget.offer_read(4, 0).unwrap();
        assert_eq!(
            budget.finish_read(5),
            Err(AdministrativeIoError::Settlement)
        );
        assert_eq!(budget.counters().read_bytes, 0);
    }

    #[test]
    fn first_deadline_refusal_cannot_be_reset_by_an_earlier_observation() {
        let profile = super::super::tests::profile();
        let mut budget = AdministrativeIoBudget::new(&profile).unwrap();
        assert_eq!(
            budget.offer_read(1, 1),
            Err(AdministrativeIoError::Deadline)
        );
        assert_eq!(
            budget.offer_write(1, 0),
            Err(AdministrativeIoError::Deadline)
        );
        assert_eq!(budget.counters().read_attempts, 0);
        assert_eq!(budget.counters().write_attempts, 0);
    }
}
