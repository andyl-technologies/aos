//! Records local shared edges without publishing or dereferencing pointers.
//!
//! A serializer pass retains the borrowed original owners while this finite
//! lookup compares their backing addresses. Only first-group ordinals cross
//! the historical format; no label reconstructs a live authority allocation.

use super::*;

/// Owns a separately precharged temporary shared-edge lookup for one cut.
pub(crate) struct OriginalRestoredOwnerCapacityAliases {
    identities: Vec<*const ()>,
    maximum: usize,
    comparisons: usize,
    attempted: bool,
    ready: bool,
}

impl OriginalRestoredOwnerCapacityAliases {
    /// Quotes only the lookup backing; its inline root is a separate term.
    ///
    /// # Errors
    /// Refuses zero, excessive population or checked backing overflow.
    pub(crate) fn requested_bytes(maximum: usize) -> Result<usize, RuntimeError> {
        if maximum == 0 || maximum > MAXIMUM_ROWS {
            return Err(RuntimeError::ResourceLimit);
        }
        maximum
            .checked_mul(size_of::<*const ()>())
            .ok_or(RuntimeError::ResourceLimit)
    }

    /// Creates an unallocated DATA lookup for retention before reservation.
    ///
    /// # Errors
    /// Refuses an invalid or overflowing prospective population.
    pub(crate) fn unallocated(maximum: usize) -> Result<Self, RuntimeError> {
        Self::requested_bytes(maximum)?;
        Ok(Self {
            identities: Vec::new(),
            maximum,
            comparisons: 0,
            attempted: false,
            ready: false,
        })
    }

    /// Reserves this same retained lookup once, preserving every partial on error.
    ///
    /// # Errors
    /// Refuses another attempt, allocation failure or a capacity beyond the quote.
    pub(crate) fn reserve(&mut self) -> Result<(), RuntimeError> {
        let requested = Self::requested_bytes(self.maximum)?;
        if self.attempted || !self.identities.is_empty() || self.identities.capacity() != 0 {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.attempted = true;
        self.identities
            .try_reserve_exact(self.maximum)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if self.allocated_bytes()? > requested {
            return Err(RuntimeError::ResourceLimit);
        }
        self.ready = true;
        Ok(())
    }

    /// Retains the empty owner before the first fallible allocation.
    ///
    /// # Errors
    /// Refuses a populated slot, invalid demand or failed bounded reservation.
    pub(crate) fn reserve_into(
        maximum: usize,
        completed: &mut Option<Self>,
    ) -> Result<(), RuntimeError> {
        if completed.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        *completed = Some(Self::unallocated(maximum)?);
        completed
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .reserve()
    }

    /// Reports actual lookup capacity, including an interrupted reservation.
    ///
    /// # Errors
    /// Refuses checked backing-size overflow.
    pub(crate) fn allocated_bytes(&self) -> Result<usize, RuntimeError> {
        self.identities
            .capacity()
            .checked_mul(size_of::<*const ()>())
            .ok_or(RuntimeError::ResourceLimit)
    }

    /// Starts a new serialization pass without changing any historical owner.
    ///
    /// The enclosing writer calls this once for the whole history graph, never
    /// between independent owner views whose shared edges must remain linked.
    ///
    /// # Errors
    /// Refuses a lookup whose original reservation did not complete.
    pub(crate) fn begin_pass(&mut self) -> Result<(), RuntimeError> {
        if !self.ready {
            return Err(RuntimeError::ResourceLimit);
        }
        self.identities.clear();
        self.comparisons = 0;
        Ok(())
    }

    pub(super) fn group(&mut self, identity: *const ()) -> Result<usize, RuntimeError> {
        if !self.ready {
            return Err(RuntimeError::ResourceLimit);
        }
        for (group, actual) in self.identities.iter().enumerate() {
            self.comparisons = self
                .comparisons
                .checked_add(1)
                .ok_or(RuntimeError::ResourceLimit)?;
            if self.comparisons > MAXIMUM_ROWS {
                return Err(RuntimeError::ResourceLimit);
            }
            if *actual == identity {
                return Ok(group);
            }
        }
        if self.identities.len() >= self.maximum
            || self.identities.len() >= self.identities.capacity()
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let group = self.identities.len();
        self.identities.push(identity);
        Ok(group)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    #[test]
    fn actual_shared_edges_keep_groups_and_one_short_never_grows() -> Result<(), RuntimeError> {
        let first = Rc::new(7u8);
        let alias = Rc::clone(&first);
        let independent = Rc::new(7u8);
        let mut slot = None;
        OriginalRestoredOwnerCapacityAliases::reserve_into(1, &mut slot)?;
        let bank = slot.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        assert_eq!(bank.group(Rc::as_ptr(&first).cast())?, 0);
        assert_eq!(bank.group(Rc::as_ptr(&alias).cast())?, 0);
        let before = bank.allocated_bytes()?;
        assert_eq!(
            bank.group(Rc::as_ptr(&independent).cast()),
            Err(RuntimeError::ResourceLimit)
        );
        assert_eq!(bank.allocated_bytes()?, before);
        bank.begin_pass()?;
        assert_eq!(bank.group(Rc::as_ptr(&independent).cast())?, 0);
        Ok(())
    }
}
