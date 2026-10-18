//! Counts the same verified archive and its untouched archive-ticketed Host.
//!
//! Historical source identity and prebirth owner data confer no native, graph,
//! restoration or allocation authority. The fixed counter is separately named;
//! recursive observer/compiler frames and physical allocator peak are excluded.

use super::collecting::CollectingTargetPhase;
use super::*;
use crate::node_contract::HostSchedulingSource;

impl CompleteOriginalSource {
    pub(super) fn authenticate_collecting_prebirth_storage_phase(
        &self,
    ) -> Result<(), RuntimeError> {
        self.authenticate_birth()?;
        let CompleteOriginalSourcePurpose::Collecting { target, .. } = &self.purpose else {
            return Err(RuntimeError::ForeignAuthority);
        };
        if !matches!(
            *target
                .try_borrow()
                .map_err(|_| RuntimeError::OutstandingObligations)?,
            CollectingTargetPhase::Unbound
        ) || self.target_started.get()
            || self
                .target
                .try_borrow()
                .map_err(|_| RuntimeError::OutstandingObligations)?
                .is_some()
            || !self.host_issued.get()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let owners = self.archive.owners();
        let issued = self.native_issued.get();
        let host = &self.host.selection_data().owner.owner.id;
        if owners.len() != issued.len()
            || owners.iter().filter(|row| &row.owner == host).count() != 1
            || owners
                .iter()
                .enumerate()
                .any(|(index, row)| issued[index] != (&row.owner != host))
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.authenticate_birth()
    }
}

impl CompleteOriginalRestorationSource {
    /// Authenticates the exact unstarted collecting archive and fresh Host pair.
    ///
    /// All four tickets must already be issued while collecting remains Unbound.
    /// This origin-only check does not hash, allocate, call a policy or query a
    /// live runtime. It never starts or renews target binding or any ticket.
    ///
    /// # Errors
    /// Refuses foreign custody, ordinary/spent collecting phases, busy loans,
    /// missing ticket issuance or another/nonfresh archive-ticketed Host source.
    pub fn authenticate_original_prebirth_host_data(
        &self,
        host: &Rc<HostSchedulingSource>,
    ) -> Result<(), RuntimeError> {
        self.inner
            .authenticate_collecting_prebirth_storage_phase()?;
        host.authenticate_archive_report_startup_data(&self.inner)?;
        self.inner.authenticate_collecting_prebirth_storage_phase()
    }

    /// Counts actual verified archive backing and its same fresh Host once.
    ///
    /// The actual source Rc/header, archive/content/admin/Host record/reference
    /// and retained weak Plan views use the existing concrete owning walker.
    /// The fresh Host Rc/header and its independent metadata clones are added;
    /// only its authenticated alias of this SAME source allocation is excluded.
    /// The actual three-usize local counter is included before observer work.
    /// Other caller roots and recursive/compiler frames remain separate terms.
    ///
    /// # Errors
    /// Refuses a changed/foreign/busy pair or any unsupported owner, checked
    /// overflow, or a total beyond `maximum`. Failure retains original owners.
    pub fn retained_original_prebirth_storage_data(
        &self,
        host: &Rc<HostSchedulingSource>,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_original_prebirth_host_data(host)?;
        let mut parts = [0usize; 3];
        if std::mem::size_of_val(&parts) > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        parts[0] = std::mem::size_of_val(&parts);
        parts[1] = self.inner.capture_owned_storage()?;
        parts[2] = host.retained_archive_prebirth_host_storage_data(&self.inner, maximum)?;
        parts[0] = parts[0]
            .checked_add(parts[1])
            .and_then(|n| n.checked_add(parts[2]))
            .filter(|n| *n <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        self.authenticate_original_prebirth_host_data(host)?;
        Ok(parts[0])
    }
}
