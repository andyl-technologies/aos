//! Checks original launch metadata ownership without native currentness work.
//!
//! This fixed DATA gate checks the actual retained guard, custody and executable
//! creator identities before a historical walk is admitted. It performs no
//! kernel query, registrar callback, native read or allocation. A successful
//! check issues no read, execution, admission or restoration grant; callers
//! separately fund and retain their full live-currentness fences.

use super::{
    CnpSemanticLaunchGuard, CnpSemanticProcessCustody, executable_guard::OriginalExecutable,
};
use crate::node_contract::RuntimeError;
use crucible_node_provider::ProviderError;
use std::{mem::size_of, rc::Rc};

impl CnpSemanticLaunchGuard {
    /// Checks the actual original process and executable-thread metadata owners.
    ///
    /// Revoked or busy native reads are not inspected by this DATA-only gate.
    /// Their independent live predicates remain mandatory for the later effect.
    ///
    /// # Errors
    /// Refuses a foreign guard or custody process, absent retained custody or
    /// executable, or an executable belonging to another process or thread.
    pub(in crate::node_adapters::cnp::semantic) fn original_metadata_origin_data(
        &self,
    ) -> Result<(), RuntimeError> {
        self.ensure_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let custody = self
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        custody
            .ensure_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let executable = custody
            .executable_guard
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        executable.storage_origin_precredit_data()?;

        // This repeats only the same borrowed ownership facts. It cannot renew
        // read-owner phase, process currency or independently allocated credit.
        custody
            .ensure_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        executable.storage_origin_precredit_data()?;
        self.ensure_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)
    }

    /// Counts the fixed borrowed headers used by the metadata-only origin gate.
    pub(in crate::node_adapters::cnp::semantic) fn original_metadata_origin_counter_scratch_data()
    -> usize {
        size_of::<&Self>()
            + size_of::<&CnpSemanticProcessCustody>()
            + size_of::<&OriginalExecutable>()
            + size_of::<&Box<CnpSemanticProcessCustody>>()
            + size_of::<Option<&Box<CnpSemanticProcessCustody>>>()
            + size_of::<Result<&Box<CnpSemanticProcessCustody>, RuntimeError>>()
            + size_of::<&Rc<OriginalExecutable>>()
            + size_of::<Option<&Rc<OriginalExecutable>>>()
            + size_of::<Result<&Rc<OriginalExecutable>, RuntimeError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + 2 * size_of::<u32>()
    }
}
