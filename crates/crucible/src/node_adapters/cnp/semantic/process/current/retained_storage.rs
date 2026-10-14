//! Observes retained read-handle aliases after live currentness may have ended.

use super::*;
use crate::node_adapters::cnp::semantic::{
    CnpRetainedStorageReport, retained_storage::Counter, unknown,
};
use crate::node_contract::OperationFailure;

impl CnpSemanticSourceRead {
    /// Counts actual shared backing retained by this same original read handle.
    ///
    /// The containing handle's inline slot is caller-owned. Actual ReadOwner,
    /// registrar and executable roots are conservatively counted per view; equal
    /// labels never discharge another view. This method remains usable after
    /// revocation and invokes no live source, registrar renewal or kernel query.
    /// It grants no source, reclamation, process-currentness or native authority.
    ///
    /// # Errors
    /// Refuses foreign creator processes/threads, unsupported SDK metadata or
    /// arithmetic/traversal/storage bounds. Opaque lease workers remain unknown.
    pub fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<CnpRetainedStorageReport, OperationFailure> {
        if self.process != std::process::id() {
            return Err(super::super::super::refused(
                "original source read has another creator",
            ));
        }
        self.executable.ensure_origin().map_err(unknown)?;
        let Self {
            process: _,
            owner,
            registration,
            kernel: _,
            executable,
        } = self;
        let mut counter = Counter::new(maximum);
        counter.rc(owner)?;
        counter.metadata(
            &registration
                .retained_metadata_facts_data()
                .map_err(unknown)?,
        )?;
        if counter.rc(executable)? {
            executable.charge_retained_storage_data(&mut counter)?;
        }
        self.executable.ensure_origin().map_err(unknown)?;
        Ok(counter.finish())
    }
}
