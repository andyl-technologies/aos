//! Preserves all actual retained Source birth/finalization capacity geometry.
//!
//! Keys, revisions, files, flags and fixed quoted DATA stay in the enclosing
//! Source allocation. Kernel resources and strong external plan/Source owners
//! remain separate. Weak views retain their real shells without upgrading them;
//! shared barriers also retain their defining nested weak views. No lifecycle
//! readiness, private boot, native member or replacement input is constructed.

use super::*;
use crate::node_adapters::cnp::PacketCompleteSemanticSource;
use crate::node_contract::{
    RuntimeError, restored_owner_history::OriginalOwnerCapacityMetadataData,
};
use crucible_node_transport::retained_metadata::{
    RetainedProtocolMetadataFacts, records::PacketRuntimeMetadataRecordBank,
};
use std::{
    cell::{BorrowError, Ref},
    mem::size_of,
};

impl OriginalAckPeerBirth {
    /// Includes actual inputs and every retained finalization in one census.
    ///
    /// # Errors
    /// Refuses foreign origin, borrowed marker custody, unsupported nested
    /// depth/layout, exhausted selected rows or unavailable physical backing.
    pub(super) fn record_retained_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            process,
            thread,
            key,
            birth_id,
            host_executable,
            host_file: _,
            host_revision,
            private_launch,
            source_birth,
            expected_host_registration,
            boot_started,
            ready,
            failed,
            report_startup_required,
            report_startup,
            native_startup,
            native_import18,
            native_host_finalization,
            host_startup,
        } = self;
        if *process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if *thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        let HostRevision {
            device,
            inode,
            length,
            uid,
            mode,
            modified,
            changed,
        } = host_revision;

        census.observe_inline_data(key)?;
        census.observe_inline_data(birth_id)?;
        census.observe_inline_data(device)?;
        census.observe_inline_data(inode)?;
        census.observe_inline_data(length)?;
        census.observe_inline_data(uid)?;
        census.observe_inline_data(mode)?;
        census.observe_inline_data(modified)?;
        census.observe_inline_data(changed)?;
        census.observe_inline_cell_data(boot_started)?;
        census.observe_inline_data(ready)?;
        census.observe_inline_data(failed)?;
        census.observe_inline_data(report_startup_required)?;

        census.observe(host_executable)?;
        census.observe(private_launch)?;
        census.observe(source_birth)?;
        census.observe(expected_host_registration)?;
        if let Some(state) = report_startup {
            state.record_retained_capacity_data(census)?;
        }
        if let Some(state) = native_startup {
            state.record_retained_capacity_data(census)?;
        }
        if let Some(state) = native_import18 {
            state.record_retained_capacity_data(census)?;
        }
        if let Some(state) = native_host_finalization {
            state.record_retained_capacity_data(census)?;
        }
        let marker = host_startup
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if let Some(marker) = marker.as_ref() {
            marker.record_retained_capacity_data(census)?;
        }
        Ok(())
    }
}

impl PacketCompleteSemanticSource {
    /// Reports the original private birth's complete retained capacity geometry.
    ///
    /// The caller first admits the selected bank and
    /// [`Self::original_complete_birth_capacity_counter_scratch_data`]. Rows
    /// append without clearing prior components. Failed and unready births keep
    /// their actual backing; equivalent numeric DATA cannot renew live custody.
    /// Other Source components and the genuine one-use action remain separate.
    ///
    /// # Errors
    /// Refuses foreign origin, borrowed birth/marker custody, unsupported nested
    /// depth/layout, exhausted selected rows or unavailable physical backing.
    pub fn original_complete_birth_capacity_data(
        &self,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let maximum = bank.as_ref().map_or(usize::MAX, |bank| bank.maximum_rows());
        let mut census = OriginalOwnerCapacityMetadataData::new(maximum, bank);
        let birth = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if let Some(birth) = birth.as_ref() {
            birth.record_retained_capacity_data(&mut census)?;
        }
        self.storage_origin_with_error::<RuntimeError>()?;
        Ok(census.finish())
    }

    /// Names actual birth, nested member, JSON and marker borrowed controls.
    pub fn original_complete_birth_capacity_counter_scratch_data() -> usize {
        use crate::node_admission::{
            OriginalHostFinalizationSource, OriginalNativeImport18StartupMember,
            OriginalNativeImport18StartupQuote, OriginalNativeStartupMember,
            OriginalReportStartupMember,
        };
        OriginalOwnerCapacityMetadataData::counter_scratch_data()
            + OriginalNativeStartupMember::retained_capacity_counter_scratch_data()
            + Self::original_complete_host_startup_marker_capacity_counter_scratch_data()
            + super::super::super::retained_values::value_capacity_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&OriginalAckPeerBirth>()
            + size_of::<Option<&OriginalAckPeerBirth>>()
            + size_of::<Ref<'static, Option<OriginalAckPeerBirth>>>()
            + size_of::<Result<Ref<'static, Option<OriginalAckPeerBirth>>, BorrowError>>()
            + size_of::<&OriginalReportStartupMember>()
            + size_of::<&OriginalNativeImport18StartupMember>()
            + size_of::<&OriginalNativeImport18StartupQuote>()
            + size_of::<&OriginalHostFinalizationSource>()
            + size_of::<&report_startup::OriginalReportStartupFinalization>()
            + size_of::<&native_startup::OriginalNativeStartupFinalization>()
            + size_of::<&native_startup::OriginalNativeImport18Finalization>()
            + size_of::<&ContentRef>()
            + size_of::<&crucible_node_format::HashRef>()
            + size_of::<&Id>()
            + size_of::<&Vec<u8>>()
            + size_of::<&HostRevision>()
            + size_of::<[&Option<serde_json::Value>; 2]>()
            + size_of::<[&Option<serde_json::Value>; 3]>()
            + size_of::<
                std::iter::Flatten<std::array::IntoIter<&'static Option<serde_json::Value>, 2>>,
            >()
            + size_of::<
                std::iter::Flatten<std::array::IntoIter<&'static Option<serde_json::Value>, 3>>,
            >()
            + size_of::<std::option::Iter<'static, serde_json::Value>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
            + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<usize>()
    }
}

#[cfg(test)]
#[path = "metadata/tests.rs"]
mod tests;
