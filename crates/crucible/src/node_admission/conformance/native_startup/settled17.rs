//! Borrows complete native member rows, shared barrier and consumed suffix state.
//!
//! ```text
//! {origin_role,host_finalization_edge,host_finalization,host_finalization_index,
//!  edition,source,plan,rows,suffix,finalization_bytes,source_capture_backend_bytes,
//!  source_capture_execution_bytes,source_capture_execution_scratch,wire_requested_bytes,
//!  host_launch_requested_bytes,launch_digest,maximum_boot_bytes}
//! ```

use super::*;

use crate::node_contract::restored_owner_history::{
    OriginalRestoredOwnerCapacityAliases as Aliases,
    finalizers17::{add_demands, shared_edge, weak_demand, weak_edge},
};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::cell::RefCell;

use crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityRow;
use crucible_node_provider::{
    ProviderError, protocol_snapshot::compact_bytes::BorrowedCompactBytes,
};

struct Member<'a> {
    original: &'a OriginalNativeStartupMember,
    source: &'a PacketCompleteSemanticSource,
    aliases: &'a RefCell<Aliases>,
}
struct Rows<'a> {
    original: &'a NativeStartupRows,
    aliases: &'a RefCell<Aliases>,
}
struct Overlap<'a> {
    original: &'a crucible_node_provider::reference_packet::service::native_startup::PacketNativeBirthRetainedOverlapData,
    aliases: &'a RefCell<Aliases>,
}

impl OriginalNativeStartupMember {
    fn history17_origin(&self, source: &PacketCompleteSemanticSource) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        if !std::ptr::eq(self.source.as_ptr(), source) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Borrows the complete defining owner as historical DATA without a live grant.
    ///
    /// # Errors
    /// Refuses a foreign original process/thread or Source association.
    pub(crate) fn borrowed_settled17_history_data<'a>(
        &'a self,
        source: &'a PacketCompleteSemanticSource,
        aliases: &'a RefCell<Aliases>,
    ) -> Result<impl Serialize + 'a, RuntimeError> {
        self.history17_origin(source)?;
        Ok(Member {
            original: self,
            source,
            aliases,
        })
    }

    /// Counts actual capacity rows and shared alias occurrences before allocation.
    ///
    /// # Errors
    /// Refuses a foreign/busy original or checked traversal and population overflow.
    pub(crate) fn settled17_history_metadata_demand_data(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(usize, usize), RuntimeError> {
        self.history17_origin(source)?;
        add_demands(&[
            (1, 1),
            self.host_finalization
                .settled17_history_metadata_demand_data()?,
            weak_demand(&self.source),
            weak_demand(&self.plan.0),
            if self.rows.retained_overlap.is_some() {
                (2, 2)
            } else {
                (0, 0)
            },
            self.suffix
                .as_ref()
                .map(|suffix| suffix.settled17_history_metadata_demand_data(source))
                .transpose()?
                .unwrap_or((0, 0)),
        ])
    }

    /// Counts the concrete borrowed, scalar, result and alias-counter views.
    pub(crate) fn settled17_history_counter_scratch_data() -> usize {
        use crucible_node_provider::reference_packet::service::native_startup::PacketNativeBirthRetainedOverlapData;
        size_of::<[(usize, usize); 6]>() + size_of::<Member<'static>>() + size_of::<Rows<'static>>() + size_of::<Overlap<'static>>()
            + size_of::<Result<Member<'static>, RuntimeError>>()
            + size_of::<Option<Overlap<'static>>>()
            + size_of::<(OriginalRestoredOwnerCapacityRow, OriginalRestoredOwnerCapacityRow)>()
            + size_of::<Result<(OriginalRestoredOwnerCapacityRow, OriginalRestoredOwnerCapacityRow), ProviderError>>()
            + size_of::<[&usize; 8]>() + size_of::<BorrowedCompactBytes<'static>>()
            + crate::node_admission::OriginalReportStartupMember::settled17_history_counter_scratch_data()
            + OriginalHostFinalizationBarrier::settled17_history_counter_scratch_data()
            + OriginalRestoredSuffixStartupMember::settled17_history_counter_scratch_data()
            + PacketNativeBirthRetainedOverlapData::settled17_history_counter_scratch_data::<(OriginalRestoredOwnerCapacityRow, OriginalRestoredOwnerCapacityRow)>()
    }
}

impl Serialize for Overlap<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        self.original
            .borrowed_settled17_history_data(|launch, private_launch| {
                let mut aliases = self
                    .aliases
                    .try_borrow_mut()
                    .map_err(|_| ProviderError::Correlation("historical alias lookup busy"))?;
                Ok((
                    aliases.borrowed_identity_data(launch).map_err(|_| {
                        ProviderError::Correlation("historical alias lookup exhausted")
                    })?,
                    aliases
                        .borrowed_identity_data(private_launch)
                        .map_err(|_| {
                            ProviderError::Correlation("historical alias lookup exhausted")
                        })?,
                ))
            })
            .map_err(S::Error::custom)?
            .serialize(serializer)
    }
}

impl Serialize for Rows<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let NativeStartupRows {
            private_bootstrap,
            native_birth,
            restore_prepare,
            retained_overlap,
            initial_report_rows,
        } = self.original;
        let overlap = retained_overlap.as_ref().map(|original| Overlap {
            original,
            aliases: self.aliases,
        });
        let reports = initial_report_rows
            .as_ref()
            .map(|rows| rows.borrowed_settled17_history_data());
        let mut state = serializer.serialize_struct("HistoricalNativeStartupRows17", 5)?;
        state.serialize_field("private_bootstrap", private_bootstrap)?;
        state.serialize_field("native_birth", native_birth)?;
        state.serialize_field("restore_prepare", restore_prepare)?;
        state.serialize_field("retained_overlap", &overlap)?;
        state.serialize_field("initial_report_rows", &reports)?;
        state.end()
    }
}

impl Serialize for Member<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let owner = self.original;
        owner
            .history17_origin(self.source)
            .map_err(S::Error::custom)?;
        let OriginalNativeStartupMember {
            host_finalization,
            host_finalization_index,
            edition,
            process: _,
            thread: _,
            source,
            plan,
            rows,
            suffix,
            finalization_bytes,
            source_capture_backend_bytes,
            source_capture_execution_bytes,
            source_capture_execution_scratch,
            wire_requested_bytes,
            host_launch_requested_bytes,
            launch_digest,
            maximum_boot_bytes,
        } = owner;
        let edition = match edition {
            NativeStartupMemberEdition::Startup14 => "startup14",
            NativeStartupMemberEdition::Invocation15 => "invocation15",
        };
        let suffix = suffix
            .as_ref()
            .map(|owner| owner.borrowed_settled17_history_data(self.source, self.aliases))
            .transpose()
            .map_err(S::Error::custom)?;
        let mut state = serializer.serialize_struct("HistoricalNativeStartupMember17", 17)?;
        state.serialize_field("origin_role", "original-source-process-thread")?;
        state.serialize_field(
            "host_finalization_edge",
            &shared_edge(host_finalization, self.aliases).map_err(S::Error::custom)?,
        )?;
        state.serialize_field(
            "host_finalization",
            &host_finalization
                .borrowed_settled17_history_data(
                    self.source,
                    *host_finalization_index,
                    self.aliases,
                )
                .map_err(S::Error::custom)?,
        )?;
        state.serialize_field("host_finalization_index", host_finalization_index)?;
        state.serialize_field("edition", edition)?;
        state.serialize_field(
            "source",
            &weak_edge(source, self.aliases).map_err(S::Error::custom)?,
        )?;
        state.serialize_field(
            "plan",
            &weak_edge(&plan.0, self.aliases).map_err(S::Error::custom)?,
        )?;
        state.serialize_field(
            "rows",
            &Rows {
                original: rows,
                aliases: self.aliases,
            },
        )?;
        state.serialize_field("suffix", &suffix)?;
        state.serialize_field("finalization_bytes", finalization_bytes)?;
        state.serialize_field("source_capture_backend_bytes", source_capture_backend_bytes)?;
        state.serialize_field(
            "source_capture_execution_bytes",
            source_capture_execution_bytes,
        )?;
        state.serialize_field(
            "source_capture_execution_scratch",
            source_capture_execution_scratch,
        )?;
        state.serialize_field("wire_requested_bytes", wire_requested_bytes)?;
        state.serialize_field("host_launch_requested_bytes", host_launch_requested_bytes)?;
        state.serialize_field("launch_digest", &BorrowedCompactBytes::new(launch_digest))?;
        state.serialize_field("maximum_boot_bytes", maximum_boot_bytes)?;
        let result = state.end()?;
        owner
            .history17_origin(self.source)
            .map_err(S::Error::custom)?;
        Ok(result)
    }
}
