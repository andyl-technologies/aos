//! Composes the complete borrowed original Source birth history for edition17.
//!
//! Every actual finalizer and shared marker remains historical DATA. No decoder,
//! boot material extractor or live marker constructor is part of this codec.
//!
//! ```text
//! {schema,identity,report_startup,native_startup,native_host_finalization,host_startup}
//! ```

use super::*;

use crate::node_contract::{
    RuntimeError,
    restored_owner_history::{
        OriginalRestoredOwnerCapacityAliases as Aliases,
        OriginalRestoredOwnerCapacityRows as Capacities, finalizers17::add_demands,
    },
};
use crucible_node_provider::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::{cell::RefCell, mem::size_of};

use crate::node_adapters::cnp::semantic::packet_complete_source::PacketCompleteSemanticSource;
use std::cell::Ref;

struct History<'a> {
    original: &'a OriginalAckPeerBirth,
    source: &'a PacketCompleteSemanticSource,
    aliases: &'a RefCell<Aliases>,
    // The actual marker remains borrowed throughout preflight and serialization.
    host: Ref<'a, Option<host_startup::OriginalHostStartupMarker>>,
}

impl OriginalAckPeerBirth {
    fn history17_source_data(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        if self.native_import18.is_some() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        self.ensure_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        source.storage_origin_with_error::<RuntimeError>()?;
        let retained = source
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if retained
            .as_ref()
            .is_none_or(|birth| !std::ptr::eq(birth, self))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Borrows the actual complete birth under its same retained Source read.
    ///
    /// No key getter, executable read, authority callback or completed-state
    /// qualification is performed. The alias bank belongs to the enclosing
    /// whole history pass and must already have its admitted fixed capacity.
    ///
    /// # Errors
    /// Refuses a foreign Source/origin or a mutable loan of the actual marker.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn borrowed_settled17_history_data<
        'a,
    >(
        &'a self,
        source: &'a PacketCompleteSemanticSource,
        common_aliases: &'a RefCell<Aliases>,
    ) -> Result<impl Serialize + 'a, RuntimeError> {
        self.history17_source_data(source)?;
        let host = self
            .host_startup
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        Ok(History {
            original: self,
            source,
            aliases: common_aliases,
            host,
        })
    }

    /// Counts the actual complete capacity rows and shared alias occurrences.
    ///
    /// # Errors
    /// Refuses a foreign/busy original or checked/depth/population overflow.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn settled17_history_metadata_demand_data(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(usize, usize), RuntimeError> {
        self.history17_source_data(source)?;
        let host = self
            .host_startup
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        add_demands(&[
            self.historical_identity_metadata_demand_data()?,
            self.report_startup
                .as_ref()
                .map(|state| state.settled17_history_metadata_demand_data(source))
                .transpose()?
                .unwrap_or((0, 0)),
            self.native_startup
                .as_ref()
                .map(|state| state.settled17_history_metadata_demand_data(source))
                .transpose()?
                .unwrap_or((0, 0)),
            self.native_host_finalization
                .as_ref()
                .map(|state| state.settled17_history_metadata_demand_data())
                .transpose()?
                .unwrap_or((0, 0)),
            host.as_ref()
                .map(|state| state.settled17_history_metadata_demand_data())
                .transpose()?
                .unwrap_or((0, 0)),
        ])
    }

    /// Counts all actual birth child backing without granting deduplication credit.
    ///
    /// The Source allocation already includes the inline Birth and marker root.
    /// A retained weak barrier allocation is conservatively additional even when
    /// the same member's separate row also keeps that allocation alive.
    ///
    /// # Errors
    /// Refuses foreign/busy originals, invalid backing or the unchanged ceiling.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn settled17_history_retained_heap_data(
        &self,
        source: &PacketCompleteSemanticSource,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.history17_source_data(source)?;
        self.retained_heap_storage_data_with_error::<RuntimeError>(maximum)?
            .checked_add(
                self.native_host_finalization
                    .as_ref()
                    .map(|state| state.settled17_history_retained_heap_data())
                    .unwrap_or(0),
            )
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    }

    /// Counts the defining complete Birth borrowed views before any allocation.
    ///
    /// # Errors
    /// Refuses checked layout arithmetic overflow.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn settled17_history_counter_scratch_data()
    -> Result<usize, RuntimeError> {
        let terms = [Self::historical_identity_counter_scratch_data(),
            report_startup::OriginalReportStartupFinalization::settled17_history_counter_scratch_data(),
            native_startup::OriginalNativeStartupFinalization::settled17_history_counter_scratch_data(),
            host_startup::OriginalHostStartupMarker::settled17_history_counter_scratch_data(),
            crate::node_admission::OriginalHostFinalizationBarrier::settled17_history_counter_scratch_data(),
            size_of::<History<'static>>(), size_of::<Result<History<'static>, RuntimeError>>(),
            size_of::<Ref<'static, Option<host_startup::OriginalHostStartupMarker>>>(),
            size_of::<Result<Ref<'static, Option<host_startup::OriginalHostStartupMarker>>, std::cell::BorrowError>>(),
            size_of::<Ref<'static, Option<Self>>>(),
            size_of::<Result<Ref<'static, Option<Self>>, std::cell::BorrowError>>(),
            size_of::<Option<&Self>>(), size_of::<[&Option<serde_json::Value>; 2]>(),
            size_of::<[(usize,usize);5]>(), size_of::<std::slice::Iter<'static, usize>>(),
            size_of::<usize>(), size_of::<Result<usize,RuntimeError>>(),
            crate::node_contract::restored_owner_history::finalizers17::counter_scratch_data()];
        terms
            .iter()
            .try_fold(std::mem::size_of_val(&terms), |sum, bytes| {
                sum.checked_add(*bytes).ok_or(RuntimeError::ResourceLimit)
            })
    }
}

impl Serialize for History<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let owner = self.original;
        owner
            .history17_source_data(self.source)
            .map_err(S::Error::custom)?;
        let identity = owner.historical_identity_data().map_err(S::Error::custom)?;
        let report = owner
            .report_startup
            .as_ref()
            .map(|state| state.borrowed_settled17_history_data(self.source, self.aliases));
        let native = owner
            .native_startup
            .as_ref()
            .map(|state| state.borrowed_settled17_history_data(self.source, self.aliases));
        let finalization = owner
            .native_host_finalization
            .as_ref()
            .map(|state| state.borrowed_settled17_history_data(self.source, self.aliases));
        let host = self
            .host
            .as_ref()
            .map(|state| state.borrowed_settled17_history_data(self.aliases));
        let mut state = serializer.serialize_struct("HistoricalSourceBirth17", 6)?;
        state.serialize_field("schema", "source-private.source-birth-history/17")?;
        state.serialize_field("identity", &identity)?;
        state.serialize_field("report_startup", &report)?;
        state.serialize_field("native_startup", &native)?;
        state.serialize_field("native_host_finalization", &finalization)?;
        state.serialize_field("host_startup", &host)?;
        let result = state.end()?;
        owner
            .history17_source_data(self.source)
            .map_err(S::Error::custom)?;
        Ok(result)
    }
}
