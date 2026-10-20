//! Borrows the retained identity and backing of an original private Source birth.
//!
//! This is one component of the whole birth history, not a whole-owner codec.
//! Native/report finalizers, their actual shared Core members, and the HOST
//! marker are separately composed by the enclosing same-read Source writer.
//! The private key is historical verification material: it is never exposed by
//! a public key getter or decoded into a new live birth, boot or signing grant.
//!
//! ```text
//! {schema,key_role,key,birth_id,host_executable,host_executable_capacities,
//!  host_file_role,host_file_inline_bytes,host_revision,private_launch,
//!  private_launch_capacities,source_birth,source_birth_capacities,
//!  expected_host_registration,expected_host_registration_capacities,
//!  boot_started,ready,failed,report_startup_required}
//! ```

use super::*;
use crate::node_contract::RuntimeError;
use crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityRows as Capacities;
use crucible_node_provider::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::mem::{size_of, size_of_val};

pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct SourceBirthIdentityHistory<
    'a,
> {
    original: &'a OriginalAckPeerBirth,
    boot_started: bool,
}

struct HistoricalSourceSigningKey<'a>(&'a [u8; 32]);

#[derive(Serialize)]
struct HostRevisionHistory<'a> {
    device: &'a u64,
    inode: &'a u64,
    length: &'a u64,
    uid: &'a u32,
    mode: &'a u32,
    modified: &'a (i64, i64),
    changed: &'a (i64, i64),
}

impl OriginalAckPeerBirth {
    /// Borrows the private identity component without acquiring live authority.
    ///
    /// The Source Capture writer retains this private loan under its owning
    /// read. No method hands its raw key to an external caller or protocol DTO.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn historical_identity_data(
        &self,
    ) -> Result<SourceBirthIdentityHistory<'_>, RuntimeError> {
        self.ensure_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        Ok(SourceBirthIdentityHistory {
            original: self,
            boot_started: self.boot_started.get(),
        })
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn historical_identity_metadata_demand_data(
        &self,
    ) -> Result<(usize, usize), RuntimeError> {
        self.ensure_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let mut rows = 0usize;
        let mut shared = 0usize;
        for demand in [
            Capacities(&self.host_executable).metadata_demand_data()?,
            Capacities(&self.private_launch).metadata_demand_data()?,
            Capacities(&self.source_birth).metadata_demand_data()?,
            Capacities(&self.expected_host_registration).metadata_demand_data()?,
        ] {
            rows = rows
                .checked_add(demand.0)
                .ok_or(RuntimeError::ResourceLimit)?;
            shared = shared
                .checked_add(demand.1)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        Ok((rows, shared))
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn historical_identity_counter_scratch_data()
    -> usize {
        let terms = [
            size_of::<Self>(), size_of::<&Self>(), size_of::<SourceBirthIdentityHistory<'static>>(),
            size_of::<&SourceBirthIdentityHistory<'static>>(),
            size_of::<Result<SourceBirthIdentityHistory<'static>, RuntimeError>>(),
            size_of::<HistoricalSourceSigningKey<'static>>(), size_of::<&HistoricalSourceSigningKey<'static>>(),
            size_of::<HostRevisionHistory<'static>>(), size_of::<&HostRevisionHistory<'static>>(),
            size_of::<(&u64, &u64, &u64, &u32, &u32, &(i64,i64), &(i64,i64))>(),
            size_of::<&HostRevision>(), size_of::<&File>(), size_of::<&[u8;32]>(),
            size_of::<&ContentRef>(), size_of::<&Id>(), size_of::<&Vec<u8>>(),
            size_of::<&bool>(), size_of::<&usize>(), size_of::<&'static str>(), size_of::<bool>(),
            size_of::<(usize,usize)>(), size_of::<[(usize,usize);4]>(),
            size_of::<std::array::IntoIter<(usize,usize),4>>(),
            size_of::<Result<(usize,usize),RuntimeError>>(), size_of::<Result<(),RuntimeError>>(),
            size_of::<Result<(),OperationFailure>>(), size_of::<BorrowedCompactBytes<'static>>(),
            size_of::<&BorrowedCompactBytes<'static>>(),
            crate::node_contract::restored_owner_history::original_restored_owner_capacity_counter_scratch_data(),
            BorrowedCompactBytes::requested_serialization_scratch_bytes(),
        ];
        size_of_val(&terms)
            + size_of::<std::slice::Iter<'static, usize>>()
            + terms.iter().sum::<usize>()
    }
}

impl Serialize for HistoricalSourceSigningKey<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl Serialize for SourceBirthIdentityHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        self.original
            .ensure_origin()
            .map_err(|error| S::Error::custom(error.reason))?;
        let OriginalAckPeerBirth {
            process: _,
            thread: _,
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
            // These actual owners are separate REQUIRED components of the outer
            // whole birth. This identity component neither serializes nor drops them.
            report_startup: _,
            native_startup: _,
            native_import18: _,
            native_host_finalization: _,
            host_startup: _,
        } = self.original;
        if boot_started.get() != self.boot_started {
            return Err(S::Error::custom(RuntimeError::ForeignAuthority));
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
        let revision = HostRevisionHistory {
            device,
            inode,
            length,
            uid,
            mode,
            modified,
            changed,
        };
        let mut state = serializer.serialize_struct("SourceBirthIdentityHistory", 19)?;
        state.serialize_field("schema", "source-private.source-birth-identity-history/17")?;
        state.serialize_field("key_role", "historical-source-signing-key")?;
        state.serialize_field("key", &HistoricalSourceSigningKey(key))?;
        state.serialize_field("birth_id", birth_id)?;
        state.serialize_field("host_executable", host_executable)?;
        state.serialize_field("host_executable_capacities", &Capacities(host_executable))?;
        state.serialize_field("host_file_role", "retained-original-host-executable")?;
        state.serialize_field("host_file_inline_bytes", &size_of::<File>())?;
        state.serialize_field("host_revision", &revision)?;
        state.serialize_field("private_launch", private_launch)?;
        state.serialize_field("private_launch_capacities", &Capacities(private_launch))?;
        state.serialize_field("source_birth", &BorrowedCompactBytes::new(source_birth))?;
        state.serialize_field("source_birth_capacities", &Capacities(source_birth))?;
        state.serialize_field(
            "expected_host_registration",
            &BorrowedCompactBytes::new(expected_host_registration),
        )?;
        state.serialize_field(
            "expected_host_registration_capacities",
            &Capacities(expected_host_registration),
        )?;
        state.serialize_field("boot_started", &self.boot_started)?;
        state.serialize_field("ready", ready)?;
        state.serialize_field("failed", failed)?;
        state.serialize_field("report_startup_required", report_startup_required)?;
        let completed = state.end()?;
        self.original
            .ensure_origin()
            .map_err(|error| S::Error::custom(error.reason))?;
        if boot_started.get() != self.boot_started {
            return Err(S::Error::custom(RuntimeError::ForeignAuthority));
        }
        Ok(completed)
    }
}
