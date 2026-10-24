//! Retains the same immutable original tuple through fresh job retirement.
//!
//! A tuple is moved once; no Launch clone, serialization, capacity normalization
//! or public address substitutes for this actor-local strong ownership. These
//! owners carry no Source, native member, deployment grant or accepted result.

use crate::node_contract::{NodeRuntime, RuntimeError};
use crucible_node_transport::reference_packet::service::PacketNative5SourceLaunch;
use crucible_node_transport::retained_metadata::observe_retained_native_launch;
use std::{
    mem::{align_of, size_of},
    rc::Rc,
    thread::ThreadId,
};

struct OriginalTuple {
    launches: [PacketNative5SourceLaunch; 3],
    process: u32,
    thread: ThreadId,
}

/// Owns the moved immutable original three-member launch tuple.
///
/// No mutable reference, public pointer or serialization implementation escapes.
/// Rc deliberately follows the existing actor-local Source/Job ownership model.
pub struct OriginalSourceBirthLaunches {
    original: Rc<OriginalTuple>,
}

/// Keeps one selected original alive independently of Prepared or other jobs.
#[derive(Clone)]
pub struct OriginalSourceBirthLaunch {
    original: Rc<OriginalTuple>,
    member: usize,
}

impl OriginalSourceBirthLaunches {
    /// Quotes the actual tuple payload with the existing shared-header supplier.
    ///
    /// Existing child buffers move unchanged and remain separately observed.
    /// The real parent admits this demand before calling [`Self::retain_into`].
    ///
    /// # Errors
    /// Refuses checked layout overflow or the supplied restriction.
    pub fn allocation_storage_data(maximum: usize) -> Result<usize, RuntimeError> {
        let header = NodeRuntime::capture_protocol_shared_header_storage(
            1,
            align_of::<OriginalTuple>(),
            maximum,
        )?;
        size_of::<OriginalTuple>()
            .checked_add(header)
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    }

    /// Moves the original tuple into one immutable holder without cloning it.
    ///
    /// The caller preadmits the real payload/control allocation and fixed
    /// constructor windows under its original deployment. Standard Rc allocation
    /// remains subject to that enforced parent domain, not a numeric grant here.
    ///
    /// # Errors
    /// Refuses occupied output or missing original input before taking it.
    pub fn retain_into(
        input: &mut Option<[PacketNative5SourceLaunch; 3]>,
        output: &mut Option<Self>,
    ) -> Result<(), RuntimeError> {
        if output.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        let launches = input.take().ok_or(RuntimeError::OwnerUnavailable)?;
        *output = Some(Self {
            original: Rc::new(OriginalTuple {
                launches,
                process: std::process::id(),
                thread: std::thread::current().id(),
            }),
        });
        Ok(())
    }

    /// Borrows the complete original tuple without exposing replacement rights.
    pub fn originals(&self) -> &[PacketNative5SourceLaunch; 3] {
        &self.original.launches
    }

    /// Retains the actual selected member without copying its buffers.
    ///
    /// # Errors
    /// Refuses another actor or a member outside the original fixed tuple.
    pub fn selected(&self, member: usize) -> Result<OriginalSourceBirthLaunch, RuntimeError> {
        self.authenticate()?;
        if member >= self.original.launches.len() {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(OriginalSourceBirthLaunch {
            original: Rc::clone(&self.original),
            member,
        })
    }

    /// Observes the actual original tuple and its complete child backing.
    ///
    /// Shared views are conservatively repeated by each independent caller.
    /// This is a same-owner census, not a deployment or constructor permission.
    ///
    /// # Errors
    /// Refuses real metadata observation, overflow or the supplied restriction.
    pub fn retained_requested_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let bytes = known_backing(&self.original)?;
        if bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(bytes)
    }

    fn authenticate(&self) -> Result<(), RuntimeError> {
        authenticate(&self.original)
    }

    /// Names only this concrete move/holder/loan family's fixed headers.
    pub fn counter_scratch_data() -> usize {
        crucible_node_transport::retained_metadata::retained_native_launch_counter_scratch_data()
            + size_of::<OriginalTuple>() * 2
            + size_of::<Option<[PacketNative5SourceLaunch; 3]>>()
            + size_of::<&mut Option<[PacketNative5SourceLaunch; 3]>>()
            + size_of::<&mut Option<Self>>()
            + size_of::<Rc<OriginalTuple>>() * 2
            + size_of::<OriginalSourceBirthLaunch>() * 2
            + size_of::<&Self>()
            + size_of::<usize>() * 3
            + size_of::<Result<OriginalSourceBirthLaunch, RuntimeError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}

impl OriginalSourceBirthLaunch {
    /// Borrows the retained selected original, never a decoded replacement.
    pub fn original(&self) -> &PacketNative5SourceLaunch {
        &self.original.launches[self.member]
    }

    /// Checks the same actor and private strong occurrence/member association.
    ///
    /// Equal bytes, capacities or hashes do not make another owner original.
    pub fn same_original(&self, other: &Self) -> bool {
        self.member == other.member
            && Rc::ptr_eq(&self.original, &other.original)
            && authenticate(&self.original).is_ok()
            && authenticate(&other.original).is_ok()
    }

    pub(in crate::node_adapters::cnp) fn authenticate(&self) -> Result<(), RuntimeError> {
        authenticate(&self.original)
    }

    pub(in crate::node_adapters::cnp) fn known_backing_data(&self) -> Result<usize, RuntimeError> {
        known_backing(&self.original)
    }
}

fn known_backing(original: &OriginalTuple) -> Result<usize, RuntimeError> {
    let mut bytes = OriginalSourceBirthLaunches::allocation_storage_data(usize::MAX)?;
    // Conservatively repeat the complete actual tuple per owning view;
    // no content hash or detached total earns an alias subtraction.
    for launch in &original.launches {
        let facts =
            observe_retained_native_launch(launch).map_err(|_| RuntimeError::ResourceLimit)?;
        let children = super::super::PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(&facts, usize::MAX)?;
        bytes = bytes
            .checked_add(children)
            .ok_or(RuntimeError::ResourceLimit)?;
    }
    Ok(bytes)
}

fn authenticate(original: &OriginalTuple) -> Result<(), RuntimeError> {
    if original.process != std::process::id() || original.thread != std::thread::current().id() {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(())
}
