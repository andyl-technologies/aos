//! Counts the same owning preparation with fixed, caller-retained scratch.

use std::{
    fs::File,
    mem::{align_of, align_of_val, size_of, size_of_val},
    path::PathBuf,
    rc::Rc,
};

use crucible_node_format::ContentRef;
use crucible_node_transport::{ProviderError, retained_metadata::RetainedProtocolMetadataFacts};

use crate::node_contract::{NodeRuntime, RuntimeError};

use super::super::{CnpRetainedStorageReport, CnpRetainedStorageUnknowns};

const SHARED_OWNERS: usize = 256;

#[derive(Clone, Copy)]
struct SharedOwner {
    identity: *const (),
    bytes: usize,
}

pub(in crate::node_adapters::cnp::semantic) struct PreparationCounter {
    bytes: usize,
    maximum: usize,
    shared: [Option<SharedOwner>; SHARED_OWNERS],
    used: usize,
    pub(in crate::node_adapters::cnp::semantic) unknowns: CnpRetainedStorageUnknowns,
    pub(in crate::node_adapters::cnp::semantic) std_child_layout: bool,
}

impl PreparationCounter {
    pub(in crate::node_adapters::cnp::semantic) fn new(maximum: usize) -> Self {
        Self {
            bytes: 0,
            maximum,
            shared: [None; SHARED_OWNERS],
            used: 0,
            unknowns: CnpRetainedStorageUnknowns::default(),
            std_child_layout: false,
        }
    }

    pub(super) fn reset(&mut self, maximum: usize) {
        // Clear pointer observations on success, refusal and unwind. No owner
        // reference or identity escapes the original synchronous immutable loan.
        self.shared.fill(None);
        self.bytes = 0;
        self.maximum = maximum;
        self.used = 0;
        self.unknowns = CnpRetainedStorageUnknowns::default();
        self.std_child_layout = false;
    }

    pub(in crate::node_adapters::cnp::semantic) fn finish(&self) -> CnpRetainedStorageReport {
        CnpRetainedStorageReport {
            known_requested_bytes: self.bytes,
            unknowns: self.unknowns,
            std_child_layout: self.std_child_layout,
        }
    }

    pub(in crate::node_adapters::cnp::semantic) fn remaining(&self) -> usize {
        self.maximum - self.bytes
    }

    pub(in crate::node_adapters::cnp::semantic) fn ceiling(&self) -> usize {
        self.maximum
    }

    pub(in crate::node_adapters::cnp::semantic) fn add(
        &mut self,
        bytes: usize,
    ) -> Result<(), RuntimeError> {
        let next = self
            .bytes
            .checked_add(bytes)
            .filter(|next| *next <= self.maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        self.bytes = next;
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic) fn metadata(
        &mut self,
        facts: &RetainedProtocolMetadataFacts,
    ) -> Result<(), RuntimeError> {
        self.add(
            super::super::super::PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                facts,
                self.remaining(),
            )?,
        )
    }

    pub(in crate::node_adapters::cnp::semantic) fn shared(
        &mut self,
        identity: *const (),
        bytes: usize,
    ) -> Result<bool, RuntimeError> {
        if identity.is_null() {
            return Err(RuntimeError::ForeignAuthority);
        }
        for owner in self.shared[..self.used].iter().flatten() {
            if owner.identity == identity {
                return if owner.bytes == bytes {
                    Ok(false)
                } else {
                    Err(RuntimeError::ForeignAuthority)
                };
            }
        }
        if self.used == self.shared.len() {
            return Err(RuntimeError::ResourceLimit);
        }
        self.add(bytes)?;
        self.shared[self.used] = Some(SharedOwner { identity, bytes });
        self.used += 1;
        Ok(true)
    }

    pub(in crate::node_adapters::cnp::semantic) fn rc<T: ?Sized>(
        &mut self,
        value: &Rc<T>,
    ) -> Result<bool, RuntimeError> {
        self.shared_layout(
            Rc::as_ptr(value).cast(),
            size_of_val(value.as_ref()),
            align_of_val(value.as_ref()),
        )
    }

    pub(in crate::node_adapters::cnp::semantic) fn activation(
        &mut self,
        value: &crate::node_contract::WorldActivation,
    ) -> Result<(), RuntimeError> {
        let facts = value.retained_requested_storage_data(self.ceiling())?;
        self.add(facts.independent_bytes())?;
        for owner in facts.shared_allocations() {
            self.shared(owner.identity(), owner.requested_bytes())?;
        }
        Ok(())
    }

    fn shared_layout(
        &mut self,
        identity: *const (),
        inline: usize,
        alignment: usize,
    ) -> Result<bool, RuntimeError> {
        let header =
            NodeRuntime::capture_protocol_shared_header_storage(1, alignment, self.ceiling())?;
        self.shared(
            identity,
            inline
                .checked_add(header)
                .ok_or(RuntimeError::ResourceLimit)?,
        )
    }

    pub(in crate::node_adapters::cnp::semantic) fn arc_file(
        &mut self,
        file: &File,
    ) -> Result<(), RuntimeError> {
        self.shared_layout(
            std::ptr::from_ref(file).cast(),
            size_of::<File>(),
            align_of::<File>(),
        )?;
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic) fn path(
        &mut self,
        value: &PathBuf,
    ) -> Result<(), RuntimeError> {
        self.add(value.capacity())
    }

    pub(in crate::node_adapters::cnp::semantic) fn content_reference(
        &mut self,
        value: &ContentRef,
    ) -> Result<(), RuntimeError> {
        for text in [
            &value.hash.algorithm,
            &value.hash.domain,
            &value.hash.digest,
            &value.media_type,
        ] {
            self.add(text.capacity())?;
        }
        Ok(())
    }
}

/// Does not format or box a failure from an inert SDK metadata observer.
pub(in crate::node_adapters::cnp::semantic) fn metadata_failure(
    error: ProviderError,
) -> RuntimeError {
    match error {
        ProviderError::ResourceExhausted(_) => RuntimeError::ResourceLimit,
        _ => RuntimeError::OwnerUnavailable,
    }
}
