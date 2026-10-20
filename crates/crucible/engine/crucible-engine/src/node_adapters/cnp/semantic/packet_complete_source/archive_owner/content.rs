//! Restricts inert archive comparisons to their actual authenticated inventory.

use super::*;
use crate::node_state::ParentArchive17ReadScope;

#[derive(Clone, Copy)]
pub(in crate::node_adapters::cnp::semantic::packet_complete_source) enum ArchivedContentData<'a> {
    Verified(&'a VerifiedStateContent),
    Parent(&'a ParentArchive17ReadScope<'a, 'a>),
}

impl<'a> ArchivedContentData<'a> {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn get(
        &self,
        reference: &ContentRef,
    ) -> Option<&'a [u8]> {
        match self {
            Self::Verified(content) => (*content).get(reference),
            Self::Parent(scope) => (*scope).body_data(reference).ok(),
        }
    }

    pub(super) fn capture_owned_storage(&self) -> Result<usize, OperationFailure> {
        match self {
            Self::Verified(content) => content.capture_owned_storage().map_err(unknown),
            Self::Parent(scope) => scope
                .retained_content_requested_storage_data()
                .map_err(unknown),
        }
    }

    pub(super) fn same_data(&self, other: Self) -> bool {
        match (self, other) {
            (Self::Verified(left), Self::Verified(right)) => std::ptr::eq(*left, right),
            (Self::Parent(left), Self::Parent(right)) => std::ptr::eq(*left, right),
            _ => false,
        }
    }

    pub(super) fn live_data(&self) -> Result<&'a VerifiedStateContent, OperationFailure> {
        match self {
            Self::Verified(content) => Ok(content),
            Self::Parent(_) => Err(refused("inert parent data is not an original Source loan")),
        }
    }
}
