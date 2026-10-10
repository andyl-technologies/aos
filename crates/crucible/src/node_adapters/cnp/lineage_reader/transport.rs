//! Routes every selected native effect through the owning two-group guard.

use crucible_node_contract::*;
use crucible_node_provider::{
    ProviderError,
    bodies::ResponseBody,
    envelope::Method,
    reference_lineage::LineageSourceGuard,
    reference_service::{ReferenceProfile, ReferenceServiceBootstrap},
};
use serde::de::DeserializeOwned;

pub(super) struct OriginalContext<'a> {
    pub(super) profile: &'a ReferenceProfile,
    pub(super) bootstrap: &'a ReferenceServiceBootstrap,
    guard: &'a LineageSourceGuard,
}

impl<'a> OriginalContext<'a> {
    pub(super) fn new(
        profile: &'a ReferenceProfile,
        bootstrap: &'a ReferenceServiceBootstrap,
        guard: &'a LineageSourceGuard,
    ) -> Self {
        Self {
            profile,
            bootstrap,
            guard,
        }
    }

    pub(super) fn content(&self, reference: &ContentRef) -> Result<&'a [u8], ProviderError> {
        self.guard.content(reference)
    }

    pub(super) fn record<T: DeserializeOwned>(
        &self,
        reference: &ContentRef,
    ) -> Result<T, ProviderError> {
        let value = canonical::parse_json(self.content(reference)?, 1_048_576)?;
        Ok(serde_json::from_value(value).map_err(ContractError::from)?)
    }
}

pub(super) struct OriginalSender<'a> {
    guard: &'a mut LineageSourceGuard,
}

impl<'a> OriginalSender<'a> {
    pub(super) fn new(guard: &'a mut LineageSourceGuard) -> Self {
        Self { guard }
    }

    pub(super) fn upload(
        &mut self,
        reference: &ContentRef,
        bytes: &[u8],
    ) -> Result<(), ProviderError> {
        self.guard.upload(reference, bytes)
    }

    pub(super) fn call(
        &mut self,
        id: Id,
        operation: Option<Id>,
        method: Method,
        owned: bool,
        body: impl serde::Serialize,
    ) -> Result<ResponseBody, ProviderError> {
        self.guard.call(id, operation, method, owned, body)
    }
}
