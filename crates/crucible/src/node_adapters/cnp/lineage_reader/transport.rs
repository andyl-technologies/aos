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
    collecting: Option<(
        &'a dyn super::LineageReferenceQualification,
        &'a crate::node_admission::InstalledConformancePlan,
    )>,
}

impl<'a> OriginalSender<'a> {
    pub(super) fn new(
        guard: &'a mut LineageSourceGuard,
        collecting: Option<(
            &'a dyn super::LineageReferenceQualification,
            &'a crate::node_admission::InstalledConformancePlan,
        )>,
    ) -> Self {
        Self { guard, collecting }
    }

    fn current(&self) -> Result<(), ProviderError> {
        if let Some((qualification, plan)) = self.collecting {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                qualification.authenticate_collection_dispatch(plan)
            }))
            .map_err(|_| ProviderError::Correlation("terminal collection source read unwound"))??;
        }
        Ok(())
    }

    pub(super) fn upload(
        &mut self,
        reference: &ContentRef,
        bytes: &[u8],
    ) -> Result<(), ProviderError> {
        self.current()?;
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
        self.current()?;
        self.guard.call(id, operation, method, owned, body)
    }
}
