//! Retains commitment effects in the ordinary reference controller.

use crucible_node_format::*;
use crucible_node_transport::{
    ProviderError, bodies::*, envelope::Method, reference_service::ReferenceServiceBootstrap,
};
use serde::de::DeserializeOwned;

use super::super::control::CnpControlledReference;
use super::{InputCommitPeer, StagedInput};
use crate::node_contract::OperationFailure;

impl InputCommitPeer for CnpControlledReference {
    fn staged_input(&self) -> Option<&StagedInput> {
        self.input.as_ref()
    }

    fn staged_input_mut(&mut self) -> Option<&mut StagedInput> {
        self.input.as_mut()
    }

    fn commit_owner_binding(&self) -> &OwnerBinding {
        &self.owner_binding
    }

    fn commit_bootstrap(&self) -> Result<ReferenceServiceBootstrap, ProviderError> {
        Ok(self.controller()?.bootstrap.clone())
    }

    fn commit_features(&self) -> Result<IdSet, ProviderError> {
        self.verify_native_custody()?;
        Ok(self.controller()?.selected_features().clone())
    }

    fn commit_request_hash(
        &self,
        request: Id,
        body: &InputRequest,
        extensions: Extensions,
    ) -> Result<HashRef, ProviderError> {
        self.controller()?.request_hash_with_extensions(
            request,
            None,
            Method::Input,
            true,
            body,
            extensions,
        )
    }

    fn commit_upload(&mut self, reference: &ContentRef, bytes: &[u8]) -> Result<(), ProviderError> {
        self.controller_mut()?.upload(reference, bytes)
    }

    fn commit_call(
        &mut self,
        request: Id,
        body: InputRequest,
        extensions: Extensions,
    ) -> Result<ResponseBody, ProviderError> {
        self.controller_mut()?.call_with_extensions(
            request,
            None,
            Method::Input,
            true,
            body,
            extensions,
        )
    }

    fn commit_record<T: DeserializeOwned + Validate>(
        &self,
        reference: &ContentRef,
    ) -> Result<T, ProviderError> {
        self.controller()?.record(reference)
    }

    fn commit_content(&self, reference: &ContentRef) -> Result<&[u8], ProviderError> {
        self.controller()?.content(reference)
    }

    fn commit_verify_native(&self) -> Result<(), ProviderError> {
        self.verify_native_custody()
    }

    fn commit_retain_boundary(
        &mut self,
        reference: &ContentRef,
        dependencies: Vec<ContentRef>,
    ) -> Result<(), OperationFailure> {
        self.retain_boundary_record(reference, dependencies)
    }
}
