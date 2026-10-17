//! Authenticates original Hello against private independently issued launch custody.

use super::{InstalledTypedReaderSourceFixture, invalid};
use crucible_node_contract::{ContentRef, Id, IdSet, ProviderManifest, SchemaRef};
use crucible_node_provider::{
    ProviderError,
    handshake::{
        EXTENSION_NEGOTIATION_V1, HelloRequest, HelloResult, ResumedOperation,
        TrustedHandshakeVerifier, TrustedInstallation,
    },
    reference_lineage::INPUT_LINEAGE_FEATURE,
};
use std::rc::Rc;

/// Borrows one exact source installation without exposing private launch bytes.
///
/// Fresh connection authentication cannot resume or replace the original owner.
/// Typed registrar verification remains a separate mandatory handshake layer.
pub struct TypedReaderSourceHandshake {
    pub(super) source: Rc<InstalledTypedReaderSourceFixture>,
    pub(super) node: Id,
}

impl TrustedHandshakeVerifier for TypedReaderSourceHandshake {
    fn authenticate_exchange(
        &mut self,
        _: &Id,
        installation: &TrustedInstallation,
        request: &HelloRequest,
        result: &HelloResult,
    ) -> Result<(), ProviderError> {
        self.source.binding(&self.node)?;
        let source = self.source.source(&self.node)?;
        let bootstrap = &source.launch.bootstrap;
        if installation.session_id != bootstrap.authority.session_id
            || installation.incarnation_id != bootstrap.authority.incarnation_id
            || installation.measured_implementation != source.profile.implementation
            || installation.launch_receipt != bootstrap.admission_receipt
            || installation.admission_token.as_slice() != bootstrap.admission_token.as_slice()
            || request.admission_token != bootstrap.admission_token
            || request.session_id != bootstrap.authority.session_id
            || request.resume_session.is_some()
            || result.session_id != bootstrap.authority.session_id
            || result.incarnation_id != bootstrap.authority.incarnation_id
            || result.controller_nonce != request.controller_nonce
            || result.provider_identity != source.profile.provider_manifest
            || !result.resumed_operations.is_empty()
            || result.selected_features != features()?
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn verify_contract_selection(
        &mut self,
        manifest: &ProviderManifest,
        features_selected: &IdSet,
        schemas: &[SchemaRef],
        guarantees: &ContentRef,
    ) -> Result<(), ProviderError> {
        let source = self.source.source(&self.node)?;
        self.source.binding(&self.node)?;
        if manifest != &source.profile.provider_manifest
            || features_selected != &features()?
            || !schemas.is_empty()
            || guarantees != &source.binding.guarantees_ref
        {
            return Err(invalid());
        }
        source.profile.content(guarantees)?;
        Ok(())
    }

    fn resume_custody(
        &mut self,
        _: &Id,
        _: &Id,
        operations: &IdSet,
    ) -> Result<Vec<ResumedOperation>, ProviderError> {
        if !operations.is_empty() {
            return Err(invalid());
        }
        Ok(Vec::new())
    }

    fn fence_connection(&mut self, _: &Id) -> Result<(), ProviderError> {
        Err(invalid())
    }
}

pub(super) fn features() -> Result<IdSet, ProviderError> {
    [
        "cnp.control-evidence/1",
        "cnp.core/1",
        EXTENSION_NEGOTIATION_V1,
        INPUT_LINEAGE_FEATURE,
    ]
    .into_iter()
    .map(|name| Id::new(name).map_err(Into::into))
    .collect()
}
