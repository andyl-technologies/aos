//! Lends normal Prepare63 to the existing authenticated durable source issuer.
//!
//! The request, protected catalogs, canonical dispatch and verified original D
//! remain together under the real service loan. This frontier emits neither a
//! client response nor worker permission; child custody and finalization remain
//! separately owed on this same original.

use super::*;
use super::callsite::NetworkServiceMethodV4;
use super::preissue::NetworkPrepareSourcesOriginalV4;
use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_model::{CanonicalAssignmentManifestV1, model::SandboxSpec};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use aos_sandbox_broker::receiving::NetworkServiceReceivingLoanV4;

#[derive(Clone, Copy)]
enum First { Order, Purpose, Geometry, Funding, Sources }

/// Retains the actual signed Prepare63 sources and their first selected failure.
///
/// Construction is inert. A prepared source is not a worker result: the real
/// child F/Source, request admission, effects, observation, finalization and all
/// enclosing posts must finish before any successful client response exists.
#[must_use]
pub struct NetworkServicePrepareOriginalV4 {
    pub(super) sources: NetworkPrepareSourcesOriginalV4,
    geometry: Option<std::result::Result<ResourceVector, AccountingError>>,
    funding: Option<std::result::Result<(), Closed>>,
    result: Option<Result<()>>,
    first: Option<First>,
    entered: bool,
    original_selected: bool,
}

impl NetworkServicePrepareOriginalV4 {
    /// Creates fixed empty destinations without admitting a request or opening IO.
    #[must_use]
    pub fn new() -> Self {
        Self { sources: NetworkPrepareSourcesOriginalV4::new(), geometry: None,
            funding: None, result: None, first: None, entered: false,
            original_selected: false }
    }

    /// Identifies a refusal selected from this same actual parent payer.
    #[must_use]
    pub fn original_failure_selected_v4(&self) -> bool { self.original_selected }

    /// Borrows the selected source, arithmetic or closed-stage refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Sources => self.sources.failure(),
            First::Geometry => self.geometry.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Order | First::Purpose | First::Funding => None,
        }.or(Some(&NetworkServiceClosedV4))
    }
}

impl Default for NetworkServicePrepareOriginalV4 {
    fn default() -> Self { Self::new() }
}

impl NetworkServiceDomainCallsiteV4<'_> {
    /// Runs the sole existing signed63 source issuer on the real protected owners.
    ///
    /// The existing issuer verifies the authenticated original, narrows the
    /// unchanged D, prepays model growth, and gates each State append. No copied
    /// header, callback signer, catalog replacement or alternate issuer is used.
    ///
    /// # Errors
    /// Retains purpose, request, quote, funding, signature, reservation, durable
    /// state or dispatch refusal, with actual payer attribution when selected.
    pub fn prepare_sources_once_v4(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        manifest: &CanonicalAssignmentManifestV1,
        specification: &SandboxSpec,
        loan: &mut NetworkServiceReceivingLoanV4<'_>,
        original: &mut NetworkServicePrepareOriginalV4,
    ) -> Result<()> {
        if original.entered {
            original.first.get_or_insert(First::Order);
            return Err(NetworkServiceClosedV4);
        }
        original.entered = true;
        if !matches!(self.method, NetworkServiceMethodV4::Prepare)
            || request.method() != BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2 {
            original.first = Some(First::Purpose);
            return Err(NetworkServiceClosedV4);
        }
        original.geometry = Some((|| {
            let bytes = std::mem::size_of::<NetworkServicePrepareOriginalV4>()
                .checked_mul(2).and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
            Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
        })());
        let Some(Ok(demand)) = original.geometry.as_ref() else {
            original.first = Some(First::Geometry);
            return Err(NetworkServiceClosedV4);
        };
        original.funding = Some(loan.require_additional_representation_v4(*demand));
        if !matches!(original.funding, Some(Ok(()))) {
            original.first = Some(First::Funding);
            original.original_selected = true;
            return Err(NetworkServiceClosedV4);
        }
        original.result = Some(original.sources.prepare_once_v4(&mut *self.coordinator,
            &mut *self.preparations, request, manifest, specification, loan));
        if !matches!(original.result, Some(Ok(()))) {
            original.first = Some(First::Sources);
            original.original_selected = original.sources.original_failure_selected_v4();
            return Err(NetworkServiceClosedV4);
        }
        Ok(())
    }
}
