//! Source-installed consuming schemas and actual peer custody for packet service.

use crucible_node_contract::*;
use serde::Deserialize;
use serde_json::Value;
use std::{cell::RefCell, collections::BTreeMap};

use super::{super::control::PacketControlSelection, PacketSourceLaunch};
use crate::{ProviderError, blob::*, connection::*, envelope::*, handshake::*};

pub(super) struct Policy {
    pub(super) selection: PacketControlSelection,
    pub(super) coordinator: crate::reference_service::InstalledContent,
    pub(super) definition: ContentRef,
    pub(super) common: Option<super::super::coordinator::PacketCoordinatorInstallation>,
}

impl super::super::endpoint::PacketEndpointPolicy for Policy {
    fn authenticate_source(
        &self,
        authority: &ConnectionAuthority,
        selection: &PacketControlSelection,
    ) -> Result<(), ProviderError> {
        let binding = selection
            .realization
            .bindings
            .first()
            .ok_or(ProviderError::Correlation("packet installed owner absent"))?;
        if selection != &self.selection
            || authority.session_id() != &binding.authority.session_id
            || authority.incarnation_id() != &binding.authority.incarnation_id
            || authority.limits().requests.get() != 64
        {
            return Err(ProviderError::Correlation(
                "packet installed negotiated source changed",
            ));
        }
        Ok(())
    }

    fn consuming_schema(&self, _: &ContentRef, _: &Envelope) -> Result<ContentRef, ProviderError> {
        Ok(self.definition.clone())
    }
}

impl BlobSchemaVerifier for Policy {
    fn verify_schema(
        &self,
        schema: &ContentRef,
        content: &ContentRef,
        bytes: &[u8],
    ) -> Result<(), ProviderError> {
        if schema != &self.definition || content.media_type != "application/json" {
            return Err(ProviderError::Correlation(
                "packet consuming schema not installed",
            ));
        }
        content.verify(bytes)?;
        let value = canonical::parse_json(bytes, 65_536)?;
        if canonical::canonical_json(&value)? != bytes {
            return Err(ProviderError::Correlation(
                "packet consuming bytes not canonical",
            ));
        }
        if content == &self.coordinator.reference {
            return if bytes == self.coordinator.bytes.as_slice() {
                Ok(())
            } else {
                Err(ProviderError::Correlation(
                    "packet original coordinator changed",
                ))
            };
        }
        if value.get("schema").and_then(Value::as_str) == Some("crucible/coordinator-initial/1")
            && let Some(common) = &self.common
        {
            return common.validate_body(bytes);
        }
        match value.get("schema").and_then(Value::as_str) {
            Some("source-owned.packet-common-grant.v1") => {
                let _: super::super::common::PacketCommonGrant =
                    serde_json::from_value(value).map_err(ContractError::from)?;
                Ok(())
            }
            Some("source-owned.packet-consumption.v1") => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Consumption {
                    schema: String,
                    operation: Id,
                    outputs: Vec<Id>,
                }
                let body: Consumption =
                    serde_json::from_value(value).map_err(ContractError::from)?;
                if body.schema != "source-owned.packet-consumption.v1" || body.outputs.len() > 1 {
                    return Err(ProviderError::Correlation("packet consumption shape"));
                }
                body.operation.validate()?;
                for id in body.outputs {
                    id.validate()?;
                }
                Ok(())
            }
            None => {
                let manifest: ActivationManifest =
                    serde_json::from_value(value).map_err(ContractError::from)?;
                manifest.validate()?;
                Ok(())
            }
            _ => Err(ProviderError::Correlation(
                "packet consuming schema unsupported",
            )),
        }
    }
}

impl BodySchemaVerifier for Policy {
    fn verify(
        &self,
        _: &ConnectionAuthority,
        envelope: &Envelope,
        _: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        if !envelope.extensions.is_empty()
            || envelope.body.get("extensions").is_some_and(|extensions| {
                extensions
                    .as_object()
                    .is_none_or(|values| !values.is_empty())
            })
        {
            return Err(ProviderError::Correlation(
                "packet source extensions unsupported",
            ));
        }
        Ok(())
    }
}

pub(super) struct Supervisor {
    incidents: RefCell<Vec<ConnectionIncident>>,
    blobs: RefCell<Vec<BlobQuarantine>>,
}

impl Supervisor {
    pub(super) fn new() -> Result<Self, ProviderError> {
        let mut incidents = Vec::new();
        let mut blobs = Vec::new();
        incidents
            .try_reserve_exact(1)
            .map_err(|_| ProviderError::ResourceExhausted("packet incident slot"))?;
        blobs
            .try_reserve_exact(1)
            .map_err(|_| ProviderError::ResourceExhausted("packet quarantine slot"))?;
        Ok(Self {
            incidents: RefCell::new(incidents),
            blobs: RefCell::new(blobs),
        })
    }
}

impl ConnectionSupervisor for Supervisor {
    fn quarantine(&self, incident: ConnectionIncident) {
        self.incidents.borrow_mut().push(incident);
    }
}
impl BlobSupervisor for Supervisor {
    fn quarantine(&self, ledger: BlobQuarantine) {
        self.blobs.borrow_mut().push(ledger);
    }
}

pub(super) struct Verifier<'a>(pub(super) &'a PacketSourceLaunch);
impl TrustedHandshakeVerifier for Verifier<'_> {
    fn authenticate_exchange(
        &mut self,
        _: &Id,
        installation: &TrustedInstallation,
        _: &HelloRequest,
        result: &HelloResult,
    ) -> Result<(), ProviderError> {
        if installation.measured_implementation != self.0.selection.provider.implementation
            || result.provider_identity != self.0.selection.provider
        {
            return Err(ProviderError::Correlation(
                "packet private actual implementation changed",
            ));
        }
        Ok(())
    }
    fn verify_contract_selection(
        &mut self,
        manifest: &ProviderManifest,
        features: &IdSet,
        schemas: &[SchemaRef],
        guarantees: &ContentRef,
    ) -> Result<(), ProviderError> {
        let expected = vec![Id::new("cnp.control-evidence/1")?, Id::new("cnp.core/1")?];
        if manifest != &self.0.selection.provider
            || features != &expected
            || !schemas.is_empty()
            || self
                .0
                .selection
                .realization
                .bindings
                .first()
                .is_none_or(|binding| guarantees != &binding.compatibility.guarantees_ref)
        {
            return Err(ProviderError::Correlation(
                "packet installed original contract changed",
            ));
        }
        Ok(())
    }
    fn resume_custody(
        &mut self,
        _: &Id,
        _: &Id,
        _: &IdSet,
    ) -> Result<Vec<ResumedOperation>, ProviderError> {
        Err(ProviderError::Correlation(
            "packet source restoration not qualified",
        ))
    }
    fn fence_connection(&mut self, _: &Id) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation(
            "packet original connection cannot be substituted",
        ))
    }
}

pub(super) fn features() -> Result<Vec<Id>, ProviderError> {
    Ok(vec![
        Id::new("cnp.control-evidence/1")?,
        Id::new("cnp.core/1")?,
    ])
}

pub(super) fn extensions() -> BTreeMap<String, Id> {
    BTreeMap::new()
}
