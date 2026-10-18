//! Source-installed consuming schemas and actual peer custody for packet service.

use crucible_node_contract::*;
use serde::Deserialize;
use serde_json::Value;
use std::{cell::RefCell, collections::BTreeMap};

use super::{super::control::PacketControlSelection, server::ServerLaunch};
use crate::{ProviderError, blob::*, connection::*, envelope::*, handshake::*};

pub(super) struct Policy {
    pub(super) selection: PacketControlSelection,
    pub(super) coordinator: crate::reference_service::InstalledContent,
    pub(super) definition: ContentRef,
    pub(super) common: Option<super::super::coordinator::PacketCoordinatorInstallation>,
    pub(super) world: Option<super::super::coordinator::PacketWorldCoordinatorInstallation>,
    pub(super) connected: Option<super::super::coordinator::PacketConnectedCoordinatorInstallation>,
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
            || authority.limits().requests.get()
                != if self.world.is_some() || self.connected.is_some() {
                    256
                } else {
                    64
                }
            || authority.limits().journal_entries.get()
                != if self.world.is_some() || self.connected.is_some() {
                    1024
                } else {
                    256
                }
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
        if schema != &self.definition {
            return Err(ProviderError::Correlation(
                "packet consuming schema not installed",
            ));
        }
        content.verify(bytes)?;
        if self.connected.is_some() && content.media_type == "application/octet-stream" {
            return if bytes.len() <= 1024 {
                Ok(())
            } else {
                Err(ProviderError::ResourceExhausted(
                    "packet original connected payload",
                ))
            };
        }
        if self.connected.is_some()
            && content.media_type == "application/vnd.crucible.input-inventory+json"
        {
            let value = canonical::parse_json(bytes, 65_536)?;
            if canonical::canonical_json(&value)? != bytes {
                return Err(ProviderError::Frame(
                    "packet original input inventory canonical bytes",
                ));
            }
            let rows = value
                .as_array()
                .ok_or(ProviderError::Frame("packet delivery inventory shape"))?;
            if rows.len() > 4 {
                return Err(ProviderError::ResourceExhausted(
                    "packet original delivery population",
                ));
            }
            let _: Vec<crate::input_commit::CommittedDeliveryV1> =
                serde_json::from_value(value).map_err(ContractError::from)?;
            // Complete actual route, event, causal and payload authentication
            // remains in the native original Input operation after upload.
            return Ok(());
        }
        if content.media_type != "application/json" {
            return Err(ProviderError::Correlation(
                "packet source storage media unsupported",
            ));
        }
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
        if value.get("schema").and_then(Value::as_str) == Some("crucible/coordinator-initial/1")
            && let Some(world) = &self.world
        {
            return world.validate_body(bytes);
        }
        if value.get("schema").and_then(Value::as_str) == Some("crucible/coordinator-initial/1")
            && let Some(connected) = &self.connected
        {
            return connected.validate_body(bytes);
        }
        match value.get("schema").and_then(Value::as_str) {
            Some("source-owned.packet-common-grant.v4") if self.connected.is_some() => {
                let _: super::super::common::PacketConnectedCommonGrant =
                    serde_json::from_value(value).map_err(ContractError::from)?;
                Ok(())
            }
            Some("source-owned.packet-common-grant.v2")
                if self.world.is_some() || self.connected.is_some() =>
            {
                let _: super::super::common::PacketCommonGrant =
                    serde_json::from_value(value).map_err(ContractError::from)?;
                Ok(())
            }
            Some("source-owned.packet-common-grant.v1")
                if self.world.is_none() && self.connected.is_none() =>
            {
                let _: super::super::common::PacketCommonGrant =
                    serde_json::from_value(value).map_err(ContractError::from)?;
                Ok(())
            }
            Some("source-owned.packet-consumption.v1")
            | Some("source-owned.packet-consumption.v4") => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Consumption {
                    schema: String,
                    operation: Id,
                    outputs: Vec<Id>,
                }
                let body: Consumption =
                    serde_json::from_value(value).map_err(ContractError::from)?;
                let connected = body.schema == "source-owned.packet-consumption.v4";
                if (connected && self.connected.is_none())
                    || body.outputs.len() > if connected { 4 } else { 1 }
                {
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
        authority: &ConnectionAuthority,
        envelope: &Envelope,
        _: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        if !envelope.extensions.is_empty() {
            if self.connected.is_none()
                || envelope.message != MessageKind::Request
                || envelope.method != Method::Input
                || !authority
                    .selected_features()
                    .iter()
                    .any(|feature| feature.as_str() == super::super::input::PACKET_INPUT_FEATURE)
            {
                return Err(ProviderError::Correlation(
                    "packet source extensions unsupported",
                ));
            }
            super::super::input::PacketInputContext::decode(&envelope.extensions)?;
        } else if self.connected.is_some()
            && envelope.message == MessageKind::Request
            && envelope.method == Method::Input
        {
            return Err(ProviderError::Correlation(
                "packet source original input context absent",
            ));
        }
        if envelope.body.get("extensions").is_some_and(|extensions| {
            extensions
                .as_object()
                .is_none_or(|values| !values.is_empty())
        }) {
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

pub(super) struct Verifier<'a>(pub(super) &'a ServerLaunch);
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
        selected_features: &IdSet,
        schemas: &[SchemaRef],
        guarantees: &ContentRef,
    ) -> Result<(), ProviderError> {
        let expected = features(self.0.schema_version)?;
        if manifest != &self.0.selection.provider
            || selected_features != &expected
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

pub(super) fn features(edition: u16) -> Result<Vec<Id>, ProviderError> {
    let mut features = vec![Id::new("cnp.control-evidence/1")?, Id::new("cnp.core/1")?];
    if edition == 4 {
        features.push(Id::new(super::super::input::PACKET_INPUT_FEATURE)?);
    }
    Ok(features)
}

pub(super) fn extensions(edition: u16) -> Result<BTreeMap<String, Id>, ProviderError> {
    if edition == 4 {
        let feature = super::super::input::PACKET_INPUT_FEATURE;
        Ok(BTreeMap::from([(feature.into(), Id::new(feature)?)]))
    } else {
        Ok(BTreeMap::new())
    }
}

// Only a successful service context borrows these banks, after authenticating
// its original boot/thread. Any retained quarantine makes whole capture refuse.
pub(super) struct OriginalNativeSupervisorOwned11<'a> {
    creator: u32,
    thread: std::thread::ThreadId,
    incidents: std::cell::Ref<'a, Vec<ConnectionIncident>>,
    blobs: std::cell::Ref<'a, Vec<BlobQuarantine>>,
}

impl Supervisor {
    pub(super) fn borrow_empty_owned11(
        &self,
    ) -> Result<OriginalNativeSupervisorOwned11<'_>, ProviderError> {
        let Self { incidents, blobs } = self;
        let incidents = incidents
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("native whole11 incidents borrowed"))?;
        let blobs = blobs
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("native whole11 blob quarantine borrowed"))?;
        if !incidents.is_empty() || !blobs.is_empty() {
            return Err(ProviderError::Correlation(
                "native whole11 supervisor unresolved",
            ));
        }
        Ok(OriginalNativeSupervisorOwned11 {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            incidents,
            blobs,
        })
    }
}

impl OriginalNativeSupervisorOwned11<'_> {
    fn ensure_origin(&self) -> Result<(), ProviderError> {
        if self.creator != std::process::id() || self.thread != std::thread::current().id() {
            return Err(ProviderError::Correlation(
                "native whole11 supervisor loan foreign origin",
            ));
        }
        Ok(())
    }

    pub(super) fn observe_owned11_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        observer.vector::<ConnectionIncident>(self.incidents.capacity())?;
        observer.vector::<BlobQuarantine>(self.blobs.capacity())
    }
}

impl serde::Serialize for OriginalNativeSupervisorOwned11<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.ensure_origin().map_err(serde::ser::Error::custom)?;
        serde::Serialize::serialize(
            &(
                "source-private.native-empty-supervisor/11",
                (
                    self.incidents.capacity(),
                    std::mem::size_of::<ConnectionIncident>(),
                ),
                (self.blobs.capacity(), std::mem::size_of::<BlobQuarantine>()),
            ),
            serializer,
        )
    }
}

// These typed empty banks preserve historical allocation shape only. They do
// not implement either quarantine trait and cannot become a live Supervisor.
pub(crate) struct HistoricalNativeSupervisorBanks {
    incidents: Vec<ConnectionIncident>,
    blobs: Vec<BlobQuarantine>,
}

impl HistoricalNativeSupervisorBanks {
    pub(crate) fn reconstruct_empty_into(
        completed: &mut Option<Self>,
        incident_capacity: usize,
        blob_capacity: usize,
        admitted_bank_bytes: usize,
    ) -> Result<(), ProviderError> {
        if completed.is_some() {
            return Err(ProviderError::Conflict(
                "historical supervisor bank slot occupied",
            ));
        }
        let bytes = incident_capacity
            .checked_mul(std::mem::size_of::<ConnectionIncident>())
            .and_then(|incidents| {
                blob_capacity
                    .checked_mul(std::mem::size_of::<BlobQuarantine>())
                    .and_then(|blobs| incidents.checked_add(blobs))
            })
            .filter(|bytes| *bytes <= admitted_bank_bytes)
            .ok_or(ProviderError::ResourceExhausted(
                "historical supervisor typed bank credit",
            ))?;
        *completed = Some(Self {
            incidents: Vec::new(),
            blobs: Vec::new(),
        });
        let original = completed.as_mut().ok_or(ProviderError::Conflict(
            "historical supervisor bank slot absent",
        ))?;
        original
            .incidents
            .try_reserve_exact(incident_capacity)
            .map_err(|_| ProviderError::ResourceExhausted("historical incident bank allocation"))?;
        original
            .blobs
            .try_reserve_exact(blob_capacity)
            .map_err(|_| {
                ProviderError::ResourceExhausted("historical blob quarantine allocation")
            })?;
        if original.incidents.capacity() != incident_capacity
            || original.blobs.capacity() != blob_capacity
        {
            return Err(ProviderError::ResourceExhausted(
                "historical supervisor actual capacity differs",
            ));
        }
        let actual = original.incidents.capacity() * std::mem::size_of::<ConnectionIncident>()
            + original.blobs.capacity() * std::mem::size_of::<BlobQuarantine>();
        if actual != bytes {
            return Err(ProviderError::ResourceExhausted(
                "historical supervisor actual extent differs",
            ));
        }
        Ok(())
    }

    pub(crate) fn capacity_rows(&self) -> (usize, usize) {
        (self.incidents.capacity(), self.blobs.capacity())
    }
}

pub(crate) const fn original_native_supervisor_layout() -> usize {
    std::mem::size_of::<Supervisor>()
}

pub(crate) const fn original_native_supervisor_bank_layouts() -> (usize, usize) {
    (
        std::mem::size_of::<ConnectionIncident>(),
        std::mem::size_of::<BlobQuarantine>(),
    )
}

impl HistoricalNativeSupervisorBanks {
    pub(crate) fn observe_historical_retained_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self { incidents, blobs } = self;
        if !incidents.is_empty() || !blobs.is_empty() {
            return Err(ProviderError::Correlation(
                "historical empty supervisor bank changed",
            ));
        }
        observer.vector::<ConnectionIncident>(incidents.capacity())?;
        observer.vector::<BlobQuarantine>(blobs.capacity())
    }
}

mod settled;

pub(in crate::reference_packet::service) use settled::NativeSupervisorHistory;

/// Reports the actual retained native supervisor payload alignment.
pub(crate) const fn original_native_supervisor_alignment17_data() -> usize {
    std::mem::align_of::<Supervisor>()
}

mod settled17_reader;
pub(crate) use settled17_reader::{
    HistoricalNativeSupervisor17, read_current_native17_supervisor_root_data,
};

pub(crate) mod current17;
