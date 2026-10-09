//! Actual child, verified content pins, and bounded persistent native supervision.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::rc::Rc;

use crucible_node_contract::*;
use serde::{Deserialize, Serialize};

use crate::ProviderError;
use crate::blob::{
    BlobLimits, BlobQuarantine, BlobReceiver, BlobSupervisor, OperationContentPin, VerifiedTransfer,
};
use crate::connection::{ConnectionIncident, ConnectionSupervisor};
use crate::native_journal::{NativeCustody, NativeJournalSupervisor, NativeSupervision};
use crate::reference_device::{DeviceGrant, DeviceReceipt, ReferenceDevice};

use super::bootstrap::ReferenceServiceBootstrap;
use super::profile::ReferenceProfile;

pub(super) const MAX_SUPERVISION: usize = 64;

/// Acknowledges exact retained controller-origin terminal response bytes.
///
/// Only an authenticated admitted controller can submit this object. It retires
/// request outcomes, while operation, input, native output and content custody
/// continue until their independently verified disposition.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestConsumption {
    /// Selects the closed reference request-consumption schema.
    pub schema: String,
    /// Names the admitted session.
    pub session_id: Id,
    /// Names the surviving provider incarnation.
    pub incarnation_id: Id,
    /// Lists exact retained outcomes in request-ID order.
    pub requests: Vec<ConsumedRequest>,
    /// Carries explicit supported receipt extensions.
    pub extensions: Extensions,
}

/// Binds one original controller request to its complete terminal response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumedRequest {
    /// Names the original controller-generated request.
    pub request_id: Id,
    /// Commits to all original request material and scope.
    pub request_hash: HashRef,
    /// Commits to exact canonical terminal response-body bytes.
    pub outcome: ContentRef,
}

impl Validate for RequestConsumption {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema != "reference-device/request-consumption-v1"
            || !self.extensions.is_empty()
            || self.requests.is_empty()
            || self.requests.len() > 4096
            || self
                .requests
                .windows(2)
                .any(|pair| pair[0].request_id >= pair[1].request_id)
        {
            return Err(crate::bodies::invalid(
                "consumption",
                "invalid complete original request custody",
            ));
        }
        for request in &self.requests {
            request.request_hash.validate()?;
            request.outcome.validate()?;
            if request.request_hash.domain != "cnp.request.v1" {
                return Err(crate::bodies::invalid(
                    "request_hash",
                    "foreign request identity",
                ));
            }
        }
        Ok(())
    }
}

/// Binds an authenticated host publication acknowledgment to original output custody.
///
/// The service accepts this receipt only from its actual admitted controller,
/// after output bytes were transferred and while the matching native window and
/// stop receipt remain retained. Its schema fields alone authorize no release.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationConsumption {
    /// Selects the versioned reference publication-consumption schema.
    pub schema: String,
    /// Names the admitted world session.
    pub session_id: Id,
    /// Names the actual surviving provider.
    pub incarnation_id: Id,
    /// Names the original completed quantized operation.
    pub operation_id: Id,
    /// Names the original device grant.
    pub grant_id: Id,
    /// Commits to the privately admitted world.
    pub world_binding_hash: HashRef,
    /// Commits to the complete original staged observation batch.
    pub observation_batch_hash: HashRef,
    /// Binds original complete output and stop evidence.
    pub stop_receipt: ContentRef,
    /// Locates the fixed output publication boundary.
    pub publication: Position,
    /// Carries explicit versioned receipt extensions.
    pub extensions: Extensions,
}

impl Validate for PublicationConsumption {
    fn validate(&self) -> Result<(), ContractError> {
        self.world_binding_hash.validate()?;
        self.observation_batch_hash.validate()?;
        self.stop_receipt.validate()?;
        self.publication.validate()?;
        if self.schema != "reference-device/publication-consumption-v1"
            || !self.extensions.is_empty()
            || self.world_binding_hash.domain != "cnp.world-binding.v1"
            || self.observation_batch_hash.domain != "cnp.observation-batch.v1"
            || self.publication.microstep.get() != 0
            || self.publication.phase != Phase::Publication
        {
            return Err(crate::bodies::invalid(
                "consumption",
                "foreign reference publication scope",
            ));
        }
        Ok(())
    }
}

pub(super) struct Window {
    pub(super) operation: Id,
    pub(super) grant: DeviceGrant,
    pub(super) native: DeviceReceipt,
    pub(super) stop: ContentRef,
    pub(super) observation: ObservationBatch,
    pub(super) observation_ref: ContentRef,
    pub(super) pending: ContentRef,
    pub(super) measurement: ContentRef,
    pub(super) closed: bool,
    pub(super) committed_ref: Option<ContentRef>,
    pub(super) publication_acknowledged: bool,
}

pub(super) struct Resources {
    pub(super) bootstrap: ReferenceServiceBootstrap,
    pub(super) profile: ReferenceProfile,
    pub(super) child_path: PathBuf,
    pub(super) socket_parent: PathBuf,
    pub(super) child: Option<ReferenceDevice>,
    pub(super) binding: NodeBinding,
    pub(super) owner_binding: OwnerBinding,
    pub(super) realized: bool,
    pub(super) admitted: bool,
    pub(super) staged: bool,
    pub(super) active: bool,
    pub(super) gate_receipt: Option<ContentRef>,
    pub(super) ready_receipt: Option<ContentRef>,
    pub(super) contents: BTreeMap<String, (ContentRef, Vec<u8>)>,
    pub(super) content_bytes: usize,
    pub(super) blobs: BlobReceiver,
    pub(super) verified: BTreeMap<String, VerifiedTransfer>,
    pub(super) pins: Vec<OperationContentPin>,
    pub(super) input: Option<InputBatch>,
    pub(super) input_bytes: Vec<u8>,
    pub(super) input_custody: Option<ContentRef>,
    pub(super) next_quantum: U64,
    pub(super) next_observation: U64,
    pub(super) window: Option<Window>,
    pub(super) transferred: RefCell<BTreeSet<String>>,
    pub(super) consumed: BTreeSet<String>,
}

impl Resources {
    pub(super) fn content(&self, reference: &ContentRef) -> Result<&[u8], ProviderError> {
        let (installed, bytes) =
            self.contents
                .get(&reference.hash.digest)
                .ok_or(ProviderError::Correlation(
                    "content is not in local native custody",
                ))?;
        if installed != reference {
            return Err(ProviderError::Conflict(
                "content reference changed metadata",
            ));
        }
        reference.verify(bytes)?;
        Ok(bytes)
    }

    pub(super) fn store(
        &mut self,
        bytes: Vec<u8>,
        media_type: &str,
    ) -> Result<ContentRef, ProviderError> {
        let reference = canonical::content_ref(&bytes, media_type)?;
        if let Some((original, original_bytes)) = self.contents.get(&reference.hash.digest) {
            if original != &reference || original_bytes != &bytes {
                return Err(ProviderError::Conflict("content identity changed"));
            }
            return Ok(reference);
        }
        let total = self
            .content_bytes
            .checked_add(bytes.len())
            .ok_or(ProviderError::ResourceExhausted("reference content bytes"))?;
        if total as u64 > self.bootstrap.resource_limits.content_bytes.get()
            || self.contents.len() >= 4096
        {
            return Err(ProviderError::ResourceExhausted(
                "reference content custody",
            ));
        }
        self.contents
            .insert(reference.hash.digest.clone(), (reference.clone(), bytes));
        self.content_bytes = total;
        Ok(reference)
    }

    pub(super) fn store_json(
        &mut self,
        value: impl Serialize,
    ) -> Result<ContentRef, ProviderError> {
        let value = serde_json::to_value(value).map_err(ContractError::from)?;
        self.store(canonical::canonical_json(&value)?, "application/json")
    }

    pub(super) fn resolve<T: serde::de::DeserializeOwned + Validate>(
        &self,
        reference: &ContentRef,
    ) -> Result<T, ProviderError> {
        Ok(canonical::decode(
            self.content(reference)?,
            16 * 1024 * 1024,
        )?)
    }
}

struct Supervised {
    native: Vec<Option<NativeCustody<Resources>>>,
    reserved: Vec<bool>,
    blobs: Vec<BlobQuarantine>,
    connections: Vec<ConnectionIncident>,
}

thread_local! {
    // Strong thread-lifetime custody survives every service/connection borrower.
    // Metadata and actual handles stay finite; slot exhaustion refuses admission.
    static SUPERVISED: Rc<RefCell<Supervised>> = Rc::new(RefCell::new(Supervised {
        native:(0..MAX_SUPERVISION).map(|_|None).collect(), reserved:vec![false;MAX_SUPERVISION],
        blobs:Vec::new(), connections:Vec::new(),
    }));
}

#[derive(Clone)]
pub(super) struct Supervisor(Rc<RefCell<Supervised>>);

impl Supervisor {
    pub(super) fn new() -> Self {
        SUPERVISED.with(|state| Self(Rc::clone(state)))
    }
    pub(super) fn blob_limits(
        bootstrap: &ReferenceServiceBootstrap,
    ) -> Result<BlobLimits, ProviderError> {
        let bytes = usize::try_from(bootstrap.resource_limits.content_bytes.get())
            .map_err(|_| ProviderError::ResourceExhausted("native content allowance"))?;
        let count = usize::try_from(bootstrap.limits.journal_entries.get())
            .map_err(|_| ProviderError::ResourceExhausted("native transfer allowance"))?;
        Ok(BlobLimits {
            reserved_bytes: bytes,
            content_bytes: bytes,
            chunk_bytes: usize::try_from(bootstrap.limits.blob_chunk_bytes.get())
                .map_err(|_| ProviderError::ResourceExhausted("native chunk allowance"))?,
            transfers_per_origin: count,
            tombstones_per_origin: count,
            chunks_per_transfer: 4096,
            operation_pins: 4096,
        })
    }
}

struct Slot {
    state: Rc<RefCell<Supervised>>,
    index: usize,
    retained: bool,
}

impl NativeJournalSupervisor<Resources> for Supervisor {
    fn reserve(&self) -> Result<Box<dyn NativeSupervision<Resources>>, ProviderError> {
        let mut state = self
            .0
            .try_borrow_mut()
            .map_err(|_| ProviderError::Correlation("native supervision already borrowed"))?;
        let index = state
            .reserved
            .iter()
            .position(|occupied| !occupied)
            .ok_or(ProviderError::ResourceExhausted("native supervision slots"))?;
        state.reserved[index] = true;
        Ok(Box::new(Slot {
            state: Rc::clone(&self.0),
            index,
            retained: false,
        }))
    }
}

impl NativeSupervision<Resources> for Slot {
    fn retain(&mut self, custody: NativeCustody<Resources>) {
        // The slot is preallocated, owned uniquely, and inaccessible to wire
        // values. A violated native invariant cannot resume normal execution.
        let Ok(mut state) = self.state.try_borrow_mut() else {
            std::process::abort();
        };
        if state.native[self.index].is_some() {
            std::process::abort();
        }
        state.native[self.index] = Some(custody);
        self.retained = true;
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        if !self.retained
            && let Ok(mut state) = self.state.try_borrow_mut()
        {
            state.reserved[self.index] = false;
        }
    }
}

impl BlobSupervisor for Supervisor {
    fn quarantine(&self, custody: BlobQuarantine) {
        let Ok(mut state) = self.0.try_borrow_mut() else {
            std::process::abort();
        };
        if state.blobs.len() >= MAX_SUPERVISION {
            std::process::abort();
        }
        state.blobs.push(custody);
    }
}

impl ConnectionSupervisor for Supervisor {
    fn quarantine(&self, incident: ConnectionIncident) {
        let Ok(mut state) = self.0.try_borrow_mut() else {
            std::process::abort();
        };
        if state.connections.len() >= 4096 {
            std::process::abort();
        }
        state.connections.push(incident);
    }
}
