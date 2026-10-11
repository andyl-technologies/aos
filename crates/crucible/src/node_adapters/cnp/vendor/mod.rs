//! Implementation-neutral CNP nodes beneath independently installed source policy.
//!
//! Baseline envelopes and closed method bodies are checked before transmission.
//! Actual native semantics are authenticated by the exact installed vendor codec,
//! never inferred from provider response shape. Every operation keeps its original
//! opaque admission and complete raw journal through cancellation and containment.

mod capture;
mod custody;
mod facets;
mod protocol;
mod runtime;
mod scope;

pub use capture::VendorNativeCapture;
pub use custody::{VendorCnpCustodyQueue, VendorCnpCustodySlot};
pub use protocol::*;
pub use runtime::VendorCnpNode;

use std::{collections::BTreeMap, io::Write, rc::Rc};

use crucible_node_contract::Id;
use crucible_node_provider::{
    bodies::{decode_request, decode_response},
    envelope::{Envelope, MessageKind, Method},
};
use rustix::process::{Pid, getpgid};
use serde::Serialize;

use crate::node_contract::{
    ActivationRecord, EffectKnowledge, OperationAdmission, OperationFailure, OperationOutcome,
    ReadyAttestation,
};

struct OriginalInput {
    batch: Rc<crate::node_scheduling::RuntimeInputBatch>,
    acknowledgement: Option<crate::node_scheduling::NativeInputAcknowledgement>,
}

struct OriginalOperation {
    original: Rc<OperationAdmission>,
    outcome: Option<OperationOutcome>,
    outcome_validated: bool,
    failure: Option<OperationFailure>,
    close_attempted: bool,
    acknowledged: bool,
    cancellation: Option<crate::node_contract::CancelStatus>,
}

/// Owns every original resource and ledger across node drop or uncertain cleanup.
///
/// This capsule exposes no runtime mutation permission. A supervisor retains it
/// until independent native reclamation validates the whole original owner group.
pub struct VendorCnpCustody {
    peer: VendorCnpPeer,
    cleanup: Rc<dyn InstalledVendorPeerCleanup>,
    host_release: Option<crucible_node_contract::ContentRef>,
    identity: Option<VendorCnpIdentity>,
    codec: Option<protocol::VendorCodec>,
    facets: Vec<VendorCnpFacet>,
    operations: BTreeMap<Id, OriginalOperation>,
    inputs: BTreeMap<Id, OriginalInput>,
    uncertain: bool,
    adopted: bool,
    containment_error: Option<OperationFailure>,
    capture: Option<VendorNativeCapture>,
    reclamation: Vec<crate::node_contract::NativeReclamationReceipt>,
    prepared: Option<(
        ActivationRecord,
        ReadyAttestation,
        Vec<crucible_node_contract::PreparedOwner>,
    )>,
    active: Option<crate::node_contract::WorldActivation>,
    limits: VendorCnpLimits,
    metadata_used: usize,
    next_request: u64,
    quarantined: bool,
}

impl VendorCnpCustody {
    /// Borrows complete original process, transport, raw journals and byte custody.
    pub fn peer(&self) -> &VendorCnpPeer {
        &self.peer
    }

    /// Borrows exact prepared identity, absent only before metadata authentication.
    pub fn identity(&self) -> Option<&VendorCnpIdentity> {
        self.identity.as_ref()
    }

    /// Borrows the independently installed prebirth native cleanup owner.
    pub fn cleanup_owner(&self) -> &dyn InstalledVendorPeerCleanup {
        self.cleanup.as_ref()
    }

    /// Counts retained original operation obligations without inferring completion.
    pub fn original_operations(&self) -> usize {
        self.operations.len()
    }

    /// Observes whether native containment has been requested, not whether it succeeded.
    pub fn is_quarantined(&self) -> bool {
        self.quarantined
    }

    fn identity_and_codec(
        &self,
    ) -> Result<(&VendorCnpIdentity, &dyn InstalledVendorCnpCodec), OperationFailure> {
        match (&self.identity, &self.codec) {
            (Some(identity), Some(codec)) => Ok((identity, codec.as_ref())),
            _ => Err(refused("vendor source codec is not installed")),
        }
    }

    fn current(&self) -> Result<(), OperationFailure> {
        let (identity, codec) = self.identity_and_codec()?;
        self.peer
            .session
            .authority()
            .ensure_live()
            .map_err(protocol::native)?;
        let result = (|| {
            codec.authenticate_current(identity, &self.peer)?;
            let revision = codec.current_source_revision(identity, &self.peer)?;
            let binding = identity
                .binding
                .compatibility
                .identity()
                .map_err(contract)?;
            // Actual session and sealed revision reads follow every codec
            // callback. Neither terminal check invokes provider code.
            self.peer
                .session
                .authority()
                .ensure_live()
                .map_err(protocol::native)?;
            revision
                .authenticate_node(&identity.profile, &binding)
                .map_err(|error| refused(&error.message))
        })();
        result.map_err(|error| {
            if self.uncertain {
                unknown(&error.reason)
            } else {
                error
            }
        })
    }

    fn exchange(
        &mut self,
        action: VendorCnpAction<'_>,
    ) -> Result<VendorCnpEvidence, OperationFailure> {
        if self.quarantined || self.uncertain {
            return Err(unknown("vendor original has an unresolved exchange"));
        }
        self.current()?;
        let next = self
            .next_request
            .checked_add(1)
            .ok_or_else(|| refused("vendor request identities exhausted"))?;
        let request_id =
            Id::new(format!("vendor-control-{}", self.next_request)).map_err(contract)?;
        self.next_request = next;
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| refused("vendor identity absent"))?;
        let codec = self
            .codec
            .as_ref()
            .ok_or_else(|| refused("vendor codec absent"))?;
        let request = codec.request(
            identity,
            action.borrowed(),
            &request_id,
            self.limits.metadata_bytes,
        )?;
        validate_request_scope(identity, &self.peer, &action, &request_id, &request)?;
        let bytes = encoded_size(&request, self.limits.metadata_bytes)?;
        codec.validate_request(identity, action.borrowed(), &request, &self.peer)?;
        self.metadata_used = self
            .metadata_used
            .checked_add(bytes)
            .filter(|used| *used <= self.limits.metadata_bytes)
            .ok_or_else(|| refused("vendor original aggregate metadata credit exhausted"))?;
        self.current()?;
        // ClientSession owns the original request before its first write and
        // stores raw response/content before the semantic callback below.
        // Latch before the first transport effect. An error or unwind keeps the
        // same raw journal and permanently prohibits a replacement request.
        self.uncertain = true;
        let response = self
            .peer
            .session
            .exchange(
                &mut self.peer.journal,
                request.clone(),
                self.limits.exchange_timeout,
            )
            .map_err(protocol::native)?;
        let request_body =
            decode_request(request.method, &request.body).map_err(protocol::native)?;
        let decoded = decode_response(&request_body, &response.body).map_err(protocol::native)?;
        let (identity, codec) = self.identity_and_codec()?;
        let evidence = codec
            .response(VendorCnpResponse {
                identity,
                action: action.borrowed(),
                request: &request,
                response: &response,
                decoded: &decoded,
                peer: &self.peer,
                maximum_bytes: self
                    .limits
                    .metadata_bytes
                    .saturating_sub(self.metadata_used),
            })
            .map_err(|error| unknown(&error.reason))?;
        if !evidence_matches(&action, &evidence) {
            return Err(unknown(
                "vendor response changed the requested semantic role",
            ));
        }
        self.current()?;
        self.uncertain = false;
        Ok(evidence)
    }
}

impl VendorCnpAction<'_> {
    fn borrowed(&self) -> VendorCnpAction<'_> {
        match self {
            Self::Status => Self::Status,
            Self::Arm(world) => Self::Arm(world),
            Self::Activate(world) => Self::Activate(world),
            Self::Input(batch) => Self::Input(batch),
            Self::Begin(original) => Self::Begin(original),
            Self::Poll(original) => Self::Poll(original),
            Self::Cancel(original) => Self::Cancel(original),
            Self::Close(original) => Self::Close(original),
            Self::Acknowledge(original, outputs) => Self::Acknowledge(original, outputs),
            Self::Scheduling(world) => Self::Scheduling(world),
        }
    }

    fn method(&self) -> Method {
        match self {
            Self::Status | Self::Scheduling(_) => Method::Observe,
            Self::Arm(_) => Method::Activate,
            Self::Activate(_) => Method::WorldActivate,
            Self::Input(_) => Method::Input,
            Self::Begin(_) => Method::Begin,
            Self::Poll(_) => Method::Poll,
            Self::Cancel(_) => Method::Cancel,
            Self::Close(_) => Method::QuantumClose,
            Self::Acknowledge(_, _) => Method::Retire,
        }
    }

    fn original(&self) -> Option<&OperationAdmission> {
        match self {
            Self::Begin(original)
            | Self::Poll(original)
            | Self::Cancel(original)
            | Self::Close(original)
            | Self::Acknowledge(original, _) => Some(original),
            _ => None,
        }
    }
}

/// Retains the original actual launch below its already reserved supervision slot.
pub struct VendorCnpLaunchGuard {
    custody: Option<Box<VendorCnpCustody>>,
    slot: Option<VendorCnpCustodySlot>,
}

impl VendorCnpLaunchGuard {
    /// Takes original native and transport custody before validating launch facts.
    ///
    /// The caller reserves the slot before spawning and creates a private native
    /// process group. All constructor failures return the same complete guard.
    ///
    /// # Errors
    /// Refuses foreign peer PID, private directory, process group or limits.
    ///
    /// # Panics
    /// An installed inspector may unwind. The complete original guard transfers
    /// to its preowned supervisor; unwinding never establishes native release.
    pub fn new(
        child: std::process::Child,
        directory: std::path::PathBuf,
        session: crucible_node_provider::client::ClientSession,
        journal: crucible_node_provider::client::ClientCustody,
        custody_slot: VendorCnpCustodySlot,
        limits: VendorCnpLimits,
    ) -> Result<Self, VendorCnpFailure> {
        let guard = Self {
            custody: Some(Box::new(VendorCnpCustody {
                peer: VendorCnpPeer {
                    child,
                    directory,
                    session,
                    journal,
                    reaped: None,
                },
                cleanup: Rc::clone(&custody_slot.cleanup),
                host_release: None,
                identity: None,
                codec: None,
                facets: Vec::new(),
                operations: BTreeMap::new(),
                inputs: BTreeMap::new(),
                uncertain: false,
                adopted: false,
                containment_error: None,
                capture: None,
                reclamation: Vec::new(),
                prepared: None,
                active: None,
                limits,
                metadata_used: 0,
                next_request: 1,
                quarantined: false,
            })),
            slot: Some(custody_slot),
        };
        let result = (|| {
            validate_limits(limits)?;
            let custody = guard
                .custody
                .as_ref()
                .ok_or_else(|| refused("original vendor custody absent"))?;
            if !custody.peer.directory.is_absolute()
                || custody.peer.session.peer_pid() != custody.peer.child.id()
            {
                return Err(refused(
                    "vendor native launch differs from its authenticated peer",
                ));
            }
            custody.cleanup.authenticate_original(&custody.peer)?;
            let (journal, content) = custody.peer.journal.byte_reservations();
            if journal
                .checked_add(content)
                .is_none_or(|bytes| bytes > limits.transport_bytes)
            {
                return Err(refused("vendor raw transport exceeds original reservation"));
            }
            let pid = i32::try_from(custody.peer.child.id())
                .ok()
                .and_then(Pid::from_raw)
                .ok_or_else(|| refused("invalid original vendor PID"))?;
            if getpgid(Some(pid)).map_err(|error| unknown(&error.to_string()))? != pid {
                return Err(refused(
                    "vendor launch lacks an original private process group",
                ));
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(guard),
            Err(error) => Err(VendorCnpFailure {
                error: unknown(&error.reason),
                guard,
            }),
        }
    }

    /// Borrows complete original custody without transferring its wait ownership.
    pub fn custody(&self) -> Option<&VendorCnpCustody> {
        self.custody.as_deref()
    }
}

impl Drop for VendorCnpLaunchGuard {
    fn drop(&mut self) {
        if let (Some(custody), Some(slot)) = (self.custody.take(), self.slot.take()) {
            slot.retain(custody);
        }
    }
}

fn validate_limits(limits: VendorCnpLimits) -> Result<(), OperationFailure> {
    let maximum = VendorCnpLimits::default();
    if limits.operations == 0
        || limits.operations > maximum.operations
        || limits.outputs == 0
        || limits.outputs > maximum.outputs
        || limits.metadata_bytes == 0
        || limits.metadata_bytes > maximum.metadata_bytes
        || limits.transport_bytes == 0
        || limits.transport_bytes > maximum.transport_bytes
        || limits.exchange_timeout.is_zero()
        || limits.exchange_timeout > maximum.exchange_timeout
    {
        return Err(refused("invalid vendor CNP original resource ceilings"));
    }
    Ok(())
}

fn validate_request_scope(
    identity: &VendorCnpIdentity,
    peer: &VendorCnpPeer,
    action: &VendorCnpAction<'_>,
    request_id: &Id,
    request: &Envelope,
) -> Result<(), OperationFailure> {
    request.validate().map_err(contract)?;
    if request.message != MessageKind::Request
        || request.method != action.method()
        || request.request_id.0.as_ref() != Some(request_id)
        || request.session_id.0.as_ref() != Some(peer.session.authority().session_id())
        || request.incarnation_id.0.as_ref() != Some(peer.session.authority().incarnation_id())
        || request.node_id.0.as_ref() != Some(&identity.descriptor.id)
        || request.execution_owner_id.0.as_ref()
            != Some(&identity.binding.compatibility.execution_owner.id)
        || request.capture_owner_id.0.as_ref()
            != Some(&identity.binding.compatibility.capture_owner.id)
        || request.operation_id.0.as_ref()
            != action
                .original()
                .map(|original| original.token().operation())
    {
        return Err(refused(
            "vendor request changed original CNP method or complete owner scope",
        ));
    }
    let body = decode_request(request.method, &request.body).map_err(contract)?;
    scope::validate_original(identity, action, &body)?;
    Ok(())
}

pub(super) fn encoded_size(
    value: &(impl Serialize + ?Sized),
    maximum: usize,
) -> Result<usize, OperationFailure> {
    struct Counter {
        maximum: usize,
        used: usize,
    }
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.used = self
                .used
                .checked_add(bytes.len())
                .filter(|used| *used <= self.maximum)
                .ok_or_else(|| std::io::Error::other("vendor metadata credit exhausted"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Counter { maximum, used: 0 };
    serde_json::to_writer(&mut count, value).map_err(|error| refused(&error.to_string()))?;
    Ok(count.used)
}

pub(super) fn refused(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: reason.into(),
    }
}

pub(super) fn unknown(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::Unknown,
        reason: reason.into(),
    }
}

fn contract(error: impl std::fmt::Display) -> OperationFailure {
    refused(&error.to_string())
}

fn evidence_matches(action: &VendorCnpAction<'_>, evidence: &VendorCnpEvidence) -> bool {
    matches!(
        (action, evidence),
        (VendorCnpAction::Status, VendorCnpEvidence::Status(_))
            | (VendorCnpAction::Arm(_), VendorCnpEvidence::Readiness(_, _))
            | (
                VendorCnpAction::Activate(_),
                VendorCnpEvidence::Acknowledged
            )
            | (VendorCnpAction::Input(_), VendorCnpEvidence::Input(_))
            | (
                VendorCnpAction::Begin(_) | VendorCnpAction::Poll(_) | VendorCnpAction::Close(_),
                VendorCnpEvidence::Pending | VendorCnpEvidence::Outcome(_)
            )
            | (
                VendorCnpAction::Cancel(_),
                VendorCnpEvidence::Cancellation(_)
            )
            | (
                VendorCnpAction::Acknowledge(_, _),
                VendorCnpEvidence::Acknowledged
            )
            | (
                VendorCnpAction::Scheduling(_),
                VendorCnpEvidence::Scheduling(_)
            )
    )
}

fn activation_credit(record: &ActivationRecord, maximum: usize) -> Result<usize, OperationFailure> {
    #[derive(Serialize)]
    struct BorrowedActivation<'a> {
        generation: crucible_node_contract::U64,
        activation_id: &'a Id,
        world_binding_hash: &'a crucible_node_contract::HashRef,
        owners: &'a [crate::node_contract::OwnerIdentity],
        boundary: crucible_node_contract::Position,
    }
    encoded_size(
        &BorrowedActivation {
            generation: record.generation,
            activation_id: &record.activation_id,
            world_binding_hash: &record.world_binding_hash,
            owners: &record.owners,
            boundary: record.boundary,
        },
        maximum,
    )
}
