//! Original CNP peer custody and independently installed vendor semantic codecs.

use std::{
    path::PathBuf,
    process::{Child, ExitStatus},
    rc::Rc,
    task::{Context, Poll},
    time::Duration,
};

use crucible_node_contract::{ContentRef, Id, NodeBinding, NodeDescriptor, PreparedOwner};
use crucible_node_provider::{
    ProviderError,
    bodies::ResponseBody,
    client::{ClientCustody, ClientSession},
    envelope::Envelope,
};

use crate::{
    node_contract::{
        ActivationRecord, CancelStatus, FacetKind, NativeReclamationReceipt, NodeRoute, NodeStatus,
        OperationAdmission, OperationFailure, OperationOutcome, OwnerIdentity, ReadyAttestation,
        WorldActivation,
    },
    node_scheduling::{
        InputPayload, NativeInputAcknowledgement, NativeSchedulingObservation, RuntimeInputBatch,
    },
};

/// Bounds original metadata, exchanges and native operation custody.
#[derive(Clone, Copy, Debug)]
pub struct VendorCnpLimits {
    /// Maximum retained original operations; never recycled by transport polling.
    pub operations: usize,
    /// Maximum complete original outcome publications.
    pub outputs: usize,
    /// Maximum codec request/reply and original evidence metadata bytes.
    pub metadata_bytes: usize,
    /// Aggregate raw journal and immutable content reservation, separate from decoded metadata.
    pub transport_bytes: usize,
    /// Finite hardware exchange deadline, never modeled simulation time.
    pub exchange_timeout: Duration,
}

impl Default for VendorCnpLimits {
    fn default() -> Self {
        Self {
            operations: 256,
            outputs: 4096,
            metadata_bytes: 16 * 1024 * 1024,
            transport_bytes: 32 * 1024 * 1024,
            exchange_timeout: Duration::from_secs(60),
        }
    }
}

/// Retains actual original native handles and their bounded transport journal.
///
/// No public field or method extracts the Child or replaces its session. Native
/// cleanup must authenticate the same retained wait result and complete group.
pub struct VendorCnpPeer {
    pub(super) child: Child,
    pub(super) directory: PathBuf,
    pub(super) session: ClientSession,
    pub(super) journal: ClientCustody,
    pub(super) reaped: Option<ExitStatus>,
}

impl VendorCnpPeer {
    /// Borrows the original child for independent native/source inspection.
    pub fn child(&self) -> &Child {
        &self.child
    }

    /// Borrows the original privately installed working directory.
    pub fn directory(&self) -> &std::path::Path {
        &self.directory
    }

    /// Borrows the original authenticated session and launch measurements.
    pub fn session(&self) -> &ClientSession {
        &self.session
    }

    /// Borrows complete original requests, responses and authenticated byte custody.
    pub fn journal(&self) -> &ClientCustody {
        &self.journal
    }

    /// Borrows an actual kernel child-wait outcome; missing remains unknown.
    pub fn wait_result(&self) -> Option<&ExitStatus> {
        self.reaped.as_ref()
    }
}

/// Owns independent native cleanup before a provider process is born.
///
/// This authority is installed host configuration, retained by the reserved
/// queue slot before Child allocation. It never derives release from remote
/// fields or socket closure. Validation must establish the complete original
/// process group, descriptors and private resource reclamation using authentic
/// native birth/wait evidence, including when metadata/codec adoption fails.
pub trait InstalledVendorPeerCleanup {
    /// Authenticates actual original native birth and private resource ownership.
    ///
    /// # Errors
    /// Refuses unknown or foreign original native process/resource custody.
    fn authenticate_original(&self, peer: &VendorCnpPeer) -> Result<(), OperationFailure>;

    /// Requests once-only containment of that same entire original native group.
    ///
    /// # Errors
    /// Reports unresolved containment while keeping every original handle owned.
    fn request_containment(&self, peer: &mut VendorCnpPeer) -> Result<(), OperationFailure>;

    /// Polls authentic complete original group/resource release after kernel wait.
    fn poll_release(
        &self,
        peer: &VendorCnpPeer,
        context: &mut Context<'_>,
    ) -> Poll<Result<ContentRef, OperationFailure>>;

    /// Reauthenticates the retained actual release proof and original native birth.
    ///
    /// # Errors
    /// Refuses absent or foreign complete native release, including PID reuse.
    fn validate_release(
        &self,
        peer: &VendorCnpPeer,
        receipt: &ContentRef,
    ) -> Result<(), OperationFailure>;
}

/// Binds exact immutable semantics to one original live vendor node.
#[derive(Clone)]
pub struct VendorCnpIdentity {
    /// Names the exact profile authenticated by the installed source codec.
    pub profile: Id,
    /// Complete immutable descriptor, including every typed directed lane.
    pub descriptor: NodeDescriptor,
    /// Exact implementation-keyed configuration and current live binding.
    pub binding: NodeBinding,
    /// Complete original mutable-owner roster.
    pub route: NodeRoute,
}

/// Selects an installed facet without inferring support from its wire name.
#[derive(Clone)]
pub struct VendorCnpFacet {
    /// Common runtime dispatch facet.
    pub kind: FacetKind,
    /// Exact profile identity in the original operating contract.
    pub profile: Id,
}

/// Borrows one genuine original runtime action for exact CNP request encoding.
pub enum VendorCnpAction<'a> {
    /// Reads bounded owner status without modeled progress.
    Status,
    /// Stages readiness while keeping the native execution gate closed.
    Arm(&'a ActivationRecord),
    /// Publishes the actual complete durable all-owner activation.
    Activate(&'a WorldActivation),
    /// Stages the actual frozen typed input batch exactly once.
    Input(&'a RuntimeInputBatch),
    /// Begins the original opaque coordinator admission.
    Begin(&'a OperationAdmission),
    /// Polls that same original operation, never a replacement run.
    Poll(&'a OperationAdmission),
    /// Requests cancellation while retaining the original completion obligation.
    Cancel(&'a OperationAdmission),
    /// Closes the original outstanding quantized Begin.
    Close(&'a OperationAdmission),
    /// Acknowledges only validated original publications.
    Acknowledge(&'a OperationAdmission, &'a [Id]),
    /// Reads the actual complete scheduling inventory at this activation.
    Scheduling(&'a WorldActivation),
}

/// Returns source-authenticated semantics without manufacturing runtime authority.
pub enum VendorCnpEvidence {
    /// Original native lifecycle status.
    Status(NodeStatus),
    /// Closed-gate native readiness with original public preparation records.
    Readiness(ReadyAttestation, Vec<PreparedOwner>),
    /// Authenticated staging/activation or durable output consumption.
    Acknowledged,
    /// Authentic exactly-once staged input custody.
    Input(NativeInputAcknowledgement),
    /// Original operation remains running; the caller retains its opaque token.
    Pending,
    /// Complete original terminal outcome with all referenced native evidence.
    Outcome(Box<OperationOutcome>),
    /// Authentic cancellation disposition, distinct from native completion.
    Cancellation(CancelStatus),
    /// Complete authentic original producer/consumer scheduling inventory.
    Scheduling(Box<NativeSchedulingObservation>),
}

/// Borrows the complete retained exchange for independent semantic inspection.
///
/// None of these protocol values grants authority; the inspector verifies them
/// against the installed source and the same original native custody.
pub struct VendorCnpResponse<'a> {
    /// Exact installed profile, descriptor and original binding.
    pub identity: &'a VendorCnpIdentity,
    /// Original opaque runtime action being inspected.
    pub action: VendorCnpAction<'a>,
    /// Retained original transmitted request.
    pub request: &'a Envelope,
    /// Retained original received response.
    pub response: &'a Envelope,
    /// Baseline closed response body decoded from those original bytes.
    pub decoded: &'a ResponseBody,
    /// Actual original native process and complete raw journal.
    pub peer: &'a VendorCnpPeer,
    /// Remaining aggregate metadata credit for returned semantic evidence.
    pub maximum_bytes: usize,
}

/// Inspects exact installed vendor source, schemas and original native receipts.
///
/// Implementations belong to host installation, not the remote provider. The
/// registry separately authenticates normal behavioral acceptance. Generic CNP
/// decoding and a callback returning matching data cannot supply either gate.
/// Every allocation respects the supplied original aggregate metadata bound.
pub trait InstalledVendorCnpCodec {
    /// Authenticates current measured code/profile/schema identities and native custody.
    ///
    /// # Errors
    /// Refuses revoked installation, changed live owner or missing original source.
    fn authenticate_current(
        &self,
        identity: &VendorCnpIdentity,
        peer: &VendorCnpPeer,
    ) -> Result<(), OperationFailure>;

    /// Lends the retained source revision for this actual original native node.
    ///
    /// This fence cannot replace native identity/session/schema inspection or
    /// ordinary class acceptance. The owner remains with its same installed
    /// original source scope and must revoke before withdrawing that scope.
    ///
    /// # Errors
    /// Defaults to refusal without original source revision support.
    fn current_source_revision(
        &self,
        _identity: &VendorCnpIdentity,
        _peer: &VendorCnpPeer,
    ) -> Result<crate::node_contract::ProviderAuthorizationLease, OperationFailure> {
        Err(super::refused(
            "vendor original source revision is unsupported",
        ))
    }

    /// Resolves only independently qualified facets of this exact original binding.
    ///
    /// # Errors
    /// Refuses unknown editions or unsupported exact/quantized/state semantics.
    fn facets(&self, identity: &VendorCnpIdentity)
    -> Result<Vec<VendorCnpFacet>, OperationFailure>;

    /// Encodes the method body for this original request under fixed host ceilings.
    ///
    /// The caller supplies the request ID and checks baseline envelope/body scope
    /// before writing. Grant/provenance fields must derive from the actual opaque
    /// action and independently inspected original evidence, never requested limits.
    ///
    /// # Errors
    /// Refuses unsupported actions, unknown body codecs or preallocation credit.
    fn request(
        &self,
        identity: &VendorCnpIdentity,
        action: VendorCnpAction<'_>,
        request: &Id,
        maximum_bytes: usize,
    ) -> Result<Envelope, OperationFailure>;

    /// Authenticates exact original request semantics before its first native effect.
    ///
    /// # Errors
    /// Refuses changed native scope, typed payloads, source definitions or grants.
    fn validate_request(
        &self,
        identity: &VendorCnpIdentity,
        action: VendorCnpAction<'_>,
        request: &Envelope,
        peer: &VendorCnpPeer,
    ) -> Result<(), OperationFailure>;

    /// Authenticates original native semantics after raw reply custody is retained.
    ///
    /// The transport has already retained the whole request/reply and original
    /// content. Inspectors authenticate native stop, FIFO, ACK, clock and complete
    /// state geometry against actual custody; structural decoding is insufficient.
    ///
    /// # Errors
    /// Refuses unsupported evidence, foreign originals or unknown native effects.
    fn response(
        &self,
        original: VendorCnpResponse<'_>,
    ) -> Result<VendorCnpEvidence, OperationFailure>;

    /// Authenticates complete original stopped preparation and unchanged state.
    ///
    /// # Errors
    /// Refuses unsupported initial/restored readiness or missing original records.
    fn validate_readiness(
        &self,
        identity: &VendorCnpIdentity,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
        owners: &[PreparedOwner],
        peer: &VendorCnpPeer,
    ) -> Result<(), OperationFailure>;

    /// Authenticates a cached native outcome against the actual original admission.
    ///
    /// # Errors
    /// Refuses changed clocks, publications, inventory, scope or source custody.
    fn validate_outcome(
        &self,
        identity: &VendorCnpIdentity,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        peer: &VendorCnpPeer,
    ) -> Result<(), OperationFailure>;

    /// Produces a bounded candidate from the actual stopped original runtime.
    ///
    /// The candidate is data and owning artifacts, never an acceptance seal.
    /// The adapter retains it before validating source/key/native semantics.
    ///
    /// # Errors
    /// Defaults to refusal. Allocations and artifacts must respect every supplied
    /// aggregate bound before copying or checkpoint effects.
    fn capture(
        &self,
        _identity: &VendorCnpIdentity,
        _peer: &mut VendorCnpPeer,
        _activation: &WorldActivation,
        _runtime: &crate::node_contract::RuntimeSnapshot,
        _limits: crate::node_contract::NativeCaptureLimits,
    ) -> Result<super::VendorNativeCapture, OperationFailure> {
        Err(super::refused(
            "vendor native capture codec is not installed",
        ))
    }

    /// Authenticates the candidate's exact key and complete stopped originals.
    ///
    /// # Errors
    /// Defaults to refusal; matching response fields do not establish native
    /// completeness, implementation compatibility or stopped capture permission.
    fn validate_capture(
        &self,
        _identity: &VendorCnpIdentity,
        _peer: &VendorCnpPeer,
        _activation: &WorldActivation,
        _runtime: &crate::node_contract::RuntimeSnapshot,
        _candidate: &super::VendorNativeCapture,
    ) -> Result<(), OperationFailure> {
        Err(super::refused(
            "vendor native capture inspector is not installed",
        ))
    }

    /// Requests containment of the same original native process group.
    ///
    /// The owning capsule is marked before this callback. A refusal or unwind
    /// retains the original Child, session, requests and wait obligation.
    ///
    /// # Errors
    /// Defaults to unknown containment; closing a socket is not native release.
    fn request_containment(
        &self,
        _identity: &VendorCnpIdentity,
        _peer: &mut VendorCnpPeer,
    ) -> Result<(), OperationFailure> {
        Err(super::unknown("vendor native containment is not installed"))
    }

    /// Authenticates every original payload/proof object before it is exposed.
    ///
    /// # Errors
    /// Defaults to refusal; arbitrary byte custody cannot establish semantic roles.
    fn validate_evidence(
        &self,
        _identity: &VendorCnpIdentity,
        _original: &OperationAdmission,
        _references: &[ContentRef],
        _objects: &[InputPayload],
        _peer: &VendorCnpPeer,
    ) -> Result<(), OperationFailure> {
        Err(super::refused(
            "vendor original evidence codec is not installed",
        ))
    }

    /// Authenticates complete staged typed input custody and its original receipt.
    ///
    /// # Errors
    /// Defaults to refusal for unsupported payload/state interpretation.
    fn validate_input(
        &self,
        _identity: &VendorCnpIdentity,
        _batch: &RuntimeInputBatch,
        _ack: &NativeInputAcknowledgement,
        _peer: &VendorCnpPeer,
    ) -> Result<(), OperationFailure> {
        Err(super::refused("vendor typed input codec is not installed"))
    }

    /// Authenticates the complete actual all-lane producer scheduling observation.
    ///
    /// # Errors
    /// Defaults to refusal; empty queues and response counts are not lookahead.
    fn validate_scheduling(
        &self,
        _identity: &VendorCnpIdentity,
        _world: &WorldActivation,
        _observation: &NativeSchedulingObservation,
        _peer: &VendorCnpPeer,
    ) -> Result<(), OperationFailure> {
        Err(super::refused("vendor scheduling codec is not installed"))
    }

    /// Authenticates fresh initial state rather than inferring it from empty journals.
    ///
    /// # Errors
    /// Defaults to refusal for unsupported initial state codecs.
    fn validate_initial(
        &self,
        _identity: &VendorCnpIdentity,
        _world: &ActivationRecord,
        _ready: &ReadyAttestation,
        _peer: &VendorCnpPeer,
    ) -> Result<(), OperationFailure> {
        Err(super::refused(
            "vendor initial state codec is not installed",
        ))
    }

    /// Supervises the same original native owner after containment was requested.
    ///
    /// The kernel Child wait result is retained before this callback. Receipts
    /// must cover the complete process group, helpers, descriptors and device
    /// leases; client EOF or root Child exit alone is insufficient.
    ///
    /// # Errors
    /// Retains Pending/Err until actual complete native reclamation is established.
    fn poll_reclamation(
        &self,
        identity: &VendorCnpIdentity,
        owner: &OwnerIdentity,
        peer: &VendorCnpPeer,
        context: &mut Context<'_>,
    ) -> Poll<Result<NativeReclamationReceipt, OperationFailure>>;

    /// Authenticates complete resource reclamation against original native custody.
    ///
    /// # Errors
    /// Refuses foreign receipts, incomplete cleanup or absent kernel wait evidence.
    fn validate_reclamation(
        &self,
        identity: &VendorCnpIdentity,
        peer: &VendorCnpPeer,
        receipt: &NativeReclamationReceipt,
    ) -> Result<(), OperationFailure>;
}

/// Retains a failed construction's whole original node with its diagnostic.
pub struct VendorCnpFailure {
    /// Original diagnostic and conservative effect certainty.
    pub error: OperationFailure,
    /// Original launch handles and complete supervision slot.
    pub guard: super::VendorCnpLaunchGuard,
}

/// Keeps the registered semantic codec owned with its original native peer.
pub(super) type VendorCodec = Rc<dyn InstalledVendorCnpCodec>;

pub(super) fn native(error: ProviderError) -> OperationFailure {
    super::unknown(&error.to_string())
}
