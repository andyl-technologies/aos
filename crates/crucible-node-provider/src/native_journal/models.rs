//! Native journal bounds, opaque request permits, and retained custody records.

use crucible_node_contract::{ContentRef, IdSet, InputBatch, ObservationBatch};

use super::*;

/// Bounds native operation, input, observation, and retained metadata storage.
#[derive(Clone, Copy, Debug)]
pub struct NativeJournalLimits {
    /// Bounds live operations independently of transport request credit.
    pub operations: usize,
    /// Bounds retired operation identities for the entire session.
    pub operation_tombstones: usize,
    /// Bounds original input batch records, including unresolved custody.
    pub input_batches: usize,
    /// Bounds retained observation batches and owner stream metadata.
    pub observation_batches: usize,
    /// Bounds canonical input, observation, and original operation metadata bytes.
    pub retained_bytes: usize,
}

impl Validate for NativeJournalLimits {
    fn validate(&self) -> Result<(), crucible_node_contract::ContractError> {
        if [
            self.operations,
            self.operation_tombstones,
            self.input_batches,
            self.observation_batches,
        ]
        .iter()
        .any(|count| *count == 0 || *count > crate::journal::MAX_JOURNAL_ENTRIES)
            || self.retained_bytes == 0
        {
            return Err(bodies::invalid(
                "limits",
                "native allowances must be positive and bounded",
            ));
        }
        Ok(())
    }
}

/// Reserves finite supervision before native journal admission.
pub trait NativeJournalSupervisor<C: 'static> {
    /// Reserves one persistent slot that can retain the complete native ledger.
    ///
    /// # Errors
    /// Refuses exhausted or unavailable capacity before any native admission.
    fn reserve(&self) -> Result<Box<dyn NativeSupervision<C>>, ProviderError>;
}

/// Owns a preallocated supervision slot independently of the journal's lifetime.
///
/// Implementations must retain custody infallibly without starting replacement
/// effects. The slot's own Drop releases unused capacity, but a retained capsule
/// survives until trusted native reconciliation, resource reclamation, and
/// durable outcome consumption. Implementations must not panic in `retain`.
pub trait NativeSupervision<C: 'static> {
    /// Transfers actual resources and every unresolved portable obligation.
    fn retain(&mut self, custody: NativeCustody<C>);
}

/// Returns an unsuccessful reclaim together with all original native custody.
pub struct NativeReclaimFailure<C: 'static> {
    /// Explains why admission of the retained capsule failed.
    pub error: ProviderError,
    /// Preserves actual resources and complete ledger for further supervision.
    pub custody: NativeCustody<C>,
}

/// Binds resource access to one locally registered original request.
#[derive(Debug)]
pub struct NativeRequestPermit {
    pub(super) identity: u64,
    pub(super) key: RequestKey,
}

/// Returns either a new resource permit or the original retained request status.
pub enum NativeRequestRegistration {
    /// Grants a single native effect attempt under the original request.
    New(NativeRequestPermit),
    /// Retains existing state without another resource permit.
    Original(RequestSnapshot),
}

/// Preserves original request status independently of connection sequencing.
#[derive(Clone, Debug)]
pub struct RequestSnapshot {
    /// Names the origin-scoped original request.
    pub key: RequestKey,
    /// Commits to its original portable material.
    pub hash: HashRef,
    /// Retains current effect knowledge.
    pub state: JournalState,
    /// Retains canonical terminal bytes, or no terminal outcome yet.
    pub outcome: Option<Vec<u8>>,
}

pub(super) struct RequestRecord {
    pub(super) reservation: Reservation,
    pub(super) original: Envelope,
    pub(super) started: bool,
}

/// Binds verified native ownership and state domains for an operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeScope {
    /// Names the execution owner bound by the admitted request envelope.
    pub execution_owner: Id,
    /// Names its indivisible capture owner, if preservation is supported.
    pub capture_owner: Option<Id>,
    /// Fences prior native realizations of this owner.
    pub owner_generation: U64,
    /// Commits to the complete admitted owner binding.
    pub binding_hash: HashRef,
    /// Lists every admitted participant in strict ID order.
    pub participants: IdSet,
    /// Lists all owned state domains in strict ID order.
    pub state_domains: IdSet,
}

/// Preserves one original long-lived operation and its native custody status.
#[derive(Clone, Debug)]
pub struct OperationSnapshot {
    /// Names the original controller-generated operation.
    pub operation_id: Id,
    /// Names the original request whose outcome it retains.
    pub request_key: RequestKey,
    /// Commits to that complete original request.
    pub request_hash: HashRef,
    /// Retains the original closed begin arguments and grant.
    pub original: bodies::BeginRequest,
    /// Retains verified ownership and all locked state domains.
    pub scope: NativeScope,
    /// Retains progress independently of terminal response status.
    pub state: bodies::OperationState,
    /// Records a cancellation request without claiming native stop.
    pub cancel_requested: bool,
    /// Reports whether trusted native evidence released domain exclusivity.
    pub domains_released: bool,
    /// Retains the immutable terminal begin response body, if one exists.
    pub outcome: Option<Map<String, Value>>,
    /// Prevents identity reuse after authenticated outcome consumption.
    pub retired: bool,
}

/// Selects native exclusivity release independently of response formatting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeDisposition {
    /// Retains execution or preservation locks while native effects are unresolved.
    Held,
    /// Proves native domain activity stopped or never began.
    Released,
}

/// Identifies an input or observation stream beneath one native owner generation.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct OwnerStream {
    /// Names the complete execution owner.
    pub owner: Id,
    /// Fences prior realizations while retaining captured cursors.
    pub generation: U64,
}

/// Retains an original input batch even when native custody is uncertain.
#[derive(Clone, Debug)]
pub struct InputSnapshot {
    /// Binds the original owner generation.
    pub stream: OwnerStream,
    /// Retains exact batch contents, epoch, and sequence.
    pub batch: InputBatch,
    /// Commits to original complete batch material.
    pub batch_hash: HashRef,
    /// Retains the original input request identity.
    pub request_key: RequestKey,
    /// Commits to the original input request and admitted envelope scope.
    pub request_hash: HashRef,
    /// Retains known input custody rather than a guessed native retry decision.
    pub state: bodies::OperationState,
    /// Retains an authenticated accepted-input result, if established.
    pub result: Option<bodies::InputResult>,
}

/// Preserves the admitted input epoch and next contiguous sequence.
#[derive(Clone, Debug)]
pub struct InputCursor {
    /// Names the original admitted input custody epoch.
    pub epoch: Id,
    /// Names the next batch sequence; reconnect cannot reset it.
    pub next_sequence: U64,
}

/// Returns an immutable page of a retained original owner observation stream.
#[derive(Clone, Debug)]
pub struct ObservationPage {
    /// Retains complete original batches after the requested cursor.
    pub observations: Vec<ObservationBatch>,
    /// Gives the cursor through the returned complete batches.
    pub next_sequence: U64,
    /// Proves enumeration through the currently retained owner cursor only.
    pub complete: bool,
}

/// Transfers actual resources and complete request, operation, and event custody.
pub struct NativeCustody<C: 'static> {
    /// Names the admitted world session whose original obligations are retained.
    pub session_id: Id,
    /// Names the surviving actual native provider incarnation.
    pub incarnation_id: Id,
    /// Owns actual native handles, content pins, bindings, and activation state.
    pub resources: C,
    /// Retains original origin-scoped request outcomes and reuse tombstones.
    pub requests: RequestJournal,
    pub(super) reservations: BTreeMap<RequestKey, RequestRecord>,
    /// Retains original operations, including consumed reuse tombstones.
    pub operations: BTreeMap<Id, OperationSnapshot>,
    /// Retains bounded refused begin identities without native effect authority.
    pub refused_operations: BTreeMap<Id, RefusedOperation>,
    /// Retains exact accepted or uncertain original input batches.
    pub inputs: BTreeMap<(OwnerStream, Id), InputSnapshot>,
    /// Preserves original admitted input epochs and monotonic stream cursors.
    pub input_streams: BTreeMap<OwnerStream, InputCursor>,
    /// Retains monotonically increasing observation cursors for each owner.
    pub observation_streams: BTreeMap<OwnerStream, U64>,
    /// Retains original ordered observation batches and staged payload custody.
    pub observations: Vec<ObservationBatch>,
    pub(super) retained_bytes: usize,
}

/// Preserves a proved not-started begin refusal without an execution scope.
#[derive(Clone, Debug)]
pub struct RefusedOperation {
    /// Names the original controller-generated operation.
    pub operation_id: Id,
    /// Names the original controller request.
    pub request_key: RequestKey,
    /// Commits to all original envelope and begin arguments.
    pub request_hash: HashRef,
    /// Retains the exact requested node correlation, without admission authority.
    pub node_id: Option<Id>,
    /// Retains requested execution correlation, without granting an owner lease.
    pub execution_owner_id: Option<Id>,
    /// Retains requested capture correlation, without claiming capture support.
    pub capture_owner_id: Option<Id>,
    /// Retains the exact immutable not-started response body.
    pub outcome: Map<String, Value>,
}

/// Authenticates native reclamation and durable consumption before retirement.
pub trait NativeConsumptionVerifier<C> {
    /// Verifies consumption and native resource closure for an original operation.
    ///
    /// # Errors
    /// Rejects uncommitted, foreign, uncertain, or unreclaimed native custody.
    fn verify_operation(
        &self,
        resources: &C,
        original: &OperationSnapshot,
        receipt: &ContentRef,
    ) -> Result<(), ProviderError>;
}
