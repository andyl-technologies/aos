//! Adversarial native journal tests with explicitly model-only native evidence.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use crucible_node_contract::{ContentRef, Extensions, Phase, Position};
use serde_json::json;

use crate::bodies::{BeginRequest, InputRequest, InputResult};
use crate::envelope::{MessageKind, Method, Nullable};
use crate::handshake::{Handshake, tests::authority};

use super::*;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}
fn reference() -> ContentRef {
    canonical::content_ref(b"fixture", "application/json").unwrap()
}
fn identity(domain: &str) -> HashRef {
    canonical::hash(domain, b"fixture").unwrap()
}

#[derive(Default)]
struct Resources {
    effects: usize,
    inputs: usize,
}

struct Supervisor(Rc<RefCell<Vec<NativeCustody<Resources>>>>, Rc<Cell<bool>>);
struct Slot {
    capsules: Rc<RefCell<Vec<NativeCustody<Resources>>>>,
    occupied: Rc<Cell<bool>>,
    retained: bool,
}

impl NativeJournalSupervisor<Resources> for Supervisor {
    fn reserve(&self) -> Result<Box<dyn NativeSupervision<Resources>>, ProviderError> {
        if self.1.replace(true) {
            return Err(ProviderError::ResourceExhausted("fixture supervision slot"));
        }
        Ok(Box::new(Slot {
            capsules: Rc::clone(&self.0),
            occupied: Rc::clone(&self.1),
            retained: false,
        }))
    }
}

impl NativeSupervision<Resources> for Slot {
    fn retain(&mut self, custody: NativeCustody<Resources>) {
        self.retained = true;
        self.capsules.borrow_mut().push(custody);
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        if !self.retained {
            self.occupied.set(false);
        }
    }
}

struct Verifier {
    allow: bool,
    release: bool,
    fail_input: Cell<bool>,
    domains: Vec<Id>,
}

impl NativeScopeVerifier<Resources> for Verifier {
    fn verify_begin(
        &self,
        _: &Resources,
        envelope: &Envelope,
        original: &BeginRequest,
    ) -> Result<NativeScope, ProviderError> {
        if !self.allow {
            return Err(ProviderError::Correlation("fixture denied actual scope"));
        }
        Ok(NativeScope {
            execution_owner: envelope
                .execution_owner_id
                .0
                .clone()
                .unwrap_or_else(|| id("capture-associated-owner")),
            capture_owner: Some(id("capture-owner")),
            owner_generation: original.owner_generation,
            binding_hash: original.binding_hash.clone(),
            participants: vec![id("node")],
            state_domains: self.domains.clone(),
        })
    }
}

impl NativeOutcomeVerifier<Resources> for Verifier {
    fn verify_terminal(
        &self,
        _: &Resources,
        _: &OperationSnapshot,
        _: &bodies::ResponseBody,
    ) -> Result<NativeDisposition, ProviderError> {
        if !self.allow {
            return Err(ProviderError::Correlation(
                "fixture denied actual terminal evidence",
            ));
        }
        Ok(if self.release {
            NativeDisposition::Released
        } else {
            NativeDisposition::Held
        })
    }
}

impl NativeConsumptionVerifier<Resources> for Verifier {
    fn verify_operation(
        &self,
        _: &Resources,
        _: &OperationSnapshot,
        _: &ContentRef,
    ) -> Result<(), ProviderError> {
        if self.allow {
            Ok(())
        } else {
            Err(ProviderError::Correlation("fixture denied consumption"))
        }
    }
}

impl crate::journal::ConsumptionVerifier for Verifier {
    fn verify(
        &self,
        _: &RequestKey,
        _: &HashRef,
        _: &[u8],
        _: &ContentRef,
    ) -> Result<(), ProviderError> {
        if self.allow {
            Ok(())
        } else {
            Err(ProviderError::Correlation(
                "fixture denied request consumption",
            ))
        }
    }
}

impl NativeInputVerifier<Resources> for Verifier {
    fn verify_input(
        &self,
        _: &Resources,
        _: &Envelope,
        _: &InputRequest,
        _: &crucible_node_contract::InputBatch,
    ) -> Result<(), ProviderError> {
        if self.allow {
            Ok(())
        } else {
            Err(ProviderError::Correlation("fixture denied payload custody"))
        }
    }
    fn accept_input(
        &self,
        resources: &mut Resources,
        batch: &crucible_node_contract::InputBatch,
    ) -> Result<InputResult, ProviderError> {
        resources.inputs += 1;
        if self.fail_input.get() {
            return Err(ProviderError::Correlation(
                "fixture native input uncertainty",
            ));
        }
        Ok(InputResult {
            accepted_event_ids: Vec::new(),
            input_watermark: batch.batch_sequence,
            custody_receipt: reference(),
            inventory_hash: identity("cnp.pending-inventory.v1"),
        })
    }
}

impl NativeObservationVerifier<Resources> for Verifier {
    fn verify_observation(
        &self,
        _: &Resources,
        _: &OperationSnapshot,
        _: &crucible_node_contract::ObservationBatch,
    ) -> Result<(), ProviderError> {
        if self.allow {
            Ok(())
        } else {
            Err(ProviderError::Correlation(
                "fixture denied actual output pins",
            ))
        }
    }
}

impl NativeInputReconciler<Resources> for Verifier {
    fn recover_input(
        &self,
        resources: &Resources,
        original: &InputSnapshot,
    ) -> Result<InputResult, ProviderError> {
        if !self.allow || resources.inputs == 0 {
            return Err(ProviderError::Correlation(
                "fixture denied original accepted native batch",
            ));
        }
        Ok(InputResult {
            accepted_event_ids: Vec::new(),
            input_watermark: original.batch.batch_sequence,
            custody_receipt: reference(),
            inventory_hash: identity("cnp.pending-inventory.v1"),
        })
    }
}

fn verifier() -> Verifier {
    Verifier {
        allow: true,
        release: true,
        fail_input: Cell::new(false),
        domains: vec![id("ram")],
    }
}

fn fixture() -> (
    Handshake,
    ConnectionAuthority,
    NativeJournal<Resources>,
    Supervisor,
) {
    let (handshake, authority) = authority();
    let supervisor = Supervisor(Rc::new(RefCell::new(Vec::new())), Rc::new(Cell::new(false)));
    let journal = NativeJournal::new(
        authority.session_id().clone(),
        authority.incarnation_id().clone(),
        JournalLimits {
            entries_per_origin: 16,
            outcome_bytes: 65536,
            tombstones_per_origin: 16,
        },
        NativeJournalLimits {
            operations: 4,
            operation_tombstones: 4,
            input_batches: 4,
            observation_batches: 4,
            retained_bytes: 65536,
        },
        Resources::default(),
        &supervisor,
    )
    .unwrap();
    (handshake, authority, journal, supervisor)
}

fn envelope(
    authority: &ConnectionAuthority,
    request: &str,
    operation: Option<&str>,
    method: Method,
    body: Value,
) -> Envelope {
    Envelope {
        protocol: "CNP/1".to_owned(),
        message: MessageKind::Request,
        sequence: U64::new(2),
        session_id: Nullable(Some(authority.session_id().clone())),
        incarnation_id: Nullable(Some(authority.incarnation_id().clone())),
        node_id: Nullable(None),
        execution_owner_id: Nullable(Some(id("owner"))),
        capture_owner_id: Nullable(None),
        request_id: Nullable(Some(id(request))),
        operation_id: Nullable(operation.map(id)),
        method,
        body: body.as_object().unwrap().clone(),
        extensions: Extensions::new(),
    }
}

fn begin(
    authority: &ConnectionAuthority,
    request: &str,
    operation: &str,
) -> (Envelope, BeginRequest) {
    let start = Position::new(U64::new(100), U64::new(0), Phase::BoundaryControl);
    let limit = Position::new(U64::new(200), U64::new(0), Phase::BoundaryControl);
    let body = json!({"kind":"exact_run","binding_hash":identity("cnp.owner-binding.v1"),"owner_generation":"1","activation_id":"activation","world_generation":"1","arguments":{"grant_id":"grant","realization_id":"realization","input_epoch":"epoch","activation_id":"activation","world_generation":"1","owner_generation":"1","participant_ids":["node"],"mode":"exact","ordering_profile":"superdense-v1","start":start,"limit":limit,"boundary_policy":"ordinary_stop","input_authorization":reference(),"input_watermark":"0"},"extensions":{}});
    let envelope = envelope(authority, request, Some(operation), Method::Begin, body);
    let RequestBody::Begin(original) =
        bodies::decode_request(Method::Begin, &envelope.body).unwrap()
    else {
        panic!("begin fixture");
    };
    (envelope, original)
}

fn terminal(reached: u64) -> Map<String, Value> {
    json!({"status":"completed","operation_state":"completed","result":{"grant_id":"grant","reached":{"time_ps":reached.to_string(),"microstep":"0","phase":0},"stop_reason":"ceiling","stop_receipt":reference(),"observation_batch":reference(),"pending_inventory":reference(),"next_attention":{"kind":"unknown","position":null,"evidence":null}},"extensions":{}}).as_object().unwrap().clone()
}

fn reserve(
    journal: &mut NativeJournal<Resources>,
    authority: &ConnectionAuthority,
    request: &str,
    operation: &str,
) -> NativeOperationPermit {
    let (envelope, original) = begin(authority, request, operation);
    let BeginRegistration::New(permit) = journal
        .register_begin(authority, &envelope, &original, &verifier())
        .unwrap()
    else {
        panic!("new operation fixture");
    };
    permit
}

#[test]
fn refused_begin_retains_original_identity_without_a_native_effect_permit() {
    let (_handshake, authority, mut journal, supervisor) = fixture();
    let (original, begin) = begin(&authority, "refused", "refused-operation");
    let NativeRequestRegistration::New(permit) = journal
        .register_request(&authority, &original, RequestOrigin::Controller)
        .unwrap()
    else {
        panic!("new refusal");
    };
    assert!(
        journal
            .with_request_resources(&permit, |resources| {
                resources.effects += 1;
                Ok(())
            })
            .is_err()
    );
    let response = json!({"status":"error","operation_state":"not_started","error":{"code":"UNSUPPORTED_FEATURE",
        "message":"unsupported fixture facet","effect":"not_started","retryable":false,"details":{}},"extensions":{}}).as_object().unwrap().clone();
    journal.record_request_refusal(&permit, &response).unwrap();
    assert_eq!(journal.resources().effects, 0);
    assert!(journal.snapshot().operations.is_empty());
    assert!(
        journal
            .register_begin(&authority, &original, &begin, &verifier())
            .is_err()
    );
    let NativeRequestRegistration::Original(snapshot) = journal
        .register_request(&authority, &original, RequestOrigin::Controller)
        .unwrap()
    else {
        panic!("original refusal");
    };
    assert_eq!(snapshot.outcome.unwrap(), canonical_map(&response).unwrap());
    assert_eq!(
        journal
            .resumed_operations(&vec![id("refused-operation")])
            .unwrap()[0]
            .operation_state,
        bodies::OperationState::NotStarted
    );

    drop(journal);
    let custody = supervisor.0.borrow_mut().pop().unwrap();
    assert_eq!(custody.refused_operations.len(), 1);
    assert_eq!(custody.resources.effects, 0);
}

#[test]
fn started_nonbegin_effect_cannot_be_relabelled_as_not_started_refusal() {
    let (_handshake, authority, mut journal, _) = fixture();
    let request = envelope(
        &authority,
        "discover",
        None,
        Method::Discover,
        json!({"profile_ids":[],"extensions":{}}),
    );
    let NativeRequestRegistration::New(permit) = journal
        .register_request(&authority, &request, RequestOrigin::Controller)
        .unwrap()
    else {
        panic!("new request");
    };
    journal
        .with_request_resources(&permit, |resources| {
            resources.effects += 1;
            Ok(())
        })
        .unwrap();
    let response = json!({"status":"error","operation_state":"not_started","error":{"code":"INVALID_STATE",
        "message":"not a rollback","effect":"not_started","retryable":false,"details":{}},"extensions":{}}).as_object().unwrap().clone();
    assert!(journal.record_request_refusal(&permit, &response).is_err());
    assert_eq!(journal.resources().effects, 1);
    assert_eq!(
        journal
            .snapshot()
            .requests
            .get(&RequestKey {
                origin: RequestOrigin::Controller,
                id: id("discover")
            })
            .unwrap()
            .state(),
        JournalState::Unknown
    );
}

#[test]
fn retry_never_issues_another_effect_permit_and_domain_conflicts_precede_effects() {
    let (_handshake, authority, mut journal, _) = fixture();
    let permit = reserve(&mut journal, &authority, "request", "operation");
    journal
        .with_operation_resources(&permit, |resources| {
            resources.effects += 1;
            Ok(())
        })
        .unwrap();
    assert!(
        journal
            .with_operation_resources(&permit, |_| Ok(()))
            .is_err()
    );
    let (request, original) = begin(&authority, "request", "operation");
    assert!(matches!(
        journal
            .register_begin(&authority, &request, &original, &verifier())
            .unwrap(),
        BeginRegistration::Original(_)
    ));
    let (other, original) = begin(&authority, "replacement", "replacement-operation");
    assert!(
        journal
            .register_begin(&authority, &other, &original, &verifier())
            .is_err()
    );
    assert_eq!(journal.resources().effects, 1);
    assert_eq!(journal.snapshot().operations.len(), 1);
}

#[test]
fn native_failure_and_cancel_retain_original_unknown_work_and_exclusivity() {
    let (_handshake, authority, mut journal, _) = fixture();
    let permit = reserve(&mut journal, &authority, "request", "operation");
    assert!(
        journal
            .with_operation_resources(&permit, |resources| {
                resources.effects += 1;
                Err::<(), _>(ProviderError::Correlation("native acknowledgment lost"))
            })
            .is_err()
    );
    let canceled = journal.request_cancel(permit.operation_id()).unwrap();
    assert!(canceled.cancel_requested);
    assert_eq!(canceled.operation_state, bodies::OperationState::Unknown);
    assert!(
        journal
            .with_operation_resources(&permit, |_| Ok(()))
            .is_err()
    );
    assert!(!journal.snapshot().operations[permit.operation_id()].domains_released);
}

#[test]
fn terminal_requires_original_grant_and_actual_evidence_and_cannot_change() {
    let (_handshake, authority, mut journal, _) = fixture();
    let permit = reserve(&mut journal, &authority, "request", "operation");
    let denied = Verifier {
        allow: false,
        ..verifier()
    };
    assert!(
        journal
            .record_terminal(&permit, &terminal(201), &verifier())
            .is_err()
    );
    assert!(
        journal
            .record_terminal(&permit, &terminal(200), &denied)
            .is_err()
    );
    assert!(
        journal.snapshot().operations[permit.operation_id()]
            .outcome
            .is_none()
    );
    journal
        .record_terminal(&permit, &terminal(200), &verifier())
        .unwrap();
    journal
        .record_terminal(&permit, &terminal(200), &denied)
        .unwrap();
    assert!(
        journal
            .record_terminal(&permit, &terminal(199), &verifier())
            .is_err()
    );
    assert_eq!(
        journal
            .poll(permit.operation_id(), U64::new(0), 4)
            .unwrap()
            .outcome
            .0,
        Some(terminal(200))
    );
}

#[test]
fn native_unknown_terminal_remains_locked_until_independent_reconciliation() {
    let (_handshake, authority, mut journal, _) = fixture();
    let permit = reserve(&mut journal, &authority, "request", "operation");
    let outcome = json!({"status":"error","operation_state":"unknown","error":{"code":"OUTCOME_UNKNOWN","message":"actual unresolved custody","effect":"unknown","retryable":false,"details":{}},"extensions":{}}).as_object().unwrap().clone();
    journal
        .record_terminal(
            &permit,
            &outcome,
            &Verifier {
                release: false,
                ..verifier()
            },
        )
        .unwrap();
    assert!(
        journal
            .retire_operation(permit.operation_id(), &reference(), &verifier())
            .is_err()
    );
    journal
        .reconcile_domain_release(permit.operation_id(), &verifier())
        .unwrap();
    assert_eq!(
        journal
            .poll(permit.operation_id(), U64::new(0), 4)
            .unwrap()
            .outcome
            .0,
        Some(outcome)
    );
    journal
        .retire_operation(permit.operation_id(), &reference(), &verifier())
        .unwrap();
}

#[test]
fn operation_and_request_retirement_are_separate_and_never_reuse_original_ids() {
    let (_handshake, authority, mut journal, _) = fixture();
    let permit = reserve(&mut journal, &authority, "request", "operation");
    journal
        .record_terminal(&permit, &terminal(200), &verifier())
        .unwrap();
    journal
        .retire_request(
            RequestOrigin::Controller,
            &id("request"),
            &reference(),
            &verifier(),
        )
        .unwrap();
    assert!(journal.poll(permit.operation_id(), U64::new(0), 4).is_ok());
    journal
        .retire_operation(permit.operation_id(), &reference(), &verifier())
        .unwrap();
    let (request, original) = begin(&authority, "new-request", "operation");
    assert!(
        journal
            .register_begin(&authority, &request, &original, &verifier())
            .is_err()
    );
    assert!(journal.poll(permit.operation_id(), U64::new(0), 4).is_err());
}

#[test]
fn foreign_opaque_permits_and_revoked_connections_cannot_mutate_resources() {
    let (mut handshake, authority, mut journal, _) = fixture();
    let (_other_handshake, other_authority, mut other, _) = fixture();
    let permit = reserve(&mut other, &other_authority, "request", "operation");
    assert!(
        journal
            .with_operation_resources(&permit, |_| Ok(()))
            .is_err()
    );
    handshake.contain();
    let (request, original) = begin(&authority, "request", "operation");
    assert!(
        journal
            .register_begin(&authority, &request, &original, &verifier())
            .is_err()
    );
    assert_eq!(journal.resources().effects, 0);
}

#[test]
fn drop_transfers_actual_resources_and_complete_original_unknown_custody() {
    let (_handshake, authority, mut journal, supervisor) = fixture();
    let permit = reserve(&mut journal, &authority, "request", "operation");
    journal
        .with_operation_resources(&permit, |resources| {
            resources.effects += 1;
            Ok(())
        })
        .unwrap();
    journal
        .mark_operation_uncertain(permit.operation_id())
        .unwrap();
    drop(journal);
    let retained = supervisor.0.borrow();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].resources.effects, 1);
    assert_eq!(
        retained[0].operations[permit.operation_id()].state,
        bodies::OperationState::Unknown
    );
    assert!(
        retained[0]
            .requests
            .get(&RequestKey {
                origin: RequestOrigin::Controller,
                id: id("request")
            })
            .is_some()
    );
}

fn input(
    authority: &ConnectionAuthority,
    request: &str,
    batch: &str,
    sequence: u64,
    epoch: &str,
) -> (Envelope, InputRequest) {
    let batch = crucible_node_contract::InputBatch {
        schema_version: 1,
        execution_owner_id: id("owner"),
        input_epoch: id(epoch),
        batch_id: id(batch),
        batch_sequence: U64::new(sequence),
        events: Vec::new(),
        extensions: Extensions::new(),
    };
    let body = json!({"binding_hash":identity("cnp.owner-binding.v1"),"owner_generation":"1","batch_id":batch.batch_id,"batch_sequence":batch.batch_sequence,"input_epoch":batch.input_epoch,"events":[],"batch_hash":batch.identity().unwrap(),"extensions":{}});
    let envelope = envelope(authority, request, None, Method::Input, body);
    let RequestBody::Input(original) =
        bodies::decode_request(Method::Input, &envelope.body).unwrap()
    else {
        panic!("input fixture");
    };
    (envelope, original)
}

#[test]
fn input_custody_is_exactly_once_and_epoch_sequences_survive_connection_changes() {
    let (_handshake, authority, mut journal, _) = fixture();
    let (request, original) = input(&authority, "request", "batch", 1, "epoch");
    assert!(matches!(
        journal
            .accept_input(&authority, &request, &original, &verifier())
            .unwrap(),
        InputAcceptance::Accepted(_)
    ));
    assert!(matches!(
        journal
            .accept_input(&authority, &request, &original, &verifier())
            .unwrap(),
        InputAcceptance::Original(_)
    ));
    let (request, original) = input(&authority, "next", "next-batch", 3, "epoch");
    assert!(
        journal
            .accept_input(&authority, &request, &original, &verifier())
            .is_err()
    );
    let (request, original) = input(&authority, "reset", "next-batch", 2, "new-epoch");
    assert!(
        journal
            .accept_input(&authority, &request, &original, &verifier())
            .is_err()
    );
    assert_eq!(journal.resources().inputs, 1);
}

#[test]
fn uncertain_input_preserves_original_batch_without_a_replacement_acceptance() {
    let (_handshake, authority, mut journal, _) = fixture();
    let (request, original) = input(&authority, "request", "batch", 1, "epoch");
    assert!(
        journal
            .accept_input(
                &authority,
                &request,
                &original,
                &Verifier {
                    fail_input: Cell::new(true),
                    ..verifier()
                }
            )
            .is_err()
    );
    let InputAcceptance::Original(snapshot) = journal
        .accept_input(&authority, &request, &original, &verifier())
        .unwrap()
    else {
        panic!("original uncertain input");
    };
    assert_eq!(snapshot.state, bodies::OperationState::Unknown);
    assert!(snapshot.result.is_none());
    assert_eq!(journal.resources().inputs, 1);
}

fn observation(operation: &Id, sequence: u64) -> crucible_node_contract::ObservationBatch {
    use crucible_node_contract::{Endpoint, Event, EventStage, ObservationBatch, Visibility};

    let position = Position::new(U64::new(100 + sequence), U64::new(0), Phase::Publication);
    ObservationBatch {
        schema_version: 1,
        execution_owner_id: id("owner"),
        owner_binding_hash: identity("cnp.owner-binding.v1"),
        world_binding_hash: identity("cnp.world-binding.v1"),
        activation_id: id("activation"),
        world_generation: U64::new(1),
        owner_generation: U64::new(1),
        operation_id: operation.clone(),
        grant_id: Some(id("grant")),
        first_sequence: U64::new(sequence),
        last_sequence: U64::new(sequence),
        events: vec![Event {
            schema_version: 1,
            id: id(&format!("event-{sequence}")),
            source: Endpoint {
                node_id: id("node"),
                port_id: id("port"),
                lane_id: id("lane"),
            },
            destination: Endpoint {
                node_id: id("peer"),
                port_id: id("port"),
                lane_id: id("lane"),
            },
            position,
            stage: EventStage::Publication,
            publication_position: position,
            delivery_position: None,
            source_sequence: U64::new(sequence),
            causal_parent_ids: Vec::new(),
            payload: reference(),
            provenance_ref: reference(),
            extensions: Extensions::new(),
        }],
        visibility: Visibility::Staged,
        measurement_ref: reference(),
        extensions: Extensions::new(),
    }
}

#[test]
fn observations_preserve_original_lineage_and_monotonic_cursors() {
    let (_handshake, authority, mut journal, _) = fixture();
    let permit = reserve(&mut journal, &authority, "request", "operation");
    let first = observation(permit.operation_id(), 1);
    journal
        .append_observation(&permit, &first, &verifier())
        .unwrap();
    journal
        .append_observation(
            &permit,
            &first,
            &Verifier {
                allow: false,
                ..verifier()
            },
        )
        .unwrap();
    let mut changed = first;
    changed.events[0].id = id("changed");
    assert!(
        journal
            .append_observation(&permit, &changed, &verifier())
            .is_err()
    );
    assert!(
        journal
            .append_observation(&permit, &observation(permit.operation_id(), 3), &verifier())
            .is_err()
    );
    let second = observation(permit.operation_id(), 2);
    journal
        .append_observation(&permit, &second, &verifier())
        .unwrap();
    let poll = journal.poll(permit.operation_id(), U64::new(1), 1).unwrap();
    assert_eq!(poll.observations, vec![second]);
    assert_eq!(poll.next_observation_sequence, U64::new(2));
    assert!(journal.poll(permit.operation_id(), U64::new(3), 1).is_err());
}

#[test]
fn reclaim_preserves_complete_native_streams_and_refusal_returns_owned_custody() {
    let (_handshake, authority, mut journal, supervisor) = fixture();
    let permit = reserve(&mut journal, &authority, "request", "operation");
    journal
        .with_operation_resources(&permit, |resources| {
            resources.effects += 1;
            Ok(())
        })
        .unwrap();
    journal
        .append_observation(&permit, &observation(permit.operation_id(), 1), &verifier())
        .unwrap();
    let (request, original) = input(&authority, "input", "batch", 1, "epoch");
    journal
        .accept_input(&authority, &request, &original, &verifier())
        .unwrap();
    let limits = journal.limits;
    drop(journal);
    let capsule = supervisor.0.borrow_mut().pop().unwrap();
    // Taking the capsule transfers its sole reserved capacity for re-admission.
    supervisor.1.set(false);
    let failure = match NativeJournal::from_custody(
        capsule,
        NativeJournalLimits {
            retained_bytes: 1,
            ..limits
        },
        &supervisor,
    ) {
        Ok(_) => panic!("undersized reclaim must fail"),
        Err(failure) => failure,
    };
    assert_eq!(failure.custody.resources.effects, 1);
    let mut reclaimed = match NativeJournal::from_custody(failure.custody, limits, &supervisor) {
        Ok(journal) => journal,
        Err(_) => panic!("original bounded custody must reclaim"),
    };
    assert!(
        reclaimed
            .with_operation_resources(&permit, |_| Ok(()))
            .is_err()
    );
    assert_eq!(
        reclaimed
            .poll(permit.operation_id(), U64::new(0), 4)
            .unwrap()
            .next_observation_sequence,
        U64::new(1)
    );
    let (request, original) = input(&authority, "next-input", "next-batch", 2, "epoch");
    reclaimed
        .accept_input(&authority, &request, &original, &verifier())
        .unwrap();
    assert_eq!(reclaimed.resources().inputs, 2);
}

#[test]
fn full_supervision_capacity_refuses_native_admission_and_keeps_original_capsule() {
    let (_handshake, authority, journal, supervisor) = fixture();
    let limits = journal.limits;
    drop(journal);
    assert!(
        NativeJournal::new(
            authority.session_id().clone(),
            authority.incarnation_id().clone(),
            JournalLimits {
                entries_per_origin: 2,
                outcome_bytes: 4096,
                tombstones_per_origin: 2
            },
            limits,
            Resources::default(),
            &supervisor
        )
        .is_err()
    );
    assert_eq!(supervisor.0.borrow().len(), 1);
}

#[test]
fn intersecting_domains_block_other_owners_and_capture_before_any_new_effect() {
    let (_handshake, authority, mut journal, _) = fixture();
    let _permit = reserve(&mut journal, &authority, "request", "operation");
    let (mut second, original) = begin(&authority, "second", "second-operation");
    second.execution_owner_id = Nullable(Some(id("another-owner")));
    let partial = Verifier {
        domains: vec![id("disk"), id("ram")],
        ..verifier()
    };
    assert!(
        journal
            .register_begin(&authority, &second, &original, &partial)
            .is_err()
    );
    let independent = Verifier {
        domains: vec![id("disk")],
        ..verifier()
    };
    assert!(matches!(
        journal
            .register_begin(&authority, &second, &original, &independent)
            .unwrap(),
        BeginRegistration::New(_)
    ));

    let capture_body = json!({"kind":"capture","binding_hash":identity("cnp.owner-binding.v1"),"owner_generation":"1","activation_id":"activation","world_generation":"1","arguments":{"capture_id":"capture","participant_ids":["node"],"cut_id":"cut","cut":{"time_ps":"100","microstep":"0","phase":0},"event_ordinal":"0","ordering_profile":"superdense-v1","preservation_contract":"complete/1"},"extensions":{}});
    let mut capture = envelope(
        &authority,
        "capture-request",
        Some("capture-operation"),
        Method::Begin,
        capture_body,
    );
    capture.execution_owner_id = Nullable(None);
    capture.capture_owner_id = Nullable(Some(id("capture-owner")));
    let RequestBody::Begin(original) =
        bodies::decode_request(Method::Begin, &capture.body).unwrap()
    else {
        panic!("capture fixture");
    };
    assert!(
        journal
            .register_begin(&authority, &capture, &original, &verifier())
            .is_err()
    );
    assert_eq!(journal.snapshot().operations.len(), 2);
    assert_eq!(journal.resources().effects, 0);
}

#[test]
fn lost_input_acknowledgment_reconciles_the_original_batch_without_acceptance() {
    let (_handshake, authority, mut journal, _) = fixture();
    let (request, original) = input(&authority, "request", "batch", 1, "epoch");
    assert!(
        journal
            .accept_input(
                &authority,
                &request,
                &original,
                &Verifier {
                    fail_input: Cell::new(true),
                    ..verifier()
                }
            )
            .is_err()
    );
    let stream = OwnerStream {
        owner: id("owner"),
        generation: U64::new(1),
    };
    assert!(
        journal
            .reconcile_input(
                &stream,
                &id("batch"),
                &Verifier {
                    allow: false,
                    ..verifier()
                }
            )
            .is_err()
    );
    journal
        .reconcile_input(&stream, &id("batch"), &verifier())
        .unwrap();
    assert_eq!(journal.resources().inputs, 1);
    let (request, original) = input(&authority, "next", "next-batch", 2, "epoch");
    journal
        .accept_input(&authority, &request, &original, &verifier())
        .unwrap();
    assert_eq!(journal.resources().inputs, 2);
}
