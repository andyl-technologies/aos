//! Genuine protected-file tests with a state-only canonical DATA schema.
//!
//! The schema and deliberate token corruption exercise error ownership, not
//! Root/Read authority or a production guard/decision factory.

use super::*;
use std::{
    fs,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
};

// The reducer framing requires at least eight canonical body bytes.
const STATE_BODY: &[u8; 8] = b"state-v1";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct StateData;

impl ProtectedDomainSchemaV1 for StateData {
    type Kind = u8;
    type ReplayValidator = ();
    const MAGIC: [u8; 8] = *b"TESTDT01";
    const HASH_DOMAIN: &'static [u8] = b"retained.state.data.test\0";
    const KEY_PREFIX: &'static [u8] = b"retained-test/";
    const MAXIMUM_PAYLOAD_BYTES: usize = 1024;
    fn kind_code(kind: u8) -> u8 {
        kind
    }
    fn kind_from_code(code: u8) -> Option<u8> {
        (code == 1).then_some(code)
    }
    fn namespace(_: u8) -> RecordNamespace {
        RecordNamespace::DesiredState
    }
    fn order(kind: u8) -> u8 {
        kind
    }
    fn role(_: u8) -> ProtectedRecordRoleV1 {
        ProtectedRecordRoleV1::State
    }
    fn is_checkpoint(_: u8) -> bool {
        false
    }
    fn family(_: u8) -> u8 {
        1
    }
    fn decode_reducer_phase(
        _: &(),
        _: u8,
        identity: &[u8],
        body: &[u8],
    ) -> Option<ProtectedReducerPhaseV1> {
        (identity.len() == 1 && body == STATE_BODY).then_some(ProtectedReducerPhaseV1::Terminal)
    }
    fn validates_identity(kind: u8, identity: &[u8]) -> bool {
        kind == 1 && identity.len() == 1
    }
}

fn fixture() -> (tempfile::TempDir, Journal, Journal) {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let uid = fs::metadata(root.path()).unwrap().uid();
    Journal::initialize_cache_policy_hold_at(root.path(), uid).unwrap();
    let open = |name| {
        let (mut journal, _) =
            Journal::open_protected_at_uid(root.path(), name, JournalLimits::default(), uid)
                .unwrap();
        journal
            .enable_cache_policy_hold_gate(root.path(), uid)
            .unwrap();
        journal
    };
    let state = open("state.journal");
    let authority = open("authority.journal");
    (root, state, authority)
}

fn plan(
    adapter: &ProtectedDomainJournalV1<'_, StateData>,
    gate: &mut HeldCacheMutationGateV1,
) -> PreparedDomainTransactionV1<StateData> {
    let key = ProtectedDomainKeyV1::new(1, vec![1]).unwrap();
    let payload =
        encode_reducer_payload_with_validator::<StateData>(&key, STATE_BODY, &()).unwrap();
    let envelope =
        ProtectedDomainEnvelopeV1::new_with_validator(key, 1, None, payload, &()).unwrap();
    adapter
        .plan_with_retained_cache_gate_v1([1; 16], vec![envelope], gate)
        .unwrap()
}

#[test]
fn strict_stale_prepared_retains_original_without_refresh_or_retry() {
    let (_root, mut state, authority) = fixture();
    let mut gate = Journal::retain_cache_read_mutation_gate_v1(&state, &authority).unwrap();
    let mut adapter =
        ProtectedDomainJournalV1::<StateData>::claim_with_validator(&mut state, ()).unwrap();
    let prepared = plan(&adapter, &mut gate);
    let old_sequence = prepared.snapshot.sequence;
    let digest = prepared.transaction_digest();
    let intervening = JournalTransaction::new(
        [2; 16],
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            b"other".to_vec(),
            vec![2],
        )],
    )
    .unwrap();
    adapter
        .journal
        .commit_with_retained_cache_gate_v1(&intervening, &mut gate)
        .unwrap();
    let before = adapter.journal.snapshot_sequence();
    match adapter.commit_strict_with_retained_cache_gate_v1(prepared, &mut gate) {
        Err(RetainedCommitFailureV1::BeforeJournalAppend {
            prepared,
            cause: ProtectedDomainJournalErrorV1::StaleAuthority,
        }) => {
            assert_eq!(prepared.snapshot.sequence, old_sequence);
            assert_eq!(prepared.transaction_digest(), digest);
            assert_eq!(adapter.journal.snapshot_sequence(), before);
        }
        _ => panic!("strict path must retain original stale token, not refresh it"),
    }
}

#[test]
fn strict_named_mode_failure_retains_prepared_and_original_journal_cause() {
    let (root, mut state, authority) = fixture();
    let mut gate = Journal::retain_cache_read_mutation_gate_v1(&state, &authority).unwrap();
    let mut adapter =
        ProtectedDomainJournalV1::<StateData>::claim_with_validator(&mut state, ()).unwrap();
    let prepared = plan(&adapter, &mut gate);
    let digest = prepared.transaction_digest();
    fs::set_permissions(
        root.path().join("state.journal"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    match adapter.commit_strict_with_retained_cache_gate_v1(prepared, &mut gate) {
        Err(RetainedCommitFailureV1::BeforeJournalAppend {
            prepared,
            cause: ProtectedDomainJournalErrorV1::Journal(_),
        }) => assert_eq!(prepared.transaction_digest(), digest),
        _ => panic!("real protected-name refusal must return original custody"),
    }
}

#[test]
fn strict_after_append_readback_keeps_pending_and_exact_domain_error() {
    let (_root, mut state, authority) = fixture();
    let mut gate = Journal::retain_cache_read_mutation_gate_v1(&state, &authority).unwrap();
    let mut adapter =
        ProtectedDomainJournalV1::<StateData>::claim_with_validator(&mut state, ()).unwrap();
    let mut prepared = plan(&adapter, &mut gate);
    let digest = prepared.transaction_digest();
    // Private DATA corruption after genuine plan: no production constructor.
    prepared.after[0].push(0);
    match adapter.commit_strict_with_retained_cache_gate_v1(prepared, &mut gate) {
        Err(RetainedCommitFailureV1::AfterAppendReadback {
            pending,
            cause: ProtectedDomainJournalErrorV1::CompareAndSwapFailed,
        }) => {
            assert_eq!(pending.prepared.transaction_digest(), digest);
            assert_eq!(pending.prepared.after[0].last(), Some(&0));
        }
        _ => panic!("postappend readback error is pending, not Prepared or Applied"),
    }
}

#[test]
fn strict_after_append_sealing_keeps_pending_without_fake_applied() {
    let (_root, mut state, authority) = fixture();
    let mut gate = Journal::retain_cache_read_mutation_gate_v1(&state, &authority).unwrap();
    let mut adapter =
        ProtectedDomainJournalV1::<StateData>::claim_with_validator(&mut state, ()).unwrap();
    let mut prepared = plan(&adapter, &mut gate);
    let digest = prepared.transaction_digest();
    // The actual transaction remains canonical; only local test metadata fails.
    prepared.roles.clear();
    match adapter.commit_strict_with_retained_cache_gate_v1(prepared, &mut gate) {
        Err(RetainedCommitFailureV1::AfterAppendSealing {
            pending,
            cause: ProtectedDomainJournalErrorV1::NonCanonicalRecord,
        }) => {
            assert_eq!(pending.prepared.transaction_digest(), digest);
            assert!(pending.prepared.roles.is_empty());
        }
        _ => panic!("sealing cannot discard pending or fabricate Applied"),
    }
}

#[test]
fn ordinary_readback_and_sealing_errors_keep_existing_distinct_diagnostics() {
    for sealing in [false, true] {
        let (_root, mut state, authority) = fixture();
        let mut gate = Journal::retain_cache_read_mutation_gate_v1(&state, &authority).unwrap();
        let mut adapter =
            ProtectedDomainJournalV1::<StateData>::claim_with_validator(&mut state, ()).unwrap();
        let mut prepared = plan(&adapter, &mut gate);
        drop(gate);
        if sealing {
            prepared.roles.clear();
        } else {
            prepared.after[0].push(0);
        }
        match (sealing, adapter.commit(prepared)) {
            (
                false,
                Ok(DomainCommitOutcomeV1::OutcomeUnknown {
                    cause: JournalError::AuthorityPreflightMismatch,
                    ..
                }),
            ) => {}
            (true, Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord)) => {}
            _ => panic!("ordinary error classification must remain unchanged"),
        }
    }
}
