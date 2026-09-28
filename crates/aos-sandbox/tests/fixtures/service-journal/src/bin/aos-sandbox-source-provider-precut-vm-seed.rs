//! Seeds one VM-only native Provider recovery cut after a real fixed handshake.
//!
//! The signed Acquire belongs to the retained session in the protected journal.
//! This fixture has no Provider signing key or backend effect authority. Its
//! only durable effect is an Applying/Reserved graph with terminal headroom.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use aos_sandbox::{
    GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRecoveryBindingV1,
    GlobalCapacityReservationRequestV1, Journal, JournalLimits, JournalRecord, JournalTransaction,
    RecordNamespace,
};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_ledger::identity::{
    acquire_effect_id_v1, acquire_native_no_dispatch_id_v1,
};
use aos_sandbox_source_provider_ledger::ledger::format::{
    acquisition_key, attempt_key, decode_record, encode_acquisition, encode_attempt,
    encode_catalog, encode_session, encode_session_history, record_digest, session_history_key,
    session_key,
};
use aos_sandbox_source_provider_ledger::ledger::model::{
    AcquisitionKeyV1, AcquisitionRecordV1, AttemptKeyV1, AttemptRecordV1, AuthorityHeadRecordV1,
    CatalogHeadRecordV1, DecodedRecordV1, HolderSessionHeadRecordV1, ProviderAcquisitionStateV1,
    ProviderAttemptStateV1,
};
use aos_sandbox_source_provider_ledger::{
    LedgerFormatErrorV1, NormalizedAcquisitionIntentV1, validate_prospective_records,
    validate_prospective_transition,
};
use aos_sandbox_source_provider_protocol::{
    ProviderHeldSnapshotCatalogV1, SignedSourceProviderHelloV1, SignedSourceProviderRequestV1,
    SourceProviderMethod, decode_acquire_request, digest_acquire_request, digest_signed_request,
    source_provider_request_attempt_digest_v1, verify_request,
};
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

const STATE_ROOT: &str = "/var/lib/aos/source-provider";
const JOURNAL_NAME: &str = "provider.journal";
const ROOT_RECORD_SEED: [u8; 32] = [12; 32];
const ZERO_DIGEST: ObjectDigest = ObjectDigest::from_bytes([0; 32]);
const TERMINAL_BYTES: u64 = 3 * 1024 * 1024;
const TERMINAL_RECORDS: u32 = 5;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn main() {
    if let Err(error) = run() {
        eprintln!("native Provider pre-cut fixture failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut arguments = std::env::args().skip(1);
    let signed_path = arguments.next().ok_or("missing signed Acquire file")?;
    if rustix::process::geteuid().as_raw() != 0 {
        return Err("fixed Provider pre-cut fixture requires UID 0".into());
    }
    if signed_path == "catalog-head" {
        if arguments.next().is_some() {
            return Err("catalog-head takes no additional arguments".into());
        }
        return print_catalog_head();
    }
    let publication_path = arguments.next().ok_or("missing catalog publication file")?;
    let held_path = arguments
        .next()
        .ok_or("missing held-snapshot catalog file")?;
    if arguments.next().is_some() {
        return Err("unexpected extra argument".into());
    }
    let signed_bytes = fs::read(signed_path)?;
    let publication_bytes = fs::read(publication_path)?;
    let held_bytes = fs::read(held_path)?;
    let (mut journal, _) =
        Journal::open_existing_protected_at(STATE_ROOT, JOURNAL_NAME, JournalLimits::default())?;
    let mut authority = journal.claim_source_provider_native_terminal_authority_v1()?;
    let current: BTreeMap<Vec<u8>, Vec<u8>> = authority
        .records()?
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect();
    checked_ledger(validate_prospective_records(records(&current)))?;

    let (mutated, capacity, changed) =
        prepare_cut(&current, &signed_bytes, &publication_bytes, &held_bytes)?;
    checked_ledger(validate_prospective_transition(
        records(&current),
        records(&mutated),
    ))?;

    let transaction_id = transaction_id(&changed)?;
    let prepared = authority.prepare_global_capacity_reservation_v1(capacity, transaction_id)?;
    let mut journal_records: Vec<_> = changed
        .into_iter()
        .map(|(key, value)| {
            JournalRecord::put(RecordNamespace::SourceProviderAuthority, key, value)
        })
        .collect();
    journal_records.push(prepared.record().clone());
    let transaction = JournalTransaction::new(transaction_id, journal_records)?;
    let preflight = authority.preflight_global_capacity_reservation_v1(&prepared, &transaction)?;
    let (_, reserved_capacity) =
        authority.commit_global_capacity_reservation_v1(&preflight, prepared, &transaction)?;
    if reserved_capacity.request() != capacity {
        return Err("committed native capacity differs from Applying record".into());
    }
    drop(authority);
    drop(journal);

    let (mut reopened, _) =
        Journal::open_existing_protected_at(STATE_ROOT, JOURNAL_NAME, JournalLimits::default())?;
    let reopened = reopened.claim_source_provider_native_terminal_authority_v1()?;
    let cold: BTreeMap<Vec<u8>, Vec<u8>> = reopened
        .records()?
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect();
    if cold != mutated {
        return Err("cold replay changed the exact Provider graph".into());
    }
    checked_ledger(validate_prospective_records(records(&cold)))?;
    let reservation =
        reopened.recover_unique_global_capacity_reservation_v1(&capacity_binding(capacity))?;
    if reservation.request() != capacity {
        return Err("cold capacity reservation differs from Applying record".into());
    }
    reopened.validate_global_capacity_reservation_set_v1(&BTreeSet::from([
        reservation.reservation_id()
    ]))?;
    println!("source-provider-native-precut:PASS");
    Ok(())
}

fn print_catalog_head() -> Result<()> {
    let (mut journal, _) =
        Journal::open_existing_protected_at(STATE_ROOT, JOURNAL_NAME, JournalLimits::default())?;
    let authority = journal.claim_source_provider_native_terminal_authority_v1()?;
    let records: BTreeMap<Vec<u8>, Vec<u8>> = authority
        .records()?
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect();
    checked_ledger(validate_prospective_records(self::records(&records)))?;

    let mut head = None;
    let mut catalog = None;
    for (key, bytes) in &records {
        match checked_ledger(decode_record(key, bytes))? {
            DecodedRecordV1::Authority(value) => unique(&mut head, value)?,
            DecodedRecordV1::Catalog(value) => {
                if catalog
                    .as_ref()
                    .is_none_or(|current: &CatalogHeadRecordV1| {
                        value.catalog_generation > current.catalog_generation
                    })
                {
                    catalog = Some(value);
                }
            }
            _ => {}
        }
    }
    let head: AuthorityHeadRecordV1 = head.ok_or("missing fixed Provider authority")?;
    let catalog: CatalogHeadRecordV1 = catalog.ok_or("missing fixed Provider catalog")?;
    if catalog.provider != head.provider
        || catalog.catalog_generation != head.catalog_generation
        || catalog.catalog_digest != head.catalog_digest
    {
        return Err("current Provider catalog head disagrees with authority".into());
    }

    let mut hash = Sha256::new();
    hash.update(b"aos.sandbox.source-provider.current-catalog-publication-head.v1\0");
    hash.update(encode_catalog(&catalog));
    let digest: [u8; 32] = hash.finalize().into();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        write!(&mut hex, "{byte:02x}")?;
    }
    println!("{hex}");
    Ok(())
}

fn records(map: &BTreeMap<Vec<u8>, Vec<u8>>) -> impl Iterator<Item = (&[u8], &[u8])> {
    map.iter()
        .map(|(key, value)| (key.as_slice(), value.as_slice()))
}

fn checked_ledger<T>(result: std::result::Result<T, LedgerFormatErrorV1>) -> Result<T> {
    result.map_err(|error| format!("Provider ledger rejected fixture graph: {error:?}").into())
}

fn prepare_cut(
    current: &BTreeMap<Vec<u8>, Vec<u8>>,
    signed_bytes: &[u8],
    publication_bytes: &[u8],
    held_bytes: &[u8],
) -> Result<(
    BTreeMap<Vec<u8>, Vec<u8>>,
    GlobalCapacityReservationRequestV1,
    Vec<(Vec<u8>, Vec<u8>)>,
)> {
    let signed = SignedSourceProviderRequestV1::from_canonical_bytes(signed_bytes)?;
    if signed.to_canonical_bytes() != signed_bytes
        || signed.method() != SourceProviderMethod::Acquire
    {
        return Err("signed request is not a canonical Acquire".into());
    }
    let request = decode_acquire_request(signed.subject())?;
    if request.kernel_coupled() {
        return Err("native pre-cut requires proofless, non-kernel-coupled Acquire".into());
    }

    let mut authority = None;
    let mut catalog = None;
    let mut session = None;
    for (key, bytes) in current {
        match checked_ledger(decode_record(key, bytes))? {
            DecodedRecordV1::Authority(value) => unique(&mut authority, value)?,
            DecodedRecordV1::Catalog(value) => {
                if catalog.as_ref().is_none_or(|head: &CatalogHeadRecordV1| {
                    value.catalog_generation > head.catalog_generation
                }) {
                    catalog = Some(value);
                }
            }
            DecodedRecordV1::Session(value)
                if value.holder.authority_id() == request.holder_authority_id() =>
            {
                unique(&mut session, value)?
            }
            DecodedRecordV1::Attempt(_)
            | DecodedRecordV1::Acquisition(_)
            | DecodedRecordV1::Release(_) => {
                return Err("pre-cut fixture requires a fresh Provider graph".into());
            }
            _ => {}
        }
    }
    let authority: AuthorityHeadRecordV1 = authority.ok_or("missing real Provider authority")?;
    let catalog: CatalogHeadRecordV1 = catalog.ok_or("missing authenticated catalog")?;
    let mut session: HolderSessionHeadRecordV1 = session.ok_or("missing actual holder session")?;
    if authority.provider != session.provider
        || catalog.provider != authority.provider
        || catalog.canonical_publication != publication_bytes
        || authority.catalog_generation != catalog.catalog_generation
        || authority.catalog_digest != catalog.catalog_digest
        || session.pending_attempt_digest.is_some()
        || session.signers[1] != *signed.signer()
        || session.session_binding != request.session_binding()
        || session.next_request_sequence != request.sequence()
        || session.next_acquisition_sequence != request.acquisition_sequence()
        || session.holder.authority_generation() != request.holder_generation()
        || session.holder.authority_digest() != request.holder_authority_digest()
        || session.revocation_digest != request.revocation_digest()
    {
        return Err(
            "Acquire does not match the actual authenticated old session and catalog".into(),
        );
    }
    verify_request(
        &signed,
        &SigningKey::from_bytes(&ROOT_RECORD_SEED)
            .verifying_key()
            .to_bytes(),
    )?;

    let held = ProviderHeldSnapshotCatalogV1::from_canonical_bytes(held_bytes)?;
    if held.to_canonical_bytes() != held_bytes {
        return Err("held-snapshot catalog is not canonical".into());
    }
    let (resource, _) = held.select_under_head(
        catalog.catalog_generation,
        catalog.catalog_digest,
        catalog.resource_namespace_digest,
        request.binding_digest(),
    )?;
    if resource.resource_namespace_digest() != session.resource_namespace_digest {
        return Err("selected native resource crosses Provider namespace".into());
    }

    let now: i64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()?;
    if now < authority.valid_from_seconds
        || now >= request.deadline_seconds()
        || request.deadline_seconds() > authority.valid_until_seconds
    {
        return Err("Acquire is not within the real Provider authority validity".into());
    }
    let attempt_digest = source_provider_request_attempt_digest_v1(
        signed.signer(),
        signed.method(),
        request.request_id(),
    );
    let provider_hello =
        SignedSourceProviderHelloV1::from_canonical_bytes(&session.provider_hello)?;
    let negotiated_capabilities = provider_hello.subject();
    let normalized = NormalizedAcquisitionIntentV1::from_acquire_request(
        &request,
        authority.provider.clone(),
        session.holder.clone(),
        request.node_id(),
        request.boot_id(),
        session.route_id,
        session.route_generation,
        session.route_digest,
        session.resource_namespace_digest,
        session.revocation_generation,
        session.revocation_digest,
    )?;
    let effect_id = acquire_effect_id_v1(request.acquisition_id(), attempt_digest)
        .ok_or("zero derived effect ID")?;
    let backend_id = acquire_native_no_dispatch_id_v1(
        normalized.digest(),
        catalog.catalog_generation,
        catalog.catalog_digest,
    );
    let attempt = reserved_attempt(
        &signed,
        &request,
        &session,
        negotiated_capabilities.proof_class_capabilities(),
        negotiated_capabilities.supports_recursive(),
        negotiated_capabilities.supports_kernel_coupled(),
        normalized.digest(),
        attempt_digest,
        now,
    );

    session.revision = session
        .revision
        .checked_add(1)
        .ok_or("session revision exhausted")?;
    session.next_request_sequence = session
        .next_request_sequence
        .checked_add(1)
        .ok_or("request sequence exhausted")?;
    session.next_acquisition_sequence = session
        .next_acquisition_sequence
        .checked_add(1)
        .ok_or("acquisition sequence exhausted")?;
    session.pending_attempt_digest = Some(attempt_digest);

    let acquisition = AcquisitionRecordV1 {
        revision: 1,
        state: ProviderAcquisitionStateV1::Applying,
        provider: authority.provider,
        holder: session.holder.clone(),
        acquisition_id: request.acquisition_id(),
        acquisition_sequence: request.acquisition_sequence(),
        effect_id,
        normalized_intent: normalized,
        effect_attempt_digest: attempt_digest,
        current_attempt_digest: attempt_digest,
        lease_attempt_digest: None,
        lease_issue_generation: 0,
        lease_id: None,
        lease_digest: None,
        lease_history: Vec::new(),
        resource_namespace_digest: session.resource_namespace_digest,
        resource_id: resource.resource_id(),
        resource_generation: resource.resource_generation(),
        resource_digest: resource.resource_digest(),
        catalog_generation: catalog.catalog_generation,
        catalog_digest: catalog.catalog_digest,
        selection_generation: resource.selection_generation(),
        selection_digest: resource.selection_digest(),
        proof_class: 0,
        proof_digest: ZERO_DIGEST,
        resource_commitment: ZERO_DIGEST,
        backend_id,
        backend_lineage_digest: lineage_digest(
            &session,
            attempt_digest,
            request.acquisition_id(),
            effect_id,
            backend_id,
        ),
        native_no_dispatch_reservation_digest: None,
        backend_evidence: None,
        reopen_identity: None,
        source_root: None,
        release_effect_id: None,
        signed_lease: Vec::new(),
    };
    let attempt_identity = AttemptKeyV1 {
        provider_id: session.provider.authority_id(),
        holder_id: session.holder.authority_id(),
        root_record_key_id: signed.signer().key_id(),
        method: SourceProviderMethod::Acquire as u8,
        request_id: request.request_id(),
    };
    let acquisition_identity = AcquisitionKeyV1 {
        provider_id: session.provider.authority_id(),
        holder_id: session.holder.authority_id(),
        acquisition_id: request.acquisition_id(),
    };
    // Preserve production reserve-acquire order in the transaction identity.
    let changed = vec![
        (attempt_key(&attempt_identity), encode_attempt(&attempt)),
        (
            acquisition_key(&acquisition_identity),
            encode_acquisition(&acquisition),
        ),
        (
            session_key(
                session.provider.authority_id(),
                session.holder.authority_id(),
            ),
            encode_session(&session),
        ),
        (
            session_history_key(
                session.provider.authority_id(),
                session.holder.authority_id(),
                session.session_binding,
            ),
            encode_session_history(&session),
        ),
    ];
    if changed
        .iter()
        .any(|(key, value)| current.get(key) == Some(value))
    {
        return Err("pre-cut must change attempt, acquisition, session, and history".into());
    }
    let mut prospective = current.clone();
    for (key, value) in &changed {
        prospective.insert(key.clone(), value.clone());
    }
    let capacity = capacity_request(&acquisition, &attempt, &session)?;
    Ok((prospective, capacity, changed))
}

fn unique<T>(slot: &mut Option<T>, value: T) -> Result<()> {
    if slot.replace(value).is_some() {
        return Err("duplicate protected head".into());
    }
    Ok(())
}

fn reserved_attempt(
    signed: &SignedSourceProviderRequestV1,
    request: &aos_sandbox_source_provider_protocol::AcquireSourceRequestV1,
    session: &HolderSessionHeadRecordV1,
    proof_class_capabilities: u8,
    supports_recursive: bool,
    supports_kernel_coupled: bool,
    intent_digest: ObjectDigest,
    attempt_digest: ObjectDigest,
    now: i64,
) -> AttemptRecordV1 {
    let signed_digest = digest_signed_request(signed);
    AttemptRecordV1 {
        revision: 1,
        state: ProviderAttemptStateV1::Reserved,
        provider: session.provider.clone(),
        holder: session.holder.clone(),
        root_record_signer: signed.signer().clone(),
        method: SourceProviderMethod::Acquire,
        status: None,
        request_id: request.request_id(),
        signed_request_digest: signed_digest,
        typed_request_digest: digest_acquire_request(request),
        operation_intent_digest: intent_digest,
        acquisition_sequence: request.acquisition_sequence(),
        attempt_digest,
        session_binding: session.session_binding,
        request_sequence: request.sequence(),
        response_sequence: None,
        deadline_seconds: request.deadline_seconds(),
        verified_at_seconds: now,
        completed_at_seconds: None,
        // The signed deadline is a conservative bound on the recorded fixture
        // verification window; it never claims a longer live session lifetime.
        current_valid_until_seconds: request.deadline_seconds(),
        proof_class_capabilities,
        supports_recursive,
        supports_kernel_coupled,
        root_process_instance: session.root_process_instance,
        provider_process_instance: session.provider_process_instance,
        signer_set_commitment: session.signer_set_commitment,
        recovery_predecessor_attempt_digest: None,
        recovery_predecessor_session_binding: None,
        recovery_fence_digest: None,
        recovery_fence_class: 0,
        recovery_revocation_generation: 0,
        recovery_revocation_digest: ZERO_DIGEST,
        signed_request_digest_again: signed_digest,
        response_digest: None,
        descriptor_commitment: ZERO_DIGEST,
        result_digest: None,
        response_catalog_generation: 0,
        response_catalog_digest: ZERO_DIGEST,
        signed_request: signed.to_canonical_bytes(),
        completed_response: Vec::new(),
    }
}

fn lineage_digest(
    session: &HolderSessionHeadRecordV1,
    attempt_digest: ObjectDigest,
    acquisition_id: ObjectDigest,
    effect_id: [u8; 16],
    backend_id: [u8; 32],
) -> ObjectDigest {
    let mut hash = Sha256::new();
    hash.update(b"aos.sandbox.source-provider.acquire-lineage.v1\0");
    hash.update(session.provider.authority_id());
    hash.update(session.holder.authority_id());
    hash.update(session.session_binding.as_bytes());
    hash.update(attempt_digest.as_bytes());
    hash.update(acquisition_id.as_bytes());
    hash.update(effect_id);
    hash.update([0; 16]);
    hash.update([0; 32]);
    hash.update(backend_id);
    ObjectDigest::from_bytes(hash.finalize().into())
}

fn capacity_request(
    acquisition: &AcquisitionRecordV1,
    attempt: &AttemptRecordV1,
    session: &HolderSessionHeadRecordV1,
) -> Result<GlobalCapacityReservationRequestV1> {
    let mut owner = Sha256::new();
    owner.update(b"aos.sandbox.source-provider.native-capacity-owner.v1\0");
    owner.update(acquisition.provider.authority_id());
    owner.update(acquisition.holder.authority_id());
    owner.update(acquisition.acquisition_id.as_bytes());
    Ok(GlobalCapacityReservationRequestV1 {
        purpose: GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal,
        owner_namespace: RecordNamespace::SourceProviderAuthority,
        owner_id: owner.finalize().into(),
        owner_digest: *checked_ledger(record_digest(&encode_acquisition(acquisition)))?.as_bytes(),
        operation_id: acquisition.effect_id,
        artifact_digest: *attempt.attempt_digest.as_bytes(),
        checkpoint_digest: *attempt.signed_request_digest.as_bytes(),
        chain_head_digest: *session.session_binding.as_bytes(),
        future_transactions: 1,
        terminal_records: TERMINAL_RECORDS,
        terminal_bytes: TERMINAL_BYTES,
        poison_records: TERMINAL_RECORDS,
        poison_bytes: TERMINAL_BYTES,
    })
}

fn capacity_binding(
    request: GlobalCapacityReservationRequestV1,
) -> GlobalCapacityReservationRecoveryBindingV1 {
    GlobalCapacityReservationRecoveryBindingV1 {
        purpose: request.purpose,
        operation_id: request.operation_id,
        artifact_digest: request.artifact_digest,
        checkpoint_digest: request.checkpoint_digest,
        chain_head_digest: request.chain_head_digest,
        future_transactions: request.future_transactions,
        terminal_records: request.terminal_records,
        terminal_bytes: request.terminal_bytes,
        poison_records: request.poison_records,
        poison_bytes: request.poison_bytes,
    }
}

fn transaction_id(changed: &[(Vec<u8>, Vec<u8>)]) -> Result<[u8; 16]> {
    let mut hash = Sha256::new();
    hash.update(b"aos.sandbox.source-provider.ledger.transaction-id.v1\0");
    hash.update((b"reserve-acquire".len() as u32).to_be_bytes());
    hash.update(b"reserve-acquire");
    for (key, value) in changed {
        hash.update((key.len() as u32).to_be_bytes());
        hash.update(key);
        hash.update([1]);
        hash.update(checked_ledger(record_digest(value))?.as_bytes());
    }
    let digest: [u8; 32] = hash.finalize().into();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    Ok(id)
}
