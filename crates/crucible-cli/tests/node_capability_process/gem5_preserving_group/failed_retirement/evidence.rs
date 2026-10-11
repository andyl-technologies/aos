//! Checks exact retained no-archive data without constructing a release permit.
//!
//! The signed failure root is published before native release. These readers
//! check its original request/result, closed source roster, complete history
//! bytes and actual Shutdown/reaping data. They never read authentication keys
//! or turn the signature, a cached PID or a terminal flag into native authority.
//! The owning daemon's actual release path remains a separate conjunction.

use super::*;
use crucible_cas::content_store::{
    ContentId, DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend,
    ObjectKind, RefName,
};
use crucible_core::node_contract::{NodeRoute, SavedRuntimeActivation};
use crucible_node_contract::{HashRef, PreparedOwner, U64};
use crucible_node_provider::client::ExchangeDeadline;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

const INDEX_BYTES: u64 = 1024 * 1024;
const SOURCE_BODY_BYTES: u64 = 512 * 1024 * 1024;
const SOURCE_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const PRIVATE_ACK_BYTES: u64 = 65_536 * (2 * 516 + 128 + 9) + 64;
const HISTORY_BYTES: u64 = (16 + 3 * 16 + 64) * 1024 * 1024 + PRIVATE_ACK_BYTES;

type Checked<T> = Result<T, String>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedFailure {
    body: Failure,
    authentication: Bytes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Failure {
    format: String,
    version: u16,
    request: String,
    completion: String,
    activation: SavedRuntimeActivation,
    retained: Summary,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    format: String,
    version: u32,
    execution: String,
    route: String,
    request: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Summary {
    source_credit: ContentRef,
    source_index: ContentRef,
    metadata: ContentRef,
    histories: Vec<ContentRef>,
    shutdown: ContentRef,
    reaping: ContentRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceIndex {
    schema: String,
    credit: ContentRef,
    members: Vec<Mapping>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mapping {
    reference: ContentRef,
    identity: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceCredit {
    schema: String,
    source_world: HashRef,
    archive_credit: ContentRef,
    source_members: Vec<SourceMember>,
    runtime_bytes: usize,
    host_owners: usize,
    host_record_bytes: usize,
    native_record_bytes: usize,
    private_ack_bytes: usize,
    index_bytes: usize,
    source_index_bytes: usize,
    terminal_bytes: usize,
    maximum_history_roots: usize,
    complete_retained_bytes: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceMember {
    reference: ContentRef,
    role: SourceRole,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum SourceRole {
    SourceDefinition,
    InstalledArtifact,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    format: String,
    version: u16,
    source_credit: ContentRef,
    activation: SavedRuntimeActivation,
    runtime: RuntimeSnapshot,
    scheduler: crucible_core::node_scheduling::SchedulingSnapshot,
    owners: Vec<PreparedOwner>,
    coordinator: crucible_core::node_scheduling::InputPayload,
    nodes: Vec<Value>,
    histories: Vec<(NodeRoute, Vec<ContentRef>)>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Shutdown {
    format: String,
    version: u16,
    owner: Id,
    incarnation: Id,
    generation: U64,
    request: Vec<u8>,
    written: usize,
    received: Vec<u8>,
    acknowledged: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reaping {
    schema: String,
    owner: Id,
    incarnation: Id,
    generation: U64,
    pid: String,
    start_ticks: String,
    source_scope: Value,
    #[serde(deserialize_with = "required_nullable")]
    exit_code: Option<i32>,
    #[serde(deserialize_with = "required_nullable")]
    exit_signal: Option<i32>,
    remaining_group_members: Vec<Value>,
    graceful_shutdown: Graceful,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Graceful {
    written_bytes: String,
    received_bytes: Vec<u8>,
    acknowledged: bool,
    signal_fallback: bool,
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn error(value: impl std::fmt::Display) -> String {
    value.to_string()
}

fn require(condition: bool, detail: &str) -> Checked<()> {
    if condition {
        Ok(())
    } else {
        Err(detail.to_owned())
    }
}

fn root(refs: &dyn MutableRefBackend, name: &str) -> Checked<ContentId> {
    refs.read_ref(&RefName::new(name.to_owned()).map_err(error)?)
        .map_err(error)?
        .ok_or_else(|| format!("original root absent: {name}"))
}

fn body(blobs: &dyn ImmutableBlobBackend, identity: ContentId, maximum: u64) -> Checked<Vec<u8>> {
    require(
        identity.kind() == ObjectKind::Trace && identity.schema_version() == 1,
        "original retained CAS identity differs",
    )?;
    let bytes = blobs
        .read(identity, None)
        .map_err(error)?
        .read_all(maximum)
        .map_err(error)?;
    require(
        identity.authenticates(&bytes),
        "original retained CAS bytes differ",
    )?;
    Ok(bytes)
}

fn bounded_geometry<'a>(
    references: impl Iterator<Item = &'a ContentRef>,
    maximum: u64,
) -> Checked<()> {
    let mut total = 0_u64;
    let mut distinct = BTreeSet::new();
    for reference in references {
        require(
            distinct.insert(reference.clone()),
            "duplicate retained full content reference",
        )?;
        total = total
            .checked_add(reference.length.get())
            .ok_or("retained byte sum overflow")?;
        require(total <= maximum, "retained complete body credit exceeded")?;
    }
    Ok(())
}

/// Waits for original retained data without claiming native release from its root.
///
/// # Panics
/// Panics on invalid storage, expiration or inconsistent retained data. The
/// caller's same owning service guard remains live and retains its original Child.
pub(super) fn await_original(
    state: &Path,
    output: &Path,
    refused: &CapabilityPreparationRecord,
    baseline: &NodeScenario,
) -> Vec<u8> {
    let refs = DirectoryRefBackend::new(state.join("refs"));
    let name = RefName::new(format!(
        "node-capability-failed-retirement/{}",
        refused.execution
    ))
    .unwrap();
    let deadline = ExchangeDeadline::start(Duration::from_secs(1200)).unwrap();
    loop {
        deadline.remaining().unwrap();
        let original = refs.read_ref(&name).unwrap();
        let remaining = deadline.remaining().unwrap();
        if original.is_some() {
            break;
        }

        // Early or spurious wakes cannot renew the one original wait budget.
        std::thread::park_timeout(remaining.min(Duration::from_millis(100)));
        deadline.remaining().unwrap();
    }
    verify_original(state, output, refused, baseline, None).unwrap()
}

/// Checks the original complete data conjunction before or after owning retirement.
///
/// # Errors
/// Refuses changed roots/bodies/media/rosters, foreign original requests or owners,
/// missing Shutdown ACK, absent clean child/group proof or exhausted fixed credits.
pub(super) fn verify_original(
    state: &Path,
    output: &Path,
    refused: &CapabilityPreparationRecord,
    baseline: &NodeScenario,
    expected: Option<&[u8]>,
) -> Checked<Vec<u8>> {
    let blobs = DirectoryBlobBackend::new("original-failed-world", state.join("blobs"));
    let refs = DirectoryRefBackend::new(state.join("refs"));
    let execution = &refused.execution;
    let sealed = root(
        &refs,
        &format!("node-capability-failed-retirement/{execution}"),
    )?;
    let bytes = body(&blobs, sealed, 128 * 1024)?;
    require(
        expected.is_none_or(|expected| expected == bytes),
        "original failure seal changed",
    )?;
    let retained: SignedFailure = serde_json::from_slice(&bytes).map_err(error)?;
    let failure = &retained.body;
    require(
        failure.format == "crucible.capability-failed-retirement"
            && failure.version == 1
            && !retained.authentication.as_slice().is_empty()
            && failure.request == refused.request
            && failure.activation.owners.len() == 4,
        "original signed failure data scope differs",
    )?;
    // Authentication bytes stay opaque: only the actual owning daemon can use
    // its original operational authenticator in the native release conjunction.
    let completion = ContentId::parse(&failure.completion).map_err(error)?;
    for name in [
        "node-capability-preparations",
        "node-capability-native-results",
    ] {
        require(
            root(&refs, &format!("{name}/{execution}"))? == completion,
            "original refusal/result roots differ",
        )?;
    }
    let completion_bytes = body(&blobs, completion, 16 * 1024 * 1024)?;
    let completed: CapabilityPreparationRecord =
        serde_json::from_slice(&completion_bytes).map_err(error)?;
    require(
        serde_json::to_value(&completed).map_err(error)?
            == serde_json::to_value(refused).map_err(error)?,
        "original durable refusal differs",
    )?;
    let request_id = ContentId::parse(&refused.request).map_err(error)?;
    let request_bytes = body(&blobs, request_id, 4 * 1024 * 1024)?;
    let request: Value = serde_json::from_slice(&request_bytes).map_err(error)?;
    require(
        request["execution"] == *execution && request["action"]["operation"] == "capture",
        "same original capture request differs",
    )?;
    let claim_bytes = body(
        &blobs,
        root(
            &refs,
            &format!("node-original-preparation-claims/{execution}"),
        )?,
        4096,
    )?;
    let claim: Claim = serde_json::from_slice(&claim_bytes).map_err(error)?;
    require(
        claim.format == "crucible.original-node-preparation-claim"
            && claim.version == 1
            && claim.execution == *execution
            && claim.route == "capability"
            && claim.request == refused.request,
        "same original common claim differs",
    )?;

    let summary = &failure.retained;
    let index_bytes = body(
        &blobs,
        root(
            &refs,
            &format!("node-capability-failure-source/{execution}/index"),
        )?,
        INDEX_BYTES,
    )?;
    summary.source_index.verify(&index_bytes).map_err(error)?;
    let index: SourceIndex = serde_json::from_slice(&index_bytes).map_err(error)?;
    require(
        index.schema == "crucible.independent-group.failed-source-index.v1"
            && index.credit == summary.source_credit
            && index.members.len() <= 4097,
        "complete original source index differs",
    )?;
    bounded_geometry(
        index.members.iter().map(|member| &member.reference),
        SOURCE_TOTAL_BYTES,
    )?;
    let credit = index
        .members
        .iter()
        .find(|member| member.reference == index.credit)
        .ok_or("original source credit body absent")?;
    let credit_bytes = read_member(&blobs, &refs, execution, credit, INDEX_BYTES)?;
    let credit: SourceCredit = serde_json::from_slice(&credit_bytes).map_err(error)?;
    require(
        credit.schema == "crucible.independent-group.failure-retirement-credit.v2"
            && credit.source_world == failure.activation.world_binding_hash,
        "original source-born world differs",
    )?;
    require(
        credit.runtime_bytes == 16 * 1024 * 1024
            && credit.host_owners == 3
            && credit.host_record_bytes == 16 * 1024 * 1024
            && credit.native_record_bytes == 64 * 1024 * 1024
            && credit.private_ack_bytes == PRIVATE_ACK_BYTES as usize
            && credit.index_bytes == INDEX_BYTES as usize
            && credit.source_index_bytes == INDEX_BYTES as usize
            && credit.terminal_bytes == 256 * 1024
            && credit.maximum_history_roots == 16
            && credit.complete_retained_bytes <= SOURCE_TOTAL_BYTES as usize,
        "original prebirth source/history ceilings differ",
    )?;
    let declared: BTreeSet<_> = credit
        .source_members
        .iter()
        .map(|member| member.reference.clone())
        .collect();
    require(
        declared.len() == credit.source_members.len()
            && declared.contains(&credit.archive_credit)
            && index.members.len() == declared.len() + 1
            && index.members.iter().all(|member| {
                member.reference == index.credit || declared.contains(&member.reference)
            }),
        "original typed source roster differs",
    )?;
    for member in &credit.source_members {
        if matches!(member.role, SourceRole::InstalledArtifact) {
            require(
                member.reference.media_type == "application/octet-stream",
                "installed artifact media differs",
            )?;
        }
    }
    for member in &index.members {
        read_member(&blobs, &refs, execution, member, SOURCE_BODY_BYTES)?;
    }

    let expected_histories: BTreeSet<_> = summary
        .histories
        .iter()
        .cloned()
        .chain([summary.shutdown.clone(), summary.reaping.clone()])
        .collect();
    require(
        summary.histories.len() == 7
            && expected_histories.len() == 9
            && summary.histories.contains(&summary.metadata),
        "complete history/terminal roster differs",
    )?;
    bounded_geometry(summary.histories.iter(), HISTORY_BYTES)?;
    require(
        summary.shutdown.length.get() <= 64 * 1024 && summary.reaping.length.get() <= 64 * 1024,
        "original terminal credit differs",
    )?;
    let namespace = RefName::new(format!(
        "node-capability-failure-source/{execution}/history"
    ))
    .map_err(error)?;
    let page = refs.scan_refs(&namespace, None, 16).map_err(error)?;
    require(
        page.next_after().is_none() && page.entries().len() == 9,
        "complete original history roots differ",
    )?;
    // Check actual retained stream geometry before copying any historical body.
    // The public index bounds exact data custody, not parser transient allocation.
    let expected_bytes = expected_histories
        .iter()
        .try_fold(0_u64, |total, reference| {
            total
                .checked_add(reference.length.get())
                .ok_or("complete history byte sum overflow")
        })?;
    let mut total = 0_u64;
    let mut handles = Vec::with_capacity(9);
    for entry in page.entries() {
        require(
            entry.name().as_str() == format!("{}/{}", namespace.as_str(), entry.target().encode()),
            "history root does not name its exact original CAS body",
        )?;
        let handle = blobs.read(entry.target(), None).map_err(error)?;
        total = total
            .checked_add(handle.logical_length())
            .ok_or("actual history byte sum overflow")?;
        require(
            total <= expected_bytes
                && handle.logical_length() <= PRIVATE_ACK_BYTES.max(64 * 1024 * 1024),
            "actual original history stream exceeds precredited geometry",
        )?;
        handles.push((entry.target(), handle));
    }
    require(
        total == expected_bytes,
        "actual complete history length differs",
    )?;
    let mut histories = BTreeMap::new();
    for (identity, handle) in handles {
        require(
            identity.kind() == ObjectKind::Trace && identity.schema_version() == 1,
            "original history CAS identity differs",
        )?;
        let content = handle
            .read_all(PRIVATE_ACK_BYTES.max(64 * 1024 * 1024))
            .map_err(error)?;
        require(
            identity.authenticates(&content),
            "original history CAS bytes differ",
        )?;
        let matches: Vec<_> = expected_histories
            .iter()
            .filter(|reference| reference.verify(&content).is_ok())
            .collect();
        require(
            matches.len() == 1,
            "missing, foreign or ambiguous original history body",
        )?;
        require(
            histories.insert((*matches[0]).clone(), content).is_none(),
            "duplicate original history body",
        )?;
    }
    let metadata_bytes = histories
        .get(&summary.metadata)
        .ok_or("original metadata absent")?;
    require(
        summary.metadata.media_type == "application/json"
            && metadata_bytes.len() <= 16 * 1024 * 1024,
        "original metadata grammar/credit differs",
    )?;
    let metadata: Metadata = serde_json::from_slice(metadata_bytes).map_err(error)?;
    verify_metadata(&metadata, failure, baseline, execution)?;
    let cpu = metadata
        .histories
        .iter()
        .find(|(route, _)| route.node.as_str() == "cpu")
        .ok_or("original CPU route absent")?;
    require(
        cpu.0.owners.len() == 1 && cpu.1.len() == 3,
        "original CPU custody roster differs",
    )?;
    verify_terminal(&histories, summary, &cpu.0)?;

    if expected.is_none() {
        fs::write(output.join("failed-retirement.json"), &bytes).map_err(error)?;
        for (name, reference) in [
            ("original-failure-history.json", &summary.metadata),
            ("original-shutdown.json", &summary.shutdown),
            ("original-reaping.json", &summary.reaping),
        ] {
            fs::write(
                output.join(name),
                histories
                    .get(reference)
                    .ok_or("retained selected body absent")?,
            )
            .map_err(error)?;
        }
    }
    Ok(bytes)
}

fn read_member(
    blobs: &dyn ImmutableBlobBackend,
    refs: &dyn MutableRefBackend,
    execution: &str,
    member: &Mapping,
    maximum: u64,
) -> Checked<Vec<u8>> {
    require(
        member.reference.length.get() <= maximum,
        "source body exceeds selected reader credit",
    )?;
    let identity = ContentId::parse(&member.identity).map_err(error)?;
    require(
        root(
            refs,
            &format!(
                "node-capability-failure-source/{execution}/{}",
                identity.encode()
            ),
        )? == identity,
        "original direct source root differs",
    )?;
    let handle = blobs.read(identity, None).map_err(error)?;
    require(
        handle.logical_length() == member.reference.length.get(),
        "actual source stream differs from borrowed precredit",
    )?;
    let bytes = handle.read_all(maximum).map_err(error)?;
    require(
        identity.kind() == ObjectKind::Trace
            && identity.schema_version() == 1
            && identity.authenticates(&bytes),
        "original source CAS identity/bytes differ",
    )?;
    member.reference.verify(&bytes).map_err(error)?;
    Ok(bytes)
}

fn verify_metadata(
    metadata: &Metadata,
    failure: &Failure,
    baseline: &NodeScenario,
    execution: &str,
) -> Checked<()> {
    require(
        metadata.format == "crucible.independent-group.original-failure-history"
            && metadata.version == 1
            && metadata.source_credit == failure.retained.source_credit
            && metadata.activation == failure.activation
            && metadata.runtime.source_activation == metadata.activation
            && metadata.runtime.schema_version == 1
            && metadata.runtime.condition_stop.is_none()
            && metadata.runtime.terminal.is_none(),
        "original operational metadata scope differs",
    )?;
    require(
        metadata.owners.len() == 4 && metadata.nodes.len() == 4 && metadata.histories.len() == 4,
        "complete original preparation roster absent",
    )?;
    metadata
        .coordinator
        .reference
        .verify(&metadata.coordinator.bytes)
        .map_err(error)?;
    let selected: BTreeSet<_> = baseline
        .descriptors
        .iter()
        .map(|node| node.id.clone())
        .collect();
    let routed: BTreeSet<_> = metadata
        .histories
        .iter()
        .map(|(route, _)| route.node.clone())
        .collect();
    require(
        selected.len() == 4 && selected == routed,
        "original selected node/history roster differs",
    )?;
    let owners: BTreeSet<_> = metadata.activation.owners.iter().cloned().collect();
    let prepared: BTreeSet<_> = metadata
        .owners
        .iter()
        .map(|owner| crucible_core::node_contract::OwnerIdentity {
            owner: owner.owner_id.clone(),
            incarnation: owner.incarnation_id.clone(),
            generation: owner.owner_generation,
        })
        .collect();
    require(
        owners.len() == 4 && owners == prepared,
        "original prepared owners differ from actual activation",
    )?;
    let mut routed_owners = BTreeSet::new();
    for (route, records) in &metadata.histories {
        require(
            route.owners.len() == 1
                && owners.contains(&route.owners[0])
                && routed_owners.insert(route.owners[0].clone())
                && records.len() == if route.node.as_str() == "cpu" { 3 } else { 1 },
            "original history route/role differs",
        )?;
    }
    let actual: BTreeSet<_> = std::iter::once(failure.retained.metadata.clone())
        .chain(
            metadata
                .histories
                .iter()
                .flat_map(|(_, records)| records.iter().cloned()),
        )
        .collect();
    require(
        actual.len() == 7 && actual == failure.retained.histories.iter().cloned().collect(),
        "closed original metadata/history references differ",
    )?;
    require(
        metadata
            .runtime
            .operations
            .iter()
            .any(|operation| operation.route.node.as_str() == "cpu"),
        "refusal did not retain an original CPU operation",
    )?;
    let mut operations = BTreeSet::new();
    for operation in &metadata.runtime.operations {
        require(
            operations.insert(operation.operation.clone())
                && operation.operation.as_str()
                    == format!("capability/{}/0/{}", execution, operation.route.node)
                && selected.contains(&operation.route.node),
            "original one-round operation identity/route differs",
        )?;
        let SavedRuntimeResult::Acknowledged(outcome) = &operation.result else {
            return Err("first round did not preserve completed original ACKs".to_owned());
        };
        let commit = operation
            .scheduling_commit
            .as_ref()
            .ok_or("original scheduling commitment absent")?;
        require(
            outcome.operation == operation.operation
                && outcome.node == operation.route.node
                && outcome.owners == operation.route.owners
                && commit.operation == operation.operation
                && commit.node == operation.route.node
                && commit.retained_outputs == outcome.retained_outputs,
            "original operation/private ACK association differs",
        )?;
    }
    // Runtime/Scheduler remain their complete exact source-owned bodies. This
    // data reader does not recreate a scheduler or infer native pending state.
    require(
        metadata.scheduler.capture_cut == metadata.runtime.capture_cut,
        "original runtime/scheduler cut differs",
    )
}

fn verify_terminal(
    histories: &BTreeMap<ContentRef, Vec<u8>>,
    summary: &Summary,
    cpu: &NodeRoute,
) -> Checked<()> {
    require(
        summary.shutdown.media_type == "application/json"
            && summary.reaping.media_type == "application/json",
        "terminal media differs",
    )?;
    let shutdown: Shutdown =
        serde_json::from_slice(histories.get(&summary.shutdown).ok_or("Shutdown absent")?)
            .map_err(error)?;
    let reaping: Reaping =
        serde_json::from_slice(histories.get(&summary.reaping).ok_or("reaping absent")?)
            .map_err(error)?;
    let owner = &cpu.owners[0];
    let frame = b"\0\0\0\x13{\"kind\":\"shutdown\"}";
    require(
        shutdown.format == "crucible.gem5.retirement-shutdown-history"
            && shutdown.version == 1
            && shutdown.owner == owner.owner
            && shutdown.incarnation == owner.incarnation
            && shutdown.generation == owner.generation
            && shutdown.request == frame
            && shutdown.written == frame.len()
            && shutdown.received == frame
            && shutdown.acknowledged,
        "same original complete Shutdown exchange absent",
    )?;
    require(
        reaping.schema == "crucible.gem5.native-reclamation.v1"
            && reaping.owner == owner.owner
            && reaping.incarnation == owner.incarnation
            && reaping.generation == owner.generation
            && reaping.pid.parse::<u32>().is_ok_and(|pid| pid > 0)
            && reaping
                .start_ticks
                .parse::<u64>()
                .is_ok_and(|ticks| ticks > 0)
            && reaping
                .source_scope
                .as_object()
                .is_some_and(|scope| !scope.is_empty())
            && reaping.exit_code == Some(0)
            && reaping.exit_signal.is_none()
            && reaping.remaining_group_members.is_empty()
            && reaping.graceful_shutdown.written_bytes == frame.len().to_string()
            && reaping.graceful_shutdown.received_bytes == frame
            && reaping.graceful_shutdown.acknowledged
            && !reaping.graceful_shutdown.signal_fallback,
        "same original clean child/group proof absent",
    )
}

#[cfg(test)]
#[path = "evidence_tests.rs"]
mod tests;
