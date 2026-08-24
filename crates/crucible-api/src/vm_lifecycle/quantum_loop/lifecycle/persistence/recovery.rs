//! Bounded decoding and semantic validation for durable lifecycle run state.

use super::*;
use serde::de::{DeserializeOwned, IgnoredAny, MapAccess, SeqAccess, Visitor};
use std::io::Read as _;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductionRunStatePreflight {
    version: u32,
    runtime_event_records: u64,
    runtime_event_log_bytes: u64,
    manifest: ProductionRunManifestPreflight,
    journal: ProductionLifecycleJournalPreflight,
}

#[derive(serde::Deserialize)]
struct ProductionRunManifestPreflight {
    #[serde(rename = "version")]
    _version: IgnoredAny,
    #[serde(rename = "scenario")]
    _scenario: IgnoredAny,
    #[serde(rename = "owner")]
    _owner: IgnoredAny,
    processes: CountedMap,
    staged_processes: CountedMap,
    #[serde(rename = "clean_shutdown")]
    _clean_shutdown: IgnoredAny,
    #[serde(rename = "recovered_after_host_exit")]
    _recovered_after_host_exit: IgnoredAny,
}

#[derive(serde::Deserialize)]
struct ProductionLifecycleJournalPreflight {
    #[serde(rename = "version")]
    _version: IgnoredAny,
    #[serde(rename = "transaction")]
    _transaction: IgnoredAny,
    #[serde(rename = "phase")]
    _phase: IgnoredAny,
    nodes: CountedSequence,
    completed_exits: CountedSequence,
}

struct CountedMap(u64);

impl<'de> serde::Deserialize<'de> for CountedMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct CountedMapVisitor;

        impl<'de> Visitor<'de> for CountedMapVisitor {
            type Value = CountedMap;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a bounded process-ownership map")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut count = 0_u64;
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
                    count = count.checked_add(1).ok_or_else(|| {
                        serde::de::Error::custom("process-ownership count overflow")
                    })?;
                }
                Ok(CountedMap(count))
            }
        }

        deserializer.deserialize_map(CountedMapVisitor)
    }
}

struct CountedSequence(u64);

impl<'de> serde::Deserialize<'de> for CountedSequence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct CountedSequenceVisitor;

        impl<'de> Visitor<'de> for CountedSequenceVisitor {
            type Value = CountedSequence;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a bounded lifecycle record sequence")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut count = 0_u64;
                while sequence.next_element::<IgnoredAny>()?.is_some() {
                    count = count.checked_add(1).ok_or_else(|| {
                        serde::de::Error::custom("lifecycle record count overflow")
                    })?;
                }
                Ok(CountedSequence(count))
            }
        }

        deserializer.deserialize_seq(CountedSequenceVisitor)
    }
}

pub(in crate::vm_lifecycle) fn decode_run_json_bounded<T: DeserializeOwned>(
    path: &Path,
    configured_maximum: u64,
) -> Result<T, String> {
    let bytes = read_run_json_bounded(path, configured_maximum)?;
    serde_json::from_slice(&bytes).map_err(|error| format!("decode {}: {error}", path.display()))
}

fn read_run_json_bounded(path: &Path, configured_maximum: u64) -> Result<Vec<u8>, String> {
    let maximum = configured_maximum.min(HARD_RUN_STATE_JSON_BYTES);
    let file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let length = file
        .metadata()
        .map_err(|error| format!("inspect {}: {error}", path.display()))?
        .len();
    if length > maximum {
        return Err(format!(
            "{} contains {length} bytes, above the bounded maximum {maximum}",
            path.display()
        ));
    }
    let capacity = usize::try_from(length)
        .map_err(|_| format!("{} length is not representable", path.display()))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| format!("reserve {capacity} bytes for {}", path.display()))?;
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(format!("{} grew beyond {maximum} bytes", path.display()));
    }
    Ok(bytes)
}

pub(in crate::vm_lifecycle) fn decode_prior_run_state(
    directory: &Path,
    scenario_identity: &str,
    limits: FaultResourceLimits,
) -> Result<(ProductionRunManifest, ProductionLifecycleJournal, u64, u64), String> {
    let state_path = directory.join(PRODUCTION_RUN_STATE_FILE);
    let bytes = read_run_json_bounded(&state_path, limits.event_log_bytes)
        .map_err(|message| format!("invalid prior run state: {message}"))?;
    let preflight: ProductionRunStatePreflight = serde_json::from_slice(&bytes)
        .map_err(|error| format!("preflight {}: {error}", state_path.display()))?;
    if preflight.version != PRODUCTION_RUN_STATE_VERSION {
        return Err(format!(
            "prior run state {} has incompatible version {}",
            state_path.display(),
            preflight.version
        ));
    }
    let state_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    limits
        .reserve(
            "event_log_bytes",
            preflight.runtime_event_log_bytes,
            state_bytes,
        )
        .map_err(|error| format!("admit aggregate prior run state: {error}"))?;
    for (role, count) in [
        ("current process", preflight.manifest.processes.0),
        ("staged process", preflight.manifest.staged_processes.0),
        ("lifecycle node", preflight.journal.nodes.0),
    ] {
        limits
            .reserve("nodes", 0, count)
            .map_err(|error| format!("admit {role} count before owned decode: {error}"))?;
    }
    let event_records = preflight
        .journal
        .nodes
        .0
        .checked_add(preflight.journal.completed_exits.0)
        .ok_or_else(|| String::from("preflight lifecycle event-record count overflow"))?;
    limits
        .reserve(
            "event_records",
            preflight.runtime_event_records,
            event_records,
        )
        .map_err(|error| format!("admit lifecycle record count before owned decode: {error}"))?;
    let admitted_count = |role: &str, count: u64| {
        usize::try_from(count)
            .map_err(|_| format!("admitted {role} count {count} is not representable"))
    };
    let _decode_shape = process_owners::enter_durable_decode_shape(
        admitted_count("current process", preflight.manifest.processes.0)?,
        admitted_count("staged process", preflight.manifest.staged_processes.0)?,
        admitted_count("lifecycle node", preflight.journal.nodes.0)?,
        admitted_count("completed exit", preflight.journal.completed_exits.0)?,
    );
    let state: ProductionRunState = serde_json::from_slice(&bytes)
        .map_err(|error| format!("decode {}: {error}", state_path.display()))?;
    let manifest = state.manifest;
    let journal = state.journal;
    if manifest.version != 2 || manifest.scenario != scenario_identity {
        return Err(format!(
            "prior run manifest {} has incompatible identity or version",
            state_path.display()
        ));
    }
    if !valid_process_identity(&manifest.owner)
        || manifest
            .processes
            .iter()
            .any(|(node, identity)| node.is_empty() || !valid_process_identity(identity))
        || manifest
            .staged_processes
            .iter()
            .any(|(node, identity)| node.is_empty() || !valid_process_identity(identity))
    {
        return Err(format!(
            "prior run manifest {} has invalid process ownership",
            state_path.display()
        ));
    }
    if let Some(node) = manifest
        .staged_processes
        .keys()
        .find(|node| !manifest.processes.contains_key(node))
    {
        return Err(format!(
            "prior run manifest stages replacement for unknown current node `{node}`"
        ));
    }
    validate_recovered_lifecycle_journal(&journal, &manifest, limits).map_err(|message| {
        format!(
            "invalid prior lifecycle journal {}: {message}",
            state_path.display()
        )
    })?;
    Ok((
        manifest,
        journal,
        state.runtime_event_records,
        state.runtime_event_log_bytes,
    ))
}

pub(in crate::vm_lifecycle) fn validate_recovered_lifecycle_journal(
    journal: &ProductionLifecycleJournal,
    manifest: &ProductionRunManifest,
    limits: FaultResourceLimits,
) -> Result<(), String> {
    if journal.version != 1 {
        return Err(format!(
            "unsupported lifecycle journal version {}",
            journal.version
        ));
    }
    let records = journal
        .nodes
        .len()
        .checked_add(journal.completed_exits.len())
        .ok_or_else(|| String::from("lifecycle journal record count overflow"))?;
    if u64::try_from(records).unwrap_or(u64::MAX) > limits.event_records {
        return Err(format!(
            "lifecycle journal has {records} records above limit {}",
            limits.event_records
        ));
    }
    if u64::try_from(journal.nodes.len()).unwrap_or(u64::MAX) > limits.nodes {
        return Err(format!(
            "lifecycle journal has {} nodes above limit {}",
            journal.nodes.len(),
            limits.nodes
        ));
    }
    for (node, identity) in manifest.staged_processes.iter() {
        let journal_identity = journal
            .nodes
            .iter()
            .find(|journal_node| journal_node.node == *node)
            .and_then(|journal_node| journal_node.replacement_process.as_ref());
        if journal_identity != Some(identity) {
            return Err(format!(
                "staged process owner `{node}` has no exact lifecycle journal owner"
            ));
        }
    }
    if matches!(
        journal.phase,
        ProductionLifecycleJournalPhase::Idle | ProductionLifecycleJournalPhase::Committed
    ) && !journal.nodes.is_empty()
    {
        return Err(format!(
            "lifecycle journal phase {:?} cannot retain live node ownership",
            journal.phase
        ));
    }
    if matches!(journal.phase, ProductionLifecycleJournalPhase::Idle)
        && (journal.transaction != 0 || !journal.completed_exits.is_empty())
    {
        return Err(String::from(
            "idle lifecycle journal cannot retain transaction history",
        ));
    }
    if !matches!(journal.phase, ProductionLifecycleJournalPhase::Idle) && journal.transaction == 0 {
        return Err(format!(
            "lifecycle journal phase {:?} requires a nonzero transaction",
            journal.phase
        ));
    }
    if matches!(
        journal.phase,
        ProductionLifecycleJournalPhase::Intent
            | ProductionLifecycleJournalPhase::Prepared
            | ProductionLifecycleJournalPhase::ExitsReaped
    ) && journal.nodes.is_empty()
    {
        return Err(format!(
            "lifecycle journal phase {:?} requires at least one live node owner",
            journal.phase
        ));
    }
    for (index, node) in journal.nodes.iter().enumerate() {
        if node.node.is_empty()
            || journal.nodes[..index]
                .iter()
                .any(|prior| prior.node == node.node)
        {
            return Err(format!(
                "lifecycle journal node {} is empty or duplicated",
                node.node
            ));
        }
        let current = manifest.processes.get(&node.node);
        let staged = manifest.staged_processes.get(&node.node);
        if !journal_process_ownership_is_exact(&journal.phase, node, current, staged) {
            return Err(format!(
                "lifecycle journal node {} is not bound to manifest process ownership",
                node.node
            ));
        }
        if node.current_generation == 0
            || !valid_lifecycle_generation(node)
            || !valid_lifecycle_transition(&node.transition)
            || !valid_lifecycle_hash(&node.action_sha256)
            || !valid_lifecycle_hash(&node.evidence_sha256)
            || !valid_process_identity(&node.current_process)
        {
            return Err(format!(
                "lifecycle journal node {} has invalid canonical fields",
                node.node
            ));
        }
    }
    for (index, exit) in journal.completed_exits.iter().enumerate() {
        if exit.node.is_empty()
            || exit.transaction == 0
            || exit.transaction > journal.transaction
            || exit.generation == 0
            || !valid_completed_exit_transition(&exit.transition)
            || !valid_lifecycle_hash(&exit.action_sha256)
            || !valid_lifecycle_hash(&exit.evidence_sha256)
            || expected_lifecycle_exit_code(&exit.transition) != Some(exit.expected_exit_code)
            || exit.expected_exit_code != exit.observed_exit_code
            || !valid_process_identity(&exit.process)
            || journal.completed_exits[..index]
                .iter()
                .any(|prior| prior.transaction == exit.transaction && prior.node == exit.node)
        {
            return Err(format!(
                "completed lifecycle exit for {} has invalid canonical fields",
                exit.node
            ));
        }
    }
    Ok(())
}

fn valid_completed_exit_transition(value: &str) -> bool {
    matches!(value, "Crash" | "PowerOff" | "PermanentFailure")
}

fn expected_lifecycle_exit_code(value: &str) -> Option<i32> {
    match value {
        "Crash" => Some(70),
        "PowerOff" => Some(71),
        "PermanentFailure" => Some(72),
        _ => None,
    }
}

fn journal_process_ownership_is_exact(
    phase: &ProductionLifecycleJournalPhase,
    node: &ProductionLifecycleJournalNode,
    current: Option<&QemuProcessIdentity>,
    staged: Option<&QemuProcessIdentity>,
) -> bool {
    match phase {
        ProductionLifecycleJournalPhase::Idle | ProductionLifecycleJournalPhase::Committed => false,
        ProductionLifecycleJournalPhase::Intent => {
            current == Some(&node.current_process)
                && staged.is_none()
                && node.replacement_process.is_none()
        }
        ProductionLifecycleJournalPhase::Prepared
        | ProductionLifecycleJournalPhase::ExitsReaped => {
            current == Some(&node.current_process)
                && prepared_process_ownership_is_exact(node, staged)
        }
        ProductionLifecycleJournalPhase::Quarantined => {
            quarantined_process_ownership_is_recoverable(node, current, staged)
        }
    }
}

fn prepared_process_ownership_is_exact(
    node: &ProductionLifecycleJournalNode,
    staged: Option<&QemuProcessIdentity>,
) -> bool {
    match node.transition.as_str() {
        "PermanentFailure" => node.replacement_process.is_none() && staged.is_none(),
        "Crash" | "PowerOff" => node
            .replacement_process
            .as_ref()
            .is_some_and(|replacement| staged == Some(replacement)),
        "Boot" | "PowerCycle" | "Reset" => false,
        _ => false,
    }
}

fn quarantined_process_ownership_is_recoverable(
    node: &ProductionLifecycleJournalNode,
    current: Option<&QemuProcessIdentity>,
    staged: Option<&QemuProcessIdentity>,
) -> bool {
    if current == Some(&node.current_process) {
        return match (staged, node.replacement_process.as_ref()) {
            (None, None) => true,
            (Some(staged), Some(replacement)) => {
                matches!(node.transition.as_str(), "Crash" | "PowerOff") && staged == replacement
            }
            _ => false,
        };
    }
    if staged.is_some() {
        return false;
    }
    if let Some(replacement) = node.replacement_process.as_ref() {
        return matches!(node.transition.as_str(), "Crash" | "PowerOff")
            && current == Some(replacement);
    }
    current.is_none()
        && node.transition == "PermanentFailure"
        && node.next_generation == node.current_generation
}

fn valid_lifecycle_generation(node: &ProductionLifecycleJournalNode) -> bool {
    match node.transition.as_str() {
        "Crash" | "Reset" | "PowerOff" | "PowerCycle" => {
            node.next_generation == node.current_generation.saturating_add(1)
        }
        "Boot" | "PermanentFailure" => node.next_generation == node.current_generation,
        _ => false,
    }
}

fn valid_lifecycle_transition(value: &str) -> bool {
    matches!(
        value,
        "Boot" | "Crash" | "Reset" | "PowerOff" | "PowerCycle" | "PermanentFailure"
    )
}

fn valid_process_identity(identity: &QemuProcessIdentity) -> bool {
    identity.process_id != 0 && identity.start_time_ticks != 0 && identity.executable.is_absolute()
}

fn valid_lifecycle_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}
