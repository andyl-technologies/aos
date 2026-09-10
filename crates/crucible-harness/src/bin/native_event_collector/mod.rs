//! Collector orchestration, bounds, and stable report schema.

mod scenario;
mod segment;

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

pub(super) const REPORT_FORMAT: &str = "crucible.native-event-collector.v1";
const DEFAULT_RUN_STATE_ROOT: &str = "build/crucible-fleet-workdir/run-state";
const DEFAULT_MAX_OBJECTS: u64 = 1_000_000;
const DEFAULT_MAX_EVENTS: u64 = 1_000_000;
const DEFAULT_MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const DEFAULT_MAX_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_MAX_CLOSURES: u64 = 65_536;
const DEFAULT_MAX_JSON_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub(super) struct Args {
    input: Input,
    scenario: Option<String>,
    scenario_source: Option<PathBuf>,
    bounds: Bounds,
}

#[derive(Debug)]
enum Input {
    Process(u32),
    ScenarioRoot(PathBuf),
}

#[derive(Clone, Copy, Debug)]
struct Bounds {
    objects: u64,
    events: u64,
    total_bytes: u64,
    object_bytes: u64,
    closures: u64,
    json_bytes: u64,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            objects: DEFAULT_MAX_OBJECTS,
            events: DEFAULT_MAX_EVENTS,
            total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            object_bytes: DEFAULT_MAX_OBJECT_BYTES,
            closures: DEFAULT_MAX_CLOSURES,
            json_bytes: DEFAULT_MAX_JSON_BYTES,
        }
    }
}

impl Args {
    pub(super) fn parse(arguments: impl Iterator<Item = OsString>) -> Result<Self, String> {
        let mut arguments = arguments;
        let mut process = None;
        let mut root = None;
        let mut scenario = None;
        let mut scenario_source = None;
        let mut bounds = Bounds::default();
        while let Some(argument) = arguments.next() {
            let argument = argument
                .to_str()
                .ok_or_else(|| String::from("argument is not UTF-8"))?;
            let value = |arguments: &mut dyn Iterator<Item = OsString>| {
                arguments
                    .next()
                    .ok_or_else(|| format!("{argument} requires a value"))
            };
            match argument {
                "--pid" => {
                    process = Some(parse_u32(value(&mut arguments)?, "--pid")?);
                }
                "--root" => root = Some(PathBuf::from(value(&mut arguments)?)),
                "--scenario" => {
                    let candidate = os_string(value(&mut arguments)?, "--scenario")?;
                    require_hash(&candidate, "scenario")?;
                    scenario = Some(candidate);
                }
                "--scenario-source" => {
                    scenario_source = Some(PathBuf::from(value(&mut arguments)?));
                }
                "--max-objects" => {
                    bounds.objects = parse_u64(value(&mut arguments)?, argument)?;
                }
                "--max-events" => {
                    bounds.events = parse_u64(value(&mut arguments)?, argument)?;
                }
                "--max-total-bytes" => {
                    bounds.total_bytes = parse_u64(value(&mut arguments)?, argument)?;
                }
                "--max-object-bytes" => {
                    bounds.object_bytes = parse_u64(value(&mut arguments)?, argument)?;
                }
                "--max-closures" => {
                    bounds.closures = parse_u64(value(&mut arguments)?, argument)?;
                }
                "--max-json-bytes" => {
                    bounds.json_bytes = parse_u64(value(&mut arguments)?, argument)?;
                }
                "--help" | "-h" => return Err(usage()),
                _ => return Err(format!("unknown argument `{argument}`; {}", usage())),
            }
        }
        let input = match (process, root) {
            (Some(process), None) => Input::Process(process),
            (None, Some(root)) => Input::ScenarioRoot(root),
            _ => {
                return Err(format!(
                    "choose exactly one of --pid or --root; {}",
                    usage()
                ));
            }
        };
        for (name, value) in [
            ("--max-objects", bounds.objects),
            ("--max-events", bounds.events),
            ("--max-total-bytes", bounds.total_bytes),
            ("--max-object-bytes", bounds.object_bytes),
            ("--max-closures", bounds.closures),
            ("--max-json-bytes", bounds.json_bytes),
        ] {
            if value == 0 {
                return Err(format!("{name} must be nonzero"));
            }
        }
        for (name, value, ceiling) in [
            ("--max-objects", bounds.objects, DEFAULT_MAX_OBJECTS),
            ("--max-events", bounds.events, DEFAULT_MAX_EVENTS),
            (
                "--max-total-bytes",
                bounds.total_bytes,
                DEFAULT_MAX_TOTAL_BYTES,
            ),
            (
                "--max-object-bytes",
                bounds.object_bytes,
                DEFAULT_MAX_OBJECT_BYTES,
            ),
            ("--max-closures", bounds.closures, DEFAULT_MAX_CLOSURES),
            (
                "--max-json-bytes",
                bounds.json_bytes,
                DEFAULT_MAX_JSON_BYTES,
            ),
        ] {
            if value > ceiling {
                return Err(format!("{name} exceeds compiled ceiling {ceiling}"));
            }
        }
        Ok(Self {
            input,
            scenario,
            scenario_source,
            bounds,
        })
    }
}

#[derive(Debug, Serialize)]
pub(super) struct FailureReport {
    pub(super) format: &'static str,
    pub(super) status: &'static str,
    pub(super) error: String,
}

#[derive(Debug, Serialize)]
pub(super) struct Report {
    format: &'static str,
    status: &'static str,
    consistency: &'static str,
    inspected_root: String,
    scenario: String,
    bounds: BoundsReport,
    objects: ObjectReport,
    events: EventReport,
    checkpoint_closures: ClosureReport,
    lifecycle: LifecycleReport,
    prerequisites: scenario::PrerequisiteReport,
}

#[derive(Debug, Serialize)]
struct BoundsReport {
    maximum_objects: u64,
    maximum_events: u64,
    maximum_total_bytes: u64,
    maximum_object_bytes: u64,
    maximum_closures: u64,
    maximum_json_bytes: u64,
}

#[derive(Debug, Serialize)]
struct ObjectReport {
    count: u64,
    bytes: u64,
    first_name: Option<String>,
    last_name: Option<String>,
    newest: Option<NewestObject>,
}

#[derive(Debug, Serialize)]
struct NewestObject {
    name: String,
    modified_seconds: u64,
    modified_nanoseconds: u32,
    bytes: u64,
}

#[derive(Debug, Serialize)]
struct EventReport {
    scope: &'static str,
    segments: u64,
    entries: u64,
    distinct_sequences: u64,
    reused_sequence_entries: u64,
    kind_counts: BTreeMap<String, u64>,
    sequence_minimum: Option<u64>,
    sequence_maximum: Option<u64>,
    virtual_ticks_maximum: Option<u64>,
    icount_retired_maximum: Option<u64>,
    node_state_transitions: Vec<NodeStateTransition>,
}

#[derive(Debug, Serialize)]
struct NodeStateTransition {
    node: String,
    state: String,
    entries: u64,
    sequence_minimum: u64,
    sequence_maximum: u64,
}

#[derive(Debug, Serialize)]
struct ClosureReport {
    status: &'static str,
    count: u64,
    identities: Vec<ClosureEntry>,
}

#[derive(Debug, Serialize)]
struct ClosureEntry {
    identity: String,
    manifest_status: &'static str,
    manifest_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
struct LifecycleReport {
    version: u64,
    runtime_event_records: u64,
    runtime_event_log_bytes: u64,
    phase: String,
    transaction: u64,
    current_generations: BTreeMap<String, CurrentGeneration>,
    completed_exits: Vec<CompletedExit>,
}

#[derive(Debug, Serialize)]
struct CurrentGeneration {
    generation: u64,
    basis: &'static str,
    process_id: u64,
    start_time_ticks: u64,
}

#[derive(Debug, Serialize)]
struct CompletedExit {
    transaction: u64,
    node: String,
    generation: u64,
    transition: String,
    expected_exit_code: i64,
    observed_exit_code: i64,
}

pub(super) fn collect(args: Args) -> Result<Report, String> {
    let root = resolve_scenario_root(&args)?;
    let scenario = root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("scenario root {} has no UTF-8 identity", root.display()))?
        .to_owned();
    require_hash(&scenario, "scenario root")?;
    if let Some(expected) = &args.scenario
        && expected != &scenario
    {
        return Err(format!(
            "resolved scenario `{scenario}` differs from requested `{expected}`"
        ));
    }
    let declarations = args
        .scenario_source
        .as_deref()
        .map(|path| scenario::ScenarioDeclarations::load(path, args.bounds.json_bytes))
        .transpose()?;
    let evidence_queries = declarations
        .as_ref()
        .map(scenario::ScenarioDeclarations::evidence_queries)
        .unwrap_or_default();
    let lifecycle = inspect_lifecycle(&root, &scenario, args.bounds)?;
    let (objects, events, evidence) = inspect_objects(&root, args.bounds, evidence_queries)?;
    let checkpoint_closures = inspect_closures(&root, args.bounds)?;
    let prerequisites = match declarations {
        Some(declarations) => declarations.finish(&evidence)?,
        None => scenario::unavailable(),
    };
    Ok(Report {
        format: REPORT_FORMAT,
        status: "ok",
        consistency: "independent_bounded_file_observations",
        inspected_root: root.display().to_string(),
        scenario,
        bounds: BoundsReport {
            maximum_objects: args.bounds.objects,
            maximum_events: args.bounds.events,
            maximum_total_bytes: args.bounds.total_bytes,
            maximum_object_bytes: args.bounds.object_bytes,
            maximum_closures: args.bounds.closures,
            maximum_json_bytes: args.bounds.json_bytes,
        },
        objects,
        events,
        checkpoint_closures,
        lifecycle,
        prerequisites,
    })
}

fn resolve_scenario_root(args: &Args) -> Result<PathBuf, String> {
    match &args.input {
        Input::ScenarioRoot(root) => Ok(root.clone()),
        Input::Process(process) => {
            let parent = PathBuf::from(format!("/proc/{process}/root/{DEFAULT_RUN_STATE_ROOT}"));
            if let Some(scenario) = &args.scenario {
                return Ok(parent.join(scenario));
            }
            let mut candidates = Vec::new();
            for entry in sorted_entries(&parent, args.bounds.objects)? {
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| String::from("run-state scenario name is not UTF-8"))?;
                if is_hash(&name)
                    && entry
                        .file_type()
                        .map_err(|error| format!("inspect scenario `{name}`: {error}"))?
                        .is_dir()
                {
                    candidates.push(entry.path());
                }
            }
            if candidates.len() != 1 {
                return Err(format!(
                    "PID {process} exposes {} scenario roots; supply --scenario",
                    candidates.len()
                ));
            }
            candidates
                .pop()
                .ok_or_else(|| String::from("resolved scenario root disappeared"))
        }
    }
}

fn inspect_objects(
    root: &Path,
    bounds: Bounds,
    evidence_queries: &[scenario::EvidenceQuery],
) -> Result<(ObjectReport, EventReport, Vec<u64>), String> {
    let directory = root.join("checkpoint-objects");
    let mut paths = Vec::new();
    for shard in sorted_entries(&directory, 256)? {
        let shard_name = file_name(&shard)?;
        if shard_name.len() != 2 || !shard_name.bytes().all(is_lower_hex) {
            return Err(format!("invalid checkpoint-object shard `{shard_name}`"));
        }
        if !shard
            .file_type()
            .map_err(|error| format!("inspect shard `{shard_name}`: {error}"))?
            .is_dir()
        {
            return Err(format!(
                "checkpoint-object shard `{shard_name}` is not a directory"
            ));
        }
        for object in sorted_entries(&shard.path(), bounds.objects)? {
            let name = file_name(&object)?;
            require_hash(&name, "checkpoint object")?;
            if !name.starts_with(&shard_name) {
                return Err(format!("checkpoint object `{name}` is in the wrong shard"));
            }
            paths.push((name, object.path()));
            if u64::try_from(paths.len()).unwrap_or(u64::MAX) > bounds.objects {
                return Err(format!(
                    "checkpoint object count exceeds bound {}",
                    bounds.objects
                ));
            }
        }
    }
    paths.sort_by(|left, right| left.0.cmp(&right.0));
    let object_count = u64::try_from(paths.len())
        .map_err(|_| String::from("checkpoint object count is not representable"))?;
    if object_count > bounds.objects {
        return Err(format!(
            "checkpoint object count {object_count} exceeds bound {}",
            bounds.objects
        ));
    }

    let mut total_bytes = 0_u64;
    let mut newest = None;
    let mut sequences = BTreeSet::new();
    let mut segments = 0_u64;
    let mut event_entries = 0_u64;
    let mut reused_sequence_entries = 0_u64;
    let mut kind_counts = BTreeMap::new();
    let mut virtual_max = None;
    let mut icount_max = None;
    let mut node_state_transitions = BTreeMap::new();
    let mut evidence = Vec::new();
    evidence
        .try_reserve_exact(evidence_queries.len())
        .map_err(|_| String::from("reserve scenario evidence counters"))?;
    evidence.resize(evidence_queries.len(), 0_u64);
    for (name, path) in &paths {
        let remaining_total = bounds.total_bytes.saturating_sub(total_bytes);
        let read_limit = bounds.object_bytes.min(remaining_total);
        let (bytes, metadata) =
            read_bounded_file_with_metadata(path, read_limit, "checkpoint object")?;
        let length = u64::try_from(bytes.len())
            .map_err(|_| format!("checkpoint object `{name}` length is not representable"))?;
        total_bytes = total_bytes
            .checked_add(length)
            .ok_or_else(|| String::from("checkpoint object byte count overflow"))?;
        if total_bytes > bounds.total_bytes {
            return Err(format!(
                "checkpoint objects have {total_bytes} bytes above bound {}",
                bounds.total_bytes
            ));
        }
        let observed = blake3::hash(&bytes).to_hex().to_string();
        if observed != *name {
            return Err(format!("checkpoint object `{name}` hashes to `{observed}`"));
        }
        let modified = metadata
            .modified()
            .map_err(|error| format!("read checkpoint object `{name}` mtime: {error}"))?
            .duration_since(UNIX_EPOCH)
            .map_err(|_| format!("checkpoint object `{name}` mtime predates the Unix epoch"))?;
        let replace_newest = newest
            .as_ref()
            .is_none_or(|(_, prior, _): &(String, std::time::Duration, u64)| modified > *prior);
        if replace_newest {
            newest = Some((name.clone(), modified, length));
        }
        if segment::has_magic(&bytes) {
            segments = segments
                .checked_add(1)
                .ok_or_else(|| String::from("event segment count overflow"))?;
            let remaining_events = bounds.events.saturating_sub(event_entries);
            for entry in segment::decode(&bytes, remaining_events)? {
                event_entries = event_entries
                    .checked_add(1)
                    .ok_or_else(|| String::from("event entry count overflow"))?;
                if !sequences.insert(entry.sequence) {
                    reused_sequence_entries = reused_sequence_entries
                        .checked_add(1)
                        .ok_or_else(|| String::from("reused event sequence count overflow"))?;
                }
                let kind_count = kind_counts.entry(entry.kind.clone()).or_insert(0_u64);
                *kind_count = kind_count
                    .checked_add(1)
                    .ok_or_else(|| String::from("event kind count overflow"))?;
                virtual_max = Some(virtual_max.map_or(entry.virtual_ticks, |value: u64| {
                    value.max(entry.virtual_ticks)
                }));
                icount_max = Some(icount_max.map_or(entry.icount_retired, |value: u64| {
                    value.max(entry.icount_retired)
                }));
                if entry.kind == "node_state" {
                    let node = canonical_material_field(
                        &entry.material,
                        "event_payload.attribute.node.value.name=",
                    )?;
                    let state = canonical_material_field(
                        &entry.material,
                        "event_payload.attribute.state.value.value=",
                    )?;
                    let aggregate = node_state_transitions.entry((node, state)).or_insert((
                        0_u64,
                        entry.sequence,
                        entry.sequence,
                    ));
                    aggregate.0 = aggregate
                        .0
                        .checked_add(1)
                        .ok_or_else(|| String::from("node-state transition count overflow"))?;
                    aggregate.1 = aggregate.1.min(entry.sequence);
                    aggregate.2 = aggregate.2.max(entry.sequence);
                }
                for (index, query) in evidence_queries.iter().enumerate() {
                    if query.matches(&entry.kind, &entry.material) {
                        evidence[index] = evidence[index]
                            .checked_add(1)
                            .ok_or_else(|| String::from("prerequisite evidence count overflow"))?;
                    }
                }
            }
        }
    }
    let first_name = paths.first().map(|entry| entry.0.clone());
    let last_name = paths.last().map(|entry| entry.0.clone());
    let newest = newest.map(|(name, modified, bytes)| NewestObject {
        name,
        modified_seconds: modified.as_secs(),
        modified_nanoseconds: modified.subsec_nanos(),
        bytes,
    });
    let distinct_sequences = u64::try_from(sequences.len())
        .map_err(|_| String::from("distinct event sequence count is not representable"))?;
    let node_state_transitions = node_state_transitions
        .into_iter()
        .map(
            |((node, state), (entries, sequence_minimum, sequence_maximum))| NodeStateTransition {
                node,
                state,
                entries,
                sequence_minimum,
                sequence_maximum,
            },
        )
        .collect();
    Ok((
        ObjectReport {
            count: object_count,
            bytes: total_bytes,
            first_name,
            last_name,
            newest,
        },
        EventReport {
            scope: "all_content_addressed_segments",
            segments,
            entries: event_entries,
            distinct_sequences,
            reused_sequence_entries,
            kind_counts,
            sequence_minimum: sequences.first().copied(),
            sequence_maximum: sequences.last().copied(),
            virtual_ticks_maximum: virtual_max,
            icount_retired_maximum: icount_max,
            node_state_transitions,
        },
        evidence,
    ))
}

fn inspect_closures(root: &Path, bounds: Bounds) -> Result<ClosureReport, String> {
    let directory = root.join("checkpoint-closures");
    if !directory.exists() {
        return Ok(ClosureReport {
            status: "directory_missing",
            count: 0,
            identities: Vec::new(),
        });
    }
    let mut identities = Vec::new();
    for entry in sorted_entries(&directory, bounds.closures)? {
        let identity = file_name(&entry)?;
        if identity.starts_with('.') {
            continue;
        }
        require_hash(&identity, "checkpoint closure")?;
        if !entry
            .file_type()
            .map_err(|error| format!("inspect checkpoint closure `{identity}`: {error}"))?
            .is_dir()
        {
            return Err(format!(
                "checkpoint closure `{identity}` is not a directory"
            ));
        }
        let manifest = entry.path().join("manifest.bin");
        let (manifest_status, manifest_bytes) = match fs::symlink_metadata(&manifest) {
            Ok(metadata) if metadata.file_type().is_file() => {
                if metadata.len() > bounds.json_bytes {
                    return Err(format!(
                        "checkpoint closure `{identity}` manifest has {} bytes above bound {}",
                        metadata.len(),
                        bounds.json_bytes
                    ));
                }
                ("present_unparsed", Some(metadata.len()))
            }
            Ok(_) => {
                return Err(format!(
                    "checkpoint closure `{identity}` manifest is not a file"
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => ("missing", None),
            Err(error) => return Err(format!("inspect checkpoint closure `{identity}`: {error}")),
        };
        identities.push(ClosureEntry {
            identity,
            manifest_status,
            manifest_bytes,
        });
    }
    let count = u64::try_from(identities.len())
        .map_err(|_| String::from("checkpoint closure count is not representable"))?;
    if count > bounds.closures {
        return Err(format!(
            "checkpoint closure count {count} exceeds bound {}",
            bounds.closures
        ));
    }
    Ok(ClosureReport {
        status: "enumerated",
        count,
        identities,
    })
}

fn inspect_lifecycle(
    root: &Path,
    scenario: &str,
    bounds: Bounds,
) -> Result<LifecycleReport, String> {
    let path = root.join("run-state.json");
    let bytes = read_bounded_file(&path, bounds.json_bytes, "lifecycle run state")?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("decode lifecycle run state {}: {error}", path.display()))?;
    let version = json_u64(&value, &["version"])?;
    if version != 2 {
        return Err(format!("unsupported lifecycle run-state version {version}"));
    }
    let recorded_scenario = json_string(&value, &["manifest", "scenario"])?;
    if recorded_scenario != scenario {
        return Err(format!(
            "run-state scenario `{recorded_scenario}` differs from root `{scenario}`"
        ));
    }
    let runtime_event_records = json_u64(&value, &["runtime_event_records"])?;
    let runtime_event_log_bytes = json_u64(&value, &["runtime_event_log_bytes"])?;
    let phase = json_string(&value, &["journal", "phase"])?.to_owned();
    let transaction = json_u64(&value, &["journal", "transaction"])?;
    let exits = json_array(&value, &["journal", "completed_exits"])?;
    if u64::try_from(exits.len()).unwrap_or(u64::MAX) > bounds.objects {
        return Err(String::from("completed-exit count exceeds object bound"));
    }
    let mut completed_exits = Vec::new();
    let mut last_generation = BTreeMap::new();
    for exit in exits {
        let node = json_string(exit, &["node"])?.to_owned();
        let generation = json_u64(exit, &["generation"])?;
        last_generation
            .entry(node.clone())
            .and_modify(|value: &mut u64| *value = (*value).max(generation))
            .or_insert(generation);
        completed_exits.push(CompletedExit {
            transaction: json_u64(exit, &["transaction"])?,
            node,
            generation,
            transition: json_string(exit, &["transition"])?.to_owned(),
            expected_exit_code: json_i64(exit, &["expected_exit_code"])?,
            observed_exit_code: json_i64(exit, &["observed_exit_code"])?,
        });
    }
    let processes = json_object(&value, &["manifest", "processes"])?;
    let journal_nodes = json_array(&value, &["journal", "nodes"])?;
    let mut journal_generations = BTreeMap::new();
    for node in journal_nodes {
        let replacement = json_at(node, &["replacement_process"])?;
        let replacement_identity = if replacement.is_null() {
            None
        } else {
            Some((
                json_u64(replacement, &["process_id"])?,
                json_u64(replacement, &["start_time_ticks"])?,
            ))
        };
        journal_generations.insert(
            json_string(node, &["node"])?.to_owned(),
            (
                json_u64(node, &["current_generation"])?,
                json_u64(node, &["next_generation"])?,
                (
                    json_u64(node, &["current_process", "process_id"])?,
                    json_u64(node, &["current_process", "start_time_ticks"])?,
                ),
                replacement_identity,
            ),
        );
    }
    let mut current_generations = BTreeMap::new();
    for (node, process) in processes {
        let process_identity = (
            json_u64(process, &["process_id"])?,
            json_u64(process, &["start_time_ticks"])?,
        );
        let (generation, basis) = if let Some((current, next, current_identity, replacement)) =
            journal_generations.get(node)
        {
            if process_identity == *current_identity {
                (*current, "journal_current_process")
            } else if replacement.as_ref() == Some(&process_identity) {
                (*next, "journal_replacement_process")
            } else {
                return Err(format!(
                    "manifest process `{node}` does not match its lifecycle journal identities"
                ));
            }
        } else {
            (
                last_generation
                    .get(node)
                    .copied()
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or_else(|| format!("derive current generation for `{node}`"))?,
                "completed_exit_successor",
            )
        };
        current_generations.insert(
            node.clone(),
            CurrentGeneration {
                generation,
                basis,
                process_id: process_identity.0,
                start_time_ticks: process_identity.1,
            },
        );
    }
    Ok(LifecycleReport {
        version,
        runtime_event_records,
        runtime_event_log_bytes,
        phase,
        transaction,
        current_generations,
        completed_exits,
    })
}

pub(super) fn read_bounded_file(path: &Path, maximum: u64, role: &str) -> Result<Vec<u8>, String> {
    read_bounded_file_with_metadata(path, maximum, role).map(|(bytes, _)| bytes)
}

fn read_bounded_file_with_metadata(
    path: &Path,
    maximum: u64,
    role: &str,
) -> Result<(Vec<u8>, fs::Metadata), String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("open {role} {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect {role} {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!("{role} {} is not a regular file", path.display()));
    }
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {role} path {}: {error}", path.display()))?;
    if !path_metadata.file_type().is_file()
        || path_metadata.dev() != metadata.dev()
        || path_metadata.ino() != metadata.ino()
    {
        return Err(format!(
            "{role} {} is a link or changed identity while opened",
            path.display()
        ));
    }
    let length = metadata.len();
    if length > maximum {
        return Err(format!(
            "{role} {} has {length} bytes above bound {maximum}",
            path.display()
        ));
    }
    let capacity = usize::try_from(length)
        .map_err(|_| format!("{role} {} length is not representable", path.display()))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| format!("reserve {length} bytes for {role} {}", path.display()))?;
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {role} {}: {error}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != length {
        return Err(format!(
            "{role} {} changed length while read",
            path.display()
        ));
    }
    Ok((bytes, metadata))
}

fn sorted_entries(path: &Path, maximum: u64) -> Result<Vec<fs::DirEntry>, String> {
    let directory =
        fs::read_dir(path).map_err(|error| format!("enumerate {}: {error}", path.display()))?;
    let mut entries = Vec::new();
    for entry in directory {
        entries.push(entry.map_err(|error| format!("enumerate {}: {error}", path.display()))?);
        if u64::try_from(entries.len()).unwrap_or(u64::MAX) > maximum {
            return Err(format!(
                "directory {} has more than {maximum} entries",
                path.display()
            ));
        }
    }
    entries.sort_by_key(fs::DirEntry::file_name);
    Ok(entries)
}

fn file_name(entry: &fs::DirEntry) -> Result<String, String> {
    entry
        .file_name()
        .into_string()
        .map_err(|_| format!("path name below {} is not UTF-8", entry.path().display()))
}

fn require_hash(value: &str, role: &str) -> Result<(), String> {
    if is_hash(value) {
        Ok(())
    } else {
        Err(format!(
            "{role} `{value}` is not a 64-character lowercase hash"
        ))
    }
}

fn is_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(is_lower_hex)
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

fn canonical_material_field(material: &str, prefix: &str) -> Result<String, String> {
    let mut values = material
        .lines()
        .filter_map(|line| line.strip_prefix(prefix));
    let value = values
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("event material lacks `{prefix}` field"))?;
    if values.next().is_some() {
        return Err(format!("event material repeats `{prefix}` field"));
    }
    Ok(value.to_owned())
}

fn parse_u64(value: OsString, role: &str) -> Result<u64, String> {
    os_string(value, role)?
        .parse()
        .map_err(|error| format!("parse {role}: {error}"))
}

fn parse_u32(value: OsString, role: &str) -> Result<u32, String> {
    os_string(value, role)?
        .parse()
        .map_err(|error| format!("parse {role}: {error}"))
}

fn os_string(value: OsString, role: &str) -> Result<String, String> {
    value
        .into_string()
        .map_err(|_| format!("{role} value is not UTF-8"))
}

fn usage() -> String {
    String::from(
        "usage: crucible-native-event-collector (--pid PID [--scenario HASH] | --root SCENARIO_ROOT) [--scenario-source TOML] [--max-objects N] [--max-events N] [--max-total-bytes N] [--max-object-bytes N] [--max-closures N] [--max-json-bytes N]",
    )
}

fn json_at<'a>(
    value: &'a serde_json::Value,
    path: &[&str],
) -> Result<&'a serde_json::Value, String> {
    let mut current = value;
    for component in path {
        current = current
            .get(component)
            .ok_or_else(|| format!("lifecycle run state lacks `{}`", path.join(".")))?;
    }
    Ok(current)
}

fn json_u64(value: &serde_json::Value, path: &[&str]) -> Result<u64, String> {
    json_at(value, path)?
        .as_u64()
        .ok_or_else(|| format!("lifecycle field `{}` is not u64", path.join(".")))
}

fn json_i64(value: &serde_json::Value, path: &[&str]) -> Result<i64, String> {
    json_at(value, path)?
        .as_i64()
        .ok_or_else(|| format!("lifecycle field `{}` is not i64", path.join(".")))
}

fn json_string<'a>(value: &'a serde_json::Value, path: &[&str]) -> Result<&'a str, String> {
    json_at(value, path)?
        .as_str()
        .ok_or_else(|| format!("lifecycle field `{}` is not a string", path.join(".")))
}

fn json_array<'a>(
    value: &'a serde_json::Value,
    path: &[&str],
) -> Result<&'a Vec<serde_json::Value>, String> {
    json_at(value, path)?
        .as_array()
        .ok_or_else(|| format!("lifecycle field `{}` is not an array", path.join(".")))
}

fn json_object<'a>(
    value: &'a serde_json::Value,
    path: &[&str],
) -> Result<&'a serde_json::Map<String, serde_json::Value>, String> {
    json_at(value, path)?
        .as_object()
        .ok_or_else(|| format!("lifecycle field `{}` is not an object", path.join(".")))
}

#[cfg(test)]
mod tests;
