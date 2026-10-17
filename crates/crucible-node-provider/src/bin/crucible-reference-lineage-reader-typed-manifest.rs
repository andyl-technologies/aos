//! Emits distinct typed-peer original-input reader artifact identities without source-class qualification.
//!
//! The source-owned package supplies an authoritative realized Nix reference
//! graph. This tool measures its regular ELF files and the declared provider,
//! device, source, recipe and contract. It never emits test verdicts, readiness,
//! native capabilities or vendor acceptance certificates.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

use crucible_node_contract::{ContentRef, HashRef, U64, canonical};
use serde::{Deserialize, Serialize};

#[path = "lineage_reader_typed_manifest/contracts.rs"]
mod contracts;

type Failure = Box<dyn std::error::Error>;

const MAXIMUM_METADATA_BYTES: usize = 1024 * 1024;
const MAXIMUM_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const MAXIMUM_MEASURED_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAXIMUM_STORE_PATHS: usize = 512;
const MAXIMUM_VISITED_FILES: usize = 65_536;
const MAXIMUM_ELF_OBJECTS: usize = 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    provider: PathBuf,
    device: PathBuf,
    source: PathBuf,
    recipe: PathBuf,
    contract: PathBuf,
    reference_graph: PathBuf,
    build_reference_graph: PathBuf,
    build_roots: Vec<PathBuf>,
    build_tools: BTreeMap<String, PathBuf>,
    reader_sources: ReaderSources,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReaderSources {
    namespace_origin: PathBuf,
    event_definition: PathBuf,
    input_definition: PathBuf,
    stop_definition: PathBuf,
}

#[derive(Serialize)]
struct ReaderDefinitionRecord {
    schema: &'static str,
    definition: crucible_node_contract::ExtensionDeclaration,
    selection: crucible_node_contract::ExtensionSelection,
    durable_application: crucible_node_contract::ExtensionUse,
    sources: BTreeMap<&'static str, Artifact>,
    bodies: BTreeMap<&'static str, Artifact>,
    semantic_contracts: BTreeMap<&'static str, ContentRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceGraph {
    schema: String,
    roots: Vec<PathBuf>,
    #[serde(rename = "subtractRoots")]
    subtract_roots: Vec<PathBuf>,
    paths: Vec<ReferenceGraphPath>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceGraphPath {
    path: PathBuf,
    #[serde(rename = "narHash")]
    _nar_hash: String,
    #[serde(rename = "narSize")]
    _nar_size: u64,
    references: Vec<PathBuf>,
}

#[derive(Clone, Serialize)]
struct Artifact {
    path: PathBuf,
    content: ContentRef,
}

#[derive(Serialize)]
struct RuntimeClosure {
    schema: &'static str,
    roots: BTreeMap<&'static str, Artifact>,
    reference_graph: Artifact,
    store_paths: Vec<PathBuf>,
    objects: Vec<Artifact>,
    build_reference_graph: Artifact,
    build_tools: BTreeMap<String, Artifact>,
}

#[derive(Serialize)]
struct Implementation {
    schema: &'static str,
    policy_id: &'static str,
    policy_version: u16,
    artifacts: BTreeMap<&'static str, Artifact>,
    source_artifacts: BTreeMap<&'static str, Artifact>,
    limitations: Vec<&'static str>,
}

fn main() {
    if run().is_err() {
        eprintln!("installed reference implementation measurement failed");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Failure> {
    let mut arguments = std::env::args_os().skip(1);
    let input = PathBuf::from(arguments.next().ok_or("expected bounded input document")?);
    let output = PathBuf::from(
        arguments
            .next()
            .ok_or("expected installed output directory")?,
    );
    if arguments.next().is_some() {
        return Err("unexpected measurement argument".into());
    }
    let inputs: Inputs = decode_metadata(&read_argument_metadata(&input)?)?;
    require_store_path(&output)?;
    let mut total = 0u64;
    let provider = measure(&inputs.provider, "application/octet-stream", &mut total)?;
    let device = measure(&inputs.device, "application/octet-stream", &mut total)?;
    let roots = BTreeMap::from([("provider", provider), ("device", device)]);
    let graph_bytes = read_metadata(&inputs.reference_graph)?;
    let graph: ReferenceGraph = decode_metadata(&graph_bytes)?;
    let expected_roots = roots
        .values()
        .map(|root| require_store_path(&root.path))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let store_paths = validate_graph(&graph, &expected_roots)?;
    let objects = measure_elf_objects(&store_paths, &mut total)?;
    for root in roots.values() {
        if !objects
            .iter()
            .any(|object| object.path == root.path && object.content == root.content)
        {
            return Err("declared provider or device is absent from the actual ELF closure".into());
        }
    }
    if inputs.build_roots.is_empty()
        || inputs.build_roots.len() > 16
        || inputs.build_tools.is_empty()
        || inputs.build_tools.len() > 16
    {
        return Err("build tool declarations exceed their finite scope".into());
    }
    let build_graph: ReferenceGraph =
        decode_metadata(&read_metadata(&inputs.build_reference_graph)?)?;
    let build_roots = inputs
        .build_roots
        .iter()
        .map(|root| require_store_path(root))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if build_roots.len() != inputs.build_roots.len() {
        return Err("build roots are duplicated".into());
    }
    let build_paths = validate_graph(&build_graph, &build_roots)?;
    let mut build_tools = BTreeMap::new();
    for (role, original_path) in &inputs.build_tools {
        if role.is_empty()
            || role.len() > 128
            || !role
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err("build tool role has invalid bounded syntax".into());
        }
        require_store_path(original_path)?;
        let path = std::fs::canonicalize(original_path)?;
        if build_paths
            .binary_search(&require_store_path(&path)?)
            .is_err()
        {
            return Err("measured build tool is outside the original build closure".into());
        }
        build_tools.insert(
            role.clone(),
            measure(&path, "application/octet-stream", &mut total)?,
        );
    }
    let closure = RuntimeClosure {
        schema: "crucible.reference.runtime-closure.v1",
        roots: roots.clone(),
        reference_graph: measure(&inputs.reference_graph, "application/json", &mut total)?,
        store_paths,
        objects,
        build_reference_graph: measure(
            &inputs.build_reference_graph,
            "application/json",
            &mut total,
        )?,
        build_tools,
    };
    let closure_path = output.join("runtime-closure.json");
    write_canonical(&closure_path, &closure)?;
    // The launch retains this finite identity document, not a JSON byte array
    // containing the complete corresponding-source archive. Installation still
    // independently reads and authenticates every named original closure role.
    let handler_path = output.join("reader-handler.json");
    write_canonical(
        &handler_path,
        &serde_json::json!({
            "schema":"crucible.reference.original-input-reader-handler.v1",
            "provider":roots.get("provider").ok_or("provider artifact is missing")?.content,
            "device":roots.get("device").ok_or("device artifact is missing")?.content,
            "source":measure(&inputs.source, "application/gzip", &mut total)?.content,
            "recipe":measure(&inputs.recipe, "text/plain", &mut total)?.content,
            "contract":measure(&inputs.contract, "application/gzip", &mut total)?.content,
            "runtime_closure":measure(&closure_path, "application/json", &mut total)?.content,
            "source_policy":"public-original-input-lineage-reader-typed-v2"
        }),
    )?;
    let mut sources = BTreeMap::from([
        (
            "namespace_publication",
            measure(
                &inputs.reader_sources.namespace_origin,
                "application/json",
                &mut total,
            )?,
        ),
        (
            "handler",
            measure(&handler_path, "application/json", &mut total)?,
        ),
        (
            "event",
            measure(
                &inputs.reader_sources.event_definition,
                "text/plain",
                &mut total,
            )?,
        ),
        (
            "input",
            measure(
                &inputs.reader_sources.input_definition,
                "text/plain",
                &mut total,
            )?,
        ),
        (
            "stop",
            measure(
                &inputs.reader_sources.stop_definition,
                "text/plain",
                &mut total,
            )?,
        ),
    ]);
    let definition =
        crucible_node_provider::reference_lineage::InputLineageDefinition::build_negotiated(
            sources["namespace_publication"].content.clone(),
            sources["handler"].content.clone(),
            sources["event"].content.clone(),
            sources["input"].content.clone(),
            sources["stop"].content.clone(),
        )?;
    let names = [
        "schema",
        "specification",
        "timing",
        "state",
        "errors",
        "conformance",
        "declaration",
    ];
    if definition.objects().len() != names.len() {
        return Err("reader definition role count differs".into());
    }
    let mut bodies = BTreeMap::new();
    for (name, (reference, bytes)) in names.into_iter().zip(definition.objects()) {
        reference.verify(bytes)?;
        let path = output.join(format!("reader-{name}.body"));
        let mut file = File::options().write(true).create_new(true).open(&path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        bodies.insert(name, measure(&path, &reference.media_type, &mut total)?);
    }
    let mut semantic_contracts = BTreeMap::new();
    for (role, text) in contracts::STRUCTURAL_AXES {
        let path = output.join(format!("reader-{role}-contract.body"));
        let mut file = File::options().write(true).create_new(true).open(&path)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        let artifact = measure(&path, "text/plain", &mut total)?;
        semantic_contracts.insert(role, artifact.content.clone());
        bodies.insert(role, artifact);
    }
    for (axis, role) in [
        ("timing", "timing"),
        ("state", "state"),
        ("error", "errors"),
        ("qualification", "conformance"),
    ] {
        let artifact = bodies
            .get(role)
            .ok_or("semantic contract body is missing")?;
        semantic_contracts.insert(axis, artifact.content.clone());
    }
    let reader = ReaderDefinitionRecord {
        schema: "crucible.reference.original-input-reader-definition.v1",
        definition: definition.declaration().clone(),
        selection: definition.selection().clone(),
        durable_application: definition.durable_application(),
        sources: sources.clone(),
        bodies,
        semantic_contracts,
    };
    let reader_path = output.join("reader-definition.json");
    write_canonical(&reader_path, &reader)?;
    sources.insert(
        "reader_definition",
        measure(&reader_path, "application/json", &mut total)?,
    );
    let descriptor = Implementation {
        schema: "crucible.reference.installed-lineage-reader-implementation.v1",
        policy_id: "public-original-input-lineage-reader-typed-v2",
        policy_version: 1,
        artifacts: roots,
        source_artifacts: BTreeMap::from([
            (
                "source",
                measure(&inputs.source, "application/gzip", &mut total)?,
            ),
            ("recipe", measure(&inputs.recipe, "text/plain", &mut total)?),
            (
                "contract",
                measure(&inputs.contract, "application/gzip", &mut total)?,
            ),
            (
                "build_closure",
                measure(&closure_path, "application/json", &mut total)?,
            ),
        ]),
        limitations: vec![
            "conditional-native-timing",
            "exact-execution-unsupported",
            "limited-state-only",
            "native-preservation-unsupported",
            "physical-pause-unsupported",
            "repeatability-unqualified",
            "source-class-unqualified",
            "coordinator-lineage-association-unsupported",
            "higher-hop-input-adoption-unsupported",
        ],
    };
    let mut descriptor = descriptor;
    descriptor.source_artifacts.extend(sources);
    write_canonical(&output.join("implementation.json"), &descriptor)
}

fn require_store_path(path: &Path) -> Result<PathBuf, Failure> {
    let text = path.to_str().ok_or("store path is not UTF-8")?;
    if text.len() > 4096
        || text.contains('\0')
        || text.contains("//")
        || text.split('/').any(|part| part == "." || part == "..")
    {
        return Err("store path has unsupported lexical geometry".into());
    }
    let mut components = path.components();
    if components.next() != Some(Component::RootDir)
        || components.next() != Some(Component::Normal("nix".as_ref()))
        || components.next() != Some(Component::Normal("store".as_ref()))
    {
        return Err("installed artifact is outside the Nix store".into());
    }
    let Some(Component::Normal(name)) = components.next() else {
        return Err("installed artifact has no store root".into());
    };
    let name = name.to_str().ok_or("store root is not UTF-8")?;
    let (hash, label) = name.split_once('-').ok_or("store root has no identity")?;
    if hash.len() != 32
        || !hash
            .bytes()
            .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte))
        || label.is_empty()
        || !label.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err("store root has invalid identity".into());
    }
    Ok(Path::new("/nix/store").join(name))
}

fn open_regular(path: &Path) -> Result<File, Failure> {
    require_store_path(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err("installed content is not an original regular file".into());
    }
    Ok(file)
}

fn read_metadata(path: &Path) -> Result<Vec<u8>, Failure> {
    require_store_path(path)?;
    read_argument_metadata(path)
}

// Only this build-time instruction file may live in the private build directory.
// Every declared measured object still has to be an immutable store artifact.
fn read_argument_metadata(path: &Path) -> Result<Vec<u8>, Failure> {
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?
        .take(MAXIMUM_METADATA_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAXIMUM_METADATA_BYTES {
        return Err("installed metadata exceeds its finite allowance".into());
    }
    Ok(bytes)
}

fn decode_metadata<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Failure> {
    Ok(serde_json::from_value(canonical::parse_json(
        bytes,
        MAXIMUM_METADATA_BYTES,
    )?)?)
}

fn measure(path: &Path, media_type: &str, total: &mut u64) -> Result<Artifact, Failure> {
    let mut file = open_regular(path)?;
    let before = file.metadata()?;
    if before.len() > MAXIMUM_ARTIFACT_BYTES {
        return Err("installed artifact exceeds its finite allowance".into());
    }
    *total = total
        .checked_add(before.len())
        .filter(|sum| *sum <= MAXIMUM_MEASURED_BYTES)
        .ok_or("installed measured closure exceeds its finite allowance")?;
    let hash = hash_stream(&mut file, before.len())?;
    let after = file.metadata()?;
    if before.len() != after.len()
        || (
            before.dev(),
            before.ino(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
    {
        return Err("installed artifact changed during measurement".into());
    }
    Ok(Artifact {
        path: path.to_path_buf(),
        content: ContentRef {
            hash,
            length: U64::new(before.len()),
            media_type: media_type.into(),
        },
    })
}

fn hash_stream(file: &mut impl Read, length: u64) -> Result<HashRef, Failure> {
    let domain = "cnp.blob.v1";
    let mut hash = blake3::Hasher::new();
    hash.update(b"CNP/1\0");
    hash.update(&(domain.len() as u32).to_be_bytes());
    hash.update(domain.as_bytes());
    hash.update(&length.to_be_bytes());
    let mut observed = 0u64;
    let mut buffer = [0u8; 65_536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        observed = observed
            .checked_add(count as u64)
            .filter(|size| *size <= length)
            .ok_or("installed artifact grew during measurement")?;
        hash.update(&buffer[..count]);
    }
    if observed != length {
        return Err("installed artifact ended before its original length".into());
    }
    Ok(HashRef {
        algorithm: "blake3-256".into(),
        domain: domain.into(),
        digest: hash.finalize().to_hex().to_string(),
    })
}

fn validate_graph(
    graph: &ReferenceGraph,
    expected: &BTreeSet<PathBuf>,
) -> Result<Vec<PathBuf>, Failure> {
    if graph.schema != "aos.reference-graph/v1"
        || !graph.subtract_roots.is_empty()
        || graph.paths.is_empty()
        || graph.paths.len() > MAXIMUM_STORE_PATHS
    {
        return Err("unsupported or oversized realized reference graph".into());
    }
    let paths = graph
        .paths
        .iter()
        .map(|entry| entry.path.clone())
        .collect::<Vec<_>>();
    if paths.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("realized reference graph is duplicated or unsorted".into());
    }
    let actual = graph.roots.iter().cloned().collect::<BTreeSet<_>>();
    if actual.len() != graph.roots.len() || &actual != expected {
        return Err("realized reference graph has foreign original roots".into());
    }
    for entry in &graph.paths {
        if require_store_path(&entry.path)? != entry.path
            || entry.references.len() > MAXIMUM_STORE_PATHS
            || entry.references.windows(2).any(|pair| pair[0] >= pair[1])
            || entry
                .references
                .iter()
                .any(|reference| paths.binary_search(reference).is_err())
        {
            return Err("realized reference graph has foreign or unbounded references".into());
        }
    }
    if expected
        .iter()
        .any(|root| paths.binary_search(root).is_err())
    {
        return Err("realized reference graph omits an original root".into());
    }
    let mut reachable = BTreeSet::new();
    let mut pending = expected.iter().cloned().collect::<Vec<_>>();
    while let Some(root) = pending.pop() {
        if !reachable.insert(root.clone()) {
            continue;
        }
        let index = paths
            .binary_search(&root)
            .map_err(|_| "reference graph root disappeared")?;
        for reference in &graph.paths[index].references {
            if !reachable.contains(reference) {
                pending.push(reference.clone());
            }
        }
        if pending.len() > MAXIMUM_STORE_PATHS * MAXIMUM_STORE_PATHS {
            return Err("realized reference graph traversal exceeds its finite allowance".into());
        }
    }
    if reachable.len() != paths.len() {
        return Err("realized reference graph contains an unscoped store root".into());
    }
    Ok(paths)
}

fn measure_elf_objects(paths: &[PathBuf], total: &mut u64) -> Result<Vec<Artifact>, Failure> {
    let mut pending = paths.to_vec();
    let mut visited = 0usize;
    let mut objects = BTreeMap::new();
    while let Some(path) = pending.pop() {
        visited = visited
            .checked_add(1)
            .filter(|count| *count <= MAXIMUM_VISITED_FILES)
            .ok_or("runtime closure directory inventory exceeds its finite allowance")?;
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path)? {
                if visited
                    .checked_add(pending.len())
                    .is_none_or(|count| count >= MAXIMUM_VISITED_FILES)
                {
                    return Err(
                        "runtime closure pending inventory exceeds its finite allowance".into(),
                    );
                }
                pending.push(entry?.path());
            }
        } else if metadata.is_file() {
            let mut magic = [0; 4];
            let mut file = open_regular(&path)?;
            if metadata.len() < magic.len() as u64 {
                continue;
            }
            file.read_exact(&mut magic)?;
            if magic == *b"\x7fELF" {
                if objects.len() >= MAXIMUM_ELF_OBJECTS {
                    return Err("runtime ELF inventory exceeds its finite allowance".into());
                }
                objects.insert(
                    path.clone(),
                    measure(&path, "application/octet-stream", total)?,
                );
            }
        }
        // Symlink names do not stand in for native mapped file identities. The
        // realized reference graph separately retains their immutable roots.
    }
    Ok(objects.into_values().collect())
}

fn write_canonical(path: &Path, value: &impl Serialize) -> Result<(), Failure> {
    require_store_path(path)?;
    let bytes = canonical::canonical_json(&serde_json::to_value(value)?)?;
    if bytes.len() > MAXIMUM_METADATA_BYTES {
        return Err("emitted installed metadata exceeds its finite allowance".into());
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow rust-allow -- geometry assertions intentionally panic on a failed fixture invariant.
    // crucible-lint: allow panic-shortcut -- Manifest geometry tests deliberately panic when measured source or closure fixtures violate their expected invariants.
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;

    fn root(label: &str) -> PathBuf {
        PathBuf::from(format!("/nix/store/{}-{label}", "a".repeat(32)))
    }

    fn entry(path: PathBuf, references: Vec<PathBuf>) -> ReferenceGraphPath {
        ReferenceGraphPath {
            path,
            _nar_hash: "sha256:retained-source-graph-metadata".into(),
            _nar_size: 1,
            references,
        }
    }

    fn graph() -> ReferenceGraph {
        ReferenceGraph {
            schema: "aos.reference-graph/v1".into(),
            roots: vec![root("provider")],
            subtract_roots: Vec::new(),
            paths: vec![
                entry(root("loader"), Vec::new()),
                entry(root("provider"), vec![root("loader")]),
            ],
        }
    }

    #[test]
    fn streamed_content_preserves_the_existing_cnp_identity_construction() {
        for bytes in [Vec::new(), vec![0, 1, 255], vec![42; 140_000]] {
            let expected = canonical::hash("cnp.blob.v1", &bytes).unwrap();
            assert_eq!(
                hash_stream(&mut Cursor::new(&bytes), bytes.len() as u64).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn truncated_and_extended_original_artifacts_never_measure_successfully() {
        assert!(hash_stream(&mut Cursor::new(b"original"), 9).is_err());
        assert!(hash_stream(&mut Cursor::new(b"original+suffix"), 8).is_err());
    }

    #[test]
    fn complete_original_runtime_graph_keeps_the_actual_loader_root() {
        let graph = graph();
        let paths = validate_graph(&graph, &BTreeSet::from([root("provider")])).unwrap();
        assert_eq!(paths, vec![root("loader"), root("provider")]);
    }

    #[test]
    fn foreign_original_roots_and_subtracted_closures_are_refused() {
        let mut graph = graph();
        assert!(validate_graph(&graph, &BTreeSet::from([root("another-provider")])).is_err());
        graph.subtract_roots.push(root("loader"));
        assert!(validate_graph(&graph, &BTreeSet::from([root("provider")])).is_err());
    }

    #[test]
    fn omitted_loader_and_unscoped_extra_objects_are_refused() {
        let mut graph = graph();
        graph.paths.remove(0);
        assert!(validate_graph(&graph, &BTreeSet::from([root("provider")])).is_err());

        let mut graph = self::graph();
        graph
            .paths
            .insert(0, entry(root("foreign-library"), Vec::new()));
        assert!(validate_graph(&graph, &BTreeSet::from([root("provider")])).is_err());
    }

    #[test]
    fn duplicate_or_reordered_store_inventory_cannot_be_normalized_to_success() {
        let mut graph = graph();
        graph.paths.reverse();
        assert!(validate_graph(&graph, &BTreeSet::from([root("provider")])).is_err());
        graph.paths.insert(0, entry(root("loader"), Vec::new()));
        assert!(validate_graph(&graph, &BTreeSet::from([root("provider")])).is_err());
    }

    #[test]
    fn installation_paths_refuse_parent_traversal_and_non_store_content() {
        assert!(require_store_path(Path::new("/tmp/provider")).is_err());
        assert!(require_store_path(&root("provider").join("../another-provider")).is_err());
        assert!(require_store_path(Path::new("/nix/store/not-a-root/provider")).is_err());
        assert_eq!(
            require_store_path(&root("provider").join("bin/provider")).unwrap(),
            root("provider")
        );
    }
}
