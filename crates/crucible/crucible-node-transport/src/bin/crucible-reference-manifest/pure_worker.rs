//! Measures the closed pure-worker installation and its actual runtime tree.
//!
//! All records are content claims, not permission or admission. The parent
//! measures the opened executable originals and checks this complete inventory
//! before requesting the separately enforced OS program and task capabilities.
//!
//! The closed installation uses these records (each artifact is a path and the
//! existing CNP `ContentRef`, without a verdict field):
//!
//! ```text
//! installation.json
//!   schema: crucible.pure-worker.installation/1
//!   profile: pure-worker-v1
//!   launcher, worker, runtime_closure: Artifact
//!   read_only_roots: sorted unique store roots, at most 128
//!   source, vendor, recipe, algorithm, request_codec, result_codec: Artifact
//! runtime-closure.json
//!   schema: crucible.pure-worker.runtime-closure/1
//!   reference_graph: Artifact
//!   store_paths: sorted unique store roots
//!   objects: sorted regular ELF Artifacts
//!   entries: sorted directory {path, mode}, file {path, mode, content},
//!            or symlink {path, target} records, tagged by `kind`
//! ```

use std::io::{Seek, SeekFrom};

use super::*;

const MAXIMUM_READ_ONLY_ROOTS: usize = 128;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerInputs {
    launcher: PathBuf,
    worker: PathBuf,
    source: PathBuf,
    vendor: PathBuf,
    recipe: PathBuf,
    reference_graph: PathBuf,
}

#[derive(Serialize)]
struct Installation {
    schema: &'static str,
    profile: &'static str,
    launcher: Artifact,
    worker: Artifact,
    runtime_closure: Artifact,
    read_only_roots: Vec<PathBuf>,
    source: Artifact,
    vendor: Artifact,
    recipe: Artifact,
    algorithm: Artifact,
    request_codec: Artifact,
    result_codec: Artifact,
}

#[derive(Serialize)]
struct Algorithm {
    schema: &'static str,
    id: &'static str,
    source: ContentRef,
    vendor: ContentRef,
    recipe: ContentRef,
}

#[derive(Serialize)]
struct Codec {
    schema: &'static str,
    id: &'static str,
    magic: &'static str,
    version: u16,
    header_bytes: u16,
    source: ContentRef,
}

#[derive(Serialize)]
struct WorkerClosure {
    schema: &'static str,
    reference_graph: Artifact,
    store_paths: Vec<PathBuf>,
    objects: Vec<Artifact>,
    entries: Vec<TreeEntry>,
}

// The manifest records every name, including empty directories and symlinks.
// It never follows a link while collecting content identities.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum TreeEntry {
    Directory {
        path: PathBuf,
        mode: u32,
    },
    File {
        path: PathBuf,
        mode: u32,
        content: ContentRef,
    },
    Symlink {
        path: PathBuf,
        target: PathBuf,
    },
}

impl TreeEntry {
    fn path(&self) -> &Path {
        match self {
            Self::Directory { path, .. } | Self::File { path, .. } | Self::Symlink { path, .. } => {
                path
            }
        }
    }
}

/// Measures one closed worker installation from its bounded build instructions.
///
/// # Errors
///
/// Returns an error for argument/schema mismatch, unsupported path or tree
/// geometry, content drift, missing closure members, or exceeded existing bounds.
pub(super) fn run(mut arguments: impl Iterator<Item = std::ffi::OsString>) -> Result<(), Failure> {
    let input = PathBuf::from(arguments.next().ok_or("expected worker input document")?);
    let output = PathBuf::from(arguments.next().ok_or("expected worker output directory")?);
    if arguments.next().is_some() {
        return Err("unexpected worker measurement argument".into());
    }
    let inputs: WorkerInputs = decode_metadata(&read_argument_metadata(&input)?)?;
    require_store_path(&output)?;
    let mut total = 0;
    let launcher = measure(&inputs.launcher, "application/octet-stream", &mut total)?;
    let worker = measure(&inputs.worker, "application/octet-stream", &mut total)?;
    let source = measure(&inputs.source, "application/gzip", &mut total)?;
    let vendor = measure(&inputs.vendor, "application/gzip", &mut total)?;
    let recipe = measure(&inputs.recipe, "text/plain", &mut total)?;

    let graph: ReferenceGraph = decode_metadata(&read_metadata(&inputs.reference_graph)?)?;
    let expected = [&launcher.path, &worker.path]
        .into_iter()
        .map(|path| require_store_path(path))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let paths = validate_graph(&graph, &expected)?;
    if paths.len() > MAXIMUM_READ_ONLY_ROOTS {
        return Err("pure-worker runtime exceeds its fixed root inventory".into());
    }
    let (entries, objects) = measure_tree(&paths, &mut total)?;
    for root in [&launcher, &worker] {
        if !objects
            .iter()
            .any(|object| object.path == root.path && object.content == root.content)
        {
            return Err(
                "worker or launcher is absent from the measured runtime ELF closure".into(),
            );
        }
    }
    let closure = WorkerClosure {
        schema: "crucible.pure-worker.runtime-closure/1",
        reference_graph: measure(&inputs.reference_graph, "application/json", &mut total)?,
        store_paths: paths.clone(),
        objects,
        entries,
    };
    let runtime_path = output.join("runtime-closure.json");
    write_canonical(&runtime_path, &closure)?;

    let algorithm_path = output.join("algorithm.json");
    write_canonical(
        &algorithm_path,
        &Algorithm {
            schema: "crucible.pure-worker.algorithm/1",
            id: "crucible.source-birth.derivation/1",
            source: source.content.clone(),
            vendor: vendor.content.clone(),
            recipe: recipe.content.clone(),
        },
    )?;
    let request_path = output.join("request-codec.json");
    let result_path = output.join("result-codec.json");
    for (path, id, magic, header_bytes) in [
        (
            &request_path,
            "crucible.source-birth.request/1",
            "CSBIN001",
            160,
        ),
        (
            &result_path,
            "crucible.source-birth.result/1",
            "CSBR0001",
            240,
        ),
    ] {
        write_canonical(
            path,
            &Codec {
                schema: "crucible.pure-worker.codec/1",
                id,
                magic,
                version: 1,
                header_bytes,
                source: source.content.clone(),
            },
        )?;
    }
    let installation = Installation {
        schema: "crucible.pure-worker.installation/1",
        profile: "pure-worker-v1",
        launcher,
        worker,
        runtime_closure: measure(&runtime_path, "application/json", &mut total)?,
        read_only_roots: paths,
        source,
        vendor,
        recipe,
        algorithm: measure(&algorithm_path, "application/json", &mut total)?,
        request_codec: measure(&request_path, "application/json", &mut total)?,
        result_codec: measure(&result_path, "application/json", &mut total)?,
    };
    write_canonical(&output.join("installation.json"), &installation)
}

fn measure_tree(
    paths: &[PathBuf],
    total: &mut u64,
) -> Result<(Vec<TreeEntry>, Vec<Artifact>), Failure> {
    let mut pending = paths.to_vec();
    let mut entries = BTreeMap::new();
    let mut objects = BTreeMap::new();
    while let Some(path) = pending.pop() {
        if entries
            .len()
            .checked_add(pending.len())
            .is_none_or(|count| count >= MAXIMUM_VISITED_FILES)
        {
            return Err("worker runtime inventory exceeds its finite allowance".into());
        }
        require_store_path(&path)?;
        let metadata = std::fs::symlink_metadata(&path)?;
        let entry = if metadata.is_dir() {
            for child in std::fs::read_dir(&path)? {
                if entries
                    .len()
                    .checked_add(pending.len())
                    .is_none_or(|count| count >= MAXIMUM_VISITED_FILES)
                {
                    return Err(
                        "worker runtime pending inventory exceeds its finite allowance".into(),
                    );
                }
                pending.push(child?.path());
            }
            TreeEntry::Directory {
                path: path.clone(),
                mode: metadata.mode() & 0o7777,
            }
        } else if metadata.is_file() {
            let (artifact, elf, mode) = measure_runtime_file(&path, total)?;
            if elf {
                if objects.len() >= MAXIMUM_ELF_OBJECTS {
                    return Err("worker runtime ELF inventory exceeds its finite allowance".into());
                }
                objects.insert(path.clone(), artifact.clone());
            }
            TreeEntry::File {
                path: path.clone(),
                mode,
                content: artifact.content,
            }
        } else if metadata.file_type().is_symlink() {
            TreeEntry::Symlink {
                path: path.clone(),
                target: std::fs::read_link(&path)?,
            }
        } else {
            return Err("worker runtime contains a non-file object".into());
        };
        if entries.insert(path, entry).is_some() {
            return Err("worker runtime contains a repeated name".into());
        }
    }
    for entry in entries.values() {
        if matches!(entry, TreeEntry::Symlink { .. }) {
            resolve_link(entry.path(), &entries, paths)?;
        }
    }
    Ok((
        entries.into_values().collect(),
        objects.into_values().collect(),
    ))
}

// Classify and hash the same opened original, including executable mode.
fn measure_runtime_file(path: &Path, total: &mut u64) -> Result<(Artifact, bool, u32), Failure> {
    let mut file = open_regular(path)?;
    let before = file.metadata()?;
    if before.len() > MAXIMUM_ARTIFACT_BYTES {
        return Err("worker runtime file exceeds its finite allowance".into());
    }
    *total = total
        .checked_add(before.len())
        .filter(|size| *size <= MAXIMUM_MEASURED_BYTES)
        .ok_or("worker runtime content exceeds its finite allowance")?;
    let mut magic = [0; 4];
    if before.len() >= 4 {
        file.read_exact(&mut magic)?;
        file.seek(SeekFrom::Start(0))?;
    }
    let hash = hash_stream(&mut file, before.len())?;
    let after = file.metadata()?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.mode(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.mode(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) {
        return Err("worker runtime original changed during measurement".into());
    }
    Ok((
        Artifact {
            path: path.to_path_buf(),
            content: ContentRef {
                hash,
                length: U64::new(before.len()),
                media_type: "application/octet-stream".into(),
            },
        },
        magic == *b"\x7fELF",
        before.mode() & 0o7777,
    ))
}

// Resolve only names already present in the measured tree. Expand each link
// before interpreting a subsequent `..`, matching actual pathname traversal.
// Neither filesystem canonicalization nor a broad store-directory grant may
// supply an omitted target, intermediate link, or other filesystem object.
fn resolve_link(
    path: &Path,
    entries: &BTreeMap<PathBuf, TreeEntry>,
    roots: &[PathBuf],
) -> Result<PathBuf, Failure> {
    let mut pending = path.to_path_buf();
    let mut seen = BTreeSet::new();
    for _ in 0..MAXIMUM_VISITED_FILES {
        if pending.as_os_str().len() > 4096
            || !pending.is_absolute()
            || !seen.insert(pending.clone())
        {
            return Err("worker runtime symlink is cyclic or oversized".into());
        }
        let mut prefix = PathBuf::new();
        // Retain `.` and a trailing slash: traversing `file/.` or `file/`
        // requires a directory, even though Path::components normalizes them.
        let components = pending
            .to_str()
            .ok_or("worker link is not UTF-8")?
            .split('/')
            .collect::<Vec<_>>();
        prefix.push("/");
        let mut replaced = false;
        for (index, component) in components.iter().enumerate() {
            match *component {
                "" | "." => {}
                ".." => {
                    if !prefix.pop() {
                        return Err("worker symlink escapes filesystem root".into());
                    }
                }
                name => {
                    prefix.push(name);
                    if prefix == Path::new("/nix") || prefix == Path::new("/nix/store") {
                        continue;
                    }
                    if roots.binary_search(&require_store_path(&prefix)?).is_err() {
                        return Err("worker runtime symlink escapes its exact closure".into());
                    }
                    let entry = entries
                        .get(&prefix)
                        .ok_or("worker runtime symlink target is absent")?;
                    if let TreeEntry::Symlink { target, .. } = entry {
                        let mut next = if target.is_absolute() {
                            target.clone()
                        } else {
                            prefix.parent().ok_or("symlink has no parent")?.join(target)
                        };
                        for suffix in &components[index + 1..] {
                            next.push(suffix);
                        }
                        pending = next;
                        replaced = true;
                        break;
                    }
                    if index + 1 < components.len() && !matches!(entry, TreeEntry::Directory { .. })
                    {
                        return Err("worker runtime symlink traverses a non-directory".into());
                    }
                }
            }
        }
        if !replaced {
            if roots.binary_search(&require_store_path(&prefix)?).is_err()
                || !entries.contains_key(&prefix)
            {
                return Err("worker runtime symlink target is absent".into());
            }
            return Ok(prefix);
        }
    }
    Err("worker runtime symlink resolution is excessive".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_worker_dispatch_refuses_missing_and_extra_arguments() {
        assert!(run(Vec::<std::ffi::OsString>::new().into_iter()).is_err());
        assert!(
            run(["input", "output", "extra"]
                .map(std::ffi::OsString::from)
                .into_iter())
            .is_err()
        );
    }

    #[test]
    fn measured_link_resolution_rejects_escape_missing_and_cycles() -> Result<(), Failure> {
        let root = PathBuf::from(format!("/nix/store/{}-worker", "a".repeat(32)));
        let file = root.join("file");
        let link = root.join("link");
        let mut entries = BTreeMap::from([
            (
                root.clone(),
                TreeEntry::Directory {
                    path: root.clone(),
                    mode: 0o555,
                },
            ),
            (
                file.clone(),
                TreeEntry::Directory {
                    path: file.clone(),
                    mode: 0o555,
                },
            ),
            (
                link.clone(),
                TreeEntry::Symlink {
                    path: link.clone(),
                    target: PathBuf::from("file"),
                },
            ),
        ]);
        assert_eq!(
            resolve_link(&link, &entries, std::slice::from_ref(&root))?,
            file
        );
        let directory = root.join("directory");
        let nested = directory.join("nested");
        let selected = directory.join("file");
        let route = root.join("route");
        for path in [&directory, &nested, &selected] {
            entries.insert(
                path.clone(),
                TreeEntry::Directory {
                    path: path.clone(),
                    mode: 0o555,
                },
            );
        }
        entries.insert(
            route.clone(),
            TreeEntry::Symlink {
                path: route.clone(),
                target: PathBuf::from("directory/nested"),
            },
        );
        entries.insert(
            link.clone(),
            TreeEntry::Symlink {
                path: link.clone(),
                target: PathBuf::from("route/../file"),
            },
        );
        assert_eq!(
            resolve_link(&link, &entries, std::slice::from_ref(&root))?,
            selected
        );
        entries.insert(
            route.clone(),
            TreeEntry::Symlink {
                path: route,
                target: PathBuf::from("/etc"),
            },
        );
        assert!(resolve_link(&link, &entries, std::slice::from_ref(&root)).is_err());
        let plain = root.join("plain");
        entries.insert(
            plain.clone(),
            TreeEntry::File {
                path: plain.clone(),
                mode: 0o444,
                content: ContentRef {
                    hash: canonical::hash("cnp.blob.v1", b"")?,
                    length: U64::new(0),
                    media_type: "application/octet-stream".into(),
                },
            },
        );
        entries.insert(
            link.clone(),
            TreeEntry::Symlink {
                path: link.clone(),
                target: PathBuf::from("plain"),
            },
        );
        assert_eq!(
            resolve_link(&link, &entries, std::slice::from_ref(&root))?,
            plain
        );
        for target in ["missing", "link", "/etc/passwd", "plain/", "plain/."] {
            entries.insert(
                link.clone(),
                TreeEntry::Symlink {
                    path: link.clone(),
                    target: PathBuf::from(target),
                },
            );
            assert!(resolve_link(&link, &entries, std::slice::from_ref(&root)).is_err());
        }
        Ok(())
    }
}
