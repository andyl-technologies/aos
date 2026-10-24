//! Checks actual ELF interpreter and explicit library search closure.
//!
//! The supported installed profile resolves every needed object through already
//! loaded SONAMEs or the measured ELF RPATH/RUNPATH. It never treats arbitrary
//! basename membership, host ld.so.cache or default host directories as proof.
//! DT_NEEDED tokens and directory-alias search alternatives are unsupported;
//! RPATH/RUNPATH retain their checked ORIGIN substitution. An installation
//! requiring an unmeasured lookup is refused before Source.

use super::*;
use std::collections::VecDeque;

struct Dynamic {
    interpreter: Option<PathBuf>,
    soname: Option<String>,
    needed: Vec<String>,
    rpath: Vec<PathBuf>,
    runpath: Vec<PathBuf>,
}

pub(super) fn check_program(
    installed: &Installation,
    program: &LinuxPureWorkerProgram,
    entries: &BTreeMap<PathBuf, &TreeEntry>,
    roots: &[PathBuf],
) -> Result<(), Failure> {
    // Launcher and worker each start a fresh exec image; loaded names and RPATH
    // ancestry from the parent process never authenticate either image.
    for (path, original) in [
        (&installed.launcher.path, program.launcher_file()),
        (&installed.worker.path, program.worker_file()),
    ] {
        check_image(path, original, entries, roots, open_regular)?;
    }

    Ok(())
}

/// Checks one exec image with its own loaded names and RPATH ancestry.
fn check_image(
    path: &Path,
    original: &File,
    entries: &BTreeMap<PathBuf, &TreeEntry>,
    roots: &[PathBuf],
    open_dependency: impl Fn(&Path) -> Result<File, Failure>,
) -> Result<(), Failure> {
    let main = parse(original, path)?;
    let mut loaded = BTreeMap::<String, PathBuf>::new();
    let mut visited = BTreeSet::new();
    let mut originals = BTreeMap::new();
    let main_metadata = original
        .metadata()
        .map_err(|_| RuntimeError::OwnerUnavailable)?;
    originals.insert(
        (main_metadata.dev(), main_metadata.ino()),
        path.to_path_buf(),
    );
    let mut queue = VecDeque::new();
    if let Some(interpreter) = &main.interpreter {
        let resolved = resolve(interpreter, entries, roots)?;
        let file = open_dependency(&resolved)?;
        let dynamic = parse(&file, &resolved)?;
        if dynamic.interpreter.is_some() || !dynamic.needed.is_empty() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let metadata = file
            .metadata()
            .map_err(|_| RuntimeError::OwnerUnavailable)?;
        originals.insert((metadata.dev(), metadata.ino()), resolved.clone());
        remember(&mut loaded, &resolved, &dynamic);
        queue.push_back((resolved, dynamic, Vec::<PathBuf>::new()));
    }
    remember(&mut loaded, path, &main);
    queue.push_back((path.to_path_buf(), main, Vec::<PathBuf>::new()));

    // Resolve a whole object's DT_NEEDED list before visiting children, as
    // the loader link-map establishes direct dependencies breadth first.
    while let Some((path, dynamic, ancestry)) = queue.pop_front() {
        if !visited.insert(path.clone()) {
            continue;
        }
        if visited.len() + queue.len() > MAXIMUM_OBJECTS {
            return Err(RuntimeError::ResourceLimit);
        }
        let mut inherited = if dynamic.runpath.is_empty() {
            dynamic.rpath.clone()
        } else {
            Vec::new()
        };
        inherited.extend(ancestry);
        for needed in &dynamic.needed {
            // RUNPATH suppresses the RPATH ancestry for this lookup;
            // descendants without RUNPATH still receive the ancestry.
            let paths = if dynamic.runpath.is_empty() {
                &inherited
            } else {
                &dynamic.runpath
            };
            let Some(candidate) = select_needed(needed, &path, &loaded, paths, entries, roots)?
            else {
                continue;
            };
            if !matches!(entries.get(&candidate), Some(TreeEntry::File { .. })) {
                return Err(RuntimeError::UnsupportedFacet);
            }
            let file = open_dependency(&candidate)?;
            let metadata = file
                .metadata()
                .map_err(|_| RuntimeError::OwnerUnavailable)?;
            let identity = (metadata.dev(), metadata.ino());
            if let Some(original) = originals.get(&identity) {
                loaded.insert(needed.clone(), original.clone());
                continue;
            }
            let child = parse(&file, &candidate)?;
            originals.insert(identity, candidate.clone());
            // PT_INTERP belongs to an exec image, not a DT_NEEDED mapping.
            // Glibc's libc carries one for direct execution; the loader ignores
            // it when mapping libc as a dependency. Only the main interpreter
            // above is an actual edge that must resolve inside this closure.
            loaded.insert(needed.clone(), candidate.clone());
            remember(&mut loaded, &candidate, &child);
            queue.push_back((candidate, child, inherited.clone()));
        }
    }
    Ok(())
}

fn select_needed(
    needed: &str,
    owner: &Path,
    loaded: &BTreeMap<String, PathBuf>,
    paths: &[PathBuf],
    entries: &BTreeMap<PathBuf, &TreeEntry>,
    roots: &[PathBuf],
) -> Result<Option<PathBuf>, Failure> {
    // Glibc expands DT_NEEDED tokens before loaded-name lookup. This closed
    // profile refuses those forms before consulting any alias, so two owner
    // origins can never share an unexpanded `$ORIGIN/...` cache entry.
    // RPATH/RUNPATH retain their separate supported ORIGIN expansion.
    if needed.contains('$') {
        return Err(RuntimeError::UnsupportedFacet);
    }
    if loaded.contains_key(needed) {
        return Ok(None);
    }
    if needed.contains('/') {
        return resolve(&expand(needed, owner)?, entries, roots).map(Some);
    }
    for directory in paths {
        let directory = resolve(directory, entries, roots)?;
        if !matches!(entries.get(&directory), Some(TreeEntry::Directory { .. })) {
            return Err(RuntimeError::UnsupportedFacet);
        }
        // Glibc tries hardware-capability suffixes before the base directory.
        // The inventory is intentionally no-follow: a directory symlink can
        // hide an alternate in another measured root. Refuse such aliases and
        // nested same-name candidates rather than guess this host's suffixes.
        for (path, entry) in entries {
            if !path.starts_with(&directory) {
                continue;
            }
            if matches!(entry, TreeEntry::Symlink { .. }) {
                let target = resolve(path, entries, roots)?;
                if matches!(entries.get(&target), Some(TreeEntry::Directory { .. })) {
                    return Err(RuntimeError::UnsupportedFacet);
                }
            }
            if path.parent() != Some(directory.as_path())
                && path
                    .file_name()
                    .is_some_and(|name| name == std::ffi::OsStr::new(needed))
                && !matches!(entry, TreeEntry::Directory { .. })
            {
                return Err(RuntimeError::UnsupportedFacet);
            }
        }
        let candidate = directory.join(needed);
        // A missing candidate is a normal search miss. Existing wrong-type or
        // foreign links are not silently skipped.
        if entries.contains_key(&candidate) {
            return resolve(&candidate, entries, roots).map(Some);
        }
    }
    Err(RuntimeError::UnsupportedFacet)
}

fn remember(loaded: &mut BTreeMap<String, PathBuf>, path: &Path, dynamic: &Dynamic) {
    // Reuse only an actual SONAME or the exact DT_NEEDED alias installed by the
    // caller. Mere basename equality is not dynamic-loader identity.
    if let Some(name) = &dynamic.soname {
        loaded
            .entry(name.clone())
            .or_insert_with(|| path.to_path_buf());
    }
}

fn parse(file: &File, path: &Path) -> Result<Dynamic, Failure> {
    let header = read::<64>(file, 0)?;
    // The source-built installed worker profile is ELF64 little endian on the
    // selected Linux target. This check constrains installations, never input
    // Launch/Value grammar or the pure derivation algorithm.
    let machine = if cfg!(target_arch = "x86_64") {
        62
    } else if cfg!(target_arch = "aarch64") {
        183
    } else {
        return Err(RuntimeError::UnsupportedFacet);
    };
    if &header[..4] != b"\x7fELF"
        || header[4] != 2
        || header[5] != 1
        || header[6] != 1
        || !matches!(u16_at(&header, 16)?, 2 | 3)
        || u16_at(&header, 18)? != machine
        || !matches!(header[7], 0 | 3)
        || header[8] != 0
        || header[9..16].iter().any(|byte| *byte != 0)
        || u32_at(&header, 20)? != 1
        || u16_at(&header, 52)? != 64
        || u16_at(&header, 54)? != 56
    {
        return Err(RuntimeError::UnsupportedFacet);
    }
    let count = usize::from(u16_at(&header, 56)?);
    if count == 0 || count > 4096 {
        return Err(RuntimeError::UnsupportedFacet);
    }
    let offset = u64_at(&header, 32)?;
    let file_length = file
        .metadata()
        .map_err(|_| RuntimeError::OwnerUnavailable)?
        .len();
    let mut loads = Vec::new();
    let mut interpreter = None;
    let mut dynamic = None;
    for index in 0..count {
        let position = offset
            .checked_add(
                (index as u64)
                    .checked_mul(56)
                    .ok_or(RuntimeError::ResourceLimit)?,
            )
            .ok_or(RuntimeError::ResourceLimit)?;
        let record = read::<56>(file, position)?;
        let tag = u32_at(&record, 0)?;
        let offset = u64_at(&record, 8)?;
        let address = u64_at(&record, 16)?;
        let size = u64_at(&record, 32)?;
        if offset.checked_add(size).is_none_or(|end| end > file_length) {
            return Err(RuntimeError::InvalidReceipt);
        }
        match tag {
            1 => loads.push((address, offset, size)),
            2 => {
                if dynamic.replace((offset, size)).is_some() {
                    return Err(RuntimeError::InvalidReceipt);
                }
            }
            3 => {
                if interpreter.is_some() || size == 0 || size > 4096 {
                    return Err(RuntimeError::InvalidReceipt);
                }
                let bytes = read_bytes(file, offset, size as usize)?;
                interpreter = Some(PathBuf::from(cstring(&bytes)?));
                if !interpreter.as_ref().is_some_and(|path| path.is_absolute()) {
                    return Err(RuntimeError::UnsupportedFacet);
                }
            }
            _ => {}
        }
    }
    let Some((offset, size)) = dynamic else {
        return Ok(Dynamic {
            interpreter,
            soname: None,
            needed: Vec::new(),
            rpath: Vec::new(),
            runpath: Vec::new(),
        });
    };
    if size % 16 != 0 || size / 16 > 4096 {
        return Err(RuntimeError::UnsupportedFacet);
    }
    let mut table = None;
    let mut table_size = None;
    let mut needed = Vec::new();
    let mut soname = None;
    let mut rpath = None;
    let mut runpath = None;
    let mut terminated = false;
    for index in 0..size / 16 {
        let record = read::<16>(
            file,
            offset
                .checked_add(index * 16)
                .ok_or(RuntimeError::ResourceLimit)?,
        )?;
        let tag = u64_at(&record, 0)?;
        let value = u64_at(&record, 8)?;
        match tag {
            0 => {
                terminated = true;
                break;
            }
            1 => needed.push(value),
            5 => table = Some(value),
            10 => table_size = Some(value),
            14 => soname = Some(value),
            15 => rpath = Some(value),
            29 => runpath = Some(value),
            // Audit/filter objects add loader paths/callback images that this
            // closed operational profile does not authenticate.
            0x6fff_fefb | 0x6fff_fefc | 0x7fff_fffd | 0x7fff_ffff => {
                return Err(RuntimeError::UnsupportedFacet);
            }
            _ => {}
        }
    }
    if !terminated {
        return Err(RuntimeError::InvalidReceipt);
    }
    let mut string = |index: u64| -> Result<String, Failure> {
        let table = table.ok_or(RuntimeError::InvalidReceipt)?;
        let length = table_size.ok_or(RuntimeError::InvalidReceipt)?;
        if index >= length {
            return Err(RuntimeError::InvalidReceipt);
        }
        let address = table
            .checked_add(index)
            .ok_or(RuntimeError::ResourceLimit)?;
        let remaining = length - index;
        let (start, limit) = loads
            .iter()
            .find_map(|(base, offset, size)| {
                let relative = address.checked_sub(*base)?;
                if relative >= *size {
                    return None;
                }
                Some((
                    offset.checked_add(relative)?,
                    remaining.min(size - relative).min(4096),
                ))
            })
            .ok_or(RuntimeError::InvalidReceipt)?;
        let bytes = read_bytes(file, start, limit as usize)?;
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(RuntimeError::UnsupportedFacet)?;
        let text =
            std::str::from_utf8(&bytes[..end]).map_err(|_| RuntimeError::UnsupportedFacet)?;
        if text.is_empty() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        Ok(text.to_owned())
    };
    let soname = soname.map(&mut string).transpose()?;
    let needed = needed
        .into_iter()
        .map(&mut string)
        .collect::<Result<Vec<_>, _>>()?;
    let rpath = rpath
        .map(&mut string)
        .transpose()?
        .map(|text| search_paths(&text, path))
        .transpose()?
        .unwrap_or_default();
    let runpath = runpath
        .map(&mut string)
        .transpose()?
        .map(|text| search_paths(&text, path))
        .transpose()?
        .unwrap_or_default();
    Ok(Dynamic {
        interpreter,
        soname,
        needed,
        rpath,
        runpath,
    })
}

fn search_paths(text: &str, original: &Path) -> Result<Vec<PathBuf>, Failure> {
    text.split(':').map(|text| expand(text, original)).collect()
}

fn expand(text: &str, original: &Path) -> Result<PathBuf, Failure> {
    let origin = original
        .parent()
        .and_then(Path::to_str)
        .ok_or(RuntimeError::UnsupportedFacet)?;
    let mut expanded = String::new();
    let mut rest = text;
    while let Some(index) = rest.find('$') {
        expanded.push_str(&rest[..index]);
        rest = &rest[index..];
        if let Some(suffix) = rest.strip_prefix("${ORIGIN}") {
            expanded.push_str(origin);
            rest = suffix;
        } else if let Some(suffix) = rest.strip_prefix("$ORIGIN") {
            if suffix
                .as_bytes()
                .first()
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                return Err(RuntimeError::UnsupportedFacet);
            }
            expanded.push_str(origin);
            rest = suffix;
        } else {
            return Err(RuntimeError::UnsupportedFacet);
        }
    }
    expanded.push_str(rest);
    let text = expanded;
    if text.contains('$') || text.is_empty() || !Path::new(&text).is_absolute() {
        return Err(RuntimeError::UnsupportedFacet);
    }
    Ok(PathBuf::from(text))
}

fn cstring(bytes: &[u8]) -> Result<&str, Failure> {
    let (last, body) = bytes.split_last().ok_or(RuntimeError::InvalidReceipt)?;
    if *last != 0 || body.contains(&0) {
        return Err(RuntimeError::InvalidReceipt);
    }
    std::str::from_utf8(body).map_err(|_| RuntimeError::UnsupportedFacet)
}

fn read<const N: usize>(file: &File, offset: u64) -> Result<[u8; N], Failure> {
    let mut bytes = [0; N];
    file.read_exact_at(&mut bytes, offset)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    Ok(bytes)
}

fn read_bytes(file: &File, offset: u64, length: usize) -> Result<Vec<u8>, Failure> {
    let mut bytes = vec![0; length];
    file.read_exact_at(&mut bytes, offset)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    Ok(bytes)
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, Failure> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(RuntimeError::InvalidReceipt)?
            .try_into()
            .map_err(|_| RuntimeError::InvalidReceipt)?,
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, Failure> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(RuntimeError::InvalidReceipt)?
            .try_into()
            .map_err(|_| RuntimeError::InvalidReceipt)?,
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, Failure> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(RuntimeError::InvalidReceipt)?
            .try_into()
            .map_err(|_| RuntimeError::InvalidReceipt)?,
    ))
}

#[cfg(test)]
#[path = "loader/tests.rs"]
mod tests;
