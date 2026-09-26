//! Independent `PT_INTERP` and transitive `DT_NEEDED` closure verification.
//!
//! The signed V2 inventory supplies file identities, not dependency edges.
//! This reader derives those edges from the retained ELF descriptors and
//! resolves each dependency through its encoded Nix-store search paths. It
//! deliberately rejects unsupported loader features and ambiguous resolution;
//! it does not execute a loader or accept another signer-supplied allowlist.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use super::{
    InspectorDeploymentErrorV2, MemberRole, RetainedMember, canonical_store_file, io_error,
    read_exact_at, require_canonical_path,
};

const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const MAXIMUM_PROGRAM_HEADERS: usize = 128;
const MAXIMUM_DYNAMIC_ENTRIES: usize = 4096;
const MAXIMUM_NEEDED: usize = 128;
const MAXIMUM_SEARCH_DIRECTORIES: usize = 128;
const MAXIMUM_STRING_BYTES: usize = 512;
const MAXIMUM_DIRECTORY_ENTRIES: usize = 8192;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;
const DT_SONAME: u64 = 14;
const DT_RPATH: u64 = 15;
const DT_RUNPATH: u64 = 29;
const DT_CONFIG: u64 = 0x6fff_fefa;
const DT_DEPAUDIT: u64 = 0x6fff_fefb;
const DT_AUDIT: u64 = 0x6fff_fefc;
const DT_AUXILIARY: u64 = 0x7fff_fffd;
const DT_FILTER: u64 = 0x7fff_ffff;

#[derive(Clone, Copy)]
struct LoadSegment {
    offset: u64,
    address: u64,
    length: u64,
}

#[derive(Debug)]
struct ElfDependencies {
    object_type: u16,
    interpreter: Option<String>,
    soname: Option<String>,
    needed: Vec<String>,
    rpath: Option<Vec<String>>,
    runpath: Option<Vec<String>>,
}

/// Verifies one signed executable's complete statically declared load graph.
pub(super) fn verify_service(
    members: &[RetainedMember],
    inspector: bool,
) -> Result<(), InspectorDeploymentErrorV2> {
    verify_service_with_owner(members, inspector, (0, 0))
}

// The owner parameter lets the nonroot Nix build fixture exercise the real
// dependency walk; the production entrypoint above always requires root.
fn verify_service_with_owner(
    members: &[RetainedMember],
    inspector: bool,
    directory_owner: (u32, u32),
) -> Result<(), InspectorDeploymentErrorV2> {
    let root_role = if inspector {
        MemberRole::Inspector
    } else {
        MemberRole::LifecycleWorker
    };
    let root = members
        .iter()
        .position(|member| member.expectation.role == root_role)
        .ok_or(InspectorDeploymentErrorV2::Invalid)?;
    let mut visited = BTreeMap::<usize, Vec<String>>::new();
    let mut names = BTreeMap::<String, usize>::new();
    let mut pending = vec![(root, Vec::new())];
    let mut interpreter = None;

    while let Some((index, inherited_rpath)) = pending.pop() {
        if let Some(previous) = visited.get(&index) {
            if previous != &inherited_rpath {
                return Err(InspectorDeploymentErrorV2::Invalid);
            }
            continue;
        }
        if visited.len() >= members.len() {
            return Err(InspectorDeploymentErrorV2::Invalid);
        }
        visited.insert(index, inherited_rpath.clone());

        let member = &members[index];
        let bytes = read_exact_at(&member.descriptor, member.expectation.length)?;
        let elf = parse_elf(&bytes)?;
        if index == root {
            if elf.soname.is_some() {
                return Err(InspectorDeploymentErrorV2::Invalid);
            }
            let path = elf
                .interpreter
                .as_deref()
                .ok_or(InspectorDeploymentErrorV2::Invalid)?;
            let resolved = resolve_absolute(path, members, MemberRole::Interpreter)?;
            let loader = &members[resolved];
            let loader_bytes = read_exact_at(&loader.descriptor, loader.expectation.length)?;
            let loader_elf = parse_elf(&loader_bytes)?;
            if loader_elf.object_type != 3
                || loader_elf.interpreter.is_some()
                || !loader_elf.needed.is_empty()
            {
                return Err(InspectorDeploymentErrorV2::Invalid);
            }
            if let Some(name) = loader_elf.soname {
                remember_name(&mut names, name, resolved)?;
            }
            interpreter = Some(resolved);
        } else {
            if elf.object_type != 3 {
                return Err(InspectorDeploymentErrorV2::Invalid);
            }
            if let Some(path) = elf.interpreter.as_deref() {
                let resolved = resolve_absolute(path, members, MemberRole::Interpreter)?;
                if Some(resolved) != interpreter {
                    return Err(InspectorDeploymentErrorV2::Invalid);
                }
            }
            if let Some(name) = elf.soname.as_ref() {
                remember_name(&mut names, name.clone(), index)?;
            }
        }

        let (search, child_rpath) = search_plan(&elf, &inherited_rpath, directory_owner)?;
        for needed in &elf.needed {
            let resolved = resolve_needed(needed, &search, members)?;
            remember_name(&mut names, needed.clone(), resolved)?;
            if Some(resolved) != interpreter {
                pending.push((resolved, child_rpath.clone()));
            }
        }
    }

    interpreter.ok_or(InspectorDeploymentErrorV2::Invalid)?;
    Ok(())
}

fn remember_name(
    names: &mut BTreeMap<String, usize>,
    name: String,
    index: usize,
) -> Result<(), InspectorDeploymentErrorV2> {
    if !valid_library_name(&name) || names.insert(name, index).is_some_and(|old| old != index) {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    Ok(())
}

fn valid_library_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAXIMUM_STRING_BYTES
        && !name.contains('/')
        && !name.contains('$')
}

fn search_plan(
    elf: &ElfDependencies,
    inherited_rpath: &[String],
    directory_owner: (u32, u32),
) -> Result<(Vec<String>, Vec<String>), InspectorDeploymentErrorV2> {
    // RUNPATH is direct-only. Do not inherit it to children or use a
    // parent path to rescue a missing direct RUNPATH dependency.
    if let Some(runpath) = elf.runpath.as_ref() {
        return Ok((
            search_directories(Some(runpath), &[], directory_owner)?,
            Vec::new(),
        ));
    }
    let paths = search_directories(elf.rpath.as_ref(), inherited_rpath, directory_owner)?;
    Ok((paths.clone(), paths))
}

fn search_directories(
    own: Option<&Vec<String>>,
    inherited: &[String],
    expected_owner: (u32, u32),
) -> Result<Vec<String>, InspectorDeploymentErrorV2> {
    let mut result = Vec::new();
    for path in own.into_iter().flatten().chain(inherited) {
        if !result.contains(path) {
            result.push(path.clone());
        }
    }
    if result.len() > MAXIMUM_SEARCH_DIRECTORIES {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    for directory in &result {
        let path = Path::new(directory);
        require_canonical_path(path)?;
        let metadata = std::fs::metadata(path)
            .map_err(|source| io_error("inspect ELF search directory", source))?;
        if !metadata.is_dir()
            || (metadata.uid(), metadata.gid()) != expected_owner
            || metadata.mode() & 0o222 != 0
        {
            return Err(InspectorDeploymentErrorV2::Invalid);
        }
    }
    Ok(result)
}

fn resolve_needed(
    name: &str,
    directories: &[String],
    members: &[RetainedMember],
) -> Result<usize, InspectorDeploymentErrorV2> {
    if !valid_library_name(name) {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    let mut paths = BTreeSet::<PathBuf>::new();
    for directory in directories {
        reject_nested_candidate(Path::new(directory), name)?;
        let candidate = Path::new(directory).join(name);
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) => {
                paths.insert(
                    std::fs::canonicalize(&candidate)
                        .map_err(|source| io_error("resolve ELF dependency candidate", source))?,
                );
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error("inspect ELF dependency candidate", source)),
        }
    }
    if paths.len() != 1 {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    let path = paths
        .into_iter()
        .next()
        .ok_or(InspectorDeploymentErrorV2::Invalid)?;
    resolve_member(
        &path,
        members,
        &[MemberRole::Library, MemberRole::Interpreter],
    )
}

// glibc may prefer a hardware-capability copy below an RPATH directory.
// Reject nested same-name candidates rather than model host CPU selection.
fn reject_nested_candidate(directory: &Path, name: &str) -> Result<(), InspectorDeploymentErrorV2> {
    let mut pending = vec![directory.to_path_buf()];
    let mut entries = 0;
    while let Some(parent) = pending.pop() {
        for entry in std::fs::read_dir(&parent)
            .map_err(|source| io_error("scan ELF search directory", source))?
        {
            let entry = entry.map_err(|source| io_error("inspect ELF search entry", source))?;
            entries += 1;
            if entries > MAXIMUM_DIRECTORY_ENTRIES {
                return Err(InspectorDeploymentErrorV2::Invalid);
            }
            let kind = entry
                .file_type()
                .map_err(|source| io_error("inspect ELF search entry type", source))?;
            if kind.is_dir() {
                if entry.file_name() == name {
                    return Err(InspectorDeploymentErrorV2::Invalid);
                }
                pending.push(entry.path());
            } else if kind.is_symlink() {
                let metadata = std::fs::metadata(entry.path())
                    .map_err(|source| io_error("resolve ELF search symlink", source))?;
                if metadata.is_dir() || (parent != directory && entry.file_name() == name) {
                    return Err(InspectorDeploymentErrorV2::Invalid);
                }
            } else if parent != directory && entry.file_name() == name {
                return Err(InspectorDeploymentErrorV2::Invalid);
            }
        }
    }
    Ok(())
}

fn resolve_absolute(
    path: &str,
    members: &[RetainedMember],
    role: MemberRole,
) -> Result<usize, InspectorDeploymentErrorV2> {
    if !canonical_store_file(path) {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    let physical = std::fs::canonicalize(path)
        .map_err(|source| io_error("resolve ELF interpreter", source))?;
    resolve_member(&physical, members, &[role])
}

fn resolve_member(
    physical: &Path,
    members: &[RetainedMember],
    roles: &[MemberRole],
) -> Result<usize, InspectorDeploymentErrorV2> {
    let path = physical
        .to_str()
        .ok_or(InspectorDeploymentErrorV2::Invalid)?;
    if !canonical_store_file(path) {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    let index = members
        .iter()
        .position(|member| {
            roles.contains(&member.expectation.role) && member.expectation.path == path
        })
        .ok_or(InspectorDeploymentErrorV2::Invalid)?;
    verify_member_identity(physical, &members[index])?;
    Ok(index)
}

fn verify_member_identity(
    physical: &Path,
    member: &RetainedMember,
) -> Result<(), InspectorDeploymentErrorV2> {
    let metadata = std::fs::metadata(physical)
        .map_err(|source| io_error("inspect ELF closure member", source))?;
    if metadata.dev() != member.device || metadata.ino() != member.inode {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    Ok(())
}

fn parse_elf(bytes: &[u8]) -> Result<ElfDependencies, InspectorDeploymentErrorV2> {
    if bytes.len() < ELF_HEADER_SIZE
        || &bytes[..6] != b"\x7fELF\x02\x01"
        || bytes[6] != 1
        || !matches!(u16_at(bytes, 16)?, 2 | 3)
        || u16_at(bytes, 18)? != 62
        || u32_at(bytes, 20)? != 1
        || u16_at(bytes, 52)? != ELF_HEADER_SIZE as u16
        || u16_at(bytes, 54)? != PROGRAM_HEADER_SIZE as u16
    {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    let object_type = u16_at(bytes, 16)?;
    let count = usize::from(u16_at(bytes, 56)?);
    let offset = usize_at(u64_at(bytes, 32)?)?;
    if !(1..=MAXIMUM_PROGRAM_HEADERS).contains(&count) {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    let headers = range(bytes, offset, count * PROGRAM_HEADER_SIZE)?;
    let mut loads = Vec::new();
    let mut dynamic = None;
    let mut interpreter = None;
    for header in headers.chunks_exact(PROGRAM_HEADER_SIZE) {
        let kind = u32_at(header, 0)?;
        let file_offset = usize_at(u64_at(header, 8)?)?;
        let address = u64_at(header, 16)?;
        let length = usize_at(u64_at(header, 32)?)?;
        let memory_length = u64_at(header, 40)?;
        match kind {
            PT_LOAD => {
                if length as u64 > memory_length || address.checked_add(memory_length).is_none() {
                    return Err(InspectorDeploymentErrorV2::Invalid);
                }
                range(bytes, file_offset, length)?;
                loads.push(LoadSegment {
                    offset: file_offset as u64,
                    address,
                    length: length as u64,
                });
            }
            PT_DYNAMIC => {
                if length as u64 > memory_length {
                    return Err(InspectorDeploymentErrorV2::Invalid);
                }
                range(bytes, file_offset, length)?;
                if dynamic.replace((file_offset, address, length)).is_some() {
                    return Err(InspectorDeploymentErrorV2::Invalid);
                }
            }
            PT_INTERP => {
                let text = exact_c_string(range(bytes, file_offset, length)?)?;
                if interpreter.replace(text.to_owned()).is_some() {
                    return Err(InspectorDeploymentErrorV2::Invalid);
                }
            }
            _ => {}
        }
    }
    let (dynamic_offset, dynamic_address, dynamic_length) =
        dynamic.ok_or(InspectorDeploymentErrorV2::Invalid)?;
    let dynamic = mapped_bytes(
        bytes,
        &loads,
        dynamic_address,
        dynamic_offset,
        dynamic_length,
    )?;
    if dynamic.is_empty() || dynamic.len() % 16 != 0 || dynamic.len() / 16 > MAXIMUM_DYNAMIC_ENTRIES
    {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    let mut string_address = None;
    let mut string_size = None;
    let mut needed_offsets = Vec::new();
    let mut soname_offset = None;
    let mut rpath_offset = None;
    let mut runpath_offset = None;
    let mut terminated = false;
    for entry in dynamic.chunks_exact(16) {
        let tag = u64_at(entry, 0)?;
        let value = u64_at(entry, 8)?;
        if tag == DT_NULL {
            terminated = true;
            break;
        }
        match tag {
            DT_NEEDED => needed_offsets.push(usize_at(value)?),
            DT_SONAME => replace_once(&mut soname_offset, usize_at(value)?)?,
            DT_STRTAB => replace_once(&mut string_address, value)?,
            DT_STRSZ => replace_once(&mut string_size, usize_at(value)?)?,
            DT_RPATH => replace_once(&mut rpath_offset, usize_at(value)?)?,
            DT_RUNPATH => replace_once(&mut runpath_offset, usize_at(value)?)?,
            DT_CONFIG | DT_AUDIT | DT_DEPAUDIT | DT_FILTER | DT_AUXILIARY => {
                return Err(InspectorDeploymentErrorV2::Invalid);
            }
            _ => {}
        }
    }
    if !terminated
        || needed_offsets.len() > MAXIMUM_NEEDED
        || (rpath_offset.is_some() && runpath_offset.is_some())
    {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    let address = string_address.ok_or(InspectorDeploymentErrorV2::Invalid)?;
    let size = string_size.ok_or(InspectorDeploymentErrorV2::Invalid)?;
    let strings = mapped_strings(bytes, &loads, address, size)?;
    let needed = needed_offsets
        .into_iter()
        .map(|offset| c_string(strings, offset).map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    let soname = soname_offset
        .map(|offset| c_string(strings, offset).map(str::to_owned))
        .transpose()?;
    let rpath = rpath_offset
        .map(|offset| search_path(strings, offset))
        .transpose()?;
    let runpath = runpath_offset
        .map(|offset| search_path(strings, offset))
        .transpose()?;
    Ok(ElfDependencies {
        object_type,
        interpreter,
        soname,
        needed,
        rpath,
        runpath,
    })
}

fn replace_once<T>(slot: &mut Option<T>, value: T) -> Result<(), InspectorDeploymentErrorV2> {
    if slot.is_some() {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    *slot = Some(value);
    Ok(())
}

fn mapped_bytes<'a>(
    bytes: &'a [u8],
    loads: &[LoadSegment],
    address: u64,
    offset: usize,
    size: usize,
) -> Result<&'a [u8], InspectorDeploymentErrorV2> {
    let matches = loads
        .iter()
        .filter(|load| {
            address
                .checked_sub(load.address)
                .and_then(|relative| {
                    let end = relative.checked_add(size as u64)?;
                    (end <= load.length).then_some(relative)
                })
                .and_then(|relative| load.offset.checked_add(relative))
                == Some(offset as u64)
        })
        .count();
    if matches != 1 {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    range(bytes, offset, size)
}

fn mapped_strings<'a>(
    bytes: &'a [u8],
    loads: &[LoadSegment],
    address: u64,
    size: usize,
) -> Result<&'a [u8], InspectorDeploymentErrorV2> {
    let mut mapped = None;
    for load in loads {
        let Some(relative) = address.checked_sub(load.address) else {
            continue;
        };
        let Some(end) = relative.checked_add(size as u64) else {
            continue;
        };
        if end <= load.length {
            let offset = usize_at(
                load.offset
                    .checked_add(relative)
                    .ok_or(InspectorDeploymentErrorV2::Invalid)?,
            )?;
            if mapped.replace(range(bytes, offset, size)?).is_some() {
                return Err(InspectorDeploymentErrorV2::Invalid);
            }
        }
    }
    mapped.ok_or(InspectorDeploymentErrorV2::Invalid)
}

fn search_path(strings: &[u8], offset: usize) -> Result<Vec<String>, InspectorDeploymentErrorV2> {
    let text = c_string(strings, offset)?;
    let mut paths = Vec::new();
    for directory in text.split(':') {
        if !canonical_store_file(directory) || directory.contains('$') || directory.contains(';') {
            return Err(InspectorDeploymentErrorV2::Invalid);
        }
        paths.push(directory.to_owned());
    }
    if paths.is_empty() || paths.len() > MAXIMUM_SEARCH_DIRECTORIES {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    Ok(paths)
}

fn exact_c_string(bytes: &[u8]) -> Result<&str, InspectorDeploymentErrorV2> {
    let Some((&0, value)) = bytes.split_last() else {
        return Err(InspectorDeploymentErrorV2::Invalid);
    };
    if value.len() > MAXIMUM_STRING_BYTES || value.contains(&0) {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    std::str::from_utf8(value).map_err(|_| InspectorDeploymentErrorV2::Invalid)
}

fn c_string(bytes: &[u8], offset: usize) -> Result<&str, InspectorDeploymentErrorV2> {
    let tail = bytes
        .get(offset..)
        .ok_or(InspectorDeploymentErrorV2::Invalid)?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(InspectorDeploymentErrorV2::Invalid)?;
    if end > MAXIMUM_STRING_BYTES {
        return Err(InspectorDeploymentErrorV2::Invalid);
    }
    std::str::from_utf8(&tail[..end]).map_err(|_| InspectorDeploymentErrorV2::Invalid)
}

fn range(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], InspectorDeploymentErrorV2> {
    let end = offset
        .checked_add(length)
        .ok_or(InspectorDeploymentErrorV2::Invalid)?;
    bytes
        .get(offset..end)
        .ok_or(InspectorDeploymentErrorV2::Invalid)
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, InspectorDeploymentErrorV2> {
    Ok(u16::from_le_bytes(
        range(bytes, offset, 2)?
            .try_into()
            .map_err(|_| InspectorDeploymentErrorV2::Invalid)?,
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, InspectorDeploymentErrorV2> {
    Ok(u32::from_le_bytes(
        range(bytes, offset, 4)?
            .try_into()
            .map_err(|_| InspectorDeploymentErrorV2::Invalid)?,
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, InspectorDeploymentErrorV2> {
    Ok(u64::from_le_bytes(
        range(bytes, offset, 8)?
            .try_into()
            .map_err(|_| InspectorDeploymentErrorV2::Invalid)?,
    ))
}

fn usize_at(value: u64) -> Result<usize, InspectorDeploymentErrorV2> {
    usize::try_from(value).map_err(|_| InspectorDeploymentErrorV2::Invalid)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::inspector_deployment::MemberExpectation;

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn synthetic_root(interpreter: &str, library_directory: &str) -> Vec<u8> {
        let mut bytes = vec![0; 0x800];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[6] = 1;
        put_u16(&mut bytes, 16, 3);
        put_u16(&mut bytes, 18, 62);
        put_u32(&mut bytes, 20, 1);
        put_u64(&mut bytes, 32, 64);
        put_u16(&mut bytes, 52, ELF_HEADER_SIZE as u16);
        put_u16(&mut bytes, 54, PROGRAM_HEADER_SIZE as u16);
        put_u16(&mut bytes, 56, 3);

        let load = ELF_HEADER_SIZE;
        put_u32(&mut bytes, load, PT_LOAD);
        put_u64(&mut bytes, load + 32, 0x800);
        put_u64(&mut bytes, load + 40, 0x800);

        let interp = load + PROGRAM_HEADER_SIZE;
        put_u32(&mut bytes, interp, PT_INTERP);
        put_u64(&mut bytes, interp + 8, 0x180);
        put_u64(&mut bytes, interp + 16, 0x180);
        put_u64(&mut bytes, interp + 32, (interpreter.len() + 1) as u64);
        put_u64(&mut bytes, interp + 40, (interpreter.len() + 1) as u64);
        bytes[0x180..0x180 + interpreter.len()].copy_from_slice(interpreter.as_bytes());

        let dynamic = interp + PROGRAM_HEADER_SIZE;
        put_u32(&mut bytes, dynamic, PT_DYNAMIC);
        put_u64(&mut bytes, dynamic + 8, 0x500);
        put_u64(&mut bytes, dynamic + 16, 0x500);
        put_u64(&mut bytes, dynamic + 32, 5 * 16);
        put_u64(&mut bytes, dynamic + 40, 5 * 16);

        let strings = format!("\0libm.so.6\0{library_directory}\0");
        let rpath_offset = "\0libm.so.6\0".len();
        bytes[0x300..0x300 + strings.len()].copy_from_slice(strings.as_bytes());
        for (index, (tag, value)) in [
            (DT_NEEDED, 1),
            (DT_STRTAB, 0x300),
            (DT_STRSZ, strings.len() as u64),
            (DT_RPATH, rpath_offset as u64),
            (DT_NULL, 0),
        ]
        .into_iter()
        .enumerate()
        {
            put_u64(&mut bytes, 0x500 + index * 16, tag);
            put_u64(&mut bytes, 0x508 + index * 16, value);
        }
        bytes
    }

    fn retained_member(path: &Path, role: MemberRole) -> RetainedMember {
        let descriptor = std::fs::File::open(path).unwrap();
        let metadata = descriptor.metadata().unwrap();
        let content = std::fs::read(path).unwrap();
        RetainedMember {
            expectation: MemberExpectation {
                role,
                path: path.to_str().unwrap().to_owned(),
                length: metadata.len(),
                mode: metadata.mode() & 0o7777,
                sha256: Sha256::digest(content).into(),
            },
            descriptor,
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn current_elf() -> Vec<u8> {
        std::fs::read("/proc/self/exe").unwrap()
    }

    #[test]
    fn reads_real_elf_program_headers_and_dynamic_edges() {
        let elf = parse_elf(&current_elf()).unwrap();

        assert!(elf.interpreter.as_deref().is_some_and(canonical_store_file));
        assert!(!elf.needed.is_empty());
        assert!(elf.rpath.is_some() || elf.runpath.is_some());
    }

    #[test]
    fn rejects_wrong_class_machine_and_program_header_bounds() {
        let original = current_elf();
        let mut wrong_class = original.clone();
        wrong_class[4] = 1;
        assert!(parse_elf(&wrong_class).is_err());

        let mut wrong_machine = original.clone();
        wrong_machine[18..20].copy_from_slice(&3_u16.to_le_bytes());
        assert!(parse_elf(&wrong_machine).is_err());

        let mut wrong_bounds = original;
        wrong_bounds[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(parse_elf(&wrong_bounds).is_err());
    }

    #[test]
    fn rejects_dynamic_loader_indirections_and_unbounded_search_paths() {
        let bytes = current_elf();
        let headers = usize_at(u64_at(&bytes, 32).unwrap()).unwrap();
        let count = usize::from(u16_at(&bytes, 56).unwrap());
        let dynamic = (0..count)
            .map(|index| headers + index * PROGRAM_HEADER_SIZE)
            .find(|offset| u32_at(&bytes, *offset).unwrap() == PT_DYNAMIC)
            .unwrap();
        let mut wrong_mapping = bytes.clone();
        wrong_mapping[dynamic + 16..dynamic + 24].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(parse_elf(&wrong_mapping).is_err());

        let dynamic_offset = usize_at(u64_at(&bytes, dynamic + 8).unwrap()).unwrap();
        for tag in [DT_CONFIG, DT_AUDIT, DT_DEPAUDIT, DT_FILTER, DT_AUXILIARY] {
            let mut alternate = bytes.clone();
            alternate[dynamic_offset..dynamic_offset + 8].copy_from_slice(&tag.to_le_bytes());
            assert!(
                parse_elf(&alternate).is_err(),
                "accepted dynamic tag {tag:#x}"
            );
        }

        assert!(search_path(b"$ORIGIN\0", 0).is_err());
        assert!(
            search_path(
                b"/nix/store/0123456789abcdfghijklmnpqrsvwxyz-pkg/lib::/tmp\0",
                0
            )
            .is_err()
        );
        assert!(c_string(b"unterminated", 0).is_err());
    }

    #[test]
    fn rejects_nested_hardware_capability_shadow() {
        let directory = tempfile::tempdir().unwrap();
        let variant = directory.path().join("glibc-hwcaps/x86-64-v3");
        std::fs::create_dir_all(&variant).unwrap();
        assert!(reject_nested_candidate(directory.path(), "libexample.so").is_ok());

        std::fs::write(variant.join("libexample.so"), b"alternate").unwrap();
        assert!(reject_nested_candidate(directory.path(), "libexample.so").is_err());
    }

    #[test]
    fn one_soname_cannot_name_two_inventory_members() {
        let mut names = BTreeMap::new();
        assert!(remember_name(&mut names, "libexample.so".to_owned(), 3).is_ok());
        assert!(remember_name(&mut names, "libalias.so".to_owned(), 3).is_ok());
        assert!(remember_name(&mut names, "libexample.so".to_owned(), 3).is_ok());
        assert!(remember_name(&mut names, "libexample.so".to_owned(), 4).is_err());
        assert!(remember_name(&mut names, "libalias.so".to_owned(), 4).is_err());
        assert!(remember_name(&mut names, "$ORIGIN".to_owned(), 3).is_err());
    }

    #[test]
    fn runpath_is_direct_only_but_rpath_reaches_children() {
        let directory = tempfile::tempdir().unwrap();
        let parent = directory.path().join("parent");
        let own = directory.path().join("own");
        std::fs::create_dir(&parent).unwrap();
        std::fs::create_dir(&own).unwrap();
        for path in [&parent, &own] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o555)).unwrap();
        }
        let metadata = std::fs::metadata(&parent).unwrap();
        let owner = (metadata.uid(), metadata.gid());
        let parent = parent.to_str().unwrap().to_owned();
        let own = own.to_str().unwrap().to_owned();
        let inherited = vec![parent.clone()];

        let mut elf = ElfDependencies {
            object_type: 3,
            interpreter: None,
            soname: None,
            needed: Vec::new(),
            rpath: Some(vec![own.clone()]),
            runpath: None,
        };
        let (search, children) = search_plan(&elf, &inherited, owner).unwrap();
        assert_eq!(search, vec![own.clone(), parent.clone()]);
        assert_eq!(children, search);

        elf.rpath = None;
        elf.runpath = Some(vec![own.clone()]);
        let (search, children) = search_plan(&elf, &inherited, owner).unwrap();
        assert_eq!(search, vec![own]);
        assert!(children.is_empty());

        elf.runpath = None;
        let (search, children) = search_plan(&elf, &inherited, owner).unwrap();
        assert_eq!(search, vec![parent]);
        assert_eq!(children, search);
    }

    #[test]
    fn rejects_ambiguous_candidate_even_when_one_is_pinned() {
        let current = parse_elf(&current_elf()).unwrap();
        let interpreter = std::fs::canonicalize(current.interpreter.unwrap()).unwrap();
        let library_directory = interpreter.parent().unwrap();
        let libc = std::fs::canonicalize(library_directory.join("libc.so.6")).unwrap();
        let member = retained_member(&libc, MemberRole::Library);
        let signed_directory = library_directory.to_str().unwrap().to_owned();
        assert!(matches!(
            resolve_needed("libc.so.6", &[signed_directory.clone()], &[member]),
            Ok(0)
        ));

        let shadow = tempfile::tempdir().unwrap();
        std::fs::write(shadow.path().join("libc.so.6"), b"shadow").unwrap();
        let member = retained_member(&libc, MemberRole::Library);
        let directories = [signed_directory, shadow.path().to_str().unwrap().to_owned()];
        assert!(resolve_needed("libc.so.6", &directories, &[member]).is_err());
    }

    #[test]
    fn detects_path_replacement_after_member_was_pinned() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("member");
        let replacement = directory.path().join("replacement");
        std::fs::write(&path, b"original").unwrap();
        std::fs::write(&replacement, b"replaced").unwrap();
        let member = retained_member(&path, MemberRole::Library);
        assert!(verify_member_identity(&path, &member).is_ok());

        std::fs::rename(&replacement, &path).unwrap();
        assert!(verify_member_identity(&path, &member).is_err());
    }

    #[test]
    fn verifies_transitive_glibc_closure_against_existing_members() {
        let current = parse_elf(&current_elf()).unwrap();
        let interpreter = std::fs::canonicalize(current.interpreter.unwrap()).unwrap();
        let directory = Path::new(&interpreter).parent().unwrap();
        let root_directory = tempfile::tempdir().unwrap();
        let root = root_directory.path().join("root");
        std::fs::write(
            &root,
            synthetic_root(interpreter.to_str().unwrap(), directory.to_str().unwrap()),
        )
        .unwrap();

        let libm = std::fs::canonicalize(directory.join("libm.so.6")).unwrap();
        let libc = std::fs::canonicalize(directory.join("libc.so.6")).unwrap();

        let mut members = vec![
            retained_member(&root, MemberRole::Inspector),
            retained_member(&interpreter, MemberRole::Interpreter),
            retained_member(&libm, MemberRole::Library),
            retained_member(&libc, MemberRole::Library),
        ];
        let directory_metadata = std::fs::metadata(directory).unwrap();
        let owner = (directory_metadata.uid(), directory_metadata.gid());
        assert!(verify_service_with_owner(&members, true, owner).is_ok());
        if owner != (0, 0) {
            assert!(verify_service(&members, true).is_err());
        }

        members[2].inode ^= 1;
        assert!(verify_service_with_owner(&members, true, owner).is_err());
        members[2].inode ^= 1;
        members.pop();
        assert!(verify_service_with_owner(&members, true, owner).is_err());
    }
}
