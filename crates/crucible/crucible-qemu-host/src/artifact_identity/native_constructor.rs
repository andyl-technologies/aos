//! Authenticates compiled native-constructor requests in one pinned final ELF.
//!
//! ```text
//! .qemu.crucible.standing-constructor[96]
//! CRUCSTC2 | BE32(schema2,length96)
//! BE32(Setup5,Purpose8,outer8,control8,tag21,frame61,roles5,roles6)
//! BE32(publication3,cancellation4,workspace5,Purpose2520,live1504,payload1496)
//! BE32(roster11,reserved0) | BE64(requested_owner_bytes,mapping1504)
//! ```
//!
//! The optional userfaultfd section is decoded by [`userfaultfd`]. Both requests
//! share this reader and complete-file digest; a missing kernel request grants
//! no constructor fallback. Its interior event is included in the whole body.
//!
//! These are artifact observations and requested extents, never a Source
//! activation flag or resource grant. The caller retains the real immutable
//! artifact, original Preparation and paid reader frame. Native constructor,
//! loader, execution and allocator proofs remain separate requirements.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::os::unix::fs::FileExt;

use crucible_host_resources::host_supervision::{HostOperationGuard, HostSupervisionError};
use sha2::{Digest, Sha256};

const STANDING_SECTION: &[u8] = b".qemu.crucible.standing-constructor";
const DECLARATION_BYTES: usize = 96;
const SECTION_HEADER_BYTES: usize = 64;

mod receiver;
pub(crate) use receiver::{NativeReceiverArtifact, NativeReceiverError};

#[cfg(test)]
pub(crate) mod test_support;

mod userfaultfd;
pub(crate) use userfaultfd::UserfaultfdConstructorRequest;

/// Describes the requested native owner and mapping extents without granting them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct StandingConstructorDeclaration {
    owner_bytes: u64,
    mapping_bytes: u64,
}

impl StandingConstructorDeclaration {
    /// Returns both exact requests for independent prebirth floor accounting.
    pub(super) const fn requested_bytes(self) -> (u64, u64) {
        (self.owner_bytes, self.mapping_bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeConstructorDeclarations {
    standing: StandingConstructorDeclaration,
    receiver: Result<receiver::ReceiverDeclaration, &'static str>,
    userfaultfd: Result<Option<UserfaultfdConstructorRequest>, &'static str>,
}

/// Retains requests observed in the complete immutable selected QEMU.
///
/// Its private constructor hashes the actual borrowed file under the same
/// original; neither decoded bytes nor a provided hash can publish this value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NativeConstructorArtifact {
    declarations: NativeConstructorDeclarations,
    qemu_sha256: [u8; 32],
}

impl NativeConstructorArtifact {
    pub(super) fn receiver_artifact(&self) -> NativeReceiverArtifact {
        NativeReceiverArtifact::from_observed(self.declarations.receiver, self.qemu_sha256)
    }

    /// Borrows request geometry; it issues no descriptor or memory credit.
    ///
    /// # Errors
    /// Returns the retained malformed, duplicate or unknown declaration refusal.
    /// An absent declaration remains `Ok(None)` and grants no fallback request.
    pub(super) fn userfaultfd(
        &self,
    ) -> Result<Option<&UserfaultfdConstructorRequest>, &'static str> {
        self.declarations
            .userfaultfd
            .as_ref()
            .map(Option::as_ref)
            .map_err(|reason| *reason)
    }

    /// Returns the unchanged standing preinit floor; no endpoint is born here.
    pub(super) fn requested_bytes(&self) -> Option<u64> {
        let (owner, mapping) = self.declarations.standing.requested_bytes();
        owner.checked_add(mapping)
    }
}

/// Observes constructor requests and hashes the actual final immutable file.
///
/// # Errors
/// Refuses the real original or artifact read/declaration. The caller pays the
/// fixed streaming frame before entry and retains package/path provenance.
pub(super) fn authenticate_final_elf(
    file: &File,
    original: &HostOperationGuard,
) -> Result<NativeConstructorArtifact, NativeConstructorReadError> {
    let declarations = read_declarations(file, original)?;
    original.wait_slice()?;
    let extent = file.metadata()?.len();
    let mut hash = Sha256::new();
    let mut scratch = [0; 8192];
    let mut offset = 0;
    while offset < extent {
        let bytes = usize::try_from((extent - offset).min(scratch.len() as u64))
            .map_err(|_| NativeConstructorReadError::Invalid("hash extent"))?;
        read_at(file, offset, &mut scratch[..bytes], extent, original)?;
        hash.update(&scratch[..bytes]);
        offset = offset
            .checked_add(bytes as u64)
            .ok_or(NativeConstructorReadError::Invalid("hash offset"))?;
    }
    original.wait_slice()?;
    Ok(NativeConstructorArtifact {
        declarations,
        qemu_sha256: hash.finalize().into(),
    })
}

/// Preserves the actual original or artifact observation failure.
#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeConstructorReadError {
    #[error("native constructor original refused: {0}")]
    Original(#[from] HostSupervisionError),
    #[error("native constructor artifact read failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("native constructor artifact is invalid: {0}")]
    Invalid(&'static str),
}

/// Reads constructor declarations under the caller's actual entered Preparation.
///
/// The borrowed file creates no descriptor. The caller must price the fixed
/// header/name/declaration frame and retain the final immutable package binding
/// before entering this helper; this function itself authenticates no package.
///
/// # Errors
/// Refuses the actual original, unsupported ELF geometry, an absent or malformed
/// standing declaration, checked-offset overflow or the real artifact read.
/// Optional kernel-request refusals are retained for that request's accessor;
/// they cannot invalidate the standing resident identity or produce a fallback.
fn read_declarations(
    file: &File,
    original: &HostOperationGuard,
) -> Result<NativeConstructorDeclarations, NativeConstructorReadError> {
    original.wait_slice()?;
    let extent = file.metadata()?.len();
    let mut header = [0; SECTION_HEADER_BYTES];
    read_at(file, 0, &mut header, extent, original)?;
    if header[..7] != *b"\x7fELF\x02\x01\x01"
        || !matches!(u16_at(&header, 16), 2 | 3)
        || u16_at(&header, 18) != 62
        || u16_at(&header, 58) != SECTION_HEADER_BYTES as u16
    {
        return Err(NativeConstructorReadError::Invalid("ELF header"));
    }
    let table = u64_at(&header, 40);
    let count = u16_at(&header, 60);
    let names_index = u16_at(&header, 62);
    if count == 0 || names_index == 0 || names_index >= count {
        return Err(NativeConstructorReadError::Invalid("section roster"));
    }
    let end = table.checked_add(u64::from(count) * SECTION_HEADER_BYTES as u64);
    if end.is_none_or(|end| end > extent) {
        return Err(NativeConstructorReadError::Invalid("section table extent"));
    }
    let mut entry = [0; SECTION_HEADER_BYTES];
    read_at(
        file,
        section_offset(table, names_index)?,
        &mut entry,
        extent,
        original,
    )?;
    if u32_at(&entry, 4) != 3 {
        return Err(NativeConstructorReadError::Invalid("section names type"));
    }
    let names_offset = u64_at(&entry, 24);
    let names_bytes = u64_at(&entry, 32);
    if names_offset
        .checked_add(names_bytes)
        .is_none_or(|end| end > extent)
    {
        return Err(NativeConstructorReadError::Invalid("section names extent"));
    }
    let mut declaration = None;
    let mut userfaultfd = Ok(None);
    let mut receiver = Err("missing receiver declaration");
    let mut receiver_seen = false;
    let mut kernel_seen = false;
    for index in 0..count {
        read_at(
            file,
            section_offset(table, index)?,
            &mut entry,
            extent,
            original,
        )?;
        let name = u64::from(u32_at(&entry, 0));
        let Some(remaining) = names_bytes.checked_sub(name) else {
            continue;
        };
        let mut name_bytes = [0; userfaultfd::SECTION.len() + 1];
        let length = usize::try_from(remaining.min(name_bytes.len() as u64))
            .map_err(|_| NativeConstructorReadError::Invalid("section name length"))?;
        read_at(
            file,
            names_offset
                .checked_add(name)
                .ok_or(NativeConstructorReadError::Invalid("section name offset"))?,
            &mut name_bytes[..length],
            extent,
            original,
        )?;
        let actual_name = &name_bytes[..length];
        let standing = exact_name(actual_name, STANDING_SECTION);
        let kernel = exact_name(actual_name, userfaultfd::SECTION);
        let is_receiver = exact_name(actual_name, receiver::SECTION);
        if !standing && !kernel && !is_receiver {
            continue;
        }
        let proper_section = u32_at(&entry, 4) == 1 && u64_at(&entry, 8) == 2;
        if is_receiver {
            if receiver_seen {
                receiver = Err("duplicate receiver declaration");
                continue;
            }
            receiver_seen = true;
            if !proper_section || u64_at(&entry, 32) != receiver::BYTES as u64 {
                receiver = Err("receiver declaration section");
                continue;
            }
            let mut bytes = [0; receiver::BYTES];
            read_at(file, u64_at(&entry, 24), &mut bytes, extent, original)?;
            receiver = match receiver::decode(&bytes) {
                Ok(declaration) => Ok(declaration),
                Err(NativeConstructorReadError::Invalid(reason)) => Err(reason),
                Err(error) => return Err(error),
            };
            continue;
        }
        if standing {
            if declaration.is_some()
                || !proper_section
                || u64_at(&entry, 32) != DECLARATION_BYTES as u64
            {
                return Err(NativeConstructorReadError::Invalid(
                    "standing declaration section",
                ));
            }
            let mut bytes = [0; DECLARATION_BYTES];
            read_at(file, u64_at(&entry, 24), &mut bytes, extent, original)?;
            declaration = Some(decode_declaration(&bytes)?);
            continue;
        }

        // Resident provenance does not require a kernel constructor. Preserve
        // a request refusal without allowing a later duplicate to overwrite it.
        if kernel_seen {
            userfaultfd = Err("duplicate userfaultfd declaration");
            continue;
        }
        kernel_seen = true;
        if !proper_section || u64_at(&entry, 32) != userfaultfd::DECLARATION_BYTES as u64 {
            userfaultfd = Err("userfaultfd declaration section");
            continue;
        }
        let offset = u64_at(&entry, 24);
        if offset
            .checked_add(userfaultfd::DECLARATION_BYTES as u64)
            .is_none_or(|end| end > extent)
        {
            userfaultfd = Err("userfaultfd declaration outside ELF");
            continue;
        }
        let mut bytes = [0; userfaultfd::DECLARATION_BYTES];
        read_at(file, offset, &mut bytes, extent, original)?;
        userfaultfd = match userfaultfd::decode_declaration(&bytes) {
            Ok(request) => Ok(Some(request)),
            Err(NativeConstructorReadError::Invalid(reason)) => Err(reason),
            Err(error) => return Err(error),
        };
    }
    original.wait_slice()?;
    let declaration = declaration.ok_or(NativeConstructorReadError::Invalid(
        "missing standing declaration",
    ))?;
    Ok(NativeConstructorDeclarations {
        standing: declaration,
        receiver,
        userfaultfd,
    })
}

fn exact_name(actual: &[u8], name: &[u8]) -> bool {
    actual.get(..name.len()) == Some(name) && actual.get(name.len()) == Some(&0)
}

#[cfg(test)]
fn read_declaration(
    file: &File,
    original: &HostOperationGuard,
) -> Result<StandingConstructorDeclaration, NativeConstructorReadError> {
    read_declarations(file, original).map(|declarations| declarations.standing)
}

fn section_offset(table: u64, index: u16) -> Result<u64, NativeConstructorReadError> {
    table
        .checked_add(u64::from(index) * SECTION_HEADER_BYTES as u64)
        .ok_or(NativeConstructorReadError::Invalid("section offset"))
}

fn read_at(
    file: &File,
    mut offset: u64,
    mut bytes: &mut [u8],
    extent: u64,
    original: &HostOperationGuard,
) -> Result<(), NativeConstructorReadError> {
    if offset
        .checked_add(bytes.len() as u64)
        .is_none_or(|end| end > extent)
    {
        return Err(NativeConstructorReadError::Invalid("artifact read extent"));
    }
    while !bytes.is_empty() {
        original.wait_slice()?;
        let count = file.read_at(bytes, offset)?;
        if count == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }
        offset = offset
            .checked_add(count as u64)
            .ok_or(NativeConstructorReadError::Invalid("artifact read offset"))?;
        bytes = &mut bytes[count..];
    }
    Ok(())
}

fn decode_declaration(
    bytes: &[u8; DECLARATION_BYTES],
) -> Result<StandingConstructorDeclaration, NativeConstructorReadError> {
    if bytes[..8] != *b"CRUCSTC2" {
        return Err(NativeConstructorReadError::Invalid("declaration magic"));
    }
    for (index, expected) in [
        2, 96, 5, 8, 8, 8, 21, 61, 5, 6, 3, 4, 5, 2520, 1504, 1496, 11, 0,
    ]
    .into_iter()
    .enumerate()
    {
        let offset = 8 + index * 4;
        let actual = u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| NativeConstructorReadError::Invalid("declaration word"))?,
        );
        if actual != expected {
            return Err(NativeConstructorReadError::Invalid(
                "declaration edition or geometry",
            ));
        }
    }
    let owner_bytes = u64::from_be_bytes(
        bytes[80..88]
            .try_into()
            .map_err(|_| NativeConstructorReadError::Invalid("owner request"))?,
    );
    let mapping_bytes = u64::from_be_bytes(
        bytes[88..96]
            .try_into()
            .map_err(|_| NativeConstructorReadError::Invalid("mapping request"))?,
    );
    if owner_bytes == 0
        || mapping_bytes != 1504
        || usize::try_from(owner_bytes).is_err()
        || owner_bytes.checked_add(mapping_bytes).is_none()
    {
        return Err(NativeConstructorReadError::Invalid("requested extents"));
    }
    Ok(StandingConstructorDeclaration {
        owner_bytes,
        mapping_bytes,
    })
}

fn u16_at(bytes: &[u8; SECTION_HEADER_BYTES], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8; SECTION_HEADER_BYTES], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn u64_at(bytes: &[u8; SECTION_HEADER_BYTES], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- component controls panic on incorrect artifact observations or refusal.
    #![allow(clippy::unwrap_used)]

    use super::*;

    pub(super) fn declaration() -> [u8; 96] {
        let mut bytes = [0; 96];
        bytes[..8].copy_from_slice(b"CRUCSTC2");
        for (index, value) in [
            2_u32, 96, 5, 8, 8, 8, 21, 61, 5, 6, 3, 4, 5, 2520, 1504, 1496, 11, 0,
        ]
        .into_iter()
        .enumerate()
        {
            bytes[8 + index * 4..12 + index * 4].copy_from_slice(&value.to_be_bytes());
        }
        // A numerical artifact fixture is not an actual native owner-size proof.
        bytes[80..88].copy_from_slice(&4096_u64.to_be_bytes());
        bytes[88..96].copy_from_slice(&1504_u64.to_be_bytes());
        bytes
    }

    fn elf(declarations: usize) -> Vec<u8> {
        let count = 2 + declarations;
        let names = b"\0.qemu.crucible.standing-constructor\0";
        let names_offset = 64 + count * 64;
        let body_offset = names_offset + names.len();
        let mut bytes = vec![0; body_offset + declarations * 96];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[40..48].copy_from_slice(&64_u64.to_le_bytes());
        bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
        bytes[60..62].copy_from_slice(&(count as u16).to_le_bytes());
        bytes[62..64].copy_from_slice(&1_u16.to_le_bytes());
        bytes[132..136].copy_from_slice(&3_u32.to_le_bytes());
        bytes[152..160].copy_from_slice(&(names_offset as u64).to_le_bytes());
        bytes[160..168].copy_from_slice(&(names.len() as u64).to_le_bytes());
        bytes[names_offset..body_offset].copy_from_slice(names);
        for index in 0..declarations {
            let header = (index + 3) * 64;
            bytes[header..header + 4].copy_from_slice(&1_u32.to_le_bytes());
            bytes[header + 4..header + 8].copy_from_slice(&1_u32.to_le_bytes());
            bytes[header + 8..header + 16].copy_from_slice(&2_u64.to_le_bytes());
            bytes[header + 24..header + 32]
                .copy_from_slice(&((body_offset + index * 96) as u64).to_le_bytes());
            bytes[header + 32..header + 40].copy_from_slice(&96_u64.to_le_bytes());
            bytes[body_offset + index * 96..body_offset + (index + 1) * 96]
                .copy_from_slice(&declaration());
        }
        bytes
    }

    #[test]
    fn actual_bounded_elf_reader_refuses_missing_duplicate_and_overflowed_sections() {
        use crucible_host_resources::host_supervision::{
            HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
        };
        use std::io::{Seek, SeekFrom, Write};

        // This owns a real component operation/file, never a Main or Source.
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
        let mut source = tempfile::tempfile().unwrap();
        source.write_all(&elf(1)).unwrap();
        assert_eq!(
            read_declaration(&source, &original)
                .unwrap()
                .requested_bytes(),
            (4096, 1504)
        );

        let mut overflow = elf(1);
        overflow[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        for bytes in [elf(0), elf(2), overflow] {
            source.set_len(0).unwrap();
            source.seek(SeekFrom::Start(0)).unwrap();
            source.write_all(&bytes).unwrap();
            assert!(read_declaration(&source, &original).is_err());
        }
    }

    #[test]
    fn observation_preserves_requested_extents_without_activation() {
        assert_eq!(
            decode_declaration(&declaration())
                .unwrap()
                .requested_bytes(),
            (4096, 1504)
        );
    }

    #[test]
    fn changed_geometry_or_reserved_word_refuses() {
        for offset in (8..80).step_by(4) {
            let mut bytes = declaration();
            bytes[offset + 3] ^= 1;
            assert!(decode_declaration(&bytes).is_err(), "offset {offset}");
        }
        let mut bytes = declaration();
        bytes[0] ^= 1;
        assert!(decode_declaration(&bytes).is_err());
    }

    #[test]
    fn zero_overflowing_or_changed_requested_extents_refuse() {
        for request in [0_u64, u64::MAX] {
            let mut bytes = declaration();
            bytes[80..88].copy_from_slice(&request.to_be_bytes());
            assert!(decode_declaration(&bytes).is_err());
        }
        let mut bytes = declaration();
        bytes[88..96].copy_from_slice(&609_u64.to_be_bytes());
        assert!(decode_declaration(&bytes).is_err());
    }

    fn kernel_declaration() -> [u8; userfaultfd::DECLARATION_BYTES] {
        let mut bytes = [0; userfaultfd::DECLARATION_BYTES];
        bytes[..8].copy_from_slice(b"CRUCUFD1");
        bytes[8..12].copy_from_slice(&1_u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&64_u32.to_be_bytes());
        for (offset, value) in [(16, 512_u64), (24, 64), (32, 128), (40, 128), (48, 8)] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        bytes[56..60].copy_from_slice(&2_u32.to_be_bytes());
        bytes
    }

    fn elf_with_kernel(requests: &[[u8; userfaultfd::DECLARATION_BYTES]]) -> Vec<u8> {
        let count = 3 + requests.len();
        let mut names = vec![0];
        names.extend_from_slice(STANDING_SECTION);
        names.push(0);
        let kernel_name = names.len() as u32;
        names.extend_from_slice(userfaultfd::SECTION);
        names.push(0);
        let names_offset = 64 + count * 64;
        let body_offset = names_offset + names.len();
        let mut bytes = vec![0; body_offset + DECLARATION_BYTES + requests.len() * 64];
        bytes[..64].copy_from_slice(&elf(1)[..64]);
        bytes[60..62].copy_from_slice(&(count as u16).to_le_bytes());
        bytes[132..136].copy_from_slice(&3_u32.to_le_bytes());
        bytes[152..160].copy_from_slice(&(names_offset as u64).to_le_bytes());
        bytes[160..168].copy_from_slice(&(names.len() as u64).to_le_bytes());
        bytes[names_offset..body_offset].copy_from_slice(&names);
        let standing = declaration();
        for index in 0..=requests.len() {
            let header = (index + 3) * 64;
            let name = if index == 0 { 1 } else { kernel_name };
            let offset = if index == 0 {
                body_offset
            } else {
                body_offset + DECLARATION_BYTES + (index - 1) * 64
            };
            let body: &[u8] = if index == 0 {
                &standing
            } else {
                &requests[index - 1]
            };
            bytes[header..header + 4].copy_from_slice(&name.to_le_bytes());
            bytes[header + 4..header + 8].copy_from_slice(&1_u32.to_le_bytes());
            bytes[header + 8..header + 16].copy_from_slice(&2_u64.to_le_bytes());
            bytes[header + 24..header + 32].copy_from_slice(&(offset as u64).to_le_bytes());
            bytes[header + 32..header + 40].copy_from_slice(&(body.len() as u64).to_le_bytes());
            bytes[offset..offset + body.len()].copy_from_slice(body);
        }
        bytes
    }

    #[test]
    fn real_elf_observation_keeps_kernel_refusals_separate_from_resident_provenance() {
        use crucible_host_resources::host_supervision::{
            HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
        };
        use std::io::{Seek, SeekFrom, Write};

        // The real component file/operation authenticates no Main, Source or bank.
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
        let mut source = tempfile::tempfile().unwrap();
        let kernel = kernel_declaration();
        let current = elf_with_kernel(&[kernel]);
        source.write_all(&current).unwrap();
        let artifact = authenticate_final_elf(&source, &original).unwrap();

        let expected: [u8; 32] = Sha256::digest(&current).into();
        assert_eq!(artifact.qemu_sha256, expected);
        assert_eq!(artifact.requested_bytes(), Some(4096 + 1504));
        assert_eq!(
            artifact
                .userfaultfd()
                .unwrap()
                .unwrap()
                .body_layout()
                .size(),
            512
        );

        let mut unknown = kernel;
        unknown[8..12].copy_from_slice(&2_u32.to_be_bytes());
        let mut writable = elf_with_kernel(&[kernel]);
        writable[264..272].copy_from_slice(&3_u64.to_le_bytes());
        let mut truncated = elf_with_kernel(&[kernel]);
        truncated.pop();
        let mut overflow = elf_with_kernel(&[kernel]);
        overflow[280..288].copy_from_slice(&u64::MAX.to_le_bytes());
        for bytes in [
            elf_with_kernel(&[unknown]),
            elf_with_kernel(&[kernel, kernel]),
            writable,
            truncated,
            overflow,
        ] {
            source.set_len(0).unwrap();
            source.seek(SeekFrom::Start(0)).unwrap();
            source.write_all(&bytes).unwrap();
            let artifact = authenticate_final_elf(&source, &original).unwrap();

            assert_eq!(artifact.requested_bytes(), Some(4096 + 1504));
            assert!(artifact.userfaultfd().is_err());
        }
        source.set_len(0).unwrap();
        source.seek(SeekFrom::Start(0)).unwrap();
        source.write_all(&elf(1)).unwrap();
        let artifact = authenticate_final_elf(&source, &original).unwrap();
        assert!(artifact.userfaultfd().unwrap().is_none());
    }
}
