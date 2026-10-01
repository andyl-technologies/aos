//! Parses checked ELF header, program-table, and dynamic-table byte ranges.
//!
//! Parsers accept caller-fetched ranges rather than fetching content or casting
//! native structures. Every reference is an object-relative checked offset.

use super::{ElfValue, Error};
use alloc::vec::Vec;

/// A validated ELF header with the information needed for bounded range reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElfHeader {
    /// The fixed header attributes, before interpreter and library resolution.
    pub value: ElfValue,
    /// Whether integer fields use little-endian byte order.
    pub little_endian: bool,
    /// The program table's object-relative offset.
    pub program_offset: u64,
    /// The program table's number of fixed-size entries.
    pub program_count: u16,
    /// The registered ELF32 or ELF64 entry width.
    pub program_width: u16,
}

/// One validated ELF program segment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElfProgram {
    /// ELF `p_type` (LOAD=1, DYNAMIC=2, INTERP=3).
    pub kind: u32,
    /// The file offset of the segment's bytes.
    pub offset: u64,
    /// The segment's virtual address used to resolve DT_STRTAB.
    pub address: u64,
    /// The number of bytes present in the object.
    pub file_size: u64,
    /// The segment's memory size, never used as a file read length.
    pub memory_size: u64,
}

/// A dynamic-table fragment's string-table references and needed-name offsets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElfDynamic {
    /// DT_STRTAB virtual address, when supplied by this fragment.
    pub string_address: Option<u64>,
    /// DT_STRSZ byte length, when supplied by this fragment.
    pub string_size: Option<u64>,
    /// DT_NEEDED offsets in table order.
    pub needed: Vec<u64>,
    /// Whether this fragment ended at DT_NULL.
    pub terminated: bool,
}

fn field(bytes: &[u8], offset: usize, width: usize, little: bool) -> Result<u64, Error> {
    let value = bytes
        .get(offset..offset.checked_add(width).ok_or(Error::Limit)?)
        .ok_or(Error::MalformedExecutable)?;
    let mut result = 0u64;
    if little {
        for &byte in value.iter().rev() {
            result = (result << 8) | u64::from(byte);
        }
    } else {
        for &byte in value {
            result = (result << 8) | u64::from(byte);
        }
    }
    Ok(result)
}

fn range(offset: u64, length: u64, size: u64) -> Result<(), Error> {
    if offset.checked_add(length).is_none_or(|end| end > size) {
        return Err(Error::MalformedExecutable);
    }
    Ok(())
}

/// Parses a complete ELF32 or ELF64 fixed header and checks its program range.
///
/// Version 1 accepts both byte orders and rejects extended program counts,
/// nonstandard entry sizes, and inconsistent fixed-header sizes explicitly.
///
/// # Errors
/// Returns a typed malformed-format or offset overflow failure.
pub fn parse_elf_header(bytes: &[u8], object_size: u64) -> Result<ElfHeader, Error> {
    if !bytes.starts_with(b"\x7fELF") || bytes.get(6) != Some(&1) {
        return Err(Error::MalformedExecutable);
    }
    let class = match bytes.get(4) {
        Some(1) => 32,
        Some(2) => 64,
        _ => return Err(Error::MalformedExecutable),
    };
    let little = match bytes.get(5) {
        Some(1) => true,
        Some(2) => false,
        _ => return Err(Error::MalformedExecutable),
    };
    let (header_width, phoff, phwidth, phcount) = if class == 32 {
        (52, 28, 42, 44)
    } else {
        (64, 32, 54, 56)
    };
    if bytes.len() < header_width
        || object_size < header_width as u64
        || field(bytes, 20, 4, little)? != 1
    {
        return Err(Error::MalformedExecutable);
    }
    let header_size_offset = if class == 32 { 40 } else { 52 };
    if field(bytes, header_size_offset, 2, little)? != header_width as u64 {
        return Err(Error::MalformedExecutable);
    }
    let program_offset = field(bytes, phoff, if class == 32 { 4 } else { 8 }, little)?;
    let program_count = field(bytes, phcount, 2, little)? as u16;
    let program_width = field(bytes, phwidth, 2, little)? as u16;
    let expected_width = if class == 32 { 32 } else { 56 };
    if program_count == u16::MAX
        || program_count != 0
            && (program_width != expected_width || program_offset < header_width as u64)
    {
        return Err(Error::MalformedExecutable);
    }
    range(
        program_offset,
        u64::from(program_count) * u64::from(program_width),
        object_size,
    )?;
    Ok(ElfHeader {
        value: ElfValue {
            class,
            machine: field(bytes, 18, 2, little)? as u16,
            elf_type: field(bytes, 16, 2, little)? as u16,
            interpreter: None,
            needed: Vec::new(),
        },
        little_endian: little,
        program_offset,
        program_count,
        program_width,
    })
}

/// Parses one or more complete program entries from a fetched table fragment.
///
/// Fragment size is bounded by its input. Segment file ranges and virtual
/// memory arithmetic are checked before a caller can fetch their contents.
///
/// # Errors
/// Returns a malformed-format failure for partial entries or invalid segments.
pub fn parse_elf_programs(
    header: &ElfHeader,
    bytes: &[u8],
    object_size: u64,
) -> Result<Vec<ElfProgram>, Error> {
    let width = if header.value.class == 32 {
        32
    } else if header.value.class == 64 {
        56
    } else {
        return Err(Error::MalformedExecutable);
    };
    if !bytes.len().is_multiple_of(width) {
        return Err(Error::MalformedExecutable);
    }
    let mut programs = Vec::new();
    for entry in bytes.chunks_exact(width) {
        let little = header.little_endian;
        let (offset, address, file_size, memory_size) = if header.value.class == 32 {
            (
                field(entry, 4, 4, little)?,
                field(entry, 8, 4, little)?,
                field(entry, 16, 4, little)?,
                field(entry, 20, 4, little)?,
            )
        } else {
            (
                field(entry, 8, 8, little)?,
                field(entry, 16, 8, little)?,
                field(entry, 32, 8, little)?,
                field(entry, 40, 8, little)?,
            )
        };
        let kind = field(entry, 0, 4, little)? as u32;
        range(offset, file_size, object_size)?;
        if address.checked_add(memory_size).is_none() || kind == 1 && file_size > memory_size {
            return Err(Error::MalformedExecutable);
        }
        programs.push(ElfProgram {
            kind,
            offset,
            address,
            file_size,
            memory_size,
        });
    }
    Ok(programs)
}

/// Parses a complete-entry dynamic-table fragment, stopping at its first null.
///
/// Other tags are ignored without depending on platform libraries. Repeated
/// string-table descriptors in one fragment are rejected as ambiguous.
///
/// # Errors
/// Returns a malformed-format failure for partial entries or duplicate descriptors.
pub fn parse_elf_dynamic(header: &ElfHeader, bytes: &[u8]) -> Result<ElfDynamic, Error> {
    let word = match header.value.class {
        32 => 4,
        64 => 8,
        _ => return Err(Error::MalformedExecutable),
    };
    let width = word * 2;
    if !bytes.len().is_multiple_of(width) {
        return Err(Error::MalformedExecutable);
    }
    let mut result = ElfDynamic {
        string_address: None,
        string_size: None,
        needed: Vec::new(),
        terminated: false,
    };
    for entry in bytes.chunks_exact(width) {
        let tag = field(entry, 0, word, header.little_endian)?;
        let value = field(entry, word, word, header.little_endian)?;
        match tag {
            0 => {
                result.terminated = true;
                break;
            }
            1 => result.needed.push(value),
            5 => assign_unique(&mut result.string_address, value)?,
            10 => assign_unique(&mut result.string_size, value)?,
            _ => {}
        }
    }
    Ok(result)
}

fn assign_unique(slot: &mut Option<u64>, value: u64) -> Result<(), Error> {
    if slot.replace(value).is_some() {
        return Err(Error::MalformedExecutable);
    }
    Ok(())
}
