//! A minimal, dependency-free ELF64 reader for reference attribution.
//!
//! The profiler does not disassemble or relink ELF files; it only needs
//! enough structure to answer one question: *given a byte offset where a
//! store-hash string was found, which part of the binary is it in?* That
//! requires the section table (to map an offset to a section name) plus
//! the dynamic linker path and RPATH/RUNPATH entries (to recognise
//! genuine runtime search paths). Everything else is ignored.
//!
//! Only little-endian ELF64 is parsed — the class of every AOS
//! production target (`x86_64` and `aarch64`). Anything else (the i686
//! source-bootstrap stages, big-endian objects) returns [`None`], and
//! the caller falls back to path-based classification. The reader is
//! fully bounds-checked and contains no `unsafe`.
//!
//! ```text
//! ELF64 header          section header (64 bytes each)
//!   e_type    @0x10       sh_name   @0x00  (u32, index into shstrtab)
//!   e_shoff   @0x28       sh_type   @0x04  (u32; 6=DYNAMIC, 8=NOBITS)
//!   e_shentsz @0x3a       sh_offset @0x18  (u64, byte offset in file)
//!   e_shnum   @0x3c       sh_size   @0x20  (u64)
//!   e_shstrndx@0x3e
//! ```

/// A single ELF section, reduced to what the profiler needs.
#[derive(Debug, Clone)]
pub struct Section {
    /// Section name, e.g. `.text`, `.comment`, `.dynstr`.
    pub name: String,
    /// Byte offset of the section's data within the file.
    pub file_off: u64,
    /// Size of the section's data in bytes.
    pub size: u64,
    /// Whether the section occupies no file space (`SHT_NOBITS`, e.g.
    /// `.bss`); such sections never contain reference strings.
    pub nobits: bool,
}

/// Structural facts extracted from an ELF64 object.
#[derive(Debug, Clone, Default)]
pub struct ElfInfo {
    /// True for `ET_DYN` (shared objects and PIE executables).
    pub is_shared: bool,
    /// All sections, in header order.
    pub sections: Vec<Section>,
    /// The `.interp` dynamic-linker path, if present.
    pub interp: Option<String>,
    /// Combined `DT_RPATH` and `DT_RUNPATH` search-path entries (already
    /// split on `:`).
    pub runpaths: Vec<String>,
}

impl ElfInfo {
    /// Returns the name of the section whose file range contains
    /// `offset`, or `None` if the offset falls outside every
    /// file-backed section.
    pub fn section_at(&self, offset: u64) -> Option<&str> {
        self.sections
            .iter()
            .filter(|s| !s.nobits && s.size > 0)
            .find(|s| offset >= s.file_off && offset < s.file_off + s.size)
            .map(|s| s.name.as_str())
    }
}

const SHT_DYNAMIC: u32 = 6;
const SHT_NOBITS: u32 = 8;
const DT_NULL: i64 = 0;
const DT_RPATH: i64 = 15;
const DT_RUNPATH: i64 = 29;

/// Parses an ELF64 little-endian object, returning the structure the
/// profiler needs, or `None` if `data` is not little-endian ELF64.
pub fn parse(data: &[u8]) -> Option<ElfInfo> {
    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return None;
    }
    // EI_CLASS == ELFCLASS64, EI_DATA == ELFDATA2LSB.
    if data[4] != 2 || data[5] != 1 {
        return None;
    }

    let e_type = read_u16(data, 0x10)?;
    let e_shoff = read_u64(data, 0x28)?;
    let e_shentsize = read_u16(data, 0x3a)? as usize;
    let e_shnum = read_u16(data, 0x3c)? as usize;
    let e_shstrndx = read_u16(data, 0x3e)? as usize;

    if e_shoff == 0 || e_shnum == 0 || e_shentsize < 64 {
        // No section table to work with; still report the ELF type so
        // callers can categorise the file.
        return Some(ElfInfo {
            is_shared: e_type == 3,
            ..Default::default()
        });
    }

    // Locate the section-header string table so section names resolve.
    let shstr = section_header(data, e_shoff, e_shentsize, e_shstrndx)?;
    let shstr_off = read_u64(&shstr, 0x18)?;
    let shstr_size = read_u64(&shstr, 0x20)?;

    let mut sections = Vec::with_capacity(e_shnum);
    for i in 0..e_shnum {
        let sh = match section_header(data, e_shoff, e_shentsize, i) {
            Some(sh) => sh,
            None => break,
        };
        let sh_name = read_u32(&sh, 0x00)? as u64;
        let sh_type = read_u32(&sh, 0x04)?;
        let sh_offset = read_u64(&sh, 0x18)?;
        let sh_size = read_u64(&sh, 0x20)?;
        let name = read_cstr(data, shstr_off + sh_name, shstr_size).unwrap_or_default();
        sections.push((
            sh_type,
            Section {
                name,
                file_off: sh_offset,
                size: sh_size,
                nobits: sh_type == SHT_NOBITS,
            },
        ));
    }

    // The `.interp` section, if any, holds the dynamic-linker path.
    let interp = sections
        .iter()
        .find(|(_, s)| s.name == ".interp")
        .and_then(|(_, s)| read_cstr(data, s.file_off, s.size));

    // RPATH/RUNPATH live in `.dynamic`, indexing into `.dynstr`.
    let dynstr = sections
        .iter()
        .find(|(_, s)| s.name == ".dynstr")
        .map(|(_, s)| (s.file_off, s.size));
    let runpaths = match (sections.iter().find(|(t, _)| *t == SHT_DYNAMIC), dynstr) {
        (Some((_, dynamic)), Some((str_off, str_size))) => {
            parse_runpaths(data, dynamic, str_off, str_size)
        }
        _ => Vec::new(),
    };

    Some(ElfInfo {
        is_shared: e_type == 3,
        sections: sections.into_iter().map(|(_, s)| s).collect(),
        interp,
        runpaths,
    })
}

/// Reads `DT_RPATH`/`DT_RUNPATH` strings out of a `.dynamic` section.
fn parse_runpaths(data: &[u8], dynamic: &Section, str_off: u64, str_size: u64) -> Vec<String> {
    let mut out = Vec::new();
    let base = dynamic.file_off as usize;
    let end = base.saturating_add(dynamic.size as usize).min(data.len());
    let mut pos = base;
    while pos + 16 <= end {
        let tag = read_i64(data, pos as u64).unwrap_or(DT_NULL);
        let val = read_u64(data, (pos + 8) as u64).unwrap_or(0);
        if tag == DT_NULL {
            break;
        }
        if (tag == DT_RPATH || tag == DT_RUNPATH)
            && let Some(s) = read_cstr(data, str_off + val, str_size)
        {
            out.extend(s.split(':').filter(|p| !p.is_empty()).map(String::from));
        }
        pos += 16;
    }
    out
}

/// Returns a copy of the `index`-th section header's 64 bytes.
fn section_header(data: &[u8], shoff: u64, entsize: usize, index: usize) -> Option<[u8; 64]> {
    let start = (shoff as usize).checked_add(index.checked_mul(entsize)?)?;
    let slice = data.get(start..start + 64)?;
    let mut buf = [0u8; 64];
    buf.copy_from_slice(slice);
    Some(buf)
}

/// Reads a NUL-terminated string from `data` starting at `off`, bounded
/// by `[off, off+limit)` and the slice length.
fn read_cstr(data: &[u8], off: u64, limit: u64) -> Option<String> {
    let start = off as usize;
    let end = (off + limit).min(data.len() as u64) as usize;
    let region = data.get(start..end)?;
    let len = region.iter().position(|&b| b == 0).unwrap_or(region.len());
    Some(String::from_utf8_lossy(&region[..len]).into_owned())
}

fn read_u16(data: &[u8], off: u64) -> Option<u16> {
    let i = off as usize;
    Some(u16::from_le_bytes(data.get(i..i + 2)?.try_into().ok()?))
}

fn read_u32(data: &[u8], off: u64) -> Option<u32> {
    let i = off as usize;
    Some(u32::from_le_bytes(data.get(i..i + 4)?.try_into().ok()?))
}

fn read_u64(data: &[u8], off: u64) -> Option<u64> {
    let i = off as usize;
    Some(u64::from_le_bytes(data.get(i..i + 8)?.try_into().ok()?))
}

fn read_i64(data: &[u8], off: u64) -> Option<i64> {
    read_u64(data, off).map(|v| v as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_elf() {
        assert!(parse(b"not an elf file at all, padding padding padding____").is_none());
        assert!(parse(&[0u8; 64]).is_none());
    }

    #[test]
    fn rejects_elf32_and_big_endian() {
        let mut hdr = [0u8; 64];
        hdr[0..4].copy_from_slice(b"\x7fELF");
        hdr[4] = 1; // ELFCLASS32
        hdr[5] = 1;
        assert!(parse(&hdr).is_none());
    }

    #[test]
    fn parses_headerless_elf64_type() {
        let mut hdr = [0u8; 64];
        hdr[0..4].copy_from_slice(b"\x7fELF");
        hdr[4] = 2; // ELFCLASS64
        hdr[5] = 1; // little-endian
        hdr[0x10] = 3; // ET_DYN
        let info = parse(&hdr).expect("valid elf64 header");
        assert!(info.is_shared);
        assert!(info.sections.is_empty());
    }
}
