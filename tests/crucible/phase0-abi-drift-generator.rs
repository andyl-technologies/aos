use std::fs::{self, File};
use std::io::{self, Write};
use std::mem::{align_of, offset_of, size_of};
use std::path::Path;

const REGION_MAGIC: u64 = u64::from_le_bytes(*b"CRUCSHM1");
const ABI_VERSION: u32 = 2;
const HEADER_SIZE: usize = 256;
const HEADER_ALIGN: usize = 128;

#[repr(C, align(128))]
struct RegionHeader {
    magic: u64,
    abi_version: u32,
    node_count: u32,
    queue_capacity: u32,
    ring_count: u32,
    ring_hdr_off: u64,
    ring_data_off: u64,
    entry_stride: u64,
    region_size: u64,
    icount_shift: u32,
    pause_requested: u8,
    shutdown_requested: u8,
    reserved: [u8; 194],
}

const _: () = assert!(size_of::<RegionHeader>() == HEADER_SIZE);
const _: () = assert!(align_of::<RegionHeader>() == HEADER_ALIGN);
const _: () = assert!(offset_of!(RegionHeader, magic) == 0);
const _: () = assert!(offset_of!(RegionHeader, abi_version) == 8);
const _: () = assert!(offset_of!(RegionHeader, node_count) == 12);
const _: () = assert!(offset_of!(RegionHeader, queue_capacity) == 16);
const _: () = assert!(offset_of!(RegionHeader, ring_count) == 20);
const _: () = assert!(offset_of!(RegionHeader, ring_hdr_off) == 24);
const _: () = assert!(offset_of!(RegionHeader, ring_data_off) == 32);
const _: () = assert!(offset_of!(RegionHeader, entry_stride) == 40);
const _: () = assert!(offset_of!(RegionHeader, region_size) == 48);
const _: () = assert!(offset_of!(RegionHeader, icount_shift) == 56);
const _: () = assert!(offset_of!(RegionHeader, pause_requested) == 60);
const _: () = assert!(offset_of!(RegionHeader, shutdown_requested) == 61);

#[derive(Clone, Copy)]
enum Value {
    U64(u64),
    U32(u32),
    U8(u8),
}

#[derive(Clone, Copy)]
struct FieldFact {
    name: &'static str,
    c_type: &'static str,
    rust_type: &'static str,
    offset: usize,
    drifted_offset: usize,
    value: Value,
}

fn fields() -> [FieldFact; 12] {
    [
        FieldFact {
            name: "magic",
            c_type: "uint64_t",
            rust_type: "u64",
            offset: offset_of!(RegionHeader, magic),
            drifted_offset: offset_of!(RegionHeader, magic),
            value: Value::U64(REGION_MAGIC),
        },
        FieldFact {
            name: "abi_version",
            c_type: "uint32_t",
            rust_type: "u32",
            offset: offset_of!(RegionHeader, abi_version),
            drifted_offset: offset_of!(RegionHeader, abi_version),
            value: Value::U32(ABI_VERSION),
        },
        FieldFact {
            name: "node_count",
            c_type: "uint32_t",
            rust_type: "u32",
            offset: offset_of!(RegionHeader, node_count),
            drifted_offset: offset_of!(RegionHeader, queue_capacity),
            value: Value::U32(4),
        },
        FieldFact {
            name: "queue_capacity",
            c_type: "uint32_t",
            rust_type: "u32",
            offset: offset_of!(RegionHeader, queue_capacity),
            drifted_offset: offset_of!(RegionHeader, node_count),
            value: Value::U32(8),
        },
        FieldFact {
            name: "ring_count",
            c_type: "uint32_t",
            rust_type: "u32",
            offset: offset_of!(RegionHeader, ring_count),
            drifted_offset: offset_of!(RegionHeader, ring_count),
            value: Value::U32(12),
        },
        FieldFact {
            name: "ring_hdr_off",
            c_type: "uint64_t",
            rust_type: "u64",
            offset: offset_of!(RegionHeader, ring_hdr_off),
            drifted_offset: offset_of!(RegionHeader, ring_hdr_off),
            value: Value::U64(4096),
        },
        FieldFact {
            name: "ring_data_off",
            c_type: "uint64_t",
            rust_type: "u64",
            offset: offset_of!(RegionHeader, ring_data_off),
            drifted_offset: offset_of!(RegionHeader, ring_data_off),
            value: Value::U64(8192),
        },
        FieldFact {
            name: "entry_stride",
            c_type: "uint64_t",
            rust_type: "u64",
            offset: offset_of!(RegionHeader, entry_stride),
            drifted_offset: offset_of!(RegionHeader, entry_stride),
            value: Value::U64(64),
        },
        FieldFact {
            name: "region_size",
            c_type: "uint64_t",
            rust_type: "u64",
            offset: offset_of!(RegionHeader, region_size),
            drifted_offset: offset_of!(RegionHeader, region_size),
            value: Value::U64(16384),
        },
        FieldFact {
            name: "icount_shift",
            c_type: "uint32_t",
            rust_type: "u32",
            offset: offset_of!(RegionHeader, icount_shift),
            drifted_offset: offset_of!(RegionHeader, icount_shift),
            value: Value::U32(0),
        },
        FieldFact {
            name: "pause_requested",
            c_type: "uint8_t",
            rust_type: "u8",
            offset: offset_of!(RegionHeader, pause_requested),
            drifted_offset: offset_of!(RegionHeader, pause_requested),
            value: Value::U8(1),
        },
        FieldFact {
            name: "shutdown_requested",
            c_type: "uint8_t",
            rust_type: "u8",
            offset: offset_of!(RegionHeader, shutdown_requested),
            drifted_offset: offset_of!(RegionHeader, shutdown_requested),
            value: Value::U8(0),
        },
    ]
}

fn main() -> io::Result<()> {
    let Some(out_dir) = std::env::args_os().nth(1) else {
        eprintln!("usage: phase0-abi-drift-generator <out-dir>");
        std::process::exit(2);
    };
    let out_dir = Path::new(&out_dir);
    fs::create_dir_all(out_dir)?;

    let facts = fields();
    write_header(&out_dir.join("crucible_shmem_abi.h"), &facts, false)?;
    write_header(
        &out_dir.join("crucible_shmem_abi_drifted.h"),
        &facts,
        true,
    )?;
    write_c_smoke(&out_dir.join("c-good.c"), "crucible_shmem_abi.h")?;
    write_c_smoke(&out_dir.join("c-drift.c"), "crucible_shmem_abi_drifted.h")?;
    write_c_encoder(&out_dir.join("c-encode-good.c"), &facts, false)?;
    write_c_encoder(&out_dir.join("c-encode-drift.c"), &facts, true)?;
    write_c_roundtrip(&out_dir.join("c-roundtrip-good.c"), &facts)?;
    write_rust_layout(&out_dir.join("rust-good.rs"), &facts, false)?;
    write_rust_layout(&out_dir.join("rust-drift.rs"), &facts, true)?;
    write_rust_roundtrip(&out_dir.join("rust-roundtrip-good.rs"), &facts)?;
    write_golden(&out_dir.join("golden-good.bin"), &facts, false)?;
    write_golden(&out_dir.join("golden-drift.bin"), &facts, true)?;

    Ok(())
}

fn write_header(path: &Path, facts: &[FieldFact], drifted: bool) -> io::Result<()> {
    let mut file = File::create(path)?;
    writeln!(file, "#ifndef CRUCIBLE_SHMEM_ABI_H")?;
    writeln!(file, "#define CRUCIBLE_SHMEM_ABI_H")?;
    writeln!(file, "#include <stddef.h>")?;
    writeln!(file, "#include <stdint.h>")?;
    writeln!(file)?;
    writeln!(file, "#define CRUCIBLE_SHMEM_ABI_VERSION {}u", ABI_VERSION)?;
    writeln!(file, "#define CRUCIBLE_SHMEM_REGION_HEADER_SIZE {HEADER_SIZE}u")?;
    writeln!(
        file,
        "#define CRUCIBLE_SHMEM_REGION_HEADER_ALIGN {HEADER_ALIGN}u"
    )?;
    writeln!(file)?;
    write_c_struct(&mut file, facts, drifted, true)?;
    writeln!(file)?;
    write_c_asserts(&mut file, facts)?;
    writeln!(file, "#endif")?;
    Ok(())
}

fn write_c_struct(
    file: &mut File,
    facts: &[FieldFact],
    drifted: bool,
    named: bool,
) -> io::Result<()> {
    let suffix = if named {
        " crucible_region_header"
    } else {
        ""
    };
    writeln!(file, "struct __attribute__((aligned(128))){suffix} {{")?;
    for name in field_order(drifted) {
        let fact = find_fact(facts, name);
        writeln!(file, "  {} {};", fact.c_type, fact.name)?;
    }
    writeln!(file, "  uint8_t reserved[194];")?;
    writeln!(file, "}};")?;
    Ok(())
}

fn write_c_asserts(file: &mut File, facts: &[FieldFact]) -> io::Result<()> {
    writeln!(
        file,
        "_Static_assert(sizeof(struct crucible_region_header) == {HEADER_SIZE}, \"RegionHeader size\");"
    )?;
    writeln!(
        file,
        "_Static_assert(_Alignof(struct crucible_region_header) == {HEADER_ALIGN}, \"RegionHeader align\");"
    )?;
    for fact in facts {
        writeln!(
            file,
            "_Static_assert(offsetof(struct crucible_region_header, {}) == {}, \"RegionHeader.{} offset\");",
            fact.name, fact.offset, fact.name
        )?;
    }
    Ok(())
}

fn write_c_smoke(path: &Path, header: &str) -> io::Result<()> {
    let mut file = File::create(path)?;
    writeln!(file, "#include \"{header}\"")?;
    writeln!(file, "int main(void) {{ return 0; }}")?;
    Ok(())
}

fn write_c_encoder(path: &Path, facts: &[FieldFact], drifted: bool) -> io::Result<()> {
    let mut file = File::create(path)?;
    writeln!(file, "#include <stdint.h>")?;
    writeln!(file, "#include <stdio.h>")?;
    writeln!(file, "#include <string.h>")?;
    if drifted {
        write_c_struct(&mut file, facts, true, true)?;
    } else {
        writeln!(file, "#include \"crucible_shmem_abi.h\"")?;
    }
    write_c_populate_function(&mut file)?;
    writeln!(file, "int main(int argc, char **argv) {{")?;
    writeln!(file, "  if (argc != 2) {{ return 2; }}")?;
    writeln!(file, "  struct crucible_region_header header;")?;
    writeln!(file, "  populate(&header);")?;
    writeln!(file, "  FILE *out = fopen(argv[1], \"wb\");")?;
    writeln!(file, "  if (out == NULL) {{ return 3; }}")?;
    writeln!(
        file,
        "  if (fwrite(&header, 1, sizeof(header), out) != sizeof(header)) {{ return 4; }}"
    )?;
    writeln!(file, "  return fclose(out) == 0 ? 0 : 5;")?;
    writeln!(file, "}}")?;
    Ok(())
}

fn write_c_roundtrip(path: &Path, facts: &[FieldFact]) -> io::Result<()> {
    let mut file = File::create(path)?;
    writeln!(file, "#include \"crucible_shmem_abi.h\"")?;
    writeln!(file, "#include <stdint.h>")?;
    writeln!(file, "#include <stdio.h>")?;
    write_c_check_function(&mut file, facts)?;
    writeln!(file, "int main(int argc, char **argv) {{")?;
    writeln!(file, "  if (argc != 3) {{ return 2; }}")?;
    writeln!(file, "  struct crucible_region_header header;")?;
    writeln!(file, "  FILE *in = fopen(argv[1], \"rb\");")?;
    writeln!(file, "  if (in == NULL) {{ return 3; }}")?;
    writeln!(
        file,
        "  if (fread(&header, 1, sizeof(header), in) != sizeof(header)) {{ return 4; }}"
    )?;
    writeln!(file, "  if (fclose(in) != 0) {{ return 5; }}")?;
    writeln!(file, "  if (check(&header) != 0) {{ return 6; }}")?;
    writeln!(file, "  FILE *out = fopen(argv[2], \"wb\");")?;
    writeln!(file, "  if (out == NULL) {{ return 7; }}")?;
    writeln!(
        file,
        "  if (fwrite(&header, 1, sizeof(header), out) != sizeof(header)) {{ return 8; }}"
    )?;
    writeln!(file, "  return fclose(out) == 0 ? 0 : 9;")?;
    writeln!(file, "}}")?;
    Ok(())
}

fn write_c_populate_function(file: &mut File) -> io::Result<()> {
    writeln!(
        file,
        "static void populate(struct crucible_region_header *header) {{"
    )?;
    writeln!(file, "  memset(header, 0, sizeof(*header));")?;
    writeln!(file, "  header->magic = UINT64_C(0x314d485343555243);")?;
    writeln!(file, "  header->abi_version = {ABI_VERSION};")?;
    writeln!(file, "  header->node_count = 4;")?;
    writeln!(file, "  header->queue_capacity = 8;")?;
    writeln!(file, "  header->ring_count = 12;")?;
    writeln!(file, "  header->ring_hdr_off = 4096;")?;
    writeln!(file, "  header->ring_data_off = 8192;")?;
    writeln!(file, "  header->entry_stride = 64;")?;
    writeln!(file, "  header->region_size = 16384;")?;
    writeln!(file, "  header->icount_shift = 0;")?;
    writeln!(file, "  header->pause_requested = 1;")?;
    writeln!(file, "  header->shutdown_requested = 0;")?;
    writeln!(file, "}}")?;
    Ok(())
}

fn write_c_check_function(file: &mut File, facts: &[FieldFact]) -> io::Result<()> {
    writeln!(
        file,
        "static int check(const struct crucible_region_header *header) {{"
    )?;
    for fact in facts {
        write!(file, "  if (header->{} != ", fact.name)?;
        write_c_value(file, fact.value)?;
        writeln!(file, ") {{ return 1; }}")?;
    }
    writeln!(file, "  return 0;")?;
    writeln!(file, "}}")?;
    Ok(())
}

fn write_c_value(file: &mut File, value: Value) -> io::Result<()> {
    match value {
        Value::U64(value) => write!(file, "UINT64_C(0x{value:016x})"),
        Value::U32(value) => write!(file, "{value}u"),
        Value::U8(value) => write!(file, "{value}u"),
    }
}

fn write_rust_layout(path: &Path, facts: &[FieldFact], drifted: bool) -> io::Result<()> {
    let mut file = File::create(path)?;
    writeln!(file, "use std::mem::{{align_of, offset_of, size_of}};")?;
    write_rust_struct(&mut file, facts, drifted)?;
    write_rust_asserts(&mut file, facts)?;
    writeln!(file, "fn main() {{}}")?;
    Ok(())
}

fn write_rust_roundtrip(path: &Path, facts: &[FieldFact]) -> io::Result<()> {
    let mut file = File::create(path)?;
    writeln!(file, "use std::fs;")?;
    writeln!(file, "use std::io;")?;
    writeln!(file, "use std::mem::{{align_of, offset_of, size_of}};")?;
    write_rust_struct(&mut file, facts, false)?;
    write_rust_asserts(&mut file, facts)?;
    writeln!(file, "fn main() -> io::Result<()> {{")?;
    writeln!(file, "    let mut args = std::env::args_os();")?;
    writeln!(file, "    let _program = args.next();")?;
    writeln!(file, "    let Some(input) = args.next() else {{")?;
    writeln!(file, "        eprintln!(\"usage: rust-roundtrip <input> <output>\");")?;
    writeln!(file, "        std::process::exit(2);")?;
    writeln!(file, "    }};")?;
    writeln!(file, "    let Some(output) = args.next() else {{")?;
    writeln!(file, "        eprintln!(\"usage: rust-roundtrip <input> <output>\");")?;
    writeln!(file, "        std::process::exit(2);")?;
    writeln!(file, "    }};")?;
    writeln!(file, "    let bytes = fs::read(input)?;")?;
    writeln!(file, "    if bytes.len() != size_of::<RegionHeader>() {{")?;
    writeln!(file, "        return Err(io::Error::new(io::ErrorKind::InvalidData, \"wrong input size\"));")?;
    writeln!(file, "    }}")?;
    writeln!(file, "    let header = decode(&bytes)?;")?;
    writeln!(file, "    fs::write(output, encode(&header))")?;
    writeln!(file, "}}")?;
    write_rust_decode(&mut file, facts)?;
    write_rust_encode(&mut file, facts)?;
    write_rust_helpers(&mut file)?;
    Ok(())
}

fn write_rust_struct(file: &mut File, facts: &[FieldFact], drifted: bool) -> io::Result<()> {
    writeln!(file, "#[repr(C, align(128))]")?;
    writeln!(file, "struct RegionHeader {{")?;
    for name in field_order(drifted) {
        let fact = find_fact(facts, name);
        writeln!(file, "    {}: {},", fact.name, fact.rust_type)?;
    }
    writeln!(file, "    reserved: [u8; 194],")?;
    writeln!(file, "}}")?;
    Ok(())
}

fn write_rust_asserts(file: &mut File, facts: &[FieldFact]) -> io::Result<()> {
    writeln!(
        file,
        "const _: () = assert!(size_of::<RegionHeader>() == {HEADER_SIZE});"
    )?;
    writeln!(
        file,
        "const _: () = assert!(align_of::<RegionHeader>() == {HEADER_ALIGN});"
    )?;
    for fact in facts {
        writeln!(
            file,
            "const _: () = assert!(offset_of!(RegionHeader, {}) == {});",
            fact.name, fact.offset
        )?;
    }
    Ok(())
}

fn write_rust_decode(file: &mut File, facts: &[FieldFact]) -> io::Result<()> {
    writeln!(file, "fn decode(bytes: &[u8]) -> io::Result<RegionHeader> {{")?;
    writeln!(file, "    let header = RegionHeader {{")?;
    for fact in facts {
        writeln!(
            file,
            "        {}: read_{}(bytes, offset_of!(RegionHeader, {})),",
            fact.name, fact.rust_type, fact.name
        )?;
    }
    writeln!(file, "        reserved: [0; 194],")?;
    writeln!(file, "    }};")?;
    for fact in facts {
        write!(file, "    if header.{} != ", fact.name)?;
        write_rust_value(file, fact.value)?;
        writeln!(file, " {{")?;
        writeln!(
            file,
            "        return Err(io::Error::new(io::ErrorKind::InvalidData, \"{} mismatch\"));",
            fact.name
        )?;
        writeln!(file, "    }}")?;
    }
    writeln!(file, "    Ok(header)")?;
    writeln!(file, "}}")?;
    Ok(())
}

fn write_rust_encode(file: &mut File, facts: &[FieldFact]) -> io::Result<()> {
    writeln!(file, "fn encode(header: &RegionHeader) -> [u8; {HEADER_SIZE}] {{")?;
    writeln!(file, "    let mut bytes = [0u8; {HEADER_SIZE}];")?;
    for fact in facts {
        writeln!(
            file,
            "    write_{}(&mut bytes, offset_of!(RegionHeader, {}), header.{});",
            fact.rust_type, fact.name, fact.name
        )?;
    }
    writeln!(file, "    bytes")?;
    writeln!(file, "}}")?;
    Ok(())
}

fn write_rust_helpers(file: &mut File) -> io::Result<()> {
    writeln!(file, "fn read_u64(bytes: &[u8], offset: usize) -> u64 {{")?;
    writeln!(file, "    let mut value = [0u8; 8];")?;
    writeln!(file, "    value.copy_from_slice(&bytes[offset..offset + 8]);")?;
    writeln!(file, "    u64::from_le_bytes(value)")?;
    writeln!(file, "}}")?;
    writeln!(file, "fn read_u32(bytes: &[u8], offset: usize) -> u32 {{")?;
    writeln!(file, "    let mut value = [0u8; 4];")?;
    writeln!(file, "    value.copy_from_slice(&bytes[offset..offset + 4]);")?;
    writeln!(file, "    u32::from_le_bytes(value)")?;
    writeln!(file, "}}")?;
    writeln!(file, "fn read_u8(bytes: &[u8], offset: usize) -> u8 {{")?;
    writeln!(file, "    bytes[offset]")?;
    writeln!(file, "}}")?;
    writeln!(file, "fn write_u64(bytes: &mut [u8; {HEADER_SIZE}], offset: usize, value: u64) {{")?;
    writeln!(file, "    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());")?;
    writeln!(file, "}}")?;
    writeln!(file, "fn write_u32(bytes: &mut [u8; {HEADER_SIZE}], offset: usize, value: u32) {{")?;
    writeln!(file, "    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());")?;
    writeln!(file, "}}")?;
    writeln!(file, "fn write_u8(bytes: &mut [u8; {HEADER_SIZE}], offset: usize, value: u8) {{")?;
    writeln!(file, "    bytes[offset] = value;")?;
    writeln!(file, "}}")?;
    Ok(())
}

fn write_rust_value(file: &mut File, value: Value) -> io::Result<()> {
    match value {
        Value::U64(value) => write!(file, "{value}u64"),
        Value::U32(value) => write!(file, "{value}u32"),
        Value::U8(value) => write!(file, "{value}u8"),
    }
}

fn write_golden(path: &Path, facts: &[FieldFact], drifted: bool) -> io::Result<()> {
    let mut bytes = [0u8; HEADER_SIZE];
    for fact in facts {
        let offset = if drifted {
            fact.drifted_offset
        } else {
            fact.offset
        };
        write_value(&mut bytes, offset, fact.value);
    }
    fs::write(path, bytes)
}

fn write_value(bytes: &mut [u8; HEADER_SIZE], offset: usize, value: Value) {
    match value {
        Value::U64(value) => bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes()),
        Value::U32(value) => bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes()),
        Value::U8(value) => bytes[offset] = value,
    }
}

fn field_order(drifted: bool) -> [&'static str; 12] {
    if drifted {
        [
            "magic",
            "abi_version",
            "queue_capacity",
            "node_count",
            "ring_count",
            "ring_hdr_off",
            "ring_data_off",
            "entry_stride",
            "region_size",
            "icount_shift",
            "pause_requested",
            "shutdown_requested",
        ]
    } else {
        [
            "magic",
            "abi_version",
            "node_count",
            "queue_capacity",
            "ring_count",
            "ring_hdr_off",
            "ring_data_off",
            "entry_stride",
            "region_size",
            "icount_shift",
            "pause_requested",
            "shutdown_requested",
        ]
    }
}

fn find_fact(facts: &[FieldFact], name: &str) -> FieldFact {
    for fact in facts {
        if fact.name == name {
            return *fact;
        }
    }
    unreachable!("missing layout fact for {name}");
}
