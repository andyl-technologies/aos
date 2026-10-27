//! Replay-oracle preimage comparison for a failed checkpoint promotion.
//!
//! A replay-oracle mismatch names only RAM and device-projection digests. When
//! the flight sets `CRUCIBLE_FINGERPRINT_MATERIAL_DUMP_DIR`, the QEMU plugin
//! keeps the exact preimages behind each in-window sample (see the plugin's
//! `fingerprint_sampler::material_dump`). This module pairs those dumps with
//! the digests in each mismatch record and prints where they differ:
//!
//! ```text
//! material-candidates icount=<n> stems=[<stem>:ram=<8 hex>:device=<8 hex>,...]
//! material-ram a=<label> b=<label> block=<name> pages=<n> ranges=[0x<start>-0x<end>,...]
//! material-ram-page block=<name> page=0x<offset> diffs=[+<offset>:<a>><b>,...]
//! material-device a=<label> b=<label> section=<id>/<instance> a_bytes=<n> b_bytes=<n> diffs=[...]
//! material-device-bytes section=<id>/<instance> side=<label> hex=<payload>
//! ```
//!
//! Every other dump taken at the mismatching count is also compared against
//! the fat side, which separates a live process that diverged from a
//! checkpoint whose preimage is incomplete. The output is diagnostic only.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const DUMP_DIRECTORY_ENVIRONMENT: &str = "CRUCIBLE_FINGERPRINT_MATERIAL_DUMP_DIR";
const RECORD_PREFIX: &str = "CRUCIBLE-PHASE4-CLOCK-TRACE";
const PROJECTION_MAGIC: &[u8] = b"CRUCFPR1";
const PAGE_BYTES: usize = 4096;
const MAXIMUM_RANGES: usize = 32;
const MAXIMUM_DETAILED_PAGES: usize = 6;
const MAXIMUM_BYTE_DIFFS: usize = 24;
const MAXIMUM_FULL_SECTION_BYTES: usize = 768;

/// Component digests that one side of a mismatch record reports.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ComponentDigests {
    icount: u64,
    ram: String,
    device: String,
}

/// One complete dump announced by its metadata file.
#[derive(Clone, Debug)]
struct MaterialDump {
    stem: String,
    icount: u64,
    ram: String,
    device: String,
}

/// One device-projection section located in a preimage.
struct ProjectionSection<'a> {
    name: String,
    payload: &'a [u8],
}

/// Prints preimage differences for every replay-oracle mismatch in `records`.
pub(super) fn report_replay_oracle_material(records: &[String]) {
    let Some(directory) = std::env::var_os(DUMP_DIRECTORY_ENVIRONMENT).map(PathBuf::from) else {
        return;
    };
    let dumps = match read_dumps(&directory) {
        Ok(dumps) => dumps,
        Err(error) => {
            println!("{RECORD_PREFIX} material-unavailable error={error}");
            return;
        }
    };

    let mut mismatches = records
        .iter()
        .filter(|record| record.contains(" oracle-mismatch "))
        .filter_map(|record| {
            Some((
                component_digests(record, "fat_components=")?,
                component_digests(record, "thin_components=")?,
            ))
        })
        .collect::<Vec<_>>();
    mismatches.sort();
    mismatches.dedup();

    for (fat, thin) in mismatches {
        report_mismatch(&directory, &dumps, &fat, &thin);
    }
}

fn report_mismatch(
    directory: &Path,
    dumps: &[MaterialDump],
    fat: &ComponentDigests,
    thin: &ComponentDigests,
) {
    let candidates = dumps
        .iter()
        .filter(|dump| dump.icount == fat.icount)
        .collect::<Vec<_>>();
    let listing = candidates
        .iter()
        .map(|dump| {
            format!(
                "{}:ram={}:device={}",
                dump.stem,
                short(&dump.ram),
                short(&dump.device)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "{RECORD_PREFIX} material-candidates icount={} stems=[{listing}]",
        fat.icount
    );

    let find = |digests: &ComponentDigests| {
        candidates
            .iter()
            .find(|dump| dump.ram == digests.ram && dump.device == digests.device)
            .copied()
    };
    let Some(fat_dump) = find(fat) else {
        println!(
            "{RECORD_PREFIX} material-missing side=fat ram={}",
            short(&fat.ram)
        );
        return;
    };
    match find(thin) {
        Some(thin_dump) => compare_dumps(directory, ("fat", fat_dump), ("thin", thin_dump)),
        None => println!(
            "{RECORD_PREFIX} material-missing side=thin ram={}",
            short(&thin.ram)
        ),
    }

    // Any other process sampled at this count, such as the live capture, is
    // compared against the fat preimage as well.
    for other in candidates
        .iter()
        .filter(|dump| dump.ram != fat.ram && dump.ram != thin.ram)
    {
        compare_dumps(directory, ("fat", fat_dump), (other.stem.as_str(), other));
    }
}

fn compare_dumps(directory: &Path, a: (&str, &MaterialDump), b: (&str, &MaterialDump)) {
    let read = |dump: &MaterialDump, extension: &str| {
        std::fs::read(directory.join(format!("{}.{extension}", dump.stem)))
    };
    match (read(a.1, "ram"), read(b.1, "ram")) {
        (Ok(left), Ok(right)) => compare_ram(a.0, &left, b.0, &right),
        (Err(error), _) | (_, Err(error)) => {
            println!("{RECORD_PREFIX} material-ram-unavailable error={error}");
        }
    }
    match (read(a.1, "device"), read(b.1, "device")) {
        (Ok(left), Ok(right)) => compare_device(a.0, &left, b.0, &right),
        (Err(error), _) | (_, Err(error)) => {
            println!("{RECORD_PREFIX} material-device-unavailable error={error}");
        }
    }
}

fn compare_ram(a_label: &str, a: &[u8], b_label: &str, b: &[u8]) {
    let (Some(a_blocks), Some(b_blocks)) = (ram_blocks(a), ram_blocks(b)) else {
        println!("{RECORD_PREFIX} material-ram-unparsed a={a_label} b={b_label}");
        return;
    };

    for (name, a_bytes) in &a_blocks {
        let Some(b_bytes) = b_blocks.get(name) else {
            println!("{RECORD_PREFIX} material-ram-block-missing block={name} side={b_label}");
            continue;
        };
        let pages = a_bytes
            .chunks(PAGE_BYTES)
            .zip(b_bytes.chunks(PAGE_BYTES))
            .enumerate()
            .filter(|(_, (left, right))| left != right)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if pages.is_empty() && a_bytes.len() == b_bytes.len() {
            continue;
        }

        println!(
            "{RECORD_PREFIX} material-ram a={a_label} b={b_label} block={name} a_bytes={} b_bytes={} pages={} ranges=[{}]",
            a_bytes.len(),
            b_bytes.len(),
            pages.len(),
            page_ranges(&pages),
        );
        for page in pages.iter().take(MAXIMUM_DETAILED_PAGES) {
            let start = page * PAGE_BYTES;
            let end = (start + PAGE_BYTES).min(a_bytes.len()).min(b_bytes.len());
            println!(
                "{RECORD_PREFIX} material-ram-page block={name} page=0x{start:x} diffs=[{}]",
                byte_diffs(&a_bytes[start..end], &b_bytes[start..end]),
            );
        }
    }
}

fn compare_device(a_label: &str, a: &[u8], b_label: &str, b: &[u8]) {
    let (Some(a_sections), Some(b_sections)) = (projection_sections(a), projection_sections(b))
    else {
        println!("{RECORD_PREFIX} material-device-unparsed a={a_label} b={b_label}");
        return;
    };
    let b_by_name = b_sections
        .iter()
        .map(|section| (section.name.as_str(), section.payload))
        .collect::<BTreeMap<_, _>>();

    for section in &a_sections {
        let Some(other) = b_by_name.get(section.name.as_str()) else {
            println!(
                "{RECORD_PREFIX} material-device-section-missing section={} side={b_label}",
                section.name
            );
            continue;
        };
        if section.payload == *other {
            continue;
        }

        println!(
            "{RECORD_PREFIX} material-device a={a_label} b={b_label} section={} a_bytes={} b_bytes={} diffs=[{}]",
            section.name,
            section.payload.len(),
            other.len(),
            byte_diffs(section.payload, other),
        );
        if section.payload.len().max(other.len()) <= MAXIMUM_FULL_SECTION_BYTES {
            for (label, payload) in [(a_label, section.payload), (b_label, *other)] {
                println!(
                    "{RECORD_PREFIX} material-device-bytes section={} side={label} hex={}",
                    section.name,
                    hex::encode(payload),
                );
            }
        }
    }
}

/// Reads every dump whose metadata file is complete.
fn read_dumps(directory: &Path) -> std::io::Result<Vec<MaterialDump>> {
    let mut dumps = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("meta") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        let text = std::fs::read_to_string(&path)?;
        let fields = text
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect::<BTreeMap<_, _>>();
        let (Some(icount), Some(ram), Some(device)) = (
            fields
                .get("sample_icount")
                .and_then(|value| value.parse().ok()),
            fields.get("ram_digest"),
            fields.get("device_digest"),
        ) else {
            continue;
        };
        dumps.push(MaterialDump {
            stem: stem.to_owned(),
            icount,
            ram: (*ram).to_owned(),
            device: (*device).to_owned(),
        });
    }

    dumps.sort_by(|left, right| left.stem.cmp(&right.stem));
    Ok(dumps)
}

/// Extracts `icount=`, `ram=<bytes>:<hex>`, and `device=<bytes>:<hex>` after `marker`.
fn component_digests(record: &str, marker: &str) -> Option<ComponentDigests> {
    let (_, components) = record.split_once(marker)?;
    let mut icount = None;
    let mut ram = None;
    let mut device = None;
    for field in components.split_whitespace() {
        if let Some(value) = field.strip_prefix("icount=") {
            icount = value.parse().ok();
        } else if let Some(value) = field.strip_prefix("ram=") {
            ram = value.split_once(':').map(|(_, digest)| digest.to_owned());
        } else if let Some(value) = field.strip_prefix("device=") {
            device = value.split_once(':').map(|(_, digest)| digest.to_owned());
        } else if field.contains("_components=") {
            break;
        }
    }

    Some(ComponentDigests {
        icount: icount?,
        ram: ram?,
        device: device?,
    })
}

/// Splits the RAM preimage into named blocks.
///
/// The preimage is a length-prefixed domain string followed by, per block, a
/// length-prefixed name, the block length, and the length-prefixed bytes.
fn ram_blocks(material: &[u8]) -> Option<BTreeMap<String, &[u8]>> {
    let mut cursor = 0;
    let _domain = length_prefixed(material, &mut cursor)?;
    let mut blocks = BTreeMap::new();
    while cursor < material.len() {
        let name = String::from_utf8_lossy(length_prefixed(material, &mut cursor)?).into_owned();
        let declared = be_u64(material, &mut cursor)?;
        let bytes = length_prefixed(material, &mut cursor)?;
        if declared != bytes.len() as u64 {
            return None;
        }
        blocks.insert(name, bytes);
    }

    Some(blocks)
}

/// Locates device-projection sections by their self-describing headers.
///
/// Section payloads carry no length, so each payload runs to the next
/// plausible header or to the ten-byte stream terminator. Both compared
/// preimages share one schema, so any accidental split is identical on both.
fn projection_sections(material: &[u8]) -> Option<Vec<ProjectionSection<'_>>> {
    let start = material
        .windows(PROJECTION_MAGIC.len())
        .position(|window| window == PROJECTION_MAGIC)?
        + PROJECTION_MAGIC.len();
    let end = material.len().checked_sub(10)?;

    let mut headers = Vec::new();
    let mut cursor = start;
    while cursor < end {
        let Some((name, payload_start)) = projection_header(material, cursor) else {
            cursor += 1;
            continue;
        };
        headers.push((name, cursor, payload_start));
        cursor = payload_start;
    }

    let sections = headers
        .iter()
        .enumerate()
        .map(|(index, (name, _, payload_start))| {
            let payload_end = headers.get(index + 1).map_or(end, |next| next.1);
            ProjectionSection {
                name: name.clone(),
                payload: &material[*payload_start..payload_end],
            }
        })
        .collect::<Vec<_>>();
    (!sections.is_empty()).then_some(sections)
}

/// Parses `be16 length, id, be32 instance, be32 version` when it is plausible.
fn projection_header(material: &[u8], offset: usize) -> Option<(String, usize)> {
    let length = usize::from(u16::from_be_bytes(
        material.get(offset..offset + 2)?.try_into().ok()?,
    ));
    if !(3..=96).contains(&length) {
        return None;
    }
    let name = material.get(offset + 2..offset + 2 + length)?;
    let name_is_plausible = name
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || b"/:._-".contains(byte))
        && name.iter().any(u8::is_ascii_alphabetic);
    if !name_is_plausible {
        return None;
    }
    let numbers = offset + 2 + length;
    let instance = u32::from_be_bytes(material.get(numbers..numbers + 4)?.try_into().ok()?);
    let version = u32::from_be_bytes(material.get(numbers + 4..numbers + 8)?.try_into().ok()?);
    if instance >= 4096 || !(1..=64).contains(&version) {
        return None;
    }

    Some((
        format!("{}/{instance}", String::from_utf8_lossy(name)),
        numbers + 8,
    ))
}

fn be_u64(material: &[u8], cursor: &mut usize) -> Option<u64> {
    let bytes = material.get(*cursor..*cursor + 8)?;
    *cursor += 8;
    Some(u64::from_be_bytes(bytes.try_into().ok()?))
}

fn length_prefixed<'a>(material: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    let length = usize::try_from(be_u64(material, cursor)?).ok()?;
    let bytes = material.get(*cursor..cursor.checked_add(length)?)?;
    *cursor += length;
    Some(bytes)
}

/// Formats sorted page indices as bounded byte-offset ranges.
fn page_ranges(pages: &[usize]) -> String {
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for page in pages {
        match ranges.last_mut() {
            Some((_, end)) if *end + 1 == *page => *end = *page,
            _ => ranges.push((*page, *page)),
        }
    }
    let shown = ranges
        .iter()
        .take(MAXIMUM_RANGES)
        .map(|(start, end)| format!("0x{:x}-0x{:x}", start * PAGE_BYTES, (end + 1) * PAGE_BYTES))
        .collect::<Vec<_>>()
        .join(",");
    if ranges.len() > MAXIMUM_RANGES {
        format!("{shown},+{} more", ranges.len() - MAXIMUM_RANGES)
    } else {
        shown
    }
}

/// Formats the first differing byte positions as `+offset:a>b`.
fn byte_diffs(a: &[u8], b: &[u8]) -> String {
    let mut diffs = a
        .iter()
        .zip(b)
        .enumerate()
        .filter(|(_, (left, right))| left != right)
        .take(MAXIMUM_BYTE_DIFFS)
        .map(|(offset, (left, right))| format!("+{offset}:{left:02x}>{right:02x}"))
        .collect::<Vec<_>>();
    if a.len() != b.len() {
        diffs.push(format!("length:{}>{}", a.len(), b.len()));
    }
    diffs.join(",")
}

fn short(digest: &str) -> &str {
    digest.get(..8).unwrap_or(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, instance: u32, version: u32) -> Vec<u8> {
        let mut bytes = (name.len() as u16).to_be_bytes().to_vec();
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(&instance.to_be_bytes());
        bytes.extend_from_slice(&version.to_be_bytes());
        bytes
    }

    #[test]
    fn projection_sections_split_at_headers() {
        let mut material = b"\0\0\0\0\0\0\0\x03dom".to_vec();
        material.extend_from_slice(PROJECTION_MAGIC);
        material.extend(header("timer", 0, 6));
        material.extend_from_slice(&[1, 2, 3, 4]);
        material.extend(header("0000:00:02.0/virtio-net", 0, 11));
        material.extend_from_slice(&[9, 9]);
        material.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

        let Some(sections) = projection_sections(&material) else {
            panic!("projection did not parse");
        };

        let parsed = sections
            .iter()
            .map(|section| (section.name.as_str(), section.payload))
            .collect::<Vec<_>>();
        assert_eq!(
            parsed,
            vec![
                ("timer/0", &[1_u8, 2, 3, 4][..]),
                ("0000:00:02.0/virtio-net/0", &[9_u8, 9][..]),
            ]
        );
    }

    #[test]
    fn ram_blocks_follow_the_length_prefixed_layout() {
        let mut material = Vec::new();
        material.extend_from_slice(&6_u64.to_be_bytes());
        material.extend_from_slice(b"domain");
        material.extend_from_slice(&6_u64.to_be_bytes());
        material.extend_from_slice(b"pc.ram");
        material.extend_from_slice(&3_u64.to_be_bytes());
        material.extend_from_slice(&3_u64.to_be_bytes());
        material.extend_from_slice(&[7, 8, 9]);

        let Some(blocks) = ram_blocks(&material) else {
            panic!("RAM material did not parse");
        };

        assert_eq!(blocks.get("pc.ram").copied(), Some(&[7_u8, 8, 9][..]));
    }

    #[test]
    fn mismatch_components_are_read_per_side() {
        let record = "CRUCIBLE-PHASE4-CLOCK-TRACE oracle-mismatch node=peer fat_components=icount=5 rr=0/1/2 ram=8:aa device=4:bb sections=1 thin_components=icount=5 rr=0/1/2 ram=8:cc device=4:dd sections=1";

        let fat = component_digests(record, "fat_components=");
        let thin = component_digests(record, "thin_components=");

        assert_eq!(
            fat,
            Some(ComponentDigests {
                icount: 5,
                ram: "aa".to_owned(),
                device: "bb".to_owned(),
            })
        );
        assert_eq!(thin.map(|digests| digests.ram), Some("cc".to_owned()));
    }

    #[test]
    fn page_ranges_merge_adjacent_pages() {
        assert_eq!(page_ranges(&[0, 1, 5]), "0x0-0x2000,0x5000-0x6000");
    }
}
