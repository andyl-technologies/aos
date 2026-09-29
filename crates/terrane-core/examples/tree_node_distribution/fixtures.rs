//! Builds sorted synthetic namespaces and their complete canonical nodes.
//!
//! The fixture uses the normative 15-byte inline file entry, unsigned byte
//! ordering, leaf prefix compression, domain-separated node identities, and
//! exact child counts and subtree weights. Each key is a single component,
//! so no missing ancestor directories confound the boundary experiment.
//!
//! ```text
//! leaf-item = [key-suffix: bstr, shared: uint, entry]
//! child-ref = [last-key: bstr, child: bstr .size 32, count: uint, weight: uint]
//! node = {1: level, 2: [* item]}
//! ```

use std::error::Error;
use std::fmt;

use terrane_core::boundary::{MAX_NODE, closes_node};

const INLINE_CHUNK: [u8; 32] = [
    0x94, 0x79, 0xe1, 0xe5, 0x74, 0x91, 0x07, 0x8e, 0xb0, 0x9f, 0x9d, 0xec, 0xc2, 0xc5, 0x6c, 0x63,
    0x11, 0x0c, 0x37, 0x2d, 0xe0, 0x15, 0x57, 0xd7, 0x35, 0x60, 0xdb, 0xc2, 0xba, 0x9f, 0x3b, 0xa0,
];

#[derive(Clone, Copy)]
/// Chooses an adversarial family of sorted single-component keys.
pub(super) enum KeyFamily {
    /// Uses consecutive decimal filenames with equal width.
    Sequential,
    /// Gives all filenames the same 120-byte prefix.
    SharedPrefix,
    /// Sorts actual BLAKE3 identities rendered as hexadecimal names.
    HashLike,
}

impl KeyFamily {
    /// Lists every key family exercised by the spike.
    pub(super) const ALL: [Self; 3] = [Self::Sequential, Self::SharedPrefix, Self::HashLike];

    /// Returns the stable family name used in the measurement artifact.
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Sequential => "sequential",
            Self::SharedPrefix => "shared-prefix",
            Self::HashLike => "hash-like",
        }
    }

    pub(super) fn fixture(self, entries: usize) -> Result<Fixture, BuildError> {
        let mut digests = Vec::new();
        if matches!(self, Self::HashLike) {
            digests.try_reserve_exact(entries).map_err(|_| BuildError::Allocation)?;
            for ordinal in 0..entries {
                digests.push(*blake3::hash(&(ordinal as u64).to_le_bytes()).as_bytes());
            }
            digests.sort_unstable();
            if digests.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(BuildError::DuplicateKey);
            }
        }

        Ok(Fixture { family: self, entries, digests })
    }
}

/// Owns a sorted key stream, retaining digests only for hash-like keys.
pub(super) struct Fixture {
    family: KeyFamily,
    entries: usize,
    digests: Vec<[u8; 32]>,
}

impl Fixture {
    fn key(&self, ordinal: usize) -> Vec<u8> {
        match self.family {
            KeyFamily::Sequential => format!("file-{ordinal:08}").into_bytes(),
            KeyFamily::SharedPrefix => {
                let mut key = vec![b'p'; 120];
                key.extend_from_slice(format!("-{ordinal:08}").as_bytes());
                key
            }
            KeyFamily::HashLike => hex(&self.digests[ordinal]).into_bytes(),
        }
    }
}

#[derive(Debug)]
/// Describes a fixture construction failure independently of gate assertions.
pub(super) enum BuildError {
    /// Indicates that storage for generated digest keys could not be reserved.
    Allocation,
    /// Indicates a duplicate generated key.
    DuplicateKey,
    /// Indicates a count or size that cannot fit its encoded integer.
    Overflow,
    /// Indicates too many levels for the normative tree-depth bound.
    Depth,
    /// Indicates an empty key stream or zero ingestion batch size.
    EmptyInput,
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Allocation => "fixture digest allocation failed",
            Self::DuplicateKey => "fixture contains duplicate hash-like keys",
            Self::Overflow => "fixture node count or weight overflowed",
            Self::Depth => "fixture exceeded the sixteen-level limit",
            Self::EmptyInput => "fixture requires entries and a nonzero ingestion batch",
        })
    }
}

impl Error for BuildError {}

#[derive(Debug, PartialEq, Eq)]
/// Records a complete tree identity and each level's encoded-item sizes.
pub(super) struct Measurement {
    /// Carries the domain-separated identity of the final canonical root.
    pub(super) root: [u8; 32],
    /// Lists node statistics in leaf-to-root order.
    pub(super) levels: Vec<LevelReport>,
}

#[derive(Debug, Default, PartialEq, Eq)]
/// Records every node size while distinguishing incomplete tail nodes.
pub(super) struct LevelReport {
    /// Lists accumulated encoded item bytes, excluding node framing.
    pub(super) bytes: Vec<u64>,
    /// Counts nodes whose last item reached or exceeded the hard maximum.
    pub(super) forced: usize,
    complete_total: u64,
    complete_nodes: u64,
}

impl LevelReport {
    /// Returns the mean size of nodes closed by the boundary rule.
    pub(super) fn complete_mean(&self) -> Option<u64> {
        self.complete_total.checked_div(self.complete_nodes)
    }

    fn record(&mut self, bytes: u64, forced: bool, complete: bool) -> Result<(), BuildError> {
        self.bytes.push(bytes);
        self.forced += usize::from(forced);
        if complete {
            self.complete_total = self.complete_total.checked_add(bytes).ok_or(BuildError::Overflow)?;
            self.complete_nodes += 1;
        }

        Ok(())
    }
}

struct Child {
    last_key: Vec<u8>,
    digest: [u8; 32],
    count: u64,
    weight: u64,
}

#[derive(Default)]
struct Node {
    items: Vec<u8>,
    item_count: u64,
    count: u64,
    subtree_weight: u64,
    last_key: Vec<u8>,
}

impl Node {
    fn push(&mut self, key: &[u8], count: u64, weight: u64) -> Result<(), BuildError> {
        self.item_count = self.item_count.checked_add(1).ok_or(BuildError::Overflow)?;
        self.count = self.count.checked_add(count).ok_or(BuildError::Overflow)?;
        self.subtree_weight = self.subtree_weight.checked_add(weight).ok_or(BuildError::Overflow)?;
        self.last_key.clear();
        self.last_key.extend_from_slice(key);

        Ok(())
    }

    fn finish(&mut self, level: u64) -> Result<Child, BuildError> {
        let mut framing = Vec::new();
        framing.extend_from_slice(&[0xa2, 0x01]);
        uint(&mut framing, level);
        framing.push(0x02);
        major(&mut framing, 4, self.item_count);

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"terrane-node-v1\0");
        hasher.update(&framing);
        hasher.update(&self.items);

        let own_weight = (self.items.len() as u64)
            .checked_add(framing.len() as u64)
            .ok_or(BuildError::Overflow)?;
        let child = Child {
            last_key: self.last_key.clone(),
            digest: *hasher.finalize().as_bytes(),
            count: self.count,
            weight: self.subtree_weight.checked_add(own_weight).ok_or(BuildError::Overflow)?,
        };

        self.items.clear();
        self.item_count = 0;
        self.count = 0;
        self.subtree_weight = 0;
        self.last_key.clear();

        Ok(child)
    }
}

/// Constructs canonical nodes and measures the draft boundary procedure.
///
/// # Errors
/// Returns an error for empty inputs, integer overflow, or excessive depth.
pub(super) fn build(fixture: &Fixture, batch: usize) -> Result<Measurement, BuildError> {
    if fixture.entries == 0 || batch == 0 {
        return Err(BuildError::EmptyInput);
    }

    let mut node = Node::default();
    let mut report = LevelReport::default();
    let mut children = Vec::new();
    let mut canonical = Vec::new();

    for start in (0..fixture.entries).step_by(batch) {
        for ordinal in start..fixture.entries.min(start + batch) {
            let key = fixture.key(ordinal);
            let shared = key.iter().zip(&node.last_key).take_while(|(a, b)| a == b).count();
            canonical.clear();
            leaf_item(&mut canonical, &key, 0);
            leaf_item(&mut node.items, &key[shared..], shared as u64);
            node.push(&key, 1, 0)?;

            let size = node.items.len() as u64;
            if closes_node(size, &canonical) {
                report.record(size, size >= MAX_NODE, true)?;
                children.push(node.finish(0)?);
            }
        }
    }

    if node.item_count != 0 {
        report.record(node.items.len() as u64, false, false)?;
        children.push(node.finish(0)?);
    }

    let mut levels = vec![report];
    while children.len() > 1 {
        if levels.len() >= 16 {
            return Err(BuildError::Depth);
        }

        let level = levels.len() as u64;
        let mut parents = Vec::new();
        let mut report = LevelReport::default();
        for child in children {
            canonical.clear();
            child_item(&mut canonical, &child);
            node.items.extend_from_slice(&canonical);
            node.push(&child.last_key, child.count, child.weight)?;

            let size = node.items.len() as u64;
            if closes_node(size, &canonical) {
                report.record(size, size >= MAX_NODE, true)?;
                parents.push(node.finish(level)?);
            }
        }

        if node.item_count != 0 {
            report.record(node.items.len() as u64, false, false)?;
            parents.push(node.finish(level)?);
        }

        levels.push(report);
        children = parents;
    }

    let root = children.first().ok_or(BuildError::EmptyInput)?.digest;
    Ok(Measurement { root, levels })
}

fn leaf_item(bytes: &mut Vec<u8>, key_suffix: &[u8], shared: u64) {
    bytes.push(0x83);
    bstr(bytes, key_suffix);
    uint(bytes, shared);
    bytes.extend_from_slice(&[0xa4, 0x01, 0x01, 0x02, 0x19, 0x01, 0xa4, 0x03, 0x0f, 0x04, 0x82, 0x00]);
    bstr(bytes, &INLINE_CHUNK);
}

fn child_item(bytes: &mut Vec<u8>, child: &Child) {
    bytes.push(0x84);
    bstr(bytes, &child.last_key);
    bstr(bytes, &child.digest);
    uint(bytes, child.count);
    uint(bytes, child.weight);
}

fn bstr(bytes: &mut Vec<u8>, value: &[u8]) {
    major(bytes, 2, value.len() as u64);
    bytes.extend_from_slice(value);
}

fn uint(bytes: &mut Vec<u8>, value: u64) {
    major(bytes, 0, value);
}

fn major(bytes: &mut Vec<u8>, major_type: u8, value: u64) {
    let prefix = major_type << 5;
    match value {
        0..=23 => bytes.push(prefix | value as u8),
        24..=255 => bytes.extend_from_slice(&[prefix | 24, value as u8]),
        256..=65_535 => {
            bytes.push(prefix | 25);
            bytes.extend_from_slice(&(value as u16).to_be_bytes());
        }
        65_536..=4_294_967_295 => {
            bytes.push(prefix | 26);
            bytes.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            bytes.push(prefix | 27);
            bytes.extend_from_slice(&value.to_be_bytes());
        }
    }
}

/// Renders identities as lowercase hexadecimal for the measurement artifact.
pub(super) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 15)]));
    }

    encoded
}
    /// Generates keys independently of node construction.
    ///
    /// # Errors
    /// Returns an error if digest allocation fails or generated keys collide.
