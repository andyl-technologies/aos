//! Candidate-C heap-image snapshot format (RFC-0007 doc 31 §1, stage 1).
//!
//! A heap image is the used bytes of one serial permanent-lane reservation
//! ([`SharedFlatStoreArena`]) plus the metadata needed to remap it: the
//! reservation's domain, its capacity, and the two used-lane lengths. Reloading
//! is address-free — the bytes are copied to the same offsets in a fresh mapping
//! and the *original domain* is re-registered against the new base — so every
//! Candidate-C `(domain, index)` word in the image resolves unchanged with no
//! per-pointer rebase pass (doc 31 §3.3 end state).
//!
//! This stage-1 layer proves that round-trip in isolation over a fully-forced,
//! thunk-free value graph. It does **not** yet serialize the out-of-arena
//! residuals (the global symbol table, string contexts, the module table) or
//! collapse thunk cells — those are stage 2+ (doc 31 §1.4, §3.2). In-process the
//! symbol table is shared, so a same-process round trip needs none of them.
//!
//! # Wire format (little-endian)
//!
//! ```text
//! heap-image v6:
//!   magic:        8 bytes  = IMAGE_MAGIC ("AOSNIXH1")
//!   version:      u32      = IMAGE_VERSION
//!   domain:       u32      = the reservation's 23-bit Candidate-C domain
//!   capacity:     u64      = the reservation's virtual size in bytes
//!   old_base:     u64      = the reservation's mapped base at capture time
//!   low_len:      u64      = permanent (upward) used-lane byte length
//!   high_len:     u64      = rewindable (downward) used-lane byte length
//!   reloc_count:  u64      = number of relocation-table entries
//!   list_count:   u64      = number of list-payload segments
//!   ctx_count:    u64      = number of context-payload segments
//!   primop_count: u64      = number of primop-payload segments
//!   frame_count:  u64      = number of env-frame-table segments
//!   closure_count: u64     = number of closure-payload segments
//!   attrs_count:  u64      = number of owned-attrs payload segments
//!   string_count: u64      = number of owned-string payload segments
//!   low:          low_len bytes   (the permanent lane, offset 0)
//!   high:         high_len bytes  (the rewindable lane, ending at `capacity`)
//!   relocs:       reloc_count * (index:u32 | kind:u8)
//!   lists:        list_count * (index:u32 | byte_len:u64 | byte_len bytes)
//!   contexts:     ctx_count  * (index:u32 | byte_len:u64 | byte_len bytes)
//!   primops:      primop_count * (index:u32 | byte_len:u64 | byte_len bytes)
//!   frames:       frame_count  * (index:u32 | byte_len:u64 | byte_len bytes)
//!   closures:     closure_count * (index:u32 | byte_len:u64 | byte_len bytes)
//!   attrs:        attrs_count * (index:u32 | byte_len:u64 | byte_len bytes)
//!   strings:      string_count * (index:u32 | byte_len:u64 | byte_len bytes)
//!   digest:       u64      = xxh3-64 of every preceding byte (integrity guard)
//! ```
//!
//! The relocation table names compound flat objects (strings, paths, attrsets)
//! whose interior witness pointers restore must rebase. The list-payload segments
//! carry each flat list's out-of-arena element words (an owned `Vec<Value>` that
//! the dumped arena bytes do not capture); the context-payload segments carry a
//! context-bearing string's out-of-arena `Arc`-backed dependency set, keyed by
//! that string's relocation index; the primop-payload segments carry a captured
//! builtin closure as a registry reference plus its applied arguments, keyed by
//! its flat-closure arena index. All are filled by the `EvalHeap`-level capture;
//! their bytes are opaque to this value-agnostic layer.

use xxhash_rust::xxh3::xxh3_64;

use thiserror::Error;

use super::flat::SharedFlatStoreArena;
use super::reservation::{ArenaDomainId, ReservedArena};
use super::reservation_registry::reservation_base;

/// Magic tag at the start of every serialized heap image (`"AOSNIXH1"`).
pub const IMAGE_MAGIC: [u8; 8] = *b"AOSNIXH1";

/// The heap-image wire-format version. Bumped on any layout change so a stale
/// image is a clean, loud miss rather than a silent misparse. v2 added
/// `old_base` and the relocation table; v3 added the list-payload segments; v4
/// added the context-payload segments; v5 added the primop-payload segments that
/// carry captured builtin closures as registry references (RFC-0007 doc 31 §1
/// stage B / decision 6, step-2 primop capture); v6 added the env-frame-table
/// segments that carry the closure serializer's deduplicated captured
/// environment frames (doc 31 §1 step-3 increment 2); v7 adds the
/// closure-payload segments that carry captured lambdas and suspended thunks
/// as content-keyed code references plus frame-table environment references
/// (step-3 increment 3); v8 adds the owned-attrs and owned-string payload
/// segments that carry over-threshold attrsets' owned entry/permutation
/// arrays and over-threshold strings' owned byte buffers, which live outside
/// the reservation and would otherwise restore dangling (step-3 increment 5).
pub const IMAGE_VERSION: u32 = 8;

/// Byte length of the fixed image header preceding the lane, relocation, and
/// index-keyed payload bytes.
///
/// `magic(8) | version(4) | domain(4) | capacity(8) | old_base(8) | low_len(8) |
/// high_len(8) | reloc_count(8) | list_count(8) | ctx_count(8) | primop_count(8) |
/// frame_count(8) | closure_count(8) | attrs_count(8) | string_count(8)`.
const HEADER_LEN: usize = 8 + 4 + 4 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8;

/// Wire size of one [`RelocationEntry`] (`index(4) | kind(1)`).
const RELOCATION_ENTRY_LEN: usize = 5;

/// Wire size of an index-keyed payload segment's fixed prefix
/// (`index(4) | byte_len(8)`), preceding its variable-length opaque bytes. Shared
/// by the list-payload, context-payload, and primop-payload segments.
const INDEXED_PAYLOAD_PREFIX_LEN: usize = 12;

/// One compound flat object whose interior witness pointers must be rebased on
/// restore (RFC-0007 doc 31 §1 decision 6).
///
/// The object's run bytes are already in the dumped lanes; only its
/// `FlatBytes`/`FlatSlice` pointer words are stale after a remap. Restore
/// resolves the object at `new_base + index` and shifts each witness by
/// `new_base − old_base`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelocationEntry {
    /// The object's byte offset from the reservation base.
    pub index: u32,
    /// The object's [`FlatObjectKind`](super::flat::FlatObjectKind) discriminant,
    /// naming which store resolves it on restore.
    pub kind: u8,
}

/// One flat list's out-of-arena element words (RFC-0007 doc 31 §1 list increment).
///
/// A flat list object's arena bytes hold only an owned `Vec<Value>` header
/// (pointer, length, capacity) whose backing buffer lives outside the
/// reservation, so the dumped lanes do not carry the elements. Capture copies the
/// element words here as opaque little-endian bytes; restore rebuilds the buffer,
/// overwrites the stale header, and registers the object so its rebuilt `Vec`
/// drops exactly once.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListPayload {
    /// The list object's byte offset from the reservation base (its header's
    /// arena index), naming which restored object receives the rebuilt buffer.
    pub index: u32,
    /// The element words as contiguous little-endian bytes; length is a multiple
    /// of the value word size. Opaque to this value-agnostic layer.
    pub element_bytes: Vec<u8>,
}

/// One context-bearing string's out-of-arena dependency set (RFC-0007 doc 31 §1
/// stage-2 context collapse).
///
/// A flat string object's arena bytes hold an `Arc`-backed [`StringContext`]
/// whose element storage lives outside the reservation and is freed when the
/// source heap drops, so the dumped lanes cannot carry it. Capture serializes the
/// context elements here as opaque bytes keyed by the string's relocation index;
/// restore rebuilds the context and re-installs it on the restored string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextPayload {
    /// The context-bearing string object's arena index — the same index as its
    /// relocation entry, naming which restored string receives the rebuilt
    /// context.
    pub index: u32,
    /// The encoded context elements as opaque bytes. The encoding is owned by the
    /// `EvalHeap`-level capture (kind, path, and output are Nix-dialect concepts);
    /// this value-agnostic layer only carries the bytes.
    pub context_bytes: Vec<u8>,
}

/// One captured builtin (primop) closure (RFC-0007 doc 31 §1 step-2 primop
/// capture).
///
/// A flat primop object's arena bytes hold an owned `Vec` of applied arguments
/// and a builtin registry declaration, neither of which survives a remap or the
/// source heap's drop. Capture serializes the builtin as a stable registry
/// reference (its name) plus the applied argument words; restore re-resolves the
/// builtin against the registry — refusing on a version or name mismatch — and
/// rebuilds the closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrimopPayload {
    /// The primop object's flat-closure arena index — which restored object
    /// receives the rebuilt closure.
    pub index: u32,
    /// The encoded builtin reference and applied arguments as opaque bytes. The
    /// encoding is owned by the `EvalHeap`-level capture; this value-agnostic
    /// layer only carries the bytes.
    pub primop_bytes: Vec<u8>,
}

/// One deduplicated captured-environment frame (RFC-0007 doc 31 §1 step-3
/// increment 2, the env-frame DAG serializer).
///
/// A closure's captured environment frames are `Arc`-shared slot arrays
/// allocated outside the reservation, so the dumped lanes do not carry them.
/// The `EvalHeap`-level capture deduplicates frames by `Arc` identity into a
/// dense, parent-before-child table; each entry's bytes carry the frame's
/// parent link and its address-free slot value words. Restore rebuilds the
/// shared `Arc` frame graph bottom-up and closure payloads reference frames by
/// table index.
///
/// `EvalEnv` is an evaluator concept; this value-agnostic layer only carries
/// the bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FramePayload {
    /// The frame's dense table index (its frame id). Unlike the other
    /// index-keyed segments this is *not* an arena byte offset: frames live
    /// outside the reservation and exist only in this table.
    pub index: u32,
    /// The encoded parent link and slot words as opaque bytes. The encoding is
    /// owned by the `EvalHeap`-level capture.
    pub frame_bytes: Vec<u8>,
}

/// One captured worker closure — a lambda or a suspended thunk (RFC-0007 doc 31
/// §1 step-3 increment 3, the closure serializer).
///
/// A flat closure object's arena bytes hold per-process module ids and
/// `Arc`-shared captured environments, neither of which survives a remap or the
/// source heap's drop. Capture serializes the closure as a content-keyed code
/// reference (module source fingerprint plus IR node ids, refuse-on-drift) and
/// environment references into the deduplicated frame table; restore
/// re-resolves the code against a live module table and rebuilds the closure
/// over the shared frame graph. The encoding is owned by the `EvalHeap`-level
/// capture; this value-agnostic layer only carries the bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosurePayload {
    /// The closure object's flat-closure arena index — which restored object
    /// receives the rebuilt closure.
    pub index: u32,
    /// The encoded code reference, force-storage metadata, and environment
    /// references as opaque bytes.
    pub closure_bytes: Vec<u8>,
}

/// One over-threshold attrset's owned entry and permutation arrays (RFC-0007
/// doc 31 §1 step-3 increment 5).
///
/// Attrsets above the flat-inline threshold keep their moved owned `Vec`
/// arrays behind the arena payload (a measured churn-workload decision), so
/// the dumped lanes carry only dangling `Vec` headers. Capture serializes the
/// entries and both order permutations here; restore rebuilds owned storage
/// and overwrites the stale payload. The encoding is owned by the
/// `EvalHeap`-level capture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedAttrsPayload {
    /// The attrs object's arena index.
    pub index: u32,
    /// The encoded entries and permutations as opaque bytes.
    pub attrs_bytes: Vec<u8>,
}

/// One over-threshold string's owned byte buffer and context (RFC-0007 doc 31
/// §1 step-3 increment 5).
///
/// Strings above the flat-inline byte threshold keep their moved owned
/// `Vec<u8>` behind the arena payload, so the dumped lanes carry only a
/// dangling `Vec` header. Capture serializes the bytes (and the string's
/// context, which for owned strings rides here instead of the
/// context-payload segment); restore rebuilds the owned string and overwrites
/// the stale payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedStringPayload {
    /// The string or path object's arena index.
    pub index: u32,
    /// The encoded bytes and context as opaque bytes.
    pub string_bytes: Vec<u8>,
}

/// A captured Candidate-C reservation heap image.
///
/// Holds the reservation identity, its two used-lane byte ranges, the base it
/// was mapped at when captured, and the relocation table of compound objects to
/// rebase on restore. Serialize with [`HeapImage::to_bytes`] and reload with
/// [`HeapImage::from_bytes`] + [`restore_reservation`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeapImage {
    /// The reservation's 23-bit Candidate-C domain, re-registered on restore so
    /// dumped words resolve unchanged.
    pub domain: u32,
    /// The reservation's virtual capacity in bytes (the restore mapping size).
    pub capacity: u64,
    /// The reservation's mapped base address when captured. The restore rebase
    /// delta is `new_base − old_base`.
    pub old_base: u64,
    /// The permanent, upward-growing lane bytes, at offset zero.
    pub low: Vec<u8>,
    /// The rewindable, downward-growing lane bytes, ending at `capacity`.
    pub high: Vec<u8>,
    /// The compound objects whose interior witnesses restore must rebase; filled
    /// by the `EvalHeap`-level capture that enumerates the flat stores.
    pub relocations: Vec<RelocationEntry>,
    /// Each flat list's out-of-arena element words; filled by the `EvalHeap`-level
    /// capture and re-attached to the restored list objects on load.
    pub list_payloads: Vec<ListPayload>,
    /// Each context-bearing string's out-of-arena dependency set; filled by the
    /// `EvalHeap`-level capture and re-installed on the restored strings on load.
    pub context_payloads: Vec<ContextPayload>,
    /// Each captured builtin (primop) closure as a registry reference plus its
    /// applied arguments; filled by the `EvalHeap`-level capture and rebuilt on
    /// load against the builtin registry.
    pub primop_payloads: Vec<PrimopPayload>,
    /// The deduplicated captured-environment frame table, keyed by dense frame
    /// id; filled by the `EvalHeap`-level closure capture and rebuilt into the
    /// shared `Arc` frame graph on load.
    pub frame_payloads: Vec<FramePayload>,
    /// Each captured lambda and suspended thunk as a content-keyed code
    /// reference plus environment references into the frame table; filled by
    /// the `EvalHeap`-level closure capture and rebuilt on load against a
    /// code-identity resolver.
    pub closure_payloads: Vec<ClosurePayload>,
    /// Each over-threshold attrset's owned entry/permutation arrays; filled by
    /// the `EvalHeap`-level capture and rebuilt as owned storage on load.
    pub attrs_payloads: Vec<OwnedAttrsPayload>,
    /// Each over-threshold string's owned byte buffer (plus context); filled
    /// by the `EvalHeap`-level capture and rebuilt as an owned string on load.
    pub string_payloads: Vec<OwnedStringPayload>,
}

impl HeapImage {
    /// Serializes the image to its little-endian wire form with a trailing
    /// integrity digest.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let reloc_bytes = self.relocations.len() * RELOCATION_ENTRY_LEN;
        let indexed_bytes = |lengths: &[usize]| -> usize {
            lengths
                .iter()
                .map(|len| INDEXED_PAYLOAD_PREFIX_LEN + len)
                .sum()
        };
        let list_bytes = indexed_bytes(
            &self
                .list_payloads
                .iter()
                .map(|p| p.element_bytes.len())
                .collect::<Vec<_>>(),
        );
        let context_bytes = indexed_bytes(
            &self
                .context_payloads
                .iter()
                .map(|p| p.context_bytes.len())
                .collect::<Vec<_>>(),
        );
        let primop_bytes = indexed_bytes(
            &self
                .primop_payloads
                .iter()
                .map(|p| p.primop_bytes.len())
                .collect::<Vec<_>>(),
        );
        let frame_bytes = indexed_bytes(
            &self
                .frame_payloads
                .iter()
                .map(|p| p.frame_bytes.len())
                .collect::<Vec<_>>(),
        );
        let closure_bytes = indexed_bytes(
            &self
                .closure_payloads
                .iter()
                .map(|p| p.closure_bytes.len())
                .collect::<Vec<_>>(),
        );
        let attrs_bytes = indexed_bytes(
            &self
                .attrs_payloads
                .iter()
                .map(|p| p.attrs_bytes.len())
                .collect::<Vec<_>>(),
        );
        let string_bytes = indexed_bytes(
            &self
                .string_payloads
                .iter()
                .map(|p| p.string_bytes.len())
                .collect::<Vec<_>>(),
        );
        let mut out = Vec::with_capacity(
            HEADER_LEN
                + self.low.len()
                + self.high.len()
                + reloc_bytes
                + list_bytes
                + context_bytes
                + primop_bytes
                + frame_bytes
                + closure_bytes
                + attrs_bytes
                + string_bytes
                + 8,
        );
        out.extend_from_slice(&IMAGE_MAGIC);
        out.extend_from_slice(&IMAGE_VERSION.to_le_bytes());
        out.extend_from_slice(&self.domain.to_le_bytes());
        out.extend_from_slice(&self.capacity.to_le_bytes());
        out.extend_from_slice(&self.old_base.to_le_bytes());
        out.extend_from_slice(&(self.low.len() as u64).to_le_bytes());
        out.extend_from_slice(&(self.high.len() as u64).to_le_bytes());
        out.extend_from_slice(&(self.relocations.len() as u64).to_le_bytes());
        out.extend_from_slice(&(self.list_payloads.len() as u64).to_le_bytes());
        out.extend_from_slice(&(self.context_payloads.len() as u64).to_le_bytes());
        out.extend_from_slice(&(self.primop_payloads.len() as u64).to_le_bytes());
        out.extend_from_slice(&(self.frame_payloads.len() as u64).to_le_bytes());
        out.extend_from_slice(&(self.closure_payloads.len() as u64).to_le_bytes());
        out.extend_from_slice(&(self.attrs_payloads.len() as u64).to_le_bytes());
        out.extend_from_slice(&(self.string_payloads.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.low);
        out.extend_from_slice(&self.high);
        for entry in &self.relocations {
            out.extend_from_slice(&entry.index.to_le_bytes());
            out.push(entry.kind);
        }
        for payload in &self.list_payloads {
            write_indexed_payload(&mut out, payload.index, &payload.element_bytes);
        }
        for payload in &self.context_payloads {
            write_indexed_payload(&mut out, payload.index, &payload.context_bytes);
        }
        for payload in &self.primop_payloads {
            write_indexed_payload(&mut out, payload.index, &payload.primop_bytes);
        }
        for payload in &self.frame_payloads {
            write_indexed_payload(&mut out, payload.index, &payload.frame_bytes);
        }
        for payload in &self.closure_payloads {
            write_indexed_payload(&mut out, payload.index, &payload.closure_bytes);
        }
        for payload in &self.attrs_payloads {
            write_indexed_payload(&mut out, payload.index, &payload.attrs_bytes);
        }
        for payload in &self.string_payloads {
            write_indexed_payload(&mut out, payload.index, &payload.string_bytes);
        }
        let digest = xxh3_64(&out);
        out.extend_from_slice(&digest.to_le_bytes());
        out
    }

    /// Parses and integrity-checks an image from its wire form.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::Truncated`] when `bytes` is shorter than the
    /// declared layout, [`SnapshotError::BadMagic`] or
    /// [`SnapshotError::UnsupportedVersion`] on a header mismatch, and
    /// [`SnapshotError::IntegrityMismatch`] when the trailing digest does not
    /// match the recomputed one.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SnapshotError> {
        if bytes.len() < HEADER_LEN + 8 {
            return Err(SnapshotError::Truncated {
                needed: HEADER_LEN + 8,
                got: bytes.len(),
            });
        }
        if bytes[0..8] != IMAGE_MAGIC {
            return Err(SnapshotError::BadMagic);
        }
        let version = u32::from_le_bytes(read4(bytes, 8));
        if version != IMAGE_VERSION {
            return Err(SnapshotError::UnsupportedVersion { version });
        }
        let domain = u32::from_le_bytes(read4(bytes, 12));
        let capacity = u64::from_le_bytes(read8(bytes, 16));
        let old_base = u64::from_le_bytes(read8(bytes, 24));
        let low_len = u64::from_le_bytes(read8(bytes, 32)) as usize;
        let high_len = u64::from_le_bytes(read8(bytes, 40)) as usize;
        let reloc_count = u64::from_le_bytes(read8(bytes, 48)) as usize;
        let list_count = u64::from_le_bytes(read8(bytes, 56)) as usize;
        let context_count = u64::from_le_bytes(read8(bytes, 64)) as usize;
        let primop_count = u64::from_le_bytes(read8(bytes, 72)) as usize;
        let frame_count = u64::from_le_bytes(read8(bytes, 80)) as usize;
        let closure_count = u64::from_le_bytes(read8(bytes, 88)) as usize;
        let attrs_count = u64::from_le_bytes(read8(bytes, 96)) as usize;
        let string_count = u64::from_le_bytes(read8(bytes, 104)) as usize;

        // Bound the fixed-width prefix (lanes + relocation table + each indexed
        // segment's fixed header) before parsing; each segment's variable bytes
        // are length-checked as the cursor advances.
        let lanes_start = HEADER_LEN;
        let fixed_end = [
            low_len,
            high_len,
            reloc_count * RELOCATION_ENTRY_LEN,
            (list_count
                + context_count
                + primop_count
                + frame_count
                + closure_count
                + attrs_count
                + string_count)
                * INDEXED_PAYLOAD_PREFIX_LEN,
        ]
        .iter()
        .try_fold(lanes_start, |acc, len| acc.checked_add(*len))
        .ok_or(SnapshotError::Truncated {
            needed: usize::MAX,
            got: bytes.len(),
        })?;
        if bytes.len() < fixed_end + 8 {
            return Err(SnapshotError::Truncated {
                needed: fixed_end + 8,
                got: bytes.len(),
            });
        }

        let low = bytes[lanes_start..lanes_start + low_len].to_vec();
        let high = bytes[lanes_start + low_len..lanes_start + low_len + high_len].to_vec();
        let mut relocations = Vec::with_capacity(reloc_count);
        let mut cursor = lanes_start + low_len + high_len;
        for _ in 0..reloc_count {
            relocations.push(RelocationEntry {
                index: u32::from_le_bytes(read4(bytes, cursor)),
                kind: bytes[cursor + 4],
            });
            cursor += RELOCATION_ENTRY_LEN;
        }

        let mut list_payloads = Vec::with_capacity(list_count);
        for _ in 0..list_count {
            let (index, segment) = read_indexed_payload(bytes, &mut cursor)?;
            list_payloads.push(ListPayload {
                index,
                element_bytes: segment,
            });
        }

        let mut context_payloads = Vec::with_capacity(context_count);
        for _ in 0..context_count {
            let (index, segment) = read_indexed_payload(bytes, &mut cursor)?;
            context_payloads.push(ContextPayload {
                index,
                context_bytes: segment,
            });
        }

        let mut primop_payloads = Vec::with_capacity(primop_count);
        for _ in 0..primop_count {
            let (index, segment) = read_indexed_payload(bytes, &mut cursor)?;
            primop_payloads.push(PrimopPayload {
                index,
                primop_bytes: segment,
            });
        }

        let mut frame_payloads = Vec::with_capacity(frame_count);
        for _ in 0..frame_count {
            let (index, segment) = read_indexed_payload(bytes, &mut cursor)?;
            frame_payloads.push(FramePayload {
                index,
                frame_bytes: segment,
            });
        }

        let mut closure_payloads = Vec::with_capacity(closure_count);
        for _ in 0..closure_count {
            let (index, segment) = read_indexed_payload(bytes, &mut cursor)?;
            closure_payloads.push(ClosurePayload {
                index,
                closure_bytes: segment,
            });
        }

        let mut attrs_payloads = Vec::with_capacity(attrs_count);
        for _ in 0..attrs_count {
            let (index, segment) = read_indexed_payload(bytes, &mut cursor)?;
            attrs_payloads.push(OwnedAttrsPayload {
                index,
                attrs_bytes: segment,
            });
        }

        let mut string_payloads = Vec::with_capacity(string_count);
        for _ in 0..string_count {
            let (index, segment) = read_indexed_payload(bytes, &mut cursor)?;
            string_payloads.push(OwnedStringPayload {
                index,
                string_bytes: segment,
            });
        }

        let digest_start = cursor;
        let expected = xxh3_64(&bytes[..digest_start]);
        let actual = u64::from_le_bytes(read8(bytes, digest_start));
        if expected != actual {
            return Err(SnapshotError::IntegrityMismatch { expected, actual });
        }

        Ok(Self {
            domain,
            capacity,
            old_base,
            low,
            high,
            relocations,
            list_payloads,
            context_payloads,
            primop_payloads,
            frame_payloads,
            closure_payloads,
            attrs_payloads,
            string_payloads,
        })
    }
}

/// Appends one index-keyed payload segment (`index(4) | byte_len(8) | bytes`).
fn write_indexed_payload(out: &mut Vec<u8>, index: u32, bytes: &[u8]) {
    out.extend_from_slice(&index.to_le_bytes());
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Reads one index-keyed payload segment at `*cursor`, advancing it past the
/// segment, and returns its index and a copy of its variable bytes.
///
/// # Errors
///
/// Returns [`SnapshotError::Truncated`] when the declared segment length would
/// run past the buffer's trailing digest.
fn read_indexed_payload(bytes: &[u8], cursor: &mut usize) -> Result<(u32, Vec<u8>), SnapshotError> {
    let index = u32::from_le_bytes(read4(bytes, *cursor));
    let byte_len = u64::from_le_bytes(read8(bytes, *cursor + 4)) as usize;
    let start = *cursor + INDEXED_PAYLOAD_PREFIX_LEN;
    let end = start
        .checked_add(byte_len)
        .ok_or(SnapshotError::Truncated {
            needed: usize::MAX,
            got: bytes.len(),
        })?;
    // The variable segment must fit before the trailing digest.
    if bytes.len() < end + 8 {
        return Err(SnapshotError::Truncated {
            needed: end + 8,
            got: bytes.len(),
        });
    }
    *cursor = end;
    Ok((index, bytes[start..end].to_vec()))
}

/// Captures a heap image of a reservation-backed serial flat arena.
///
/// Records the reservation's current base as [`HeapImage::old_base`] and leaves
/// the relocation, list, context, and primop segments empty; the `EvalHeap`-level
/// capture enumerates the flat stores and fills them before serializing.
///
/// # Errors
///
/// Returns [`SnapshotError::NotReservationBacked`] when `arena` uses the chunked
/// compatibility backend, which is not address-free and cannot be snapshotted.
pub fn capture_reservation(arena: &SharedFlatStoreArena) -> Result<HeapImage, SnapshotError> {
    let (domain, capacity, low, high) = arena
        .capture_reservation_image()
        .ok_or(SnapshotError::NotReservationBacked)?;
    let old_base = reservation_base(domain).ok_or(SnapshotError::NotReservationBacked)? as u64;
    Ok(HeapImage {
        domain: domain.raw(),
        capacity: capacity as u64,
        old_base,
        low,
        high,
        relocations: Vec::new(),
        list_payloads: Vec::new(),
        context_payloads: Vec::new(),
        primop_payloads: Vec::new(),
        frame_payloads: Vec::new(),
        closure_payloads: Vec::new(),
        attrs_payloads: Vec::new(),
        string_payloads: Vec::new(),
    })
}

/// Restores a heap image into a fresh reservation-backed serial flat arena.
///
/// Maps a new reservation of the image's capacity, copies the used lanes to
/// their original offsets, and re-registers the image's domain against the new
/// base so every dumped `(domain, index)` word resolves unchanged.
///
/// # Errors
///
/// Returns [`SnapshotError::InvalidDomain`] when the stored domain is out of the
/// valid Candidate-C range, [`SnapshotError::DomainAlreadyLive`] when that domain
/// is still registered (the source reservation must be dropped first — see the
/// domain-preservation invariant in [`crate::heap::reservation::image`]), or
/// [`SnapshotError::Reservation`] when the mapping or registration fails.
pub fn restore_reservation(image: &HeapImage) -> Result<SharedFlatStoreArena, SnapshotError> {
    let domain = ArenaDomainId::from_raw(image.domain)
        .ok_or(SnapshotError::InvalidDomain { raw: image.domain })?;
    if reservation_base(domain).is_some() {
        return Err(SnapshotError::DomainAlreadyLive {
            domain: image.domain,
        });
    }
    let arena = ReservedArena::from_reloaded_image(
        domain,
        image.capacity as usize,
        &image.low,
        &image.high,
    )?;
    Ok(SharedFlatStoreArena::from_reserved(arena))
}

/// Reads a fixed 4-byte little-endian field at `offset`.
///
/// The caller must have bounds-checked that `offset + 4 <= bytes.len()`.
fn read4(bytes: &[u8], offset: usize) -> [u8; 4] {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[offset..offset + 4]);
    buf
}

/// Reads a fixed 8-byte little-endian field at `offset`.
///
/// The caller must have bounds-checked that `offset + 8 <= bytes.len()`.
fn read8(bytes: &[u8], offset: usize) -> [u8; 8] {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[offset..offset + 8]);
    buf
}

/// A heap-image capture, parse, or restore failure.
#[derive(Debug, Error)]
pub enum SnapshotError {
    /// The arena uses the chunked compatibility backend, which is not
    /// address-free and cannot be snapshotted.
    #[error("heap image requires a Candidate-C reservation-backed arena")]
    NotReservationBacked,
    /// The serialized image was shorter than its declared layout.
    #[error("heap image is truncated: need {needed} bytes, got {got}")]
    Truncated {
        /// The byte length the declared layout requires.
        needed: usize,
        /// The byte length actually supplied.
        got: usize,
    },
    /// The image did not begin with [`IMAGE_MAGIC`].
    #[error("heap image magic tag is invalid")]
    BadMagic,
    /// The image's format version is not understood by this build.
    #[error("heap image version {version} is unsupported (expected {IMAGE_VERSION})")]
    UnsupportedVersion {
        /// The rejected on-disk version.
        version: u32,
    },
    /// The trailing digest did not match the recomputed one.
    #[error("heap image integrity digest mismatch: expected {expected:#018x}, got {actual:#018x}")]
    IntegrityMismatch {
        /// The digest recomputed over the payload.
        expected: u64,
        /// The digest stored in the image trailer.
        actual: u64,
    },
    /// The stored domain was outside the valid Candidate-C domain range.
    #[error("heap image domain {raw} is not a valid Candidate-C reservation domain")]
    InvalidDomain {
        /// The rejected raw domain value.
        raw: u32,
    },
    /// The stored domain is still registered; the source reservation must be
    /// dropped before its image can be reloaded (domain-preservation invariant).
    #[error("heap image domain {domain} is still live; drop the source reservation before restore")]
    DomainAlreadyLive {
        /// The still-registered domain.
        domain: u32,
    },
    /// The restore mapping or registration failed.
    #[error(transparent)]
    Reservation(#[from] super::reservation::ReservedArenaError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::reservation_registry::reservation_containing_address;
    use crate::value::compressed::CandidateCScalarStore;

    /// Two wide integers that do not fit the inline `i32` payload, so each boxes
    /// a hash-consed cell in the reservation arena — giving the round trip real
    /// `(domain, index)` heap words to resolve.
    const WIDE_A: i64 = 1_000_000_000_000;
    const WIDE_B: i64 = -42_000_000_000;

    #[test]
    fn reservation_image_round_trip_is_address_free_and_value_equal() {
        let arena = SharedFlatStoreArena::new();
        if !arena.uses_reservation() {
            // The chunked fallback is not snapshottable; nothing to prove here.
            return;
        }

        let mut scalars = CandidateCScalarStore::new(arena.clone());
        let word_a = scalars.encode_int(WIDE_A).expect("boxes a wide integer");
        let word_b = scalars.encode_int(WIDE_B).expect("boxes a wide integer");
        let index_a = word_a.arena_index().expect("boxed word carries an index");
        let domain = arena.arena_domain_id().expect("reservation-backed arena");

        let image = capture_reservation(&arena).expect("captures the reservation");
        let bytes = image.to_bytes();

        // Drop the source reservation so its domain is free to re-register.
        drop(scalars);
        drop(arena);
        assert!(
            reservation_base(domain).is_none(),
            "dropping the source reservation withdraws its domain"
        );

        let reloaded = HeapImage::from_bytes(&bytes).expect("parses the serialized image");
        let restored = restore_reservation(&reloaded).expect("restores the reservation");
        assert_eq!(
            restored.arena_domain_id(),
            Some(domain),
            "restore preserves the original domain"
        );

        // Address-free resolution: the dumped word is untouched, and the
        // registry now rebinds its domain to the fresh base, so `domain + index`
        // names the reloaded mapping with no per-word rewrite.
        let base = reservation_base(domain).expect("restored domain is registered");
        assert_eq!(
            word_a.arena_domain(),
            Some(domain),
            "domain word is unchanged"
        );
        assert_eq!(
            word_a.arena_index(),
            Some(index_a),
            "index word is unchanged"
        );
        assert_eq!(
            reservation_containing_address(base + index_a.raw() as usize),
            Some((domain, base)),
            "the restored mapping owns the resolved address"
        );

        // Byte-identical arena round trip: re-capturing the restored arena
        // reproduces the exact used-lane bytes and metadata.
        let recaptured = capture_reservation(&restored).expect("re-captures the restored arena");
        assert_eq!(recaptured.low, image.low);
        assert_eq!(recaptured.high, image.high);
        assert_eq!(recaptured.domain, image.domain);
        assert_eq!(recaptured.capacity, image.capacity);

        // End-to-end value equality: a fresh scalar store over the restored
        // reservation decodes both boxed cells to their original integers.
        let mut restored_scalars = CandidateCScalarStore::new(restored.clone());
        restored_scalars.adopt_reloaded_regions();
        assert_eq!(
            restored_scalars.decode_int(word_a).expect("decodes a"),
            WIDE_A
        );
        assert_eq!(
            restored_scalars.decode_int(word_b).expect("decodes b"),
            WIDE_B
        );
    }

    #[test]
    fn from_bytes_rejects_a_corrupted_image() {
        let arena = SharedFlatStoreArena::new();
        if !arena.uses_reservation() {
            return;
        }
        let mut scalars = CandidateCScalarStore::new(arena.clone());
        scalars.encode_int(WIDE_A).expect("boxes a wide integer");
        let image = capture_reservation(&arena).expect("captures the reservation");
        let mut bytes = image.to_bytes();

        // Flip a payload byte; the trailing digest must catch it.
        let mid = HEADER_LEN + image.low.len() / 2;
        bytes[mid] ^= 0xff;
        assert!(matches!(
            HeapImage::from_bytes(&bytes),
            Err(SnapshotError::IntegrityMismatch { .. })
        ));

        // A short buffer is a clean truncation error, not a panic.
        assert!(matches!(
            HeapImage::from_bytes(&bytes[..HEADER_LEN]),
            Err(SnapshotError::Truncated { .. })
        ));
    }

    #[test]
    fn from_bytes_rejects_bad_magic_and_version() {
        let image = HeapImage {
            domain: 1,
            capacity: 0x1000,
            old_base: 0x4000,
            low: vec![1, 2, 3, 4],
            high: Vec::new(),
            relocations: vec![RelocationEntry { index: 8, kind: 4 }],
            list_payloads: vec![ListPayload {
                index: 16,
                element_bytes: vec![9, 10, 11, 12, 13, 14, 15, 16],
            }],
            context_payloads: vec![ContextPayload {
                index: 8,
                context_bytes: vec![1, 2, 3],
            }],
            primop_payloads: vec![PrimopPayload {
                index: 24,
                primop_bytes: vec![7, 6, 5, 4],
            }],
            frame_payloads: vec![FramePayload {
                index: 0,
                frame_bytes: vec![0xff, 0xff, 0xff, 0xff, 1, 0, 0, 0],
            }],
            closure_payloads: vec![ClosurePayload {
                index: 32,
                closure_bytes: vec![9, 8, 7],
            }],
            attrs_payloads: vec![OwnedAttrsPayload {
                index: 48,
                attrs_bytes: vec![1, 2],
            }],
            string_payloads: vec![OwnedStringPayload {
                index: 56,
                string_bytes: vec![3, 4, 5],
            }],
        };
        let good = image.to_bytes();

        let mut bad_magic = good.clone();
        bad_magic[0] ^= 0xff;
        // Recompute the digest so magic is what fails, not integrity.
        fix_digest(&mut bad_magic);
        assert!(matches!(
            HeapImage::from_bytes(&bad_magic),
            Err(SnapshotError::BadMagic)
        ));

        let mut bad_version = good.clone();
        bad_version[8] = 0xff;
        fix_digest(&mut bad_version);
        assert!(matches!(
            HeapImage::from_bytes(&bad_version),
            Err(SnapshotError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn wire_round_trip_preserves_every_payload_segment() {
        let image = HeapImage {
            domain: 3,
            capacity: 0x2000,
            old_base: 0x8000,
            low: vec![1, 2, 3, 4, 5, 6, 7, 8],
            high: vec![9, 10],
            relocations: vec![RelocationEntry { index: 8, kind: 4 }],
            list_payloads: vec![ListPayload {
                index: 16,
                element_bytes: vec![1; 16],
            }],
            context_payloads: vec![ContextPayload {
                index: 8,
                context_bytes: vec![2; 5],
            }],
            primop_payloads: vec![PrimopPayload {
                index: 24,
                primop_bytes: vec![3; 7],
            }],
            frame_payloads: vec![
                FramePayload {
                    index: 0,
                    frame_bytes: vec![4; 12],
                },
                FramePayload {
                    index: 1,
                    frame_bytes: vec![5; 20],
                },
            ],
            closure_payloads: vec![ClosurePayload {
                index: 40,
                closure_bytes: vec![6; 9],
            }],
            attrs_payloads: vec![OwnedAttrsPayload {
                index: 48,
                attrs_bytes: vec![7; 11],
            }],
            string_payloads: vec![OwnedStringPayload {
                index: 56,
                string_bytes: vec![8; 4],
            }],
        };
        let parsed = HeapImage::from_bytes(&image.to_bytes()).expect("wire image parses");
        assert_eq!(parsed, image);
    }

    /// Recomputes the trailing digest so a header-field mutation is exercised in
    /// isolation from the integrity check.
    fn fix_digest(bytes: &mut [u8]) {
        let len = bytes.len();
        let digest = xxh3_64(&bytes[..len - 8]);
        bytes[len - 8..].copy_from_slice(&digest.to_le_bytes());
    }
}
