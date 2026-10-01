//! Encodes the registered version-one root snapshots and resumable state.
//!
//! ```text
//! GcRoots = {0:1, 1:cycle, 2:epoch, 3:time, 4:[roots...]}
//! GcMark = {0:1, 1:cycle, 2:epoch, 3:shard, 4:[sorted hashes], 5:filter}
//! GcState = {0:1, 1:cycle, 2:epoch, 3:phase, 4:time,
//!            5:[checkpoint pointers], 6:[pending], 7:[contexts], 8:[packs],
//!            9:[typed expansion contexts]}
//! ```
//!
//! These records contain untrusted traversal claims. Decoding does not prove root
//! completeness, certificate validity, current lease ownership or deletion permission.

use super::{GcError, MARK_FILTER_BYTES, MarkSet, ParentCutoff, ProofContext, key};
use crate::{
    cbor::{self, Decoder},
    identity::Digest,
    refs::RefName,
};
use alloc::vec::Vec;

/// The retention rule explaining why a commit is a collection root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootReason {
    /// The current value of an ordinary ref.
    Current,
    /// A reflog record within ordinary GC retention.
    ReflogGc,
    /// A committed new value selected by the ref's sequence-count retention.
    ReflogCount,
    /// A historical commit within its TTL.
    ReflogTtl,
    /// A ref or history record covered by a live lease.
    Lease,
    /// A historical record retained indefinitely.
    Forever,
    /// The value of a create-once tag.
    Tag,
    /// The value of an unexpired job ref.
    Job,
    /// Metadata evidence for a root excluded from ordinary content retention.
    RetentionWitness,
}

impl RootReason {
    /// Returns the closed registered reason string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::ReflogGc => "reflog-gc",
            Self::ReflogCount => "reflog-count",
            Self::ReflogTtl => "reflog-ttl",
            Self::Lease => "lease",
            Self::Forever => "forever",
            Self::Tag => "tag",
            Self::Job => "job",
            Self::RetentionWitness => "retention-witness",
        }
    }

    fn decode(value: &str) -> Result<Self, GcError> {
        match value {
            "current" => Ok(Self::Current),
            "reflog-gc" => Ok(Self::ReflogGc),
            "reflog-count" => Ok(Self::ReflogCount),
            "reflog-ttl" => Ok(Self::ReflogTtl),
            "lease" => Ok(Self::Lease),
            "forever" => Ok(Self::Forever),
            "tag" => Ok(Self::Tag),
            "job" => Ok(Self::Job),
            "retention-witness" => Ok(Self::RetentionWitness),
            _ => Err(GcError::Schema),
        }
    }
}

/// One explained root of the immutable collection snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcRoot {
    /// Validated complete ref name.
    pub reference: RefName,
    /// Signed commit identity named by the root.
    pub commit: Digest,
    /// Timestamp, unbounded ancestry, or independently selected roots-only context.
    pub parent_cutoff: ParentCutoff,
    /// Closed rule that made this record reachable.
    pub reason: RootReason,
}

/// An immutable complete root snapshot selected at a collection's start.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcRoots {
    /// Collection cycle owning this snapshot.
    pub cycle: u64,
    /// Collector fencing epoch that wrote the snapshot.
    pub epoch: u64,
    /// Authoritative snapshot time in Unix seconds.
    pub timestamp: u64,
    /// Every selected current, historical, tag, and active-job root.
    pub roots: Vec<GcRoot>,
}

impl GcRoots {
    /// Encodes the exact registered GcRoots map.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        header(&mut bytes, 5, self.cycle, self.epoch);
        field(&mut bytes, 3, self.timestamp);
        cbor::write_uint(&mut bytes, 4);
        cbor::write_array(&mut bytes, self.roots.len());
        for root in &self.roots {
            cbor::write_array(&mut bytes, 4);
            cbor::write_text(&mut bytes, root.reference.as_str());
            cbor::write_bytes(&mut bytes, &root.commit);
            cutoff(&mut bytes, root.parent_cutoff);
            cbor::write_text(&mut bytes, root.reason.as_str());
        }
        bytes
    }

    /// Decodes a version-one snapshot with validated names and retention reasons.
    ///
    /// # Errors
    /// Rejects noncanonical CBOR, unknown schema/version, invalid names, widths,
    /// null alternatives, reason vocabulary, or trailing data.
    pub fn decode(bytes: &[u8]) -> Result<Self, GcError> {
        let mut decoder = Decoder::new(bytes);
        let (cycle, epoch) = read_header(&mut decoder, 5)?;
        key(&mut decoder, 3)?;
        let timestamp = decoder.uint()?;
        key(&mut decoder, 4)?;
        let count = collection(&mut decoder, 38)?;
        let mut roots = Vec::new();
        for _ in 0..count {
            if decoder.array(4)? != 4 {
                return Err(GcError::Schema);
            }
            let reference =
                RefName::parse(decoder.text(bytes.len())?).map_err(|_| GcError::Schema)?;
            let commit = digest(&mut decoder)?;
            let parent_cutoff = read_cutoff(&mut decoder)?;
            let reason = RootReason::decode(decoder.text(17)?)?;
            roots.push(GcRoot {
                reference,
                commit,
                parent_cutoff,
                reason,
            });
        }
        decoder.finish()?;
        Ok(Self {
            cycle,
            epoch,
            timestamp,
            roots,
        })
    }
}

/// A verified index-shaped mark shard with an exactly reconstructed hint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcMark {
    cycle: u64,
    epoch: u64,
    shard: u8,
    hashes: Vec<Digest>,
    filter: Vec<u8>,
}

impl GcMark {
    /// Constructs an immutable checkpoint from strictly sorted hashes of one shard.
    ///
    /// # Errors
    /// Rejects repeated or unsorted hashes and a digest from another shard.
    pub fn new(cycle: u64, epoch: u64, shard: u8, hashes: Vec<Digest>) -> Result<Self, GcError> {
        validate_hashes(shard, &hashes)?;
        let filter = MarkSet::filter(&hashes);
        Ok(Self {
            cycle,
            epoch,
            shard,
            hashes,
            filter,
        })
    }

    /// Returns the owning cycle.
    pub const fn cycle(&self) -> u64 {
        self.cycle
    }

    /// Returns the writer's fencing epoch.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the digest prefix byte shared by every record.
    pub const fn shard(&self) -> u8 {
        self.shard
    }

    /// Borrows the exact strictly sorted digest set.
    pub fn hashes(&self) -> &[Digest] {
        &self.hashes
    }

    /// Borrows the exactly reconstructed 2,048-byte membership hint.
    pub fn filter(&self) -> &[u8] {
        &self.filter
    }

    /// Performs an exact membership lookup after testing the hint.
    pub fn contains(&self, hash: &Digest) -> bool {
        MarkSet::filter_may_contain(&self.filter, hash) && self.hashes.binary_search(hash).is_ok()
    }

    /// Encodes the registered immutable checkpoint map.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        header(&mut bytes, 6, self.cycle, self.epoch);
        field(&mut bytes, 3, u64::from(self.shard));
        cbor::write_uint(&mut bytes, 4);
        cbor::write_array(&mut bytes, self.hashes.len());
        for hash in &self.hashes {
            cbor::write_bytes(&mut bytes, hash);
        }
        cbor::write_uint(&mut bytes, 5);
        cbor::write_bytes(&mut bytes, &self.filter);
        bytes
    }

    /// Decodes and reconstructs the registered filter before exposing any mark.
    ///
    /// # Errors
    /// Rejects noncanonical schema, unknown version, a shard beyond 255,
    /// duplicate/unsorted/wrong-shard hashes, any filter disagreement, and trailing data.
    pub fn decode(bytes: &[u8]) -> Result<Self, GcError> {
        let mut decoder = Decoder::new(bytes);
        let (cycle, epoch) = read_header(&mut decoder, 6)?;
        key(&mut decoder, 3)?;
        let shard = u8::try_from(decoder.uint()?).map_err(|_| GcError::Schema)?;
        key(&mut decoder, 4)?;
        let count = collection(&mut decoder, 34)?;
        let mut hashes = Vec::new();
        for _ in 0..count {
            let hash = digest(&mut decoder)?;
            if hash[0] != shard || hashes.last().is_some_and(|previous| previous >= &hash) {
                return Err(GcError::Schema);
            }
            hashes.push(hash);
        }
        key(&mut decoder, 5)?;
        let filter = decoder.bytes(MARK_FILTER_BYTES)?;
        decoder.finish()?;
        let mark = Self::new(cycle, epoch, shard, hashes)?;
        if filter != mark.filter {
            return Err(GcError::Schema);
        }
        Ok(mark)
    }
}

/// The resumable phase named by a fenced collection state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Root selection has not finished.
    Snapshot,
    /// Metadata reachability is being expanded.
    Mark,
    /// Unmarked old packs are being excluded.
    Sweep,
    /// Mature tombstoned packs are being physically deleted.
    Delete,
    /// The cycle completed all effects.
    Done,
}

impl Phase {
    /// Returns the registered phase string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::Mark => "mark",
            Self::Sweep => "sweep",
            Self::Delete => "delete",
            Self::Done => "done",
        }
    }

    fn decode(value: &str) -> Result<Self, GcError> {
        match value {
            "snapshot" => Ok(Self::Snapshot),
            "mark" => Ok(Self::Mark),
            "sweep" => Ok(Self::Sweep),
            "delete" => Ok(Self::Delete),
            "done" => Ok(Self::Done),
            _ => Err(GcError::Schema),
        }
    }
}

/// One immutable mark revision selected by a fenced state record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointPointer {
    /// Digest-prefix shard number.
    pub shard: u8,
    /// Immutable checkpoint revision selected for this shard.
    pub revision: u64,
    /// Raw BLAKE3-256 digest of the exact canonical checkpoint bytes.
    pub hash: Digest,
}

/// An exact unexpanded traversal edge preserved across checkpoints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pending {
    /// Registered pack kind, zero through nine.
    pub kind: u8,
    /// Content identity in the registered kind's domain.
    pub hash: Digest,
    /// Exact ordinary-parent timestamp, unbounded, or roots-only context.
    pub parent_cutoff: ParentCutoff,
    /// Parent, root, index, and witness-only bits zero through three.
    pub flags: u8,
    /// Exact destination proof position; absence preserves legacy traversal.
    pub proof_context: Option<ProofContext>,
}

impl Pending {
    /// Tests whether this edge must pass the ordinary parent-age test.
    pub const fn is_parent(&self) -> bool {
        self.flags & 1 != 0
    }

    /// Tests whether the node is a root that may carry properties.
    pub const fn is_root(&self) -> bool {
        self.flags & 2 != 0
    }

    /// Tests whether node keys belong to an index tree.
    pub const fn is_index(&self) -> bool {
        self.flags & 4 != 0
    }

    /// Tests whether only metadata and proof dependencies are retained.
    pub const fn is_witness(&self) -> bool {
        self.flags & 8 != 0
    }

    fn validate(&self) -> Result<(), GcError> {
        if self.kind > 9
            || self.flags & !15 != 0
            || (self.is_witness() && self.kind == 0)
            || (self.is_parent() && self.kind != 3)
            || ((self.is_root() || self.is_index()) && self.kind != 2)
        {
            return Err(GcError::Schema);
        }
        Ok(())
    }
}

/// The broadest ordinary parent context already expanded for one signed commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpandedContext {
    /// Signed commit identity.
    pub commit: Digest,
    /// Broadest completed roots-only, timestamp, or unbounded context.
    pub parent_cutoff: ParentCutoff,
    /// Exact destination proof position; absence preserves legacy traversal.
    pub proof_context: Option<ProofContext>,
}

/// One completed typed metadata expansion, independent of ordinary parent age.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExpandedObject {
    /// Registered pack kind.
    pub kind: u8,
    /// Identity in that kind's domain.
    pub hash: Digest,
    /// Root, index, and witness-only bits; the parent bit is prohibited.
    pub flags: u8,
    /// Exact destination proof position; absence preserves legacy traversal.
    pub proof_context: Option<ProofContext>,
}

impl ExpandedObject {
    fn validate(&self) -> Result<(), GcError> {
        if self.flags & !14 != 0 || (self.kind == 3 && self.flags & 8 == 0) {
            return Err(GcError::Schema);
        }
        Pending {
            kind: self.kind,
            hash: self.hash,
            parent_cutoff: ParentCutoff::Unbounded,
            flags: self.flags,
            proof_context: self.proof_context.clone(),
        }
        .validate()
    }
}

/// The fenced authoritative progress record selecting immutable mark revisions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcState {
    /// Owning collection cycle.
    pub cycle: u64,
    /// Writer's fencing epoch.
    pub epoch: u64,
    /// Current resumable phase.
    pub phase: Phase,
    /// Time of the selected immutable root snapshot.
    pub snapshot_at: u64,
    /// Strictly ordered, unique selected shard revisions.
    pub checkpoints: Vec<CheckpointPointer>,
    /// Exact unexpanded frontier, preserving edge order and contexts.
    pub pending: Vec<Pending>,
    /// Strictly ordered, unique least restrictive expanded commit contexts.
    pub expanded: Vec<ExpandedContext>,
    /// Strictly ordered, unique physical pack IDs completed in this phase.
    pub progress: Vec<[u8; 16]>,
    /// Strictly ordered, unique typed full and witness-only expansion contexts.
    pub objects: Vec<ExpandedObject>,
}

impl GcState {
    /// Encodes a validated version-one progress map.
    ///
    /// # Errors
    /// Rejects nonunique or unordered pointers, contexts, progress, invalid kinds,
    /// or reserved/inapplicable pending flags.
    pub fn encode(&self) -> Result<Vec<u8>, GcError> {
        self.validate()?;
        let mut bytes = Vec::new();
        header(&mut bytes, 10, self.cycle, self.epoch);
        cbor::write_uint(&mut bytes, 3);
        cbor::write_text(&mut bytes, self.phase.as_str());
        field(&mut bytes, 4, self.snapshot_at);
        cbor::write_uint(&mut bytes, 5);
        cbor::write_array(&mut bytes, self.checkpoints.len());
        for pointer in &self.checkpoints {
            cbor::write_array(&mut bytes, 3);
            cbor::write_uint(&mut bytes, u64::from(pointer.shard));
            cbor::write_uint(&mut bytes, pointer.revision);
            cbor::write_bytes(&mut bytes, &pointer.hash);
        }
        cbor::write_uint(&mut bytes, 6);
        cbor::write_array(&mut bytes, self.pending.len());
        for pending in &self.pending {
            cbor::write_array(&mut bytes, 4 + usize::from(pending.proof_context.is_some()));
            cbor::write_uint(&mut bytes, u64::from(pending.kind));
            cbor::write_bytes(&mut bytes, &pending.hash);
            cutoff(&mut bytes, pending.parent_cutoff);
            cbor::write_uint(&mut bytes, u64::from(pending.flags));
            write_proof_context(&mut bytes, pending.proof_context.as_ref());
        }
        cbor::write_uint(&mut bytes, 7);
        cbor::write_array(&mut bytes, self.expanded.len());
        for context in &self.expanded {
            cbor::write_array(&mut bytes, 2 + usize::from(context.proof_context.is_some()));
            cbor::write_bytes(&mut bytes, &context.commit);
            cutoff(&mut bytes, context.parent_cutoff);
            write_proof_context(&mut bytes, context.proof_context.as_ref());
        }
        cbor::write_uint(&mut bytes, 8);
        cbor::write_array(&mut bytes, self.progress.len());
        for pack in &self.progress {
            cbor::write_bytes(&mut bytes, pack);
        }
        cbor::write_uint(&mut bytes, 9);
        cbor::write_array(&mut bytes, self.objects.len());
        for object in &self.objects {
            cbor::write_array(&mut bytes, 3 + usize::from(object.proof_context.is_some()));
            cbor::write_uint(&mut bytes, u64::from(object.kind));
            cbor::write_bytes(&mut bytes, &object.hash);
            cbor::write_uint(&mut bytes, u64::from(object.flags));
            write_proof_context(&mut bytes, object.proof_context.as_ref());
        }
        Ok(bytes)
    }

    /// Decodes an exact frontier and validates all registered ordering invariants.
    ///
    /// # Errors
    /// Rejects noncanonical CBOR, unknown version/phase, invalid widths, kinds,
    /// flags, unordered or duplicate pointers/contexts/progress, and trailing values.
    pub fn decode(bytes: &[u8]) -> Result<Self, GcError> {
        let mut decoder = Decoder::new(bytes);
        let (cycle, epoch) = read_header(&mut decoder, 10)?;
        key(&mut decoder, 3)?;
        let phase = Phase::decode(decoder.text(8)?)?;
        key(&mut decoder, 4)?;
        let snapshot_at = decoder.uint()?;
        key(&mut decoder, 5)?;
        let count = collection(&mut decoder, 37)?;
        let mut checkpoints = Vec::new();
        for _ in 0..count {
            if decoder.array(3)? != 3 {
                return Err(GcError::Schema);
            }
            let shard = u8::try_from(decoder.uint()?).map_err(|_| GcError::Schema)?;
            let revision = decoder.uint()?;
            let hash = digest(&mut decoder)?;
            let pointer = CheckpointPointer {
                shard,
                revision,
                hash,
            };
            if checkpoints
                .last()
                .is_some_and(|previous: &CheckpointPointer| previous.shard >= shard)
            {
                return Err(GcError::Schema);
            }
            checkpoints.push(pointer);
        }
        key(&mut decoder, 6)?;
        let count = collection(&mut decoder, 38)?;
        let mut pending = Vec::new();
        for _ in 0..count {
            let width = decoder.array(5)?;
            if !(4..=5).contains(&width) {
                return Err(GcError::Schema);
            }
            let kind = u8::try_from(decoder.uint()?).map_err(|_| GcError::Schema)?;
            let hash = digest(&mut decoder)?;
            let parent_cutoff = read_cutoff(&mut decoder)?;
            let flags = u8::try_from(decoder.uint()?).map_err(|_| GcError::Schema)?;
            let item = Pending {
                kind,
                hash,
                parent_cutoff,
                flags,
                proof_context: read_proof_context(&mut decoder, width == 5)?,
            };
            item.validate()?;
            pending.push(item);
        }
        key(&mut decoder, 7)?;
        let count = collection(&mut decoder, 36)?;
        let mut expanded = Vec::new();
        for _ in 0..count {
            let width = decoder.array(3)?;
            if !(2..=3).contains(&width) {
                return Err(GcError::Schema);
            }
            let commit = digest(&mut decoder)?;
            let parent_cutoff = read_cutoff(&mut decoder)?;
            let context = ExpandedContext {
                commit,
                parent_cutoff,
                proof_context: read_proof_context(&mut decoder, width == 3)?,
            };
            if expanded.last().is_some_and(|previous: &ExpandedContext| {
                (previous.commit, &previous.proof_context)
                    >= (context.commit, &context.proof_context)
            }) {
                return Err(GcError::Schema);
            }
            expanded.push(context);
        }
        key(&mut decoder, 8)?;
        let count = collection(&mut decoder, 17)?;
        let mut progress = Vec::new();
        for _ in 0..count {
            let pack = decoder.bytes(16)?.try_into().map_err(|_| GcError::Schema)?;
            if progress.last().is_some_and(|previous| previous >= &pack) {
                return Err(GcError::Schema);
            }
            progress.push(pack);
        }
        key(&mut decoder, 9)?;
        let count = collection(&mut decoder, 37)?;
        let mut objects = Vec::new();
        for _ in 0..count {
            let width = decoder.array(4)?;
            if !(3..=4).contains(&width) {
                return Err(GcError::Schema);
            }
            let kind = u8::try_from(decoder.uint()?).map_err(|_| GcError::Schema)?;
            let hash = digest(&mut decoder)?;
            let flags = u8::try_from(decoder.uint()?).map_err(|_| GcError::Schema)?;
            let object = ExpandedObject {
                kind,
                hash,
                flags,
                proof_context: read_proof_context(&mut decoder, width == 4)?,
            };
            object.validate()?;
            if objects.last().is_some_and(|previous| previous >= &object) {
                return Err(GcError::Schema);
            }
            objects.push(object);
        }
        decoder.finish()?;
        let state = Self {
            cycle,
            epoch,
            phase,
            snapshot_at,
            checkpoints,
            pending,
            expanded,
            progress,
            objects,
        };
        state.validate()?;
        Ok(state)
    }

    fn validate(&self) -> Result<(), GcError> {
        if self
            .checkpoints
            .windows(2)
            .any(|pair| pair[0].shard >= pair[1].shard)
            || self.expanded.windows(2).any(|pair| {
                (pair[0].commit, &pair[0].proof_context) >= (pair[1].commit, &pair[1].proof_context)
            })
            || self.progress.windows(2).any(|pair| pair[0] >= pair[1])
            || self.objects.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(GcError::Schema);
        }
        for pending in &self.pending {
            pending.validate()?;
        }
        for object in &self.objects {
            object.validate()?;
        }
        Ok(())
    }
}

// Each entry has a fixed minimum encoded width. Never reserve attacker-declared
// collection capacity; validate complete entries before growing retained state.
fn collection(decoder: &mut Decoder<'_>, minimum_width: usize) -> Result<usize, GcError> {
    Ok(decoder.array(decoder.remaining().len() / minimum_width)?)
}

fn header(bytes: &mut Vec<u8>, fields: usize, cycle: u64, epoch: u64) {
    cbor::write_map(bytes, fields);
    field(bytes, 0, 1);
    field(bytes, 1, cycle);
    field(bytes, 2, epoch);
}

fn read_header(decoder: &mut Decoder<'_>, fields: usize) -> Result<(u64, u64), GcError> {
    if decoder.map(fields)? != fields {
        return Err(GcError::Schema);
    }
    key(decoder, 0)?;
    if decoder.uint()? != 1 {
        return Err(GcError::Schema);
    }
    key(decoder, 1)?;
    let cycle = decoder.uint()?;
    key(decoder, 2)?;
    let epoch = decoder.uint()?;
    Ok((cycle, epoch))
}

fn field(bytes: &mut Vec<u8>, key: u64, value: u64) {
    cbor::write_uint(bytes, key);
    cbor::write_uint(bytes, value);
}

fn cutoff(bytes: &mut Vec<u8>, value: ParentCutoff) {
    match value {
        ParentCutoff::Since(value) => cbor::write_uint(bytes, value),
        ParentCutoff::Unbounded => bytes.push(0xf6),
        ParentCutoff::RootsOnly => bytes.push(0xf4),
    }
}

fn read_cutoff(decoder: &mut Decoder<'_>) -> Result<ParentCutoff, GcError> {
    if decoder.peek_major()? == 0 {
        return Ok(ParentCutoff::Since(decoder.uint()?));
    }
    match decoder.simple()? {
        0xf6 => Ok(ParentCutoff::Unbounded),
        0xf4 => Ok(ParentCutoff::RootsOnly),
        _ => Err(GcError::Schema),
    }
}

fn digest(decoder: &mut Decoder<'_>) -> Result<Digest, GcError> {
    decoder.bytes(32)?.try_into().map_err(|_| GcError::Schema)
}

fn validate_hashes(shard: u8, hashes: &[Digest]) -> Result<(), GcError> {
    if hashes.iter().any(|hash| hash[0] != shard)
        || hashes.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(GcError::Schema);
    }
    Ok(())
}

fn write_proof_context(bytes: &mut Vec<u8>, context: Option<&ProofContext>) {
    if let Some(context) = context {
        cbor::write_array(bytes, 3);
        cbor::write_bytes(bytes, context.destination());
        cbor::write_bytes(bytes, context.root());
        cbor::write_bytes(bytes, context.absolute_path());
    }
}

fn read_proof_context(
    decoder: &mut Decoder<'_>,
    present: bool,
) -> Result<Option<ProofContext>, GcError> {
    if !present {
        return Ok(None);
    }
    if decoder.array(3)? != 3 {
        return Err(GcError::Schema);
    }
    let destination = digest(decoder)?;
    let root = digest(decoder)?;
    let path = decoder.bytes(4097)?.to_vec();
    Ok(Some(ProofContext::new(destination, root, path)?))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod context_tests;
