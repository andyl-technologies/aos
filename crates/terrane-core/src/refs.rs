//! Commit ancestry and the mutable ref namespace.
//!
//! Names and records follow specification 09 and `reference/terrane-v1.cddl`.
//! Commit ancestry uses parent edges rather than advisory timestamps.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use crate::cbor::{self, Decoder};
use crate::identity::Digest;

mod codec;
mod record_codec;

pub use codec::{
    Commit, CommitIdentityError, CommitSource, Lease, PackLocation, PrincipalKind, ProfilePair,
    Provenance,
};

const MAX_RECORD_BYTES: usize = 1 << 20;
const MAX_TEXT_BYTES: usize = 65536;

/// A canonical ref or commit record could not be encoded or decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordError {
    /// The CBOR input violates the deterministic encoding subset.
    Cbor(cbor::Error),
    /// A field violates the record's CDDL schema or semantic constraints.
    Schema,
}

impl From<cbor::Error> for RecordError {
    fn from(error: cbor::Error) -> Self {
        Self::Cbor(error)
    }
}

impl fmt::Display for RecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cbor(error) => fmt::Display::fmt(error, formatter),
            Self::Schema => formatter.write_str("record violates the Terrane schema"),
        }
    }
}

impl core::error::Error for RecordError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Cbor(error) => Some(error),
            Self::Schema => None,
        }
    }
}

fn read_digest(decoder: &mut Decoder<'_>) -> Result<Digest, RecordError> {
    decoder
        .bytes(32)?
        .try_into()
        .map_err(|_| RecordError::Schema)
}

fn read_bool(decoder: &mut Decoder<'_>) -> Result<bool, RecordError> {
    match decoder.simple()? {
        0xf4 => Ok(false),
        0xf5 => Ok(true),
        _ => Err(RecordError::Schema),
    }
}

fn write_bool(output: &mut Vec<u8>, value: bool) {
    output.push(if value { 0xf5 } else { 0xf4 });
}

fn read_key(decoder: &mut Decoder<'_>, previous: &mut u64, max: u64) -> Result<u64, RecordError> {
    let key = decoder.uint()?;
    if key <= *previous || key > max {
        return Err(RecordError::Schema);
    }
    *previous = key;
    Ok(key)
}

fn validate_raw_map(bytes: &[u8], key_type: u8) -> Result<(), RecordError> {
    let mut decoder = Decoder::new(bytes);
    let count = decoder.map(MAX_RECORD_BYTES)?;
    let mut previous = None;
    for _ in 0..count {
        if decoder.peek_major()? != key_type {
            return Err(RecordError::Schema);
        }
        let start = decoder.position();
        decoder.raw_value(MAX_RECORD_BYTES)?;
        let key = decoder.slice(start, decoder.position())?;
        if previous.is_some_and(|prior: &[u8]| key <= prior) {
            return Err(RecordError::Schema);
        }
        previous = Some(key);
        decoder.raw_value(MAX_RECORD_BYTES)?;
    }
    decoder.finish()?;
    Ok(())
}

/// One class in the closed ref namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum RefClass {
    /// A branch that advances by compare-and-swap.
    Heads,
    /// A create-once tag, including snapshots.
    Tags,
    /// Advisory sidecar data.
    Notes,
    /// A resumable tree-job checkpoint.
    Jobs,
    /// An unresolved merge awaiting resolution.
    Conflicts,
    /// A shared, named derivation.
    Derived,
}

/// The conditional write primitive for an ordinary ref update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefWriteMode {
    /// Compare the complete previous value before advancing.
    CompareAndSwap,
    /// Create once and reject subsequent ordinary writes.
    PutIfAbsent,
}

impl RefClass {
    /// Returns the class's exact namespace component.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Heads => "heads",
            Self::Tags => "tags",
            Self::Notes => "notes",
            Self::Jobs => "jobs",
            Self::Conflicts => "conflicts",
            Self::Derived => "derived",
        }
    }

    /// Returns the ordinary conditional write mode for this class.
    ///
    /// Administrative tag mutation is a separate, explicitly authorized
    /// procedure; ordinary tag creation always uses put-if-absent.
    pub const fn write_mode(self) -> RefWriteMode {
        match self {
            Self::Tags => RefWriteMode::PutIfAbsent,
            Self::Heads | Self::Notes | Self::Jobs | Self::Conflicts | Self::Derived => {
                RefWriteMode::CompareAndSwap
            }
        }
    }
}

/// A validated `refs/<class>/<path>` name.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RefName {
    value: String,
    class: RefClass,
}

impl RefName {
    /// Parses a ref name under the closed class and segment grammar.
    ///
    /// # Errors
    ///
    /// Returns [`RefNameError`] for an unknown class, empty segment,
    /// forbidden byte, or a segment containing two consecutive dots.
    pub fn parse(value: &str) -> Result<Self, RefNameError> {
        let mut components = value.split('/');
        if components.next() != Some("refs") {
            return Err(RefNameError::Prefix);
        }

        let class = match components.next() {
            Some("heads") => RefClass::Heads,
            Some("tags") => RefClass::Tags,
            Some("notes") => RefClass::Notes,
            Some("jobs") => RefClass::Jobs,
            Some("conflicts") => RefClass::Conflicts,
            Some("derived") => RefClass::Derived,
            _ => return Err(RefNameError::Class),
        };

        let mut count = 0;
        for component in components {
            count += 1;
            if component.is_empty() {
                return Err(RefNameError::EmptySegment);
            }
            if component.contains("..") {
                return Err(RefNameError::DotDot);
            }
            if component
                .bytes()
                .any(|byte| !(0x21..=0x7e).contains(&byte) || b"~^:?*[\\".contains(&byte))
            {
                return Err(RefNameError::ForbiddenCharacter);
            }
        }
        if count == 0 {
            return Err(RefNameError::EmptySegment);
        }

        Ok(Self {
            value: value.to_string(),
            class,
        })
    }

    /// Returns the complete validated name.
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Returns the ref class.
    pub const fn class(&self) -> RefClass {
        self.class
    }

    /// Returns the immutable reflog key for a branch advance.
    ///
    /// # Errors
    ///
    /// Returns [`RefLogNameError::NotBranch`] for another ref class and
    /// [`RefLogNameError::ZeroSequence`] for a non-record sequence.
    pub fn reflog_key(&self, seq: u64) -> Result<String, RefLogNameError> {
        if self.class != RefClass::Heads {
            return Err(RefLogNameError::NotBranch);
        }
        if seq == 0 {
            return Err(RefLogNameError::ZeroSequence);
        }

        let mut key = String::from("logs/");
        key.push_str(&self.value);
        key.push('/');
        key.push_str(&seq.to_string());
        Ok(key)
    }
}

impl FromStr for RefName {
    type Err = RefNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl fmt::Display for RefName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.value)
    }
}

/// Why a ref name failed the namespace grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefNameError {
    /// The name does not begin with `refs/`.
    Prefix,
    /// The class is missing or unknown.
    Class,
    /// The path is absent or has an empty segment.
    EmptySegment,
    /// A segment contains `..`.
    DotDot,
    /// A segment contains non-printable ASCII or a forbidden character.
    ForbiddenCharacter,
}

impl fmt::Display for RefNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Prefix => "ref name must begin with refs/",
            Self::Class => "ref name has an unknown class",
            Self::EmptySegment => "ref name has an empty path segment",
            Self::DotDot => "ref name contains consecutive dots",
            Self::ForbiddenCharacter => "ref name contains a forbidden character",
        };
        formatter.write_str(message)
    }
}

impl core::error::Error for RefNameError {}

/// A reflog key cannot be formed for this name and sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefLogNameError {
    /// Reflog keys belong to branch refs only.
    NotBranch,
    /// Reflog sequences begin at one.
    ZeroSequence,
}

impl fmt::Display for RefLogNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotBranch => formatter.write_str("reflog key requires a branch ref"),
            Self::ZeroSequence => formatter.write_str("reflog sequence must be positive"),
        }
    }
}

impl core::error::Error for RefLogNameError {}

/// An authority's region, zone, and host labels.
///
/// All three are optional in the canonical locality map. A backend may
/// impose a stronger placement policy when it creates an authority.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Locality {
    /// Region label, if the authority identifies one.
    pub region: Option<String>,
    /// Zone label, if the authority identifies one.
    pub zone: Option<String>,
    /// Host label, if the authority identifies one.
    pub host: Option<String>,
}

/// A merge policy named by the canonical ref-policy schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MergePolicy {
    /// Prefer the target branch's value.
    PreferOurs,
    /// Prefer the incoming branch's value.
    PreferTheirs,
    /// Prefer a value satisfying the configured trust selector.
    PreferTrusted,
    /// Prefer the value with the newer advisory timestamp.
    PreferNewer,
    /// Preserve an unresolved conflict value.
    KeepConflict,
    /// Fail an unresolved merge.
    Error,
}

/// A ref-specific retention override.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Retention {
    /// Normal garbage-collection policy.
    Gc,
    /// Retain for the lease lifetime.
    Lease,
    /// Retain indefinitely.
    Forever,
    /// Retain for a duration in seconds.
    Ttl(u64),
}

/// A signed annotation on a tag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotEnvelope {
    /// Name of the tag to which the annotation is bound.
    pub tag: RefName,
    /// Commit identity bound to the tag.
    pub commit: Digest,
    /// Canonical CBOR map of attestation values.
    pub attestation: Vec<u8>,
    /// Identifier of the signing key.
    pub signer_key: String,
    /// Ed25519 signature over envelope keys 1 through 4.
    pub signature: [u8; 64],
}

/// Optional policy fields on a ref record.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RefPolicy {
    /// Whether multiple writers may merge and retry.
    pub multi_writer: Option<bool>,
    /// Ordered policies used to resolve concurrent writes.
    pub merge_policies: Option<Vec<MergePolicy>>,
    /// Ref-specific retention override.
    pub retention: Option<Retention>,
    /// Whether the ref's tree carries a conflict value.
    pub conflicted: Option<bool>,
    /// Signed annotation, available only on an annotated tag.
    pub snapshot: Option<SnapshotEnvelope>,
}

/// The complete mutable value compared by a ref compare-and-swap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefRecord {
    /// Identity of the commit named by this ref.
    pub commit: Digest,
    /// Monotone sequence, beginning at one.
    pub seq: u64,
    /// Fencing epoch of the current writer.
    pub writer_epoch: u64,
    /// Locality of the authority that owns this ref.
    pub home: Locality,
    /// Optional multi-writer, retention, and annotation policy.
    pub policy: Option<RefPolicy>,
}

/// A rejected ref-record transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefSequenceError {
    /// The sequence cannot increase by one in `u64`.
    Exhausted,
    /// A record is not the first write or exact next sequence.
    InvalidSequence,
    /// The writer's epoch is older than the record being replaced.
    EpochRegression,
    /// An ordinary write attempted to move the ref's authority.
    HomeChanged,
}

impl fmt::Display for RefSequenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exhausted => formatter.write_str("ref sequence exhausted"),
            Self::InvalidSequence => formatter.write_str("ref sequence is not the next value"),
            Self::EpochRegression => formatter.write_str("writer epoch regressed"),
            Self::HomeChanged => formatter.write_str("ref authority home changed"),
        }
    }
}

impl core::error::Error for RefSequenceError {}

/// The closed set of reflog reasons.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefLogReason {
    /// An ordinary commit.
    Commit,
    /// A branch merge.
    Merge,
    /// A child branch folded into its parent.
    Fold,
    /// An advance naming an earlier commit.
    Rollback,
    /// A resumable job checkpoint.
    JobCheckpoint,
    /// A migration write.
    Migrate,
}

/// An immutable account of one successful ref advance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefLogRecord {
    /// The new ref value.
    pub record: RefRecord,
    /// Commit named before the advance, absent on the first write.
    pub previous_commit: Option<Digest>,
    /// Principal that advanced the ref.
    pub principal: String,
    /// Why the ref advanced.
    pub reason: RefLogReason,
    /// Advisory seconds since the Unix epoch.
    pub timestamp: u64,
}

/// One immutable commit's ordered parent edges.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitParents {
    /// The commit's identity.
    pub identity: Digest,
    /// Parents, with the target's previous commit first for merges.
    pub parents: Vec<Digest>,
}

/// An in-memory commit DAG used for ancestry and merge-base decisions.
#[derive(Clone, Debug, Default)]
pub struct CommitGraph {
    commits: BTreeMap<Digest, Vec<Digest>>,
}

impl CommitGraph {
    /// Creates an empty graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a commit's ordered parent edges after rejecting a cycle.
    ///
    /// Parent commits may arrive later. Queries fail distinctly while an
    /// edge they need has no corresponding commit record.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::Cycle`] for a self-edge or a path from a parent
    /// back to the new commit, or [`GraphError::DifferentRecord`] if a known
    /// identity is presented with different parents.
    pub fn insert(&mut self, commit: CommitParents) -> Result<(), GraphError> {
        if let Some(previous) = self.commits.get(&commit.identity) {
            return if previous == &commit.parents {
                Ok(())
            } else {
                Err(GraphError::DifferentRecord(commit.identity))
            };
        }

        for parent in &commit.parents {
            if *parent == commit.identity
                || self.has_path_even_if_incomplete(*parent, commit.identity)
            {
                return Err(GraphError::Cycle(commit.identity));
            }
        }

        self.commits.insert(commit.identity, commit.parents);
        Ok(())
    }

    /// Reports whether `ancestor` is an ancestor of or equal to `descendant`.
    ///
    /// Equality permits a fold when the parent has not advanced since the
    /// fork. Cycle checks separately reject nonempty paths back to a commit.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::MissingCommit`] if a traversed parent is absent.
    pub fn is_ancestor(&self, ancestor: Digest, descendant: Digest) -> Result<bool, GraphError> {
        self.ancestors_including(descendant)
            .map(|ancestors| ancestors.contains(&ancestor))
    }

    /// Finds the unique lowest common ancestor of two commits.
    ///
    /// Multiple lowest common ancestors require a recursive merge. This
    /// graph reports them distinctly so a caller cannot choose arbitrarily.
    /// Advisory timestamps never influence this decision.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::MissingCommit`] for an incomplete graph,
    /// [`GraphError::NoCommonAncestor`] for unrelated roots, or
    /// [`GraphError::MultipleMergeBases`] when recursive merging is needed.
    pub fn merge_base(&self, ours: Digest, theirs: Digest) -> Result<Digest, GraphError> {
        let ours_ancestors = self.ancestors_including(ours)?;
        let theirs_ancestors = self.ancestors_including(theirs)?;
        let common: BTreeSet<Digest> = ours_ancestors
            .intersection(&theirs_ancestors)
            .copied()
            .collect();
        let mut lowest = common.clone();

        for candidate in common {
            for ancestor in self.ancestors_including(candidate)? {
                if ancestor != candidate {
                    lowest.remove(&ancestor);
                }
            }
        }

        match lowest.len() {
            0 => Err(GraphError::NoCommonAncestor),
            1 => lowest
                .iter()
                .next()
                .copied()
                .ok_or(GraphError::NoCommonAncestor),
            _ => Err(GraphError::MultipleMergeBases(lowest.into_iter().collect())),
        }
    }

    fn has_path_even_if_incomplete(&self, start: Digest, target: Digest) -> bool {
        let mut pending = VecDeque::from([start]);
        let mut visited = BTreeSet::new();

        while let Some(commit) = pending.pop_front() {
            if !visited.insert(commit) {
                continue;
            }
            if commit == target {
                return true;
            }
            if let Some(parents) = self.commits.get(&commit) {
                pending.extend(parents.iter().copied());
            }
        }

        false
    }

    fn ancestors_including(&self, start: Digest) -> Result<BTreeSet<Digest>, GraphError> {
        let mut pending = VecDeque::from([start]);
        let mut visited = BTreeSet::new();

        while let Some(commit) = pending.pop_front() {
            if !visited.insert(commit) {
                continue;
            }
            let parents = self
                .commits
                .get(&commit)
                .ok_or(GraphError::MissingCommit(commit))?;
            pending.extend(parents.iter().copied());
        }

        Ok(visited)
    }
}

/// A malformed or incomplete commit DAG.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GraphError {
    /// A commit record needed for the answer is unavailable.
    MissingCommit(Digest),
    /// An identity was reused with different parent edges.
    DifferentRecord(Digest),
    /// A parent edge would make a commit its own ancestor.
    Cycle(Digest),
    /// The two histories have no common commit.
    NoCommonAncestor,
    /// A criss-cross history has more than one lowest common ancestor.
    MultipleMergeBases(Vec<Digest>),
}

impl fmt::Display for GraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCommit(_) => formatter.write_str("commit graph is incomplete"),
            Self::DifferentRecord(_) => formatter.write_str("identity has different parent edges"),
            Self::Cycle(_) => formatter.write_str("commit graph contains a cycle"),
            Self::NoCommonAncestor => formatter.write_str("commits have no common ancestor"),
            Self::MultipleMergeBases(_) => formatter.write_str("recursive merge base required"),
        }
    }
}

impl core::error::Error for GraphError {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::vec;

    fn digest(value: u8) -> Digest {
        [value; 32]
    }

    fn hex_bytes(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = core::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }

    #[test]
    fn ref_and_reflog_match_normative_golden_vectors() {
        let record_bytes = hex_bytes(concat!(
            "a4015820c8efdd180de6c5b1e04abe4435238e8969776497759682c6094a4ced",
            "e9c579d60201030104a1016965752d776573742d31"
        ));
        let log_bytes = hex_bytes(concat!(
            "a501a4015820c8efdd180de6c5b1e04abe4435238e8969776497759682c6094a",
            "4cede9c579d60201030104a1016965752d776573742d3102f6036663692d6a6f",
            "620466636f6d6d6974051a68e77800"
        ));
        let record = RefRecord::decode(&record_bytes).unwrap();
        assert_eq!(record.encode().unwrap(), record_bytes);
        assert_eq!(record.seq, 1);
        assert_eq!(record.home.region.as_deref(), Some("eu-west-1"));

        let log = RefLogRecord::decode(&log_bytes).unwrap();
        assert_eq!(log.encode().unwrap(), log_bytes);
        assert_eq!(log.record, record);
        assert_eq!(log.previous_commit, None);
        assert_eq!(log.reason, RefLogReason::Commit);
    }

    #[test]
    fn ref_decoder_rejects_unknown_keys_and_noncanonical_order() {
        let mut record = RefRecord::first(digest(1), 1, Locality::default())
            .encode()
            .unwrap();
        record[0] = 0xa5;
        record.extend_from_slice(&[0x06, 0xf6]);
        assert!(RefRecord::decode(&record).is_err());

        let mut record = RefRecord::first(digest(1), 1, Locality::default())
            .encode()
            .unwrap();
        record[0] = 0xa5;
        record.extend_from_slice(&[0x04, 0xa0]);
        assert!(RefRecord::decode(&record).is_err());
    }

    #[test]
    fn ref_names_accept_exact_classes_and_nested_paths() {
        for class in ["heads", "tags", "notes", "jobs", "conflicts", "derived"] {
            let name = format!("refs/{class}/tenant/a.b_@-+/leaf");
            assert_eq!(RefName::parse(&name).unwrap().as_str(), name);
        }
        assert_ne!(
            RefName::parse("refs/heads/A"),
            RefName::parse("refs/heads/a")
        );

        let branch = RefName::parse("refs/heads/tenant/main").unwrap();
        assert_eq!(branch.class().write_mode(), RefWriteMode::CompareAndSwap);
        assert_eq!(
            branch.reflog_key(17).unwrap(),
            "logs/refs/heads/tenant/main/17"
        );
        let tag = RefName::parse("refs/tags/tenant/v1").unwrap();
        assert_eq!(tag.class().write_mode(), RefWriteMode::PutIfAbsent);
        assert_eq!(tag.reflog_key(1), Err(RefLogNameError::NotBranch));
        assert_eq!(branch.reflog_key(0), Err(RefLogNameError::ZeroSequence));
    }

    #[test]
    fn ref_names_reject_malformed_segments_and_characters() {
        for name in [
            "",
            "refs",
            "refs/heads",
            "refs/unknown/x",
            "refs/heads/",
            "refs/heads//x",
            "refs/heads/x/",
            "refs/heads/a..b",
            "refs/heads/x y",
            "refs/heads/x\n",
            "refs/heads/é",
            "refs/heads/~",
            "refs/heads/^",
            "refs/heads/:",
            "refs/heads/?",
            "refs/heads/*",
            "refs/heads/[",
            "refs/heads/\\",
            "logs/refs/heads/a/1",
        ] {
            assert!(RefName::parse(name).is_err(), "accepted {name:?}");
        }
    }

    #[test]
    fn ref_record_advances_by_one_and_fences_old_epochs() {
        let first = RefRecord::first(digest(1), 5, Locality::default());
        let next = first.advance(digest(2), 5).unwrap();
        assert_eq!(next.seq, 2);
        assert_eq!(next.home, first.home);
        assert_eq!(RefRecord::validate_successor(None, &first), Ok(()));
        assert_eq!(RefRecord::validate_successor(Some(&first), &next), Ok(()));
        assert_eq!(
            first.advance(digest(2), 4),
            Err(RefSequenceError::EpochRegression)
        );

        let mut skipped = next.clone();
        skipped.seq = 3;
        assert_eq!(
            RefRecord::validate_successor(Some(&first), &skipped),
            Err(RefSequenceError::InvalidSequence)
        );
        let mut moved = next;
        moved.home.region = Some(String::from("elsewhere"));
        assert_eq!(
            RefRecord::validate_successor(Some(&first), &moved),
            Err(RefSequenceError::HomeChanged)
        );
    }

    #[test]
    fn ancestry_and_unique_merge_base_follow_parent_edges() {
        let mut graph = CommitGraph::new();
        for (identity, parents) in [
            (1, vec![]),
            (2, vec![1]),
            (3, vec![2]),
            (4, vec![2]),
            (5, vec![3, 4]),
        ] {
            graph
                .insert(CommitParents {
                    identity: digest(identity),
                    parents: parents.into_iter().map(digest).collect(),
                })
                .unwrap();
        }
        assert_eq!(graph.is_ancestor(digest(2), digest(5)), Ok(true));
        assert_eq!(graph.is_ancestor(digest(5), digest(5)), Ok(true));
        assert_eq!(graph.is_ancestor(digest(4), digest(3)), Ok(false));
        assert_eq!(graph.merge_base(digest(3), digest(4)), Ok(digest(2)));
        assert_eq!(graph.merge_base(digest(5), digest(4)), Ok(digest(4)));
    }

    #[test]
    fn criss_cross_merge_requires_recursive_resolution() {
        let mut graph = CommitGraph::new();
        for (identity, parents) in [
            (1, vec![]),
            (2, vec![1]),
            (3, vec![1]),
            (4, vec![2, 3]),
            (5, vec![3, 2]),
        ] {
            graph
                .insert(CommitParents {
                    identity: digest(identity),
                    parents: parents.into_iter().map(digest).collect(),
                })
                .unwrap();
        }
        assert_eq!(
            graph.merge_base(digest(4), digest(5)),
            Err(GraphError::MultipleMergeBases(vec![digest(2), digest(3)])),
        );
    }

    #[test]
    fn inserting_a_delayed_parent_cannot_complete_a_cycle() {
        let mut graph = CommitGraph::new();
        graph
            .insert(CommitParents {
                identity: digest(1),
                parents: vec![digest(2)],
            })
            .unwrap();
        assert_eq!(
            graph.insert(CommitParents {
                identity: digest(2),
                parents: vec![digest(1)]
            }),
            Err(GraphError::Cycle(digest(2))),
        );
        assert_eq!(
            graph.is_ancestor(digest(2), digest(1)),
            Err(GraphError::MissingCommit(digest(2))),
        );
    }
}
