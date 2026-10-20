//! Owns the canonical immutable Source lineage record and its decoder.
//!
//! AOSHTL01 links saved Tree heads; it confers no Controller currentness or
//! independent rollback floor. Actual Source/native owners remain above.

use aos_sandbox_core::{ObjectDigest, ProjectId};
use aos_sandbox_protocol::controller_source_seed::{CONTROLLER_SOURCE_TREE_SEED_BYTES_V1, ControllerSourceTreeSeedV1, decode_retained_source_tree_seed_v1};
use aos_sandbox_protocol::domain_ledger::DomainLedgerDataError as HierarchyProtectedJournalErrorV1;

const MAGIC: &[u8; 8] = b"AOSHTL01";
const HEADER_BYTES: usize = 168;

/// Retains one immutable Tree generation link, without granting its authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosedTreeLineageRecordV1 {
    /// Retains the exact saved lineage comparison field.
    pub project: ProjectId,
    /// Retains the exact saved lineage comparison field.
    pub generation: u64,
    /// Retains the exact saved lineage comparison field.
    pub prior_tree_head: Option<ObjectDigest>,
    /// Retains the exact saved lineage comparison field.
    pub tree_head: ObjectDigest,
    /// Retains the exact saved lineage comparison field.
    pub prior_lineage_head: Option<ObjectDigest>,
    /// Retains the exact saved lineage comparison field.
    pub tree_commitment: ObjectDigest,
    /// Retains the exact saved lineage comparison field.
    pub initial_seed_packet: Option<[u8; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1]>,
}

impl ClosedTreeLineageRecordV1 {
    /// Constructs a historical structural link without authenticating it.
    pub fn new(
        project: ProjectId,
        generation: u64,
        prior_tree_head: Option<ObjectDigest>,
        tree_head: ObjectDigest,
        prior_lineage_head: Option<ObjectDigest>,
        tree_commitment: ObjectDigest,
        initial_seed_packet: Option<[u8; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1]>,
    ) -> Option<Self> {
        let genesis = generation == 1;
        if project.as_bytes() == &[0; 16]
            || generation == 0
            || generation == u64::MAX
            || tree_head.as_bytes() == &[0; 32]
            || tree_commitment.as_bytes() == &[0; 32]
            || prior_tree_head.is_none() != genesis
            || prior_lineage_head.is_none() != genesis
            || initial_seed_packet.is_some() != genesis
            || prior_tree_head.is_some_and(|head| head.as_bytes() == &[0; 32])
            || prior_lineage_head.is_some_and(|head| head.as_bytes() == &[0; 32])
            || initial_seed_packet.as_ref().is_some_and(|packet| {
                seed_claims(packet).is_none_or(|seed| seed.project() != project)
            })
        {
            return None;
        }
        Some(Self {
            project,
            generation,
            prior_tree_head,
            tree_head,
            prior_lineage_head,
            tree_commitment,
            initial_seed_packet,
        })
    }

    /// Returns the canonical saved project/generation identity.
    pub fn identity(&self) -> [u8; 48] {
        let mut identity = [0; 48];
        identity[..16].copy_from_slice(self.project.as_bytes());
        identity[24..32].copy_from_slice(&self.generation.to_be_bytes());
        identity[32..48].copy_from_slice(self.project.as_bytes());
        identity
    }

    /// Encodes the exact fixed lineage body and optional retained seed.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            HEADER_BYTES
                + self
                    .initial_seed_packet
                    .as_ref()
                    .map_or(0, |seed| seed.len()),
        );
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(self.project.as_bytes());
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(
            &self
                .prior_tree_head
                .map_or([0; 32], |head| *head.as_bytes()),
        );
        bytes.extend_from_slice(self.tree_head.as_bytes());
        bytes.extend_from_slice(
            &self
                .prior_lineage_head
                .map_or([0; 32], |head| *head.as_bytes()),
        );
        bytes.extend_from_slice(self.tree_commitment.as_bytes());
        let seed = self
            .initial_seed_packet
            .as_ref()
            .map_or(&[][..], |packet| packet.as_slice());
        bytes.extend_from_slice(&(seed.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(seed);
        bytes
    }
}

pub fn decode_closed_tree_lineage_v1(bytes: &[u8]) -> Option<ClosedTreeLineageRecordV1> {
    decode_lineage::<HierarchyProtectedJournalErrorV1>(bytes, None)
}

fn optional_head(bytes: [u8; 32]) -> Option<ObjectDigest> {
    (bytes != [0; 32]).then_some(ObjectDigest::from_bytes(bytes))
}

// Shape-checks a retained proposal. This does not authenticate its signature,
// Controller current heads, or anti-replay epoch.
/// Returns the existing shape-decoded retained seed comparison DATA.
///
/// This does not authenticate its signature, current heads or anti-replay floor.
#[doc(hidden)]
pub fn seed_claims(
    packet: &[u8; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1],
) -> Option<ControllerSourceTreeSeedV1> {
    decode_retained_source_tree_seed_v1(packet).ok()
}

pub struct LineageDecodeOriginalsV1<E = HierarchyProtectedJournalErrorV1> {
    record: Option<ClosedTreeLineageRecordV1>,
    encoded: Option<Vec<u8>>,
    accepted: Option<bool>,
    entered: bool,
    error: Option<E>,
}

impl<E: From<HierarchyProtectedJournalErrorV1> + std::error::Error + 'static> LineageDecodeOriginalsV1<E> {
    pub const fn new() -> Self {
        Self { record: None, encoded: None, accepted: None, entered: false, error: None }
    }

    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.as_ref().map(|error| error as _)
    }

    /// Moves the original pure refusal to its caller's typed error boundary.
    ///
    /// The attempt remains entered and cannot become a successful decode.
    pub fn take_failure_once(&mut self) -> Option<E> { self.error.take() }

    pub const fn receiving_metadata_cells_v1() -> usize { 0 }
}

pub fn decode_lineage_retaining_v1<E: From<HierarchyProtectedJournalErrorV1> + std::error::Error + 'static>(bytes: &[u8], capture: &mut LineageDecodeOriginalsV1<E>)
    -> Option<ClosedTreeLineageRecordV1>
{
    if capture.entered { capture.error.get_or_insert_with(|| E::from(HierarchyProtectedJournalErrorV1::NonCanonicalRecord)); return None; }
    capture.entered = true;
    let value = decode_lineage(bytes, Some(capture));
    if value.is_none() { capture.error.get_or_insert_with(|| E::from(HierarchyProtectedJournalErrorV1::NonCanonicalRecord)); }
    value
}

fn decode_lineage<E: From<HierarchyProtectedJournalErrorV1> + std::error::Error + 'static>(bytes: &[u8], capture: Option<&mut LineageDecodeOriginalsV1<E>>)
    -> Option<ClosedTreeLineageRecordV1>
{
    if bytes.len() < HEADER_BYTES
        || &bytes[..8] != MAGIC
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10..12] != [0; 2]
        || bytes[166..168] != [0; 2]
    {
        return None;
    }
    let seed_len = usize::from(u16::from_be_bytes(bytes[164..166].try_into().ok()?));
    if bytes.len() != HEADER_BYTES + seed_len
        || (seed_len != 0 && seed_len != CONTROLLER_SOURCE_TREE_SEED_BYTES_V1)
    {
        return None;
    }
    let initial_seed_packet = (seed_len != 0)
        .then(|| bytes[HEADER_BYTES..].try_into().ok())
        .flatten();
    let record = ClosedTreeLineageRecordV1::new(
        ProjectId::from_bytes(bytes[12..28].try_into().ok()?),
        u64::from_be_bytes(bytes[28..36].try_into().ok()?),
        optional_head(bytes[36..68].try_into().ok()?),
        ObjectDigest::from_bytes(bytes[68..100].try_into().ok()?),
        optional_head(bytes[100..132].try_into().ok()?),
        ObjectDigest::from_bytes(bytes[132..164].try_into().ok()?),
        initial_seed_packet,
    )?;
    match capture {
        None => (record.encode() == bytes).then_some(record),
        Some(capture) => {
            capture.record = Some(record);
            capture.encoded = capture.record.as_ref().map(ClosedTreeLineageRecordV1::encode);
            let accepted = capture.encoded.as_deref() == Some(bytes);
            capture.accepted = Some(accepted);
            if accepted { capture.record.clone() } else { None }
        }
    }
}
