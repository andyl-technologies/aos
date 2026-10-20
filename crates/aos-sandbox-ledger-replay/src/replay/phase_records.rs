//! Canonical first-successor records shared by the three native journals.
//!
//! These fixed-width values are DATA. Decoding, constructing or hashing one
//! supplies neither a held writer nor a current Root, Controller or Source loan.
//! Native phase checksums use `aos.sandbox.source-first-successor.<label>.v2\0`;
//! the full-resource Root intent uses its distinct v3 checksum.
//!
//! ```text
//! header16 = magic8 | version:u16be=2 | purpose:u8=1 | native-phase:u8 |
//!            reserved4=0
//! Begin296 / Anchored144 / Complete240: Controller immutable phase records
//! Intent1248 / Floor688: Root admission intent and revision-two semantic floor
//! Resource Intent1424 retains approval1072 with its distinct v3 checksum.
//! Receipt536 / Pending256 / Ack192: Source append and exact settlement records
//! Every record ends in checksum32; nested records retain their own checksum.
//! ```

use aos_sandbox_core::{ObjectDigest, ProjectId};

use crate::data::{SourceSuccessorDataErrorV2 as SourceGenesisErrorV1, hash};
use crate::successor::SourceSuccessorApprovalDataV2;
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;

macro_rules! record {
    ($name:ident, $width:expr, $magic:literal, $phase:expr, $domain:literal
        $(, $field:ident: $field_type:ty => $decoder:expr)*) => {
        /// Retains canonical phase DATA without conferring live authority.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name {
            bytes: [u8; $width],
            $($field: $field_type,)*
        }

        impl $name {
            /// Decodes the exact fixed-purpose record without granting custody.
            ///
            /// # Errors
            /// Rejects changed framing, checksum, sentinels or nested bindings.
            pub fn decode(bytes: &[u8]) -> Result<Self, SourceGenesisErrorV1> {
                require_record(bytes, $magic, $phase, $width, $domain)?;
                let record = Self {
                    bytes: array_at(bytes, 0),
                    $($field: ($decoder)(bytes)?,)*
                };
                record.validate()?;
                Ok(record)
            }

            /// Decodes canonical record DATA using the same sole decoder.
            ///
            /// # Errors
            /// Returns the framing and binding failures from [`Self::decode`].
            pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, SourceGenesisErrorV1> {
                Self::decode(bytes)
            }

            /// Borrows the complete canonical fixed-width representation.
            pub const fn as_bytes(&self) -> &[u8; $width] {
                &self.bytes
            }

            /// Returns the domain-separated record commitment, not currentness.
            pub fn digest(&self) -> ObjectDigest {
                hash($domain, &self.bytes)
            }
        }
    };
}

record!(ControllerFirstSourceSuccessorBeginV2, 296, b"AOSCSB02", 1,
    b"aos.sandbox.source-first-successor.controller-begin.v2\0",
    names: ProtectedJournalNamesV1 => |bytes: &[u8]| names_at(bytes, 216));
record!(ControllerFirstSourceSuccessorAnchoredV2, 144, b"AOSCSH02", 5,
    b"aos.sandbox.source-first-successor.controller-anchored.v2\0");
record!(ControllerFirstSourceSuccessorCompleteV2, 240, b"AOSCSC02", 7,
    b"aos.sandbox.source-first-successor.controller-complete.v2\0");
record!(SourceFirstSuccessorReceiptV2, 536, b"AOSSSR02", 3,
    b"aos.sandbox.source-first-successor.source-receipt.v2\0",
    names: ProtectedJournalNamesV1 => |bytes: &[u8]| names_at(bytes, 456));
record!(SourceFirstSuccessorPendingV2, 256, b"AOSSSN02", 3,
    b"aos.sandbox.source-first-successor.source-pending.v2\0",
    names: ProtectedJournalNamesV1 => |bytes: &[u8]| names_at(bytes, 176));
record!(SourceFirstSuccessorAckV2, 192, b"AOSSSA02", 6,
    b"aos.sandbox.source-first-successor.source-ack.v2\0");
record!(RootFirstSourceSuccessorFloorV2, 688, b"AOSRSF02", 4,
    b"aos.sandbox.source-first-successor.root-floor.v2\0",
    source_receipt: SourceFirstSuccessorReceiptV2 => |bytes: &[u8]|
        SourceFirstSuccessorReceiptV2::decode(&bytes[88..624]));

macro_rules! digest_getters {
    ($($name:ident: $offset:expr),+ $(,)?) => {
        $(
            #[doc = concat!("Returns the canonical `", stringify!($name), "` commitment DATA.")]
            pub fn $name(&self) -> ObjectDigest {
                ObjectDigest::from_bytes(array_at(&self.bytes, $offset))
            }
        )+
    };
}

/// Supplies fixed canonical phase fields without native custody or admission.
pub struct ControllerFirstSourceSuccessorBeginFieldsV2 {
    /// Retains the exact historical `approval` field.
    pub approval: ObjectDigest,
    /// Retains the exact historical `predecessor_floor` field.
    pub predecessor_floor: ObjectDigest,
    /// Retains the exact historical `genesis_complete` field.
    pub genesis_complete: ObjectDigest,
    /// Retains the exact historical `old_tree_head` field.
    pub old_tree_head: ObjectDigest,
    /// Retains the exact historical `old_lineage_head` field.
    pub old_lineage_head: ObjectDigest,
    /// Retains the exact historical `next_tree_commit` field.
    pub next_tree_commit: ObjectDigest,
    /// Retains the exact historical `source_uid` field.
    pub source_uid: u32,
    /// Retains the exact historical `source_names` field.
    pub source_names: ProtectedJournalNamesV1,
}

impl ControllerFirstSourceSuccessorBeginV2 {
    /// Encodes and validates the exact canonical phase fields.
    ///
    /// # Errors
    /// Rejects noncanonical fields and inconsistent fixed crosslinks.
    pub fn new(fields: ControllerFirstSourceSuccessorBeginFieldsV2)
        -> Result<Self, SourceGenesisErrorV1>
    {
        let mut bytes = header::<296>(b"AOSCSB02", 1);
        for (offset, digest) in [
            (16, fields.approval), (48, fields.predecessor_floor),
            (80, fields.genesis_complete), (112, fields.old_tree_head),
            (144, fields.old_lineage_head), (176, fields.next_tree_commit),
        ] {
            bytes[offset..offset + 32].copy_from_slice(digest.as_bytes());
        }
        bytes[208..212].copy_from_slice(&fields.source_uid.to_be_bytes());
        bytes[216..264].copy_from_slice(&fields.source_names.to_bytes());
        finish(&mut bytes, b"aos.sandbox.source-first-successor.controller-begin.v2\0");
        Self::decode(&bytes)
    }

    fn validate(&self) -> Result<(), SourceGenesisErrorV1> {
        require_nonzero(&self.bytes, &[16, 48, 80, 112, 144, 176])?;
        if self.source_uid() == 0 || self.bytes[212..216] != [0; 4] {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        Ok(())
    }

    digest_getters!(approval: 16, predecessor_floor: 48, genesis_complete: 80,
        old_tree_head: 112, old_lineage_head: 144, next_tree_commit: 176);

    /// Returns the actual selected Source filesystem UID DATA.
    pub fn source_uid(&self) -> u32 {
        u32::from_be_bytes(array_at(&self.bytes, 208))
    }

    /// Returns the exact directory, journal and lock identities.
    pub fn source_names(&self) -> ProtectedJournalNamesV1 {
        self.names
    }
}

/// Supplies fixed canonical phase fields without native custody or admission.
pub struct ControllerFirstSourceSuccessorAnchoredFieldsV2 {
    /// Retains the exact historical `approval` field.
    pub approval: ObjectDigest,
    /// Retains the exact historical `receipt` field.
    pub receipt: ObjectDigest,
    /// Retains the exact historical `floor` field.
    pub floor: ObjectDigest,
}

impl ControllerFirstSourceSuccessorAnchoredV2 {
    /// Encodes and validates the exact canonical phase fields.
    ///
    /// # Errors
    /// Rejects noncanonical fields and inconsistent fixed crosslinks.
    pub fn new(fields: ControllerFirstSourceSuccessorAnchoredFieldsV2)
        -> Result<Self, SourceGenesisErrorV1>
    {
        let mut bytes = header::<144>(b"AOSCSH02", 5);
        bytes[16..48].copy_from_slice(fields.approval.as_bytes());
        bytes[48..80].copy_from_slice(fields.receipt.as_bytes());
        bytes[80..112].copy_from_slice(fields.floor.as_bytes());
        finish(&mut bytes, b"aos.sandbox.source-first-successor.controller-anchored.v2\0");
        Self::decode(&bytes)
    }

    fn validate(&self) -> Result<(), SourceGenesisErrorV1> {
        require_nonzero(&self.bytes, &[16, 48, 80])
    }

    digest_getters!(approval: 16, receipt: 48, floor: 80);
}

/// Supplies fixed canonical phase fields without native custody or admission.
pub struct ControllerFirstSourceSuccessorCompleteFieldsV2 {
    /// Retains the exact historical `approval` field.
    pub approval: ObjectDigest,
    /// Retains the exact historical `receipt` field.
    pub receipt: ObjectDigest,
    /// Retains the exact historical `floor` field.
    pub floor: ObjectDigest,
    /// Retains the exact historical `ack` field.
    pub ack: ObjectDigest,
    /// Retains the exact historical `begin` field.
    pub begin: ObjectDigest,
    /// Retains the exact historical `anchored` field.
    pub anchored: ObjectDigest,
}

impl ControllerFirstSourceSuccessorCompleteV2 {
    /// Encodes and validates the exact canonical phase fields.
    ///
    /// # Errors
    /// Rejects noncanonical fields and inconsistent fixed crosslinks.
    pub fn new(fields: ControllerFirstSourceSuccessorCompleteFieldsV2)
        -> Result<Self, SourceGenesisErrorV1>
    {
        let mut bytes = header::<240>(b"AOSCSC02", 7);
        for (offset, digest) in [(16, fields.approval), (48, fields.receipt),
            (80, fields.floor), (112, fields.ack), (144, fields.begin),
            (176, fields.anchored)]
        {
            bytes[offset..offset + 32].copy_from_slice(digest.as_bytes());
        }
        finish(&mut bytes, b"aos.sandbox.source-first-successor.controller-complete.v2\0");
        Self::decode(&bytes)
    }

    fn validate(&self) -> Result<(), SourceGenesisErrorV1> {
        require_nonzero(&self.bytes, &[16, 48, 80, 112, 144, 176])
    }

    digest_getters!(approval: 16, receipt: 48, floor: 80, ack: 112, begin: 144, anchored: 176);
}

/// Supplies fixed canonical phase fields without native custody or admission.
pub struct RootFirstSourceSuccessorIntentFieldsV2 {
    /// Retains the exact historical `nonce` field.
    pub nonce: [u8; 16],
    /// Retains the exact historical `approval` field.
    pub approval: SourceSuccessorApprovalDataV2,
    /// Retains the exact historical `begin` field.
    pub begin: ObjectDigest,
    /// Retains the exact historical `source_uid` field.
    pub source_uid: u32,
    /// Retains the exact historical `source_names` field.
    pub source_names: ProtectedJournalNamesV1,
    /// Retains the exact historical `predecessor_floor` field.
    pub predecessor_floor: ObjectDigest,
    /// Retains the exact historical `predecessor_revision` field.
    pub predecessor_revision: u64,
    /// Retains the exact historical `old_tree_head` field.
    pub old_tree_head: ObjectDigest,
    /// Retains the exact historical `old_lineage_head` field.
    pub old_lineage_head: ObjectDigest,
    /// Retains the exact historical `next_tree_commit` field.
    pub next_tree_commit: ObjectDigest,
    /// Retains the exact historical `roles` field.
    pub roles: ObjectDigest,
    /// Retains the exact historical `boot` field.
    pub boot: [u8; 16],
    /// Retains the exact historical `boottime_deadline` field.
    pub boottime_deadline: u64,
    /// Retains the exact historical `expires_wall` field.
    pub expires_wall: u64,
}

const ROOT_INTENT_DOMAIN_V2: &[u8] = b"aos.sandbox.source-first-successor.root-intent.v2\0";
const ROOT_INTENT_DOMAIN_V3: &[u8] = b"aos.sandbox.source-first-successor.root-intent.v3\0";

/// Retains canonical original admission DATA without constructing a live loan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootFirstSourceSuccessorIntentV2 {
    bytes: Vec<u8>,
    names: ProtectedJournalNamesV1,
    packet: SourceSuccessorApprovalDataV2,
}

impl RootFirstSourceSuccessorIntentV2 {
    /// Decodes an exact legacy or full-resource original admission record.
    ///
    /// # Errors
    /// Rejects foreign widths, purpose, checksum, approval recipe or bindings.
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceGenesisErrorV1> {
        let resource = bytes.len() == 1424;
        let magic: &[u8; 8] = if resource { b"AOSRSI03" } else { b"AOSRSI02" };
        let domain = if resource { ROOT_INTENT_DOMAIN_V3 } else { ROOT_INTENT_DOMAIN_V2 };
        if (!resource && bytes.len() != 1248) || bytes.get(..8) != Some(magic.as_slice())
            || bytes[8..10] != (if resource { 3_u16 } else { 2 }).to_be_bytes()
            || bytes[10..16] != [1, 2, 0, 0, 0, 0]
            || hash(domain, &bytes[..bytes.len() - 32]).as_bytes() != &bytes[bytes.len() - 32..]
        {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        let joins = bytes.len() - 320;
        let packet = SourceSuccessorApprovalDataV2::from_record_bytes(&bytes[32..joins])?;
        if packet.has_resource_authorization() != resource {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        let record = Self {
            bytes: bytes.to_vec(), names: names_at(bytes, joins + 40)?, packet,
        };
        record.validate()?;
        Ok(record)
    }

    /// Decodes canonical DATA using the same sole record decoder.
    ///
    /// # Errors
    /// Returns the framing and binding failures from [`Self::decode`].
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, SourceGenesisErrorV1> {
        Self::decode(bytes)
    }

    /// Borrows the complete canonical record, never current admission.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the version-separated commitment of original admission DATA.
    pub fn digest(&self) -> ObjectDigest {
        let domain = if self.packet.has_resource_authorization() { ROOT_INTENT_DOMAIN_V3 } else { ROOT_INTENT_DOMAIN_V2 };
        hash(domain, &self.bytes)
    }

    fn joins_offset(&self) -> usize {
        self.bytes.len() - 320
    }

    /// Encodes and validates the exact canonical phase fields.
    ///
    /// # Errors
    /// Rejects noncanonical fields and inconsistent fixed crosslinks.
    pub fn new(fields: RootFirstSourceSuccessorIntentFieldsV2)
        -> Result<Self, SourceGenesisErrorV1>
    {
        let resource = fields.approval.has_resource_authorization();
        let joins = 32 + fields.approval.as_bytes().len();
        let mut bytes = vec![0; joins + 320];
        bytes[..8].copy_from_slice(if resource { b"AOSRSI03" } else { b"AOSRSI02" });
        bytes[8..10].copy_from_slice(&(if resource { 3_u16 } else { 2 }).to_be_bytes());
        bytes[10] = 1;
        bytes[11] = 2;
        bytes[16..32].copy_from_slice(&fields.nonce);
        bytes[32..joins].copy_from_slice(fields.approval.as_bytes());
        bytes[joins..joins + 32].copy_from_slice(fields.begin.as_bytes());
        bytes[joins + 32..joins + 36].copy_from_slice(&fields.source_uid.to_be_bytes());
        bytes[joins + 40..joins + 88].copy_from_slice(&fields.source_names.to_bytes());
        bytes[joins + 88..joins + 120].copy_from_slice(fields.predecessor_floor.as_bytes());
        bytes[joins + 120..joins + 128].copy_from_slice(&fields.predecessor_revision.to_be_bytes());
        bytes[joins + 128..joins + 160].copy_from_slice(fields.old_tree_head.as_bytes());
        bytes[joins + 160..joins + 192].copy_from_slice(fields.old_lineage_head.as_bytes());
        bytes[joins + 192..joins + 224].copy_from_slice(fields.next_tree_commit.as_bytes());
        bytes[joins + 224..joins + 256].copy_from_slice(fields.roles.as_bytes());
        bytes[joins + 256..joins + 272].copy_from_slice(&fields.boot);
        bytes[joins + 272..joins + 280].copy_from_slice(&fields.boottime_deadline.to_be_bytes());
        bytes[joins + 280..joins + 288].copy_from_slice(&fields.expires_wall.to_be_bytes());
        finish(&mut bytes, if resource { ROOT_INTENT_DOMAIN_V3 } else { ROOT_INTENT_DOMAIN_V2 });
        Self::decode(&bytes)
    }

    fn validate(&self) -> Result<(), SourceGenesisErrorV1> {
        let approval = self.approval_packet();
        let packet = approval.as_bytes();
        let issued_boottime = approval.issued_boottime()?;
        let validity_ns = u64::from(approval.intent()?.validity_seconds())
            .checked_mul(1_000_000_000).ok_or(SourceGenesisErrorV1::NonCanonical)?;
        let latest_deadline = issued_boottime.checked_add(validity_ns)
            .ok_or(SourceGenesisErrorV1::NonCanonical)?;
        let joins = self.joins_offset();
        require_nonzero(&self.bytes, &[joins, joins + 88, joins + 128, joins + 160, joins + 192, joins + 224])?;
        if self.nonce() == [0; 16] || self.source_uid() == 0
            || self.bytes[joins + 36..joins + 40] != [0; 4] || self.predecessor_revision() != 1
            || self.predecessor_floor().as_bytes() != &packet[144..176]
            || self.old_tree_head() != approval.old_tree_head()
            || self.old_lineage_head() != approval.old_lineage_head()
            || self.next_tree_commit() != approval.next_tree_commit()
            || self.roles().as_bytes() != &packet[112..144]
            || self.boot() != approval.boot()?
            || self.boottime_deadline() <= issued_boottime
            || self.boottime_deadline() > latest_deadline
            || self.expires_wall() != approval.expires_wall()?
        {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        Ok(())
    }

    /// Returns the original durable admission nonce, not a recovery nonce.
    pub fn nonce(&self) -> [u8; 16] { array_at(&self.bytes, 16) }

    /// Borrows the complete approval decoded by its sole codec.
    pub const fn approval_packet(&self) -> &SourceSuccessorApprovalDataV2 {
        &self.packet
    }

    /// Returns the commitment of the complete retained approval DATA.
    pub fn approval(&self) -> ObjectDigest {
        self.packet.digest()
    }

    /// Returns the Root-created instance in the retained approval.
    pub fn instance(&self) -> [u8; 32] { array_at(&self.bytes, 64) }

    /// Returns the original approved project selector DATA.
    pub fn project(&self) -> ProjectId { ProjectId::from_bytes(array_at(&self.bytes, 96)) }

    /// Returns the exact administrative request identity DATA.
    pub fn request(&self) -> [u8; 16] { array_at(&self.bytes, 112) }

    /// Returns the immutable administrative epoch DATA.
    pub fn epoch(&self) -> u64 { u64::from_be_bytes(array_at(&self.bytes, 56)) }

    /// Returns the original native Controller Begin commitment DATA.
    pub fn begin(&self) -> ObjectDigest { ObjectDigest::from_bytes(array_at(&self.bytes, self.joins_offset())) }

    /// Returns the exact predecessor floor commitment DATA.
    pub fn predecessor_floor(&self) -> ObjectDigest { ObjectDigest::from_bytes(array_at(&self.bytes, self.joins_offset() + 88)) }

    /// Returns the approved predecessor Tree head commitment DATA.
    pub fn old_tree_head(&self) -> ObjectDigest { ObjectDigest::from_bytes(array_at(&self.bytes, self.joins_offset() + 128)) }

    /// Returns the approved predecessor lineage head commitment DATA.
    pub fn old_lineage_head(&self) -> ObjectDigest { ObjectDigest::from_bytes(array_at(&self.bytes, self.joins_offset() + 160)) }

    /// Returns the approved successor Tree body commitment DATA.
    pub fn next_tree_commit(&self) -> ObjectDigest { ObjectDigest::from_bytes(array_at(&self.bytes, self.joins_offset() + 192)) }

    /// Returns the independently retained administrative roles commitment DATA.
    pub fn roles(&self) -> ObjectDigest { ObjectDigest::from_bytes(array_at(&self.bytes, self.joins_offset() + 224)) }

    /// Returns the selected Source filesystem owner DATA.
    pub fn source_uid(&self) -> u32 { u32::from_be_bytes(array_at(&self.bytes, self.joins_offset() + 32)) }

    /// Returns the original physical name identities.
    pub fn source_names(&self) -> ProtectedJournalNamesV1 {
        self.names
    }

    /// Returns the exact predecessor semantic revision, fixed at one.
    pub fn predecessor_revision(&self) -> u64 { u64::from_be_bytes(array_at(&self.bytes, self.joins_offset() + 120)) }

    /// Returns the original admission boot identity DATA.
    pub fn boot(&self) -> [u8; 16] { array_at(&self.bytes, self.joins_offset() + 256) }

    /// Returns the original nonrenewable BOOTTIME deadline DATA.
    pub fn boottime_deadline(&self) -> u64 { u64::from_be_bytes(array_at(&self.bytes, self.joins_offset() + 272)) }

    /// Returns the unchanged signed wall expiry DATA.
    pub fn expires_wall(&self) -> u64 { u64::from_be_bytes(array_at(&self.bytes, self.joins_offset() + 280)) }
}

/// Supplies fixed canonical phase fields without native custody or admission.
pub struct SourceFirstSuccessorReceiptFieldsV2 {
    /// Retains the exact historical `instance` field.
    pub instance: [u8; 32],
    /// Retains the exact historical `project` field.
    pub project: ProjectId,
    /// Retains the exact historical `request` field.
    pub request: [u8; 16],
    /// Retains the exact historical `approval` field.
    pub approval: ObjectDigest,
    /// Retains the exact historical `epoch` field.
    pub epoch: u64,
    /// Retains the exact historical `before_generation` field.
    pub before_generation: u64,
    /// Retains the exact historical `after_generation` field.
    pub after_generation: u64,
    /// Retains the exact historical `predecessor_floor` field.
    pub predecessor_floor: ObjectDigest,
    /// Retains the exact historical `old_tree_head` field.
    pub old_tree_head: ObjectDigest,
    /// Retains the exact historical `old_lineage_head` field.
    pub old_lineage_head: ObjectDigest,
    /// Retains the exact historical `old_tree_commit` field.
    pub old_tree_commit: ObjectDigest,
    /// Retains the exact historical `next_tree_head` field.
    pub next_tree_head: ObjectDigest,
    /// Retains the exact historical `next_lineage_head` field.
    pub next_lineage_head: ObjectDigest,
    /// Retains the exact historical `next_tree_commit` field.
    pub next_tree_commit: ObjectDigest,
    /// Retains the exact historical `roles` field.
    pub roles: ObjectDigest,
    /// Retains the exact historical `begin` field.
    pub begin: ObjectDigest,
    /// Retains the exact historical `root_intent` field.
    pub root_intent: ObjectDigest,
    /// Retains the exact historical `source_names` field.
    pub source_names: ProtectedJournalNamesV1,
}

impl SourceFirstSuccessorReceiptV2 {
    /// Encodes and validates the exact canonical phase fields.
    ///
    /// # Errors
    /// Rejects noncanonical fields and inconsistent fixed crosslinks.
    pub fn new(fields: SourceFirstSuccessorReceiptFieldsV2)
        -> Result<Self, SourceGenesisErrorV1>
    {
        let mut bytes = header::<536>(b"AOSSSR02", 3);
        bytes[16..48].copy_from_slice(&fields.instance);
        bytes[48..64].copy_from_slice(fields.project.as_bytes());
        bytes[64..80].copy_from_slice(&fields.request);
        bytes[80..112].copy_from_slice(fields.approval.as_bytes());
        bytes[112..120].copy_from_slice(&fields.epoch.to_be_bytes());
        bytes[120..128].copy_from_slice(&fields.before_generation.to_be_bytes());
        bytes[128..136].copy_from_slice(&fields.after_generation.to_be_bytes());
        for (offset, digest) in [
            (136, fields.predecessor_floor), (168, fields.old_tree_head),
            (200, fields.old_lineage_head), (232, fields.old_tree_commit),
            (264, fields.next_tree_head), (296, fields.next_lineage_head),
            (328, fields.next_tree_commit), (360, fields.roles),
            (392, fields.begin), (424, fields.root_intent),
        ] {
            bytes[offset..offset + 32].copy_from_slice(digest.as_bytes());
        }
        bytes[456..504].copy_from_slice(&fields.source_names.to_bytes());
        finish(&mut bytes, b"aos.sandbox.source-first-successor.source-receipt.v2\0");
        Self::decode(&bytes)
    }

    fn validate(&self) -> Result<(), SourceGenesisErrorV1> {
        require_nonzero(&self.bytes, &[16, 80, 136, 168, 200, 232, 264, 296, 328, 360, 392, 424])?;
        if self.project().as_bytes() == &[0; 16] || self.request() == [0; 16]
            || self.epoch() == 0 || self.before_generation() != 1 || self.after_generation() != 2
            || self.old_tree_head() == self.next_tree_head()
            || self.old_lineage_head() == self.next_lineage_head()
            || self.old_tree_commit() == self.next_tree_commit()
        {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        Ok(())
    }

    /// Returns the original Root-created deployment instance DATA.
    pub fn instance(&self) -> [u8; 32] { array_at(&self.bytes, 16) }

    /// Returns the approved project selector DATA.
    pub fn project(&self) -> ProjectId { ProjectId::from_bytes(array_at(&self.bytes, 48)) }

    /// Returns the original approved request identity DATA.
    pub fn request(&self) -> [u8; 16] { array_at(&self.bytes, 64) }

    /// Returns the original administrative epoch DATA.
    pub fn epoch(&self) -> u64 { u64::from_be_bytes(array_at(&self.bytes, 112)) }

    /// Returns the exact predecessor Tree generation, fixed at one.
    pub fn before_generation(&self) -> u64 { u64::from_be_bytes(array_at(&self.bytes, 120)) }

    /// Returns the exact successor Tree generation, fixed at two.
    pub fn after_generation(&self) -> u64 { u64::from_be_bytes(array_at(&self.bytes, 128)) }

    digest_getters!(approval: 80, predecessor_floor: 136, old_tree_head: 168,
        old_lineage_head: 200, old_tree_commit: 232, next_tree_head: 264,
        next_lineage_head: 296, next_tree_commit: 328, roles: 360, begin: 392, root_intent: 424);

    /// Returns the exact Source directory, journal and lock identities.
    pub fn source_names(&self) -> ProtectedJournalNamesV1 {
        self.names
    }
}

/// Supplies fixed canonical phase fields without native custody or admission.
pub struct SourceFirstSuccessorPendingFieldsV2 {
    /// Retains the exact historical `instance` field.
    pub instance: [u8; 32],
    /// Retains the exact historical `project` field.
    pub project: ProjectId,
    /// Retains the exact historical `request` field.
    pub request: [u8; 16],
    /// Retains the exact historical `approval` field.
    pub approval: ObjectDigest,
    /// Retains the exact historical `root_intent` field.
    pub root_intent: ObjectDigest,
    /// Retains the exact historical `receipt` field.
    pub receipt: ObjectDigest,
    /// Retains the exact historical `source_names` field.
    pub source_names: ProtectedJournalNamesV1,
}

impl SourceFirstSuccessorPendingV2 {
    /// Encodes and validates the exact canonical phase fields.
    ///
    /// # Errors
    /// Rejects noncanonical fields and inconsistent fixed crosslinks.
    pub fn new(fields: SourceFirstSuccessorPendingFieldsV2)
        -> Result<Self, SourceGenesisErrorV1>
    {
        let mut bytes = header::<256>(b"AOSSSN02", 3);
        bytes[16..48].copy_from_slice(&fields.instance);
        bytes[48..64].copy_from_slice(fields.project.as_bytes());
        bytes[64..80].copy_from_slice(&fields.request);
        bytes[80..112].copy_from_slice(fields.approval.as_bytes());
        bytes[112..144].copy_from_slice(fields.root_intent.as_bytes());
        bytes[144..176].copy_from_slice(fields.receipt.as_bytes());
        bytes[176..224].copy_from_slice(&fields.source_names.to_bytes());
        finish(&mut bytes, b"aos.sandbox.source-first-successor.source-pending.v2\0");
        Self::decode(&bytes)
    }

    fn validate(&self) -> Result<(), SourceGenesisErrorV1> {
        require_nonzero(&self.bytes, &[16, 80, 112, 144])?;
        if self.project().as_bytes() == &[0; 16] || self.request() == [0; 16] {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        Ok(())
    }

    /// Returns the original deployment instance DATA.
    pub fn instance(&self) -> [u8; 32] { array_at(&self.bytes, 16) }

    /// Returns the original project selector DATA.
    pub fn project(&self) -> ProjectId { ProjectId::from_bytes(array_at(&self.bytes, 48)) }

    /// Returns the exact request identity DATA.
    pub fn request(&self) -> [u8; 16] { array_at(&self.bytes, 64) }

    digest_getters!(approval: 80, root_intent: 112, receipt: 144);

    /// Returns the retained Source physical name identities.
    pub fn source_names(&self) -> ProtectedJournalNamesV1 {
        self.names
    }
}

/// Supplies fixed canonical phase fields without native custody or admission.
pub struct SourceFirstSuccessorAckFieldsV2 {
    /// Retains the exact historical `instance` field.
    pub instance: [u8; 32],
    /// Retains the exact historical `project` field.
    pub project: ProjectId,
    /// Retains the exact historical `receipt` field.
    pub receipt: ObjectDigest,
    /// Retains the exact historical `root_floor` field.
    pub root_floor: ObjectDigest,
    /// Retains the exact historical `controller_anchored` field.
    pub controller_anchored: ObjectDigest,
}

impl SourceFirstSuccessorAckV2 {
    /// Encodes and validates the exact canonical phase fields.
    ///
    /// # Errors
    /// Rejects noncanonical fields and inconsistent fixed crosslinks.
    pub fn new(fields: SourceFirstSuccessorAckFieldsV2)
        -> Result<Self, SourceGenesisErrorV1>
    {
        let mut bytes = header::<192>(b"AOSSSA02", 6);
        bytes[16..48].copy_from_slice(&fields.instance);
        bytes[48..64].copy_from_slice(fields.project.as_bytes());
        bytes[64..96].copy_from_slice(fields.receipt.as_bytes());
        bytes[96..128].copy_from_slice(fields.root_floor.as_bytes());
        bytes[128..160].copy_from_slice(fields.controller_anchored.as_bytes());
        finish(&mut bytes, b"aos.sandbox.source-first-successor.source-ack.v2\0");
        Self::decode(&bytes)
    }

    fn validate(&self) -> Result<(), SourceGenesisErrorV1> {
        require_nonzero(&self.bytes, &[16, 64, 96, 128])?;
        if self.project().as_bytes() == &[0; 16] {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        Ok(())
    }

    /// Returns the original Root-created deployment instance DATA.
    pub fn instance(&self) -> [u8; 32] { array_at(&self.bytes, 16) }

    /// Returns the exact settled project selector DATA.
    pub fn project(&self) -> ProjectId { ProjectId::from_bytes(array_at(&self.bytes, 48)) }

    digest_getters!(receipt: 64, root_floor: 96, controller_anchored: 128);
}

/// Supplies fixed canonical phase fields without native custody or admission.
pub struct RootFirstSourceSuccessorFloorFieldsV2 {
    /// Retains the exact historical `predecessor_floor` field.
    pub predecessor_floor: ObjectDigest,
    /// Retains the exact historical `approval` field.
    pub approval: ObjectDigest,
    /// Retains the exact historical `receipt` field.
    pub receipt: SourceFirstSuccessorReceiptV2,
    /// Retains the exact historical `roles` field.
    pub roles: ObjectDigest,
}

impl RootFirstSourceSuccessorFloorV2 {
    /// Encodes and validates the exact canonical phase fields.
    ///
    /// # Errors
    /// Rejects noncanonical fields and inconsistent fixed crosslinks.
    pub fn new(fields: RootFirstSourceSuccessorFloorFieldsV2)
        -> Result<Self, SourceGenesisErrorV1>
    {
        let mut bytes = header::<688>(b"AOSRSF02", 4);
        bytes[16..24].copy_from_slice(&2_u64.to_be_bytes());
        bytes[24..56].copy_from_slice(fields.predecessor_floor.as_bytes());
        bytes[56..88].copy_from_slice(fields.approval.as_bytes());
        bytes[88..624].copy_from_slice(fields.receipt.as_bytes());
        bytes[624..656].copy_from_slice(fields.roles.as_bytes());
        finish(&mut bytes, b"aos.sandbox.source-first-successor.root-floor.v2\0");
        Self::decode(&bytes)
    }

    fn validate(&self) -> Result<(), SourceGenesisErrorV1> {
        let receipt = self.receipt();
        require_nonzero(&self.bytes, &[24, 56, 624])?;
        if self.semantic_revision() != 2 || receipt.predecessor_floor() != self.predecessor_floor()
            || receipt.approval() != self.approval() || receipt.roles() != self.roles()
        {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        Ok(())
    }

    /// Borrows the exact immutable receipt decoded by its sole codec.
    pub const fn receipt(&self) -> &SourceFirstSuccessorReceiptV2 {
        &self.source_receipt
    }

    /// Returns the original immutable Source receipt commitment.
    pub fn receipt_digest(&self) -> ObjectDigest {
        self.source_receipt.digest()
    }

    /// Returns the exact semantic revision, never a frame count.
    pub fn semantic_revision(&self) -> u64 { u64::from_be_bytes(array_at(&self.bytes, 16)) }

    /// Returns the original deployment instance in the nested receipt DATA.
    pub fn instance(&self) -> [u8; 32] { array_at(&self.bytes, 104) }

    /// Returns the project in the complete nested receipt DATA.
    pub fn project(&self) -> ProjectId { ProjectId::from_bytes(array_at(&self.bytes, 136)) }

    digest_getters!(predecessor_floor: 24, approval: 56, roles: 624);
}

fn header<const N: usize>(magic: &[u8; 8], phase: u8) -> [u8; N] {
    let mut bytes = [0; N];
    bytes[..8].copy_from_slice(magic);
    bytes[8..10].copy_from_slice(&2_u16.to_be_bytes());
    bytes[10] = 1;
    bytes[11] = phase;
    bytes
}

fn finish(bytes: &mut [u8], domain: &[u8]) {
    let end = bytes.len() - 32;
    let checksum = hash(domain, &bytes[..end]);
    bytes[end..].copy_from_slice(checksum.as_bytes());
}

fn require_record(bytes: &[u8], magic: &[u8; 8], phase: u8, width: usize, domain: &[u8])
    -> Result<(), SourceGenesisErrorV1>
{
    if bytes.len() != width || bytes.get(..8) != Some(magic.as_slice())
        || bytes[8..10] != 2_u16.to_be_bytes() || bytes[10] != 1 || bytes[11] != phase
        || bytes[12..16] != [0; 4]
        || hash(domain, &bytes[..width - 32]).as_bytes() != &bytes[width - 32..]
    {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    Ok(())
}

fn require_nonzero(bytes: &[u8], offsets: &[usize]) -> Result<(), SourceGenesisErrorV1> {
    if offsets.iter().any(|offset| bytes[*offset..*offset + 32] == [0; 32]) {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    Ok(())
}

fn array_at<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut value = [0; N];
    value.copy_from_slice(&bytes[offset..offset + N]);
    value
}

fn names_at(bytes: &[u8], offset: usize) -> Result<ProtectedJournalNamesV1, SourceGenesisErrorV1> {
    ProtectedJournalNamesV1::from_bytes(&bytes[offset..offset + 48])
        .map_err(|_| SourceGenesisErrorV1::NonCanonical)
}

/// Bounds the fixed Source phase codec's consuming stack and returned values.
///
/// The closed family uses fixed arrays, fixed DTOs and SHA-256 state. The
/// surrounding Native original retains raw input and its actual returned error;
/// transient validation controls create no resident namespace metadata entries.
pub fn first_source_successor_fixed_codec_peak_bytes_v1() -> Option<usize> {
    use std::mem::size_of;

    // Four conservative model planes cover the returned record, enclosing
    // comparison guard, constructor input and nested fixed decoder. The five
    // actual record types also cover the earlier Pending-only selector.
    let models = size_of::<SourceFirstSuccessorPendingV2>()
        .checked_add(size_of::<SourceFirstSuccessorReceiptV2>())?
        .checked_add(size_of::<SourceFirstSuccessorAckV2>())?
        .checked_add(size_of::<RootFirstSourceSuccessorFloorV2>())?
        .checked_add(size_of::<ControllerFirstSourceSuccessorAnchoredV2>())?;
    let results = size_of::<Result<SourceFirstSuccessorPendingV2, SourceGenesisErrorV1>>()
        .checked_add(size_of::<Result<SourceFirstSuccessorReceiptV2, SourceGenesisErrorV1>>())?
        .checked_add(size_of::<Result<SourceFirstSuccessorAckV2, SourceGenesisErrorV1>>())?
        .checked_add(size_of::<Result<RootFirstSourceSuccessorFloorV2, SourceGenesisErrorV1>>())?
        .checked_add(size_of::<Result<ControllerFirstSourceSuccessorAnchoredV2, SourceGenesisErrorV1>>())?;
    let arrays = size_of::<[u8; 256]>()
        .checked_add(size_of::<[u8; 536]>())?
        .checked_add(size_of::<[u8; 192]>())?
        .checked_add(size_of::<[u8; 688]>())?
        .checked_add(size_of::<[u8; 144]>())?;

    models.checked_mul(4)?
        .checked_add(results.checked_mul(2)?)?
        .checked_add(arrays.checked_mul(2)?)?
        .checked_add(size_of::<RootFirstSourceSuccessorFloorFieldsV2>().checked_mul(2)?)?
        .checked_add(size_of::<ControllerFirstSourceSuccessorAnchoredFieldsV2>().checked_mul(2)?)?
        .checked_add(size_of::<ProtectedJournalNamesV1>().checked_mul(4)?)?
        .checked_add(size_of::<sha2::Sha256>().checked_mul(2)?)?
        .checked_add(size_of::<[ObjectDigest; 3]>().checked_mul(2)?)?
        .checked_add(size_of::<[usize; 12]>().checked_mul(2)?)?
        .checked_add(size_of::<[usize; 32]>())?
        .checked_add(size_of::<std::slice::Iter<'static, usize>>().checked_mul(2)?)?
        .checked_add(size_of::<[&'static [u8]; 16]>())
}

#[cfg(test)]
mod fixed_codec_tests {
    use super::*;

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    fn receipt() -> SourceFirstSuccessorReceiptV2 {
        SourceFirstSuccessorReceiptV2::new(SourceFirstSuccessorReceiptFieldsV2 {
            instance: [1; 32], project: ProjectId::from_bytes([2; 16]), request: [3; 16],
            approval: digest(4), epoch: 1, before_generation: 1, after_generation: 2,
            predecessor_floor: digest(5), old_tree_head: digest(6), old_lineage_head: digest(7),
            old_tree_commit: digest(8), next_tree_head: digest(9), next_lineage_head: digest(10),
            next_tree_commit: digest(11), roles: digest(12), begin: digest(13), root_intent: digest(14),
            source_names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (1, 3), (1, 4)),
        }).unwrap()
    }

    fn floor_fields(receipt: SourceFirstSuccessorReceiptV2) -> RootFirstSourceSuccessorFloorFieldsV2 {
        RootFirstSourceSuccessorFloorFieldsV2 {
            predecessor_floor: receipt.predecessor_floor(), approval: receipt.approval(),
            roles: receipt.roles(), receipt,
        }
    }

    #[test]
    fn consuming_codec_rejects_a_bad_project_with_a_valid_checksum() {
        let mut bytes = *receipt().as_bytes();
        bytes[48..64].fill(0);
        finish(&mut bytes, b"aos.sandbox.source-first-successor.source-receipt.v2\0");

        assert!(matches!(SourceFirstSuccessorReceiptV2::decode(&bytes), Err(SourceGenesisErrorV1::NonCanonical)));
    }

    #[test]
    fn consuming_floor_decoder_checks_the_nested_receipt_names() {
        let floor = RootFirstSourceSuccessorFloorV2::new(floor_fields(receipt())).unwrap();
        let mut bytes = *floor.as_bytes();
        bytes[88 + 496..88 + 504].fill(0);
        finish(&mut bytes[88..624], b"aos.sandbox.source-first-successor.source-receipt.v2\0");
        finish(&mut bytes, b"aos.sandbox.source-first-successor.root-floor.v2\0");

        assert!(matches!(RootFirstSourceSuccessorFloorV2::decode(&bytes), Err(SourceGenesisErrorV1::NonCanonical)));
    }

    #[test]
    fn consuming_constructor_preserves_its_exact_binding_refusal_and_roundtrip() {
        let receipt = receipt();
        let mut fields = floor_fields(receipt.clone());
        fields.predecessor_floor = digest(23);

        assert!(matches!(RootFirstSourceSuccessorFloorV2::new(fields), Err(SourceGenesisErrorV1::NonCanonical)));
        let floor = RootFirstSourceSuccessorFloorV2::new(floor_fields(receipt)).unwrap();
        assert_eq!(RootFirstSourceSuccessorFloorV2::decode(floor.as_bytes()).unwrap(), floor);
        assert!(first_source_successor_fixed_codec_peak_bytes_v1().is_some());
    }
}
