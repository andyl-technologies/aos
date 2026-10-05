//! Canonical first-successor records shared by the three native journals.
//!
//! These fixed-width values are DATA. Decoding, constructing or hashing one
//! supplies neither a held writer nor a current Root, Controller or Source loan.
//! All checksums use `aos.sandbox.source-first-successor.<label>.v2\0`.
//!
//! ```text
//! header16 = magic8 | version:u16be=2 | purpose:u8=1 | native-phase:u8 |
//!            reserved4=0
//! Begin296 / Anchored144 / Complete240: Controller immutable phase records
//! Intent1248 / Floor688: Root admission intent and revision-two semantic floor
//! Receipt536 / Pending256 / Ack192: Source append and exact settlement records
//! Every record ends in checksum32; nested records retain their own checksum.
//! ```

use aos_sandbox_core::{ObjectDigest, ProjectId};

use crate::hierarchy::genesis_profile::{SourceGenesisErrorV1, hash};
use crate::hierarchy::source_successor::SourceSuccessorApprovalDataV2;
use crate::journal::ProtectedJournalNamesV1;

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
record!(RootFirstSourceSuccessorIntentV2, 1248, b"AOSRSI02", 2,
    b"aos.sandbox.source-first-successor.root-intent.v2\0",
    names: ProtectedJournalNamesV1 => |bytes: &[u8]| names_at(bytes, 968),
    packet: SourceSuccessorApprovalDataV2 => |bytes: &[u8]|
        SourceSuccessorApprovalDataV2::from_record_bytes(&bytes[32..928]));
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

pub(crate) struct ControllerFirstSourceSuccessorBeginFieldsV2 {
    pub(crate) approval: ObjectDigest,
    pub(crate) predecessor_floor: ObjectDigest,
    pub(crate) genesis_complete: ObjectDigest,
    pub(crate) old_tree_head: ObjectDigest,
    pub(crate) old_lineage_head: ObjectDigest,
    pub(crate) next_tree_commit: ObjectDigest,
    pub(crate) source_uid: u32,
    pub(crate) source_names: ProtectedJournalNamesV1,
}

impl ControllerFirstSourceSuccessorBeginV2 {
    pub(crate) fn new(fields: ControllerFirstSourceSuccessorBeginFieldsV2)
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

pub(crate) struct ControllerFirstSourceSuccessorAnchoredFieldsV2 {
    pub(crate) approval: ObjectDigest,
    pub(crate) receipt: ObjectDigest,
    pub(crate) floor: ObjectDigest,
}

impl ControllerFirstSourceSuccessorAnchoredV2 {
    pub(crate) fn new(fields: ControllerFirstSourceSuccessorAnchoredFieldsV2)
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

pub(crate) struct ControllerFirstSourceSuccessorCompleteFieldsV2 {
    pub(crate) approval: ObjectDigest,
    pub(crate) receipt: ObjectDigest,
    pub(crate) floor: ObjectDigest,
    pub(crate) ack: ObjectDigest,
    pub(crate) begin: ObjectDigest,
    pub(crate) anchored: ObjectDigest,
}

impl ControllerFirstSourceSuccessorCompleteV2 {
    pub(crate) fn new(fields: ControllerFirstSourceSuccessorCompleteFieldsV2)
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

pub(crate) struct RootFirstSourceSuccessorIntentFieldsV2 {
    pub(crate) nonce: [u8; 16],
    pub(crate) approval: SourceSuccessorApprovalDataV2,
    pub(crate) begin: ObjectDigest,
    pub(crate) source_uid: u32,
    pub(crate) source_names: ProtectedJournalNamesV1,
    pub(crate) predecessor_floor: ObjectDigest,
    pub(crate) predecessor_revision: u64,
    pub(crate) old_tree_head: ObjectDigest,
    pub(crate) old_lineage_head: ObjectDigest,
    pub(crate) next_tree_commit: ObjectDigest,
    pub(crate) roles: ObjectDigest,
    pub(crate) boot: [u8; 16],
    pub(crate) boottime_deadline: u64,
    pub(crate) expires_wall: u64,
}

impl RootFirstSourceSuccessorIntentV2 {
    pub(crate) fn new(fields: RootFirstSourceSuccessorIntentFieldsV2)
        -> Result<Self, SourceGenesisErrorV1>
    {
        let mut bytes = header::<1248>(b"AOSRSI02", 2);
        bytes[16..32].copy_from_slice(&fields.nonce);
        bytes[32..928].copy_from_slice(fields.approval.as_bytes());
        bytes[928..960].copy_from_slice(fields.begin.as_bytes());
        bytes[960..964].copy_from_slice(&fields.source_uid.to_be_bytes());
        bytes[968..1016].copy_from_slice(&fields.source_names.to_bytes());
        bytes[1016..1048].copy_from_slice(fields.predecessor_floor.as_bytes());
        bytes[1048..1056].copy_from_slice(&fields.predecessor_revision.to_be_bytes());
        bytes[1056..1088].copy_from_slice(fields.old_tree_head.as_bytes());
        bytes[1088..1120].copy_from_slice(fields.old_lineage_head.as_bytes());
        bytes[1120..1152].copy_from_slice(fields.next_tree_commit.as_bytes());
        bytes[1152..1184].copy_from_slice(fields.roles.as_bytes());
        bytes[1184..1200].copy_from_slice(&fields.boot);
        bytes[1200..1208].copy_from_slice(&fields.boottime_deadline.to_be_bytes());
        bytes[1208..1216].copy_from_slice(&fields.expires_wall.to_be_bytes());
        finish(&mut bytes, b"aos.sandbox.source-first-successor.root-intent.v2\0");
        Self::decode(&bytes)
    }

    fn validate(&self) -> Result<(), SourceGenesisErrorV1> {
        let approval = self.approval_packet();
        let packet = approval.as_bytes();
        let issued_boottime = u64::from_be_bytes(array_at(packet, 728));
        let validity_ns = u64::from(approval.intent()?.validity_seconds())
            .checked_mul(1_000_000_000).ok_or(SourceGenesisErrorV1::NonCanonical)?;
        let latest_deadline = issued_boottime.checked_add(validity_ns)
            .ok_or(SourceGenesisErrorV1::NonCanonical)?;
        require_nonzero(&self.bytes, &[928, 1016, 1056, 1088, 1120, 1152])?;
        if self.nonce() == [0; 16] || self.source_uid() == 0
            || self.bytes[964..968] != [0; 4] || self.predecessor_revision() != 1
            || self.predecessor_floor().as_bytes() != &packet[144..176]
            || self.old_tree_head().as_bytes() != &packet[536..568]
            || self.old_lineage_head().as_bytes() != &packet[568..600]
            || self.next_tree_commit().as_bytes() != &packet[680..712]
            || self.roles().as_bytes() != &packet[112..144]
            || self.boot() != array_at::<16>(packet, 712)
            || self.boottime_deadline() <= issued_boottime
            || self.boottime_deadline() > latest_deadline
            || self.expires_wall() != u64::from_be_bytes(array_at(packet, 744))
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

    digest_getters!(begin: 928, predecessor_floor: 1016, old_tree_head: 1056,
        old_lineage_head: 1088, next_tree_commit: 1120, roles: 1152);

    /// Returns the selected Source filesystem owner DATA.
    pub fn source_uid(&self) -> u32 { u32::from_be_bytes(array_at(&self.bytes, 960)) }

    /// Returns the original physical name identities.
    pub fn source_names(&self) -> ProtectedJournalNamesV1 {
        self.names
    }

    /// Returns the exact predecessor semantic revision, fixed at one.
    pub fn predecessor_revision(&self) -> u64 { u64::from_be_bytes(array_at(&self.bytes, 1048)) }

    /// Returns the original admission boot identity DATA.
    pub fn boot(&self) -> [u8; 16] { array_at(&self.bytes, 1184) }

    /// Returns the original nonrenewable BOOTTIME deadline DATA.
    pub fn boottime_deadline(&self) -> u64 { u64::from_be_bytes(array_at(&self.bytes, 1200)) }

    /// Returns the unchanged signed wall expiry DATA.
    pub fn expires_wall(&self) -> u64 { u64::from_be_bytes(array_at(&self.bytes, 1208)) }
}

pub(crate) struct SourceFirstSuccessorReceiptFieldsV2 {
    pub(crate) instance: [u8; 32],
    pub(crate) project: ProjectId,
    pub(crate) request: [u8; 16],
    pub(crate) approval: ObjectDigest,
    pub(crate) epoch: u64,
    pub(crate) before_generation: u64,
    pub(crate) after_generation: u64,
    pub(crate) predecessor_floor: ObjectDigest,
    pub(crate) old_tree_head: ObjectDigest,
    pub(crate) old_lineage_head: ObjectDigest,
    pub(crate) old_tree_commit: ObjectDigest,
    pub(crate) next_tree_head: ObjectDigest,
    pub(crate) next_lineage_head: ObjectDigest,
    pub(crate) next_tree_commit: ObjectDigest,
    pub(crate) roles: ObjectDigest,
    pub(crate) begin: ObjectDigest,
    pub(crate) root_intent: ObjectDigest,
    pub(crate) source_names: ProtectedJournalNamesV1,
}

impl SourceFirstSuccessorReceiptV2 {
    pub(crate) fn new(fields: SourceFirstSuccessorReceiptFieldsV2)
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

pub(crate) struct SourceFirstSuccessorPendingFieldsV2 {
    pub(crate) instance: [u8; 32],
    pub(crate) project: ProjectId,
    pub(crate) request: [u8; 16],
    pub(crate) approval: ObjectDigest,
    pub(crate) root_intent: ObjectDigest,
    pub(crate) receipt: ObjectDigest,
    pub(crate) source_names: ProtectedJournalNamesV1,
}

impl SourceFirstSuccessorPendingV2 {
    pub(crate) fn new(fields: SourceFirstSuccessorPendingFieldsV2)
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

pub(crate) struct SourceFirstSuccessorAckFieldsV2 {
    pub(crate) instance: [u8; 32],
    pub(crate) project: ProjectId,
    pub(crate) receipt: ObjectDigest,
    pub(crate) root_floor: ObjectDigest,
    pub(crate) controller_anchored: ObjectDigest,
}

impl SourceFirstSuccessorAckV2 {
    pub(crate) fn new(fields: SourceFirstSuccessorAckFieldsV2)
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

pub(crate) struct RootFirstSourceSuccessorFloorFieldsV2 {
    pub(crate) predecessor_floor: ObjectDigest,
    pub(crate) approval: ObjectDigest,
    pub(crate) receipt: SourceFirstSuccessorReceiptV2,
    pub(crate) roles: ObjectDigest,
}

impl RootFirstSourceSuccessorFloorV2 {
    pub(crate) fn new(fields: RootFirstSourceSuccessorFloorFieldsV2)
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
