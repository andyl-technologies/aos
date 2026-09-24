//! Sealed Storage-to-KernelExportGrant deny-stage handoff contract.
//!
//! ```text
//! AOSKGH01 | version:u16be=1 | phase:u8=1 | reserved[5]=0 |
//! handoff-id[32] | provider-id[16] | provider-generation:u64be |
//! plan-id[16] | signed-plan-digest[32] | signed-root-digest[32] |
//! storage-readback-digest[32] | clone-journal-sequence:u64be |
//! active-clone-record-digest[32] | boot-id[16] |
//! clone-mount-id:u64be | root-device:u64be | root-inode:u64be |
//! holder-id[16] | holder-generation:u64be | holder-digest[32] |
//! consumer-cgroup-kernfs-id:u64be | grant-epoch:u64be=0 |
//! exclusive-expiry-seconds:i64be
//! SCM_RIGHTS = [detached read-only clone O_PATH, consumer cgroup-v2 O_PATH]
//! ```
//!
//! The fixed 344-byte frame is a nonauthorizing stage request. Its handoff ID
//! commits every subsequent field, but is not a signature. The receiver must
//! authenticate Storage's live service subject, re-read both descriptors,
//! validate protected clone/current-assignment evidence, and install a
//! default-deny map before returning a separate protected readback. No owner
//! endpoint or authenticated Host/Guardian consumer-cgroup producer is wired
//! yet, so the consumer witness has no production constructor and no FD-send
//! operation exists. Provider ingress cannot reach this interface.
//! The journal sequence plus active-row digest is an exact Storage snapshot
//! commitment, not a transferable cryptographic journal-head signature.

use std::time::{SystemTime, UNIX_EPOCH};

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use sha2::{Digest as _, Sha256};

use crate::live_export_clone::{
    StorageCloneActiveRecordV2, StorageLiveExportCloneErrorV1, StorageLiveExportCloneLedgerV1,
    StorageLiveExportCloneV1,
};
use crate::live_export_request_readback::StorageLiveExportReadbackV1;

const MAGIC: &[u8; 8] = b"AOSKGH01";
const VERSION: u16 = 1;
const DENY_STAGE: u8 = 1;
const FRAME_BYTES: usize = 344;
const HANDOFF_ID_DOMAIN: &[u8] = b"aos.sandbox.storage.kernel-export-deny-handoff.v1\0";
const CLONE_RECORD_DOMAIN: &[u8] = b"aos.sandbox.storage.active-clone-record.v2\0";

/// Reports an ineligible, stale, or transport-uncertain private handoff.
#[derive(Debug, thiserror::Error)]
pub(crate) enum StorageGrantHandoffErrorV1 {
    /// The frame or a bound authority identity is not canonical.
    #[error("Storage grant deny-stage handoff is noncanonical")]
    Noncanonical,
    /// The retained clone or its protected journal changed.
    #[error("Storage grant deny-stage clone changed: {0}")]
    Clone(#[from] StorageLiveExportCloneErrorV1),
    /// The protected consumer-cgroup witness is no longer current.
    #[error("Storage grant deny-stage consumer cgroup is unavailable")]
    Consumer,
}

/// Retains a joined Host/Guardian cgroup and signed RootMount consumer binding.
///
/// Host owns current physical assignment; RootMount owns the named consumer
/// claim. The missing cross-owner join is deliberately not replaced by a
/// constructor accepting a path, FD, or scalar ID. Future production code must
/// add that independently authenticated join before this type can exist.
pub(crate) struct ProtectedConsumerCgroupV1 {
    anchor: RetainedCgroupAnchor,
    holder_id: [u8; 16],
    holder_generation: u64,
    holder_digest: ObjectDigest,
    signed_root_digest: ObjectDigest,
    plan_id: [u8; 16],
    expires_seconds: i64,
}

impl ProtectedConsumerCgroupV1 {
    fn validate_for(
        &self,
        readback: &StorageLiveExportReadbackV1,
    ) -> Result<(), StorageGrantHandoffErrorV1> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StorageGrantHandoffErrorV1::Consumer)?;
        let now = i64::try_from(now.as_secs()).map_err(|_| StorageGrantHandoffErrorV1::Consumer)?;
        let (holder_id, holder_generation, holder_digest) = readback.holder_binding();
        let (_, _, plan_id) = readback.replay_identity();
        if self.holder_id != holder_id
            || self.holder_generation != holder_generation
            || self.holder_digest != holder_digest
            || self.signed_root_digest != readback.signed_root_request_digest()
            || self.plan_id != plan_id
            || self.expires_seconds <= 0
            || self.expires_seconds > readback.expires_seconds()
            || now >= self.expires_seconds
            || self.anchor.kernel_id() == 0
        {
            return Err(StorageGrantHandoffErrorV1::Consumer);
        }
        self.anchor
            .validate_current()
            .map_err(|_| StorageGrantHandoffErrorV1::Consumer)
    }
}

/// Owns only canonical deny-stage bytes, not a lease or a grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StorageDenyStageFrameV1 {
    bytes: [u8; FRAME_BYTES],
}

impl StorageDenyStageFrameV1 {
    /// Binds current protected Storage and Host observations without exporting FDs.
    pub(crate) fn prepare(
        clone: &StorageLiveExportCloneV1,
        ledger: &mut StorageLiveExportCloneLedgerV1,
        readback: &StorageLiveExportReadbackV1,
        consumer: &ProtectedConsumerCgroupV1,
    ) -> Result<Self, StorageGrantHandoffErrorV1> {
        consumer.validate_for(readback)?;
        let record = clone.active_record(ledger)?;
        let (provider_id, provider_generation, plan_id) = readback.replay_identity();
        if record.key[..16] != provider_id
            || record.key[16..24] != provider_generation.to_be_bytes()
            || record.key[24..40] != plan_id
            || record.value[16..48] != *readback.digest().as_bytes()
        {
            return Err(StorageGrantHandoffErrorV1::Noncanonical);
        }

        Self::encode(
            &record,
            readback,
            consumer.anchor.kernel_id(),
            consumer.expires_seconds,
        )
    }

    /// Returns canonical bytes, never an FD or grant authority.
    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; FRAME_BYTES] {
        &self.bytes
    }

    fn encode(
        record: &StorageCloneActiveRecordV2,
        readback: &StorageLiveExportReadbackV1,
        cgroup_id: u64,
        expires_seconds: i64,
    ) -> Result<Self, StorageGrantHandoffErrorV1> {
        let (provider_id, provider_generation, plan_id) = readback.replay_identity();
        let (holder_id, holder_generation, holder_digest) = readback.holder_binding();
        let record_digest = active_record_digest(record);
        let mut bytes = [0_u8; FRAME_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[10] = DENY_STAGE;
        bytes[48..64].copy_from_slice(&provider_id);
        bytes[64..72].copy_from_slice(&provider_generation.to_be_bytes());
        bytes[72..88].copy_from_slice(&plan_id);
        bytes[88..120].copy_from_slice(readback.signed_request_digest().as_bytes());
        bytes[120..152].copy_from_slice(readback.signed_root_request_digest().as_bytes());
        bytes[152..184].copy_from_slice(readback.digest().as_bytes());
        bytes[184..192].copy_from_slice(&record.journal_sequence.to_be_bytes());
        bytes[192..224].copy_from_slice(record_digest.as_bytes());
        bytes[224..240].copy_from_slice(&record.value[48..64]);
        bytes[240..264].copy_from_slice(&record.value[64..88]);
        bytes[264..280].copy_from_slice(&holder_id);
        bytes[280..288].copy_from_slice(&holder_generation.to_be_bytes());
        bytes[288..320].copy_from_slice(holder_digest.as_bytes());
        bytes[320..328].copy_from_slice(&cgroup_id.to_be_bytes());
        bytes[336..344].copy_from_slice(&expires_seconds.to_be_bytes());
        let id = handoff_id(&bytes);
        bytes[16..48].copy_from_slice(&id);

        let frame = Self { bytes };
        frame.validate()?;
        Ok(frame)
    }

    fn validate(&self) -> Result<(), StorageGrantHandoffErrorV1> {
        let bytes = &self.bytes;
        if &bytes[..8] != MAGIC
            || bytes[8..10] != VERSION.to_be_bytes()
            || bytes[10] != DENY_STAGE
            || bytes[11..16] != [0; 5]
            || bytes[16..48] != handoff_id(bytes)
            || bytes[48..64] == [0; 16]
            || bytes[64..72] == [0; 8]
            || bytes[72..88] == [0; 16]
            || bytes[88..120] == [0; 32]
            || bytes[120..152] == [0; 32]
            || bytes[152..184] == [0; 32]
            || bytes[184..192] == [0; 8]
            || bytes[192..224] == [0; 32]
            || bytes[224..240] == [0; 16]
            || bytes[240..248] == [0; 8]
            || bytes[248..256] == [0; 8]
            || bytes[256..264] == [0; 8]
            || bytes[264..280] == [0; 16]
            || bytes[280..288] == [0; 8]
            || bytes[288..320] == [0; 32]
            || bytes[320..328] == [0; 8]
            || bytes[328..336] != [0; 8]
            || i64::from_be_bytes(
                bytes[336..344]
                    .try_into()
                    .map_err(|_| StorageGrantHandoffErrorV1::Noncanonical)?,
            ) <= 0
        {
            return Err(StorageGrantHandoffErrorV1::Noncanonical);
        }
        Ok(())
    }

    #[cfg(test)]
    fn decode(bytes: &[u8]) -> Result<Self, StorageGrantHandoffErrorV1> {
        let bytes: [u8; FRAME_BYTES] = bytes
            .try_into()
            .map_err(|_| StorageGrantHandoffErrorV1::Noncanonical)?;
        let frame = Self { bytes };
        frame.validate()?;
        Ok(frame)
    }
}

fn active_record_digest(record: &StorageCloneActiveRecordV2) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(CLONE_RECORD_DOMAIN)
            .chain_update(record.key)
            .chain_update(record.value)
            .finalize()
            .into(),
    )
}

fn handoff_id(bytes: &[u8; FRAME_BYTES]) -> [u8; 32] {
    Sha256::new()
        .chain_update(HANDOFF_ID_DOMAIN)
        .chain_update(&bytes[48..])
        .finalize()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame() -> StorageDenyStageFrameV1 {
        let mut bytes = [0_u8; FRAME_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[10] = DENY_STAGE;
        for (range, value) in [
            (48..64, 1),
            (64..72, 2),
            (72..88, 3),
            (88..120, 4),
            (120..152, 5),
            (152..184, 6),
            (184..192, 7),
            (192..224, 8),
            (224..240, 9),
            (240..248, 10),
            (248..256, 11),
            (256..264, 12),
            (264..280, 13),
            (280..288, 14),
            (288..320, 15),
            (320..328, 16),
        ] {
            bytes[range].fill(value);
        }
        bytes[336..344].copy_from_slice(&100_i64.to_be_bytes());
        let id = handoff_id(&bytes);
        bytes[16..48].copy_from_slice(&id);
        StorageDenyStageFrameV1::decode(&bytes).unwrap()
    }

    #[test]
    fn deny_stage_frame_is_exact_and_epoch_zero() {
        let frame = frame();
        assert_eq!(frame.as_bytes().len(), 344);
        assert_eq!(&frame.as_bytes()[..8], b"AOSKGH01");
        assert_eq!(&frame.as_bytes()[328..336], &[0; 8]);
        assert_eq!(
            StorageDenyStageFrameV1::decode(frame.as_bytes()).unwrap(),
            frame
        );
    }

    #[test]
    fn deny_stage_frame_rejects_tamper_legacy_and_length_drift() {
        let original = *frame().as_bytes();
        for index in [0, 8, 10, 11, 16, 48, 88, 184, 224, 328, 343] {
            let mut tampered = original;
            tampered[index] ^= 1;
            assert!(
                StorageDenyStageFrameV1::decode(&tampered).is_err(),
                "byte {index}"
            );
        }
        assert!(StorageDenyStageFrameV1::decode(&original[..343]).is_err());
        let mut old = original;
        old[..8].copy_from_slice(b"AOSKGH00");
        assert!(StorageDenyStageFrameV1::decode(&old).is_err());
    }

    #[test]
    fn active_record_digest_binds_key_and_value() {
        let record = StorageCloneActiveRecordV2 {
            key: [1; 40],
            value: [2; 104],
            journal_sequence: 3,
        };
        let digest = active_record_digest(&record);
        let mut changed_key = record.key;
        changed_key[0] = 4;
        let mut changed_value = record.value;
        changed_value[103] = 5;

        assert_ne!(
            digest,
            active_record_digest(&StorageCloneActiveRecordV2 {
                key: changed_key,
                value: record.value,
                journal_sequence: 3,
            })
        );
        assert_ne!(
            digest,
            active_record_digest(&StorageCloneActiveRecordV2 {
                key: record.key,
                value: changed_value,
                journal_sequence: 3,
            })
        );
    }
}
