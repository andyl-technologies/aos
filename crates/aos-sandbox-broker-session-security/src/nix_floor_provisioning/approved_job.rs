//! Resident, read-only inspection of one independently signed offline proposal.
//!
//! Every file and partial buffer stays in the attempt on error or unwind. The
//! genuine externally retained startup is borrowed for its entire lifetime.
//! Successful inspection authenticates static DATA only: no TPM command, live
//! approval generation, session, floor, initialize or recover permit is produced.
//!
//! ```text
//! approved-job-v3 (1332 bytes):
//! AOSNAJ03/version3/intent1/approvalID/installation1/purposes058+059 (80)
//! + original candidate-public-v3 (268) + canonical session manifest (920)
//! + independent Ed25519 signature (64)
//! ```

use std::fs::File;
use std::io;
use std::os::fd::AsFd as _;

use aos_sandbox::normal_root::OfflineNixPrepareOriginV3;
#[cfg(test)]
use aos_sandbox_broker_session_protocol::{
    BrokerSessionKeyUsageV1, BrokerSessionProtocolV1,
};
use aos_sandbox_broker_session_protocol::manifest::BrokerSessionManifestErrorV1;
#[cfg(test)]
use aos_sandbox_broker_session_protocol::manifest::{
    BrokerSessionManifestAudienceV1, BrokerSessionManifestV1,
};
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::protected_file::{
    open_nofollow_child, read_exact_positioned_retaining_cause,
};
use ed25519_dalek::SignatureError;
use rustix::fs::{Mode, OFlags};
use zeroize::{Zeroize as _, Zeroizing};

use super::{FileIdentity, JOB_NAME, PRIVATE_NAME, PUBLIC_NAME};

const APPROVED_NAME: &str = "approved-job-v3";
const FILE_NAMES: [&str; 3] = [PRIVATE_NAME, PUBLIC_NAME, APPROVED_NAME];
const FILE_LENGTHS: [usize; 3] = [336, 268, 1332];
const FILE_MODES: [u32; 3] = [0o600, 0o400, 0o400];
const NAMED_CAPACITY: usize = 12;
const SIGNED_PREFIX_BYTES: usize = 1268;
const APPROVAL_DOMAIN: &[u8] = b"aos.sandbox.nix-floor.approved-job-inspection.v3\0";
const PREIMAGE_BYTES: usize = 1317;
#[cfg(test)]
const CONTROLLER_PURPOSE: [u8; 16] = [
    1, 0, 0, 0, 0x01, 0x80, 0xa0, 0x58, 0x81, 0x00, 0xa0, 0x58, 0, 0, 0, 0,
];
#[cfg(test)]
const OWNER_PURPOSE: [u8; 16] = [
    2, 0, 0, 0, 0x01, 0x80, 0xa0, 0x59, 0x81, 0x00, 0xa0, 0x59, 0, 0, 0, 0,
];

const _: () = assert!(APPROVAL_DOMAIN.len() + SIGNED_PREFIX_BYTES == PREIMAGE_BYTES);
const _: () = assert!(NAMED_CAPACITY <= super::MAXIMUM_NAMED_READBACKS);

/// Retains a redacted first failure of static approved-job inspection.
#[derive(Debug, thiserror::Error)]
pub enum NixApprovedJobInspectionErrorV3 {
    /// The actual Core startup retains its original typed cause.
    #[error("original offline inspection startup is fenced")]
    Startup,
    /// An actual original file, lock or bounded allocation operation failed.
    #[error("offline inspection original I/O failed")]
    Io(#[from] io::Error),
    /// An actual descriptor or mount observation failed.
    #[error("offline inspection kernel observation failed")]
    Linux(#[from] aos_sandbox_linux::Error),
    /// The sole positioned reader failed or observed unexpected trailing bytes.
    #[error("offline inspection exact read failed ({0:?})")]
    Read(aos_sandbox_linux::protected_file::ExactReadError),
    /// The existing candidate or label engine rejected the original proposal.
    #[error("offline inspection candidate custody differs")]
    Candidate(#[from] super::NixPrepareKeysErrorV3),
    /// The sole canonical manifest engine rejected the static DATA.
    #[error("offline inspection manifest differs")]
    Manifest(#[from] BrokerSessionManifestErrorV1),
    /// The original approval key or exact signature failed verification.
    #[error("offline inspection independent signature differs")]
    Signature(#[from] SignatureError),
    /// A fixed schema, role, named identity, mode or byte comparison differs.
    #[error("offline inspection original proposal differs")]
    Rejected,
    /// This attempt already completed, failed or was interrupted.
    #[error("offline inspection attempt is fenced")]
    Fenced,
}

impl From<rustix::io::Errno> for NixApprovedJobInspectionErrorV3 {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(io::Error::from_raw_os_error(error.raw_os_error()))
    }
}

type Error = NixApprovedJobInspectionErrorV3;

/// Holds one static inspection attempt and its complete original negative custody.
///
/// Its six original descriptors are separate from at most twelve named
/// readbacks. It exposes no file, seed, schema constructor or authority token.
/// Keep it and the external startup alive until explicit process exit on error
/// or caught unwind. Successful inspection is not a current approval or floor.
pub struct NixApprovedJobInspectionAttemptV3<'startup> {
    origin: OfflineNixPrepareOriginV3<'startup>,
    attempted: bool,
    first_failure: Option<Error>,
    originals: [Option<File>; 6],
    identities: [Option<FileIdentity>; 6],
    mounts: [Option<MountId>; 6],
    named: Vec<File>,
    snapshots: [[Zeroizing<Vec<u8>>; 3]; 2],
    derived: Vec<u8>,
    preimage: Vec<u8>,
}

impl<'startup> NixApprovedJobInspectionAttemptV3<'startup> {
    /// Parks empty resident slots while borrowing the genuine original startup.
    ///
    /// This constructor performs no protected I/O and authenticates no proposal.
    #[must_use]
    pub fn new(origin: OfflineNixPrepareOriginV3<'startup>) -> Self {
        Self {
            origin,
            attempted: false,
            first_failure: None,
            originals: [None, None, None, None, None, None],
            identities: [None; 6],
            mounts: [None; 6],
            named: Vec::new(),
            snapshots: std::array::from_fn(|_| {
                std::array::from_fn(|_| Zeroizing::new(Vec::new()))
            }),
            derived: Vec::new(),
            preimage: Vec::new(),
        }
    }

    /// Inspects one original, independently signed static proposal exactly once.
    ///
    /// # Errors
    /// Returns the resident first actual cause for wrong-mode or changed startup,
    /// file/lock/readback failures, malformed DATA or a mismatching independent
    /// signature. Repeated or interrupted attempts stay closed. No file is
    /// created, modified, repaired, deleted or converted into effect authority.
    pub fn inspect_once(&mut self) -> Result<(), &Error> {
        if self.attempted {
            return Err(self.first_failure.get_or_insert(Error::Fenced));
        }
        self.attempted = true;

        match self.inspect_inner() {
            Ok(()) => Ok(()),
            Err(error) => {
                self.first_failure.get_or_insert(error);
                self.wipe_secrets();
                Err(self.first_failure.get_or_insert(Error::Fenced))
            }
        }
    }

    /// Borrows the resident first returned cause without supplying a receipt.
    pub fn failure(&self) -> Option<&Error> {
        self.first_failure.as_ref()
    }

    /// Wipes parked candidate readbacks without releasing original descriptors.
    ///
    /// It does not remove files, unlock the job or approve a future effect.
    pub fn wipe_secrets(&mut self) {
        for snapshot in &mut self.snapshots {
            for bytes in snapshot {
                bytes.zeroize();
            }
        }
    }

    fn inspect_inner(&mut self) -> Result<(), Error> {
        // A prepare loan refuses before even the fixed job is opened. These
        // two bookends are the only startup rechecks in this attempt.
        self.origin.recheck_inspection().map_err(|_| Error::Startup)?;
        let (node, approval) = self.origin.public_originals().map_err(|_| Error::Startup)?;

        self.named.try_reserve_exact(NAMED_CAPACITY).map_err(io::Error::other)?;
        for snapshot in &mut self.snapshots {
            for (buffer, length) in snapshot.iter_mut().zip(FILE_LENGTHS) {
                reserve_bytes(buffer, length)?;
            }
        }
        reserve_bytes(&mut self.derived, 268)?;
        reserve_bytes(&mut self.preimage, PREIMAGE_BYTES)?;

        self.open_originals()?;
        self.read_snapshot(0)?;
        let [private, public, approved] = &self.snapshots[0];
        require_approved_data(
            private,
            public,
            approved,
            &node,
            &approval,
            &mut self.derived,
            &mut self.preimage,
        )?;

        self.read_snapshot(1)?;
        if self.snapshots[0] != self.snapshots[1] {
            return Err(Error::Rejected);
        }
        self.origin.recheck_inspection().map_err(|_| Error::Startup)
    }

    fn open_originals(&mut self) -> Result<(), Error> {
        self.originals[0] = Some(File::from(rustix::fs::openat2(
            rustix::fs::CWD,
            "/var/lib/aos",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        )?));
        self.admit_slot(0)?;

        self.originals[1] = Some(File::from(rustix::fs::openat(
            self.originals[0].as_ref().ok_or(Error::Rejected)?,
            JOB_NAME,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?));
        self.admit_slot(1)?;

        self.originals[2] = Some(File::from(open_nofollow_child(
            self.originals[1].as_ref().ok_or(Error::Rejected)?,
            "installation.lock",
        )?));
        self.admit_slot(2)?;
        rustix::fs::flock(
            self.originals[2].as_ref().ok_or(Error::Rejected)?,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )?;

        for (index, name) in FILE_NAMES.iter().enumerate() {
            let slot = index + 3;
            self.originals[slot] = Some(File::from(open_nofollow_child(
                self.originals[1].as_ref().ok_or(Error::Rejected)?,
                name,
            )?));
            self.admit_slot(slot)?;
        }
        Ok(())
    }

    fn admit_slot(&mut self, slot: usize) -> Result<(), Error> {
        let file = self.originals[slot].as_ref().ok_or(Error::Rejected)?;
        self.identities[slot] = Some(super::inspect(file)?);
        require_slot_identity(slot, self.identities[slot].as_ref().ok_or(Error::Rejected)?)?;
        self.mounts[slot] = Some(MountId::from_fd(file.as_fd())?);
        if slot > 0 {
            super::require_label(file)?;
        }
        if slot > 1 && self.mounts[slot] != self.mounts[1] {
            return Err(Error::Rejected);
        }
        Ok(())
    }

    fn require_original(&self, slot: usize) -> Result<(), Error> {
        let file = self.originals[slot].as_ref().ok_or(Error::Rejected)?;
        self.require_observed_slot(slot, file)
    }

    fn read_snapshot(&mut self, round: usize) -> Result<(), Error> {
        if round >= self.snapshots.len() || self.named.len() > NAMED_CAPACITY - 6 {
            return Err(Error::Rejected);
        }
        for slot in 0..6 {
            self.require_original(slot)?;
        }

        self.named.push(File::from(rustix::fs::openat2(
            rustix::fs::CWD,
            "/var/lib/aos",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        )?));
        self.require_named(0)?;

        self.named.push(File::from(rustix::fs::openat(
            self.originals[0].as_ref().ok_or(Error::Rejected)?,
            JOB_NAME,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?));
        self.require_named(1)?;

        self.named.push(File::from(open_nofollow_child(
            self.originals[1].as_ref().ok_or(Error::Rejected)?,
            "installation.lock",
        )?));
        self.require_named(2)?;

        for (index, name) in FILE_NAMES.iter().enumerate() {
            self.named.push(File::from(open_nofollow_child(
                self.originals[1].as_ref().ok_or(Error::Rejected)?,
                name,
            )?));
            self.require_named(index + 3)?;
        }

        for index in 0..3 {
            let slot = index + 3;
            self.require_original(slot)?;
            read_exact_positioned_retaining_cause(
                self.originals[slot].as_ref().ok_or(Error::Rejected)?,
                &mut self.snapshots[round][index],
            )
            .map_err(|failure| match failure {
                aos_sandbox_linux::protected_file::ExactReadFailure::Io(errno) => {
                    Error::Io(io::Error::from_raw_os_error(errno.raw_os_error()))
                }
                failure => Error::Read(failure.legacy_classification()),
            })?;
            self.require_original(slot)?;
        }
        for slot in 0..6 {
            self.require_original(slot)?;
        }
        Ok(())
    }

    fn require_named(&self, slot: usize) -> Result<(), Error> {
        if self.named.len() > NAMED_CAPACITY {
            return Err(Error::Rejected);
        }
        let file = self.named.last().ok_or(Error::Rejected)?;
        self.require_observed_slot(slot, file)
    }

    fn require_observed_slot(&self, slot: usize, file: &File) -> Result<(), Error> {
        if Some(super::inspect(file)?) != self.identities[slot]
            || Some(MountId::from_fd(file.as_fd())?) != self.mounts[slot]
        {
            return Err(Error::Rejected);
        }
        if slot > 0 {
            super::require_label(file)?;
        }
        Ok(())
    }
}

fn reserve_bytes(buffer: &mut Vec<u8>, length: usize) -> Result<(), Error> {
    buffer.try_reserve_exact(length).map_err(io::Error::other)?;
    buffer.resize(length, 0);
    Ok(())
}

// Validate the SAME metadata observation retained by the shared identity
// engine, not a shape read followed by an unrelated identity baseline.
fn require_slot_identity(slot: usize, identity: &FileIdentity) -> Result<(), Error> {
    if identity.2 != 0 || identity.3 != 0 {
        return Err(Error::Rejected);
    }
    let kind = rustix::fs::FileType::from_raw_mode(identity.4);
    match slot {
        0 if kind != rustix::fs::FileType::Directory || identity.4 & 0o022 != 0 => {
            return Err(Error::Rejected);
        }
        1 if kind != rustix::fs::FileType::Directory || identity.4 & 0o7777 != 0o700 => {
            return Err(Error::Rejected);
        }
        2 if kind != rustix::fs::FileType::RegularFile
            || identity.4 & 0o7777 != 0o600
            || identity.5 != 1
            || identity.6 != 0 =>
        {
            return Err(Error::Rejected);
        }
        3..=5 if kind != rustix::fs::FileType::RegularFile
            || identity.4 & 0o7777 != FILE_MODES[slot - 3]
            || identity.5 != 1
            || identity.6 != FILE_LENGTHS[slot - 3] as u64 =>
        {
            return Err(Error::Rejected);
        }
        0..=5 => {}
        _ => return Err(Error::Rejected),
    }
    Ok(())
}

#[cfg(test)]
fn require_header(approved: &[u8], approval: &[u8; 48]) -> Result<(), Error> {
    aos_sandbox::normal_root::require_nix_offline_static_header_v3(approved, approval)
        .map_err(approved_data_error)
}

#[cfg(test)]
fn fill_preimage(approved: &[u8], preimage: &mut [u8]) -> Result<(), Error> {
    aos_sandbox::normal_root::fill_nix_offline_static_preimage_v3(approved, preimage)
        .map_err(approved_data_error)
}

fn require_approved_data(
    private: &[u8],
    public: &[u8],
    approved: &[u8],
    node: &[u8; 16],
    approval: &[u8; 48],
    derived: &mut [u8],
    preimage: &mut [u8],
) -> Result<(), Error> {
    aos_sandbox::normal_root::require_nix_offline_static_approval_v3(
        private, public, approved, node, approval, derived, preimage,
    )
    .map_err(approved_data_error)
}

fn approved_data_error(error: aos_sandbox::normal_root::NixOfflineApprovedDataErrorV4) -> Error {
    use aos_sandbox::normal_root::NixOfflineApprovedDataErrorV4 as DataError;
    match error {
        DataError::Rejected => Error::Rejected,
        DataError::Candidate => Error::Candidate(super::NixPrepareKeysErrorV3::Rejected),
        DataError::Manifest(source) => Error::Manifest(source),
        DataError::Signature(source) => Error::Signature(source),
    }
}

#[cfg(test)]
mod tests {
    use aos_sandbox_broker_session_protocol::manifest::BrokerSessionManifestKeyPinV1;
    use aos_sandbox_broker_session_protocol::BrokerSessionSignerReferenceV1;
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    struct Fixture {
        private: Vec<u8>,
        public: Vec<u8>,
        approved: Vec<u8>,
        node: [u8; 16],
        approval: [u8; 48],
    }

    impl Fixture {
        fn new() -> Self {
            let node = [3; 16];
            let approver = SigningKey::from_bytes(&[90; 32]);
            let mut approval = [1; 48];
            approval[16..].copy_from_slice(approver.verifying_key().as_bytes());
            let mut private = vec![0; 336];
            private[..8].copy_from_slice(b"AOSNPK03");
            private[8..10].copy_from_slice(&3_u16.to_le_bytes());
            for index in 0..4 {
                private[16 + index * 48..32 + index * 48].fill(10 + index as u8);
                private[32 + index * 48..64 + index * 48].fill(20 + index as u8);
                private[208 + index * 32..240 + index * 32].fill(30 + index as u8);
            }
            let mut public = vec![0; 268];
            super::super::encode_public_candidates(
                &private,
                &[2; 16],
                &node,
                &approval,
                &mut public,
            )
            .unwrap();

            let roles = [
                BrokerSessionKeyUsageV1::ClientHello,
                BrokerSessionKeyUsageV1::BrokerHello,
                BrokerSessionKeyUsageV1::ClientRecord,
                BrokerSessionKeyUsageV1::BrokerOutcome,
            ];
            let keys = std::array::from_fn(|index| {
                let key = SigningKey::from_bytes(&[20 + index as u8; 32]);
                let controller = index % 2 == 0;
                let authority_generation = if controller { 7 } else { 9 };
                let signer = BrokerSessionSignerReferenceV1::for_signing_key(
                    [if controller { 4 } else { 5 }; 16],
                    authority_generation,
                    [if controller { 40 } else { 50 }; 32],
                    [10 + index as u8; 16],
                    1,
                    roles[index],
                    &key,
                )
                .unwrap();
                BrokerSessionManifestKeyPinV1::new(
                    signer,
                    key.verifying_key().to_bytes(),
                    authority_generation,
                    1,
                    false,
                    None,
                )
                .unwrap()
            });
            let manifest = BrokerSessionManifestV1::new(
                BrokerSessionProtocolV1::Nix,
                BrokerSessionManifestAudienceV1::NodeController,
                1,
                0,
                [6; 16],
                [7; 16],
                6,
                [8; 32],
                8,
                [9; 32],
                10,
                [11; 32],
                node,
                keys,
            )
            .unwrap();

            let mut approved = vec![0; 1332];
            approved[..8].copy_from_slice(b"AOSNAJ03");
            approved[8..10].copy_from_slice(&3_u16.to_be_bytes());
            approved[10..12].copy_from_slice(&1_u16.to_be_bytes());
            approved[16..32].copy_from_slice(&approval[..16]);
            approved[32..40].copy_from_slice(&1_u64.to_be_bytes());
            approved[48..64].copy_from_slice(&CONTROLLER_PURPOSE);
            approved[64..80].copy_from_slice(&OWNER_PURPOSE);
            approved[80..348].copy_from_slice(&public);
            approved[348..1268].copy_from_slice(&manifest.encode());

            let mut fixture = Self {
                private,
                public,
                approved,
                node,
                approval,
            };
            fixture.resign();
            fixture
        }

        fn resign(&mut self) {
            let mut preimage = vec![0; PREIMAGE_BYTES];
            fill_preimage(&self.approved, &mut preimage).unwrap();
            let signature = SigningKey::from_bytes(&[90; 32]).sign(&preimage);
            self.approved[1268..].copy_from_slice(&signature.to_bytes());
        }

        fn check(&self) -> Result<(), Error> {
            require_approved_data(
                &self.private,
                &self.public,
                &self.approved,
                &self.node,
                &self.approval,
                &mut [0; 268],
                &mut [0; PREIMAGE_BYTES],
            )
        }
    }

    #[test]
    fn canonical_signed_static_data_uses_the_existing_candidate_and_manifest_engines() {
        let fixture = Fixture::new();

        assert!(fixture.check().is_ok());
        assert_eq!(fixture.approved.len(), 80 + 268 + 920 + 64);
        assert_eq!(APPROVAL_DOMAIN.len(), 49);
        assert_eq!(APPROVAL_DOMAIN.last(), Some(&0));
        assert_eq!(PREIMAGE_BYTES, 49 + 1268);
        assert_eq!(FILE_LENGTHS.iter().sum::<usize>() * 2, 3872);
        assert_eq!(NAMED_CAPACITY, 12);
    }

    #[test]
    fn fixed_slot_policy_checks_only_the_same_retained_identity_data() {
        let private: FileIdentity = (1, 2, 0, 0, 0o100600, 1, 336, 3, 4, 5, 6);
        assert!(require_slot_identity(3, &private).is_ok());

        let mut changed = private;
        changed.2 = 1;
        assert!(require_slot_identity(3, &changed).is_err());
        changed = private;
        changed.5 = 2;
        assert!(require_slot_identity(3, &changed).is_err());
        changed = private;
        changed.6 = 335;
        assert!(require_slot_identity(3, &changed).is_err());
        assert!(require_slot_identity(4, &private).is_err());
        assert!(require_slot_identity(6, &private).is_err());
    }

    #[test]
    fn header_rejects_every_truncation_trailing_bytes_and_closed_field_changes() {
        let fixture = Fixture::new();
        for length in 0..1332 {
            assert!(require_header(&fixture.approved[..length], &fixture.approval).is_err());
        }
        let mut extra = fixture.approved.clone();
        extra.push(0);
        assert!(require_header(&extra, &fixture.approval).is_err());

        for offset in 0..80 {
            let mut changed = fixture.approved.clone();
            changed[offset] ^= 1;
            assert!(
                require_header(&changed, &fixture.approval).is_err(),
                "closed header byte {offset}",
            );
        }
    }

    #[test]
    fn public_and_private_originals_cannot_be_replaced_by_a_signed_digest() {
        let mut fixture = Fixture::new();
        fixture.approved[124] ^= 1;
        fixture.resign();
        assert!(matches!(fixture.check(), Err(Error::Rejected)));

        let mut fixture = Fixture::new();
        fixture.private[32] ^= 1;
        assert!(fixture.check().is_err());

        let mut fixture = Fixture::new();
        fixture.node[0] ^= 1;
        assert!(matches!(fixture.check(), Err(Error::Rejected)));
    }

    #[test]
    fn signature_requires_the_original_independent_key_and_exact_domain() {
        let mut fixture = Fixture::new();
        fixture.approved[1300] ^= 1;
        assert!(matches!(fixture.check(), Err(Error::Signature(_))));

        let mut fixture = Fixture::new();
        let mut preimage = vec![0; PREIMAGE_BYTES];
        fill_preimage(&fixture.approved, &mut preimage).unwrap();
        let signature = SigningKey::from_bytes(&[20; 32]).sign(&preimage);
        fixture.approved[1268..].copy_from_slice(&signature.to_bytes());
        assert!(matches!(fixture.check(), Err(Error::Signature(_))));

        let mut fixture = Fixture::new();
        fill_preimage(&fixture.approved, &mut preimage).unwrap();
        preimage[48] = b'0';
        let signature = SigningKey::from_bytes(&[90; 32]).sign(&preimage);
        fixture.approved[1268..].copy_from_slice(&signature.to_bytes());
        assert!(matches!(fixture.check(), Err(Error::Signature(_))));
    }

    #[test]
    fn signed_manifest_context_role_and_generation_changes_still_refuse() {
        // The manifest prefix is184; each key record is184. Mutations are
        // signed again, so canonical or proposal comparison is the reason.
        for offset in [
            348 + 10,
            348 + 11,
            348 + 12,
            348 + 14,
            348 + 168,
            348 + 184 + 56,
            348 + 184 + 72,
            348 + 184 + 88,
            348 + 184 + 112,
            348 + 184 + 152,
            348 + 184 + 160,
            348 + 184 + 168,
            348 + 184 + 2 * 184,
        ] {
            let mut fixture = Fixture::new();
            fixture.approved[offset] ^= 1;
            fixture.resign();

            assert!(fixture.check().is_err(), "signed manifest byte {offset}");
        }
    }

    #[test]
    fn copied_candidate_role_and_foreign_authority_pair_are_not_admitted() {
        let mut fixture = Fixture::new();
        let record = fixture.public[76..124].to_vec();
        fixture.public[124..172].copy_from_slice(&record);
        fixture.approved[80..348].copy_from_slice(&fixture.public);
        fixture.resign();
        assert!(fixture.check().is_err());

        let mut fixture = Fixture::new();
        // Change only the ClientRecord authority digest, retaining a canonical
        // manifest and candidate relation but breaking the Controller pair.
        fixture.approved[348 + 184 + 2 * 184 + 24] ^= 1;
        fixture.resign();
        assert!(matches!(fixture.check(), Err(Error::Rejected)));
    }
}
