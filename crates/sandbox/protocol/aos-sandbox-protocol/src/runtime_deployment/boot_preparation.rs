//! Signed normal boot-preparation DATA for the existing deployment floor.
//!
//! These records grant neither backend readiness nor a new account. The actual
//! issuer must hold the original publisher, SourceM receipt, complete protected
//! journal pair and fresh authenticated NV. Publication follows the exact
//! committed floor target and every independently owed native observation.
//!
//! ```text
//! AOSRDBP1:272 || provisioner-signature:64
//! AOSRDBR1:664 || publisher-signature:64
//! ```

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use super::{DeploymentGenesisV1, DeploymentWireErrorV1};

/// Exact normal-purpose body width, excluding its strict signature.
pub const BOOT_PREPARATION_PURPOSE_BODY_BYTES_V1: usize = 272;
/// Exact independently provisioned normal-purpose width.
pub const BOOT_PREPARATION_PURPOSE_BYTES_V1: usize = 336;
/// Exact normal preparation record body width, excluding its signature.
pub const BOOT_PREPARATION_RECORD_BODY_BYTES_V1: usize = 664;
/// Exact normal preparation record width.
pub const BOOT_PREPARATION_RECORD_BYTES_V1: usize = 728;

/// Exact externally provisioned signed genesis and normal-purpose pair width.
pub const BOOT_PREPARATION_COMPOSITE_GENESIS_BYTES_V1: usize =
    468 + BOOT_PREPARATION_PURPOSE_BYTES_V1;
/// Canonical immutable normal-purpose genesis row key.
pub const BOOT_PREPARATION_GENESIS_KEY_V1: &[u8] = b"deployment-boot-genesis-v1";

mod completion;
pub use completion::{
    BOOT_PREPARATION_COMPLETION_BODY_BYTES_V1, BOOT_PREPARATION_COMPLETION_BYTES_V1,
    BOOT_PREPARATION_COMPLETION_FILE_V1, BootPreparationCompletionFieldsDataV1,
    SignedBootPreparationCompletionDataV1,
};

const PURPOSE_DOMAIN: &[u8] = b"aos.runtime-deployment.boot-purpose.v1\0";
const RECORD_DOMAIN: &[u8] = b"aos.runtime-deployment.boot-record.v1\0";
const RECORD_DIGEST_DOMAIN: &[u8] = b"aos.runtime-deployment.boot-record-digest.v1\0";

/// Names the independently signed normal producer contract as comparison DATA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootPreparationPurposeDataV1 {
    /// Same externally provisioned node as the deployment genesis.
    pub node: [u8; 16],
    /// Same externally provisioned deployment as the deployment genesis.
    pub deployment: [u8; 16],
    /// Digest of the exact signed genesis, including its signature.
    pub signed_genesis_digest: [u8; 32],
    /// Existing deployment publisher verification key, never the provisioner.
    pub publisher: [u8; 32],
    /// Exact immutable normal publisher profile.
    pub publisher_profile: [u8; 32],
    /// Canonical Parent/HostService subdivision and native SourceM contract.
    pub source_contract: [u8; 32],
    /// Exact fixed boot producer program, including its native prerequisites.
    pub program_contract: [u8; 32],
    /// Exact fixed credential roster and independent role separation.
    pub credential_contract: [u8; 32],
    /// Fixed protected main, sidecar, publication and readback namespace.
    pub directory_contract: [u8; 32],
}

impl BootPreparationPurposeDataV1 {
    /// Constructs the bounded independent provisioner's signing preimage.
    ///
    /// # Errors
    /// Rejects the same invalid fields as the sole purpose body encoder.
    pub fn signing_bytes_v1(&self) -> Result<Vec<u8>, DeploymentWireErrorV1> {
        let mut bytes =
            Vec::with_capacity(PURPOSE_DOMAIN.len() + BOOT_PREPARATION_PURPOSE_BODY_BYTES_V1);
        bytes.extend_from_slice(PURPOSE_DOMAIN);
        bytes.extend_from_slice(&self.encode_body_v1()?);
        Ok(bytes)
    }

    /// Encodes the complete normal-purpose signing body without issuing scope.
    ///
    /// # Errors
    /// Rejects sentinel fields and a weak or malformed publisher key.
    pub fn encode_body_v1(
        &self,
    ) -> Result<[u8; BOOT_PREPARATION_PURPOSE_BODY_BYTES_V1], DeploymentWireErrorV1> {
        let key = VerifyingKey::from_bytes(&self.publisher).map_err(|_| DeploymentWireErrorV1)?;
        if self.node == [0; 16]
            || self.deployment == [0; 16]
            || key.is_weak()
            || [
                self.signed_genesis_digest,
                self.publisher_profile,
                self.source_contract,
                self.program_contract,
                self.credential_contract,
                self.directory_contract,
            ]
            .contains(&[0; 32])
        {
            return Err(DeploymentWireErrorV1);
        }
        let mut bytes = [0; BOOT_PREPARATION_PURPOSE_BODY_BYTES_V1];
        header(&mut bytes, b"AOSRDBP1");
        bytes[16..32].copy_from_slice(&self.node);
        bytes[32..48].copy_from_slice(&self.deployment);
        for (offset, field) in [
            (48, &self.signed_genesis_digest),
            (80, &self.publisher),
            (112, &self.publisher_profile),
            (144, &self.source_contract),
            (176, &self.program_contract),
            (208, &self.credential_contract),
            (240, &self.directory_contract),
        ] {
            bytes[offset..offset + 32].copy_from_slice(field);
        }
        Ok(bytes)
    }
}

/// Retains a strict provisioner-signed purpose without creating a native owner.
pub struct SignedBootPreparationPurposeDataV1 {
    fields: BootPreparationPurposeDataV1,
    bytes: [u8; BOOT_PREPARATION_PURPOSE_BYTES_V1],
}

impl SignedBootPreparationPurposeDataV1 {
    /// Authenticates only the explicit normal contract against the real genesis.
    ///
    /// # Errors
    /// Rejects wrong framing, sentinels, substituted genesis or keys, and invalid
    /// strict signatures. Native SourceM/profile/currentness checks remain owed.
    pub fn verify_v1(
        bytes: &[u8],
        signed_genesis: &[u8; 468],
        genesis: &DeploymentGenesisV1,
        provisioner: &VerifyingKey,
    ) -> Result<Self, DeploymentWireErrorV1> {
        require_header(bytes, BOOT_PREPARATION_PURPOSE_BYTES_V1, b"AOSRDBP1")?;
        // The public DATA verifier compares the supplied decoded genesis to
        // its actual signed bytes; a matching scalar digest is insufficient.
        let decoded = DeploymentGenesisV1::decode(&signed_genesis[..404])?;
        let signature: [u8; 64] = signed_genesis[404..]
            .try_into()
            .map_err(|_| DeploymentWireErrorV1)?;
        decoded.verify_signature(provisioner, signature)?;
        if &decoded != genesis || provisioner.is_weak() {
            return Err(DeploymentWireErrorV1);
        }
        let fields = BootPreparationPurposeDataV1 {
            node: take(bytes, 16)?,
            deployment: take(bytes, 32)?,
            signed_genesis_digest: take(bytes, 48)?,
            publisher: take(bytes, 80)?,
            publisher_profile: take(bytes, 112)?,
            source_contract: take(bytes, 144)?,
            program_contract: take(bytes, 176)?,
            credential_contract: take(bytes, 208)?,
            directory_contract: take(bytes, 240)?,
        };
        if fields.encode_body_v1()?.as_slice() != &bytes[..BOOT_PREPARATION_PURPOSE_BODY_BYTES_V1]
            || fields.node != genesis.node
            || fields.deployment != genesis.deployment
            || fields.publisher != genesis.signer
            || fields.publisher == provisioner.to_bytes()
            || fields.publisher_profile != genesis.publisher_profile
            || fields.signed_genesis_digest != <[u8; 32]>::from(Sha256::digest(signed_genesis))
        {
            return Err(DeploymentWireErrorV1);
        }
        verify_signature(
            bytes,
            BOOT_PREPARATION_PURPOSE_BODY_BYTES_V1,
            PURPOSE_DOMAIN,
            provisioner,
        )?;
        Ok(Self {
            fields,
            bytes: bytes.try_into().map_err(|_| DeploymentWireErrorV1)?,
        })
    }

    /// Borrows the complete independently authenticated contract as DATA.
    #[must_use]
    pub const fn fields_v1(&self) -> &BootPreparationPurposeDataV1 {
        &self.fields
    }

    /// Borrows exact signed bytes for the sole complete protected fold.
    #[must_use]
    pub const fn bytes_v1(&self) -> &[u8; BOOT_PREPARATION_PURPOSE_BYTES_V1] {
        &self.bytes
    }

    /// Commits the full signed normal purpose under its distinct domain.
    #[must_use]
    pub fn digest_v1(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(PURPOSE_DOMAIN)
            .chain_update(self.bytes)
            .finalize()
            .into()
    }
}

/// Describes one exact boot preparation and its genuine floor predecessor.
///
/// Public construction and encoding authenticate no field. The installed
/// issuer derives every member from retained originals before signing it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootPreparationRecordDataV1 {
    /// Complete signed normal-purpose commitment.
    pub purpose: [u8; 32],
    /// Exact signed genesis commitment.
    pub signed_genesis_digest: [u8; 32],
    /// Same provisioned node.
    pub node: [u8; 16],
    /// Same provisioned deployment.
    pub deployment: [u8; 16],
    /// Actual newly committed Host floor target ordinal, never a canary ordinal.
    pub publisher_generation: u64,
    /// Physically observed boot shared by the SourceM origin and signed probe.
    pub boot: [u8; 16],
    /// Actual Source-authenticated publisher recipient invocation for this run.
    pub publisher_invocation: [u8; 16],
    /// Complete preceding normal preparation record, or zero only at genesis.
    pub previous_record: [u8; 32],
    /// Exact independently signed normal SourceM grammar/partition contract.
    ///
    /// The actual current Source owner separately binds node, boot and invocation.
    pub source_contract: [u8; 32],
    /// Same immutable normal publisher profile.
    pub publisher_profile: [u8; 32],
    /// Digest of the exact canonical nspawn store path carried in the JSON.
    pub nspawn_path_digest: [u8; 32],
    /// Actual retained immutable nspawn device.
    pub nspawn_device: u64,
    /// Actual retained immutable nspawn inode.
    pub nspawn_inode: u64,
    /// Actual pinned packaged nspawn bytes.
    pub nspawn_digest: [u8; 32],
    /// Actual retained PID1 image bytes, matched to the same package artifact.
    pub pid1_digest: [u8; 32],
    /// Actual pinned Host daemon bytes named by the signed probe.
    pub hostd_digest: [u8; 32],
    /// Actual pinned inspector bytes named by the signed probe.
    pub inspector_digest: [u8; 32],
    /// Complete verified signed AOSHPB02 probe commitment.
    pub probe_digest: [u8; 32],
    /// Actual enforcing canonical MAC policy commitment.
    pub mac_policy_digest: [u8; 32],
    /// Same package-verified fixed compiler supervisor policy, not a live claim.
    pub supervisor_profile_digest: [u8; 32],
    /// Same package-verified filter source, not proof of a running payload filter.
    pub payload_filter_digest: [u8; 32],
    /// Exact bounded backend-readiness JSON bytes installed for Host ingestion.
    pub artifact_digest: [u8; 32],
    /// Actual complete predecessor floor ordinal authenticated by fresh NV.
    pub predecessor_ordinal: u64,
    /// Actual complete predecessor protected main NEXT.
    pub predecessor_sequence: u64,
    /// Actual complete predecessor protected main HEAD.
    pub predecessor_head: [u8; 32],
    /// Actual fresh authenticated NV before the new floor transition.
    pub predecessor_nv: [u8; 32],
}

impl BootPreparationRecordDataV1 {
    /// Encodes the complete normal preparation body without granting publication.
    ///
    /// # Errors
    /// Rejects sentinel identities/commitments, invalid physical coordinates,
    /// noncontiguous floor ordinals, and unsupported predecessor relations.
    pub fn encode_body_v1(
        &self,
    ) -> Result<[u8; BOOT_PREPARATION_RECORD_BODY_BYTES_V1], DeploymentWireErrorV1> {
        if self.node == [0; 16]
            || self.deployment == [0; 16]
            || self.boot == [0; 16]
            || self.publisher_invocation == [0; 16]
            || self.predecessor_ordinal.checked_add(1) != Some(self.publisher_generation)
            || self.predecessor_ordinal == 0
            || self.publisher_generation == 0
            || self.predecessor_sequence == 0
            || self.predecessor_sequence.checked_add(3).is_none()
            || self.nspawn_device == 0
            || self.nspawn_inode == 0
            || (self.predecessor_ordinal == 1) != (self.previous_record == [0; 32])
            || [
                self.purpose,
                self.signed_genesis_digest,
                self.source_contract,
                self.publisher_profile,
                self.nspawn_path_digest,
                self.nspawn_digest,
                self.pid1_digest,
                self.hostd_digest,
                self.inspector_digest,
                self.probe_digest,
                self.mac_policy_digest,
                self.supervisor_profile_digest,
                self.payload_filter_digest,
                self.artifact_digest,
                self.predecessor_head,
                self.predecessor_nv,
            ]
            .contains(&[0; 32])
        {
            return Err(DeploymentWireErrorV1);
        }
        let mut bytes = [0; BOOT_PREPARATION_RECORD_BODY_BYTES_V1];
        header(&mut bytes, b"AOSRDBR1");
        bytes[80..96].copy_from_slice(&self.node);
        bytes[96..112].copy_from_slice(&self.deployment);
        bytes[120..136].copy_from_slice(&self.boot);
        bytes[648..664].copy_from_slice(&self.publisher_invocation);
        for (offset, field) in [
            (16, &self.purpose),
            (48, &self.signed_genesis_digest),
            (136, &self.previous_record),
            (168, &self.source_contract),
            (200, &self.publisher_profile),
            (232, &self.nspawn_path_digest),
            (280, &self.nspawn_digest),
            (312, &self.pid1_digest),
            (344, &self.hostd_digest),
            (376, &self.inspector_digest),
            (408, &self.probe_digest),
            (440, &self.mac_policy_digest),
            (472, &self.supervisor_profile_digest),
            (504, &self.payload_filter_digest),
            (536, &self.artifact_digest),
            (584, &self.predecessor_head),
            (616, &self.predecessor_nv),
        ] {
            bytes[offset..offset + 32].copy_from_slice(field);
        }
        for (offset, value) in [
            (112, self.publisher_generation),
            (264, self.nspawn_device),
            (272, self.nspawn_inode),
            (568, self.predecessor_ordinal),
            (576, self.predecessor_sequence),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        Ok(bytes)
    }

    /// Builds the fixed publisher signing preimage from the sole body encoder.
    ///
    /// # Errors
    /// Rejects the same structural failures as [`Self::encode_body_v1`].
    pub fn signing_bytes_v1(&self) -> Result<Vec<u8>, DeploymentWireErrorV1> {
        let mut bytes =
            Vec::with_capacity(RECORD_DOMAIN.len() + BOOT_PREPARATION_RECORD_BODY_BYTES_V1);
        bytes.extend_from_slice(RECORD_DOMAIN);
        bytes.extend_from_slice(&self.encode_body_v1()?);
        Ok(bytes)
    }
}

/// Holds a signature-verified normal record as historical comparison DATA.
pub struct SignedBootPreparationRecordDataV1 {
    fields: BootPreparationRecordDataV1,
    bytes: [u8; BOOT_PREPARATION_RECORD_BYTES_V1],
}

impl SignedBootPreparationRecordDataV1 {
    /// Verifies one complete normal record against its independent purpose.
    ///
    /// # Errors
    /// Refuses unsupported framing, any malformed field or crosslink, and a bad
    /// signature. It proves no live floor, current boot, native receipt or scope.
    pub fn verify_v1(
        bytes: &[u8],
        purpose: &SignedBootPreparationPurposeDataV1,
    ) -> Result<Self, DeploymentWireErrorV1> {
        require_header(bytes, BOOT_PREPARATION_RECORD_BYTES_V1, b"AOSRDBR1")?;
        let fields = BootPreparationRecordDataV1 {
            purpose: take(bytes, 16)?,
            signed_genesis_digest: take(bytes, 48)?,
            node: take(bytes, 80)?,
            deployment: take(bytes, 96)?,
            publisher_generation: number(bytes, 112)?,
            boot: take(bytes, 120)?,
            publisher_invocation: take(bytes, 648)?,
            previous_record: take(bytes, 136)?,
            source_contract: take(bytes, 168)?,
            publisher_profile: take(bytes, 200)?,
            nspawn_path_digest: take(bytes, 232)?,
            nspawn_device: number(bytes, 264)?,
            nspawn_inode: number(bytes, 272)?,
            nspawn_digest: take(bytes, 280)?,
            pid1_digest: take(bytes, 312)?,
            hostd_digest: take(bytes, 344)?,
            inspector_digest: take(bytes, 376)?,
            probe_digest: take(bytes, 408)?,
            mac_policy_digest: take(bytes, 440)?,
            supervisor_profile_digest: take(bytes, 472)?,
            payload_filter_digest: take(bytes, 504)?,
            artifact_digest: take(bytes, 536)?,
            predecessor_ordinal: number(bytes, 568)?,
            predecessor_sequence: number(bytes, 576)?,
            predecessor_head: take(bytes, 584)?,
            predecessor_nv: take(bytes, 616)?,
        };
        let contract = purpose.fields_v1();
        if fields.encode_body_v1()?.as_slice() != &bytes[..BOOT_PREPARATION_RECORD_BODY_BYTES_V1]
            || fields.purpose != purpose.digest_v1()
            || fields.node != contract.node
            || fields.deployment != contract.deployment
            || fields.signed_genesis_digest != contract.signed_genesis_digest
            || fields.source_contract != contract.source_contract
            || fields.publisher_profile != contract.publisher_profile
        {
            return Err(DeploymentWireErrorV1);
        }
        let publisher =
            VerifyingKey::from_bytes(&contract.publisher).map_err(|_| DeploymentWireErrorV1)?;
        verify_signature(
            bytes,
            BOOT_PREPARATION_RECORD_BODY_BYTES_V1,
            RECORD_DOMAIN,
            &publisher,
        )?;
        Ok(Self {
            fields,
            bytes: bytes.try_into().map_err(|_| DeploymentWireErrorV1)?,
        })
    }

    /// Borrows all authenticated historical fields without a currentness grant.
    #[must_use]
    pub const fn fields_v1(&self) -> &BootPreparationRecordDataV1 {
        &self.fields
    }

    /// Borrows exact immutable signed bytes for the one full-fold engine.
    #[must_use]
    pub const fn bytes_v1(&self) -> &[u8; BOOT_PREPARATION_RECORD_BYTES_V1] {
        &self.bytes
    }

    /// Commits the complete record, including its exact signature.
    #[must_use]
    pub fn digest_v1(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(RECORD_DIGEST_DOMAIN)
            .chain_update(self.bytes)
            .finalize()
            .into()
    }
}

fn header(bytes: &mut [u8], magic: &[u8; 8]) {
    bytes[..8].copy_from_slice(magic);
    bytes[8..12].copy_from_slice(&1u32.to_be_bytes());
}

fn require_header(
    bytes: &[u8],
    width: usize,
    magic: &[u8; 8],
) -> Result<(), DeploymentWireErrorV1> {
    if bytes.len() != width
        || &bytes[..8] != magic
        || bytes[8..12] != 1u32.to_be_bytes()
        || bytes[12..16] != [0; 4]
    {
        return Err(DeploymentWireErrorV1);
    }
    Ok(())
}

fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], DeploymentWireErrorV1> {
    bytes
        .get(offset..offset + N)
        .ok_or(DeploymentWireErrorV1)?
        .try_into()
        .map_err(|_| DeploymentWireErrorV1)
}

fn number(bytes: &[u8], offset: usize) -> Result<u64, DeploymentWireErrorV1> {
    Ok(u64::from_be_bytes(take(bytes, offset)?))
}

fn verify_signature(
    bytes: &[u8],
    body_width: usize,
    domain: &[u8],
    key: &VerifyingKey,
) -> Result<(), DeploymentWireErrorV1> {
    let signature: [u8; 64] = bytes[body_width..]
        .try_into()
        .map_err(|_| DeploymentWireErrorV1)?;
    let mut preimage = Vec::with_capacity(domain.len() + body_width);
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&bytes[..body_width]);
    key.verify_strict(&preimage, &Signature::from_bytes(&signature))
        .map_err(|_| DeploymentWireErrorV1)
}

/// Derives the independently provisioned normal genesis native UUID as DATA.
///
/// It is derived after signing, so no future complete HEAD occurs in its own
/// genesis preimage. This does not initialize or adopt either physical writer.
#[must_use]
pub fn boot_preparation_genesis_transaction_data_v1(
    composite: &[u8; BOOT_PREPARATION_COMPOSITE_GENESIS_BYTES_V1],
) -> [u8; 16] {
    native_identity(
        b"aos.runtime-deployment.boot-genesis-native.v1\0",
        composite,
    )
}

/// Encodes the one canonical immutable normal record key.
///
/// # Errors
/// Refuses a generation before the first actual successor of provisioned ordinal1;
/// actual floor association remains native.
pub fn boot_preparation_key_data_v1(generation: u64) -> Result<[u8; 10], DeploymentWireErrorV1> {
    if generation < 2 {
        return Err(DeploymentWireErrorV1);
    }
    let mut key = [0; 10];
    key[0] = b'g';
    key[1..9].copy_from_slice(&generation.to_be_bytes());
    // The existing shared native history carries one canonical ten-byte key.
    // Phase1 is the sole completed preparation, never a canary phase.
    key[9] = 1;
    Ok(key)
}

/// Derives the canonical original transaction identity from the complete body.
///
/// # Errors
/// Rejects the same structural failures as the sole body encoder. A computed
/// UUID supplies no native writer, debit, floor or publication authority.
pub fn boot_preparation_transaction_data_v1(
    fields: &BootPreparationRecordDataV1,
) -> Result<[u8; 16], DeploymentWireErrorV1> {
    Ok(native_identity(
        b"aos.runtime-deployment.boot-record-native.v1\0",
        &fields.encode_body_v1()?,
    ))
}

fn native_identity(domain: &[u8], bytes: &[u8]) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(domain)
        .chain_update(bytes)
        .finalize();
    let mut identity = [0; 16];
    identity.copy_from_slice(&digest[..16]);
    identity[6] = (identity[6] & 0x0f) | 0x80;
    identity[8] = (identity[8] & 0x3f) | 0x80;
    identity
}

/// Commits the genuine normal Source grammar and SAME-account partition law.
///
/// Actual node/boot/invocation/Parent/native liveness are checked separately by
/// the real private issuer. This static contract is neither a source receipt
/// nor a way to select a Parent vector from caller DATA.
#[must_use]
pub fn boot_preparation_source_contract_data_v1() -> [u8; 32] {
    contract(
        b"aos.runtime-deployment.boot-source-contract.v1\0",
        &[
            "AOSRPE06",
            "AOSRSO03:role6",
            "initial4:listener,pid1,profile,source",
            "aos-sandbox-runtime-publisher.service",
            "--boot-preparation-v1",
            "Type=oneshot;RemainAfterExit=yes",
            "PassSubjectBeforeListen=yes",
            "Parent.manager.hostBootPreparationSender",
            "HostService.hostBootPreparationReceiving:disjoint-baseline-complement",
            "same-Parent-allocation-account:monotone-spent-highwater-no-new-B",
            "before+always-owed-after;whole-originals-until-process-exit",
        ],
    )
}

/// Commits the exact compiled normal recipe AND its immutable actual ELF pin.
#[must_use]
pub fn boot_preparation_program_contract_data_v1(executable_digest: [u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(contract(
            b"aos.runtime-deployment.boot-program-contract.v1\0",
            &[
                "runtime-boot-preparation",
                "--boot-preparation-v1",
                "source-first-initial4-before-argv-runtime-credentials",
                "signed-normal-purpose+provisioned-genesis+complete055-native-history",
                "fresh055-before+funded-single-PUT+prepare+extend+commit+finalize+fresh055-after",
                "retained-measured-boot+nspawn-artifact+hostd+inspector+signed-AOSHPB02+live-MAC",
                "same055-target-ordinal-is-generation;no-canary-ordinal;no-BackendReadiness",
                "bounded-JSON+full-signed-completion+protected-atomic-write+exact-readback",
                "all-posts-before-exit0;independent-current-successful-oneshot-consumer",
            ],
        ))
        .chain_update(executable_digest)
        .finalize()
        .into()
}

/// Commits only the fixed normal trust/secret roles and protected delivery law.
#[must_use]
pub fn boot_preparation_credential_contract_data_v1() -> [u8; 32] {
    contract(
        b"aos.runtime-deployment.boot-credential-contract.v1\0",
        &[
            "/run/credentials/aos-sandbox-runtime-publisher.service",
            "runtime-deployment-genesis-v1:468",
            "runtime-deployment-provisioner-pin-v1:32:independent",
            "runtime-deployment-signing-seed-v1:32:existing055publisher",
            "runtime-deployment-tpm-index-auth-v1:32:separate-existing055auth",
            "runtime-deployment-boot-purpose-v1:336",
            "phase0-probe-public-key-v1:32:independent-public-verifier",
            "root-only;readonly-mount;no-access-or-default-ACL",
            "Host-receives-public-genesis+pin+purpose+immutable-profile-only",
        ],
    )
}

/// Commits the unchanged055 pair and the distinct protected readiness namespace.
#[must_use]
pub fn boot_preparation_directory_contract_data_v1() -> [u8; 32] {
    contract(
        b"aos.runtime-deployment.boot-directory-contract.v1\0",
        &[
            "/var/lib/aos/sandbox/runtime-deployment",
            "preparation.journal",
            "tpm-floor.journal",
            "NV=0x0180a055;salt=0x8100a055",
            "externally-provisioned-genesis-checkpoint:ordinal1;NEXT4",
            "AOSRDBP1:336",
            "normal-composite-genesis:804",
            "AOSRDBR1:728",
            "g+ordinalBE+phase1:10",
            "AOSRDBC1:888",
            "/var/lib/aos/sandbox/runtime-deployment/readiness",
            "backend-readiness.next->backend-readiness.json:16384",
            "backend-readiness-completion.next->backend-readiness-completion-v1:888",
            "root-owned-fixed-directory;no-Host-write;held-native-posts+readback",
        ],
    )
}

fn contract(domain: &[u8], text: &[&str]) -> [u8; 32] {
    let mut hash = Sha256::new().chain_update(domain);
    for value in text {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    hash.finalize().into()
}

#[cfg(test)]
mod tests;
