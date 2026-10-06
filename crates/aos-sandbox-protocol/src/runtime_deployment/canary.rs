//! Owns the closed, version-separated Host055 canary comparison codecs.
//!
//! Signatures authenticate historical DATA, not a live floor or effect permit.
//! The installed producer must separately retain its startup, delegate, original
//! writers, clock and authenticated physical observation around every crossing.
//!
//! ```text
//! AOSRDCP2:432 + signature64 = purpose496
//! AOSRDCQ3:96 + request402 + marker208 + coordinates120 = request826
//! AOSRDC02:712 + signature64 = association776
//! AOSRDCR2:304 + signature64 = current368; association || current = reply1144
//! ```

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use super::{DeploymentGenesisV1, DeploymentWireErrorV1, array};
use crate::storage_root_export::StorageCanaryExportRequestV1;

/// Exact signed purpose width, independently provisioned before startup.
pub const PURPOSE_BYTES_V2: usize = 496;
/// Exact current version-separated publisher request width.
pub const REQUEST_BYTES_V3: usize = 826;
/// Exact immutable signed association width.
pub const ASSOCIATION_BYTES_V2: usize = 776;
/// Exact separately signed fresh-current receipt width.
pub const CURRENT_BYTES_V2: usize = 368;
/// Exact no-application-FD publisher reply width.
pub const REPLY_BYTES_V2: usize = ASSOCIATION_BYTES_V2 + CURRENT_BYTES_V2;
/// Fixed selected native genesis key; never aliases the old V1 key.
pub const GENESIS_KEY_V2: &[u8] = b"deployment-canary-genesis-v2";
/// Exact signed V1 genesis plus independently signed selected purpose width.
pub const COMPOSITE_GENESIS_BYTES_V2: usize = 468 + PURPOSE_BYTES_V2;
/// Maximum number of immutable associations in this provisioned purpose.
pub const MAXIMUM_ATTEMPTS_V2: u64 = 64;

/// Preserves authentic delegate-held coordinates as nonauthorizing DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageCoordinatesV3 {
    /// Actual catalog digest from the same validated physical binding.
    pub catalog_digest: [u8; 32],
    /// Actual catalog generation from that binding.
    pub catalog_generation: u64,
    /// Same primary predecessor's actual next native sequence.
    pub primary_next: u64,
    /// Existing materialized-primary head, not its complete-history digest.
    pub primary_head: [u8; 32],
    /// Same native issuance predecessor's actual next sequence.
    pub native_next: u64,
    /// Existing operator-named materialized-native cut DATA, not permission.
    pub native_head: [u8; 32],
}

impl StorageCoordinatesV3 {
    fn validate(&self) -> Result<(), DeploymentWireErrorV1> {
        if [self.catalog_digest, self.primary_head, self.native_head].contains(&[0; 32])
            || self.catalog_generation == 0
            || [self.primary_next, self.native_next].iter()
                .any(|next| *next == 0 || *next == u64::MAX)
        {
            return Err(DeploymentWireErrorV1);
        }
        Ok(())
    }

    fn encode_into(&self, bytes: &mut [u8; 120]) -> Result<(), DeploymentWireErrorV1> {
        self.validate()?;
        bytes[..32].copy_from_slice(&self.catalog_digest);
        bytes[32..40].copy_from_slice(&self.catalog_generation.to_be_bytes());
        bytes[40..48].copy_from_slice(&self.primary_next.to_be_bytes());
        bytes[48..80].copy_from_slice(&self.primary_head);
        bytes[80..88].copy_from_slice(&self.native_next.to_be_bytes());
        bytes[88..120].copy_from_slice(&self.native_head);
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self, DeploymentWireErrorV1> {
        if bytes.len() != 120 {
            return Err(DeploymentWireErrorV1);
        }
        let value = Self {
            catalog_digest: array(bytes, 0)?,
            catalog_generation: u64::from_be_bytes(array(bytes, 32)?),
            primary_next: u64::from_be_bytes(array(bytes, 40)?),
            primary_head: array(bytes, 48)?,
            native_next: u64::from_be_bytes(array(bytes, 80)?),
            native_head: array(bytes, 88)?,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Carries the exact original request, saved marker and delegate-held coordinates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanaryPublisherRequestV3 {
    /// Same challenge as the original Host request and signed job.
    pub nonce: [u8; 32],
    /// Same physical kernel boot as the independently signed job.
    pub boot: [u8; 16],
    /// Original independently signed lower boottime bound.
    pub not_before: u64,
    /// Original exclusive deadline, never renewed by this codec.
    pub deadline: u64,
    /// Exact complete signed job length carried by the one original FD.
    pub job_bytes: u32,
    /// Exact original canonical AOSRCQ01 request bytes.
    pub request: [u8; 402],
    /// Exact saved AOSCEB01 marker, prepared before association signing.
    pub marker: [u8; 208],
    /// Authenticated delegate-held DATA; the publisher does not reopen its writers.
    pub storage: StorageCoordinatesV3,
}

impl CanaryPublisherRequestV3 {
    /// Encodes the fixed v3 request without creating a live cut.
    ///
    /// # Errors
    /// Refuses sentinel fields, a renewed/oversized window, wrong marker/header
    /// or canonical embedded request crosslinks and invalid coordinates.
    pub fn encode(&self) -> Result<[u8; REQUEST_BYTES_V3], DeploymentWireErrorV1> {
        let request = StorageCanaryExportRequestV1::decode(&self.request)
            .map_err(|_| DeploymentWireErrorV1)?;
        if self.nonce == [0; 32] || self.boot == [0; 16]
            || self.deadline.checked_sub(self.not_before)
                .is_none_or(|width| width == 0 || width > 300_000_000_000)
            || !(1032..=349_192).contains(&self.job_bytes)
            || request.nonce != self.nonce || request.boot_id != self.boot
            || request.deadline_boottime_nanoseconds != self.deadline
            || self.marker[..8] != *b"AOSCEB01"
            || self.marker[8..10] != 1u16.to_be_bytes()
            || self.marker[10..12] != [0; 2]
            || self.marker[12..16] != 208u32.to_be_bytes()
            || self.marker[16..48] != request.digest().map_err(|_| DeploymentWireErrorV1)?
            || self.marker[144..176] != request.job_digest
            || self.marker[48..80] == [0; 32]
            || self.marker[80..112] == [0; 32]
            || self.marker[112..144] == [0; 32]
            || self.marker[176..208] == [0; 32]
        {
            return Err(DeploymentWireErrorV1);
        }
        let mut bytes = [0; REQUEST_BYTES_V3];
        bytes[..8].copy_from_slice(b"AOSRDCQ3");
        bytes[8..10].copy_from_slice(&3u16.to_be_bytes());
        bytes[12..44].copy_from_slice(&self.nonce);
        bytes[44..60].copy_from_slice(&self.boot);
        bytes[60..68].copy_from_slice(&self.not_before.to_be_bytes());
        bytes[68..76].copy_from_slice(&self.deadline.to_be_bytes());
        bytes[76..80].copy_from_slice(&self.job_bytes.to_be_bytes());
        bytes[80..84].copy_from_slice(&402u32.to_be_bytes());
        bytes[84..88].copy_from_slice(&208u32.to_be_bytes());
        bytes[96..498].copy_from_slice(&self.request);
        bytes[498..706].copy_from_slice(&self.marker);
        let mut storage = [0; 120];
        self.storage.encode_into(&mut storage)?;
        bytes[706..826].copy_from_slice(&storage);
        Ok(bytes)
    }

    /// Decodes only v3, refusing the superseded 706-byte v2 grammar.
    ///
    /// # Errors
    /// Refuses width, version, reserved bytes and all encoding crosslinks.
    pub fn decode(bytes: &[u8]) -> Result<Self, DeploymentWireErrorV1> {
        require_header(bytes, REQUEST_BYTES_V3, b"AOSRDCQ3", 3)?;
        if bytes[80..84] != 402u32.to_be_bytes()
            || bytes[84..88] != 208u32.to_be_bytes() || bytes[88..96] != [0; 8]
        {
            return Err(DeploymentWireErrorV1);
        }
        let value = Self {
            nonce: array(bytes, 12)?, boot: array(bytes, 44)?,
            not_before: u64::from_be_bytes(array(bytes, 60)?),
            deadline: u64::from_be_bytes(array(bytes, 68)?),
            job_bytes: u32::from_be_bytes(array(bytes, 76)?),
            request: array(bytes, 96)?, marker: array(bytes, 498)?,
            storage: StorageCoordinatesV3::decode(&bytes[706..826])?,
        };
        if value.encode()?.as_slice() != bytes {
            return Err(DeploymentWireErrorV1);
        }
        Ok(value)
    }
}

/// Preserves the exact independently signed selected purpose.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanaryPurposeV2 {
    bytes: [u8; PURPOSE_BYTES_V2],
}

impl CanaryPurposeV2 {
    /// Decodes and verifies the purpose against the original provisioner and genesis.
    ///
    /// # Errors
    /// Rejects unsupported grammar, sentinel or weak keys, role reuse, Names,
    /// signatures and genesis crosslinks. Live profile/contract checks are separate.
    pub fn decode(
        bytes: &[u8],
        signed_genesis: &[u8; 468],
        genesis: &DeploymentGenesisV1,
        provisioner: &VerifyingKey,
    ) -> Result<Self, DeploymentWireErrorV1> {
        require_header(bytes, PURPOSE_BYTES_V2, b"AOSRDCP2", 2)?;
        let publisher: [u8; 32] = array(bytes, 80)?;
        let approval: [u8; 32] = array(bytes, 128)?;
        let approval_key = VerifyingKey::from_bytes(&approval).map_err(|_| DeploymentWireErrorV1)?;
        if bytes[12..16] != [0; 4] || bytes[424..432] != [0; 8]
            || bytes[16..48] != Sha256::digest(signed_genesis).as_slice()
            || bytes[48..64] != genesis.node || bytes[64..80] != genesis.deployment
            || publisher != genesis.signer || approval_key.is_weak()
            || VerifyingKey::from_bytes(&publisher).map_err(|_| DeploymentWireErrorV1)?.is_weak()
            || publisher == approval || approval == provisioner.to_bytes()
            || publisher == provisioner.to_bytes() || bytes[112..128] == [0; 16]
            || bytes[320..354] != genesis.nv_name || bytes[354..388] != genesis.salt_name
            || bytes[388..392] != 64u32.to_be_bytes()
            || [160, 192, 224, 256, 288, 392].iter()
                .any(|offset| bytes[*offset..*offset + 32] == [0; 32])
        {
            return Err(DeploymentWireErrorV1);
        }
        verify_signed(bytes, 432, b"aos.runtime-deployment.canary-purpose.v2\0", provisioner)?;
        Ok(Self { bytes: array(bytes, 0)? })
    }

    /// Borrows exact independently provisioned bytes as comparison DATA.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; PURPOSE_BYTES_V2] { &self.bytes }

    /// Returns the independently admitted job approval pin as DATA, not a loader.
    #[must_use]
    pub fn approval_pin(&self) -> [u8; 48] {
        let mut pin = [0; 48];
        pin.copy_from_slice(&self.bytes[112..160]);
        pin
    }

    /// Returns the exact signed-purpose domain-separated digest.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        digest(b"aos.runtime-deployment.canary-purpose-digest.v2\0", &self.bytes)
    }

    /// Borrows a fixed schema field for same-origin comparison, never authority.
    ///
    /// # Errors
    /// Refuses any offset outside the six declared contract fields.
    pub fn contract(&self, offset: usize) -> Result<[u8; 32], DeploymentWireErrorV1> {
        if ![160, 192, 224, 256, 288, 392].contains(&offset) {
            return Err(DeploymentWireErrorV1);
        }
        array(&self.bytes, offset)
    }
}

/// Names the complete immutable association's nonauthorizing input fields.
///
/// Construction and encoding never authenticate a caller's scalar quantities.
/// The installed signer obtains them only from its same original owners.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanaryAssociationFieldsV2 {
    /// Digest of the exact independently signed selected purpose.
    pub purpose: [u8; 32],
    /// SHA-256 of the exact signed V1 genesis.
    pub genesis: [u8; 32],
    /// Independently provisioned node identity.
    pub node: [u8; 16],
    /// Independently provisioned deployment identity.
    pub deployment: [u8; 16],
    /// One immutable association's ordinal, from one through sixty-four.
    pub ordinal: u64,
    /// Original full job's attempt identity.
    pub attempt: [u8; 16],
    /// Original physical kernel boot identity.
    pub boot: [u8; 16],
    /// Independently signed original lower boottime bound.
    pub not_before: u64,
    /// Independently signed original exclusive deadline.
    pub deadline: u64,
    /// Digest of the entire signed job, including its signature.
    pub job_digest: [u8; 32],
    /// Existing canonical 402-byte request digest.
    pub request_digest: [u8; 32],
    /// Actual fixed Storage service invocation observed under unique PID1.
    pub storage_invocation: [u8; 16],
    /// Actual received kernel subject's live PID.
    pub storage_pid: u32,
    /// Actual same subject's original start-time ticks.
    pub storage_start_ticks: u64,
    /// Independently authenticated Storage image/profile digest.
    pub storage_profile: [u8; 32],
    /// Independently authenticated Storage MAC policy digest.
    pub storage_policy: [u8; 32],
    /// Genuine delegate-held catalog and both materialized predecessor cuts.
    pub storage: StorageCoordinatesV3,
    /// Existing saved marker transaction identity, not this association's TX.
    pub marker_transaction: [u8; 16],
    /// Plain SHA-256 of the exact saved 208-byte marker.
    pub marker_digest: [u8; 32],
    /// Same canonical held child identity retained by Storage.
    pub held_identity: [u8; 32],
    /// Complete predecessor association digest; zero only at ordinal one.
    pub previous_association: [u8; 32],
    /// Actual original 055 main predecessor NEXT.
    pub main_next: u64,
    /// Actual original 055 main predecessor materialized HEAD.
    pub main_head: [u8; 32],
    /// Saved association transaction derived before encoding this body.
    pub main_transaction: [u8; 16],
    /// Genuine selected publisher startup profile digest.
    pub publisher_profile: [u8; 32],
    /// Genuine selected publisher enforcing MAC policy digest.
    pub publisher_policy: [u8; 32],
    /// Same nonce as the original job and request.
    pub nonce: [u8; 32],
}

impl CanaryAssociationFieldsV2 {
    /// Encodes the sole canonical unsigned association body.
    ///
    /// # Errors
    /// Rejects sentinels, exhausted ordinals/NEXT, renewed deadlines, invalid
    /// predecessor shape and an incorrectly derived saved transaction identity.
    pub fn encode_body(&self) -> Result<[u8; 712], DeploymentWireErrorV1> {
        self.storage.validate()?;
        if !(1..=MAXIMUM_ATTEMPTS_V2).contains(&self.ordinal)
            || self.storage_pid <= 1 || self.storage_start_ticks == 0
            || self.main_next == 0 || self.main_next == u64::MAX
            || (self.previous_association == [0; 32]) != (self.ordinal == 1)
            || self.deadline.checked_sub(self.not_before)
                .is_none_or(|width| width == 0 || width > 300_000_000_000)
            || [self.node, self.deployment, self.attempt, self.boot,
                self.storage_invocation, self.marker_transaction, self.main_transaction]
                .contains(&[0; 16])
            || [self.purpose, self.genesis, self.job_digest, self.request_digest,
                self.storage_profile, self.storage_policy, self.marker_digest,
                self.held_identity, self.main_head, self.publisher_profile,
                self.publisher_policy, self.nonce].contains(&[0; 32])
            || self.main_transaction != association_transaction_v2(
                self.purpose, self.request_digest, self.storage.primary_head,
                self.main_head, self.ordinal,
            )?
        {
            return Err(DeploymentWireErrorV1);
        }

        let mut body = [0; 712];
        body[..8].copy_from_slice(b"AOSRDC02");
        body[8..10].copy_from_slice(&2u16.to_be_bytes());
        for (offset, value) in [
            (16, &self.purpose), (48, &self.genesis),
            (168, &self.job_digest), (200, &self.request_digest),
            (264, &self.storage_profile), (296, &self.storage_policy),
            (328, &self.storage.catalog_digest), (376, &self.storage.primary_head),
            (424, &self.marker_digest), (464, &self.storage.native_head),
            (496, &self.held_identity), (528, &self.previous_association),
            (568, &self.main_head), (616, &self.publisher_profile),
            (648, &self.publisher_policy), (680, &self.nonce),
        ] {
            body[offset..offset + 32].copy_from_slice(value);
        }
        for (offset, value) in [
            (80, &self.node), (96, &self.deployment), (120, &self.attempt),
            (136, &self.boot), (232, &self.storage_invocation),
            (408, &self.marker_transaction), (600, &self.main_transaction),
        ] {
            body[offset..offset + 16].copy_from_slice(value);
        }
        for (offset, value) in [
            (112, self.ordinal), (152, self.not_before), (160, self.deadline),
            (256, self.storage_start_ticks), (360, self.storage.catalog_generation),
            (368, self.storage.primary_next), (456, self.storage.native_next),
            (560, self.main_next),
        ] {
            body[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        body[248..252].copy_from_slice(&self.storage_pid.to_be_bytes());
        Ok(body)
    }

    fn decode_body(bytes: &[u8]) -> Result<Self, DeploymentWireErrorV1> {
        if bytes.len() != 712 || bytes[..8] != *b"AOSRDC02"
            || bytes[8..10] != 2u16.to_be_bytes() || bytes[10..16] != [0; 6]
            || bytes[252..256] != [0; 4]
        {
            return Err(DeploymentWireErrorV1);
        }
        let value = Self {
            purpose: array(bytes, 16)?, genesis: array(bytes, 48)?,
            node: array(bytes, 80)?, deployment: array(bytes, 96)?,
            ordinal: u64::from_be_bytes(array(bytes, 112)?),
            attempt: array(bytes, 120)?, boot: array(bytes, 136)?,
            not_before: u64::from_be_bytes(array(bytes, 152)?),
            deadline: u64::from_be_bytes(array(bytes, 160)?),
            job_digest: array(bytes, 168)?, request_digest: array(bytes, 200)?,
            storage_invocation: array(bytes, 232)?,
            storage_pid: u32::from_be_bytes(array(bytes, 248)?),
            storage_start_ticks: u64::from_be_bytes(array(bytes, 256)?),
            storage_profile: array(bytes, 264)?, storage_policy: array(bytes, 296)?,
            storage: StorageCoordinatesV3 {
                catalog_digest: array(bytes, 328)?,
                catalog_generation: u64::from_be_bytes(array(bytes, 360)?),
                primary_next: u64::from_be_bytes(array(bytes, 368)?),
                primary_head: array(bytes, 376)?,
                native_next: u64::from_be_bytes(array(bytes, 456)?),
                native_head: array(bytes, 464)?,
            },
            marker_transaction: array(bytes, 408)?, marker_digest: array(bytes, 424)?,
            held_identity: array(bytes, 496)?, previous_association: array(bytes, 528)?,
            main_next: u64::from_be_bytes(array(bytes, 560)?), main_head: array(bytes, 568)?,
            main_transaction: array(bytes, 600)?, publisher_profile: array(bytes, 616)?,
            publisher_policy: array(bytes, 648)?, nonce: array(bytes, 680)?,
        };
        if value.encode_body()?.as_slice() != bytes {
            return Err(DeploymentWireErrorV1);
        }
        Ok(value)
    }
}

/// Preserves an authenticated historical association, never a live effect permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanaryAssociationV2 {
    fields: CanaryAssociationFieldsV2,
    exact: [u8; ASSOCIATION_BYTES_V2],
}

impl CanaryAssociationV2 {
    /// Combines canonical DATA and an already obtained signature for verification.
    ///
    /// # Errors
    /// Rejects invalid canonical fields; this does not validate the signature.
    pub fn from_signed_parts(fields: CanaryAssociationFieldsV2, signature: [u8; 64])
        -> Result<Self, DeploymentWireErrorV1>
    {
        let body = fields.encode_body()?;
        let mut exact = [0; ASSOCIATION_BYTES_V2];
        exact[..712].copy_from_slice(&body);
        exact[712..].copy_from_slice(&signature);
        Ok(Self { fields, exact })
    }

    /// Decodes the sole canonical grammar and verifies the independent publisher.
    ///
    /// # Errors
    /// Rejects width, canonical DATA, weak keys and strict signature failures.
    pub fn decode(bytes: &[u8], publisher: &VerifyingKey) -> Result<Self, DeploymentWireErrorV1> {
        require_header(bytes, ASSOCIATION_BYTES_V2, b"AOSRDC02", 2)?;
        let fields = CanaryAssociationFieldsV2::decode_body(&bytes[..712])?;
        verify_signed(bytes, 712, ASSOCIATION_SIGNATURE_DOMAIN_V2, publisher)?;
        Ok(Self { fields, exact: array(bytes, 0)? })
    }

    /// Borrows authenticated historical fields without currentness conversion.
    #[must_use]
    pub const fn fields(&self) -> &CanaryAssociationFieldsV2 { &self.fields }

    /// Borrows the complete canonical signed row.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; ASSOCIATION_BYTES_V2] { &self.exact }

    /// Derives the closed immutable association digest from the whole signed row.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        digest(b"aos.runtime-deployment.canary-association-digest.v2\0", &self.exact)
    }

    /// Compares the authenticated row with one exact already retained request.
    ///
    /// This checks historical crosslinks only; Storage must still rejoin both
    /// original writer cuts, authenticated delegate and original clock.
    ///
    /// # Errors
    /// Refuses a foreign purpose/genesis, request, marker, predecessor or mode.
    pub fn require_request_v3(
        &self, request: &CanaryPublisherRequestV3,
        genesis: &DeploymentGenesisV1, purpose: &CanaryPurposeV2,
    ) -> Result<(), DeploymentWireErrorV1> {
        request.encode()?;
        let fields = &self.fields;
        if fields.purpose != purpose.digest() || fields.node != genesis.node
            || fields.deployment != genesis.deployment
            || fields.genesis != array(purpose.bytes(), 16)?
            || fields.nonce != request.nonce || fields.boot != request.boot
            || fields.not_before != request.not_before || fields.deadline != request.deadline
            || fields.job_digest != request.marker[144..176]
            || fields.request_digest != request.marker[16..48]
            || fields.storage != request.storage
            || fields.storage_profile != purpose.contract(160)?
            || fields.storage_policy != purpose.contract(192)?
            || fields.publisher_profile != genesis.publisher_profile
            || fields.publisher_policy != genesis.mac_policy
            || fields.held_identity != request.marker[48..80]
            || fields.marker_digest != <[u8; 32]>::from(Sha256::digest(request.marker))
        {
            return Err(DeploymentWireErrorV1);
        }
        Ok(())
    }
}

/// Names separately observed receipt fields; none is a reconstructed live owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanaryCurrentFieldsV2 {
    /// Exact independently signed selected purpose digest.
    pub purpose: [u8; 32],
    /// Digest of the entire immutable signed association.
    pub association: [u8; 32],
    /// Same original request nonce.
    pub nonce: [u8; 32],
    /// Same complete signed job digest.
    pub job_digest: [u8; 32],
    /// Original independently provisioned node.
    pub node: [u8; 16],
    /// Original independently provisioned deployment.
    pub deployment: [u8; 16],
    /// Same original full-job attempt.
    pub attempt: [u8; 16],
    /// Same immutable association ordinal.
    pub ordinal: u64,
    /// Actual completed main's next native sequence.
    pub main_next: u64,
    /// Actual completed main's materialized head.
    pub main_head: [u8; 32],
    /// Actual independently authenticated fresh final NV observation.
    pub fresh_nv: [u8; 32],
    /// Same original physical boot.
    pub boot: [u8; 16],
    /// Same independently signed lower boottime bound.
    pub not_before: u64,
    /// Same original exclusive deadline.
    pub deadline: u64,
}

impl CanaryCurrentFieldsV2 {
    /// Encodes the sole unsigned receipt without issuing currentness.
    ///
    /// # Errors
    /// Refuses sentinel fields, ordinal/NEXT exhaustion and unsupported windows.
    pub fn encode_body(&self) -> Result<[u8; 304], DeploymentWireErrorV1> {
        if [self.purpose, self.association, self.nonce, self.job_digest,
            self.main_head, self.fresh_nv].contains(&[0; 32])
            || [self.node, self.deployment, self.attempt, self.boot].contains(&[0; 16])
            || !(1..=MAXIMUM_ATTEMPTS_V2).contains(&self.ordinal)
            || self.main_next == 0 || self.main_next == u64::MAX
            || self.deadline.checked_sub(self.not_before)
                .is_none_or(|width| width == 0 || width > 300_000_000_000)
        {
            return Err(DeploymentWireErrorV1);
        }
        let mut body = [0; 304];
        body[..8].copy_from_slice(b"AOSRDCR2");
        body[8..10].copy_from_slice(&2u16.to_be_bytes());
        for (offset, field) in [
            (16, &self.purpose), (48, &self.association), (80, &self.nonce),
            (112, &self.job_digest), (208, &self.main_head), (240, &self.fresh_nv),
        ] {
            body[offset..offset + 32].copy_from_slice(field);
        }
        for (offset, field) in [
            (144, &self.node), (160, &self.deployment), (176, &self.attempt), (272, &self.boot),
        ] {
            body[offset..offset + 16].copy_from_slice(field);
        }
        for (offset, field) in [
            (192, self.ordinal), (200, self.main_next),
            (288, self.not_before), (296, self.deadline),
        ] {
            body[offset..offset + 8].copy_from_slice(&field.to_be_bytes());
        }
        Ok(body)
    }

    fn decode_body(bytes: &[u8]) -> Result<Self, DeploymentWireErrorV1> {
        if bytes.len() != 304 || bytes[..8] != *b"AOSRDCR2"
            || bytes[8..10] != 2u16.to_be_bytes() || bytes[10..16] != [0; 6]
        {
            return Err(DeploymentWireErrorV1);
        }
        let value = Self {
            purpose: array(bytes, 16)?, association: array(bytes, 48)?,
            nonce: array(bytes, 80)?, job_digest: array(bytes, 112)?,
            node: array(bytes, 144)?, deployment: array(bytes, 160)?,
            attempt: array(bytes, 176)?, ordinal: u64::from_be_bytes(array(bytes, 192)?),
            main_next: u64::from_be_bytes(array(bytes, 200)?), main_head: array(bytes, 208)?,
            fresh_nv: array(bytes, 240)?, boot: array(bytes, 272)?,
            not_before: u64::from_be_bytes(array(bytes, 288)?),
            deadline: u64::from_be_bytes(array(bytes, 296)?),
        };
        if value.encode_body()?.as_slice() != bytes {
            return Err(DeploymentWireErrorV1);
        }
        Ok(value)
    }
}

/// Preserves a signed point-observation receipt without treating it as authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanaryCurrentV2 {
    fields: CanaryCurrentFieldsV2,
    exact: [u8; CURRENT_BYTES_V2],
}

impl CanaryCurrentV2 {
    /// Combines the exact canonical receipt DATA with an obtained signature.
    ///
    /// # Errors
    /// Rejects malformed fields; it does not authenticate the signature.
    pub fn from_signed_parts(fields: CanaryCurrentFieldsV2, signature: [u8; 64])
        -> Result<Self, DeploymentWireErrorV1>
    {
        let body = fields.encode_body()?;
        let mut exact = [0; CURRENT_BYTES_V2];
        exact[..304].copy_from_slice(&body);
        exact[304..].copy_from_slice(&signature);
        Ok(Self { fields, exact })
    }

    /// Verifies canonical receipt and association crosslinks, never a live owner.
    ///
    /// # Errors
    /// Rejects unsupported grammar, signatures and a foreign association/cut.
    pub fn decode(
        bytes: &[u8], publisher: &VerifyingKey, association: &CanaryAssociationV2,
    ) -> Result<Self, DeploymentWireErrorV1> {
        require_header(bytes, CURRENT_BYTES_V2, b"AOSRDCR2", 2)?;
        let fields = CanaryCurrentFieldsV2::decode_body(&bytes[..304])?;
        verify_signed(bytes, 304, CURRENT_SIGNATURE_DOMAIN_V2, publisher)?;
        let linked = association.fields();
        if fields.purpose != linked.purpose || fields.association != association.digest()
            || fields.nonce != linked.nonce || fields.job_digest != linked.job_digest
            || fields.node != linked.node || fields.deployment != linked.deployment
            || fields.attempt != linked.attempt || fields.ordinal != linked.ordinal
            || fields.main_next != linked.main_next.checked_add(3).ok_or(DeploymentWireErrorV1)?
            || fields.boot != linked.boot || fields.not_before != linked.not_before
            || fields.deadline != linked.deadline
        {
            return Err(DeploymentWireErrorV1);
        }
        Ok(Self { fields, exact: array(bytes, 0)? })
    }

    /// Borrows the authenticated observation fields as historical comparison DATA.
    #[must_use]
    pub const fn fields(&self) -> &CanaryCurrentFieldsV2 { &self.fields }

    /// Borrows the complete fixed signed receipt.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; CURRENT_BYTES_V2] { &self.exact }
}

/// Exact signature domain for the unsigned association's single codec.
pub const ASSOCIATION_SIGNATURE_DOMAIN_V2: &[u8] = b"aos.runtime-deployment.canary-association.v2\0";
/// Exact signature domain for the separately observed current receipt.
pub const CURRENT_SIGNATURE_DOMAIN_V2: &[u8] = b"aos.runtime-deployment.canary-current.v2\0";

/// Derives the saved native association identity without an own-future hash cycle.
///
/// # Errors
/// Refuses sentinel comparison fields and an ordinal outside the fixed bound.
pub fn association_transaction_v2(
    purpose: [u8; 32], request: [u8; 32], primary_head: [u8; 32],
    old_main_head: [u8; 32], ordinal: u64,
) -> Result<[u8; 16], DeploymentWireErrorV1> {
    if [purpose, request, primary_head, old_main_head].contains(&[0; 32])
        || !(1..=MAXIMUM_ATTEMPTS_V2).contains(&ordinal)
    {
        return Err(DeploymentWireErrorV1);
    }
    let hash = Sha256::new()
        .chain_update(b"aos.runtime-deployment.canary-association-tx.v2\0")
        .chain_update(purpose).chain_update(request).chain_update(primary_head)
        .chain_update(old_main_head).chain_update(ordinal.to_be_bytes()).finalize();
    Ok(masked_transaction(&hash))
}

/// Derives the externally provisioned composite genesis identity as pure DATA.
///
/// # Errors
/// Refuses a nonexact composite width; authentication belongs to original custody.
pub fn composite_genesis_transaction_v2(bytes: &[u8]) -> Result<[u8; 16], DeploymentWireErrorV1> {
    if bytes.len() != COMPOSITE_GENESIS_BYTES_V2 {
        return Err(DeploymentWireErrorV1);
    }
    Ok(masked_transaction(&digest(b"aos.runtime-deployment.canary-genesis.v2\0", bytes)))
}

fn masked_transaction(hash: &[u8]) -> [u8; 16] {
    let mut value = [0; 16];
    value.copy_from_slice(&hash[..16]);
    value[6] = (value[6] & 0x0f) | 0x80;
    value[8] = (value[8] & 0x3f) | 0x80;
    value
}

fn require_header(
    bytes: &[u8], width: usize, magic: &[u8; 8], version: u16,
) -> Result<(), DeploymentWireErrorV1> {
    if bytes.len() != width || &bytes[..8] != magic
        || bytes[8..10] != version.to_be_bytes() || bytes[10..12] != [0; 2]
    {
        return Err(DeploymentWireErrorV1);
    }
    Ok(())
}

fn verify_signed(
    bytes: &[u8], body: usize, domain: &[u8], key: &VerifyingKey,
) -> Result<(), DeploymentWireErrorV1> {
    let mut preimage = Vec::new();
    preimage.try_reserve_exact(domain.len() + body).map_err(|_| DeploymentWireErrorV1)?;
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&bytes[..body]);
    key.verify_strict(&preimage, &Signature::from_bytes(&array(bytes, body)?))
        .map_err(|_| DeploymentWireErrorV1)
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(domain).chain_update(bytes).finalize().into()
}
