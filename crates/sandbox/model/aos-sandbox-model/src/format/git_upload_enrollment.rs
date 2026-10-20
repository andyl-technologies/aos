//! Canonical DATA for an exclusive, provisioned Git-only owner cohort.
//!
//! The administrative project signature commits the complete enrollment and
//! catalog. Decoding or verifying it does not create an owner, establish current
//! Root policy, freeze a remote service, or grant an allocation permit.
//!
//! ```text
//! AOSGUEN1 header516 | sorted owner108[count<=16] | project signature64
//! AOSGUOC1 header148 | member140[count<=16] | infrastructure300[count<=64]
//! AOSGUOB1 fixed244: original owner birth, never its own future head
//! AOSGUFN1 fixed268: original denial fence, no resulting prefix or own digest
//! AOSGUFP1 prefix228 | enrollment[length<=2308]
//! AOSGUFR1 fixed228; AOSGUFO1 fixed340
//! AOSGUPF1 header32 | checkpoint | Prepare request/outcome | Read request/outcome
//! AOSGUES1 header80 | five BE32 lengths | intent/catalog/Mount/Storage/local-cut
//! ```

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::{ProjectId, ResourceDimension, ResourceVector};
use super::policy_signer_credential::{
    PolicyVerifierRoleV1, decode_policy_verifier_credential_v1,
};

/// Maximum number of individually identified owners in the first profile.
pub const MAXIMUM_COVERAGE_OWNERS_V1: usize = 16;
/// Maximum number of independently classified immutable infrastructure rows.
pub const MAXIMUM_INFRASTRUCTURE_ROWS_V1: usize = 64;
/// Maximum complete signed administrative enrollment size.
pub const MAXIMUM_ENROLLMENT_BYTES_V1: usize = 2308;
/// Maximum complete fixed provisioned catalog size.
pub const MAXIMUM_OWNER_CATALOG_BYTES_V1: usize = 21588;
/// Exact owner-produced birth record size.
pub const COVERAGE_BIRTH_BYTES_V1: usize = 244;
/// Exact durable denial-fence preimage size, distinct from response DATA.
pub const COVERAGE_FENCE_BYTES_V1: usize = 268;
/// Exact signed-outcome application DATA size.
pub const COVERAGE_OUTCOME_BYTES_V1: usize = 340;
/// Exact request DATA prefix, before the optional signed enrollment.
pub const COVERAGE_REQUEST_PREFIX_BYTES_V1: usize = 228;
/// Maximum aggregate original broker proof supplied to the Root flight.
pub const MAXIMUM_COVERAGE_BROKER_PROOF_BYTES_V1: usize = 16_384;
/// Exact header before five original, individually length-delimited carriers.
pub const COVERAGE_BROKER_PROOF_HEADER_BYTES_V1: usize = 32;
/// Exact bounded Root submission header, before its five section lengths.
pub const COVERAGE_ROOT_SUBMISSION_HEADER_BYTES_V1: usize = 80;
/// Maximum complete original Root submission, including every nested carrier.
pub const MAXIMUM_COVERAGE_ROOT_SUBMISSION_BYTES_V1: usize = 60860;

const ROOT_SECTION_MAXIMUM_BYTES: [usize; 5] = [
    MAXIMUM_ENROLLMENT_BYTES_V1,
    MAXIMUM_OWNER_CATALOG_BYTES_V1,
    MAXIMUM_COVERAGE_BROKER_PROOF_BYTES_V1,
    MAXIMUM_COVERAGE_BROKER_PROOF_BYTES_V1,
    4096,
];

const ENROLLMENT_HEADER_BYTES: usize = 516;
const OWNER_BYTES: usize = 108;
const CATALOG_HEADER_BYTES: usize = 148;
const CATALOG_MEMBER_BYTES: usize = 140;
const INFRASTRUCTURE_BYTES: usize = 300;
const EXCLUSIVE_COHORT: u16 = 1;
const ENROLLMENT_DOMAIN: &[u8] = b"aos.sandbox.git-upload.coverage-enrollment.v1\0";
const CATALOG_DOMAIN: &[u8] = b"aos.sandbox.git-upload.owner-catalog.v1\0";
const MEMBER_DOMAIN: &[u8] = b"aos.sandbox.git-upload.catalog-member.v1\0";
const BIRTH_DOMAIN: &[u8] = b"aos.sandbox.git-upload.owner-birth.v1\0";
const FENCE_DOMAIN: &[u8] = b"aos.sandbox.git-upload.coverage-fence.v1\0";
const OUTCOME_DOMAIN: &[u8] = b"aos.sandbox.git-upload.coverage-outcome.v1\0";
const OWNER_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.git-upload.owner-fence-transaction.v1\0";

/// Reports malformed canonical DATA or its actual project-signature failure.
#[derive(Debug, thiserror::Error)]
pub enum GitCoverageDataErrorV1 {
    /// A width, closed discriminant, ordering, bound or commitment is invalid.
    #[error("exclusive Git coverage DATA is invalid")]
    Invalid,
    /// The supplied independently pinned project key rejected the signature.
    #[error("exclusive Git coverage project signature is invalid")]
    Signature(#[source] ed25519_dalek::SignatureError),
    /// An original public role carrier failed the existing verifier codec.
    #[error("exclusive Git coverage verifier credential is invalid")]
    RoleCredential(#[source] std::io::Error),
}

type Result<T> = std::result::Result<T, GitCoverageDataErrorV1>;

/// Names one existing owner family, not an authority-selection callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum GitCoverageOwnerKindV1 {
    /// Original Controller operation, authorization and pending state.
    Controller = 1,
    /// Original Root deployment, binding, source and reservation state.
    Root = 2,
    /// Original Source rows and pending acknowledgments.
    Source = 3,
    /// One fixed Cache authority partition.
    CacheAuthority = 4,
    /// The same partition's Cache state.
    CacheState = 5,
    /// Actual Cache physical and uncertain debt.
    CachePhysical = 6,
    /// Mount tables, worker custody, source pins and destination slots.
    Mount = 7,
    /// Storage catalog, resolver and physical lifecycle custody.
    StorageCatalog = 8,
    /// Original Storage native issuance history.
    StorageNative = 9,
    /// Original Publisher admission history.
    PublisherAdmission = 10,
    /// Original runtime assignment, execution and output obligations.
    RuntimeOutput = 11,
}

impl GitCoverageOwnerKindV1 {
    fn decode(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Controller),
            2 => Ok(Self::Root),
            3 => Ok(Self::Source),
            4 => Ok(Self::CacheAuthority),
            5 => Ok(Self::CacheState),
            6 => Ok(Self::CachePhysical),
            7 => Ok(Self::Mount),
            8 => Ok(Self::StorageCatalog),
            9 => Ok(Self::StorageNative),
            10 => Ok(Self::PublisherAdmission),
            11 => Ok(Self::RuntimeOutput),
            _ => Err(GitCoverageDataErrorV1::Invalid),
        }
    }

}

/// Identifies one closed original journal or physical-owner comparison profile.
///
/// Several originals belong to the same service and role. A signing service
/// is not the resident Cache writer; global journals have no partition alias.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum GitCoverageJournalProfileV1 {
    /// Controller operation and authorization journal.
    Controller = 1,
    /// Root policy authority journal.
    RootAuthority = 2,
    /// Original Source journal.
    Source = 3,
    /// Partition-owned Cache authority records.
    CacheAuthority = 4,
    /// Partition-owned Cache state records.
    CacheState = 5,
    /// Partition-attributed original physical Cache owner.
    CachePhysical = 6,
    /// Original Mount broker journal.
    Mount = 7,
    /// Original Storage catalog journal.
    StorageCatalog = 8,
    /// Original Storage native issuance journal.
    StorageNative = 9,
    /// Controller Publisher admission history.
    PublisherAdmission = 10,
    /// Controller runtime and output obligations.
    RuntimeOutput = 11,
    /// Global original Cache clock journal.
    CacheClock = 12,
    /// Global original Cache policy-hold journal.
    CachePolicyHold = 13,
    /// Root policy compiler state journal, distinct from its authority journal.
    RootPolicyState = 14,
    /// Global Controller-owned Cache bootstrap journal.
    CacheBootstrap = 15,
    /// Original Storage workspace and subordinate-identity catalog.
    StorageWorkspace = 16,
    /// Storage's independently authenticated execution-output ledger.
    StorageOutput = 17,
}

impl GitCoverageJournalProfileV1 {
    fn decode(code: u16) -> Result<Self> {
        match code {
            1 => Ok(Self::Controller),
            2 => Ok(Self::RootAuthority),
            3 => Ok(Self::Source),
            4 => Ok(Self::CacheAuthority),
            5 => Ok(Self::CacheState),
            6 => Ok(Self::CachePhysical),
            7 => Ok(Self::Mount),
            8 => Ok(Self::StorageCatalog),
            9 => Ok(Self::StorageNative),
            10 => Ok(Self::PublisherAdmission),
            11 => Ok(Self::RuntimeOutput),
            12 => Ok(Self::CacheClock),
            13 => Ok(Self::CachePolicyHold),
            14 => Ok(Self::RootPolicyState),
            15 => Ok(Self::CacheBootstrap),
            16 => Ok(Self::StorageWorkspace),
            17 => Ok(Self::StorageOutput),
            _ => Err(GitCoverageDataErrorV1::Invalid),
        }
    }

    /// Returns the fixed owner family, not an owner-selection permit.
    #[must_use]
    pub const fn owner(self) -> GitCoverageOwnerKindV1 {
        match self {
            Self::Controller => GitCoverageOwnerKindV1::Controller,
            Self::RootAuthority | Self::RootPolicyState => GitCoverageOwnerKindV1::Root,
            Self::Source => GitCoverageOwnerKindV1::Source,
            Self::CacheAuthority | Self::CacheClock | Self::CachePolicyHold
            | Self::CacheBootstrap => GitCoverageOwnerKindV1::CacheAuthority,
            Self::CacheState => GitCoverageOwnerKindV1::CacheState,
            Self::CachePhysical => GitCoverageOwnerKindV1::CachePhysical,
            Self::Mount => GitCoverageOwnerKindV1::Mount,
            Self::StorageCatalog | Self::StorageWorkspace => GitCoverageOwnerKindV1::StorageCatalog,
            Self::StorageNative => GitCoverageOwnerKindV1::StorageNative,
            Self::PublisherAdmission => GitCoverageOwnerKindV1::PublisherAdmission,
            Self::RuntimeOutput | Self::StorageOutput => GitCoverageOwnerKindV1::RuntimeOutput,
        }
    }

    /// Reports whether the original profile names a complete Cache partition.
    #[must_use]
    pub const fn is_partition_owned(self) -> bool {
        matches!(self, Self::CacheAuthority | Self::CacheState | Self::CachePhysical)
    }

    /// Compares the closed member set of one original native writer as DATA.
    ///
    /// Publisher admission and runtime/output have distinct member identities
    /// but reside in Controller's same journal. This table selects no writer,
    /// opens no path and proves neither currentness nor physical custody.
    #[doc(hidden)]
    #[must_use]
    pub fn is_native_writer_member_v1(self, member: Self) -> bool {
        self == member
            || (self == Self::Controller
                && matches!(member, Self::PublisherAdmission | Self::RuntimeOutput))
    }
}

/// Borrows one canonical full member without granting physical-owner authority.
#[derive(Clone, Copy)]
pub struct GitCoverageCatalogMemberV1<'a> {
    bytes: &'a [u8; CATALOG_MEMBER_BYTES],
    profile: GitCoverageJournalProfileV1,
}

impl<'a> GitCoverageCatalogMemberV1<'a> {
    /// Borrows the exact signed 140-byte member preimage.
    #[must_use]
    pub fn bytes(self) -> &'a [u8; CATALOG_MEMBER_BYTES] {
        self.bytes
    }

    /// Returns the closed original comparison profile.
    #[must_use]
    pub const fn profile(self) -> GitCoverageJournalProfileV1 {
        self.profile
    }

    /// Returns the full member commitment used by infrastructure attribution.
    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        digest(MEMBER_DOMAIN, self.bytes)
    }

    /// Borrows the independently provisioned original physical-origin digest.
    #[must_use]
    pub fn provision_origin(self) -> &'a [u8] {
        &self.bytes[72..104]
    }

    /// Borrows the original pre-birth native prefix or physical manifest digest.
    #[must_use]
    pub fn predecessor_prefix(self) -> &'a [u8] {
        &self.bytes[104..136]
    }

    /// Returns the exact number of attributed immutable provisioning rows.
    #[must_use]
    pub fn infrastructure_count(self) -> u32 {
        u32::from_be_bytes([
            self.bytes[136], self.bytes[137], self.bytes[138], self.bytes[139],
        ])
    }
}

/// Borrows the entire canonical signed enrollment without owning another copy.
pub struct GitCoverageEnrollmentV1<'a> {
    bytes: &'a [u8],
    unsigned: &'a [u8],
    owners: &'a [u8],
    signature: [u8; 64],
    project: ProjectId,
    node: [u8; 16],
    epoch: [u8; 16],
    generation: u64,
    issued_seconds: u64,
    expires_seconds: u64,
    deployment_key_generation: u64,
    project_key_generation: u64,
    commitments: [[u8; 32]; 7],
    cpu_period_micros: u64,
    ceilings: ResourceVector,
}

impl<'a> GitCoverageEnrollmentV1<'a> {
    /// Checks all shape bounds before lending canonical enrollment DATA.
    ///
    /// # Errors
    /// Rejects a nonexclusive profile, unknown owner/mask, empty identity,
    /// duplicate owner, invalid interval, malformed width or trailing bytes.
    pub fn decode(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < ENROLLMENT_HEADER_BYTES + 64
            || bytes.len() > MAXIMUM_ENROLLMENT_BYTES_V1
            || bytes.get(..8) != Some(b"AOSGUEN1")
            || u16_at(bytes, 8)? != 1
            || u16_at(bytes, 10)? != EXCLUSIVE_COHORT
            || bytes.get(508..512) != Some(&[1, 0, 0, 0])
            || bytes.get(514..516) != Some(&[0, 0])
        {
            return Err(GitCoverageDataErrorV1::Invalid);
        }

        let count = usize::from(u16_at(bytes, 512)?);
        if count == 0 || count > MAXIMUM_COVERAGE_OWNERS_V1 {
            return Err(GitCoverageDataErrorV1::Invalid);
        }
        let unsigned_length = ENROLLMENT_HEADER_BYTES + count * OWNER_BYTES;
        if bytes.len() != unsigned_length + 64 {
            return Err(GitCoverageDataErrorV1::Invalid);
        }
        let node = nonzero::<16>(bytes, 28)?;
        let epoch = nonzero::<16>(bytes, 44)?;
        let owners = bytes.get(ENROLLMENT_HEADER_BYTES..unsigned_length)
            .ok_or(GitCoverageDataErrorV1::Invalid)?;
        let mut previous: Option<&[u8]> = None;
        for (index, owner) in owners.chunks_exact(OWNER_BYTES).enumerate() {
            let kind = GitCoverageOwnerKindV1::decode(owner[0])?;
            if owner[1..4] != [0; 3]
                || array::<16>(owner, 4)? != node
                || array::<16>(owner, 20)? != epoch
                || previous.is_some_and(|prior| prior >= owner)
            {
                return Err(GitCoverageDataErrorV1::Invalid);
            }
            nonzero::<32>(owner, 36)?;
            let member = nonzero::<32>(owner, 68)?;
            let mask = u64_at(owner, 100)?;
            // Read, denial-only birth/fence, and genuine negative cleanup are
            // the only admitted producer classes. Source has no new birth PUT.
            let expected_mask = if kind == GitCoverageOwnerKindV1::Source { 5 } else { 7 };
            if mask != expected_mask
                || owners[..index * OWNER_BYTES].chunks_exact(OWNER_BYTES)
                    .any(|prior| prior.get(68..100) == Some(member.as_slice()))
            {
                return Err(GitCoverageDataErrorV1::Invalid);
            }
            previous = Some(owner);
        }

        let generation = positive_u64(bytes, 60)?;
        let issued_seconds = u64_at(bytes, 68)?;
        let expires_seconds = positive_u64(bytes, 76)?;
        if issued_seconds >= expires_seconds {
            return Err(GitCoverageDataErrorV1::Invalid);
        }
        let mut commitments = [[0; 32]; 7];
        for (index, commitment) in commitments.iter_mut().enumerate() {
            *commitment = nonzero::<32>(bytes, 100 + index * 32)?;
        }
        let mut ceilings = ResourceVector::ZERO;
        for (index, dimension) in ResourceDimension::ALL.into_iter().enumerate() {
            ceilings = ceilings.with(dimension, u64_at(bytes, 332 + index * 8)?);
        }

        Ok(Self {
            bytes,
            unsigned: &bytes[..unsigned_length],
            owners,
            signature: array(bytes, unsigned_length)?,
            project: ProjectId::from_bytes(nonzero(bytes, 12)?),
            node,
            epoch,
            generation,
            issued_seconds,
            expires_seconds,
            deployment_key_generation: positive_u64(bytes, 84)?,
            project_key_generation: positive_u64(bytes, 92)?,
            commitments,
            cpu_period_micros: positive_u64(bytes, 324)?,
            ceilings,
        })
    }

    /// Verifies the exact domain and complete original project-signed preimage.
    ///
    /// This is signature DATA only; the caller still needs independently current
    /// role pins, Root policy, immutable inputs and real owner-cohort fences.
    ///
    /// # Errors
    /// Returns the actual signature failure without replacing it with a string.
    pub fn verify_project_signature(&self, key: &VerifyingKey) -> Result<()> {
        let mut preimage = Vec::with_capacity(ENROLLMENT_DOMAIN.len() + self.unsigned.len());
        preimage.extend_from_slice(ENROLLMENT_DOMAIN);
        preimage.extend_from_slice(self.unsigned);
        key.verify_strict(&preimage, &Signature::from_bytes(&self.signature))
            .map_err(GitCoverageDataErrorV1::Signature)
    }

    /// Compares both complete public role carriers and verifies the project signature.
    ///
    /// This uses the existing canonical credential codec. The caller still
    /// supplies genuine fixed-file custody and independently current Root
    /// deployment evidence; these bytes do not provision keys or establish
    /// either fact.
    ///
    /// # Errors
    /// Rejects malformed role carriers, mismatched generations or the actual
    /// project-signature failure in that order.
    pub fn verify_role_credentials(
        &self,
        project_pin: &[u8],
        deployment_pin: &[u8],
    ) -> Result<()> {
        let (project_generation, project_key) = decode_policy_verifier_credential_v1(
            PolicyVerifierRoleV1::Project, project_pin,
        ).map_err(GitCoverageDataErrorV1::RoleCredential)?;
        let (deployment_generation, _) = decode_policy_verifier_credential_v1(
            PolicyVerifierRoleV1::Deployment, deployment_pin,
        ).map_err(GitCoverageDataErrorV1::RoleCredential)?;
        if self.role_generations() != (deployment_generation, project_generation) {
            return Err(GitCoverageDataErrorV1::Invalid);
        }
        self.verify_project_signature(&project_key)
    }

    /// Borrows the unchanged complete original signed bytes.
    #[must_use]
    pub fn bytes(&self) -> &'a [u8] { self.bytes }

    /// Returns the administratively named project, not an inferred attribution.
    #[must_use]
    pub fn project(&self) -> ProjectId { self.project }

    /// Returns the exact node and provisioned deployment epoch.
    #[must_use]
    pub fn node_epoch(&self) -> ([u8; 16], [u8; 16]) { (self.node, self.epoch) }

    /// Returns the immutable enrollment generation and Unix validity interval.
    #[must_use]
    pub fn generation_interval(&self) -> (u64, u64, u64) {
        (self.generation, self.issued_seconds, self.expires_seconds)
    }

    /// Returns the generations of both independently provisioned signer roles.
    #[must_use]
    pub fn role_generations(&self) -> (u64, u64) {
        (self.deployment_key_generation, self.project_key_generation)
    }

    /// Borrows all seven original deployment/source/policy/capacity/cut bindings.
    #[must_use]
    pub fn commitments(&self) -> &[[u8; 32]; 7] { &self.commitments }

    /// Returns finite ceiling DATA and its exact, nonconvertible CPU period.
    #[must_use]
    pub fn ceiling_period(&self) -> (ResourceVector, u64) {
        (self.ceilings, self.cpu_period_micros)
    }

    /// Borrows the validated, sorted fixed-width original owner declarations.
    #[must_use]
    pub fn owner_bytes(&self) -> &'a [u8] { self.owners }

    /// Returns the domain-separated digest of the complete signed enrollment.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] { digest(ENROLLMENT_DOMAIN, self.bytes) }

    /// Derives comparison DATA for one closed original owner birth recipe.
    ///
    /// The complete signed catalog commits every original historical PUT.
    /// Its last PUT therefore predicts NEXT only when the genuine owner also
    /// proves the complete original, uncompacted, delete-free native history.
    /// The owner must independently compare its actual NEXT and prefix before
    /// append, and its actual COMMIT after readback. This is not a future
    /// outcome, custody constructor, currentness certificate or append permit.
    ///
    /// # Errors
    /// Rejects a foreign catalog, unsupported owner, absent full member, zero
    /// nonce or exhausted sequence. No arbitrary partition/profile is accepted.
    pub fn fixed_owner_birth_recipe_v1(
        &self,
        catalog: &GitCoverageCatalogV1<'_>,
        profile: GitCoverageJournalProfileV1,
        prepare_nonce: [u8; 16],
    ) -> Result<GitCoverageBirthFieldsV1> {
        if prepare_nonce == [0; 16]
            || !matches!(profile,
                GitCoverageJournalProfileV1::Controller
                    | GitCoverageJournalProfileV1::RootAuthority
                    | GitCoverageJournalProfileV1::RootPolicyState
                    | GitCoverageJournalProfileV1::CachePolicyHold
                    | GitCoverageJournalProfileV1::Mount
                    | GitCoverageJournalProfileV1::StorageCatalog)
        {
            return Err(GitCoverageDataErrorV1::Invalid);
        }
        catalog.compare_enrollment(self)?;
        let member = catalog.fixed_member(profile, [0; 32])?;
        for related in catalog.members().filter(|related| {
            profile.is_native_writer_member_v1(related.profile())
        }) {
            if related.predecessor_prefix() != member.predecessor_prefix()
                || related.provision_origin() != member.provision_origin()
            {
                return Err(GitCoverageDataErrorV1::Invalid);
            }
        }
        let next_sequence = match catalog.infrastructure()
            .filter(|row| catalog.members().any(|related| {
                profile.is_native_writer_member_v1(related.profile())
                    && row.attribution() == related.digest()
            }))
            .map(|row| row.put_sequence()).max()
        {
            Some(sequence) => sequence.checked_add(2)
                .ok_or(GitCoverageDataErrorV1::Invalid)?,
            None => 1,
        };
        let commit_sequence = next_sequence.checked_add(3)
            .ok_or(GitCoverageDataErrorV1::Invalid)?;
        let mut transaction_digest = Sha256::new().chain_update(OWNER_TRANSACTION_DOMAIN);
        transaction_digest.update((profile as u16).to_be_bytes());
        transaction_digest.update(self.digest());
        transaction_digest.update(catalog.digest());
        transaction_digest.update(member.digest());
        transaction_digest.update(prepare_nonce);
        let whole_digest: [u8; 32] = transaction_digest.finalize().into();
        let mut transaction = [0; 16];
        transaction.copy_from_slice(&whole_digest[..16]);
        transaction[6] = (transaction[6] & 0x0f) | 0x80;
        transaction[8] = (transaction[8] & 0x3f) | 0x80;

        Ok(GitCoverageBirthFieldsV1 {
            owner: profile.owner(),
            node: self.node,
            epoch: self.epoch,
            project: self.project,
            enrollment: self.digest(),
            catalog: catalog.digest(),
            predecessor_prefix: array(member.bytes(), 104)?,
            transaction,
            commit_sequence,
            provision_origin: array(member.bytes(), 72)?,
        })
    }
}

/// Borrows one canonical provisioned catalog, not a census or coverage proof.
pub struct GitCoverageCatalogV1<'a> {
    bytes: &'a [u8],
    members: &'a [u8],
    infrastructure: &'a [u8],
    node: [u8; 16],
    epoch: [u8; 16],
    deployment: [u8; 32],
    root_profile: [u8; 32],
}

/// Borrows one attributed immutable infrastructure declaration, not live evidence.
#[derive(Clone, Copy)]
pub struct GitCoverageInfrastructureV1<'a> {
    bytes: &'a [u8],
}

impl<'a> GitCoverageInfrastructureV1<'a> {
    /// Returns the closed family code for independent original-owner checks.
    #[must_use]
    pub fn family(self) -> u8 {
        self.bytes[1]
    }

    /// Borrows the complete native key, never its padded suffix or an alias.
    #[must_use]
    pub fn key(self) -> &'a [u8] {
        let length = usize::from(u16::from_be_bytes([self.bytes[4], self.bytes[5]]));
        &self.bytes[8..8 + length]
    }

    /// Borrows the original full native transaction UUID.
    #[must_use]
    pub fn transaction(self) -> &'a [u8] {
        &self.bytes[168..184]
    }

    /// Returns the original native PUT sequence, not a predicted COMMIT.
    #[must_use]
    pub fn put_sequence(self) -> u64 {
        u64::from_be_bytes([
            self.bytes[184], self.bytes[185], self.bytes[186], self.bytes[187],
            self.bytes[188], self.bytes[189], self.bytes[190], self.bytes[191],
        ])
    }

    /// Borrows the existing SHA-256 content digest of the full original value.
    #[must_use]
    pub fn value_digest(self) -> &'a [u8] {
        &self.bytes[192..224]
    }

    /// Borrows the commitment to the exact canonical full member.
    #[must_use]
    pub fn attribution(self) -> &'a [u8] {
        &self.bytes[256..288]
    }
}

impl<'a> GitCoverageCatalogV1<'a> {
    /// Checks exact catalog shape, counts, closed members and canonical ordering.
    ///
    /// # Errors
    /// Rejects unknown roles/unit profiles, foreign nodes, inferred infrastructure,
    /// duplicate entries, unbounded rows or changed canonical checksum.
    pub fn decode(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < CATALOG_HEADER_BYTES
            || bytes.len() > MAXIMUM_OWNER_CATALOG_BYTES_V1
            || bytes.get(..8) != Some(b"AOSGUOC1")
            || u16_at(bytes, 8)? != 1
            || u16_at(bytes, 10)? != 0
            || bytes.get(112..116) != Some(&[0; 4])
        {
            return Err(GitCoverageDataErrorV1::Invalid);
        }
        let member_count = usize::from(u16_at(bytes, 108)?);
        let infrastructure_count = usize::from(u16_at(bytes, 110)?);
        if member_count == 0 || member_count > MAXIMUM_COVERAGE_OWNERS_V1
            || infrastructure_count > MAXIMUM_INFRASTRUCTURE_ROWS_V1
            || bytes.len() != CATALOG_HEADER_BYTES
                + member_count * CATALOG_MEMBER_BYTES
                + infrastructure_count * INFRASTRUCTURE_BYTES
        {
            return Err(GitCoverageDataErrorV1::Invalid);
        }
        // The checksum occupies the fixed header, not the variable suffix.
        let mut checksum = Sha256::new();
        checksum.update(CATALOG_DOMAIN);
        checksum.update(&bytes[..116]);
        checksum.update(&bytes[CATALOG_HEADER_BYTES..]);
        if checksum.finalize().as_slice() != bytes.get(116..148)
            .ok_or(GitCoverageDataErrorV1::Invalid)?
        {
            return Err(GitCoverageDataErrorV1::Invalid);
        }

        let node = nonzero::<16>(bytes, 12)?;
        let epoch = nonzero::<16>(bytes, 28)?;
        let members_end = CATALOG_HEADER_BYTES + member_count * CATALOG_MEMBER_BYTES;
        let members = &bytes[CATALOG_HEADER_BYTES..members_end];
        let infrastructure = &bytes[members_end..];
        let mut declared_rows = 0usize;
        let mut previous: Option<&[u8]> = None;
        for (index, member) in members.chunks_exact(CATALOG_MEMBER_BYTES).enumerate() {
            let kind = GitCoverageOwnerKindV1::decode(member[0])?;
            let profile = GitCoverageJournalProfileV1::decode(u16_at(member, 6)?)?;
            let count = usize::try_from(u32_at(member, 136)?)
                .map_err(|_| GitCoverageDataErrorV1::Invalid)?;
            if !matches!(member[1], 1 | 2)
                || member[2..4] != [0; 2]
                || u16_at(member, 4)? != profile_unit_code(profile)
                || kind != profile.owner()
                || array::<16>(member, 8)? != node
                || array::<16>(member, 24)? != epoch
                || previous.is_some_and(|prior| prior >= member)
                || (member[1] == 1 && count != 0)
                || (member[1] == 2 && count == 0)
                || (!profile.is_partition_owned() && array::<32>(member, 40)? != [0; 32])
                || (profile.is_partition_owned() && array::<32>(member, 40)? == [0; 32])
                || members[..index * CATALOG_MEMBER_BYTES]
                    .chunks_exact(CATALOG_MEMBER_BYTES)
                    .any(|prior| prior[6..8] == member[6..8]
                        && prior[40..72] == member[40..72])
            {
                return Err(GitCoverageDataErrorV1::Invalid);
            }
            // A Cache member commits the whole PhysicalPartitionId digest;
            // no shortened catalog alias can name that original partition.
            nonzero::<32>(member, 72)?;
            nonzero::<32>(member, 104)?;
            declared_rows = declared_rows.checked_add(count)
                .ok_or(GitCoverageDataErrorV1::Invalid)?;
            previous = Some(member);
        }
        if declared_rows != infrastructure_count {
            return Err(GitCoverageDataErrorV1::Invalid);
        }

        previous = None;
        for (index, row) in infrastructure.chunks_exact(INFRASTRUCTURE_BYTES).enumerate() {
            GitCoverageOwnerKindV1::decode(row[0])?;
            let key_length = usize::from(u16_at(row, 4)?);
            if row[1] == 0 || row[1] > 11 || row[2..4] != [0; 2]
                || row[6..8] != [0; 2]
                || key_length == 0 || key_length > 160
                || row[8 + key_length..168].iter().any(|byte| *byte != 0)
                || row[288..300] != [0; 12]
                || previous.is_some_and(|prior| prior >= row)
            {
                return Err(GitCoverageDataErrorV1::Invalid);
            }
            nonzero::<16>(row, 168)?;
            positive_u64(row, 184)?;
            nonzero::<32>(row, 192)?;
            nonzero::<32>(row, 224)?;
            let attribution = nonzero::<32>(row, 256)?;
            let mut attributed = members.chunks_exact(CATALOG_MEMBER_BYTES)
                .filter(|member| digest(MEMBER_DOMAIN, member) == attribution);
            let member = attributed.next().ok_or(GitCoverageDataErrorV1::Invalid)?;
            if attributed.next().is_some()
                || row[0] != member[0]
                || row[224..256] != member[72..104]
                || infrastructure[..index * INFRASTRUCTURE_BYTES]
                    .chunks_exact(INFRASTRUCTURE_BYTES)
                    .any(|prior| {
                        prior[256..288] == row[256..288]
                            && prior[168..184] == row[168..184]
                            && prior[184..192] == row[184..192]
                    })
            {
                return Err(GitCoverageDataErrorV1::Invalid);
            }
            previous = Some(row);
        }

        // A native PUT sequence names one historical version, not merely its
        // current map key. Clock floors can reuse their fixed key without
        // erasing any earlier original UUID, sequence or complete value.
        // Each immutable row resolves one signed full member. In particular,
        // two Cache partitions may share a Journal origin without silently
        // assigning either partition the other's provisioning rows.
        for member in members.chunks_exact(CATALOG_MEMBER_BYTES) {
            let attribution = digest(MEMBER_DOMAIN, member);
            let observed = infrastructure.chunks_exact(INFRASTRUCTURE_BYTES)
                .filter(|row| row[256..288] == attribution)
                .count();
            if observed != usize::try_from(u32_at(member, 136)?)
                .map_err(|_| GitCoverageDataErrorV1::Invalid)?
            {
                return Err(GitCoverageDataErrorV1::Invalid);
            }
        }

        Ok(Self {
            bytes,
            members,
            infrastructure,
            node,
            epoch,
            deployment: nonzero(bytes, 44)?,
            root_profile: nonzero(bytes, 76)?,
        })
    }

    /// Borrows the original complete catalog for immutable owner comparisons.
    #[must_use]
    pub fn bytes(&self) -> &'a [u8] { self.bytes }

    /// Returns the exact node, epoch, deployment and original Root profile.
    #[must_use]
    pub fn coordinates(&self) -> ([u8; 16], [u8; 16], [u8; 32], [u8; 32]) {
        (self.node, self.epoch, self.deployment, self.root_profile)
    }

    /// Borrows canonical member entries without constructing owner authority.
    #[must_use]
    pub fn member_bytes(&self) -> &'a [u8] { self.members }

    /// Borrows canonical original infrastructure declarations, not live rows.
    #[must_use]
    pub fn infrastructure_bytes(&self) -> &'a [u8] { self.infrastructure }

    /// Lends all original declarations to the actual owner's native observer.
    ///
    /// Entries have already resolved exactly one full canonical member. The
    /// observer must still compare actual namespace/family, UUID, PUT sequence,
    /// complete key/value and original physical custody; this iterator proves
    /// none of those facts by itself.
    pub fn infrastructure(&self) -> impl Iterator<Item = GitCoverageInfrastructureV1<'a>> + '_ {
        self.infrastructure.chunks_exact(INFRASTRUCTURE_BYTES)
            .map(|bytes| GitCoverageInfrastructureV1 { bytes })
    }

    /// Lends each original full member without another decoder or owned map.
    pub fn members(&self) -> impl Iterator<Item = GitCoverageCatalogMemberV1<'a>> + '_ {
        self.members.chunks_exact(CATALOG_MEMBER_BYTES).filter_map(|bytes| {
            // The sole decoder has checked the width and every profile code.
            // Keep the conversion fallible rather than adding a panic path.
            let bytes: &'a [u8; CATALOG_MEMBER_BYTES] = bytes.try_into().ok()?;
            let profile = GitCoverageJournalProfileV1::decode(
                u16::from_be_bytes([bytes[6], bytes[7]]),
            ).ok()?;
            Some(GitCoverageCatalogMemberV1 { bytes, profile })
        })
    }

    /// Borrows one complete fixed member selected by original profile and partition.
    ///
    /// This is provisioned DATA only. The genuine owner independently compares
    /// its original node, native prefix, physical identity and residual state.
    /// Global profiles use the canonical zero partition, not a truncated alias.
    ///
    /// # Errors
    /// Rejects a missing or ambiguous exact member or an invalid fixed width.
    pub fn fixed_member(
        &self,
        profile: GitCoverageJournalProfileV1,
        partition: [u8; 32],
    ) -> Result<GitCoverageCatalogMemberV1<'a>> {
        let mut selected = None;
        for member in self.members.chunks_exact(CATALOG_MEMBER_BYTES) {
            if member[6..8] != (profile as u16).to_be_bytes()
                || member[40..72] != partition
            {
                continue;
            }
            if selected.is_some() {
                return Err(GitCoverageDataErrorV1::Invalid);
            }
            selected = Some(GitCoverageCatalogMemberV1 {
                bytes: member.try_into().map_err(|_| GitCoverageDataErrorV1::Invalid)?,
                profile,
            });
        }
        selected.ok_or(GitCoverageDataErrorV1::Invalid)
    }

    /// Returns the domain-separated complete catalog digest.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] { digest(CATALOG_DOMAIN, self.bytes) }

    /// Checks each enrollment member against this exact original catalog.
    ///
    /// # Errors
    /// Rejects foreign deployment/catalog bindings, a missing or duplicated
    /// member, or mismatched node/epoch/provision origin. Actual owner state is
    /// independently checked by the live producer, never inferred here.
    pub fn compare_enrollment(&self, enrollment: &GitCoverageEnrollmentV1<'_>) -> Result<()> {
        if enrollment.node_epoch() != (self.node, self.epoch)
            || enrollment.commitments()[0] != self.deployment
            || enrollment.commitments()[6] != self.digest()
            || enrollment.owner_bytes().len() / OWNER_BYTES
                != self.members.len() / CATALOG_MEMBER_BYTES
        {
            return Err(GitCoverageDataErrorV1::Invalid);
        }
        for owner in enrollment.owner_bytes().chunks_exact(OWNER_BYTES) {
            let matching = self.members.chunks_exact(CATALOG_MEMBER_BYTES).find(|member| {
                member[0] == owner[0]
                    && member[8..40] == owner[4..36]
                    && member[72..104] == owner[36..68]
                    && digest(MEMBER_DOMAIN, member).as_slice() == &owner[68..100]
            });
            if matching.is_none() {
                return Err(GitCoverageDataErrorV1::Invalid);
            }
        }
        Ok(())
    }
}

/// Contains comparison coordinates for one owner-produced birth preimage.
///
/// These fields carry no authority. Only the actual original writer can audit
/// its native prefix and physical custody before appending the encoded bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitCoverageBirthFieldsV1 {
    /// Existing closed owner family.
    pub owner: GitCoverageOwnerKindV1,
    /// Actual node of the original owner.
    pub node: [u8; 16],
    /// Independently provisioned deployment epoch.
    pub epoch: [u8; 16],
    /// Explicit project in the original signed enrollment.
    pub project: ProjectId,
    /// Complete original signed enrollment commitment.
    pub enrollment: [u8; 32],
    /// Complete independently provisioned catalog commitment.
    pub catalog: [u8; 32],
    /// Audited native prefix before this birth, not the resulting head.
    pub predecessor_prefix: [u8; 32],
    /// UUID fixed before the original append.
    pub transaction: [u8; 16],
    /// Original transaction's native COMMIT sequence.
    pub commit_sequence: u64,
    /// Original fixed catalog member's provisioned identity.
    pub provision_origin: [u8; 32],
}

impl GitCoverageBirthFieldsV1 {
    /// Encodes one canonical birth DATA preimage without creating a writer.
    ///
    /// # Errors
    /// Rejects unknown or Source owner roles, zero coordinates or sequence.
    pub fn encode(self) -> Result<[u8; COVERAGE_BIRTH_BYTES_V1]> {
        let mut bytes = [0; COVERAGE_BIRTH_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSGUOB1");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = self.owner as u8;
        bytes[12..28].copy_from_slice(&self.node);
        bytes[28..44].copy_from_slice(&self.epoch);
        bytes[44..60].copy_from_slice(self.project.as_bytes());
        bytes[60..92].copy_from_slice(&self.enrollment);
        bytes[92..124].copy_from_slice(&self.catalog);
        bytes[124..156].copy_from_slice(&self.predecessor_prefix);
        bytes[156..172].copy_from_slice(&self.transaction);
        bytes[172..180].copy_from_slice(&self.commit_sequence.to_be_bytes());
        bytes[180..212].copy_from_slice(&self.provision_origin);
        let checksum = digest(BIRTH_DOMAIN, &bytes[..212]);
        bytes[212..].copy_from_slice(&checksum);

        GitCoverageBirthV1::decode(&bytes)?;
        Ok(bytes)
    }

    /// Returns fence comparison DATA with the same birth coordinates.
    ///
    /// The caller supplies the existing generation, already computed canonical
    /// birth digest and original Prepare nonce. This only copies fields; it
    /// neither validates coordinates nor creates writer or allocation authority.
    /// The returned fields retain the existing fence encoder's validation.
    #[must_use]
    pub fn to_fence_fields(
        &self,
        generation: u64,
        birth_digest: [u8; 32],
        prepare_nonce: [u8; 16],
    ) -> GitCoverageFenceFieldsV1 {
        GitCoverageFenceFieldsV1 {
            owner: self.owner,
            project: self.project,
            node: self.node,
            epoch: self.epoch,
            generation,
            enrollment: self.enrollment,
            birth: birth_digest,
            catalog: self.catalog,
            transaction: self.transaction,
            predecessor_prefix: self.predecessor_prefix,
            prepare_nonce,
        }
    }
}

/// Borrows an exact canonical birth and its nonauthorizing coordinates.
pub struct GitCoverageBirthV1<'a> {
    bytes: &'a [u8],
    fields: GitCoverageBirthFieldsV1,
}

impl<'a> GitCoverageBirthV1<'a> {
    /// Checks the complete fixed birth preimage and its checksum.
    ///
    /// # Errors
    /// Rejects malformed widths, reserved bytes, unsupported owner roles,
    /// zero identities or a changed checksum. No native origin is inferred.
    pub fn decode(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() != COVERAGE_BIRTH_BYTES_V1
            || bytes.get(..8) != Some(b"AOSGUOB1")
            || u16_at(bytes, 8)? != 1
            || bytes[11] != 0
            || digest(BIRTH_DOMAIN, &bytes[..212]) != array::<32>(bytes, 212)?
        {
            return Err(GitCoverageDataErrorV1::Invalid);
        }
        let owner = GitCoverageOwnerKindV1::decode(bytes[10])?;
        if owner == GitCoverageOwnerKindV1::Source {
            // Source's original global-empty engine cannot accept a birth PUT.
            return Err(GitCoverageDataErrorV1::Invalid);
        }

        Ok(Self {
            bytes,
            fields: GitCoverageBirthFieldsV1 {
                owner,
                node: nonzero(bytes, 12)?,
                epoch: nonzero(bytes, 28)?,
                project: ProjectId::from_bytes(nonzero(bytes, 44)?),
                enrollment: nonzero(bytes, 60)?,
                catalog: nonzero(bytes, 92)?,
                predecessor_prefix: nonzero(bytes, 124)?,
                transaction: nonzero(bytes, 156)?,
                commit_sequence: positive_u64(bytes, 172)?,
                provision_origin: nonzero(bytes, 180)?,
            },
        })
    }

    /// Borrows the unchanged complete native value preimage.
    #[must_use]
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns bounded comparison DATA, never an origin or allocation grant.
    #[must_use]
    pub fn fields(&self) -> GitCoverageBirthFieldsV1 {
        self.fields
    }

    /// Returns the digest of the complete canonical birth value.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        digest(BIRTH_DOMAIN, self.bytes)
    }
}

/// Contains only preappend coordinates for one permanent denial-fence value.
///
/// The value cannot embed its own digest or resulting native prefix. A signed
/// response separately commits this whole preimage after actual readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitCoverageFenceFieldsV1 {
    /// Existing original owner family.
    pub owner: GitCoverageOwnerKindV1,
    /// Explicit signed enrolled project.
    pub project: ProjectId,
    /// Actual original owner's node.
    pub node: [u8; 16],
    /// Independently provisioned deployment epoch.
    pub epoch: [u8; 16],
    /// Immutable original enrollment generation.
    pub generation: u64,
    /// Complete original signed enrollment commitment.
    pub enrollment: [u8; 32],
    /// Complete original canonical birth commitment.
    pub birth: [u8; 32],
    /// Complete independently provisioned catalog commitment.
    pub catalog: [u8; 32],
    /// Actual original UUID fixed before this transaction.
    pub transaction: [u8; 16],
    /// Audited native prefix preceding this transaction.
    pub predecessor_prefix: [u8; 32],
    /// Original Prepare nonce, not a later Read nonce.
    pub prepare_nonce: [u8; 16],
}

impl GitCoverageFenceFieldsV1 {
    /// Encodes the canonical nonrecursive denial-fence preimage.
    ///
    /// # Errors
    /// Rejects Source, zero identity/generation or noncanonical coordinates.
    pub fn encode(self) -> Result<[u8; COVERAGE_FENCE_BYTES_V1]> {
        let mut bytes = [0; COVERAGE_FENCE_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSGUFN1");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = self.owner as u8;
        bytes[12..28].copy_from_slice(self.project.as_bytes());
        bytes[28..44].copy_from_slice(&self.node);
        bytes[44..60].copy_from_slice(&self.epoch);
        bytes[60..68].copy_from_slice(&self.generation.to_be_bytes());
        bytes[68..100].copy_from_slice(&self.enrollment);
        bytes[100..132].copy_from_slice(&self.birth);
        bytes[132..164].copy_from_slice(&self.catalog);
        bytes[164..180].copy_from_slice(&self.transaction);
        bytes[180..212].copy_from_slice(&self.predecessor_prefix);
        bytes[212..220].copy_from_slice(&7_u64.to_be_bytes());
        bytes[220..236].copy_from_slice(&self.prepare_nonce);
        let checksum = digest(FENCE_DOMAIN, &bytes[..236]);
        bytes[236..].copy_from_slice(&checksum);

        GitCoverageFenceV1::decode(&bytes)?;
        Ok(bytes)
    }
}

/// Borrows one permanent denial fence, not a response or mutation permit.
pub struct GitCoverageFenceV1<'a> {
    bytes: &'a [u8],
    fields: GitCoverageFenceFieldsV1,
}

impl<'a> GitCoverageFenceV1<'a> {
    /// Checks exact durable-fence shape independently from response shape.
    ///
    /// # Errors
    /// Rejects unsupported roles, changed checksums, nonclosed masks, reserved
    /// bytes, zero coordinates or trailing data. Native origin is separate.
    pub fn decode(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() != COVERAGE_FENCE_BYTES_V1
            || bytes.get(..8) != Some(b"AOSGUFN1")
            || u16_at(bytes, 8)? != 1
            || bytes[11] != 0
            || u64_at(bytes, 212)? != 7
            || digest(FENCE_DOMAIN, &bytes[..236]) != array::<32>(bytes, 236)?
        {
            return Err(GitCoverageDataErrorV1::Invalid);
        }
        let owner = GitCoverageOwnerKindV1::decode(bytes[10])?;
        if owner == GitCoverageOwnerKindV1::Source {
            return Err(GitCoverageDataErrorV1::Invalid);
        }

        Ok(Self {
            bytes,
            fields: GitCoverageFenceFieldsV1 {
                owner,
                project: ProjectId::from_bytes(nonzero(bytes, 12)?),
                node: nonzero(bytes, 28)?,
                epoch: nonzero(bytes, 44)?,
                generation: positive_u64(bytes, 60)?,
                enrollment: nonzero(bytes, 68)?,
                birth: nonzero(bytes, 100)?,
                catalog: nonzero(bytes, 132)?,
                transaction: nonzero(bytes, 164)?,
                predecessor_prefix: nonzero(bytes, 180)?,
                prepare_nonce: nonzero(bytes, 220)?,
            },
        })
    }

    /// Borrows the complete unchanged durable denial value.
    #[must_use]
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns original comparison coordinates without releasing the fence.
    #[must_use]
    pub fn fields(&self) -> GitCoverageFenceFieldsV1 {
        self.fields
    }

    /// Returns the complete nonrecursive durable value commitment.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        digest(FENCE_DOMAIN, self.bytes)
    }

    /// Compares this fence with its independently retained original birth.
    ///
    /// # Errors
    /// Rejects role, project, node, epoch, enrollment, catalog or birth changes.
    pub fn compare_birth(&self, birth: &GitCoverageBirthV1<'_>) -> Result<()> {
        let original = birth.fields();
        if self.fields.owner != original.owner
            || self.fields.project != original.project
            || self.fields.node != original.node
            || self.fields.epoch != original.epoch
            || self.fields.enrollment != original.enrollment
            || self.fields.catalog != original.catalog
            || self.fields.birth != birth.digest()
        {
            return Err(GitCoverageDataErrorV1::Invalid);
        }
        Ok(())
    }
}

/// Names the two existing broker owners in the opt-in authenticated flights.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum GitCoverageBrokerRoleV1 {
    /// Existing Mount 2.0 owner.
    Mount = 1,
    /// Existing Storage 1.0 owner.
    Storage = 2,
}

impl GitCoverageBrokerRoleV1 {
    fn decode(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Mount),
            2 => Ok(Self::Storage),
            _ => Err(GitCoverageDataErrorV1::Invalid),
        }
    }
}

/// Borrows canonical proof framing without verifying its historical contents.
///
/// Parts are, in order, the original checkpoint, Prepare request and outcome,
/// and Read request and outcome. Existing checkpoint and authenticated packet
/// decoders remain the only signature/context engines. Framing alone creates
/// no Session, currentness, enrollment or allocation authority.
#[doc(hidden)]
pub struct GitCoverageBrokerProofV1<'a> {
    role: GitCoverageBrokerRoleV1,
    parts: [&'a [u8]; 5],
}

impl<'a> GitCoverageBrokerProofV1<'a> {
    /// Encodes five complete original carriers after aggregate bound checks.
    ///
    /// No signed packet is reencoded or projected by this DATA assembler.
    ///
    /// # Errors
    /// Rejects an empty part, checked-length overflow or aggregate above 16 KiB.
    pub fn encode(role: GitCoverageBrokerRoleV1, parts: [&[u8]; 5]) -> Result<Vec<u8>> {
        let mut lengths = [0_u32; 5];
        let mut total = COVERAGE_BROKER_PROOF_HEADER_BYTES_V1;
        for (index, part) in parts.iter().enumerate() {
            if part.is_empty() {
                return Err(GitCoverageDataErrorV1::Invalid);
            }
            lengths[index] = u32::try_from(part.len())
                .map_err(|_| GitCoverageDataErrorV1::Invalid)?;
            total = total.checked_add(part.len())
                .ok_or(GitCoverageDataErrorV1::Invalid)?;
        }
        if total > MAXIMUM_COVERAGE_BROKER_PROOF_BYTES_V1 {
            return Err(GitCoverageDataErrorV1::Invalid);
        }

        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(b"AOSGUPF1");
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.push(role as u8);
        bytes.push(0);
        for length in lengths {
            bytes.extend_from_slice(&length.to_be_bytes());
        }
        for part in parts {
            bytes.extend_from_slice(part);
        }
        Ok(bytes)
    }

    /// Borrows the exact closed proof, with no trailing or empty carriers.
    ///
    /// # Errors
    /// Rejects wrong magic, version, role or flags, aggregate/nested overflow,
    /// zero-length carriers, truncation or any trailing bytes.
    pub fn decode(bytes: &'a [u8]) -> Result<Self> {
        if !(COVERAGE_BROKER_PROOF_HEADER_BYTES_V1..=MAXIMUM_COVERAGE_BROKER_PROOF_BYTES_V1)
            .contains(&bytes.len())
            || bytes.get(..8) != Some(b"AOSGUPF1".as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes.get(11) != Some(&0)
        {
            return Err(GitCoverageDataErrorV1::Invalid);
        }
        let role = GitCoverageBrokerRoleV1::decode(bytes[10])?;
        let mut cursor = COVERAGE_BROKER_PROOF_HEADER_BYTES_V1;
        let mut parts: [&[u8]; 5] = [&[]; 5];
        for (index, part) in parts.iter_mut().enumerate() {
            let length = usize::try_from(u32_at(bytes, 12 + index * 4)?)
                .map_err(|_| GitCoverageDataErrorV1::Invalid)?;
            if length == 0 {
                return Err(GitCoverageDataErrorV1::Invalid);
            }
            let end = cursor.checked_add(length).ok_or(GitCoverageDataErrorV1::Invalid)?;
            *part = bytes.get(cursor..end).ok_or(GitCoverageDataErrorV1::Invalid)?;
            cursor = end;
        }
        if cursor != bytes.len() {
            return Err(GitCoverageDataErrorV1::Invalid);
        }
        Ok(Self { role, parts })
    }

    /// Returns the closed claimed broker role as nonauthorizing DATA.
    #[must_use]
    pub const fn role(&self) -> GitCoverageBrokerRoleV1 {
        self.role
    }

    /// Borrows all original carriers in their fixed canonical order.
    #[must_use]
    pub const fn parts(&self) -> [&'a [u8]; 5] {
        self.parts
    }
}

/// Contains the original Root-flight comparison coordinates, never authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct GitCoverageRootCoordinatesV1 {
    /// Genuine Root challenge nonce for this one nonrenewing flight.
    pub root_nonce: [u8; 16],
    /// Original absolute BOOTTIME cutoff supplied before taking owner locks.
    pub cutoff: u64,
    /// Actual Controller kernel incarnation, independently compared at Root.
    pub controller_boot: [u8; 16],
    /// Actual original enrolled node, not a caller-selected owner route.
    pub node: [u8; 16],
}

/// Lends one bounded original submission without decoding another protocol.
///
/// The parts are the complete signed intent, provisioned catalog, Mount and
/// Storage original proofs, and local-cut metadata. Their own canonical
/// decoders and genuine current owners remain mandatory independent joins.
#[doc(hidden)]
pub struct GitCoverageRootSubmissionV1<'a> {
    coordinates: GitCoverageRootCoordinatesV1,
    parts: [&'a [u8]; 5],
}

impl<'a> GitCoverageRootSubmissionV1<'a> {
    /// Checks the complete fixed header before collecting its advertised body.
    ///
    /// # Errors
    /// Rejects wrong magic/version/flags/count, zero coordinates, reserved
    /// bytes or a body beyond the existing enclosing bound. Individual section
    /// bounds are still checked by the complete decoder before lending bytes.
    pub fn bounded_body_length(header: &[u8]) -> Result<usize> {
        let (_, length) = root_submission_header(header)?;
        Ok(length)
    }

    /// Encodes the exact five original sections after all allocation bounds.
    ///
    /// No nested signature, packet, checkpoint or catalog is reencoded here.
    ///
    /// # Errors
    /// Rejects zero coordinates, empty/oversized sections or checked-length
    /// overflow before allocating or copying the complete carrier.
    pub fn encode(
        coordinates: GitCoverageRootCoordinatesV1,
        parts: [&[u8]; 5],
    ) -> Result<Vec<u8>> {
        let mut total = COVERAGE_ROOT_SUBMISSION_HEADER_BYTES_V1 + 5 * 4;
        let mut lengths = [0_u32; 5];
        for (index, part) in parts.iter().enumerate() {
            if part.is_empty() || part.len() > ROOT_SECTION_MAXIMUM_BYTES[index] {
                return Err(GitCoverageDataErrorV1::Invalid);
            }
            lengths[index] = u32::try_from(part.len())
                .map_err(|_| GitCoverageDataErrorV1::Invalid)?;
            total = total.checked_add(part.len()).ok_or(GitCoverageDataErrorV1::Invalid)?;
        }
        if total > MAXIMUM_COVERAGE_ROOT_SUBMISSION_BYTES_V1 {
            return Err(GitCoverageDataErrorV1::Invalid);
        }

        let mut header = [0; COVERAGE_ROOT_SUBMISSION_HEADER_BYTES_V1];
        header[..8].copy_from_slice(b"AOSGUES1");
        header[8..10].copy_from_slice(&1_u16.to_be_bytes());
        header[10..12].copy_from_slice(&EXCLUSIVE_COHORT.to_be_bytes());
        header[12..28].copy_from_slice(&coordinates.root_nonce);
        header[28..36].copy_from_slice(&coordinates.cutoff.to_be_bytes());
        header[36..52].copy_from_slice(&coordinates.controller_boot);
        header[52..68].copy_from_slice(&coordinates.node);
        header[68..70].copy_from_slice(&5_u16.to_be_bytes());
        header[72..80].copy_from_slice(
            &u64::try_from(total - COVERAGE_ROOT_SUBMISSION_HEADER_BYTES_V1)
                .map_err(|_| GitCoverageDataErrorV1::Invalid)?.to_be_bytes(),
        );
        root_submission_header(&header)?;

        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(&header);
        for length in lengths {
            bytes.extend_from_slice(&length.to_be_bytes());
        }
        for part in parts {
            bytes.extend_from_slice(part);
        }
        Ok(bytes)
    }

    /// Borrows the whole exact submission, refusing any extra or missing byte.
    ///
    /// # Errors
    /// Rejects malformed headers, outer/nested length overflow, empty sections,
    /// truncation, invalid reserved bytes or trailing data. This shape check
    /// grants no signature, currentness, writer or enrollment permission.
    pub fn decode(bytes: &'a [u8]) -> Result<Self> {
        let header = bytes.get(..COVERAGE_ROOT_SUBMISSION_HEADER_BYTES_V1)
            .ok_or(GitCoverageDataErrorV1::Invalid)?;
        let body = bytes.get(COVERAGE_ROOT_SUBMISSION_HEADER_BYTES_V1..)
            .ok_or(GitCoverageDataErrorV1::Invalid)?;
        Self::decode_original_parts(header, body)
    }

    /// Borrows independently parked original header and body buffers.
    ///
    /// The same complete shape decoder serves the contiguous carrier and this
    /// fixed receive path. No buffer concatenation, nested reencoding or
    /// currentness assertion is introduced.
    ///
    /// # Errors
    /// Rejects the same invalid header, lengths, bounds and trailing bytes as
    /// [`Self::decode`]. Both inputs remain nonauthorizing comparison DATA.
    pub fn decode_original_parts(header: &[u8], body: &'a [u8]) -> Result<Self> {
        let (coordinates, body_length) = root_submission_header(header)?;
        if body_length != body.len() {
            return Err(GitCoverageDataErrorV1::Invalid);
        }

        let mut cursor: usize = 5 * 4;
        let mut parts: [&[u8]; 5] = [&[]; 5];
        for (index, part) in parts.iter_mut().enumerate() {
            let length = usize::try_from(u32_at(body, index * 4)?)
                .map_err(|_| GitCoverageDataErrorV1::Invalid)?;
            if length == 0 || length > ROOT_SECTION_MAXIMUM_BYTES[index] {
                return Err(GitCoverageDataErrorV1::Invalid);
            }
            let end = cursor.checked_add(length).ok_or(GitCoverageDataErrorV1::Invalid)?;
            *part = body.get(cursor..end).ok_or(GitCoverageDataErrorV1::Invalid)?;
            cursor = end;
        }
        if cursor != body.len() {
            return Err(GitCoverageDataErrorV1::Invalid);
        }
        Ok(Self { coordinates, parts })
    }

    /// Returns only the original flight's nonauthorizing comparison coordinates.
    #[must_use]
    pub const fn coordinates(&self) -> GitCoverageRootCoordinatesV1 {
        self.coordinates
    }

    /// Borrows the complete original sections in their closed canonical order.
    #[must_use]
    pub const fn parts(&self) -> [&'a [u8]; 5] {
        self.parts
    }
}

fn root_submission_header(bytes: &[u8]) -> Result<(GitCoverageRootCoordinatesV1, usize)> {
    if bytes.len() != COVERAGE_ROOT_SUBMISSION_HEADER_BYTES_V1
        || bytes.get(..8) != Some(b"AOSGUES1".as_slice())
        || u16_at(bytes, 8)? != 1
        || u16_at(bytes, 10)? != EXCLUSIVE_COHORT
        || u16_at(bytes, 68)? != 5
        || bytes[70..72] != [0; 2]
    {
        return Err(GitCoverageDataErrorV1::Invalid);
    }
    let coordinates = GitCoverageRootCoordinatesV1 {
        root_nonce: nonzero(bytes, 12)?,
        cutoff: positive_u64(bytes, 28)?,
        controller_boot: nonzero(bytes, 36)?,
        node: nonzero(bytes, 52)?,
    };
    let body_length = usize::try_from(u64_at(bytes, 72)?)
        .map_err(|_| GitCoverageDataErrorV1::Invalid)?;
    if !(5 * 4 + 5..=MAXIMUM_COVERAGE_ROOT_SUBMISSION_BYTES_V1
        - COVERAGE_ROOT_SUBMISSION_HEADER_BYTES_V1).contains(&body_length)
    {
        return Err(GitCoverageDataErrorV1::Invalid);
    }
    Ok((coordinates, body_length))
}

/// Distinguishes a permanent denial preparation from fresh fence readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitCoverageFlightV1 {
    /// Validates original enrollment before persisting an immutable denial.
    Prepare,
    /// Reads the same persisted denial under a fresh original flight nonce.
    Read,
}

/// Selects append preparation or observation of an already durable pair.
///
/// This is closed body DATA, not a broker method or mutation permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitCoveragePrepareModeV1 {
    /// Preserves the original byte-zero preparation recipe.
    Original,
    /// Requires an existing complete pair and performs no append.
    ExistingPair,
}

/// Contains comparison DATA common to both closed request forms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitCoverageRequestCoordinatesV1 {
    /// Actual selected existing broker family.
    pub role: GitCoverageBrokerRoleV1,
    /// Exact original signed enrolled project.
    pub project: ProjectId,
    /// Original owner node.
    pub node: [u8; 16],
    /// Original provisioned deployment epoch.
    pub epoch: [u8; 16],
    /// Original immutable enrollment generation.
    pub generation: u64,
    /// Genuine current flight nonce, never an authority substitute.
    pub nonce: [u8; 16],
    /// Complete original signed enrollment commitment.
    pub enrollment: [u8; 32],
    /// Actual owner-produced birth commitment.
    pub birth: [u8; 32],
    /// Expected predecessor for Prepare, or exact durable fence for Read.
    pub expected: [u8; 32],
    /// Complete original fixed catalog commitment.
    pub catalog: [u8; 32],
}

impl GitCoverageRequestCoordinatesV1 {
    /// Encodes a bounded canonical Prepare or Read DATA request.
    ///
    /// `Some` carries the whole original signed enrollment only for Prepare;
    /// `None` produces Read. Neither form creates a Session or owner grant.
    ///
    /// # Errors
    /// Rejects malformed enrollment, changed original bindings, zero fields
    /// or a complete request bound violation before copying its carrier.
    pub fn encode(self, enrollment: Option<&[u8]>) -> Result<Vec<u8>> {
        let (magic, intent_length) = match enrollment {
            Some(bytes) => {
                let intent = GitCoverageEnrollmentV1::decode(bytes)?;
                compare_request_enrollment(self, &intent)?;
                (b"AOSGUFP1", bytes.len())
            }
            None => (b"AOSGUFR1", 0),
        };
        let mut bytes = vec![0; COVERAGE_REQUEST_PREFIX_BYTES_V1];
        bytes[..8].copy_from_slice(magic);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = self.role as u8;
        bytes[12..28].copy_from_slice(self.project.as_bytes());
        bytes[28..44].copy_from_slice(&self.node);
        bytes[44..60].copy_from_slice(&self.epoch);
        bytes[60..68].copy_from_slice(&self.generation.to_be_bytes());
        bytes[68..84].copy_from_slice(&self.nonce);
        bytes[84..116].copy_from_slice(&self.enrollment);
        bytes[116..148].copy_from_slice(&self.birth);
        bytes[148..180].copy_from_slice(&self.expected);
        bytes[180..212].copy_from_slice(&self.catalog);
        bytes[212..220].copy_from_slice(&7_u64.to_be_bytes());
        if let Some(intent) = enrollment {
            bytes[220..222].copy_from_slice(
                &u16::try_from(intent_length)
                    .map_err(|_| GitCoverageDataErrorV1::Invalid)?.to_be_bytes(),
            );
            bytes.extend_from_slice(intent);
        }

        GitCoverageRequestV1::decode(&bytes)?;
        Ok(bytes)
    }

    /// Encodes a fresh challenge for an already durable owner pair.
    ///
    /// # Errors
    /// Rejects the same invalid original bindings and bounds as [`Self::encode`].
    pub fn encode_existing_pair(self, enrollment: &[u8]) -> Result<Vec<u8>> {
        let mut bytes = self.encode(Some(enrollment))?;
        bytes[11] = 1;
        GitCoverageRequestV1::decode(&bytes)?;
        Ok(bytes)
    }
}

/// Borrows the exact canonical request and optional original signed intent.
pub struct GitCoverageRequestV1<'a> {
    bytes: &'a [u8],
    flight: GitCoverageFlightV1,
    prepare_mode: GitCoveragePrepareModeV1,
    coordinates: GitCoverageRequestCoordinatesV1,
    enrollment: Option<GitCoverageEnrollmentV1<'a>>,
}

impl<'a> GitCoverageRequestV1<'a> {
    /// Checks one complete bounded request without fabricating peer or time.
    ///
    /// # Errors
    /// Rejects unknown framing, role, flags, mask, reserved bytes, truncation,
    /// zero coordinates or an enrollment inconsistent with the request.
    pub fn decode(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < COVERAGE_REQUEST_PREFIX_BYTES_V1
            || bytes.len() > COVERAGE_REQUEST_PREFIX_BYTES_V1 + MAXIMUM_ENROLLMENT_BYTES_V1
            || u16_at(bytes, 8)? != 1
            || bytes[11] > 1
            || u64_at(bytes, 212)? != 7
        {
            return Err(GitCoverageDataErrorV1::Invalid);
        }
        let flight = match bytes.get(..8) {
            Some(b"AOSGUFP1") => GitCoverageFlightV1::Prepare,
            Some(b"AOSGUFR1") => GitCoverageFlightV1::Read,
            _ => return Err(GitCoverageDataErrorV1::Invalid),
        };
        let prepare_mode = match (flight, bytes[11]) {
            (_, 0) => GitCoveragePrepareModeV1::Original,
            (GitCoverageFlightV1::Prepare, 1) => GitCoveragePrepareModeV1::ExistingPair,
            _ => return Err(GitCoverageDataErrorV1::Invalid),
        };
        let coordinates = GitCoverageRequestCoordinatesV1 {
            role: GitCoverageBrokerRoleV1::decode(bytes[10])?,
            project: ProjectId::from_bytes(nonzero(bytes, 12)?),
            node: nonzero(bytes, 28)?,
            epoch: nonzero(bytes, 44)?,
            generation: positive_u64(bytes, 60)?,
            nonce: nonzero(bytes, 68)?,
            enrollment: nonzero(bytes, 84)?,
            birth: nonzero(bytes, 116)?,
            expected: nonzero(bytes, 148)?,
            catalog: nonzero(bytes, 180)?,
        };
        let enrollment = match flight {
            GitCoverageFlightV1::Prepare => {
                let length = usize::from(u16_at(bytes, 220)?);
                if bytes[222..228] != [0; 6]
                    || bytes.len() != COVERAGE_REQUEST_PREFIX_BYTES_V1 + length
                {
                    return Err(GitCoverageDataErrorV1::Invalid);
                }
                let intent = GitCoverageEnrollmentV1::decode(&bytes[228..])?;
                compare_request_enrollment(coordinates, &intent)?;
                Some(intent)
            }
            GitCoverageFlightV1::Read => {
                if bytes.len() != COVERAGE_REQUEST_PREFIX_BYTES_V1
                    || bytes[220..228] != [0; 8]
                {
                    return Err(GitCoverageDataErrorV1::Invalid);
                }
                None
            }
        };

        Ok(Self { bytes, flight, prepare_mode, coordinates, enrollment })
    }

    /// Borrows the complete unchanged request DATA preimage.
    #[must_use]
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact closed flight, not a workflow or mutation permit.
    #[must_use]
    pub fn flight(&self) -> GitCoverageFlightV1 {
        self.flight
    }

    /// Returns the closed Prepare body mode, without granting append authority.
    #[must_use]
    pub fn prepare_mode(&self) -> GitCoveragePrepareModeV1 {
        self.prepare_mode
    }

    /// Returns the bounded original comparison coordinates.
    #[must_use]
    pub fn coordinates(&self) -> GitCoverageRequestCoordinatesV1 {
        self.coordinates
    }

    /// Borrows the original signed intent only for a Prepare request.
    #[must_use]
    pub fn enrollment(&self) -> Option<&GitCoverageEnrollmentV1<'a>> {
        self.enrollment.as_ref()
    }
}

fn compare_request_enrollment(
    coordinates: GitCoverageRequestCoordinatesV1,
    enrollment: &GitCoverageEnrollmentV1<'_>,
) -> Result<()> {
    if coordinates.project != enrollment.project()
        || (coordinates.node, coordinates.epoch) != enrollment.node_epoch()
        || coordinates.generation != enrollment.generation_interval().0
        || coordinates.enrollment != enrollment.digest()
        || coordinates.catalog != enrollment.commitments()[6]
    {
        return Err(GitCoverageDataErrorV1::Invalid);
    }
    Ok(())
}

/// Contains separately read-back result DATA, never durable fence input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitCoverageOutcomeFieldsV1 {
    /// Exact original request coordinates; Read uses its fresh genuine nonce.
    pub request: GitCoverageRequestCoordinatesV1,
    /// Original UUID of the persisted denial-fence transaction.
    pub transaction: [u8; 16],
    /// Native predecessor of that immutable denial-fence transaction.
    pub predecessor_prefix: [u8; 32],
    /// Commitment of the complete canonical durable AOSGUFN1 value.
    pub fence: [u8; 32],
    /// Actual same-parser native COMMIT sequence after durable readback.
    pub commit_sequence: u64,
    /// Actual same-parser whole native prefix after durable readback.
    pub native_prefix: [u8; 32],
    /// Actual bounded record count observed under that same writer.
    pub record_count: u32,
}

impl GitCoverageOutcomeFieldsV1 {
    /// Encodes canonical response DATA only after its owner supplies readback.
    ///
    /// # Errors
    /// Rejects zero coordinates, unsupported roles or empty observed prefixes.
    /// Encoding does not verify a writer, Session, commit or readback origin.
    pub fn encode(self) -> Result<[u8; COVERAGE_OUTCOME_BYTES_V1]> {
        let mut bytes = [0; COVERAGE_OUTCOME_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSGUFO1");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = self.request.role as u8;
        bytes[11] = 1;
        bytes[12..28].copy_from_slice(self.request.project.as_bytes());
        bytes[28..44].copy_from_slice(&self.request.node);
        bytes[44..60].copy_from_slice(&self.request.epoch);
        bytes[60..68].copy_from_slice(&self.request.generation.to_be_bytes());
        bytes[68..84].copy_from_slice(&self.request.nonce);
        bytes[84..116].copy_from_slice(&self.request.enrollment);
        bytes[116..148].copy_from_slice(&self.request.birth);
        bytes[148..164].copy_from_slice(&self.transaction);
        bytes[164..196].copy_from_slice(&self.predecessor_prefix);
        bytes[196..228].copy_from_slice(&self.fence);
        bytes[228..260].copy_from_slice(&self.request.catalog);
        bytes[260..268].copy_from_slice(&self.commit_sequence.to_be_bytes());
        bytes[268..300].copy_from_slice(&self.native_prefix);
        bytes[300..304].copy_from_slice(&self.record_count.to_be_bytes());
        let checksum = digest(OUTCOME_DOMAIN, &bytes[..308]);
        bytes[308..].copy_from_slice(&checksum);

        GitCoverageOutcomeV1::decode(&bytes)?;
        Ok(bytes)
    }
}

/// Borrows a canonical signed-outcome body, not an authority receipt.
pub struct GitCoverageOutcomeV1<'a> {
    bytes: &'a [u8],
    fields: GitCoverageOutcomeFieldsV1,
}

impl<'a> GitCoverageOutcomeV1<'a> {
    /// Checks the closed response form separately from the durable fence form.
    ///
    /// # Errors
    /// Rejects wrong widths, versions, roles/status, changed checksums, zero
    /// coordinates, invalid native counts, reserved bytes or trailing DATA.
    pub fn decode(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() != COVERAGE_OUTCOME_BYTES_V1
            || bytes.get(..8) != Some(b"AOSGUFO1")
            || u16_at(bytes, 8)? != 1
            || bytes[11] != 1
            || bytes[304..308] != [0; 4]
            || digest(OUTCOME_DOMAIN, &bytes[..308]) != array::<32>(bytes, 308)?
        {
            return Err(GitCoverageDataErrorV1::Invalid);
        }
        let record_count = u32_at(bytes, 300)?;
        if record_count == 0 {
            return Err(GitCoverageDataErrorV1::Invalid);
        }
        let fence = nonzero(bytes, 196)?;
        let request = GitCoverageRequestCoordinatesV1 {
            role: GitCoverageBrokerRoleV1::decode(bytes[10])?,
            project: ProjectId::from_bytes(nonzero(bytes, 12)?),
            node: nonzero(bytes, 28)?,
            epoch: nonzero(bytes, 44)?,
            generation: positive_u64(bytes, 60)?,
            nonce: nonzero(bytes, 68)?,
            enrollment: nonzero(bytes, 84)?,
            birth: nonzero(bytes, 116)?,
            // The original request's expected field is not an outcome field;
            // consumers compare it explicitly according to the closed flight.
            expected: fence,
            catalog: nonzero(bytes, 228)?,
        };

        Ok(Self {
            bytes,
            fields: GitCoverageOutcomeFieldsV1 {
                request,
                transaction: nonzero(bytes, 148)?,
                predecessor_prefix: nonzero(bytes, 164)?,
                fence,
                commit_sequence: positive_u64(bytes, 260)?,
                native_prefix: nonzero(bytes, 268)?,
                record_count,
            },
        })
    }

    /// Borrows the complete original response DATA.
    #[must_use]
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns nonauthorizing current-flight and native-readback coordinates.
    #[must_use]
    pub fn fields(&self) -> GitCoverageOutcomeFieldsV1 {
        self.fields
    }

    /// Compares the response with the whole original canonical request.
    ///
    /// # Errors
    /// Rejects a changed flight nonce, project, enrollment, role, birth,
    /// catalog, generation or exact expected predecessor/fence commitment.
    pub fn compare_request(&self, request: &GitCoverageRequestV1<'_>) -> Result<()> {
        let original = request.coordinates();
        let expected = match request.flight() {
            GitCoverageFlightV1::Prepare
                if request.prepare_mode() == GitCoveragePrepareModeV1::Original =>
                self.fields.predecessor_prefix,
            GitCoverageFlightV1::Prepare => self.fields.fence,
            GitCoverageFlightV1::Read => self.fields.fence,
        };
        if original.expected != expected
            || self.fields.request != (GitCoverageRequestCoordinatesV1 {
                expected: self.fields.fence,
                ..original
            })
        {
            return Err(GitCoverageDataErrorV1::Invalid);
        }
        Ok(())
    }

    /// Compares the actual durable fence preimage, without recoding a reply.
    ///
    /// # Errors
    /// Rejects original transaction, predecessor, birth, role, project,
    /// enrollment, catalog or generation substitution. Native readback and
    /// current Session authentication remain mandatory owner operations.
    pub fn compare_fence(&self, fence: &GitCoverageFenceV1<'_>) -> Result<()> {
        let original = fence.fields();
        let owner = match self.fields.request.role {
            GitCoverageBrokerRoleV1::Mount => GitCoverageOwnerKindV1::Mount,
            GitCoverageBrokerRoleV1::Storage => GitCoverageOwnerKindV1::StorageCatalog,
        };
        if original.owner != owner
            || self.fields.fence != fence.digest()
            || self.fields.transaction != original.transaction
            || self.fields.predecessor_prefix != original.predecessor_prefix
            || self.fields.request.project != original.project
            || self.fields.request.node != original.node
            || self.fields.request.epoch != original.epoch
            || self.fields.request.generation != original.generation
            || self.fields.request.enrollment != original.enrollment
            || self.fields.request.birth != original.birth
            || self.fields.request.catalog != original.catalog
        {
            return Err(GitCoverageDataErrorV1::Invalid);
        }
        Ok(())
    }
}

// Unit codes identify existing fixed services, never arbitrary unit strings.
fn profile_unit_code(profile: GitCoverageJournalProfileV1) -> u16 {
    match profile {
        GitCoverageJournalProfileV1::StorageWorkspace
        | GitCoverageJournalProfileV1::StorageOutput => 6,
        _ => unit_code(profile.owner()),
    }
}

fn unit_code(kind: GitCoverageOwnerKindV1) -> u16 {
    match kind {
        GitCoverageOwnerKindV1::Controller | GitCoverageOwnerKindV1::PublisherAdmission
        | GitCoverageOwnerKindV1::RuntimeOutput => 1,
        GitCoverageOwnerKindV1::Root => 2,
        GitCoverageOwnerKindV1::Source => 3,
        GitCoverageOwnerKindV1::CacheAuthority | GitCoverageOwnerKindV1::CacheState
        | GitCoverageOwnerKindV1::CachePhysical => 1,
        GitCoverageOwnerKindV1::Mount => 5,
        GitCoverageOwnerKindV1::StorageCatalog | GitCoverageOwnerKindV1::StorageNative => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_submission_lends_exact_sections_and_checks_outer_and_nested_bounds() {
        // Deliberately inert framing bytes, not an owner or signed fixture.
        let coordinates = GitCoverageRootCoordinatesV1 {
            root_nonce: [1; 16], cutoff: 100, controller_boot: [2; 16], node: [3; 16],
        };
        let parts: [&[u8]; 5] = [b"intent", b"catalog", b"mount", b"storage", b"local"];
        let original = GitCoverageRootSubmissionV1::encode(coordinates, parts).unwrap();

        let decoded = GitCoverageRootSubmissionV1::decode(&original).unwrap();
        assert_eq!(decoded.coordinates(), coordinates);
        assert_eq!(decoded.parts(), parts);
        assert_eq!(GitCoverageRootSubmissionV1::bounded_body_length(&original[..80]).unwrap(),
            original.len() - 80);
        let start = original.as_ptr() as usize;
        assert!(decoded.parts().iter().all(|part| {
            let pointer = part.as_ptr() as usize;
            pointer >= start && pointer + part.len() <= start + original.len()
        }));

        for (offset, value) in [(8, 1), (11, 0), (69, 4), (70, 1)] {
            let mut changed = original.clone();
            changed[offset] = value;
            assert!(GitCoverageRootSubmissionV1::decode(&changed).is_err());
        }
        let mut oversized = original.clone();
        oversized[80..84].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(GitCoverageRootSubmissionV1::decode(&oversized).is_err());
        let mut extra = original.clone();
        extra.push(0);
        assert!(GitCoverageRootSubmissionV1::decode(&extra).is_err());
        assert!(GitCoverageRootSubmissionV1::decode(&original[..original.len() - 1]).is_err());
        assert!(GitCoverageRootSubmissionV1::encode(coordinates, [b""; 5]).is_err());

        let large_intent = vec![0; MAXIMUM_ENROLLMENT_BYTES_V1 + 1];
        assert!(GitCoverageRootSubmissionV1::encode(coordinates,
            [&large_intent, parts[1], parts[2], parts[3], parts[4]]).is_err());
        let mut header = original[..80].to_vec();
        header[72..80].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(GitCoverageRootSubmissionV1::bounded_body_length(&header).is_err());
    }

    #[test]
    fn native_writer_membership_keeps_distinct_authorities_and_closed_physical_groups() {
        use GitCoverageJournalProfileV1 as Profile;

        assert!(Profile::Controller.is_native_writer_member_v1(Profile::Controller));
        assert!(Profile::Controller.is_native_writer_member_v1(Profile::PublisherAdmission));
        assert!(Profile::Controller.is_native_writer_member_v1(Profile::RuntimeOutput));
        assert!(!Profile::PublisherAdmission.is_native_writer_member_v1(Profile::Controller));
        for profile in [Profile::RootAuthority, Profile::Source, Profile::CacheAuthority,
            Profile::CacheState, Profile::CachePhysical, Profile::Mount, Profile::StorageCatalog,
            Profile::StorageNative, Profile::CacheClock, Profile::CachePolicyHold,
            Profile::RootPolicyState, Profile::CacheBootstrap, Profile::StorageWorkspace,
            Profile::StorageOutput]
        {
            assert!(!Profile::Controller.is_native_writer_member_v1(profile));
            assert!(profile.is_native_writer_member_v1(profile));
        }
    }

    #[test]
    fn broker_proof_framing_preserves_all_five_original_slices() {
        // Framing DATA only; these bytes are deliberately not signed packets.
        let parts: [&[u8]; 5] = [b"checkpoint", b"prepare", b"prepared", b"read", b"observed"];
        let bytes = GitCoverageBrokerProofV1::encode(GitCoverageBrokerRoleV1::Mount, parts)
            .unwrap();

        let decoded = GitCoverageBrokerProofV1::decode(&bytes).unwrap();
        assert_eq!(decoded.role(), GitCoverageBrokerRoleV1::Mount);
        assert_eq!(decoded.parts(), parts);
        assert_eq!(bytes.len(), COVERAGE_BROKER_PROOF_HEADER_BYTES_V1
            + parts.iter().map(|part| part.len()).sum::<usize>());
        assert!(decoded.parts().iter().all(|part| {
            let start = bytes.as_ptr() as usize;
            let pointer = part.as_ptr() as usize;
            pointer >= start && pointer + part.len() <= start + bytes.len()
        }));
    }

    #[test]
    fn broker_proof_bounds_flags_and_exact_tail_are_closed() {
        let parts: [&[u8]; 5] = [b"a", b"b", b"c", b"d", b"e"];
        let original = GitCoverageBrokerProofV1::encode(GitCoverageBrokerRoleV1::Storage, parts)
            .unwrap();

        for (offset, value) in [(8, 1), (10, 0), (10, 3), (11, 1)] {
            let mut changed = original.clone();
            changed[offset] = value;
            assert!(GitCoverageBrokerProofV1::decode(&changed).is_err());
        }
        let mut trailing = original.clone();
        trailing.push(0);
        assert!(GitCoverageBrokerProofV1::decode(&trailing).is_err());
        assert!(GitCoverageBrokerProofV1::decode(&original[..original.len() - 1]).is_err());

        let mut overflow = original.clone();
        overflow[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(GitCoverageBrokerProofV1::decode(&overflow).is_err());
        assert!(GitCoverageBrokerProofV1::encode(
            GitCoverageBrokerRoleV1::Mount, [b"", b"b", b"c", b"d", b"e"],
        ).is_err());
        let oversized = vec![0; MAXIMUM_COVERAGE_BROKER_PROOF_BYTES_V1];
        assert!(GitCoverageBrokerProofV1::encode(
            GitCoverageBrokerRoleV1::Mount, [&oversized, b"b", b"c", b"d", b"e"],
        ).is_err());
    }

    // Canonical DATA only: this fixture contains no privileged owner, current
    // deployment, provisioning origin proof or positive admission assertion.
    fn catalog_fixture(key: &[u8]) -> Vec<u8> {
        assert!(!key.is_empty() && key.len() <= 160);
        let mut member = [0_u8; CATALOG_MEMBER_BYTES];
        member[0] = GitCoverageOwnerKindV1::CacheAuthority as u8;
        member[1] = 2;
        member[4..6].copy_from_slice(&unit_code(GitCoverageOwnerKindV1::CacheAuthority).to_be_bytes());
        member[6..8].copy_from_slice(&4_u16.to_be_bytes());
        member[8..24].fill(1);
        member[24..40].fill(2);
        member[40..72].fill(5);
        member[72..104].fill(6);
        member[104..136].fill(7);
        member[136..140].copy_from_slice(&1_u32.to_be_bytes());

        let mut row = [0_u8; INFRASTRUCTURE_BYTES];
        row[0] = GitCoverageOwnerKindV1::CacheAuthority as u8;
        row[1] = 1;
        row[4..6].copy_from_slice(&(key.len() as u16).to_be_bytes());
        row[8..8 + key.len()].copy_from_slice(key);
        row[168..184].fill(8);
        row[184..192].copy_from_slice(&3_u64.to_be_bytes());
        row[192..224].fill(9);
        row[224..256].copy_from_slice(&member[72..104]);
        row[256..288].copy_from_slice(&digest(MEMBER_DOMAIN, &member));

        let mut bytes = vec![0_u8; CATALOG_HEADER_BYTES];
        bytes[..8].copy_from_slice(b"AOSGUOC1");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[12..28].fill(1);
        bytes[28..44].fill(2);
        bytes[44..76].fill(3);
        bytes[76..108].fill(4);
        bytes[108..110].copy_from_slice(&1_u16.to_be_bytes());
        bytes[110..112].copy_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&member);
        bytes.extend_from_slice(&row);
        reseal_catalog(&mut bytes);
        bytes
    }

    fn reseal_catalog(bytes: &mut [u8]) {
        let checksum = Sha256::new()
            .chain_update(CATALOG_DOMAIN)
            .chain_update(&bytes[..116])
            .chain_update(&bytes[CATALOG_HEADER_BYTES..])
            .finalize();
        bytes[116..148].copy_from_slice(&checksum);
    }

    #[test]
    fn full_native_key_and_partition_are_preserved_as_data() {
        let bytes = catalog_fixture(&[31; 160]);

        let catalog = GitCoverageCatalogV1::decode(&bytes).unwrap();
        let member = catalog.fixed_member(GitCoverageJournalProfileV1::CacheAuthority, [5; 32])
            .unwrap();

        assert_eq!(&member.bytes()[40..72], &[5; 32]);
        assert_eq!(&catalog.infrastructure_bytes()[8..168], &[31; 160]);
        assert_eq!(MAXIMUM_OWNER_CATALOG_BYTES_V1,
            CATALOG_HEADER_BYTES + 16 * CATALOG_MEMBER_BYTES + 64 * INFRASTRUCTURE_BYTES);
    }

    #[test]
    fn oversized_key_refuses_even_with_a_valid_catalog_checksum() {
        let mut bytes = catalog_fixture(&[31; 160]);
        let row = CATALOG_HEADER_BYTES + CATALOG_MEMBER_BYTES;
        bytes[row + 4..row + 6].copy_from_slice(&161_u16.to_be_bytes());
        reseal_catalog(&mut bytes);

        assert!(GitCoverageCatalogV1::decode(&bytes).is_err());
    }

    #[test]
    fn attribution_and_physical_origin_must_resolve_the_same_full_member() {
        let original = catalog_fixture(&[31; 107]);
        let row = CATALOG_HEADER_BYTES + CATALOG_MEMBER_BYTES;

        for offset in [224, 256] {
            let mut bytes = original.clone();
            bytes[row + offset] ^= 1;
            reseal_catalog(&mut bytes);

            assert!(GitCoverageCatalogV1::decode(&bytes).is_err());
        }
    }

    #[test]
    fn historical_clock_keys_keep_distinct_original_put_versions() {
        let mut bytes = catalog_fixture(b"\0aos-cache-residency-clock-v1\0current");
        let member_start = CATALOG_HEADER_BYTES;
        let row_start = member_start + CATALOG_MEMBER_BYTES;
        bytes[member_start + 6..member_start + 8]
            .copy_from_slice(&(GitCoverageJournalProfileV1::CacheClock as u16).to_be_bytes());
        bytes[member_start + 40..member_start + 72].fill(0);
        bytes[member_start + 136..member_start + 140].copy_from_slice(&2_u32.to_be_bytes());
        bytes[110..112].copy_from_slice(&2_u16.to_be_bytes());

        let attribution = digest(MEMBER_DOMAIN, &bytes[member_start..row_start]);
        bytes[row_start + 184..row_start + 192].copy_from_slice(&2_u64.to_be_bytes());
        bytes[row_start + 256..row_start + 288].copy_from_slice(&attribution);
        let mut successor = bytes[row_start..].to_vec();
        successor[168..184].fill(9);
        successor[184..192].copy_from_slice(&5_u64.to_be_bytes());
        successor[192..224].fill(10);
        bytes.extend_from_slice(&successor);
        reseal_catalog(&mut bytes);

        let catalog = GitCoverageCatalogV1::decode(&bytes).unwrap();
        assert_eq!(catalog.infrastructure().count(), 2);
        assert!(catalog.infrastructure().all(|row| {
            row.key() == b"\0aos-cache-residency-clock-v1\0current"
        }));

        // The pure catalog compares complete native identities. The actual
        // owner's prefix replay independently rejects impossible sequence
        // reuse; this DATA decoder cannot manufacture that owner evidence.
        let successor_start = row_start + INFRASTRUCTURE_BYTES;
        bytes[successor_start + 184..successor_start + 192]
            .copy_from_slice(&2_u64.to_be_bytes());
        reseal_catalog(&mut bytes);
        assert!(GitCoverageCatalogV1::decode(&bytes).is_ok());

        // A second declaration for the SAME original UUID and PUT position
        // equivocates even when its value digest and catalog checksum differ.
        bytes[successor_start + 168..successor_start + 184].fill(8);
        reseal_catalog(&mut bytes);
        assert!(GitCoverageCatalogV1::decode(&bytes).is_err());
    }
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    let end = offset.checked_add(N).ok_or(GitCoverageDataErrorV1::Invalid)?;
    bytes.get(offset..end).and_then(|value| value.try_into().ok())
        .ok_or(GitCoverageDataErrorV1::Invalid)
}

fn nonzero<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    let value = array(bytes, offset)?;
    if value == [0; N] { return Err(GitCoverageDataErrorV1::Invalid); }
    Ok(value)
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_be_bytes(array(bytes, offset)?))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(array(bytes, offset)?))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_be_bytes(array(bytes, offset)?))
}

fn positive_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let value = u64_at(bytes, offset)?;
    if value == 0 { return Err(GitCoverageDataErrorV1::Invalid); }
    Ok(value)
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(domain).chain_update(bytes).finalize().into()
}
