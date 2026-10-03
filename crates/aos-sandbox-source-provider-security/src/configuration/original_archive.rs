//! Protected public-only deployment images and exact physical cut associations.
//!
//! An image supplies replay facts, never a current configuration or Session.
//! The fixed owner pins root-owned single-link immutable files. Journal
//! membership is established separately by matching a real committed cut.
//!
//! ```text
//! AOSSPD05 | version=1 | D[32] | limits[32] | four lengths:u32be |
//! exact manifest | exact trust | exact route | signed catalog
//! AOSSPO05 | version=1 | E[32] | D[32] | acquisition[32] | session[32] |
//! Applying-id[16] | ordered-digest[32] | floor-key/value/enrollment lengths |
//! exact original Source5 key | value | public Storage enrollment
//! AOSSPC05 | version=1 | device/inode/begin-sequence/begin-offset:u64be |
//! transaction[16] | ordered-digest[32] | before E/D | after E/D | origin O
//! | B-at-cut E | realtime-anchor:i64be | actual challenge inode/prefix |
//! current Session binding | observed-query-length:u32be | actual query bytes
//! ```

use std::collections::BTreeSet;
use std::sync::Arc;

use aos_sandbox::journal::{
    SourceOriginalAdmissionDataV5, SourceOriginalAppendSubjectV5, SourceOriginalPhysicalCutV5,
    SourceOriginalChallengeHistoryViewV5,
    native_held::{OriginalSourceCapacityRecordV5, ORIGINAL_SOURCE_CAPACITY_MAXIMUM_VALUE_BYTES_V5},
};
use aos_sandbox::{JournalRecord, RecordNamespace};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_ledger::limits::MAXIMUM_LEDGER_GRAPH_BYTES;
use sha2::{Digest as _, Sha256};

use super::{ProviderConfigurationDataV5, RevalidatedProviderConfigurationV1, project_public_capture};
use crate::protected_files::{
    ProtectedPublicArchiveDirectoryV5, ProtectedPublicArchiveFileV5, PublicConfigurationCaptureV5,
};
use crate::{SourceProviderSecurityError, VerifiedCatalogPublicationV1};

mod selected_input;
pub use selected_input::ProtectedOriginalSelectedInputV1;
mod read_only;
pub(crate) use read_only::FixedSourcePublicArchiveReadbackV1;

const DEPLOYMENT_MAGIC: &[u8; 8] = b"AOSSPD05";
const ORIGIN_MAGIC: &[u8; 8] = b"AOSSPO05";
const CUT_MAGIC: &[u8; 8] = b"AOSSPC05";
const DEPLOYMENT_HEADER: usize = 96;
const ORIGIN_HEADER: usize = 204;
const CUT_HEADER: usize = 388;
const CUT_MAXIMUM: usize = CUT_HEADER
    + aos_sandbox_source_provider_protocol::native_held_completion::MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1;
const DEPLOYMENT_MAXIMUM: usize = DEPLOYMENT_HEADER
    + crate::manifest::SOURCE_PROVIDER_SECURITY_MANIFEST_BYTES
    + crate::trust_file::MAXIMUM_SOURCE_PROVIDER_TRUST_FILE_BYTES
    + crate::route_file::SOURCE_PROVIDER_ROUTE_FILE_BYTES
    + crate::catalog::SIGNED_BYTES;
const ORIGIN_MAXIMUM: usize = ORIGIN_HEADER
    + ORIGINAL_SOURCE_CAPACITY_MAXIMUM_VALUE_BYTES_V5
    + MAXIMUM_LEDGER_GRAPH_BYTES;

/// Retains a genuine immutable public deployment readback, not current custody.
#[doc(hidden)]
pub struct ProtectedOriginalDeploymentV5 {
    file: ProtectedPublicArchiveFileV5,
    identity: ObjectDigest,
    configuration: ObjectDigest,
    limits: ObjectDigest,
    data: ProviderConfigurationDataV5,
    catalog: VerifiedCatalogPublicationV1,
}

impl ProtectedOriginalDeploymentV5 {
    /// Returns the whole-image identity E and unchanged Source commitment D.
    pub const fn identities(&self) -> (ObjectDigest, ObjectDigest) {
        (self.identity, self.configuration)
    }

    /// Returns the captured fixed Source limit-policy commitment.
    pub const fn limits_digest(&self) -> ObjectDigest {
        self.limits
    }

    /// Borrows replay-only public facts with no currentness conversion.
    pub const fn public_projection(&self) -> &ProviderConfigurationDataV5 {
        &self.data
    }

    /// Borrows the actual archived signed catalog verified under archived pins.
    pub const fn catalog(&self) -> &VerifiedCatalogPublicationV1 {
        &self.catalog
    }
}

/// Retains one bounded immutable origin envelope joined to actual Applying DATA.
#[doc(hidden)]
pub struct ProtectedOriginalOriginV5 {
    file: ProtectedPublicArchiveFileV5,
    identity: ObjectDigest,
    deployment: ObjectDigest,
    configuration: ObjectDigest,
    enrollment: std::ops::Range<usize>,
}

impl ProtectedOriginalOriginV5 {
    /// Returns the separate complete origin-envelope identity O.
    pub const fn identity(&self) -> ObjectDigest {
        self.identity
    }

    /// Borrows actual public Storage enrollment, without historical rotation authority.
    pub fn storage_enrollment(&self) -> &[u8] {
        &self.file.exact()[self.enrollment.clone()]
    }
}

/// Retains exact archive identities for a prospective or actual physical cut.
#[doc(hidden)]
pub struct ProtectedOriginalCutReferenceV5 {
    file: ProtectedPublicArchiveFileV5,
    before: (ObjectDigest, ObjectDigest),
    after: (ObjectDigest, ObjectDigest),
    origin: Option<ObjectDigest>,
    eligibility: ObjectDigest,
    observed_seconds: i64,
    challenge_prefix: ((u64, u64), u64, ObjectDigest),
    session: ObjectDigest,
}

impl ProtectedOriginalCutReferenceV5 {
    /// Returns the genuine current Session identity captured at the append boundary.
    pub const fn current_session(&self) -> ObjectDigest {
        self.session
    }

    /// Returns the independently captured B-at-cut archive and real time anchor.
    pub const fn eligibility_context(&self) -> (ObjectDigest, i64) {
        (self.eligibility, self.observed_seconds)
    }

    /// Returns the separately held actual challenge prefix captured before append.
    pub const fn challenge_prefix(&self) -> ((u64, u64), u64, ObjectDigest) {
        self.challenge_prefix
    }

    /// Borrows actually observed recovery-query bytes, never reconstructed from ACK facts.
    pub fn observed_query(&self) -> &[u8] {
        &self.file.exact()[CUT_HEADER..]
    }

    /// Returns archived before and after deployment/configuration identities.
    pub const fn deployments(&self) -> ((ObjectDigest, ObjectDigest), (ObjectDigest, ObjectDigest)) {
        (self.before, self.after)
    }

    /// Returns an origin envelope only for its actual Applying cut.
    pub const fn origin_identity(&self) -> Option<ObjectDigest> {
        self.origin
    }
}

/// Owns only the fixed protected public configuration archive.
///
/// This authority persists immutable PUBLIC bytes; it cannot sign, send,
/// activate Source, issue a nonce, construct a Session or authorize an effect.
#[doc(hidden)]
pub struct ProtectedOriginalConfigurationArchiveV5 {
    directory: ProtectedPublicArchiveDirectoryV5,
    retained: usize,
    identities: BTreeSet<(u8, ObjectDigest)>,
    deployments: Vec<Arc<ProtectedOriginalDeploymentV5>>,
}

impl ProtectedOriginalConfigurationArchiveV5 {
    /// Opens the fixed archive after the ledger and challenge owners are held.
    ///
    /// # Errors
    ///
    /// Refuses absent, foreign, writable-by-others, linked or changed protected paths.
    pub fn open_fixed() -> Result<Self, SourceProviderSecurityError> {
        Ok(Self {
            directory: ProtectedPublicArchiveDirectoryV5::open_fixed()?,
            retained: 0,
            identities: BTreeSet::new(),
            deployments: Vec::new(),
        })
    }

    /// Revalidates every retained immutable deployment and its fixed directory.
    ///
    /// # Errors
    ///
    /// Refuses inode, exact-byte, metadata, pathname or root-custody replacement.
    pub fn revalidate(&self) -> Result<(), SourceProviderSecurityError> {
        self.directory.revalidate()?;
        for image in &self.deployments {
            self.directory.validate_file(&image.file)?;
        }
        self.directory.revalidate()
    }

    /// Installs a complete current PUBLIC capture before the referenced append.
    ///
    /// D remains Source's existing commitment; E additionally commits all raw
    /// public bytes. Source must reconstruct D from this genuine readback.
    ///
    /// # Errors
    ///
    /// Refuses capture/catalog disagreement, bounds, conflicting immutable files or custody change.
    pub fn capture_deployment(
        &mut self,
        current: &RevalidatedProviderConfigurationV1,
        catalog: &VerifiedCatalogPublicationV1,
        configuration: ObjectDigest,
        limits: ObjectDigest,
    ) -> Result<Arc<ProtectedOriginalDeploymentV5>, SourceProviderSecurityError> {
        self.revalidate()?;
        crate::catalog::verify_catalog_publication(current, catalog.canonical_publication())?;
        let capture = &current.public_capture;
        let parts = [
            &capture.manifest[..],
            &capture.trust[..],
            &capture.route[..],
            catalog.canonical_publication(),
        ];
        let size = parts.iter().try_fold(DEPLOYMENT_HEADER, |size, bytes| {
            size.checked_add(bytes.len()).ok_or(SourceProviderSecurityError::Currentness)
        })?;
        let mut exact = header(DEPLOYMENT_MAGIC);
        exact.extend_from_slice(configuration.as_bytes());
        exact.extend_from_slice(limits.as_bytes());
        for bytes in parts {
            append_length(&mut exact, bytes.len())?;
        }

        let mut commitment = Sha256::new();
        commitment.update(b"aos.source.original.deployment-image.v5\0");
        commitment.update(&exact);
        for bytes in parts {
            commitment.update(bytes);
        }
        let identity = ObjectDigest::from_bytes(commitment.finalize().into());
        if let Some(image) = self.deployments.iter().find(|image| image.identity == identity) {
            return Ok(Arc::clone(image));
        }
        self.bound(size)?;
        for bytes in parts {
            exact.extend_from_slice(bytes);
        }
        let name = filename(b'e', identity);
        self.directory.install(&name, &exact, DEPLOYMENT_MAXIMUM)?;
        self.read_deployment(identity)
    }

    /// Reads and deduplicates E only from the actual immutable fixed archive.
    ///
    /// # Errors
    ///
    /// Refuses aggregate bounds before reading, absent/substituted images, noncanonical captures or signatures.
    pub fn read_deployment(
        &mut self,
        identity: ObjectDigest,
    ) -> Result<Arc<ProtectedOriginalDeploymentV5>, SourceProviderSecurityError> {
        self.revalidate()?;
        if let Some(image) = self.deployments.iter().find(|image| image.identity == identity) {
            return Ok(Arc::clone(image));
        }
        let name = filename(b'e', identity);
        let size = self.directory.bounded_size(&name, DEPLOYMENT_MAXIMUM)?;
        self.bound(size)?;
        let file = self.directory.read(&name, size)?;
        if file.exact().len() != size {
            return Err(SourceProviderSecurityError::Currentness);
        }

        let exact = file.exact();
        let (configuration, limits, parts) = deployment_parts(exact, identity)?;
        let capture = PublicConfigurationCaptureV5 {
            manifest: parts[0].to_vec(),
            trust: parts[1].to_vec(),
            route: parts[2].to_vec(),
        };
        let data = project_public_capture(&capture)?;
        let catalog = verify_archived_catalog(&data, parts[3])?;
        let bytes = exact.len();
        let image = Arc::new(ProtectedOriginalDeploymentV5 {
            file, identity, configuration, limits, data, catalog,
        });
        self.retain(b'e', identity, bytes)?;
        self.deployments.push(Arc::clone(&image));
        self.revalidate()?;
        Ok(image)
    }

    /// Persists bounded original floor/context and actual public Storage enrollment.
    ///
    /// # Errors
    ///
    /// Refuses mismatched D/owner/admission, oversized input, immutable conflict or changed archive custody.
    pub fn install_origin(
        &mut self,
        deployment: &ProtectedOriginalDeploymentV5,
        original: &SourceOriginalAdmissionDataV5,
        ordered_digest: [u8; 32],
        enrollment: &[u8],
    ) -> Result<ProtectedOriginalOriginV5, SourceProviderSecurityError> {
        self.directory.validate_file(&deployment.file)?;
        let owner = original.admission_comparison().original();
        if owner.configuration_digest != deployment.configuration {
            return Err(SourceProviderSecurityError::Currentness);
        }
        let floor = original.initial_floor().to_journal_record()
            .map_err(|_| SourceProviderSecurityError::Currentness)?;
        let value = floor.value().ok_or(SourceProviderSecurityError::Currentness)?;
        let size = ORIGIN_HEADER.checked_add(floor.key().len())
            .and_then(|size| size.checked_add(value.len()))
            .and_then(|size| size.checked_add(enrollment.len()))
            .ok_or(SourceProviderSecurityError::Currentness)?;
        self.bound(size)?;
        let mut exact = header(ORIGIN_MAGIC);
        for digest in [
            deployment.identity,
            deployment.configuration,
            owner.acquisition_id,
            owner.session_binding,
        ] {
            exact.extend_from_slice(digest.as_bytes());
        }
        exact.extend_from_slice(original.applying_transaction().id());
        exact.extend_from_slice(&ordered_digest);
        for bytes in [floor.key(), value, enrollment] {
            append_length(&mut exact, bytes.len())?;
        }
        for bytes in [floor.key(), value, enrollment] {
            exact.extend_from_slice(bytes);
        }
        let identity = identity(b"aos.source.original.origin-envelope.v5\0", &exact);
        self.directory.install(&filename(b'o', identity), &exact, ORIGIN_MAXIMUM)?;
        self.read_origin(identity, deployment, original, ordered_digest)
    }

    /// Joins protected O to exact retained Applying/floor/provenance DATA.
    ///
    /// # Errors
    ///
    /// Refuses foreign acquisition/session/E/D/TX, floor substitution, oversized or missing enrollment.
    pub fn read_origin(
        &mut self,
        identity: ObjectDigest,
        deployment: &ProtectedOriginalDeploymentV5,
        original: &SourceOriginalAdmissionDataV5,
        ordered_digest: [u8; 32],
    ) -> Result<ProtectedOriginalOriginV5, SourceProviderSecurityError> {
        self.directory.validate_file(&deployment.file)?;
        let name = filename(b'o', identity);
        let size = self.directory.bounded_size(&name, ORIGIN_MAXIMUM.min(MAXIMUM_LEDGER_GRAPH_BYTES))?;
        if !self.identities.contains(&(b'o', identity)) {
            self.bound(size)?;
        }
        let file = self.directory.read(&name, size)?;
        if file.exact().len() != size {
            return Err(SourceProviderSecurityError::Currentness);
        }
        let exact = file.exact();
        require_header(exact, ORIGIN_MAGIC, ORIGIN_HEADER)?;
        let owner = original.admission_comparison().original();
        if self::identity(b"aos.source.original.origin-envelope.v5\0", exact) != identity
            || digest_at(exact, 16)? != deployment.identity
            || digest_at(exact, 48)? != deployment.configuration
            || digest_at(exact, 80)? != owner.acquisition_id
            || digest_at(exact, 112)? != owner.session_binding
            || exact.get(144..160) != Some(original.applying_transaction().id().as_slice())
            || exact.get(160..192) != Some(ordered_digest.as_slice())
        {
            return Err(SourceProviderSecurityError::Currentness);
        }
        let parts = sections(exact, ORIGIN_HEADER, 192, 3)?;
        let floor = JournalRecord::put(
            RecordNamespace::GlobalCapacityReservation,
            parts[0].to_vec(),
            parts[1].to_vec(),
        );
        let decoded = OriginalSourceCapacityRecordV5::from_journal_record(&floor)
            .map_err(|_| SourceProviderSecurityError::Currentness)?;
        if &decoded != original.initial_floor() || parts[2].is_empty() {
            return Err(SourceProviderSecurityError::Currentness);
        }
        let enrollment = (exact.len() - parts[2].len())..exact.len();
        let bytes = exact.len();
        self.retain(b'o', identity, bytes)?;
        Ok(ProtectedOriginalOriginV5 {
            file,
            identity,
            deployment: deployment.identity,
            configuration: deployment.configuration,
            enrollment,
        })
    }

    /// Installs exact current-prefix association before one named held append.
    ///
    /// # Errors
    ///
    /// Refuses foreign origin/deployment identities, conflict, aggregate bounds or changed protected readback.
    pub fn install_cut(
        &mut self,
        subject: &SourceOriginalAppendSubjectV5,
        before: &ProtectedOriginalDeploymentV5,
        after: &ProtectedOriginalDeploymentV5,
        origin: Option<&ProtectedOriginalOriginV5>,
        eligibility: &ProtectedOriginalDeploymentV5,
        observed_seconds: i64,
        challenges: &SourceOriginalChallengeHistoryViewV5<'_>,
        session: &crate::CurrentProviderSessionProjectionV1,
        observed_query: &[u8],
    ) -> Result<ProtectedOriginalCutReferenceV5, SourceProviderSecurityError> {
        self.directory.validate_file(&before.file)?;
        self.directory.validate_file(&after.file)?;
        self.directory.validate_file(&eligibility.file)?;
        let (challenge_identity, challenge_sequence, challenge_digest) = challenges.current_prefix()
            .map_err(|_| SourceProviderSecurityError::Currentness)?;
        if observed_seconds < eligibility.data.validity().0
            || observed_seconds >= eligibility.data.validity().1
            || observed_query.len() > CUT_MAXIMUM - CUT_HEADER
        {
            return Err(SourceProviderSecurityError::Currentness);
        }
        if let Some(origin) = origin {
            self.directory.validate_file(&origin.file)?;
            if (origin.deployment, origin.configuration) != after.identities() {
                return Err(SourceProviderSecurityError::Currentness);
            }
        }
        self.bound(CUT_HEADER + observed_query.len())?;
        let (device, inode) = subject.file_identity();
        let (transaction, digest) = subject.transaction();
        let (sequence, offset) = subject.prefix();
        let mut exact = header(CUT_MAGIC);
        for value in [device, inode, sequence, offset] {
            exact.extend_from_slice(&value.to_be_bytes());
        }
        exact.extend_from_slice(&transaction);
        exact.extend_from_slice(&digest);
        for value in [before.identity, before.configuration, after.identity, after.configuration] {
            exact.extend_from_slice(value.as_bytes());
        }
        exact.extend_from_slice(origin.map_or(&[0; 32], |origin| origin.identity.as_bytes()));
        exact.extend_from_slice(eligibility.identity.as_bytes());
        exact.extend_from_slice(&observed_seconds.to_be_bytes());
        for value in [challenge_identity.0, challenge_identity.1, challenge_sequence] {
            exact.extend_from_slice(&value.to_be_bytes());
        }
        exact.extend_from_slice(challenge_digest.as_bytes());
        exact.extend_from_slice(session.session_binding().as_bytes());
        append_length(&mut exact, observed_query.len())?;
        exact.extend_from_slice(observed_query);
        let name = cut_filename(subject.file_identity(), transaction, digest);
        let file = self.directory.install(&name, &exact, CUT_MAXIMUM)?;
        let identity = identity(b"aos.source.original.cut-reference.v5\0", &exact);
        self.retain(b'c', identity, exact.len())?;
        Ok(ProtectedOriginalCutReferenceV5 {
            file,
            before: before.identities(),
            after: after.identities(),
            origin: origin.map(|origin| origin.identity),
            eligibility: eligibility.identity,
            observed_seconds,
            challenge_prefix: (challenge_identity, challenge_sequence, challenge_digest),
            session: session.session_binding(),
        })
    }

    /// Reads an association only by the real checksum-verified committed cut.
    ///
    /// # Errors
    ///
    /// Refuses missing reference, foreign inode/TX/digest/physical prefix or changed immutable bytes.
    pub fn read_cut(
        &mut self,
        cut: &SourceOriginalPhysicalCutV5,
    ) -> Result<ProtectedOriginalCutReferenceV5, SourceProviderSecurityError> {
        let name = cut_filename(cut.file_identity(), *cut.transaction_id(), *cut.transaction_digest());
        let size = self.directory.bounded_size(&name, CUT_MAXIMUM)?;
        self.bound(size)?;
        let file = self.directory.read(&name, size)?;
        let exact = file.exact();
        require_header(exact, CUT_MAGIC, CUT_HEADER)?;
        let (device, inode) = cut.file_identity();
        if exact.len() != size || u64_at(exact, 16)? != device || u64_at(exact, 24)? != inode
            || u64_at(exact, 32)? != cut.frame_sequences().0 || u64_at(exact, 40)? != cut.file_offsets().0
            || exact.get(48..64) != Some(cut.transaction_id().as_slice())
            || exact.get(64..96) != Some(cut.transaction_digest().as_slice())
        {
            return Err(SourceProviderSecurityError::Currentness);
        }
        let before = (digest_at(exact, 96)?, digest_at(exact, 128)?);
        let after = (digest_at(exact, 160)?, digest_at(exact, 192)?);
        let origin = digest_at(exact, 224)?;
        let eligibility = digest_at(exact, 256)?;
        let observed_seconds = i64::from_be_bytes(exact.get(288..296)
            .ok_or(SourceProviderSecurityError::Currentness)?.try_into().map_err(|_| SourceProviderSecurityError::Currentness)?);
        let challenge_prefix = ((u64_at(exact, 296)?, u64_at(exact, 304)?), u64_at(exact, 312)?, digest_at(exact, 320)?);
        let session = digest_at(exact, 352)?;
        sections(exact, CUT_HEADER, 384, 1)?;
        let identity = identity(b"aos.source.original.cut-reference.v5\0", exact);
        self.retain(b'c', identity, exact.len())?;
        Ok(ProtectedOriginalCutReferenceV5 {
            file,
            before,
            after,
            origin: (origin.as_bytes() != &[0; 32]).then_some(origin),
            eligibility,
            observed_seconds,
            challenge_prefix,
            session,
        })
    }

    /// Rechecks a retained origin/cut at every preparation and readback boundary.
    ///
    /// # Errors
    ///
    /// Refuses changed pathname, inode, metadata or exact bytes.
    pub fn validate_references(
        &self,
        cut: &ProtectedOriginalCutReferenceV5,
        origin: Option<&ProtectedOriginalOriginV5>,
    ) -> Result<(), SourceProviderSecurityError> {
        self.directory.validate_file(&cut.file)?;
        if let Some(origin) = origin {
            self.directory.validate_file(&origin.file)?;
        }
        self.revalidate()
    }

    /// Requires a retained reference to name this same prospective held prefix.
    ///
    /// # Errors
    ///
    /// Refuses substituted transaction bytes, prefix, inode or protected readback.
    pub fn require_append_subject(
        &self,
        reference: &ProtectedOriginalCutReferenceV5,
        subject: &SourceOriginalAppendSubjectV5,
    ) -> Result<(), SourceProviderSecurityError> {
        self.directory.validate_file(&reference.file)?;
        require_cut_subject(reference.file.exact(), subject.file_identity(),
            subject.transaction(), subject.prefix())
    }

    /// Requires a retained reference to name a real checksum-verified cut.
    ///
    /// # Errors
    ///
    /// Refuses foreign physical membership, prefix or changed protected bytes.
    pub fn require_physical_cut(
        &self,
        reference: &ProtectedOriginalCutReferenceV5,
        cut: &SourceOriginalPhysicalCutV5,
    ) -> Result<(), SourceProviderSecurityError> {
        self.directory.validate_file(&reference.file)?;
        require_cut_subject(reference.file.exact(), cut.file_identity(),
            (*cut.transaction_id(), *cut.transaction_digest()),
            (cut.frame_sequences().0, cut.file_offsets().0))
    }

    fn bound(&self, additional: usize) -> Result<(), SourceProviderSecurityError> {
        if self.retained.checked_add(additional).is_none_or(|bytes| bytes > MAXIMUM_LEDGER_GRAPH_BYTES) {
            return Err(SourceProviderSecurityError::format("configuration archive", "aggregate bound"));
        }
        Ok(())
    }

    fn retain(
        &mut self,
        kind: u8,
        identity: ObjectDigest,
        bytes: usize,
    ) -> Result<(), SourceProviderSecurityError> {
        if self.identities.contains(&(kind, identity)) {
            return Ok(());
        }
        self.bound(bytes)?;
        self.retained += bytes;
        self.identities.insert((kind, identity));
        Ok(())
    }
}

fn require_cut_subject(
    bytes: &[u8],
    identity: (u64, u64),
    transaction: ([u8; 16], [u8; 32]),
    prefix: (u64, u64),
) -> Result<(), SourceProviderSecurityError> {
    if u64_at(bytes, 16)? != identity.0 || u64_at(bytes, 24)? != identity.1
        || u64_at(bytes, 32)? != prefix.0 || u64_at(bytes, 40)? != prefix.1
        || bytes.get(48..64) != Some(transaction.0.as_slice())
        || bytes.get(64..96) != Some(transaction.1.as_slice())
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    Ok(())
}

// Return the same borrowed Vec used by the Source caller. Its three copied
// public capture parts still live in that caller through final revalidation.
fn deployment_parts(
    exact: &[u8],
    expected: ObjectDigest,
) -> Result<(ObjectDigest, ObjectDigest, Vec<&[u8]>), SourceProviderSecurityError> {
    require_header(exact, DEPLOYMENT_MAGIC, DEPLOYMENT_HEADER)?;
    if expected != identity(b"aos.source.original.deployment-image.v5\0", exact) {
        return Err(SourceProviderSecurityError::Currentness);
    }
    let configuration = digest_at(exact, 16)?;
    let limits = digest_at(exact, 48)?;
    let parts = sections(exact, DEPLOYMENT_HEADER, 80, 4)?;
    if parts[0].len() != crate::manifest::SOURCE_PROVIDER_SECURITY_MANIFEST_BYTES
        || parts[1].len() > crate::trust_file::MAXIMUM_SOURCE_PROVIDER_TRUST_FILE_BYTES
        || parts[2].len() != crate::route_file::SOURCE_PROVIDER_ROUTE_FILE_BYTES
        || parts[3].len() != crate::catalog::SIGNED_BYTES
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    Ok((configuration, limits, parts))
}

fn verify_archived_catalog(
    data: &ProviderConfigurationDataV5,
    bytes: &[u8],
) -> Result<VerifiedCatalogPublicationV1, SourceProviderSecurityError> {
    let mut verified = None;
    for key in data.historical_public_keys() {
        if let Ok(catalog) = crate::catalog::verify_retained_catalog_publication(data.trust_history(), key, bytes) {
            if verified.is_some() {
                return Err(SourceProviderSecurityError::Currentness);
            }
            verified = Some(catalog);
        }
    }
    verified.ok_or(SourceProviderSecurityError::Currentness)
}

fn header(magic: &[u8; 8]) -> Vec<u8> {
    let mut bytes = Vec::from(*magic);
    bytes.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    bytes
}

fn require_header(
    bytes: &[u8],
    magic: &[u8; 8],
    minimum: usize,
) -> Result<(), SourceProviderSecurityError> {
    if bytes.len() < minimum || bytes.get(..8) != Some(magic.as_slice())
        || bytes.get(8..16) != Some([0, 1, 0, 0, 0, 0, 0, 0].as_slice())
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    Ok(())
}

fn append_length(bytes: &mut Vec<u8>, length: usize) -> Result<(), SourceProviderSecurityError> {
    let length = u32::try_from(length).map_err(|_| SourceProviderSecurityError::Currentness)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

fn sections<'a>(
    bytes: &'a [u8],
    start: usize,
    lengths: usize,
    count: usize,
) -> Result<Vec<&'a [u8]>, SourceProviderSecurityError> {
    let mut offset = start;
    let mut parts = Vec::with_capacity(count);
    for index in 0..count {
        let length: [u8; 4] = bytes.get(lengths + index * 4..lengths + index * 4 + 4)
            .ok_or(SourceProviderSecurityError::Currentness)?.try_into().map_err(|_| SourceProviderSecurityError::Currentness)?;
        let end = offset.checked_add(u32::from_be_bytes(length) as usize).ok_or(SourceProviderSecurityError::Currentness)?;
        parts.push(bytes.get(offset..end).ok_or(SourceProviderSecurityError::Currentness)?);
        offset = end;
    }
    if offset != bytes.len() {
        return Err(SourceProviderSecurityError::Currentness);
    }
    Ok(parts)
}

fn digest_at(bytes: &[u8], offset: usize) -> Result<ObjectDigest, SourceProviderSecurityError> {
    let digest = bytes.get(offset..offset + 32).ok_or(SourceProviderSecurityError::Currentness)?
        .try_into().map_err(|_| SourceProviderSecurityError::Currentness)?;
    Ok(ObjectDigest::from_bytes(digest))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, SourceProviderSecurityError> {
    let value = bytes.get(offset..offset + 8).ok_or(SourceProviderSecurityError::Currentness)?
        .try_into().map_err(|_| SourceProviderSecurityError::Currentness)?;
    Ok(u64::from_be_bytes(value))
}

fn identity(domain: &[u8], bytes: &[u8]) -> ObjectDigest {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    ObjectDigest::from_bytes(hash.finalize().into())
}

fn filename(kind: u8, identity: ObjectDigest) -> String {
    crate::protected_files::archive_filename(kind, identity)
}

#[cfg(test)]
mod deployment_parts_tests {
    use super::*;

    fn structural_image() -> Vec<u8> {
        let lengths = [
            crate::manifest::SOURCE_PROVIDER_SECURITY_MANIFEST_BYTES,
            1,
            crate::route_file::SOURCE_PROVIDER_ROUTE_FILE_BYTES,
            crate::catalog::SIGNED_BYTES,
        ];
        let mut exact = header(DEPLOYMENT_MAGIC);
        exact.resize(80, 0);
        for length in lengths {
            append_length(&mut exact, length).unwrap();
        }
        exact.resize(DEPLOYMENT_HEADER + lengths.into_iter().sum::<usize>(), 0);
        exact
    }

    #[test]
    fn shared_parts_borrow_the_exact_structural_image() {
        let exact = structural_image();
        let digest = identity(b"aos.source.original.deployment-image.v5\0", &exact);

        let (_, _, parts) = deployment_parts(&exact, digest).unwrap();

        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0].as_ptr(), exact[DEPLOYMENT_HEADER..].as_ptr());
        assert_eq!(parts[3].len(), crate::catalog::SIGNED_BYTES);
        // Structural DATA intentionally does not invoke the signature/projector
        // engines or pretend that all-zero fields are a genuine public capture.
    }

    #[test]
    fn wrong_identity_reserved_bytes_and_extent_refuse_shared_parts() {
        let exact = structural_image();
        let digest = identity(b"aos.source.original.deployment-image.v5\0", &exact);
        assert!(deployment_parts(&exact, ObjectDigest::from_bytes([1; 32])).is_err());

        let mut reserved = exact.clone();
        reserved[10] = 1;
        assert!(deployment_parts(&reserved, identity(b"aos.source.original.deployment-image.v5\0", &reserved)).is_err());

        let mut trailing = exact.clone();
        trailing.push(0);
        assert!(deployment_parts(&trailing, identity(b"aos.source.original.deployment-image.v5\0", &trailing)).is_err());
        assert!(deployment_parts(&exact[..exact.len() - 1], digest).is_err());
    }
}

fn cut_filename(file: (u64, u64), transaction: [u8; 16], digest: [u8; 32]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"aos.source.original.cut-subject.v5\0");
    hash.update(file.0.to_be_bytes());
    hash.update(file.1.to_be_bytes());
    hash.update(transaction);
    hash.update(digest);
    filename(b'c', ObjectDigest::from_bytes(hash.finalize().into()))
}

#[cfg(test)]
mod tests;
