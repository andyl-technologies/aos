//! Protected immutable storage for namespace-inspector admission records.
//!
//! The authenticated broker publishes expected-attempt policy from its
//! dedicated staging root into an append-only final root. The namespace
//! inspector has lookup-only access to that final root and separately publishes
//! one-shot spent records through its own staging and final roots. These Rust
//! wrappers keep all four directory roles distinct; deployment MAC policy must
//! still enforce the corresponding process authority.
//!
//! ```text
//! expected final: aosni-expected-<64 lowercase hex nonce>
//! expected private: .aosni-expected-<64 lowercase hex nonce>
//! spent final: aosni-spent-<64 lowercase hex nonce>
//! spent private: .aosni-spent-<64 lowercase hex nonce>
//!
//! record:
//!   AOSNPS01 | version:u16 | role:u8 | reserved:u8 | total:u32
//!   role-body:variable | sha256(header || role-body):32
//! ```
//!
//! The terminal SHA-256 is canonical consistency framing, not record
//! authority. Authority requires trusted placement of the exact final root and
//! the deployment's independently enforced MAC policy.

use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;

use aos_sandbox_linux::immutable_file::{
    BeforeRenameFailure, FsVerityDigest, FsVerityPublicationRoot, ImmutableFileError,
    InvalidPublicationName, MaterializationCallbacks, MaterializationError,
    NoReplacePublicationError, ObserveSealedPublicationError, PublicationName,
    PublicationRootError, SealedReadOnlyCredential,
};
use sha2::{Digest as _, Sha256};

use super::{
    ExpectedInspectorAttemptV1, InspectorAttemptPolicyLookupV1, InspectorSpentNonceLedgerV1,
    MAXIMUM_REQUEST_BYTES, NetworkNamespaceInspectionRequestV1, NetworkNamespaceInspectorError,
};

const RECORD_MAGIC: &[u8; 8] = b"AOSNPS01";
const RECORD_VERSION: u16 = 1;
const RECORD_HEADER_BYTES: usize = 16;
const RECORD_DIGEST_BYTES: usize = 32;
const SPENT_BODY_BYTES: usize = 80;
const MAXIMUM_EXPECTED_RECORD_BYTES: usize =
    RECORD_HEADER_BYTES + MAXIMUM_REQUEST_BYTES + RECORD_DIGEST_BYTES;
const SPENT_RECORD_BYTES: usize = RECORD_HEADER_BYTES + SPENT_BODY_BYTES + RECORD_DIGEST_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordRole {
    Expected,
    Spent,
}

impl RecordRole {
    const fn code(self) -> u8 {
        match self {
            Self::Expected => 1,
            Self::Spent => 2,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Expected => "expected",
            Self::Spent => "spent",
        }
    }
}

/// Reports a malformed, mismatched, or unreadable protected record.
#[derive(Debug, thiserror::Error)]
pub(crate) enum InspectorProtectedStoreReadError {
    /// A deterministic record basename could not be represented.
    #[error("namespace-inspector protected record name is invalid")]
    Name(#[from] InvalidPublicationName),
    /// Descriptor-relative sealed-file observation failed.
    #[error("namespace-inspector protected record observation failed: {0}")]
    Observation(#[from] ObserveSealedPublicationError),
    /// Reading the already size-bounded sealed descriptor failed.
    #[error("namespace-inspector protected record read failed: {0}")]
    Read(#[source] std::io::Error),
    /// Canonical framing, role, nonce binding, or self-digest validation failed.
    #[error("namespace-inspector protected record is invalid: {0}")]
    Invalid(&'static str),
}

/// Reports inability to admit one configured protected-root topology.
#[derive(Debug, thiserror::Error)]
pub(crate) enum InspectorProtectedRootError {
    /// A retained directory failed the generic fs-verity root contract.
    #[error("namespace-inspector protected publication root is invalid: {0}")]
    Root(#[from] PublicationRootError),
    /// Two configured roles resolved to the same directory inode.
    #[error("namespace-inspector protected publication roles alias one directory")]
    RoleAlias,
    /// Broker and inspector views did not resolve to the same expected final directory.
    #[error("namespace-inspector expected-final directory views do not match")]
    ExpectedFinalMismatch,
    /// One rename pair does not reside on the same filesystem device.
    #[error("namespace-inspector protected staging and final roots cross filesystems")]
    CrossFilesystem,
}

/// Reports failure to publish one immutable protected record.
#[derive(Debug, thiserror::Error)]
pub(crate) enum InspectorProtectedStorePublishError<'root> {
    /// A deterministic record basename could not be represented.
    #[error("namespace-inspector protected record name is invalid")]
    Name(#[from] InvalidPublicationName),
    /// Creating the bounded, sealed read-only source failed.
    #[error("namespace-inspector protected record source failed: {0}")]
    Credential(#[from] ImmutableFileError),
    /// Duplicating the verified source's read-only description failed.
    #[error("namespace-inspector protected record source duplication failed: {0}")]
    SourceClone(#[source] std::io::Error),
    /// Private exact-mode materialization or content verification failed.
    #[error("namespace-inspector protected record materialization failed: {0}")]
    Materialization(#[from] MaterializationError<ExactRecordVerificationError>),
    /// No-replace publication failed and retained exact recovery evidence.
    #[error("namespace-inspector protected record publication failed: {0}")]
    Publication(NoReplacePublicationError<'root>),
    /// Opening and decoding the just-published final name failed.
    #[error("namespace-inspector protected record readback failed: {0}")]
    Readback(#[from] InspectorProtectedStoreReadError),
    /// Durable final readback did not equal the bytes and seal just published.
    #[error("namespace-inspector protected record durable readback mismatched")]
    ReadbackMismatch,
}

/// Reports failure to make or classify an inspector one-shot replay claim.
#[derive(Debug, thiserror::Error)]
pub(crate) enum InspectorSpentClaimError<'root> {
    /// Creating or publishing the new claim failed.
    #[error("{0}")]
    Publish(InspectorProtectedStorePublishError<'root>),
    /// An existing final name could not be read and validated.
    #[error("existing namespace-inspector spent record could not be validated: {source}")]
    ExistingUnreadable {
        /// Exact no-replace conflict, including the retained private inode.
        publication: NoReplacePublicationError<'root>,
        /// Final-record lookup failure.
        #[source]
        source: InspectorProtectedStoreReadError,
    },
    /// The final name existed but did not bind the same complete attempt.
    #[error("existing namespace-inspector spent record mismatched the attempted claim")]
    ExistingMismatch {
        /// Exact no-replace conflict, including the retained private inode.
        publication: NoReplacePublicationError<'root>,
    },
}

impl<'root> From<NoReplacePublicationError<'root>> for InspectorProtectedStorePublishError<'root> {
    fn from(error: NoReplacePublicationError<'root>) -> Self {
        Self::Publication(error)
    }
}

impl<'root> From<InspectorProtectedStorePublishError<'root>> for InspectorSpentClaimError<'root> {
    fn from(error: InspectorProtectedStorePublishError<'root>) -> Self {
        Self::Publish(error)
    }
}

/// Owns the broker-only expected-policy staging directory.
#[derive(Debug)]
pub(crate) struct BrokerExpectedStagingRoot(FsVerityPublicationRoot);

/// Owns the append-only expected-policy final directory used by the broker.
#[derive(Debug)]
pub(crate) struct BrokerExpectedFinalRoot(FsVerityPublicationRoot);

/// Owns the inspector's read-only view of expected-policy final records.
#[derive(Debug)]
pub(crate) struct InspectorExpectedFinalRoot(FsVerityPublicationRoot);

/// Owns the inspector-only spent-record staging directory.
#[derive(Debug)]
pub(crate) struct InspectorSpentStagingRoot(FsVerityPublicationRoot);

/// Owns the append-only spent-record final directory used by the inspector.
#[derive(Debug)]
pub(crate) struct InspectorSpentFinalRoot(FsVerityPublicationRoot);

/// Publishes broker-authenticated expected-attempt policy exactly once.
#[derive(Debug)]
pub(crate) struct BrokerExpectedAttemptPublisher {
    staging: BrokerExpectedStagingRoot,
    final_root: BrokerExpectedFinalRoot,
}

impl BrokerExpectedAttemptPublisher {
    /// Publishes and exactly reads back one canonical expected-attempt record.
    ///
    /// # Errors
    ///
    /// Returns an error without cleanup or adoption when encoding, sealed
    /// materialization, no-replace publication, or exact final readback fails.
    pub(crate) fn publish<'root>(
        &'root self,
        expected: &ExpectedInspectorAttemptV1,
    ) -> Result<ExpectedInspectorAttemptV1, InspectorProtectedStorePublishError<'root>> {
        let bytes = encode_expected_record(expected)?;
        let names = record_names(RecordRole::Expected, expected.nonce)?;
        let credential = sealed_source("aosni-expected-policy", &bytes)?;
        let mut verifier = ExactRecordVerifier::new(&bytes);

        let sealed = self.staging.0.materialize_and_seal_exact_mode(
            credential
                .as_fd()
                .try_clone_to_owned()
                .map_err(InspectorProtectedStorePublishError::SourceClone)?,
            names.private,
            u64::try_from(MAXIMUM_EXPECTED_RECORD_BYTES)
                .map_err(|_| InspectorProtectedStoreReadError::Invalid("size limit overflowed"))?,
            &mut verifier,
        )?;
        let created_verity = sealed.verity_digest();
        sealed.publish_noreplace_into(&self.final_root.0, names.final_name.clone())?;

        let (readback, observed_verity) = read_expected(&self.final_root.0, &names.final_name)?
            .ok_or(InspectorProtectedStoreReadError::Invalid(
                "published expected record disappeared",
            ))?;
        if readback != *expected || observed_verity != created_verity {
            return Err(InspectorProtectedStorePublishError::ReadbackMismatch);
        }
        Ok(readback)
    }
}

/// Owns the inspector's only protected-store capabilities.
///
/// Construction exposes expected policy only through [`InspectorExpectedAttemptReader`]
/// and spent mutation only through [`InspectorSpentNoncePublisher`]. It does
/// not construct a broker expected-policy publisher.
#[derive(Debug)]
pub(crate) struct InspectorProtectedStoreAccess {
    expected: InspectorExpectedAttemptReader,
    spent: InspectorSpentNoncePublisher,
}

impl InspectorProtectedStoreAccess {
    /// Borrows the inspector's expected-policy lookup-only capability.
    pub(crate) const fn expected(&self) -> &InspectorExpectedAttemptReader {
        &self.expected
    }

    /// Borrows the inspector's spent-ledger publication capability.
    pub(crate) const fn spent(&self) -> &InspectorSpentNoncePublisher {
        &self.spent
    }
}

/// Owns the globally admitted four-directory protected-store topology.
///
/// This is a provisioning boundary, not a runtime role. It validates both
/// separately opened views of the expected final directory, all four physical
/// role identities, and the device preconditions for each rename pair before
/// producing disjoint broker and inspector capability objects. Trusted
/// path-to-role placement and enforcing MAC remain external prerequisites.
#[derive(Debug)]
pub(crate) struct ProvisionedInspectorProtectedStores {
    broker: BrokerExpectedAttemptPublisher,
    inspector: InspectorProtectedStoreAccess,
}

impl ProvisionedInspectorProtectedStores {
    /// Admits the complete configured root tuple and constructs disjoint roles.
    ///
    /// `broker_expected_final` and `inspector_expected_final` must be separate
    /// descriptions of the same directory. Same-device validation is only an
    /// early rename precondition; the later `renameat2` result remains the
    /// authoritative mount-compatibility check.
    ///
    /// # Errors
    ///
    /// Returns an error when any generic root admission fails, the expected
    /// final views differ, physical roles alias, or either rename pair has
    /// different device identities.
    pub(crate) fn from_owned(
        expected_staging: OwnedFd,
        broker_expected_final: OwnedFd,
        inspector_expected_final: OwnedFd,
        spent_staging: OwnedFd,
        spent_final: OwnedFd,
    ) -> Result<Self, InspectorProtectedRootError> {
        let expected_staging = BrokerExpectedStagingRoot(admit_root(expected_staging)?);
        let broker_expected_final = BrokerExpectedFinalRoot(admit_root(broker_expected_final)?);
        let inspector_expected_final =
            InspectorExpectedFinalRoot(admit_root(inspector_expected_final)?);
        let spent_staging = InspectorSpentStagingRoot(admit_root(spent_staging)?);
        let spent_final = InspectorSpentFinalRoot(admit_root(spent_final)?);

        validate_root_topology([
            root_identity(&expected_staging.0),
            root_identity(&broker_expected_final.0),
            root_identity(&inspector_expected_final.0),
            root_identity(&spent_staging.0),
            root_identity(&spent_final.0),
        ])?;

        Ok(Self {
            broker: BrokerExpectedAttemptPublisher {
                staging: expected_staging,
                final_root: broker_expected_final,
            },
            inspector: InspectorProtectedStoreAccess {
                expected: InspectorExpectedAttemptReader {
                    final_root: inspector_expected_final,
                },
                spent: InspectorSpentNoncePublisher {
                    staging: spent_staging,
                    final_root: spent_final,
                },
            },
        })
    }

    /// Separates the broker publisher from the inspector's lookup/claim access.
    pub(crate) fn into_roles(
        self,
    ) -> (
        BrokerExpectedAttemptPublisher,
        InspectorProtectedStoreAccess,
    ) {
        (self.broker, self.inspector)
    }
}

/// Looks up only broker-published expected-attempt final records.
#[derive(Debug)]
pub(crate) struct InspectorExpectedAttemptReader {
    final_root: InspectorExpectedFinalRoot,
}

impl InspectorExpectedAttemptReader {
    /// Returns an owned canonical expected attempt, exact absence, or an error.
    ///
    /// # Errors
    ///
    /// Returns an error for every name-open failure other than exact initial
    /// absence, or when sealed observation, reading, canonical decoding,
    /// self-digest validation, or nonce/name binding fails.
    pub(crate) fn lookup(
        &self,
        nonce: &[u8; 32],
    ) -> Result<Option<ExpectedInspectorAttemptV1>, InspectorProtectedStoreReadError> {
        let names = record_names(RecordRole::Expected, *nonce)?;
        let Some((expected, _verity)) = read_expected(&self.final_root.0, &names.final_name)?
        else {
            return Ok(None);
        };
        if expected.nonce != *nonce {
            return Err(InspectorProtectedStoreReadError::Invalid(
                "expected record nonce differs from its final name",
            ));
        }
        Ok(Some(expected))
    }
}

impl InspectorAttemptPolicyLookupV1 for InspectorExpectedAttemptReader {
    fn lookup(
        &self,
        nonce: &[u8; 32],
    ) -> Result<Option<ExpectedInspectorAttemptV1>, NetworkNamespaceInspectorError> {
        InspectorExpectedAttemptReader::lookup(self, nonce)
            .map_err(|_| NetworkNamespaceInspectorError::ProtectedPolicy)
    }
}

/// Publishes and classifies inspector-owned one-shot spent-nonce records.
#[derive(Debug)]
pub(crate) struct InspectorSpentNoncePublisher {
    staging: InspectorSpentStagingRoot,
    final_root: InspectorSpentFinalRoot,
}

impl InspectorSpentNoncePublisher {
    /// Claims the complete expected attempt once using durable no-replace publication.
    ///
    /// An exact existing record returns `false`. A mismatched existing record is
    /// corruption, while every non-`EEXIST` rename outcome remains ambiguous.
    ///
    /// # Errors
    ///
    /// Returns an error without cleanup or adoption when encoding,
    /// materialization, publication, final readback, or exact existing-record
    /// classification fails.
    pub(crate) fn claim_once<'root>(
        &'root self,
        expected: &ExpectedInspectorAttemptV1,
    ) -> Result<bool, InspectorSpentClaimError<'root>> {
        let spent = SpentRecord::from_expected(expected);
        let bytes =
            encode_spent_record(spent).map_err(InspectorProtectedStorePublishError::from)?;
        let names = record_names(RecordRole::Spent, expected.nonce)
            .map_err(InspectorProtectedStorePublishError::from)?;
        let credential = sealed_source("aosni-spent-nonce", &bytes)
            .map_err(InspectorProtectedStorePublishError::from)?;
        let mut verifier = ExactRecordVerifier::new(&bytes);

        let source = credential
            .as_fd()
            .try_clone_to_owned()
            .map_err(InspectorProtectedStorePublishError::SourceClone)?;
        let maximum_bytes = u64::try_from(SPENT_RECORD_BYTES).map_err(|_| {
            InspectorProtectedStorePublishError::Readback(
                InspectorProtectedStoreReadError::Invalid("size limit overflowed"),
            )
        })?;
        let sealed = self
            .staging
            .0
            .materialize_and_seal_exact_mode(source, names.private, maximum_bytes, &mut verifier)
            .map_err(InspectorProtectedStorePublishError::from)?;
        let created_verity = sealed.verity_digest();
        match sealed.publish_noreplace_into(&self.final_root.0, names.final_name.clone()) {
            Ok(_) => {
                let (readback, observed_verity) = read_spent(&self.final_root.0, &names.final_name)
                    .map_err(InspectorProtectedStorePublishError::from)?
                    .ok_or(InspectorProtectedStoreReadError::Invalid(
                        "published spent record disappeared",
                    ))
                    .map_err(InspectorProtectedStorePublishError::from)?;
                if readback != spent || observed_verity != created_verity {
                    return Err(InspectorProtectedStorePublishError::ReadbackMismatch.into());
                }
                Ok(true)
            }
            Err(publication) if destination_exists(&publication) => {
                let existing = match read_spent(&self.final_root.0, &names.final_name) {
                    Ok(existing) => existing,
                    Err(source) => {
                        return Err(InspectorSpentClaimError::ExistingUnreadable {
                            publication,
                            source,
                        });
                    }
                };
                match existing {
                    Some((existing, _verity)) if existing == spent => Ok(false),
                    _ => Err(InspectorSpentClaimError::ExistingMismatch { publication }),
                }
            }
            Err(error) => Err(InspectorProtectedStorePublishError::Publication(error).into()),
        }
    }
}

impl InspectorSpentNonceLedgerV1 for InspectorSpentNoncePublisher {
    type Error<'ledger> = InspectorSpentClaimError<'ledger>;

    fn claim_once<'ledger>(
        &'ledger mut self,
        expected: &ExpectedInspectorAttemptV1,
    ) -> Result<bool, Self::Error<'ledger>> {
        InspectorSpentNoncePublisher::claim_once(self, expected)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SpentRecord {
    nonce: [u8; 32],
    boot_id: [u8; 16],
    policy_digest: [u8; 32],
}

impl SpentRecord {
    fn from_expected(expected: &ExpectedInspectorAttemptV1) -> Self {
        Self {
            nonce: expected.nonce,
            boot_id: expected.boot_id,
            policy_digest: *expected.policy_digest.as_bytes(),
        }
    }
}

struct RecordNames {
    private: PublicationName,
    final_name: PublicationName,
}

fn admit_root(directory: OwnedFd) -> Result<FsVerityPublicationRoot, InspectorProtectedRootError> {
    Ok(FsVerityPublicationRoot::from_owned(directory)?)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootIdentity {
    device: u64,
    inode: u64,
}

fn root_identity(root: &FsVerityPublicationRoot) -> RootIdentity {
    RootIdentity {
        device: root.device(),
        inode: root.inode(),
    }
}

fn validate_root_topology(roots: [RootIdentity; 5]) -> Result<(), InspectorProtectedRootError> {
    let [
        expected_staging,
        broker_expected_final,
        inspector_expected_final,
        spent_staging,
        spent_final,
    ] = roots;
    if broker_expected_final != inspector_expected_final {
        return Err(InspectorProtectedRootError::ExpectedFinalMismatch);
    }

    let physical_roots = [
        expected_staging,
        broker_expected_final,
        spent_staging,
        spent_final,
    ];
    for (index, root) in physical_roots.iter().enumerate() {
        for other in &physical_roots[index + 1..] {
            if root == other {
                return Err(InspectorProtectedRootError::RoleAlias);
            }
        }
    }

    if expected_staging.device != broker_expected_final.device
        || spent_staging.device != spent_final.device
    {
        return Err(InspectorProtectedRootError::CrossFilesystem);
    }
    Ok(())
}

fn record_names(role: RecordRole, nonce: [u8; 32]) -> Result<RecordNames, InvalidPublicationName> {
    let nonce = encode_hex(nonce);
    Ok(RecordNames {
        private: PublicationName::new(std::ffi::OsStr::from_bytes(
            format!(".aosni-{}-{nonce}", role.label()).as_bytes(),
        ))?,
        final_name: PublicationName::new(std::ffi::OsStr::from_bytes(
            format!("aosni-{}-{nonce}", role.label()).as_bytes(),
        ))?,
    })
}

fn encode_hex(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn encode_expected_record(
    expected: &ExpectedInspectorAttemptV1,
) -> Result<Vec<u8>, InspectorProtectedStoreReadError> {
    if expected.policy_digest
        != expected.compute_digest().map_err(|_| {
            InspectorProtectedStoreReadError::Invalid("expected policy digest is invalid")
        })?
    {
        return Err(InspectorProtectedStoreReadError::Invalid(
            "expected policy digest does not match its canonical fields",
        ));
    }
    let body = NetworkNamespaceInspectionRequestV1::from_expected(expected)
        .encode()
        .map_err(|_| InspectorProtectedStoreReadError::Invalid("expected policy is invalid"))?;
    encode_record(RecordRole::Expected, &body, MAXIMUM_EXPECTED_RECORD_BYTES)
}

fn decode_expected_record(
    bytes: &[u8],
) -> Result<ExpectedInspectorAttemptV1, InspectorProtectedStoreReadError> {
    let body = decode_record(bytes, RecordRole::Expected, MAXIMUM_EXPECTED_RECORD_BYTES)?;
    let expected = NetworkNamespaceInspectionRequestV1::decode(body)
        .map_err(|_| InspectorProtectedStoreReadError::Invalid("expected policy is invalid"))?
        .expected;
    if expected.policy_digest
        != expected.compute_digest().map_err(|_| {
            InspectorProtectedStoreReadError::Invalid("expected policy digest is invalid")
        })?
        || encode_expected_record(&expected)?.as_slice() != bytes
    {
        return Err(InspectorProtectedStoreReadError::Invalid(
            "expected policy is not canonical",
        ));
    }
    Ok(expected)
}

fn encode_spent_record(spent: SpentRecord) -> Result<Vec<u8>, InspectorProtectedStoreReadError> {
    let mut body = Vec::with_capacity(SPENT_BODY_BYTES);
    body.extend_from_slice(&spent.nonce);
    body.extend_from_slice(&spent.boot_id);
    body.extend_from_slice(&spent.policy_digest);
    encode_record(RecordRole::Spent, &body, SPENT_RECORD_BYTES)
}

fn decode_spent_record(bytes: &[u8]) -> Result<SpentRecord, InspectorProtectedStoreReadError> {
    let body = decode_record(bytes, RecordRole::Spent, SPENT_RECORD_BYTES)?;
    if body.len() != SPENT_BODY_BYTES {
        return Err(InspectorProtectedStoreReadError::Invalid(
            "spent record length is invalid",
        ));
    }
    let spent = SpentRecord {
        nonce: copy_array(&body[..32])?,
        boot_id: copy_array(&body[32..48])?,
        policy_digest: copy_array(&body[48..80])?,
    };
    if spent.nonce == [0; 32]
        || spent.boot_id == [0; 16]
        || spent.policy_digest == [0; 32]
        || encode_spent_record(spent)?.as_slice() != bytes
    {
        return Err(InspectorProtectedStoreReadError::Invalid(
            "spent record identity is invalid",
        ));
    }
    Ok(spent)
}

fn encode_record(
    role: RecordRole,
    body: &[u8],
    maximum_bytes: usize,
) -> Result<Vec<u8>, InspectorProtectedStoreReadError> {
    let total = RECORD_HEADER_BYTES
        .checked_add(body.len())
        .and_then(|bytes| bytes.checked_add(RECORD_DIGEST_BYTES))
        .ok_or(InspectorProtectedStoreReadError::Invalid(
            "protected record length overflowed",
        ))?;
    let total_u32 = u32::try_from(total)
        .map_err(|_| InspectorProtectedStoreReadError::Invalid("protected record is oversized"))?;
    if total > maximum_bytes {
        return Err(InspectorProtectedStoreReadError::Invalid(
            "protected record is oversized",
        ));
    }

    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(RECORD_MAGIC);
    bytes.extend_from_slice(&RECORD_VERSION.to_be_bytes());
    bytes.push(role.code());
    bytes.push(0);
    bytes.extend_from_slice(&total_u32.to_be_bytes());
    bytes.extend_from_slice(body);
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

fn decode_record(
    bytes: &[u8],
    role: RecordRole,
    maximum_bytes: usize,
) -> Result<&[u8], InspectorProtectedStoreReadError> {
    if bytes.len() < RECORD_HEADER_BYTES + RECORD_DIGEST_BYTES
        || bytes.len() > maximum_bytes
        || bytes.get(..8) != Some(RECORD_MAGIC.as_slice())
        || bytes.get(8..10) != Some(RECORD_VERSION.to_be_bytes().as_slice())
        || bytes.get(10) != Some(&role.code())
        || bytes.get(11) != Some(&0)
        || bytes.get(12..16)
            != Some(
                u32::try_from(bytes.len())
                    .map_err(|_| {
                        InspectorProtectedStoreReadError::Invalid("protected record is oversized")
                    })?
                    .to_be_bytes()
                    .as_slice(),
            )
    {
        return Err(InspectorProtectedStoreReadError::Invalid(
            "protected record framing or role is invalid",
        ));
    }
    let body_end = bytes.len() - RECORD_DIGEST_BYTES;
    let expected_digest: [u8; 32] = Sha256::digest(&bytes[..body_end]).into();
    if bytes[body_end..] != expected_digest {
        return Err(InspectorProtectedStoreReadError::Invalid(
            "protected record self-digest mismatched",
        ));
    }
    Ok(&bytes[RECORD_HEADER_BYTES..body_end])
}

fn sealed_source(name: &str, bytes: &[u8]) -> Result<SealedReadOnlyCredential, ImmutableFileError> {
    SealedReadOnlyCredential::create(name, bytes, bytes.len())
}

fn read_expected(
    root: &FsVerityPublicationRoot,
    name: &PublicationName,
) -> Result<Option<(ExpectedInspectorAttemptV1, FsVerityDigest)>, InspectorProtectedStoreReadError>
{
    let Some((bytes, verity)) = read_record(root, name, MAXIMUM_EXPECTED_RECORD_BYTES)? else {
        return Ok(None);
    };
    Ok(Some((decode_expected_record(&bytes)?, verity)))
}

fn read_spent(
    root: &FsVerityPublicationRoot,
    name: &PublicationName,
) -> Result<Option<(SpentRecord, FsVerityDigest)>, InspectorProtectedStoreReadError> {
    let Some((bytes, verity)) = read_record(root, name, SPENT_RECORD_BYTES)? else {
        return Ok(None);
    };
    Ok(Some((decode_spent_record(&bytes)?, verity)))
}

fn read_record(
    root: &FsVerityPublicationRoot,
    name: &PublicationName,
    maximum_bytes: usize,
) -> Result<Option<(Vec<u8>, FsVerityDigest)>, InspectorProtectedStoreReadError> {
    let maximum_bytes = u64::try_from(maximum_bytes).map_err(|_| {
        InspectorProtectedStoreReadError::Invalid("protected record size limit does not fit u64")
    })?;
    let Some(observed) = root.open_named_sealed(name, maximum_bytes)? else {
        return Ok(None);
    };
    let capacity = usize::try_from(observed.bytes()).map_err(|_| {
        InspectorProtectedStoreReadError::Invalid("protected record size does not fit memory")
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    File::from(
        observed
            .as_fd()
            .try_clone_to_owned()
            .map_err(InspectorProtectedStoreReadError::Read)?,
    )
    .read_to_end(&mut bytes)
    .map_err(InspectorProtectedStoreReadError::Read)?;
    if u64::try_from(bytes.len()).map_err(|_| {
        InspectorProtectedStoreReadError::Invalid("protected record size does not fit u64")
    })? != observed.bytes()
    {
        return Err(InspectorProtectedStoreReadError::Invalid(
            "protected record short read",
        ));
    }
    Ok(Some((bytes, observed.observed_verity_digest())))
}

fn destination_exists(error: &NoReplacePublicationError<'_>) -> bool {
    matches!(
        error,
        NoReplacePublicationError::BeforeRename {
            failure: BeforeRenameFailure::DestinationExists,
            ..
        }
    )
}

/// Reports an exact-byte mismatch while materializing a protected record.
#[derive(Debug, thiserror::Error)]
#[error("materialized protected record bytes did not match the canonical source")]
pub(crate) struct ExactRecordVerificationError;

struct ExactRecordVerifier<'bytes> {
    expected: &'bytes [u8],
    offset: usize,
}

impl<'bytes> ExactRecordVerifier<'bytes> {
    const fn new(expected: &'bytes [u8]) -> Self {
        Self {
            expected,
            offset: 0,
        }
    }
}

impl MaterializationCallbacks for ExactRecordVerifier<'_> {
    type Error = ExactRecordVerificationError;

    fn checkpoint(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn verify_chunk(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        let end = self
            .offset
            .checked_add(bytes.len())
            .ok_or(ExactRecordVerificationError)?;
        if self.expected.get(self.offset..end) != Some(bytes) {
            return Err(ExactRecordVerificationError);
        }
        self.offset = end;
        Ok(())
    }

    fn finish_verification(&mut self) -> Result<(), Self::Error> {
        if self.offset != self.expected.len() {
            return Err(ExactRecordVerificationError);
        }
        Ok(())
    }
}

fn copy_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], InspectorProtectedStoreReadError> {
    bytes.try_into().map_err(|_| {
        InspectorProtectedStoreReadError::Invalid("protected record field is truncated")
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::namespace_inspector::tests::pending;

    fn identity(device: u64, inode: u64) -> RootIdentity {
        RootIdentity { device, inode }
    }

    fn topology(physical: [RootIdentity; 4]) -> [RootIdentity; 5] {
        [
            physical[0],
            physical[1],
            physical[1],
            physical[2],
            physical[3],
        ]
    }

    fn valid_physical_roots() -> [RootIdentity; 4] {
        [
            identity(10, 1),
            identity(10, 2),
            identity(20, 3),
            identity(20, 4),
        ]
    }

    #[test]
    fn complete_topology_accepts_four_distinct_roots_and_matching_final_views() {
        assert!(validate_root_topology(topology(valid_physical_roots())).is_ok());
    }

    #[test]
    fn spent_publisher_implements_the_lifetime_preserving_ledger_contract() {
        fn assert_ledger<Ledger: InspectorSpentNonceLedgerV1>() {}

        assert_ledger::<InspectorSpentNoncePublisher>();
    }

    #[test]
    fn every_physical_role_alias_fails_global_topology_admission() {
        for first in 0..4 {
            for second in first + 1..4 {
                let mut roots = valid_physical_roots();
                roots[second] = roots[first];
                assert!(matches!(
                    validate_root_topology(topology(roots)),
                    Err(InspectorProtectedRootError::RoleAlias)
                ));
            }
        }
    }

    #[test]
    fn expected_final_views_and_each_rename_device_pair_are_exact() {
        let mut mismatched_view = topology(valid_physical_roots());
        mismatched_view[2] = identity(10, 9);
        assert!(matches!(
            validate_root_topology(mismatched_view),
            Err(InspectorProtectedRootError::ExpectedFinalMismatch)
        ));

        for changed_index in [0, 4] {
            let mut wrong_device = topology(valid_physical_roots());
            wrong_device[changed_index].device += 1;
            assert!(matches!(
                validate_root_topology(wrong_device),
                Err(InspectorProtectedRootError::CrossFilesystem)
            ));
        }
    }

    #[test]
    fn expected_record_round_trips_and_rejects_every_role_or_digest_change() {
        let expected = pending(0x31).expected;
        let bytes = encode_expected_record(&expected).unwrap();
        assert_eq!(decode_expected_record(&bytes).unwrap(), expected);

        let mut wrong_role = bytes.clone();
        wrong_role[10] = RecordRole::Spent.code();
        assert!(decode_expected_record(&wrong_role).is_err());

        for offset in [0, 8, 10, 11, 12, RECORD_HEADER_BYTES, bytes.len() - 1] {
            let mut changed = bytes.clone();
            changed[offset] ^= 0x80;
            assert!(decode_expected_record(&changed).is_err());
        }
    }

    #[test]
    fn spent_record_binds_nonce_boot_and_policy_and_rejects_expected_role() {
        let expected = pending(0x42).expected;
        let spent = SpentRecord::from_expected(&expected);
        let bytes = encode_spent_record(spent).unwrap();
        assert_eq!(decode_spent_record(&bytes).unwrap(), spent);
        assert!(decode_expected_record(&bytes).is_err());

        for offset in [RECORD_HEADER_BYTES, 48, 64, bytes.len() - 1] {
            let mut changed = bytes.clone();
            changed[offset] ^= 0x01;
            assert!(decode_spent_record(&changed).is_err());
        }
    }

    #[test]
    fn names_are_exact_role_and_nonce_bound_ordinaries() {
        let expected = record_names(RecordRole::Expected, [0xab; 32]).unwrap();
        let spent = record_names(RecordRole::Spent, [0xab; 32]).unwrap();
        assert_eq!(
            expected.private.as_os_str().as_bytes(),
            b".aosni-expected-abababababababababababababababababababababababababababababababab"
        );
        assert_eq!(
            expected.final_name.as_os_str().as_bytes(),
            b"aosni-expected-abababababababababababababababababababababababababababababababab"
        );
        assert_ne!(expected.private, spent.private);
        assert_ne!(expected.final_name, spent.final_name);
    }

    #[test]
    fn exact_verifier_rejects_substitution_truncation_and_extension() {
        let expected = b"canonical record";
        let mut exact = ExactRecordVerifier::new(expected);
        exact.verify_chunk(&expected[..4]).unwrap();
        exact.verify_chunk(&expected[4..]).unwrap();
        exact.finish_verification().unwrap();

        let mut substituted = ExactRecordVerifier::new(expected);
        assert!(substituted.verify_chunk(b"wrong").is_err());

        let mut truncated = ExactRecordVerifier::new(expected);
        truncated.verify_chunk(&expected[..4]).unwrap();
        assert!(truncated.finish_verification().is_err());

        let mut extended = ExactRecordVerifier::new(expected);
        assert!(extended.verify_chunk(b"canonical record!").is_err());
    }
}
