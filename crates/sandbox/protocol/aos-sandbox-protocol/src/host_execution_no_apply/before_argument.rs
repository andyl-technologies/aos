//! Encodes the closed V2 negative relation before an argument source exists.
//!
//! No original argument request, session or signed H/T coordinate is present
//! in this variant. All fields are comparison DATA; only the actual Host owner
//! can observe absent admission/dispatch under its protected lock and append
//! a durable future-Apply closure. Structural bytes cannot adopt that owner.
//!
//! ```text
//! AOSNAB02 | Create:16 | execution:16 | sandbox:16 | incarnation:16 |
//! node:16 | Host-boot:16 | assignment-epoch:u64be | generation:u64be |
//! accepted-public-request:32 | assignment:32 | checksum:32
//!
//! AOSHNB02 | AOSNAB02[216] | terminal-request:16 | terminal-session:32 |
//! signed-terminal-request:32 | runtime-handle:32 | execution-store:32 |
//! observed-preclose-cut:32 | observed-epoch:u64be | commit-sequence:u64be |
//! checksum:32
//! ```

use sha2::{Digest as _, Sha256};

use super::{HostExecutionNoApplyRecordErrorV1 as Error, HostExecutionNoApplyRecordV1, take};

const SOURCE_MAGIC: &[u8; 8] = b"AOSNAB02";
const SOURCE_DOMAIN: &[u8] = b"aos.sandbox.host.no-apply-before-argument-source.v2\0";
const RECORD_MAGIC: &[u8; 8] = b"AOSHNB02";
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.host.closed-before-argument-no-apply.v2\0";

/// Exact canonical length of the nonauthorizing accepted-Create source.
pub const BEFORE_ARGUMENT_NO_APPLY_SOURCE_BYTES_V2: usize = 216;

/// Exact canonical length of the closed-before-argument Host record.
pub const BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2: usize = 448;

/// Carries the accepted Create and its current assignment as comparison DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BeforeArgumentNoApplySourceFieldsV2 {
    /// Actual durable public Create operation identity.
    pub create_operation: [u8; 16],
    /// Execution identity selected by that accepted Create.
    pub execution: [u8; 16],
    /// Actual assignment sandbox.
    pub sandbox: [u8; 16],
    /// Actual assignment incarnation.
    pub incarnation: [u8; 16],
    /// Actual Host node.
    pub node: [u8; 16],
    /// Current Host kernel boot identity.
    pub host_boot: [u8; 16],
    /// Actual assignment epoch.
    pub assignment_epoch: u64,
    /// Actual desired-state generation.
    pub desired_generation: u64,
    /// Commitment to the exact accepted public Create request.
    pub accepted_request_digest: [u8; 32],
    /// Commitment to the current assignment manifest.
    pub assignment_digest: [u8; 32],
}

/// Retains structurally canonical accepted-Create DATA without argument fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BeforeArgumentNoApplySourceDataV2 {
    fields: BeforeArgumentNoApplySourceFieldsV2,
}

impl BeforeArgumentNoApplySourceDataV2 {
    /// Constructs comparison DATA, without authenticating accepted custody.
    ///
    /// # Errors
    /// Rejects zero identities, generations or commitments.
    pub fn new(fields: BeforeArgumentNoApplySourceFieldsV2) -> Result<Self, Error> {
        if [fields.create_operation, fields.execution, fields.sandbox, fields.incarnation,
            fields.node, fields.host_boot].contains(&[0; 16])
            || fields.assignment_epoch == 0 || fields.desired_generation == 0
            || fields.accepted_request_digest == [0; 32] || fields.assignment_digest == [0; 32]
        {
            return Err(Error::InvalidRecord);
        }
        Ok(Self { fields })
    }

    /// Returns the exact nonauthorizing source fields.
    pub const fn fields(self) -> BeforeArgumentNoApplySourceFieldsV2 { self.fields }

    /// Returns the exact domain-separated structural source commitment.
    ///
    /// This commitment is DATA; provenance requires its actual signed grant.
    pub fn digest(self) -> aos_sandbox_model::ObjectDigest {
        let encoded = self.encode_canonical();
        let mut digest = [0; 32];
        digest.copy_from_slice(&encoded[BEFORE_ARGUMENT_NO_APPLY_SOURCE_BYTES_V2 - 32..]);
        aos_sandbox_model::ObjectDigest::from_bytes(digest)
    }

    /// Encodes the exact source branch with its own version and checksum.
    pub fn encode_canonical(self) -> [u8; BEFORE_ARGUMENT_NO_APPLY_SOURCE_BYTES_V2] {
        let mut bytes = [0; BEFORE_ARGUMENT_NO_APPLY_SOURCE_BYTES_V2];
        bytes[..8].copy_from_slice(SOURCE_MAGIC);
        let mut cursor = 8;
        for field in [self.fields.create_operation, self.fields.execution, self.fields.sandbox,
            self.fields.incarnation, self.fields.node, self.fields.host_boot]
        {
            bytes[cursor..cursor + 16].copy_from_slice(&field);
            cursor += 16;
        }
        for field in [self.fields.assignment_epoch, self.fields.desired_generation] {
            bytes[cursor..cursor + 8].copy_from_slice(&field.to_be_bytes());
            cursor += 8;
        }
        for field in [self.fields.accepted_request_digest, self.fields.assignment_digest] {
            bytes[cursor..cursor + 32].copy_from_slice(&field);
            cursor += 32;
        }
        let checksum = Sha256::new().chain_update(SOURCE_DOMAIN)
            .chain_update(&bytes[..cursor]).finalize();
        bytes[cursor..].copy_from_slice(&checksum);
        bytes
    }

    /// Decodes only this exact canonical source branch.
    ///
    /// # Errors
    /// Rejects another version, wrong length, zero fields or changed checksum.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BEFORE_ARGUMENT_NO_APPLY_SOURCE_BYTES_V2
            || bytes.get(..8) != Some(SOURCE_MAGIC.as_slice())
        {
            return Err(Error::InvalidRecord);
        }
        let mut cursor = 8;
        let source = Self::new(BeforeArgumentNoApplySourceFieldsV2 {
            create_operation: take(bytes, &mut cursor)?,
            execution: take(bytes, &mut cursor)?,
            sandbox: take(bytes, &mut cursor)?,
            incarnation: take(bytes, &mut cursor)?,
            node: take(bytes, &mut cursor)?,
            host_boot: take(bytes, &mut cursor)?,
            assignment_epoch: u64::from_be_bytes(take(bytes, &mut cursor)?),
            desired_generation: u64::from_be_bytes(take(bytes, &mut cursor)?),
            accepted_request_digest: take(bytes, &mut cursor)?,
            assignment_digest: take(bytes, &mut cursor)?,
        })?;
        if source.encode_canonical().as_slice() != bytes { return Err(Error::InvalidRecord); }
        Ok(source)
    }
}

/// Names only actual terminal and protected Host closure coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedBeforeArgumentNoApplyRecordFieldsV2 {
    /// Structurally canonical accepted-Create source.
    pub source: BeforeArgumentNoApplySourceDataV2,
    /// Actual signed terminal request identity.
    pub terminal_request: [u8; 16],
    /// Actual authenticated terminal Session binding.
    pub terminal_session: [u8; 32],
    /// Digest of the actual signed terminal request.
    pub signed_terminal_request: [u8; 32],
    /// Current protected Host runtime handle.
    pub runtime_handle: [u8; 32],
    /// Actual protected execution-store identity.
    pub execution_store: [u8; 32],
    /// Actual protected cut observed while admission and dispatch are absent.
    pub observed_preclose_cut: [u8; 32],
    /// Actual protected execution-journal epoch before closing Apply.
    pub observed_epoch: u64,
    /// Actual sequence assigned to the durable closure append.
    pub commit_sequence: u64,
}

/// Retains a canonical closed-before-argument record as historical DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedBeforeArgumentNoApplyRecordV2 {
    fields: ClosedBeforeArgumentNoApplyRecordFieldsV2,
}

impl ClosedBeforeArgumentNoApplyRecordV2 {
    /// Constructs historical DATA without claiming the Host observed its fields.
    ///
    /// # Errors
    /// Rejects zero terminal/currentness coordinates or a nonadvancing sequence.
    pub fn new(fields: ClosedBeforeArgumentNoApplyRecordFieldsV2) -> Result<Self, Error> {
        if fields.terminal_request == [0; 16]
            || [fields.terminal_session, fields.signed_terminal_request, fields.runtime_handle,
                fields.execution_store, fields.observed_preclose_cut].contains(&[0; 32])
            || fields.observed_epoch == 0
            || fields.observed_epoch.checked_add(2) != Some(fields.commit_sequence)
        {
            return Err(Error::InvalidRecord);
        }
        Ok(Self { fields })
    }

    /// Returns the exact historical closure fields.
    pub const fn fields(self) -> ClosedBeforeArgumentNoApplyRecordFieldsV2 { self.fields }

    /// Encodes this distinct closed V2 variant without manufacturing H/T fields.
    pub fn encode_canonical(self) -> [u8; BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2] {
        let mut bytes = [0; BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2];
        bytes[..8].copy_from_slice(RECORD_MAGIC);
        bytes[8..224].copy_from_slice(&self.fields.source.encode_canonical());
        bytes[224..240].copy_from_slice(&self.fields.terminal_request);
        let mut cursor = 240;
        for field in [self.fields.terminal_session, self.fields.signed_terminal_request,
            self.fields.runtime_handle, self.fields.execution_store, self.fields.observed_preclose_cut]
        {
            bytes[cursor..cursor + 32].copy_from_slice(&field);
            cursor += 32;
        }
        for field in [self.fields.observed_epoch, self.fields.commit_sequence] {
            bytes[cursor..cursor + 8].copy_from_slice(&field.to_be_bytes());
            cursor += 8;
        }
        let checksum = Sha256::new().chain_update(RECORD_DOMAIN)
            .chain_update(&bytes[..cursor]).finalize();
        bytes[cursor..].copy_from_slice(&checksum);
        bytes
    }

    /// Decodes only the exact distinct closed-before-argument record.
    ///
    /// # Errors
    /// Rejects truncation, another variant, invalid source or changed checksum.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2
            || bytes.get(..8) != Some(RECORD_MAGIC.as_slice())
        {
            return Err(Error::InvalidRecord);
        }
        let source = BeforeArgumentNoApplySourceDataV2::decode_canonical(&bytes[8..224])?;
        let mut cursor = 224;
        let record = Self::new(ClosedBeforeArgumentNoApplyRecordFieldsV2 {
            source,
            terminal_request: take(bytes, &mut cursor)?,
            terminal_session: take(bytes, &mut cursor)?,
            signed_terminal_request: take(bytes, &mut cursor)?,
            runtime_handle: take(bytes, &mut cursor)?,
            execution_store: take(bytes, &mut cursor)?,
            observed_preclose_cut: take(bytes, &mut cursor)?,
            observed_epoch: u64::from_be_bytes(take(bytes, &mut cursor)?),
            commit_sequence: u64::from_be_bytes(take(bytes, &mut cursor)?),
        })?;
        if record.encode_canonical().as_slice() != bytes { return Err(Error::InvalidRecord); }
        Ok(record)
    }
}

/// Preserves literal argument-source markers beside the explicit closed variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostExecutionNoApplyRecordV2 {
    /// Preserves the complete existing original argument and H/T relation.
    AfterArgument(HostExecutionNoApplyRecordV1),
    /// Carries actual Host closure before an argument source exists.
    ClosedV2BeforeArgument(ClosedBeforeArgumentNoApplyRecordV2),
}

impl HostExecutionNoApplyRecordV2 {
    /// Decodes the exact closed union; legacy fields are never synthesized.
    ///
    /// # Errors
    /// Rejects unknown versions, noncanonical bytes or a malformed variant.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.get(..8) == Some(RECORD_MAGIC.as_slice()) {
            ClosedBeforeArgumentNoApplyRecordV2::decode_canonical(bytes).map(Self::ClosedV2BeforeArgument)
        } else {
            HostExecutionNoApplyRecordV1::decode_canonical(bytes).map(Self::AfterArgument)
        }
    }
}
