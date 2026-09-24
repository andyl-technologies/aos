//! Fail-closed OpenZFS readback contract for dedicated execution capture.
//!
//! A future dedicated Storage worker must run these exact bounded commands
//! with pinned AOS `zpool` and `zfs` executables and preserve their provenance.
//! Parsing command output alone is not physical authority: this source-only
//! contract neither dispatches a worker nor authorizes Host capture.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::{CaptureDatasetRequirementV1, VerifiedCaptureDatasetV1};
use crate::execution_capture_writer::UnboundCaptureWriteResultV1;
use crate::execution_output::ProtectedRetainedCaptureV1;

const OBSERVATION_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-zfs-readback.v1\0";
const PREFLIGHT_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-zfs-preflight.v1\0";
const CREATE_COMMAND_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-zfs-create-command.v1\0";
pub(crate) const MAXIMUM_MACHINE_OUTPUT_BYTES: usize = 4096;

/// Identifies the immutable OpenZFS program required by a readback command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CaptureZfsToolV1 {
    Zpool,
    Zfs,
}

/// Carries one exact argument vector; no shell or caller-chosen argv is used.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CaptureZfsReadbackCommandV1 {
    pub(crate) tool: CaptureZfsToolV1,
    pub(crate) arguments: Vec<String>,
}

/// Rejects stale identity, a checkpoint, inadequate headroom, or malformed output.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum CaptureZfsReadbackErrorV1 {
    /// The protected logical claim or measured headroom policy does not match.
    #[error("capture readback requirement does not match protected custody")]
    InvalidRequirement,
    /// Machine output was truncated, malformed, or substituted.
    #[error("capture ZFS machine readback is invalid")]
    InvalidOutput,
    /// The pool has a checkpoint, is unhealthy, or lacks its protected floor.
    #[error("capture pool is not available without a checkpoint")]
    PoolUnavailable,
    /// The exact root or capture dataset does not have the required properties.
    #[error("capture dataset does not match protected ZFS identity and space policy")]
    DatasetMismatch,
}

/// Fixes the checkpoint and capacity probes before a dedicated ZFS create.
///
/// The effect worker must run these probes under the same protected attempt
/// that will issue `zfs create`. Successful parsing is only preflight evidence:
/// ZFS must still atomically admit the exact reservation and a later catalog
/// observation must prove the create operation and dataset GUID.
pub(crate) struct CaptureZfsPreflightPlanV1 {
    requirement: CaptureDatasetRequirementV1,
    record_digest: ObjectDigest,
    minimum_remaining_bytes: u64,
    commands: [CaptureZfsReadbackCommandV1; 2],
}

impl CaptureZfsPreflightPlanV1 {
    pub(crate) fn new(
        requirement: &CaptureDatasetRequirementV1,
        retained: &ProtectedRetainedCaptureV1,
        metadata_headroom_bytes: u64,
        minimum_remaining_bytes: u64,
    ) -> Result<Self, CaptureZfsReadbackErrorV1> {
        if !retained.matches_capture_requirement(
            *requirement.execution.as_bytes(),
            *requirement.create_operation.as_bytes(),
            requirement.claim_digest,
            requirement.admitted_bytes,
        ) || retained
            .maximum_stdout_bytes()
            .checked_add(retained.maximum_stderr_bytes())
            != Some(requirement.admitted_bytes)
            || metadata_headroom_bytes == 0
            || minimum_remaining_bytes == 0
            || requirement
                .allocation_bytes
                .checked_sub(requirement.admitted_bytes)
                .is_none_or(|remaining| remaining < metadata_headroom_bytes)
            || requirement
                .allocation_bytes
                .checked_add(minimum_remaining_bytes)
                .is_none()
        {
            return Err(CaptureZfsReadbackErrorV1::InvalidRequirement);
        }

        let commands = [
            CaptureZfsReadbackCommandV1 {
                tool: CaptureZfsToolV1::Zpool,
                arguments: [
                    "list",
                    "-H",
                    "-p",
                    "-o",
                    "name,checkpoint,available,health",
                    requirement.root.pool(),
                ]
                .map(str::to_owned)
                .to_vec(),
            },
            CaptureZfsReadbackCommandV1 {
                tool: CaptureZfsToolV1::Zfs,
                arguments: [
                    "list",
                    "-H",
                    "-p",
                    "-o",
                    "name,type,guid,available",
                    requirement.root.dataset_prefix(),
                ]
                .map(str::to_owned)
                .to_vec(),
            },
        ];

        Ok(Self {
            requirement: requirement.clone(),
            record_digest: retained.record_digest(),
            minimum_remaining_bytes,
            commands,
        })
    }

    pub(crate) const fn commands(&self) -> &[CaptureZfsReadbackCommandV1; 2] {
        &self.commands
    }

    pub(crate) fn evaluate(
        &self,
        outputs: [&[u8]; 2],
    ) -> Result<CaptureZfsPreflightV1, CaptureZfsReadbackErrorV1> {
        let required_available = self
            .requirement
            .allocation_bytes
            .checked_add(self.minimum_remaining_bytes)
            .ok_or(CaptureZfsReadbackErrorV1::InvalidRequirement)?;
        let pool = parse_row::<4>(outputs[0])?;
        if pool[0] != self.requirement.root.pool()
            || pool[1] != "-"
            || pool[3] != "ONLINE"
            || decimal(pool[2])? < required_available
        {
            return Err(CaptureZfsReadbackErrorV1::PoolUnavailable);
        }

        let root = parse_row::<4>(outputs[1])?;
        if root[0] != self.requirement.root.dataset_prefix()
            || root[1] != "filesystem"
            || decimal(root[2])? != self.requirement.root.guid()
            || decimal(root[3])? < required_available
        {
            return Err(CaptureZfsReadbackErrorV1::DatasetMismatch);
        }

        let mut digest = Sha256::new();
        digest.update(PREFLIGHT_DOMAIN);
        digest.update(self.record_digest.as_bytes());
        digest.update(self.requirement.storage_create_operation.as_bytes());
        digest.update(self.requirement.allocation_bytes.to_be_bytes());
        digest.update(self.minimum_remaining_bytes.to_be_bytes());
        for (command, output) in self.commands.iter().zip(outputs) {
            digest.update([match command.tool {
                CaptureZfsToolV1::Zpool => 1,
                CaptureZfsToolV1::Zfs => 2,
            }]);
            for argument in &command.arguments {
                digest.update((argument.len() as u64).to_be_bytes());
                digest.update(argument.as_bytes());
            }
            digest.update((output.len() as u64).to_be_bytes());
            digest.update(output);
        }

        Ok(CaptureZfsPreflightV1 {
            record_digest: self.record_digest,
            storage_create_operation: self.requirement.storage_create_operation,
            dataset_name: self.requirement.name.clone(),
            allocation_bytes: self.requirement.allocation_bytes,
            observation_digest: ObjectDigest::from_bytes(digest.finalize().into()),
        })
    }
}

/// Retains checkpoint-free headroom observation without authorizing mutation.
pub(crate) struct CaptureZfsPreflightV1 {
    pub(crate) record_digest: ObjectDigest,
    pub(crate) storage_create_operation: aos_sandbox_core::OperationId,
    pub(crate) dataset_name: String,
    pub(crate) allocation_bytes: u64,
    pub(crate) observation_digest: ObjectDigest,
}

/// Compiles the only permissible detached-capture dataset create argv.
///
/// This is a source-only command description, not effect authority. A future
/// worker must require its own durable attempt and authenticated Controller
/// and Host receipts before invoking the pinned AOS ZFS executable.
pub(crate) struct CaptureZfsCreateCommandV1 {
    pub(crate) record_digest: ObjectDigest,
    pub(crate) storage_create_operation: aos_sandbox_core::OperationId,
    pub(crate) preflight_digest: ObjectDigest,
    pub(crate) arguments: [String; 10],
    pub(crate) command_digest: ObjectDigest,
}

impl CaptureZfsCreateCommandV1 {
    pub(crate) fn new(
        requirement: &CaptureDatasetRequirementV1,
        retained: &ProtectedRetainedCaptureV1,
        preflight: &CaptureZfsPreflightV1,
    ) -> Result<Self, CaptureZfsReadbackErrorV1> {
        if !retained.matches_capture_requirement(
            *requirement.execution.as_bytes(),
            *requirement.create_operation.as_bytes(),
            requirement.claim_digest,
            requirement.admitted_bytes,
        ) || preflight.record_digest != retained.record_digest()
            || preflight.storage_create_operation != requirement.storage_create_operation
            || preflight.dataset_name != requirement.name
            || preflight.allocation_bytes != requirement.allocation_bytes
            || preflight.observation_digest.as_bytes() == &[0; 32]
        {
            return Err(CaptureZfsReadbackErrorV1::InvalidRequirement);
        }

        let arguments = [
            "create".to_owned(),
            "-o".to_owned(),
            "mountpoint=none".to_owned(),
            "-o".to_owned(),
            "canmount=off".to_owned(),
            "-o".to_owned(),
            format!("refquota={}", requirement.allocation_bytes),
            "-o".to_owned(),
            format!("reservation={}", requirement.allocation_bytes),
            requirement.name.clone(),
        ];
        let mut digest = Sha256::new();
        digest.update(CREATE_COMMAND_DOMAIN);
        digest.update(preflight.observation_digest.as_bytes());
        digest.update(retained.record_digest().as_bytes());
        digest.update(requirement.storage_create_operation.as_bytes());
        for argument in &arguments {
            digest.update((argument.len() as u64).to_be_bytes());
            digest.update(argument.as_bytes());
        }

        Ok(Self {
            record_digest: retained.record_digest(),
            storage_create_operation: requirement.storage_create_operation,
            preflight_digest: preflight.observation_digest,
            arguments,
            command_digest: ObjectDigest::from_bytes(digest.finalize().into()),
        })
    }
}

/// Fixes the three read-only probes to an AOSEOR03 record and catalog GUID.
///
/// The dataset probe includes all descendants and snapshots. Its sole row must
/// be the exact unmounted filesystem; a successful direct lookup alone would
/// not establish exclusive custody. The measured metadata allowance remains
/// an input from a future Storage-owned policy, not a value inferred from the
/// output-byte ceiling or supplied by a public execution request.
pub(crate) struct CaptureZfsReadbackPlanV1 {
    verified: VerifiedCaptureDatasetV1,
    record_digest: ObjectDigest,
    minimum_remaining_bytes: u64,
    metadata_headroom_bytes: u64,
    required_dataset_available_bytes: u64,
    phase: u8,
    write_result_digest: Option<ObjectDigest>,
    commands: [CaptureZfsReadbackCommandV1; 3],
}

impl CaptureZfsReadbackPlanV1 {
    /// Constructs the exact readback plan after protected AOSEOR03 recovery.
    pub(crate) fn new(
        verified: &VerifiedCaptureDatasetV1,
        retained: &ProtectedRetainedCaptureV1,
        metadata_headroom_bytes: u64,
        minimum_remaining_bytes: u64,
    ) -> Result<Self, CaptureZfsReadbackErrorV1> {
        let requirement = &verified.requirement;
        if !retained.matches_capture_requirement(
            *requirement.execution.as_bytes(),
            *requirement.create_operation.as_bytes(),
            requirement.claim_digest,
            requirement.admitted_bytes,
        ) || retained
            .maximum_stdout_bytes()
            .checked_add(retained.maximum_stderr_bytes())
            != Some(requirement.admitted_bytes)
            || metadata_headroom_bytes == 0
            || minimum_remaining_bytes == 0
            || requirement
                .allocation_bytes
                .checked_sub(requirement.admitted_bytes)
                .is_none_or(|remaining| remaining < metadata_headroom_bytes)
        {
            return Err(CaptureZfsReadbackErrorV1::InvalidRequirement);
        }

        let pool = requirement.root.pool();
        let root = requirement.root.dataset_prefix();
        let dataset = verified.dataset_name();
        let required_dataset_available_bytes = requirement
            .admitted_bytes
            .checked_add(metadata_headroom_bytes)
            .ok_or(CaptureZfsReadbackErrorV1::InvalidRequirement)?;
        let commands = [
            CaptureZfsReadbackCommandV1 {
                tool: CaptureZfsToolV1::Zpool,
                arguments: ["list", "-H", "-p", "-o", "name,checkpoint,available,health", pool]
                    .map(str::to_owned)
                    .to_vec(),
            },
            CaptureZfsReadbackCommandV1 {
                tool: CaptureZfsToolV1::Zfs,
                arguments: ["list", "-H", "-p", "-o", "name,type,guid,available", root]
                    .map(str::to_owned)
                    .to_vec(),
            },
            CaptureZfsReadbackCommandV1 {
                tool: CaptureZfsToolV1::Zfs,
                arguments: [
                    "list",
                    "-H",
                    "-p",
                    "-r",
                    "-t",
                    "all",
                    "-o",
                    "name,type,guid,origin,refquota,reservation,mountpoint,canmount,mounted,available",
                    dataset,
                ]
                .map(str::to_owned)
                .to_vec(),
            },
        ];

        Ok(Self {
            verified: verified.clone(),
            record_digest: retained.record_digest(),
            minimum_remaining_bytes,
            metadata_headroom_bytes,
            required_dataset_available_bytes,
            phase: 1,
            write_result_digest: None,
            commands,
        })
    }

    /// Reuses the exact physical probes after both synced stream EOFs.
    ///
    /// Captured bytes have consumed part of the refquota. The remaining
    /// available floor is therefore the unwritten ceiling plus measured
    /// metadata headroom, not the original whole capture ceiling.
    pub(crate) fn after_write(
        verified: &VerifiedCaptureDatasetV1,
        retained: &ProtectedRetainedCaptureV1,
        write: &UnboundCaptureWriteResultV1,
        metadata_headroom_bytes: u64,
        minimum_remaining_bytes: u64,
    ) -> Result<Self, CaptureZfsReadbackErrorV1> {
        let mut plan = Self::new(
            verified,
            retained,
            metadata_headroom_bytes,
            minimum_remaining_bytes,
        )?;
        let captured = write
            .stdout
            .captured_bytes
            .checked_add(write.stderr.captured_bytes)
            .filter(|bytes| *bytes <= retained.admitted_bytes())
            .ok_or(CaptureZfsReadbackErrorV1::InvalidRequirement)?;
        if write.record_digest != retained.record_digest()
            || write.stdout.maximum_bytes != retained.maximum_stdout_bytes()
            || write.stderr.maximum_bytes != retained.maximum_stderr_bytes()
            || write.stdout.captured_bytes > write.stdout.maximum_bytes
            || write.stderr.captured_bytes > write.stderr.maximum_bytes
            || !write.stdout_eof
            || !write.stderr_eof
            || !write.synced_readback
            || write.result_digest.as_bytes() == &[0; 32]
        {
            return Err(CaptureZfsReadbackErrorV1::InvalidRequirement);
        }
        plan.required_dataset_available_bytes = retained
            .admitted_bytes()
            .checked_sub(captured)
            .and_then(|remaining| remaining.checked_add(metadata_headroom_bytes))
            .ok_or(CaptureZfsReadbackErrorV1::InvalidRequirement)?;
        plan.phase = 2;
        plan.write_result_digest = Some(write.result_digest);
        Ok(plan)
    }

    pub(crate) const fn commands(&self) -> &[CaptureZfsReadbackCommandV1; 3] {
        &self.commands
    }

    /// Checks three successful, complete machine outputs in command order.
    ///
    /// This parser does not attest who ran the commands or serialize them
    /// with dataset creation, mount, or pool checkpoint changes. A future
    /// worker must provide both provenance and a current effect barrier.
    pub(crate) fn evaluate(
        &self,
        outputs: [&[u8]; 3],
    ) -> Result<CaptureZfsReadbackV1, CaptureZfsReadbackErrorV1> {
        let requirement = &self.verified.requirement;
        let pool = parse_row::<4>(outputs[0])?;
        if pool[0] != requirement.root.pool()
            || pool[1] != "-"
            || pool[3] != "ONLINE"
            || decimal(pool[2])? < self.minimum_remaining_bytes
        {
            return Err(CaptureZfsReadbackErrorV1::PoolUnavailable);
        }

        let root = parse_row::<4>(outputs[1])?;
        if root[0] != requirement.root.dataset_prefix()
            || root[1] != "filesystem"
            || decimal(root[2])? != requirement.root.guid()
            || decimal(root[3])? < self.minimum_remaining_bytes
        {
            return Err(CaptureZfsReadbackErrorV1::DatasetMismatch);
        }

        let dataset = parse_row::<10>(outputs[2])?;
        let dataset_available = decimal(dataset[9])?;
        if dataset[0] != self.verified.dataset_name()
            || dataset[1] != "filesystem"
            || decimal(dataset[2])? != self.verified.guid()
            || dataset[3] != "-"
            || decimal(dataset[4])? != requirement.allocation_bytes
            || decimal(dataset[5])? != requirement.allocation_bytes
            || dataset[6] != "none"
            || dataset[7] != "off"
            || dataset[8] != "no"
            || dataset_available < self.required_dataset_available_bytes
        {
            return Err(CaptureZfsReadbackErrorV1::DatasetMismatch);
        }

        let mut digest = Sha256::new();
        digest.update(OBSERVATION_DOMAIN);
        digest.update([self.phase]);
        digest.update(self.record_digest.as_bytes());
        digest.update(self.verified.binding().as_bytes());
        if let Some(write_result_digest) = self.write_result_digest {
            digest.update(write_result_digest.as_bytes());
        }
        for (command, output) in self.commands.iter().zip(outputs) {
            digest.update([match command.tool {
                CaptureZfsToolV1::Zpool => 1,
                CaptureZfsToolV1::Zfs => 2,
            }]);
            for argument in &command.arguments {
                digest.update((argument.len() as u64).to_be_bytes());
                digest.update(argument.as_bytes());
            }
            digest.update((output.len() as u64).to_be_bytes());
            digest.update(output);
        }

        Ok(CaptureZfsReadbackV1 {
            record_digest: self.record_digest,
            catalog_binding: self.verified.binding(),
            observation_digest: ObjectDigest::from_bytes(digest.finalize().into()),
            dataset_available_bytes: dataset_available,
            observed_headroom_bytes: dataset_available
                - (self.required_dataset_available_bytes - self.metadata_headroom_bytes),
        })
    }
}

/// Carries parsed readback data without worker provenance or effect authority.
pub(crate) struct CaptureZfsReadbackV1 {
    pub(crate) record_digest: ObjectDigest,
    pub(crate) catalog_binding: ObjectDigest,
    pub(crate) observation_digest: ObjectDigest,
    pub(crate) dataset_available_bytes: u64,
    /// Effective ZFS availability above the full capture ceiling at readback.
    pub(crate) observed_headroom_bytes: u64,
}

fn parse_row<const FIELDS: usize>(
    output: &[u8],
) -> Result<[&str; FIELDS], CaptureZfsReadbackErrorV1> {
    if output.is_empty()
        || output.len() > MAXIMUM_MACHINE_OUTPUT_BYTES
        || !output.ends_with(b"\n")
        || output[..output.len() - 1].contains(&b'\n')
        || output.contains(&b'\r')
        || output.contains(&0)
    {
        return Err(CaptureZfsReadbackErrorV1::InvalidOutput);
    }
    let text = std::str::from_utf8(&output[..output.len() - 1])
        .map_err(|_| CaptureZfsReadbackErrorV1::InvalidOutput)?;
    let fields: Vec<_> = text.split('\t').collect();
    let fields: [&str; FIELDS] = fields
        .try_into()
        .map_err(|_| CaptureZfsReadbackErrorV1::InvalidOutput)?;
    if fields.iter().any(|field| field.is_empty()) {
        return Err(CaptureZfsReadbackErrorV1::InvalidOutput);
    }
    Ok(fields)
}

fn decimal(value: &str) -> Result<u64, CaptureZfsReadbackErrorV1> {
    if value.is_empty()
        || value.starts_with('0') && value.len() != 1
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(CaptureZfsReadbackErrorV1::InvalidOutput);
    }
    value
        .parse()
        .map_err(|_| CaptureZfsReadbackErrorV1::InvalidOutput)
}
