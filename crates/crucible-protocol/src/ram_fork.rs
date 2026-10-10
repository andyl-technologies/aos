//! Bounded immutable resource plans for independently owned fork children.
//!
//! A plan is passed as a sealed descriptor separately from its connected Unix
//! sockets. Socket numbers remain local to each process. The optional source
//! record authenticates the immutable cold baseline, while the native retained
//! fork fence seals the current logical RAM state independently.
//!
//! ```text
//! magic[8] = CRURFK01; edition:u32; total_bytes:u32
//! template_generation:u64; process_contract_generation:u64
//! control_bytes:u32; root_record_bytes:u32; source_present:u8; reserved[7]
//! resources[8]:u64; spill_quota_bytes:u64
//! source_binding[72] (zero when absent)
//! canonical_control_apply_frame; canonical_outer_cap[62]; optional_opaque_root_record
//! ```
//!
//! Integers use big endian. Consumers validate all lengths before allocating
//! and authenticate the opaque root with their logical RAM implementation.

use std::io::Cursor;

use crate::ram_control::{
    RAM_CONTROL_MAX_BYTES, RAM_CONTROL_OUTER_BYTES, RamControlError, RamControlFrame,
    RamControlMessage, RamControlOuterCap, RamControlOuterState, RamControlRequest,
    RamControlResources, decode_ram_control_outer, encode_ram_control_outer, read_ram_control,
    write_ram_control,
};
use crate::ram_page::RamPageBinding;

/// Portable fork plan edition admitted by matching builds.
pub const RAM_FORK_EDITION: u32 = 1;
/// Fixed prefix size, including the optional source binding.
pub const RAM_FORK_HEADER_BYTES: usize = 192;
/// Maximum bounded canonical source root metadata.
pub const RAM_FORK_ROOT_MAX_BYTES: usize = 3 * 1024 * 1024;
/// Maximum complete immutable plan size.
pub const RAM_FORK_MAX_BYTES: usize = RAM_FORK_HEADER_BYTES
    + RAM_CONTROL_MAX_BYTES
    + 4
    + RAM_CONTROL_OUTER_BYTES
    + RAM_FORK_ROOT_MAX_BYTES;

const MAGIC: &[u8; 8] = b"CRURFK01";

/// Immutable external source retained separately from the current RAM seal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RamForkSource {
    /// Fresh child endpoint and controller incarnation bound to the baseline.
    pub binding: RamPageBinding,
    /// Canonical root metadata authenticated by the receiving implementation.
    pub root_record: Vec<u8>,
}

/// Independently admitted resources and namespaces for one immediate child.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RamForkPlan {
    /// Positive native retained-template generation.
    pub template_generation: u64,
    /// Positive target process-containment generation.
    pub process_contract_generation: u64,
    /// Complete child entitlement, independent of the parent's reservation.
    pub resources: RamControlResources,
    /// Explicit private preservation quota within the complete backing grant.
    pub spill_quota_bytes: u64,
    /// Initial child policy in the normal canonical controller frame format.
    ///
    /// The frame uses sequence one and Apply revisions zero to one. Its session
    /// and target are fresh; actual controller exchange starts with its own
    /// Hello and cursor after child reconstruction.
    pub control: RamControlFrame,
    /// Original-start cap of the independently admitted child execution.
    pub outer_cap: RamControlOuterCap,
    /// Optional independently leased immutable cold baseline.
    pub source: Option<RamForkSource>,
}

/// Rejection of a malformed or unsupported fork resource plan.
#[derive(Debug, thiserror::Error)]
pub enum RamForkPlanError {
    /// An edition, scalar, size, reserved byte, or binding was invalid.
    #[error("invalid immutable RAM fork plan")]
    Invalid,
    /// The mandatory canonical controller frame was rejected.
    #[error(transparent)]
    Control(#[from] RamControlError),
}

impl RamForkPlan {
    /// Encodes a complete immutable plan with checked canonical lengths.
    ///
    /// # Errors
    /// Rejects malformed revisions, namespaces, resource entitlements, source
    /// bindings, oversized roots, or an unsupported controller frame.
    pub fn encode(&self) -> Result<Vec<u8>, RamForkPlanError> {
        self.validate()?;
        let mut control = Vec::new();
        write_ram_control(&mut control, &self.control)?;
        let root = self
            .source
            .as_ref()
            .map_or(&[][..], |source| source.root_record.as_slice());
        let total = RAM_FORK_HEADER_BYTES
            .checked_add(control.len())
            .and_then(|length| length.checked_add(RAM_CONTROL_OUTER_BYTES))
            .and_then(|length| length.checked_add(root.len()))
            .filter(|length| *length <= RAM_FORK_MAX_BYTES)
            .ok_or(RamForkPlanError::Invalid)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(total)
            .map_err(|_| RamForkPlanError::Invalid)?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&RAM_FORK_EDITION.to_be_bytes());
        bytes.extend_from_slice(&(total as u32).to_be_bytes());
        bytes.extend_from_slice(&self.template_generation.to_be_bytes());
        bytes.extend_from_slice(&self.process_contract_generation.to_be_bytes());
        bytes.extend_from_slice(&(control.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&(root.len() as u32).to_be_bytes());
        bytes.push(u8::from(self.source.is_some()));
        bytes.extend_from_slice(&[0; 7]);
        for component in resource_components(self.resources) {
            bytes.extend_from_slice(&component.to_be_bytes());
        }
        bytes.extend_from_slice(&self.spill_quota_bytes.to_be_bytes());
        if let Some(source) = &self.source {
            bytes.extend_from_slice(&source.binding.session);
            bytes.extend_from_slice(&source.binding.owner_incarnation);
            bytes.extend_from_slice(&source.binding.source_generation.to_be_bytes());
            bytes.extend_from_slice(&source.binding.root_digest);
        } else {
            bytes.extend_from_slice(&[0; 72]);
        }
        bytes.extend_from_slice(&control);
        bytes.extend_from_slice(&encode_ram_control_outer(self.outer_cap)?);
        bytes.extend_from_slice(root);
        Ok(bytes)
    }

    /// Decodes one exact immutable plan without trusting declared allocation sizes.
    ///
    /// # Errors
    /// Rejects unknown editions, truncation, trailing data, noncanonical padding,
    /// malformed namespaces or revisions, and lengths beyond the hard limits.
    pub fn decode(bytes: &[u8]) -> Result<Self, RamForkPlanError> {
        if bytes.len() < RAM_FORK_HEADER_BYTES
            || bytes.len() > RAM_FORK_MAX_BYTES
            || &bytes[..8] != MAGIC
            || read_u32(bytes, 8)? != RAM_FORK_EDITION
            || read_u32(bytes, 12)? as usize != bytes.len()
            || bytes[40] > 1
            || bytes[41..48].iter().any(|byte| *byte != 0)
        {
            return Err(RamForkPlanError::Invalid);
        }
        let control_length = read_u32(bytes, 32)? as usize;
        let root_length = read_u32(bytes, 36)? as usize;
        if !(4..=RAM_CONTROL_MAX_BYTES + 4).contains(&control_length)
            || root_length > RAM_FORK_ROOT_MAX_BYTES
            || RAM_FORK_HEADER_BYTES
                .checked_add(control_length)
                .and_then(|length| length.checked_add(RAM_CONTROL_OUTER_BYTES))
                .and_then(|length| length.checked_add(root_length))
                != Some(bytes.len())
        {
            return Err(RamForkPlanError::Invalid);
        }
        let mut reader =
            Cursor::new(&bytes[RAM_FORK_HEADER_BYTES..RAM_FORK_HEADER_BYTES + control_length]);
        let control = read_ram_control(&mut reader)?.ok_or(RamForkPlanError::Invalid)?;
        if reader.position() != control_length as u64 {
            return Err(RamForkPlanError::Invalid);
        }
        let resources = RamControlResources {
            resident_peak_bytes: read_u64(bytes, 48)?,
            backing_peak_bytes: read_u64(bytes, 56)?,
            metadata_bytes: read_u64(bytes, 64)?,
            staging_bytes: read_u64(bytes, 72)?,
            paging_io_slots: read_u64(bytes, 80)?,
            cpu_slots: read_u64(bytes, 88)?,
            task_slots: read_u64(bytes, 96)?,
            file_descriptors: read_u64(bytes, 104)?,
        };
        let source = if bytes[40] == 1 {
            if root_length == 0 {
                return Err(RamForkPlanError::Invalid);
            }
            Some(RamForkSource {
                binding: RamPageBinding {
                    session: read_array(bytes, 120)?,
                    owner_incarnation: read_array(bytes, 136)?,
                    source_generation: read_u64(bytes, 152)?,
                    root_digest: read_array(bytes, 160)?,
                },
                root_record: bytes
                    [RAM_FORK_HEADER_BYTES + control_length + RAM_CONTROL_OUTER_BYTES..]
                    .to_vec(),
            })
        } else {
            if root_length != 0 || bytes[120..192].iter().any(|byte| *byte != 0) {
                return Err(RamForkPlanError::Invalid);
            }
            None
        };
        let plan = Self {
            template_generation: read_u64(bytes, 16)?,
            process_contract_generation: read_u64(bytes, 24)?,
            resources,
            spill_quota_bytes: read_u64(bytes, 112)?,
            control,
            outer_cap: decode_ram_control_outer(
                &bytes[RAM_FORK_HEADER_BYTES + control_length
                    ..RAM_FORK_HEADER_BYTES + control_length + RAM_CONTROL_OUTER_BYTES],
            )?,
            source,
        };
        plan.validate()?;
        Ok(plan)
    }

    fn validate(&self) -> Result<(), RamForkPlanError> {
        self.outer_cap.validate()?;
        if self.template_generation == 0
            || self.process_contract_generation == 0
            || self.outer_cap.state != RamControlOuterState::Running
            || self.control.sequence != 1
            || self.control.session == [0; 32]
            || self.control.target.retained_template
            || !matches!(
                self.control.message,
                RamControlMessage::Request(RamControlRequest::Apply {
                    expected_revision: 0,
                    policy_revision: 1,
                    reservation_revision: 0,
                    resources,
                    ..
                }) if resources == self.resources
            )
            || self.resources.resident_peak_bytes == 0
            || self.resources.backing_peak_bytes == 0
            || self.resources.metadata_bytes == 0
            || self.resources.staging_bytes == 0
            || self.resources.paging_io_slots == 0
            || self.resources.cpu_slots == 0
            || self.resources.task_slots == 0
            || self.resources.file_descriptors == 0
            || self.spill_quota_bytes == 0
            || self.spill_quota_bytes > self.resources.backing_peak_bytes
        {
            return Err(RamForkPlanError::Invalid);
        }
        if let Some(source) = &self.source {
            source
                .binding
                .validate()
                .map_err(|_| RamForkPlanError::Invalid)?;
            if source.root_record.is_empty() || source.root_record.len() > RAM_FORK_ROOT_MAX_BYTES {
                return Err(RamForkPlanError::Invalid);
            }
        }
        Ok(())
    }
}

fn resource_components(resources: RamControlResources) -> [u64; 8] {
    [
        resources.resident_peak_bytes,
        resources.backing_peak_bytes,
        resources.metadata_bytes,
        resources.staging_bytes,
        resources.paging_io_slots,
        resources.cpu_slots,
        resources.task_slots,
        resources.file_descriptors,
    ]
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], RamForkPlanError> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(RamForkPlanError::Invalid)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, RamForkPlanError> {
    Ok(u32::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, RamForkPlanError> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ram_control::{
        RAM_CONTROL_BUDGET_COUNT, RamControlBudget, RamControlMode, RamControlPolicy,
        RamControlTarget,
    };

    fn plan(source: bool) -> RamForkPlan {
        let resources = RamControlResources {
            resident_peak_bytes: 4096,
            backing_peak_bytes: 8192,
            metadata_bytes: 16_384,
            staging_bytes: 8192,
            paging_io_slots: 1,
            cpu_slots: 1,
            task_slots: 4,
            file_descriptors: 16,
        };
        RamForkPlan {
            template_generation: 7,
            process_contract_generation: 19,
            spill_quota_bytes: 4096,
            resources,
            control: RamControlFrame {
                session: [9; 32],
                sequence: 1,
                target: RamControlTarget {
                    daemon_epoch: [1; 32],
                    owner_id: [2; 32],
                    node_id: [3; 32],
                    owner_generation: 5,
                    arena_generation: 6,
                    retained_template: false,
                },
                message: RamControlMessage::Request(RamControlRequest::Apply {
                    expected_revision: 0,
                    policy_revision: 1,
                    reservation_revision: 0,
                    resources,
                    policy: RamControlPolicy {
                        mode: RamControlMode::DiskOriented,
                        resident_target_bytes: 4096,
                        eviction_preference: 100,
                        writeback_bytes_per_second: 4096,
                        maximum_paging_io_in_flight: 1,
                        prefetch_on_increase: false,
                        budgets: [RamControlBudget {
                            poll_ms: 10,
                            progress_ms: Some(1000),
                            total_ms: Some(10_000),
                        }; RAM_CONTROL_BUDGET_COUNT],
                    },
                }),
            },
            outer_cap: RamControlOuterCap {
                cap_id: [13; 32],
                revision: 0,
                original_monotonic_ns: 17,
                allowance_ns: Some(300),
                state: RamControlOuterState::Running,
            },
            source: source.then(|| RamForkSource {
                binding: RamPageBinding {
                    session: [4; 16],
                    owner_incarnation: [5; 16],
                    source_generation: 12,
                    root_digest: [6; 32],
                },
                root_record: vec![8; 19],
            }),
        }
    }

    #[test]
    fn fork_plan_canonical_roundtrip_keeps_base_and_child_authorities() {
        for source in [false, true] {
            let expected = plan(source);
            let bytes = expected
                .encode()
                .unwrap_or_else(|error| panic!("unexpected fork-plan error: {error}"));
            assert_eq!(&bytes[..8], b"CRURFK01");
            assert_eq!(
                read_u32(&bytes, 12)
                    .unwrap_or_else(|error| panic!("unexpected fork-plan error: {error}"))
                    as usize,
                bytes.len()
            );
            assert_eq!(
                read_u64(&bytes, 16)
                    .unwrap_or_else(|error| panic!("unexpected fork-plan error: {error}")),
                7
            );
            assert_eq!(
                read_u64(&bytes, 24)
                    .unwrap_or_else(|error| panic!("unexpected fork-plan error: {error}")),
                19
            );
            assert_eq!(
                RamForkPlan::decode(&bytes)
                    .unwrap_or_else(|error| panic!("unexpected fork-plan error: {error}")),
                expected
            );
            assert_eq!(
                RamForkPlan::decode(&bytes)
                    .unwrap_or_else(|error| panic!("unexpected fork-plan error: {error}"))
                    .encode()
                    .unwrap_or_else(|error| panic!("unexpected fork-plan error: {error}")),
                bytes
            );
        }
    }

    #[test]
    fn fork_plan_rejects_lengths_reserved_bytes_and_absent_source_aliases() {
        let bytes = plan(false)
            .encode()
            .unwrap_or_else(|error| panic!("unexpected fork-plan error: {error}"));
        for length in 0..bytes.len() {
            assert!(
                RamForkPlan::decode(&bytes[..length]).is_err(),
                "length {length}"
            );
        }
        for offset in [8, 12, 32, 36] {
            let mut invalid = bytes.clone();
            invalid[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
            assert!(RamForkPlan::decode(&invalid).is_err(), "offset {offset}");
        }
        for offset in [40, 41, 47, 120, 159, 191] {
            let mut invalid = bytes.clone();
            invalid[offset] = 127;
            assert!(RamForkPlan::decode(&invalid).is_err(), "offset {offset}");
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(RamForkPlan::decode(&trailing).is_err());
    }

    #[test]
    fn fork_plan_rejects_parent_namespaces_stale_revisions_and_source_bindings() {
        let mut invalid = plan(true);
        invalid.control.target.retained_template = true;
        assert!(invalid.encode().is_err());
        invalid = plan(true);
        invalid.control.sequence = 2;
        assert!(invalid.encode().is_err());
        invalid = plan(true);
        if let RamControlMessage::Request(RamControlRequest::Apply {
            reservation_revision,
            ..
        }) = &mut invalid.control.message
        {
            *reservation_revision = 1;
        } else {
            panic!("fork fixture must carry its initial Apply");
        }
        assert!(invalid.encode().is_err());
        invalid = plan(true);
        invalid.template_generation = 0;
        assert!(invalid.encode().is_err());
        invalid = plan(true);
        invalid.resources.resident_peak_bytes += 4096;
        assert!(invalid.encode().is_err());
        invalid = plan(true);
        invalid
            .source
            .as_mut()
            .unwrap_or_else(|| panic!("missing fork source"))
            .binding
            .owner_incarnation = [0; 16];
        assert!(invalid.encode().is_err());
        invalid = plan(true);
        invalid
            .source
            .as_mut()
            .unwrap_or_else(|| panic!("missing fork source"))
            .root_record
            .clear();
        assert!(invalid.encode().is_err());
        let mut invalid_bytes = plan(true)
            .encode()
            .unwrap_or_else(|error| panic!("unexpected fork-plan error: {error}"));
        invalid_bytes[136..152].fill(0);
        assert!(RamForkPlan::decode(&invalid_bytes).is_err());
    }
}
