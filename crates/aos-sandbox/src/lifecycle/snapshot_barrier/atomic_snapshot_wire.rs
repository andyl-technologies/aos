//! Canonical bounded transport for an exact lifecycle dataset snapshot plan.
//!
//! Storage receives these bytes only inside an authenticated local broker
//! request. Decoding restores the complete typed member and dependency set;
//! the terminal commitment is recomputed before Storage can prepare a program.

use aos_sandbox_core::{
    BoundedReader, ObjectDigest, OperationId, ReadError, ResourceId, SandboxId, SnapshotId,
};

use super::{
    LifecycleAtomicDatasetSnapshotMemberV1, LifecycleAtomicDatasetSnapshotPlanV1,
    LifecyclePhase6ErrorV1, LifecycleResourceV1, atomic_dataset_snapshot_plan_commitment,
    distinct_snapshot_storage_handles,
};

const MAGIC: &[u8; 8] = b"AOSASP02";
const MAXIMUM_PLAN_BYTES: usize = 600_000;

impl LifecycleAtomicDatasetSnapshotPlanV1 {
    /// Encodes the complete snapshot plan for an authenticated Storage request.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1::Capacity`] if the plan exceeds the
    /// closed wire bounds.
    pub fn canonical_wire_bytes(&self) -> Result<Vec<u8>, LifecyclePhase6ErrorV1> {
        let closed_count = u16::try_from(self.closed_resources.len())
            .map_err(|_| LifecyclePhase6ErrorV1::Capacity)?;
        let member_count =
            u16::try_from(self.members.len()).map_err(|_| LifecyclePhase6ErrorV1::Capacity)?;
        let mut bytes = Vec::with_capacity(
            8 + 16 * 3
                + 214
                + 8
                + 32 * 4
                + 2
                + 17 * self.closed_resources.len()
                + 2
                + 113 * self.members.len()
                + 32,
        );
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(self.operation.as_bytes());
        bytes.extend_from_slice(self.snapshot.as_bytes());
        bytes.extend_from_slice(self.transaction.get().as_bytes());
        bytes.extend_from_slice(&self.effect.atomic_snapshot_wire_bytes());
        bytes.extend_from_slice(&self.inventory_generation.to_be_bytes());
        bytes.extend_from_slice(self.inventory_source.as_bytes());
        bytes.extend_from_slice(self.inventory_head.as_bytes());
        bytes.extend_from_slice(self.inventory.as_bytes());
        bytes.extend_from_slice(&closed_count.to_be_bytes());
        for resource in &self.closed_resources {
            encode_resource(&mut bytes, *resource);
        }
        bytes.extend_from_slice(&member_count.to_be_bytes());
        for member in &self.members {
            encode_resource(&mut bytes, member.resource);
            bytes.extend_from_slice(member.storage_handle.as_bytes());
            bytes.extend_from_slice(member.physical_identity.as_bytes());
            bytes.extend_from_slice(member.creating_request.as_bytes());
        }
        bytes.extend_from_slice(self.commitment.as_bytes());
        if bytes.len() > MAXIMUM_PLAN_BYTES {
            return Err(LifecyclePhase6ErrorV1::Capacity);
        }
        Ok(bytes)
    }

    /// Decodes a complete canonical plan and checks its terminal commitment.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for a noncanonical, oversized,
    /// truncated, duplicated, or differently committed plan.
    pub fn from_canonical_wire_bytes(bytes: &[u8]) -> Result<Self, LifecyclePhase6ErrorV1> {
        if bytes.len() > MAXIMUM_PLAN_BYTES {
            return Err(LifecyclePhase6ErrorV1::Capacity);
        }
        // Mechanical range errors retain the format's overflow/truncation distinction.
        let mut reader = BoundedReader::new(bytes, |error| match error {
            ReadError::LengthOverflow => LifecyclePhase6ErrorV1::Capacity,
            _ => LifecyclePhase6ErrorV1::InvalidInput,
        });
        if reader.array::<8>()? != *MAGIC {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let operation = OperationId::from_bytes(reader.array()?);
        let snapshot = SnapshotId::from_bytes(reader.array()?);
        let transaction =
            super::super::LifecycleTransactionIdV1::new(ResourceId::from_bytes(reader.array()?))
                .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)?;
        let effect = super::super::LifecycleEffectRequestV1::from_atomic_snapshot_wire_bytes(
            &reader.array()?,
        )?;
        let inventory_generation = u64::from_be_bytes(reader.array()?);
        let inventory_source = ObjectDigest::from_bytes(reader.array()?);
        let inventory_head = ObjectDigest::from_bytes(reader.array()?);
        let inventory = ObjectDigest::from_bytes(reader.array()?);
        let closed_count = usize::from(u16::from_be_bytes(reader.array()?));
        if closed_count == 0 || closed_count > super::super::MAXIMUM_LIFECYCLE_EXPECTATIONS {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let mut closed_resources = Vec::with_capacity(closed_count);
        for _ in 0..closed_count {
            closed_resources.push(decode_resource(&mut reader)?);
        }
        let member_count = usize::from(u16::from_be_bytes(reader.array()?));
        if member_count == 0 || member_count > super::super::MAXIMUM_LIFECYCLE_EXPECTATIONS {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let mut members = Vec::with_capacity(member_count);
        for _ in 0..member_count {
            members.push(LifecycleAtomicDatasetSnapshotMemberV1 {
                resource: decode_resource(&mut reader)?,
                storage_handle: ObjectDigest::from_bytes(reader.array()?),
                physical_identity: ObjectDigest::from_bytes(reader.array()?),
                creating_request: ObjectDigest::from_bytes(reader.array()?),
            });
        }
        let commitment = ObjectDigest::from_bytes(reader.array()?);
        if !reader.is_empty()
            || operation.as_bytes() == &[0; 16]
            || snapshot.as_bytes() == &[0; 16]
            || effect.operation() != operation
            || !closed_resources.contains(&LifecycleResourceV1::Sandbox(SandboxId::from_bytes(
                effect.target(),
            )))
            || inventory_generation == 0
            || inventory_source.as_bytes() == &[0; 32]
            || inventory_head.as_bytes() == &[0; 32]
            || inventory.as_bytes() == &[0; 32]
            || !closed_resources.windows(2).all(|pair| pair[0] < pair[1])
            || !members.windows(2).all(|pair| pair[0] < pair[1])
            || !distinct_snapshot_storage_handles(&members)
            || members.iter().any(|member| {
                !closed_resources.contains(&member.resource)
                    || !matches!(member.resource, LifecycleResourceV1::Sandbox(_))
                    || member.storage_handle.as_bytes() == &[0; 32]
                    || member.physical_identity.as_bytes() == &[0; 32]
                    || member.creating_request.as_bytes() == &[0; 32]
            })
            || commitment
                != atomic_dataset_snapshot_plan_commitment(
                    operation,
                    snapshot,
                    transaction,
                    effect,
                    inventory_generation,
                    inventory_source,
                    inventory_head,
                    inventory,
                    &closed_resources,
                    &members,
                )
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Ok(Self {
            operation,
            snapshot,
            transaction,
            effect,
            inventory_generation,
            inventory_source,
            inventory_head,
            inventory,
            closed_resources,
            members,
            commitment,
        })
    }
}

fn encode_resource(bytes: &mut Vec<u8>, resource: LifecycleResourceV1) {
    bytes.push(resource.code());
    bytes.extend_from_slice(resource.as_bytes());
}

fn decode_resource(
    reader: &mut BoundedReader<'_, LifecyclePhase6ErrorV1>,
) -> Result<LifecycleResourceV1, LifecyclePhase6ErrorV1> {
    let code = reader.array::<1>()?[0];
    let identity = reader.array()?;
    LifecycleResourceV1::from_code(code, identity).map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recommit(plan: &mut LifecycleAtomicDatasetSnapshotPlanV1) {
        plan.commitment = atomic_dataset_snapshot_plan_commitment(
            plan.operation,
            plan.snapshot,
            plan.transaction,
            plan.effect,
            plan.inventory_generation,
            plan.inventory_source,
            plan.inventory_head,
            plan.inventory,
            &plan.closed_resources,
            &plan.members,
        );
    }

    fn plan_fixture() -> LifecycleAtomicDatasetSnapshotPlanV1 {
        let effect = crate::lifecycle::phase6::atomic_snapshot_effect_fixture();
        let resources = [
            LifecycleResourceV1::Sandbox(SandboxId::from_bytes([2; 16])),
            LifecycleResourceV1::Sandbox(SandboxId::from_bytes([3; 16])),
        ];
        let mut plan = LifecycleAtomicDatasetSnapshotPlanV1 {
            operation: effect.operation(),
            snapshot: SnapshotId::from_bytes([4; 16]),
            transaction: crate::lifecycle::LifecycleTransactionIdV1::new(ResourceId::from_bytes(
                [5; 16],
            ))
            .unwrap(),
            effect,
            inventory_generation: 1,
            inventory_source: ObjectDigest::from_bytes([6; 32]),
            inventory_head: ObjectDigest::from_bytes([7; 32]),
            inventory: ObjectDigest::from_bytes([8; 32]),
            closed_resources: resources.to_vec(),
            members: resources
                .into_iter()
                .enumerate()
                .map(|(index, resource)| LifecycleAtomicDatasetSnapshotMemberV1 {
                    resource,
                    storage_handle: ObjectDigest::from_bytes([20 + index as u8; 32]),
                    physical_identity: ObjectDigest::from_bytes([22 + index as u8; 32]),
                    creating_request: ObjectDigest::from_bytes([24 + index as u8; 32]),
                })
                .collect(),
            commitment: ObjectDigest::from_bytes([0; 32]),
        };
        recommit(&mut plan);
        plan
    }

    #[test]
    fn canonical_plan_round_trips_and_rejects_every_short_prefix_and_trailing_byte() {
        let plan = plan_fixture();
        let bytes = plan.canonical_wire_bytes().unwrap();

        let decoded =
            LifecycleAtomicDatasetSnapshotPlanV1::from_canonical_wire_bytes(&bytes).unwrap();
        assert_eq!(decoded, plan);
        assert_eq!(decoded.canonical_wire_bytes().unwrap(), bytes);
        for length in 0..bytes.len() {
            assert_eq!(
                LifecycleAtomicDatasetSnapshotPlanV1::from_canonical_wire_bytes(&bytes[..length]),
                Err(LifecyclePhase6ErrorV1::InvalidInput),
                "short prefix {length}",
            );
        }

        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            LifecycleAtomicDatasetSnapshotPlanV1::from_canonical_wire_bytes(&trailing),
            Err(LifecyclePhase6ErrorV1::InvalidInput),
        );
    }

    #[test]
    fn canonical_plan_preserves_capacity_count_and_effect_commitment_errors() {
        let oversized_wrong_magic = vec![0; MAXIMUM_PLAN_BYTES + 1];
        assert_eq!(
            LifecycleAtomicDatasetSnapshotPlanV1::from_canonical_wire_bytes(&oversized_wrong_magic),
            Err(LifecyclePhase6ErrorV1::Capacity),
        );

        let plan = plan_fixture();
        let bytes = plan.canonical_wire_bytes().unwrap();
        let closed_count_offset = 8 + 16 * 3 + 214 + 8 + 32 * 3;
        let member_count_offset = closed_count_offset + 2 + 17 * plan.closed_resources.len();
        let excessive_count =
            u16::try_from(crate::lifecycle::MAXIMUM_LIFECYCLE_EXPECTATIONS + 1).unwrap();
        for offset in [closed_count_offset, member_count_offset] {
            for count in [0_u16, excessive_count] {
                let mut invalid = bytes.clone();
                invalid[offset..offset + 2].copy_from_slice(&count.to_be_bytes());

                assert_eq!(
                    LifecycleAtomicDatasetSnapshotPlanV1::from_canonical_wire_bytes(&invalid),
                    Err(LifecyclePhase6ErrorV1::InvalidInput),
                );
            }
        }

        // The embedded effect's domain and payload are validated before the outer commitment.
        for offset in [8 + 16 * 3 + 24, 8 + 16 * 3 + 213, bytes.len() - 1] {
            let mut substituted = bytes.clone();
            substituted[offset] ^= 0xff;

            assert_eq!(
                LifecycleAtomicDatasetSnapshotPlanV1::from_canonical_wire_bytes(&substituted),
                Err(LifecyclePhase6ErrorV1::InvalidInput),
            );
        }
    }

    #[test]
    fn canonical_plan_rejects_unordered_duplicate_sets_and_shared_storage_handles() {
        for variant in 0..5 {
            let mut plan = plan_fixture();
            match variant {
                0 => plan.closed_resources.swap(0, 1),
                1 => plan.closed_resources[1] = plan.closed_resources[0],
                2 => plan.members.swap(0, 1),
                3 => plan.members[1] = plan.members[0],
                4 => plan.members[1].storage_handle = plan.members[0].storage_handle,
                _ => unreachable!(),
            }
            // Recommit each malformed set so its semantic check must reject it.
            recommit(&mut plan);
            let bytes = plan.canonical_wire_bytes().unwrap();

            assert_eq!(
                LifecycleAtomicDatasetSnapshotPlanV1::from_canonical_wire_bytes(&bytes),
                Err(LifecyclePhase6ErrorV1::InvalidInput),
            );
        }
    }
}
