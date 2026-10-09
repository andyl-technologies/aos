//! Canonical bounded transport for an exact lifecycle dataset snapshot plan.
//!
//! Storage receives these bytes only inside an authenticated local broker
//! request. Decoding restores the complete typed member and dependency set;
//! the terminal commitment is recomputed before Storage can prepare a program.

use aos_sandbox_core::{ObjectDigest, OperationId, ResourceId, SandboxId, SnapshotId};

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
        let mut reader = PlanReader { bytes, offset: 0 };
        if reader.take::<8>()? != *MAGIC {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let operation = OperationId::from_bytes(reader.take()?);
        let snapshot = SnapshotId::from_bytes(reader.take()?);
        let transaction =
            super::super::LifecycleTransactionIdV1::new(ResourceId::from_bytes(reader.take()?))
                .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)?;
        let effect = super::super::LifecycleEffectRequestV1::from_atomic_snapshot_wire_bytes(
            &reader.take()?,
        )?;
        let inventory_generation = u64::from_be_bytes(reader.take()?);
        let inventory_source = ObjectDigest::from_bytes(reader.take()?);
        let inventory_head = ObjectDigest::from_bytes(reader.take()?);
        let inventory = ObjectDigest::from_bytes(reader.take()?);
        let closed_count = usize::from(u16::from_be_bytes(reader.take()?));
        if closed_count == 0 || closed_count > super::super::MAXIMUM_LIFECYCLE_EXPECTATIONS {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let mut closed_resources = Vec::with_capacity(closed_count);
        for _ in 0..closed_count {
            closed_resources.push(decode_resource(&mut reader)?);
        }
        let member_count = usize::from(u16::from_be_bytes(reader.take()?));
        if member_count == 0 || member_count > super::super::MAXIMUM_LIFECYCLE_EXPECTATIONS {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let mut members = Vec::with_capacity(member_count);
        for _ in 0..member_count {
            members.push(LifecycleAtomicDatasetSnapshotMemberV1 {
                resource: decode_resource(&mut reader)?,
                storage_handle: ObjectDigest::from_bytes(reader.take()?),
                physical_identity: ObjectDigest::from_bytes(reader.take()?),
                creating_request: ObjectDigest::from_bytes(reader.take()?),
            });
        }
        let commitment = ObjectDigest::from_bytes(reader.take()?);
        if reader.offset != bytes.len()
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
    reader: &mut PlanReader<'_>,
) -> Result<LifecycleResourceV1, LifecyclePhase6ErrorV1> {
    let code = reader.take::<1>()?[0];
    let identity = reader.take()?;
    LifecycleResourceV1::from_code(code, identity).map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)
}

struct PlanReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl PlanReader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], LifecyclePhase6ErrorV1> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(LifecyclePhase6ErrorV1::Capacity)?;
        let field = self
            .bytes
            .get(self.offset..end)
            .ok_or(LifecyclePhase6ErrorV1::InvalidInput)?;
        self.offset = end;
        field
            .try_into()
            .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)
    }
}
