//! Checks the closed provisioning companion extension of the same V2 batch.
//!
//! Header bytes 316..320 hold its bounded descriptor count. Fixed descriptors
//! follow P, before the whole-batch checksum. V1 retains a zero count and its
//! exact historical layout. Two existing pending overlays cover the logical
//! resources; their three original rows remain live until native retirement.

use super::*;
use super::super::provisioning_resources::{
    PROVISIONING_COMPANION_DESCRIPTOR_BYTES_V2, PROVISIONING_RESOURCE_KEY_BYTES_V1,
    PROVISIONING_RESOURCE_ROW_BYTES_V1, ProvisioningCompanionRetirementDataV2,
    ProvisioningResourceRowKindV1,
};

pub(super) fn receiving_bytes_v2() -> Option<usize> {
    // Iteration is sequential. A descriptor and its canonical original row
    // coexist with one comparison/key lookup; no new namespace is created.
    std::mem::size_of::<ProvisioningCompanionRetirementDataV2>().checked_mul(3)?
        .checked_add(PROVISIONING_RESOURCE_ROW_BYTES_V1.checked_mul(3)?)?
        .checked_add(PROVISIONING_RESOURCE_KEY_BYTES_V1.checked_mul(2)?)?
        .checked_add(PROVISIONING_COMPANION_DESCRIPTOR_BYTES_V2.checked_mul(3)?)?
        .checked_add(std::mem::size_of::<(aos_sandbox_core::RecordNamespace, Vec<u8>)>()
            .checked_mul(2)?)?
        .checked_add(std::mem::size_of::<Sha256>().checked_mul(3)?)
}

impl DeleteBatchEncodingDataV1<'_, '_> {
    /// Bounds the complete V2 encoding before companion bytes are allocated.
    ///
    /// This is passive length DATA, not a payment or provenance check.
    ///
    /// # Errors
    /// Refuses excessive descriptor counts, original row bounds or arithmetic
    /// overflow beyond the same complete batch wire ceiling.
    pub fn encoded_length_with_companions_v2(&self, count: usize)
        -> Result<usize, LifecycleModelError>
    {
        if count > MAXIMUM_ROWS / 2 { return Err(corrupt()); }
        self.encoded_length_v1()?.checked_add(count.checked_mul(
            PROVISIONING_COMPANION_DESCRIPTOR_BYTES_V2).ok_or_else(corrupt)?)
            .filter(|bytes| *bytes <= MAXIMUM_BYTES).ok_or_else(corrupt)
    }
}

impl<'bytes> DeleteBatchViewV1<'bytes> {
    /// Traverses the exact bounded descriptors of this fully checked view.
    ///
    /// Each value remains nonauthorizing DATA. A native admission must compare
    /// the original complete three-row set under its actual writer interval.
    pub fn companions_v2(self) -> impl Iterator<Item =
        Result<ProvisioningCompanionRetirementDataV2, LifecycleModelError>> + 'bytes
    {
        self.companions.chunks_exact(PROVISIONING_COMPANION_DESCRIPTOR_BYTES_V2)
            .map(|bytes| ProvisioningCompanionRetirementDataV2::decode_v2(bytes)
                .map_err(|_| corrupt()))
    }

    /// Finds the exact typed original belonging to a logical Other write.
    ///
    /// This performs no native observation and cannot construct an accepted
    /// retirement. The view's complete decoder already checked every descriptor.
    pub fn companion_for_resource_v2(self, resource: &[u8]) -> Option<(
        ProvisioningCompanionRetirementDataV2, ProvisioningResourceRowKindV1)>
    {
        if resource.len() != 17 || resource[0] != 9 { return None; }
        for descriptor in self.companions_v2() {
            let descriptor = descriptor.ok()?;
            let fields = descriptor.original_v1().fields_v1();
            if resource[1..] == fields.assignment.as_bytes()[..] {
                return Some((descriptor, ProvisioningResourceRowKindV1::Assignment));
            }
            if resource[1..] == fields.reservation.as_bytes()[..] {
                return Some((descriptor, ProvisioningResourceRowKindV1::Reservation));
            }
        }
        None
    }

    pub(super) fn validate_companions_v2(self) -> Result<(), LifecycleModelError> {
        let mut previous_parent = None;
        for (index, descriptor) in self.companions_v2().enumerate() {
            let descriptor = descriptor?;
            let original = descriptor.original_v1();
            let fields = original.fields_v1();
            if self.version() != 2 || fields.project != self.project()
                || descriptor.operation_v2() != self.operation()
                || descriptor.transaction_v2() != self.transaction()
                || previous_parent.is_some_and(|parent| parent >= fields.parent)
                || !self.rows(0).any(|row| row[0] == 1
                    && row[1..17] == fields.sandbox.as_bytes()[..])
            {
                return Err(corrupt());
            }
            previous_parent = Some(fields.parent);

            // No logical identity can occur in two independently named sets,
            // including an assignment/reservation kind swap across parents.
            for earlier in self.companions_v2().take(index) {
                let earlier = earlier?.original_v1().fields_v1();
                if [earlier.assignment, earlier.reservation].iter()
                    .any(|id| *id == fields.assignment || *id == fields.reservation)
                {
                    return Err(corrupt());
                }
            }
            for (kind, id) in [
                (ProvisioningResourceRowKindV1::Assignment, fields.assignment),
                (ProvisioningResourceRowKindV1::Reservation, fields.reservation),
            ] {
                let row = self.rows(0).find(|row| row[0] == 9
                    && row[1..17] == id.as_bytes()[..]).ok_or_else(corrupt)?;
                if row_key(row, 0) != original.key_v1(kind)
                    || raw64(&row[20..28]) != 1
                    || row[28..60] != native_value_digest(&original.encode_v1(kind))
                {
                    return Err(corrupt());
                }
            }
            // Class 7 is V2's explicit companion dependency relation. Both
            // logical resources depend on the Sandbox; assignment additionally
            // depends on reservation. No other class-7 edge is accepted.
            for (code, id) in [(1, fields.sandbox.as_bytes()),
                (9, fields.reservation.as_bytes())]
            {
                if !self.rows(3).any(|row| row[0] == 9
                    && row[1..17] == fields.assignment.as_bytes()[..]
                    && row[17] == code && row[18..34] == id[..] && row[34] == 7)
                {
                    return Err(corrupt());
                }
            }
            if !self.rows(3).any(|row| row[0] == 9
                && row[1..17] == fields.reservation.as_bytes()[..]
                && row[17] == 1 && row[18..34] == fields.sandbox.as_bytes()[..]
                && row[34] == 7)
            {
                return Err(corrupt());
            }
        }
        Ok(())
    }

    pub(super) fn is_companion_edge_v2(self, row: &[u8]) -> bool {
        self.companions_v2().any(|descriptor| descriptor.is_ok_and(|descriptor| {
            let fields = descriptor.original_v1().fields_v1();
            row[0] == 9 && ((row[1..17] == fields.assignment.as_bytes()[..]
                && ((row[17] == 1 && row[18..34] == fields.sandbox.as_bytes()[..])
                    || (row[17] == 9 && row[18..34] == fields.reservation.as_bytes()[..])))
                || (row[1..17] == fields.reservation.as_bytes()[..]
                    && row[17] == 1 && row[18..34] == fields.sandbox.as_bytes()[..]))
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::{AssignmentEpoch, ObjectDigest, ResourceId, Revision, SandboxId};
    use super::super::super::provisioning_resources::{
        ProvisioningModeDataV1, ProvisioningResourceFieldsV1, ProvisioningResourceRecordsV1,
    };

    fn original() -> ProvisioningResourceRecordsV1 {
        ProvisioningResourceRecordsV1::from_data_v1(ProvisioningResourceFieldsV1 {
            mode: ProvisioningModeDataV1::CreateStopped,
            parent: OperationId::from_bytes([10; 16]),
            publication_operation: OperationId::from_bytes([11; 16]),
            sandbox: SandboxId::from_bytes([12; 16]),
            project: ProjectId::from_bytes([13; 16]),
            assignment: ResourceId::from_bytes([14; 16]),
            reservation: ResourceId::from_bytes([15; 16]),
            epoch: AssignmentEpoch::new(42), reservation_revision: Revision::new(1),
            public_request: ObjectDigest::from_bytes([1; 32]),
            manifest: ObjectDigest::from_bytes([2; 32]),
            source_draft: ObjectDigest::from_bytes([3; 32]),
            root_plan: ObjectDigest::from_bytes([4; 32]),
            child_head: ObjectDigest::from_bytes([5; 32]),
            inclusive_grant: ObjectDigest::from_bytes([6; 32]),
        }).unwrap()
    }

    fn encode(original: ProvisioningResourceRecordsV1, missing_edge: bool,
        generation: u64, include_descriptor: bool) -> Result<LifecycleDeleteBatchV1, LifecycleModelError>
    {
        let fields = original.fields_v1();
        let assignment = LifecycleResourceV1::Other(fields.assignment);
        let reservation = LifecycleResourceV1::Other(fields.reservation);
        let sandbox = LifecycleResourceV1::Sandbox(fields.sandbox);
        let assignment_key = original.key_v1(ProvisioningResourceRowKindV1::Assignment);
        let reservation_key = original.key_v1(ProvisioningResourceRowKindV1::Reservation);
        let writes = [
            DeleteBatchWriteDataV1 { resource: sandbox, key: b"a-sandbox",
                before_generation: 2, before_digest: [1; 32] },
            DeleteBatchWriteDataV1 { resource: assignment, key: &assignment_key,
                before_generation: generation, before_digest: native_value_digest(
                    &original.encode_v1(ProvisioningResourceRowKindV1::Assignment)) },
            DeleteBatchWriteDataV1 { resource: reservation, key: &reservation_key,
                before_generation: 1, before_digest: native_value_digest(
                    &original.encode_v1(ProvisioningResourceRowKindV1::Reservation)) },
        ];
        let edges = [
            DeleteBatchDependencyDataV1 { dependent: assignment, dependency: sandbox, class: DeleteDependencyClassDataV2::ProvisioningCompanion.code_v2() },
            DeleteBatchDependencyDataV1 { dependent: assignment, dependency: reservation, class: DeleteDependencyClassDataV2::ProvisioningCompanion.code_v2() },
            DeleteBatchDependencyDataV1 { dependent: reservation, dependency: sandbox, class: DeleteDependencyClassDataV2::ProvisioningCompanion.code_v2() },
        ];
        let postorder = [assignment, reservation, sandbox];
        let input = DeleteBatchEncodingDataV1 {
            project: fields.project, operation: OperationId::from_bytes([20; 16]),
            transaction: [21; 16], root: sandbox, flags: 1, before_sequence: 3,
            authority_epoch: 1, commitments: [[1; 32]; 5],
            owners: std::array::from_fn(|_| DeleteBatchOwnerCutDataV1 {
                sequence: 1, count: 1, digest: [2; 32] }),
            writes: &writes, reads: &[], collections: &[],
            dependencies: &edges[..if missing_edge { 2 } else { 3 }], postorder: &postorder,
        };
        let descriptors = [ProvisioningCompanionRetirementDataV2::from_data_v2(
            original, input.operation, input.transaction).unwrap()];
        LifecycleDeleteBatchV1::from_encoding_with_companions_v2(&input,
            DeleteBatchCommitmentsDataV2 { authorization: [3; 32], source: [4; 32],
                controller: [5; 32], initial_six: [6; 32] }, 41,
            &descriptors[..usize::from(include_descriptor)])
    }

    #[test]
    fn complete_companions_use_two_logical_resources_and_the_exact_three_row_predecessor() {
        let original = original();
        let encoded = encode(original, false, 1, true).unwrap();
        let view = encoded.view().unwrap();
        let descriptor = view.companions_v2().next().unwrap().unwrap();
        let mut state = original.records_v1().into_iter().map(|row|
            ((row.namespace(), row.key().to_vec()), row.value().unwrap().to_vec()))
            .collect::<std::collections::BTreeMap<_, _>>();

        assert_eq!(view.version(), 2);
        assert_eq!(view.count(0), 3);
        assert_eq!(descriptor.original_v1(), original);
        descriptor.require_original_state_v2(&state).unwrap();
        assert_eq!(descriptor.resources_v2(), [
            LifecycleResourceV1::Other(original.fields_v1().assignment),
            LifecycleResourceV1::Other(original.fields_v1().reservation)]);
        assert!(view.rows(0).filter(|row| row[0] == 9).all(|row|
            row[68..100] == native_value_digest(&tombstone(view, row))));

        // Neither two matching resources nor their hash can replace the actual
        // third parent lookup from the same native predecessor map.
        state.remove(&(aos_sandbox_core::RecordNamespace::DesiredState,
            original.key_v1(ProvisioningResourceRowKindV1::Parent).to_vec()));
        assert!(descriptor.require_original_state_v2(&state).is_err());
    }

    #[test]
    fn other_writes_require_the_whole_descriptor_both_edges_and_initial_logical_generation() {
        let original = original();

        assert!(encode(original, true, 1, true).is_err());
        assert!(encode(original, false, 42, true).is_err());
        assert!(encode(original, false, 1, false).is_err());
        assert!(ProvisioningCompanionRetirementDataV2::from_data_v2(original,
            original.fields_v1().parent, [21; 16]).is_err());
    }
}
