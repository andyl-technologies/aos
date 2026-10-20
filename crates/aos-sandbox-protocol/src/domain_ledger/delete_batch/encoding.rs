//! Encodes complete bounded Delete batch DATA using the established grammar.
//!
//! The protected planner supplies original current cuts and canonical rows.
//! Encoding authenticates none of them: native ownership, complete inventory,
//! independent floors, authorization and before/after joins remain upper duties.

use super::*;

/// Names the four V2 comparison commitments in their fixed header order.
///
/// Authorization commits the exact canonical public request/caller/project,
/// protected capability/policy decision and original paired-clock expiry.
/// Source commits its held predecessor and complete canonical Tree, Lineage
/// and policy projection before Planned. Controller commits the entire C17
/// claim and actual native predecessor. Initial six commits all six complete
/// named planning observations, including their native boundaries, generation
/// and endpoints. A digest is never a substitute for its retained original.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteBatchCommitmentsDataV2 {
    /// Commits the same retained authorization and its original horizon.
    pub authorization: [u8; 32],
    /// Commits the complete canonical Source predecessor before Planned.
    pub source: [u8; 32],
    /// Commits the entire actual C17 claim and Controller predecessor.
    pub controller: [u8; 32],
    /// Commits the complete six planning observations and their provenance.
    pub initial_six: [u8; 32],
}

impl DeleteBatchCommitmentsDataV2 {
    fn header_slots(self, request: [u8; 32]) -> [[u8; 32]; 5] {
        [request, self.authorization, self.source, self.controller, self.initial_six]
    }
}

/// Supplies the six fixed descriptor slots as canonical comparison DATA.
#[derive(Clone, Copy)]
pub struct DeleteBatchOwnerCutDataV1 {
    /// Records the original owner's native sequence.
    pub sequence: u64,
    /// Records its complete selected row count.
    pub count: u32,
    /// Commits its exact original selected inventory.
    pub digest: [u8; 32],
}

/// Supplies one written resource's exact original projection.
#[derive(Clone, Copy)]
pub struct DeleteBatchWriteDataV1<'bytes> {
    /// Names the exact resource whose admission will be revoked.
    pub resource: LifecycleResourceV1,
    /// Borrows its canonical DesiredState projection key.
    pub key: &'bytes [u8],
    /// Records the exact original generation.
    pub before_generation: u64,
    /// Commits the complete original projection bytes.
    pub before_digest: [u8; 32],
}

/// Supplies one dependency whose exact original value is read without writing it.
#[derive(Clone, Copy)]
pub struct DeleteBatchReadDataV1<'bytes> {
    /// Names the dependency resource.
    pub resource: LifecycleResourceV1,
    /// Selects its established canonical journal namespace.
    pub namespace: u8,
    /// Borrows its exact native key.
    pub key: &'bytes [u8],
    /// Commits its original value, or records actual absence.
    pub before_digest: Option<[u8; 32]>,
}

/// Supplies an exact collection predecessor and proposed successor commitment.
#[derive(Clone, Copy)]
pub struct DeleteBatchCollectionDataV1<'bytes> {
    /// Names the resource owning this complete collection.
    pub resource: LifecycleResourceV1,
    /// Selects the established collection class.
    pub class: u8,
    /// Borrows its complete canonical collection key.
    pub key: &'bytes [u8],
    /// Records the original collection generation.
    pub before_generation: u64,
    /// Commits the original complete membership.
    pub before_digest: [u8; 32],
    /// Commits the complete proposed membership after pending overlays.
    pub after_digest: [u8; 32],
}

/// Supplies one typed dependent-before-dependency graph edge.
#[derive(Clone, Copy)]
pub struct DeleteBatchDependencyDataV1 {
    /// Names the resource that must be removed first.
    pub dependent: LifecycleResourceV1,
    /// Names the referenced resource that must remain until then.
    pub dependency: LifecycleResourceV1,
    /// Selects its established dependency class.
    pub class: u8,
}

/// Borrows a complete non-authorizing batch for one checked encoding.
///
/// The five header commitments and six descriptor slots keep their established
/// order. Their protected producer must derive and join each original; this
/// structure has no accepted-operation, currentness or append authority.
pub struct DeleteBatchEncodingDataV1<'rows, 'bytes> {
    /// Names the authenticated project partition.
    pub project: ProjectId,
    /// Names the original admitted or proposed operation.
    pub operation: OperationId,
    /// Names its exact proposed native transaction.
    pub transaction: [u8; 16],
    /// Names the root Sandbox resource.
    pub root: LifecycleResourceV1,
    /// Contains only the canonical cascade and force bits.
    pub flags: u8,
    /// Records the Controller's original native predecessor sequence.
    pub before_sequence: u64,
    /// Records V1's historical graph epoch; the V2 encoder ignores this field.
    pub authority_epoch: u64,
    /// Supplies request digest followed by the four original header commitments.
    pub commitments: [[u8; 32]; 5],
    /// Supplies each complete descriptor in its established slot order.
    pub owners: [DeleteBatchOwnerCutDataV1; 6],
    /// Borrows exact written resources in canonical native key order.
    pub writes: &'rows [DeleteBatchWriteDataV1<'bytes>],
    /// Borrows exact read dependencies in canonical namespace/key order.
    pub reads: &'rows [DeleteBatchReadDataV1<'bytes>],
    /// Borrows complete collection mutations in canonical key order.
    pub collections: &'rows [DeleteBatchCollectionDataV1<'bytes>],
    /// Borrows the complete canonical edge set.
    pub dependencies: &'rows [DeleteBatchDependencyDataV1],
    /// Borrows the complete dependent-before-dependency postorder.
    pub postorder: &'rows [LifecycleResourceV1],
}

impl DeleteBatchEncodingDataV1<'_, '_> {
    /// Checks all row and output bounds before the encoder allocates bytes.
    ///
    /// This exact length is comparison DATA for the actual caller's prepayment.
    /// It authenticates no supplied row and excludes the separate canonical
    /// graph validator's bounded scratch and the caller's retained models.
    ///
    /// # Errors
    ///
    /// Refuses oversized counts, empty or oversized keys, exhausted predecessor
    /// generations, arithmetic overflow, or an output beyond the wire limit.
    pub fn encoded_length_v1(&self) -> Result<usize, LifecycleModelError> {
        let counts = self.counts();
        if counts.iter().any(|count| *count > MAXIMUM_ROWS)
            || counts[0] == 0
            || counts[4] != counts[0]
            || counts[..3].iter().try_fold(0usize, |sum, count| sum.checked_add(*count))
                .is_none_or(|total| total > MAXIMUM_ROWS)
        {
            return Err(corrupt());
        }

        let mut length = HEADER_BYTES.checked_add(32).ok_or_else(corrupt)?;
        for row in self.writes {
            length = row_length(length, 100, row.key)?;
            successor_generation(row.before_generation)?;
        }
        for row in self.reads {
            length = row_length(length, 56, row.key)?;
        }
        for row in self.collections {
            length = row_length(length, 100, row.key)?;
            successor_generation(row.before_generation)?;
        }
        length = length.checked_add(counts[3].checked_mul(36).ok_or_else(corrupt)?)
            .and_then(|total| total.checked_add(counts[4].checked_mul(17)?))
            .filter(|total| *total <= MAXIMUM_BYTES)
            .ok_or_else(corrupt)?;
        Ok(length)
    }

    fn counts(&self) -> [usize; 5] {
        [self.writes.len(), self.reads.len(), self.collections.len(),
            self.dependencies.len(), self.postorder.len()]
    }
}

impl LifecycleDeleteBatchV1 {
    /// Encodes complete bounded DATA with canonical tombstones and graph digest.
    ///
    /// Every count, variable key and total byte bound is checked before the
    /// output allocation. The established decoder remains the sole complete
    /// canonical graph validator. Encoding succeeds without authenticating any
    /// supplied current cut, expected graph, owner or physical obligation.
    ///
    /// # Errors
    ///
    /// Returns an encoding error for exceeded bounds, exhausted generations or
    /// noncanonical complete DATA. Returns an allocation error when checked
    /// reservation of the bounded output or graph work fails.
    pub fn from_encoding_data_v1(
        input: &DeleteBatchEncodingDataV1<'_, '_>,
    ) -> Result<Self, LifecycleModelError> {
        Self::encode_version(input, 1, input.commitments, &[], None, None)
    }

    /// Encodes the explicit V2 named-cut grammar through the same row engine.
    ///
    /// The first input commitment remains the exact request digest; V1's four
    /// unnamed slots are ignored and replaced by the explicitly named values.
    /// Header96..104 records `source_predecessor_next_sequence`; V1's epoch
    /// input is ignored. The actual native caller must supply the held Source
    /// NEXT before Planned, and Root independently compares its BEGIN prefix.
    /// Native ownership and independent currentness remain upper obligations.
    ///
    /// # Errors
    /// Rejects zero commitments, exceeded bounds, noncanonical graph/rows,
    /// exhausted generations or failed checked allocation.
    pub fn from_encoding_data_v2(
        input: &DeleteBatchEncodingDataV1<'_, '_>,
        commitments: DeleteBatchCommitmentsDataV2,
        source_predecessor_next_sequence: u64,
    ) -> Result<Self, LifecycleModelError> {
        Self::from_encoding_with_companions_v2(
            input, commitments, source_predecessor_next_sequence, &[],
        )
    }

    /// Encodes a V2 graph with exact original provisioning companion sets.
    ///
    /// Both logical Other IDs must occur in W with their sole canonical keys,
    /// values and initial generations. Each descriptor also requires the exact
    /// assignment-to-Sandbox/reservation and reservation-to-Sandbox edges. Native
    /// admission independently compares all three live predecessor rows.
    ///
    /// # Errors
    /// Rejects malformed, duplicate, foreign or incomplete companion sets, row
    /// bounds, graph order, arithmetic overflow or failed checked allocation.
    pub fn from_encoding_with_companions_v2(
        input: &DeleteBatchEncodingDataV1<'_, '_>,
        commitments: DeleteBatchCommitmentsDataV2,
        source_predecessor_next_sequence: u64,
        companions: &[super::super::provisioning_resources::ProvisioningCompanionRetirementDataV2],
    ) -> Result<Self, LifecycleModelError> {
        let owners = input.owners.map(|owner| DeleteBatchOwnerCutDataV2 {
            boundary: DeleteBatchNativeBoundaryDataV2::JournalPrefix { next_sequence: owner.sequence },
            count: owner.count,
            digest: owner.digest,
        });
        Self::from_encoding_with_native_cuts_v2(
            input, commitments, source_predecessor_next_sequence, owners, companions,
        )
    }

    /// Encodes six explicitly typed native-boundary comparison cuts through V2.
    ///
    /// Every journal cut records its actual native NEXT. A default-local
    /// Transfer absence instead records the actual retained directory inode;
    /// its full native/trust preimage remains committed by that slot digest.
    /// Supplied DATA cannot prove those observations or construct six owners.
    ///
    /// # Errors
    /// Rejects invalid role/boundary combinations, absent coordinates, invalid
    /// counts/digests, noncanonical graph/companions, bounds or allocation failure.
    pub fn from_encoding_with_native_cuts_v2(
        input: &DeleteBatchEncodingDataV1<'_, '_>,
        commitments: DeleteBatchCommitmentsDataV2,
        source_predecessor_next_sequence: u64,
        owners: [DeleteBatchOwnerCutDataV2; 6],
        companions: &[super::super::provisioning_resources::ProvisioningCompanionRetirementDataV2],
    ) -> Result<Self, LifecycleModelError> {
        if source_predecessor_next_sequence == 0
            || source_predecessor_next_sequence == u64::MAX
        {
            return Err(corrupt());
        }
        Self::encode_version(input, 2,
            commitments.header_slots(input.commitments[0]), companions, Some(&owners),
            Some(source_predecessor_next_sequence))
    }

    fn encode_version(
        input: &DeleteBatchEncodingDataV1<'_, '_>,
        version: u8,
        commitments: [[u8; 32]; 5],
        companions: &[super::super::provisioning_resources::ProvisioningCompanionRetirementDataV2],
        native_cuts: Option<&[DeleteBatchOwnerCutDataV2; 6]>,
        source_predecessor_next_sequence: Option<u64>,
    ) -> Result<Self, LifecycleModelError> {
        if let Some(owners) = native_cuts {
            for (index, owner) in owners.iter().enumerate() {
                owner.require_role_v2((index + 1) as u8)?;
            }
        }
        let length = input.encoded_length_with_companions_v2(companions.len())?;
        let counts = input.counts();

        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|_| LifecycleModelError::Allocation)?;
        bytes.resize(HEADER_BYTES, 0);
        bytes[..8].copy_from_slice(if version == 2 { b"AOSDEL02" } else { b"AOSDEL01" });
        bytes[9] = version;
        bytes[10] = input.flags;
        bytes[12..16].copy_from_slice(&(length as u32).to_be_bytes());
        bytes[16..32].copy_from_slice(input.project.as_bytes());
        bytes[32..48].copy_from_slice(input.operation.as_bytes());
        bytes[48..64].copy_from_slice(&input.transaction);
        write_resource(&mut bytes[64..81], input.root);
        bytes[88..96].copy_from_slice(&input.before_sequence.to_be_bytes());
        // V1 retains its historical field literally. Production V2 records
        // the actual Source BEGIN predecessor, independently reread by Root.
        bytes[96..104].copy_from_slice(
            &source_predecessor_next_sequence.unwrap_or(input.authority_epoch).to_be_bytes(),
        );
        for (slot, digest) in bytes[104..264].chunks_exact_mut(32).zip(&commitments) {
            slot.copy_from_slice(digest);
        }
        for (slot, count) in bytes[296..316].chunks_exact_mut(4).zip(counts) {
            slot.copy_from_slice(&(count as u32).to_be_bytes());
        }
        bytes[316..320].copy_from_slice(&(companions.len() as u32).to_be_bytes());
        for (index, (slot, owner)) in bytes[320..608].chunks_exact_mut(48)
            .zip(&input.owners).enumerate()
        {
            slot[0] = (index + 1) as u8;
            slot[4..12].copy_from_slice(&owner.sequence.to_be_bytes());
            slot[12..16].copy_from_slice(&owner.count.to_be_bytes());
            slot[16..48].copy_from_slice(&owner.digest);
            if let Some(owners) = native_cuts {
                owners[index].write_descriptor_v2((index + 1) as u8, slot);
            }
        }

        let mut boundaries = [HEADER_BYTES; 6];
        for row in input.writes {
            append_mutation(&mut bytes, row.resource, 1, row.key,
                row.before_generation, row.before_digest, [0; 32])?;
        }
        boundaries[1] = bytes.len();
        for row in input.reads {
            let mut fixed = [0; 56];
            write_resource(&mut fixed[..17], row.resource);
            fixed[17] = row.namespace;
            fixed[18..20].copy_from_slice(&(row.key.len() as u16).to_be_bytes());
            if let Some(digest) = row.before_digest {
                fixed[20] = 1;
                fixed[24..56].copy_from_slice(&digest);
            }
            bytes.extend_from_slice(&fixed);
            bytes.extend_from_slice(row.key);
        }
        boundaries[2] = bytes.len();
        for row in input.collections {
            append_mutation(&mut bytes, row.resource, row.class, row.key,
                row.before_generation, row.before_digest, row.after_digest)?;
        }
        boundaries[3] = bytes.len();
        for row in input.dependencies {
            let mut fixed = [0; 36];
            write_resource(&mut fixed[..17], row.dependent);
            write_resource(&mut fixed[17..34], row.dependency);
            fixed[34] = row.class;
            bytes.extend_from_slice(&fixed);
        }
        boundaries[4] = bytes.len();
        for resource in input.postorder {
            let mut fixed = [0; 17];
            write_resource(&mut fixed, *resource);
            bytes.extend_from_slice(&fixed);
        }
        boundaries[5] = bytes.len();
        for companion in companions {
            bytes.extend_from_slice(&companion.encode_v2());
        }
        bytes.extend_from_slice(&[0; 32]);
        if bytes.len() != length {
            return Err(corrupt());
        }

        // Tombstones commit the real transaction, resource and predecessor.
        // Their hashes do not depend on the graph digest, avoiding a hash cycle.
        let mut offset = HEADER_BYTES;
        for row in input.writes {
            let end = offset + 100 + row.key.len();
            let digest = {
                let view = encoded_view(&bytes, boundaries, counts);
                native_value_digest(&tombstone(view, &bytes[offset..end]))
            };
            bytes[offset + 68..offset + 100].copy_from_slice(&digest);
            offset = end;
        }
        let graph = encoded_view(&bytes, boundaries, counts).graph_digest();
        bytes[264..296].copy_from_slice(&graph);
        seal(&mut bytes, if version == 2 { BATCH_DOMAIN_V2 } else { BATCH_DOMAIN });

        DeleteBatchViewV1::decode(&bytes)?;
        Ok(Self { bytes, project: input.project, operation: input.operation })
    }
}

impl LifecycleDeleteBatchRecordV1 {
    /// Moves a canonical batch into its initial Source Planned DATA record.
    ///
    /// The native proof is absent in this state. The record grants no Source
    /// append, Controller acceptance, currentness or deletion authority.
    pub fn planned_v1(batch: LifecycleDeleteBatchV1) -> Self {
        Self { state: 1, batch, native_proof: [0; 64] }
    }
}

fn row_length(total: usize, fixed: usize, key: &[u8]) -> Result<usize, LifecycleModelError> {
    if key.is_empty() || key.len() > 1024 {
        return Err(corrupt());
    }
    total.checked_add(fixed).and_then(|value| value.checked_add(key.len()))
        .filter(|value| *value <= MAXIMUM_BYTES).ok_or_else(corrupt)
}

fn successor_generation(before: u64) -> Result<u64, LifecycleModelError> {
    before.checked_add(1).filter(|after| successor(before, *after)).ok_or_else(corrupt)
}

fn write_resource(destination: &mut [u8], resource: LifecycleResourceV1) {
    destination[0] = resource.code();
    destination[1..17].copy_from_slice(resource.as_bytes());
}

fn append_mutation(
    bytes: &mut Vec<u8>, resource: LifecycleResourceV1, selector: u8, key: &[u8],
    before_generation: u64, before_digest: [u8; 32], after_digest: [u8; 32],
) -> Result<(), LifecycleModelError> {
    let after_generation = successor_generation(before_generation)?;
    let mut fixed = [0; 100];
    write_resource(&mut fixed[..17], resource);
    fixed[17] = selector;
    fixed[18..20].copy_from_slice(&(key.len() as u16).to_be_bytes());
    fixed[20..28].copy_from_slice(&before_generation.to_be_bytes());
    fixed[28..60].copy_from_slice(&before_digest);
    fixed[60..68].copy_from_slice(&after_generation.to_be_bytes());
    fixed[68..100].copy_from_slice(&after_digest);
    bytes.extend_from_slice(&fixed);
    bytes.extend_from_slice(key);
    Ok(())
}

fn encoded_view<'bytes>(
    bytes: &'bytes [u8], boundaries: [usize; 6], counts: [usize; 5],
) -> DeleteBatchViewV1<'bytes> {
    // Only this encoder's checked construction can call this helper. Exact
    // section widths and key lengths were established before the allocation.
    DeleteBatchViewV1 {
        bytes,
        sections: std::array::from_fn(|index| &bytes[boundaries[index]..boundaries[index + 1]]),
        counts,
        companions: &bytes[boundaries[5]..bytes.len() - 32],
    }
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::SandboxId;

    use super::*;

    fn input<'rows, 'bytes>(
        writes: &'rows [DeleteBatchWriteDataV1<'bytes>],
        dependencies: &'rows [DeleteBatchDependencyDataV1],
        postorder: &'rows [LifecycleResourceV1],
    ) -> DeleteBatchEncodingDataV1<'rows, 'bytes> {
        DeleteBatchEncodingDataV1 {
            project: ProjectId::from_bytes([4; 16]),
            operation: OperationId::from_bytes([5; 16]),
            transaction: [6; 16],
            root: LifecycleResourceV1::Sandbox(SandboxId::from_bytes([7; 16])),
            flags: 0,
            before_sequence: 1,
            authority_epoch: 1,
            commitments: [[8; 32]; 5],
            owners: std::array::from_fn(|index| DeleteBatchOwnerCutDataV1 {
                sequence: 1, count: 0, digest: [10 + index as u8; 32],
            }),
            writes,
            reads: &[],
            collections: &[],
            dependencies,
            postorder,
        }
    }

    #[test]
    fn production_encoder_preserves_the_established_single_resource_wire_image() {
        let root = LifecycleResourceV1::Sandbox(SandboxId::from_bytes([7; 16]));
        let writes = [DeleteBatchWriteDataV1 {
            resource: root,
            key: b"projection",
            before_generation: 1,
            before_digest: native_value_digest(b"retained before"),
        }];
        let postorder = [root];
        let data = input(&writes, &[], &postorder);

        let encoded = LifecycleDeleteBatchV1::from_encoding_data_v1(&data).unwrap();

        assert_eq!(encoded.as_bytes().len(), data.encoded_length_v1().unwrap());
        assert_eq!(encoded.as_bytes(), fixture_batch_v1(b"projection", b"retained before", 1));
        let planned = LifecycleDeleteBatchRecordV1::planned_v1(encoded);
        let bytes = planned.encode().unwrap();
        let replayed = LifecycleDeleteBatchRecordV1::from_bytes(&bytes).unwrap();
        assert_eq!(replayed, planned);
        assert_eq!(replayed.state(), 1);
        assert_eq!(replayed.native_proof(), &[0; 64]);
    }

    #[test]
    fn dependency_order_and_derived_tombstones_are_validated_together() {
        let root = LifecycleResourceV1::Sandbox(SandboxId::from_bytes([7; 16]));
        let child = LifecycleResourceV1::Sandbox(SandboxId::from_bytes([9; 16]));
        let writes = [
            DeleteBatchWriteDataV1 {
                resource: root, key: b"a", before_generation: 1, before_digest: [1; 32],
            },
            DeleteBatchWriteDataV1 {
                resource: child, key: b"b", before_generation: 3, before_digest: [2; 32],
            },
        ];
        let dependencies = [DeleteBatchDependencyDataV1 {
            dependent: child, dependency: root, class: 1,
        }];
        let postorder = [child, root];
        let data = input(&writes, &dependencies, &postorder);

        let encoded = LifecycleDeleteBatchV1::from_encoding_data_v1(&data).unwrap();
        let view = encoded.view().unwrap();

        for row in view.rows(0) {
            assert_eq!(row[68..100], native_value_digest(&tombstone(view, row)));
        }
        assert_eq!(view.rows(4).last().unwrap()[1..], root.as_bytes()[..]);
        let stale_order = [root, child];
        let stale = input(&writes, &dependencies, &stale_order);
        assert!(LifecycleDeleteBatchV1::from_encoding_data_v1(&stale).is_err());
    }

    #[test]
    fn oversized_keys_and_exhausted_predecessors_never_enter_output_construction() {
        let root = LifecycleResourceV1::Sandbox(SandboxId::from_bytes([7; 16]));
        let key = [b'x'; 1025];
        let mut writes = [DeleteBatchWriteDataV1 {
            resource: root, key: &key, before_generation: 1, before_digest: [1; 32],
        }];
        let postorder = [root];

        assert!(LifecycleDeleteBatchV1::from_encoding_data_v1(&input(&writes, &[], &postorder)).is_err());
        writes[0].key = b"projection";
        writes[0].before_generation = u64::MAX - 1;
        assert!(LifecycleDeleteBatchV1::from_encoding_data_v1(&input(&writes, &[], &postorder)).is_err());
    }

    #[test]
    fn current_request_comparison_preserves_omission_and_rejects_substitution() {
        let root = LifecycleResourceV1::Sandbox(SandboxId::from_bytes([7; 16]));
        let writes = [DeleteBatchWriteDataV1 {
            resource: root, key: b"projection", before_generation: 1,
            before_digest: native_value_digest(b"retained before"),
        }];
        let postorder = [root];
        let data = input(&writes, &[], &postorder);
        let cuts = DeleteBatchCommitmentsDataV2 {
            authorization: [21; 32], source: [22; 32], controller: [23; 32], initial_six: [24; 32],
        };
        let batch = LifecycleDeleteBatchV1::from_encoding_data_v2(&data, cuts, 41).unwrap();
        let view = batch.view().unwrap();
        let mut request = aos_proto::aos::sandbox::v1::DeleteSandboxRequest::default();
        request.sandbox_id = SandboxId::from_bytes([7; 16]).as_bytes().to_vec();
        request.cascade = view.flags() & 1 != 0;
        request.force = view.flags() & 2 != 0;

        assert!(view.require_public_request_v2(&request).is_ok());
        assert!(request.expected_plan_digest.is_empty());
        request.expected_plan_digest = view.graph_plan().to_vec();
        assert!(view.require_public_request_v2(&request).is_ok());

        request.expected_plan_digest[0] ^= 1;
        assert!(view.require_public_request_v2(&request).is_err());
        request.expected_plan_digest.clear();
        request.sandbox_id[0] ^= 1;
        assert!(view.require_public_request_v2(&request).is_err());
        request.sandbox_id[0] ^= 1;
        request.force = !request.force;
        assert!(view.require_public_request_v2(&request).is_err());
        request.force = !request.force;
        request.cascade = !request.cascade;
        assert!(view.require_public_request_v2(&request).is_err());

        let historical = LifecycleDeleteBatchV1::from_encoding_data_v1(&data).unwrap();
        assert!(historical.view().unwrap().require_public_request_v2(&request).is_err());
    }

    #[test]
    fn version_two_names_cuts_without_creating_a_self_referential_expected_graph() {
        let root = LifecycleResourceV1::Sandbox(SandboxId::from_bytes([7; 16]));
        let child = LifecycleResourceV1::Sandbox(SandboxId::from_bytes([9; 16]));
        let writes = [
            DeleteBatchWriteDataV1 {
                resource: root, key: b"a", before_generation: 1, before_digest: [1; 32],
            },
            DeleteBatchWriteDataV1 {
                resource: child, key: b"b", before_generation: 1, before_digest: [2; 32],
            },
        ];
        let dependencies = [DeleteBatchDependencyDataV1 {
            dependent: child, dependency: root, class: DeleteDependencyClassDataV2::SandboxParent.code_v2(),
        }];
        let postorder = [child, root];
        let data = input(&writes, &dependencies, &postorder);
        let cuts = DeleteBatchCommitmentsDataV2 {
            authorization: [21; 32], source: [22; 32], controller: [23; 32], initial_six: [24; 32],
        };

        // Historical V1 retains its literal class range. The current V2
        // parser must reject a resealed class whose typed endpoints differ.
        let cross_kind = [DeleteBatchDependencyDataV1 {
            dependent: child, dependency: root,
            class: DeleteDependencyClassDataV2::ExecutionOwner.code_v2(),
        }];
        let cross_kind_data = input(&writes, &cross_kind, &postorder);
        assert!(LifecycleDeleteBatchV1::from_encoding_data_v1(&cross_kind_data).is_ok());
        assert!(LifecycleDeleteBatchV1::from_encoding_data_v2(&cross_kind_data, cuts, 41).is_err());

        let legacy = LifecycleDeleteBatchV1::from_encoding_data_v1(&data).unwrap();
        assert_eq!(legacy.view().unwrap().named_commitments_v2(), None);
        let batch = LifecycleDeleteBatchV1::from_encoding_data_v2(&data, cuts, 41).unwrap();
        let view = batch.view().unwrap();
        assert_eq!(view.version(), 2);
        assert_eq!(view.named_commitments_v2(), Some(cuts));
        assert_eq!(view.source_predecessor_next_sequence_v2(), Some(41));
        assert_eq!(legacy.view().unwrap().source_predecessor_next_sequence_v2(), None);
        assert!(LifecycleDeleteBatchV1::from_encoding_data_v2(&data, cuts, 0).is_err());
        assert!(LifecycleDeleteBatchV1::from_encoding_data_v2(&data, cuts, u64::MAX).is_err());
        assert_ne!(legacy.view().unwrap().graph_plan(), view.graph_plan());

        let mut changed = cuts;
        changed.authorization = [25; 32];
        let other = LifecycleDeleteBatchV1::from_encoding_data_v2(&data, changed, 41).unwrap();
        assert_ne!(batch.as_bytes(), other.as_bytes());
        assert_eq!(view.graph_plan(), other.view().unwrap().graph_plan());
        let historical = fixture_batch_v1(b"projection", b"retained before", 1);
        let historical_view = DeleteBatchViewV1::decode(&historical).unwrap();
        assert_eq!(historical_view.version(), 1);
        assert_eq!(historical_view.named_commitments_v2(), None);
    }


    #[test]
    fn production_v2_encoder_preserves_explicit_native_boundary_interpretation() {
        let root = LifecycleResourceV1::Sandbox(SandboxId::from_bytes([7; 16]));
        let writes = [DeleteBatchWriteDataV1 {
            resource: root, key: b"projection", before_generation: 1, before_digest: [1; 32],
        }];
        let postorder = [root];
        let data = input(&writes, &[], &postorder);
        let commitments = DeleteBatchCommitmentsDataV2 {
            authorization: [2; 32], source: [3; 32], controller: [4; 32], initial_six: [5; 32],
        };
        let mut owners = std::array::from_fn(|index| DeleteBatchOwnerCutDataV2 {
            boundary: DeleteBatchNativeBoundaryDataV2::JournalPrefix { next_sequence: index as u64 + 1 },
            count: 0, digest: [index as u8 + 20; 32],
        });
        owners[5].boundary = DeleteBatchNativeBoundaryDataV2::RootNamespaceAbsence { directory_inode: 73 };

        let encoded = LifecycleDeleteBatchV1::from_encoding_with_native_cuts_v2(
            &data, commitments, 41, owners, &[]).unwrap();
        let view = encoded.view().unwrap();
        for role in 1..=6 {
            assert_eq!(view.native_owner_cut_v2(role).unwrap(), owners[usize::from(role) - 1]);
        }
        for invalid in [0u64, u64::MAX] {
            let mut changed = encoded.as_bytes().to_vec();
            changed[96..104].copy_from_slice(&invalid.to_be_bytes());
            seal(&mut changed, BATCH_DOMAIN_V2);
            assert!(DeleteBatchViewV1::decode(&changed).is_err());
        }
        let historical = LifecycleDeleteBatchV1::from_encoding_data_v1(&data).unwrap();
        assert!(historical.view().unwrap().native_owner_cut_v2(1).is_err());
    }

}
