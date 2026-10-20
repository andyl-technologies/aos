//! Borrows the closed canonical report without allocating another JSON tree.
//!
//! Every view points into the actual immutable report body retained by the same
//! controller. Parsing establishes data syntax only. Original source, selected
//! native receipt, live kernel/actor and full allocation admission remain
//! independent. Fixed field rosters reject unknown, duplicate and reordered
//! keys; this is the selected producer's canonical content format, not generic
//! transport JSON spelling.

use super::super::{
    PacketNative5ProtocolMetadataBankFacts, PacketNative5ProtocolMetadataBirthFacts,
};
use super::*;
use crate::protocol_snapshot::owned11::{
    OriginalOwned11Fields as Fields, original_owned11_plain_string as string,
    original_owned11_unsigned as unsigned,
};
use crucible_node_format::Phase;
use std::mem::size_of;

#[derive(Clone, Copy)]
struct Hash<'a> {
    domain: &'a str,
    digest: &'a str,
}

impl Hash<'_> {
    fn matches(&self, expected: &HashRef) -> bool {
        expected.algorithm == "blake3-256"
            && self.domain == expected.domain
            && self.digest == expected.digest
    }

    fn matches_digest(&self, expected: &[u8; 32]) -> bool {
        self.digest
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .zip(expected)
            .all(|(hex, byte)| digit(hex[0]) * 16 + digit(hex[1]) == *byte)
    }
}

struct Scope<'a> {
    activation: &'a str,
    binding_hash: Hash<'a>,
    control_originals_before: U64,
    endpoint_records_before: U64,
    incarnation: &'a str,
    model_cursor: Position,
    native_pid: U64,
    node: &'a str,
    observe_hash: Hash<'a>,
    observe_request: &'a str,
    observe_sequence: U64,
    owner: &'a str,
    owner_generation: U64,
    provider_next_sequence_before: U64,
    session: &'a str,
    world: Hash<'a>,
    world_generation: U64,
}

/// Borrows one complete closed allocation report from retained immutable bytes.
///
/// This view is correlation and requested-storage data. It grants no current
/// model, memory budget, Capture, acknowledgement or restoration permission.
pub struct PacketNativeCaptureAllocationReportView<'a> {
    bytes: &'a [u8],
    scope: Scope<'a>,
    before: PacketNativeCaptureProtocolAllocation,
    after: PacketNativeCaptureProtocolAllocation,
    metadata: PacketNative5ProtocolMetadataBirthFacts,
    retained: U64,
    shared_edges: U64,
    unique_roots: U64,
    growth: PacketNativeCaptureRetainedGrowth,
    transients: PacketNativeCaptureTransients,
}

impl<'a> PacketNativeCaptureAllocationReportView<'a> {
    /// Borrows the exact canonical report grammar without a DOM or owned clone.
    ///
    /// # Errors
    /// Refuses oversized, incomplete, noncanonical or unknown data; invalid
    /// identifiers/hashes/physical row facts; and checked requested sum overflow.
    pub fn from_original_bytes(bytes: &'a [u8]) -> Result<Self, ProviderError> {
        if bytes.is_empty()
            || bytes.len() > MAXIMUM_NATIVE_CAPTURE_ALLOCATION_REPORT_BYTES
            || bytes.iter().any(u8::is_ascii_whitespace)
        {
            return Err(invalid());
        }
        let [
            after,
            before,
            growth,
            metadata,
            retained,
            schema,
            scope,
            edges,
            transients,
            roots,
        ] = object(
            bytes,
            &[
                "after",
                "before",
                "growth",
                "metadata_banks",
                "retained_requested_bytes",
                "schema",
                "scope",
                "shared_edges",
                "transients",
                "unique_roots",
            ],
        )?;
        if string(schema)? != PACKET_NATIVE_CAPTURE_ALLOCATION_REPORT {
            return Err(invalid());
        }
        let view = Self {
            bytes,
            scope: scope_data(scope)?,
            before: protocol(before)?,
            after: protocol(after)?,
            metadata: metadata_data(metadata)?,
            retained: number(retained)?,
            shared_edges: number(edges)?,
            unique_roots: number(roots)?,
            growth: growth_data(growth)?,
            transients: transient_data(transients)?,
        };
        view.validate_data()?;
        Ok(view)
    }

    /// Borrows the complete original body without copying it.
    pub fn original_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the same original typed bank facts without allocating children.
    pub fn metadata_banks_data(&self) -> PacketNative5ProtocolMetadataBirthFacts {
        self.metadata
    }

    /// Returns the producer's checked requested peak as data only.
    ///
    /// # Errors
    /// Refuses checked arithmetic overflow.
    pub fn requested_peak_data(&self) -> Result<U64, ProviderError> {
        requested_sum(self.retained, &self.growth, &self.transients)
    }

    /// Borrows the exact activation identity reported at the original cut.
    pub fn activation_data(&self) -> &str {
        self.scope.activation
    }

    /// Returns the original world generation reported by the native producer.
    pub fn world_generation_data(&self) -> U64 {
        self.scope.world_generation
    }

    /// Returns the original local model cursor without changing it.
    pub fn model_cursor_data(&self) -> Position {
        self.scope.model_cursor
    }

    /// Returns the exact Control original count before this Observe.
    pub fn control_originals_before_data(&self) -> U64 {
        self.scope.control_originals_before
    }

    /// Returns the endpoint record population before publication, as data only.
    pub fn endpoint_records_before_data(&self) -> U64 {
        self.scope.endpoint_records_before
    }

    /// Returns the first provider sequence reserved for the original proof.
    pub fn provider_next_sequence_before_data(&self) -> U64 {
        self.scope.provider_next_sequence_before
    }

    /// Joins all report scope identities to the same authenticated inner receipt.
    ///
    /// `original_digest` is measured from that controller's actual complete sent
    /// literal. Source separately verifies the unchanged raw record, selected
    /// physical storage, activation, original/current frontier and kernel custody.
    ///
    /// # Errors
    /// Refuses any changed request, native actor, full binding/world hash, owner
    /// generation, or exact original literal commitment.
    pub fn authenticate_receipt_data(
        &self,
        receipt: &PacketNative5Record,
        original_digest: &[u8; 32],
    ) -> Result<(), ProviderError> {
        let s = &self.scope;
        if receipt.original.method != Method::Observe
            || receipt.original.message != MessageKind::Request
            || s.native_pid != receipt.native_pid
            || s.session != receipt.session.as_str()
            || s.incarnation != receipt.incarnation.as_str()
            || s.node != receipt.node.as_str()
            || s.owner != receipt.owner.as_str()
            || s.owner_generation != receipt.owner_generation
            || !s.binding_hash.matches(&receipt.binding_hash)
            || !s.world.matches(&receipt.world)
            || receipt
                .original
                .request_id
                .0
                .as_ref()
                .is_none_or(|id| id.as_str() != s.observe_request)
            || receipt.original.sequence != s.observe_sequence
            || !s.observe_hash.matches_digest(original_digest)
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn validate_data(&self) -> Result<(), ProviderError> {
        let s = &self.scope;
        if s.native_pid.get() == 0
            || s.observe_sequence.get() == 0
            || s.provider_next_sequence_before.get() == 0
            || s.observe_hash.domain != NATIVE_CAPTURE_ALLOCATION_OBSERVE_DOMAIN
            || self.unique_roots.get() == 0
            || self.unique_roots > self.shared_edges
            || self.retained.get() == 0
            || self.before.current_encoded_bytes > self.before.encoded_capacity
            || self.after.current_encoded_bytes > self.after.encoded_capacity
        {
            return Err(invalid());
        }
        self.metadata
            .validate_data(&PacketNative5ProtocolMetadataLimits {
                native_before_rows: self.metadata.before.selected_rows,
                native_after_rows: self.metadata.after.selected_rows,
            })?;
        let bytes = [
            self.before.encoded_capacity,
            self.before.literal_and_descriptor_bytes,
            self.after.encoded_capacity,
            self.after.literal_and_descriptor_bytes,
            self.metadata.before.record_bytes,
            self.metadata.before.alias_row_bytes,
            self.metadata.before.alias_lookup_bytes,
            self.metadata.after.record_bytes,
            self.metadata.after.alias_row_bytes,
            self.metadata.after.alias_lookup_bytes,
        ]
        .into_iter()
        .try_fold(0u64, |total, value| {
            total.checked_add(value.get()).ok_or_else(invalid)
        })?;
        if bytes > self.retained.get() {
            return Err(invalid());
        }
        self.requested_peak_data()?;
        Ok(())
    }
}

/// Counts explicit borrowed-view, field-cursor, hash and numeric result headers.
///
/// This getter allocates nothing and grants no permission. Compiler frames,
/// allocator/kernel bookkeeping and Source's existing receipt decoder are separate.
pub fn original_capture_allocation_report_counter_scratch_data() -> usize {
    size_of::<PacketNativeCaptureAllocationReportView<'static>>()
        + size_of::<Scope<'static>>()
        + 4 * size_of::<Fields<'static>>()
        // Top-level spans remain live while scope fields and a nested hash
        // are parsed. Count all three layers explicitly; unrelated view/field
        // headers are not credit for these simultaneous borrowed arrays.
        + size_of::<[&[u8]; 10]>()
        + size_of::<[&[u8]; 17]>()
        + size_of::<[&[u8]; 3]>()
        // Charge the corresponding name rosters conservatively even when a
        // compiler can promote their immutable literal arrays to static data.
        + size_of::<[&str; 10]>()
        + size_of::<[&str; 17]>()
        + size_of::<[&str; 3]>()
        + size_of::<[U64; 10]>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<[u8; 32]>()
        + size_of::<[u8; 128]>()
        + size_of::<[usize; 8]>()
        + crate::protocol_snapshot::owned11::correspondence::envelope_counter_scratch_data()
        + size_of::<PacketNative5ProtocolMetadataLimits>()
        + size_of::<[(U64, U64, usize); 3]>()
        + size_of::<
            std::cell::Ref<'static, crate::transport::original_frames::OriginalFrameReservation>,
        >()
        + size_of::<crate::transport::original_frames::OriginalFrame<'static>>()
}

fn object<'a, const N: usize>(
    bytes: &'a [u8],
    names: &[&str; N],
) -> Result<[&'a [u8]; N], ProviderError> {
    let mut fields = Fields::object(bytes)?;
    let mut values = [&[][..]; N];
    for (name, value) in names.iter().zip(&mut values) {
        *value = fields.named(name)?;
    }
    fields.finish()?;
    Ok(values)
}

fn number(bytes: &[u8]) -> Result<U64, ProviderError> {
    Ok(U64::new(unsigned(string(bytes)?.as_bytes())?))
}

fn id(bytes: &[u8]) -> Result<&str, ProviderError> {
    let value = string(bytes)?;
    let mut bytes = value.bytes();
    if value.len() > 128
        || !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
    {
        return Err(invalid());
    }
    Ok(value)
}

fn hash(bytes: &[u8]) -> Result<Hash<'_>, ProviderError> {
    let [algorithm, digest, domain] = object(bytes, &["algorithm", "digest", "domain"])?;
    let domain = string(domain)?;
    let digest = string(digest)?;
    if string(algorithm)? != "blake3-256"
        || domain.is_empty()
        || domain.len() > 128
        || !domain.is_ascii()
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }
    Ok(Hash { domain, digest })
}

fn digit(byte: u8) -> u8 {
    if byte.is_ascii_digit() {
        byte - b'0'
    } else {
        byte - b'a' + 10
    }
}

fn position(bytes: &[u8]) -> Result<Position, ProviderError> {
    let [microstep, phase, time] = object(bytes, &["microstep", "phase", "time_ps"])?;
    let phase = match phase {
        b"0" => Phase::BoundaryControl,
        b"1" => Phase::Publication,
        b"2" => Phase::Delivery,
        b"3" => Phase::Reaction,
        _ => return Err(invalid()),
    };
    Ok(Position::new(number(time)?, number(microstep)?, phase))
}

fn scope_data(bytes: &[u8]) -> Result<Scope<'_>, ProviderError> {
    let [
        activation,
        binding,
        originals,
        records,
        incarnation,
        cursor,
        pid,
        node,
        observe_hash,
        request,
        sequence,
        owner,
        generation,
        first,
        session,
        world,
        world_generation,
    ] = object(
        bytes,
        &[
            "activation",
            "binding_hash",
            "control_originals_before",
            "endpoint_records_before",
            "incarnation",
            "model_cursor",
            "native_pid",
            "node",
            "observe_hash",
            "observe_request",
            "observe_sequence",
            "owner",
            "owner_generation",
            "provider_next_sequence_before",
            "session",
            "world",
            "world_generation",
        ],
    )?;
    Ok(Scope {
        activation: id(activation)?,
        binding_hash: hash(binding)?,
        control_originals_before: number(originals)?,
        endpoint_records_before: number(records)?,
        incarnation: id(incarnation)?,
        model_cursor: position(cursor)?,
        native_pid: number(pid)?,
        node: id(node)?,
        observe_hash: hash(observe_hash)?,
        observe_request: id(request)?,
        observe_sequence: number(sequence)?,
        owner: id(owner)?,
        owner_generation: number(generation)?,
        provider_next_sequence_before: number(first)?,
        session: id(session)?,
        world: hash(world)?,
        world_generation: number(world_generation)?,
    })
}

fn protocol(bytes: &[u8]) -> Result<PacketNativeCaptureProtocolAllocation, ProviderError> {
    let [encoded, capacity, literal] = object(
        bytes,
        &[
            "current_encoded_bytes",
            "encoded_capacity",
            "literal_and_descriptor_bytes",
        ],
    )?;
    Ok(PacketNativeCaptureProtocolAllocation {
        encoded_capacity: number(capacity)?,
        current_encoded_bytes: number(encoded)?,
        literal_and_descriptor_bytes: number(literal)?,
    })
}

fn bank(bytes: &[u8]) -> Result<PacketNative5ProtocolMetadataBankFacts, ProviderError> {
    let [
        lookup_bytes,
        lookup_capacity,
        row_bytes,
        row_capacity,
        record_bytes,
        record_capacity,
        selected,
    ] = object(
        bytes,
        &[
            "alias_lookup_bytes",
            "alias_lookup_capacity",
            "alias_row_bytes",
            "alias_row_capacity",
            "record_bytes",
            "record_capacity",
            "selected_rows",
        ],
    )?;
    Ok(PacketNative5ProtocolMetadataBankFacts {
        selected_rows: number(selected)?,
        record_capacity: number(record_capacity)?,
        record_bytes: number(record_bytes)?,
        alias_row_capacity: number(row_capacity)?,
        alias_lookup_capacity: number(lookup_capacity)?,
        alias_row_bytes: number(row_bytes)?,
        alias_lookup_bytes: number(lookup_bytes)?,
    })
}

fn metadata_data(bytes: &[u8]) -> Result<PacketNative5ProtocolMetadataBirthFacts, ProviderError> {
    let [after, before] = object(bytes, &["after", "before"])?;
    Ok(PacketNative5ProtocolMetadataBirthFacts {
        before: bank(before)?,
        after: bank(after)?,
    })
}

fn growth_data(bytes: &[u8]) -> Result<PacketNativeCaptureRetainedGrowth, ProviderError> {
    let [after, publication, request, observe] = object(
        bytes,
        &[
            "after_confirmation_bytes",
            "capture_publication_bytes",
            "capture_request_bytes",
            "observe_publication_bytes",
        ],
    )?;
    Ok(PacketNativeCaptureRetainedGrowth {
        observe_publication_bytes: number(observe)?,
        capture_request_bytes: number(request)?,
        capture_publication_bytes: number(publication)?,
        after_confirmation_bytes: number(after)?,
    })
}

fn transient_data(bytes: &[u8]) -> Result<PacketNativeCaptureTransients, ProviderError> {
    let [model, after, before, observe, scratch] = object(
        bytes,
        &[
            "model_control_encoding_bytes",
            "native_after_encoding_bytes",
            "native_before_encoding_bytes",
            "observe_encoding_bytes",
            "quote_scratch_bytes",
        ],
    )?;
    Ok(PacketNativeCaptureTransients {
        observe_encoding_bytes: number(observe)?,
        model_control_encoding_bytes: number(model)?,
        native_before_encoding_bytes: number(before)?,
        native_after_encoding_bytes: number(after)?,
        quote_scratch_bytes: number(scratch)?,
    })
}

#[cfg(test)]
mod tests {
    //! Closed DATA controls; no native measurement, owner or permission is built.
    use super::*;
    use crate::envelope::{Envelope, Nullable};
    use crucible_node_format::{Extensions, canonical};

    fn sample() -> (PacketNativeCaptureAllocationReport, PacketNative5Record) {
        let one = U64::new(1);
        let id = |text: &str| Id::new(text).unwrap();
        let hash = |domain: &str| canonical::hash(domain, b"data-only correlation").unwrap();
        let original = Envelope {
            protocol: "CNP/1".into(), message: MessageKind::Request,
            session_id: Nullable(Some(id("session"))), incarnation_id: Nullable(Some(id("incarnation"))),
            node_id: Nullable(Some(id("node"))), execution_owner_id: Nullable(Some(id("owner"))),
            capture_owner_id: Nullable(None), request_id: Nullable(Some(id("observe"))), operation_id: Nullable(None),
            sequence: U64::new(7), method: Method::Observe,
            body: serde_json::json!({"binding_hash":hash("cnp.owner-binding.v1"),"owner_generation":"1","after_observation_sequence":"0","maximum_items":"1","extensions":{}}).as_object().unwrap().clone(),
            extensions: Extensions::new(),
        };
        let (alias, lookup) = crate::retained_metadata::aliases::original_metadata_alias_layouts();
        let bank = PacketNative5ProtocolMetadataBankFacts {
            selected_rows: one,
            record_capacity: one,
            record_bytes: U64::new(size_of::<
                crate::retained_metadata::records::MetadataCapacityRecord,
            >() as u64),
            alias_row_capacity: one,
            alias_lookup_capacity: one,
            alias_row_bytes: U64::new(alias as u64),
            alias_lookup_bytes: U64::new(lookup as u64),
        };
        let metadata = PacketNative5ProtocolMetadataBirthFacts {
            before: bank,
            after: bank,
        };
        let receipt = PacketNative5Record {
            schema: "source-owned.packet-receipt/5".into(),
            native_pid: U64::new(42),
            original,
            binding_hash: hash("cnp.owner-binding.v1"),
            session: id("session"),
            incarnation: id("incarnation"),
            node: id("node"),
            owner: id("owner"),
            owner_generation: one,
            input_epoch: id("epoch"),
            world: hash("cnp.world-binding.v1"),
            native_record: canonical::content_ref(b"data-only raw record", "application/json")
                .unwrap(),
            storage_selection: crate::reference_packet::control::PacketNative5StorageSelection {
                storage: super::super::super::PacketNative5StorageLimits {
                    snapshot_bytes: U64::new(4096),
                    control_snapshot_bytes: U64::new(1024),
                    protocol_snapshot_bytes: U64::new(1024),
                    frame_bank_bytes: U64::new(131072),
                    frames_per_direction: U64::new(256),
                    hello_bytes: U64::new(65536),
                    settlement_bytes: U64::new(4096),
                },
                limits: crate::handshake::Limits {
                    frame_bytes: U64::new(65536),
                    nesting: U64::new(64),
                    requests: U64::new(256),
                    journal_entries: U64::new(4096),
                    blob_chunk_bytes: U64::new(4096),
                },
            },
            capture_profile: super::super::super::PacketNative5CaptureProfile::OwnedProtocol11 {
                native_before_protocol_bytes: U64::new(1024),
                native_after_protocol_bytes: U64::new(1024),
                host_protocol_bytes: U64::new(1024),
            },
            confirmation_selection: Some(
                super::super::super::PacketNative5ConfirmationSelection::AfterProtocolPoll5,
            ),
            ack_emitter_selection: Some(
                super::super::super::PacketNative5AckEmitterSelection::CanonicalSdkBlob5,
            ),
            complete_restore_selection: None,
            restore_input_emitter_selection: None,
            protocol_metadata_limits: Some(PacketNative5ProtocolMetadataLimits {
                native_before_rows: one,
                native_after_rows: one,
            }),
            protocol_metadata_birth_facts: Some(metadata),
        };
        let report = PacketNativeCaptureAllocationReport {
            schema: PACKET_NATIVE_CAPTURE_ALLOCATION_REPORT.into(),
            scope: PacketNativeCaptureAllocationScope {
                native_pid: receipt.native_pid,
                observe_request: id("observe"),
                observe_sequence: U64::new(7),
                observe_hash: canonical::json_hash(
                    NATIVE_CAPTURE_ALLOCATION_OBSERVE_DOMAIN,
                    &receipt.original,
                )
                .unwrap(),
                session: receipt.session.clone(),
                incarnation: receipt.incarnation.clone(),
                node: receipt.node.clone(),
                owner: receipt.owner.clone(),
                binding_hash: receipt.binding_hash.clone(),
                world: receipt.world.clone(),
                activation: id("activation"),
                world_generation: one,
                owner_generation: one,
                model_cursor: Position::new(U64::new(10), U64::new(2), Phase::Reaction),
                control_originals_before: U64::new(6),
                endpoint_records_before: U64::new(6),
                provider_next_sequence_before: U64::new(9),
            },
            before: PacketNativeCaptureProtocolAllocation {
                encoded_capacity: U64::new(1024),
                literal_and_descriptor_bytes: U64::new(512),
                current_encoded_bytes: U64::new(20),
            },
            after: PacketNativeCaptureProtocolAllocation {
                encoded_capacity: U64::new(1024),
                literal_and_descriptor_bytes: U64::new(512),
                current_encoded_bytes: U64::new(20),
            },
            metadata_banks: metadata,
            retained_requested_bytes: U64::new(1_048_576),
            shared_edges: U64::new(2),
            unique_roots: one,
            growth: PacketNativeCaptureRetainedGrowth {
                observe_publication_bytes: one,
                capture_request_bytes: one,
                capture_publication_bytes: one,
                after_confirmation_bytes: one,
            },
            transients: PacketNativeCaptureTransients {
                observe_encoding_bytes: one,
                model_control_encoding_bytes: one,
                native_before_encoding_bytes: one,
                native_after_encoding_bytes: one,
                quote_scratch_bytes: one,
            },
        };
        (report, receipt)
    }

    #[test]
    fn borrowed_report_matches_actual_typed_contract_without_copying_body() {
        let (report, receipt) = sample();
        let bytes = canonical::canonical_json(&serde_json::to_value(&report).unwrap()).unwrap();
        let view = PacketNativeCaptureAllocationReportView::from_original_bytes(&bytes).unwrap();
        assert!(std::ptr::eq(view.original_bytes().as_ptr(), bytes.as_ptr()));
        assert_eq!(
            view.requested_peak_data().unwrap(),
            report.requested_peak_data().unwrap()
        );
        assert_eq!(view.model_cursor_data(), report.scope.model_cursor);
        assert_eq!(view.metadata_banks_data(), report.metadata_banks);
        let digest = canonical::hash(
            NATIVE_CAPTURE_ALLOCATION_OBSERVE_DOMAIN,
            &canonical::canonical_json(&serde_json::to_value(&receipt.original).unwrap()).unwrap(),
        )
        .unwrap();
        let mut raw = [0u8; 32];
        for (out, bytes) in raw.iter_mut().zip(digest.digest.as_bytes().chunks_exact(2)) {
            *out = digit(bytes[0]) * 16 + digit(bytes[1]);
        }
        view.authenticate_receipt_data(&receipt, &raw).unwrap();
    }

    #[test]
    fn borrowed_report_refuses_independent_receipt_identity_and_literal_changes() {
        let (report, receipt) = sample();
        let bytes = canonical::canonical_json(&serde_json::to_value(&report).unwrap()).unwrap();
        let view = PacketNativeCaptureAllocationReportView::from_original_bytes(&bytes).unwrap();
        let digest = canonical::hash(
            NATIVE_CAPTURE_ALLOCATION_OBSERVE_DOMAIN,
            &canonical::canonical_json(&serde_json::to_value(&receipt.original).unwrap()).unwrap(),
        )
        .unwrap();
        let mut raw = [0u8; 32];
        for (out, bytes) in raw.iter_mut().zip(digest.digest.as_bytes().chunks_exact(2)) {
            *out = digit(bytes[0]) * 16 + digit(bytes[1]);
        }
        for axis in 0..9 {
            let mut other = receipt.clone();
            match axis {
                0 => other.native_pid = U64::new(43),
                1 => other.session = Id::new("other-session").unwrap(),
                2 => other.incarnation = Id::new("other-incarnation").unwrap(),
                3 => other.node = Id::new("other-node").unwrap(),
                4 => other.owner = Id::new("other-owner").unwrap(),
                5 => other.owner_generation = U64::new(2),
                6 => {
                    other.binding_hash =
                        canonical::hash("cnp.owner-binding.v1", b"other binding").unwrap()
                }
                7 => other.world = canonical::hash("cnp.world-binding.v1", b"other world").unwrap(),
                _ => other.original.sequence = U64::new(8),
            }
            assert!(
                view.authenticate_receipt_data(&other, &raw).is_err(),
                "axis {axis}"
            );
        }
        raw[0] ^= 1;
        assert!(view.authenticate_receipt_data(&receipt, &raw).is_err());
        assert_eq!(view.original_bytes(), bytes);
    }

    #[test]
    fn borrowed_report_refuses_unknown_duplicate_and_inconsistent_physical_data() {
        let (report, _receipt) = sample();
        let mut value = serde_json::to_value(&report).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("permission".into(), serde_json::Value::Bool(true));
        let extended = canonical::canonical_json(&value).unwrap();
        assert!(PacketNativeCaptureAllocationReportView::from_original_bytes(&extended).is_err());
        let bytes = canonical::canonical_json(&serde_json::to_value(&report).unwrap()).unwrap();
        let duplicate = bytes
            .windows(9)
            .position(|bytes| bytes == b"\"schema\":")
            .unwrap();
        let mut changed = bytes.clone();
        changed.splice(
            duplicate..duplicate,
            b"\"schema\":\"duplicate\",".iter().copied(),
        );
        assert!(PacketNativeCaptureAllocationReportView::from_original_bytes(&changed).is_err());
        let mut invalid_report = report;
        invalid_report.before.current_encoded_bytes = U64::new(2048);
        assert!(invalid_report.validate_data().is_err());
        let invalid =
            canonical::canonical_json(&serde_json::to_value(&invalid_report).unwrap()).unwrap();
        assert!(PacketNativeCaptureAllocationReportView::from_original_bytes(&invalid).is_err());
    }
}

/// Borrows the inner native receipt from the exact closed outer record12 bytes.
///
/// This walks only the three original outer fields and full report reference.
/// The Source then runs its existing typed receipt/model/currentness validators;
/// this borrowed span supplies no semantic or allocation authority.
///
/// # Errors
/// Refuses unknown/duplicate/reordered outer fields, another schema or any full
/// reference mismatch. Inner native receipt validation remains the caller's duty.
pub fn original_capture_allocation_native_bytes_data<'a>(
    bytes: &'a [u8],
    reference: &ContentRef,
) -> Result<&'a [u8], ProviderError> {
    let [allocation, native, schema] = object(bytes, &["allocation", "native", "schema"])?;
    if string(schema)? != PACKET_NATIVE_CAPTURE_ALLOCATION_RECORD {
        return Err(invalid());
    }
    let [identity, length, media] = object(allocation, &["hash", "length", "media_type"])?;
    if !hash(identity)?.matches(&reference.hash)
        || number(length)? != reference.length
        || string(media)? != reference.media_type
    {
        return Err(invalid());
    }
    Ok(native)
}

// This concrete ContentRef comparison avoids invoking the generic U64
// serializer, which may construct an owned decimal String before its callback.
pub(crate) fn original_capture_allocation_reference_matches_data(
    value: &serde_json::Value,
    expected: &ContentRef,
) -> bool {
    let Some(value) = value.as_object() else {
        return false;
    };
    let Some(hash) = value.get("hash").and_then(serde_json::Value::as_object) else {
        return false;
    };
    let length = value.get("length").and_then(serde_json::Value::as_str);
    value.len() == 3
        && hash.len() == 3
        && value.get("media_type").and_then(serde_json::Value::as_str)
            == Some(expected.media_type.as_str())
        && length.is_some_and(|text| unsigned(text.as_bytes()).ok() == Some(expected.length.get()))
        && hash.get("algorithm").and_then(serde_json::Value::as_str)
            == Some(expected.hash.algorithm.as_str())
        && hash.get("domain").and_then(serde_json::Value::as_str)
            == Some(expected.hash.domain.as_str())
        && hash.get("digest").and_then(serde_json::Value::as_str)
            == Some(expected.hash.digest.as_str())
}
