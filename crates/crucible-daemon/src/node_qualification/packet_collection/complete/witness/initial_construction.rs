//! Observes real initial Oracle seals while the original runtime remains inactive.
//!
//! A mandatory node validation can enroll a native proof before runtime attachment.
//! These views count those actual owners; they never reconstruct a proof or treat
//! an entered journal as empty. The ordinary effect-consuming path is unchanged.

use super::super::PacketCompleteReportStartupHolder;
use super::*;
use crate::node_qualification::packet_collection::complete::retained::Counter;
use crucible::node_adapters::cnp::{
    PacketCompleteEffectReceiverGroup, PacketCompleteEffectReceiverReader,
};
use crucible::node_contract::RuntimeError;
use crucible_node_contract::{Phase, Position, U64};
use crucible_node_provider::retained_metadata::RetainedPacketNativeRecord;
use std::mem::size_of;

// A rejected datagram remains owned by this same descriptor. The constructor
// attempt is sticky even when the caller later inspects or drains that queue.
pub(super) fn authenticate_initial_queues_data(
    group: &Rc<PacketCompleteEffectReceiverGroup>,
    reader: &PacketCompleteEffectReceiverReader,
    observed: &mut Observed,
) -> Result<(), QualificationError> {
    if observed.failed {
        return Err(refused());
    }
    let result = (|| {
        reader
            .authenticate_original_group(group)
            .map_err(native_failure)?;
        group.authenticate_empty().map_err(native_failure)
    })();
    if result.is_err() {
        observed.failed = true;
    }
    result
}

pub(super) fn authenticate_initial_record_data(
    program: &PacketConnectedSourceProgram,
    record: PacketCompleteNativeRecord<'_>,
) -> Result<(), QualificationError> {
    // CollectingGraph and InactiveRuntime precede Ready/Arm/WorldActivate.
    // Their latest genuine proof is the unopened Realize inventory; only the
    // later WorldActivate constructor records the prospective open gate.
    let start = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
    let initial = match (program, record) {
        (
            PacketConnectedSourceProgram::Producer { program },
            PacketCompleteNativeRecord::Producer(record),
        ) => {
            let inventory = &record.inventory;
            record.grant.is_none()
                && inventory.reached == start
                && inventory.gate_closed
                && inventory.pending == program.events
                && inventory.retained_outputs.is_empty()
                && inventory.private_mutations.get() == 0
                && inventory.packet_effects.get() == 0
        }
        (
            PacketConnectedSourceProgram::Reactive { .. },
            PacketCompleteNativeRecord::Reactive(record),
        ) => {
            let inventory = &record.inventory;
            record.grant.is_none()
                && inventory.reached == start
                && inventory.gate_closed
                && inventory.reactions.is_empty()
                && inventory.delivered_inputs.is_empty()
                && inventory.publications.is_empty()
                && inventory.retained_outputs.is_empty()
                && inventory.reactions_completed.get() == 0
                && inventory.packet_effects.get() == 0
                && inventory.stages.is_empty()
                && inventory.commits.is_empty()
        }
        _ => false,
    };
    if !initial {
        return Err(refused());
    }
    Ok(())
}

pub(super) fn authenticate_initial_journal_data(
    programmes: &[PacketConnectedSourceProgram; 3],
    observed: &Observed,
) -> Result<(), QualificationError> {
    let Observed {
        seals,
        effects,
        bytes,
        failed,
    } = observed;
    if *failed || seals.len() > MAXIMUM_SEALS || effects.iter().any(|bank| !bank.is_empty()) {
        return Err(refused());
    }
    let mut policy_bytes = 0usize;
    for seal in seals {
        let program = programmes.get(seal.member).ok_or_else(refused)?;
        let record = match &seal.body {
            NativeBody::Producer(record) => PacketCompleteNativeRecord::Producer(record),
            NativeBody::Reactive(record) => PacketCompleteNativeRecord::Reactive(record),
            NativeBody::Stage(_) | NativeBody::Commit(_) => return Err(refused()),
        };
        authenticate_initial_record_data(program, record)?;
        let (_, native_bytes) = seal.native.as_ref().ok_or_else(refused)?;
        // This reproduces the journal's old logical byte debit, independently of
        // the real allocation census below. It supplies no requested-byte credit.
        policy_bytes = seal
            .bytes
            .len()
            .checked_add(native_bytes.len())
            .and_then(|n| n.checked_mul(3))
            .and_then(|n| policy_bytes.checked_add(n))
            .ok_or_else(refused)?;
    }
    if policy_bytes != *bytes {
        return Err(refused());
    }
    Ok(())
}

impl PacketCompleteNativeOracle {
    /// Charges the actual selected inactive Oracle, including already enrolled seals.
    ///
    /// The enclosing holder independently authenticates the exact original family,
    /// phase, Source and plan, and charges the shared Oracle/group/roster roots.
    /// No currentness callback, descriptor read, hash, parse or native request runs.
    ///
    /// # Errors
    /// Refuses a busy, failed or noninitial journal, an entered operation bank,
    /// unsupported typed metadata, or the actual requested-byte ceiling.
    pub(in crate::node_qualification::packet_collection::complete) fn charge_original_initial_construction_data(
        &self,
        counter: &mut Counter,
    ) -> Result<(), RuntimeError> {
        self.receiver_group
            .retained_descriptor_views_precredit_data()?;
        let observed = self
            .observed
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        authenticate_initial_journal_data(&self.programmes, &observed)
            .map_err(|_| RuntimeError::UnsupportedFacet)?;
        counter
            .charge(&self.programmes)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .charge(&self.effect_paths)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .charge(&self.schedule)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .rc(&self.receiver_reader)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        retained::charge_observed_storage_data(counter, &observed)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .add(self.originals.empty_reservation_data()?)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .charge(&self.plan)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        // Actual independent logical policy is checked after the owning walk too.
        if observed.bytes > self.maximum_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        authenticate_initial_journal_data(&self.programmes, &observed)
            .map_err(|_| RuntimeError::UnsupportedFacet)
    }

    /// Names fixed views used by the initial guard and real observed-owner walk.
    ///
    /// # Errors
    /// Refuses checked layout overflow. This is not an ABI/compiler stack bound.
    pub(crate) fn original_initial_journal_counter_scratch_data() -> Result<usize, RuntimeError> {
        [
            size_of::<Counter>(),
            size_of::<&Self>(),
            size_of::<Observed>(),
            size_of::<std::cell::Ref<'static, Observed>>(),
            size_of::<std::cell::RefMut<'static, Observed>>(),
            size_of::<std::slice::Iter<'static, Seal>>(),
            size_of::<std::slice::Iter<'static, Vec<effects::Effect>>>(),
            size_of::<std::slice::Iter<'static, effects::Effect>>(),
            size_of::<&Seal>(),
            size_of::<&PacketConnectedSourceProgram>(),
            size_of::<PacketCompleteNativeRecord<'static>>(),
            size_of::<Option<&'static PacketConnectedSourceProgram>>(),
            size_of::<Option<&'static (ContentRef, Vec<u8>)>>(),
            size_of::<Position>(),
            size_of::<Result<(), QualificationError>>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<[usize; 28]>(),
            size_of::<std::array::IntoIter<usize, 28>>(),
            size_of::<usize>(),
            size_of::<Option<usize>>(),
            size_of::<Rc<std::cell::RefCell<PacketCompleteReportStartupHolder>>>(),
            size_of::<std::cell::Ref<'static, PacketCompleteReportStartupHolder>>(),
            size_of::<Result<bool, RuntimeError>>(),
            size_of::<Option<crucible::node_admission::OriginalRuntimeConstructionPhase>>(),
            size_of::<bool>(),
            PacketCompleteEffectReceiverGroup::original_empty_queue_counter_scratch_data(),
            RetainedPacketNativeRecord::historical_counter_scratch_data(),
            original::OriginalBindings::reservation_scratch_data(),
        ]
        .into_iter()
        .try_fold(0usize, |n, term| {
            n.checked_add(term).ok_or(RuntimeError::ResourceLimit)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_contract::{Bytes, Endpoint, Extensions};
    use crucible_node_provider::{
        envelope::{Envelope, MessageKind, Method, Nullable},
        reference_packet::{
            PacketEvent, PacketProgram, PacketProgramDefinition,
            connected::{PacketConnectedDefinition, PacketConnectedProgram, PacketInputConnection},
        },
    };

    use std::os::unix::net::UnixDatagram;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn start() -> Position {
        Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl)
    }

    fn original() -> Envelope {
        Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(Id::new("session").unwrap())),
            incarnation_id: Nullable(Some(Id::new("incarnation").unwrap())),
            node_id: Nullable(Some(Id::new("producer").unwrap())),
            execution_owner_id: Nullable(Some(Id::new("owner").unwrap())),
            capture_owner_id: Nullable(Some(Id::new("capture").unwrap())),
            request_id: Nullable(Some(Id::new("realize").unwrap())),
            operation_id: Nullable(None),
            sequence: U64::new(2),
            method: Method::Realize,
            body: serde_json::Map::new(),
            extensions: Extensions::new(),
        }
    }

    fn programmes() -> [PacketConnectedSourceProgram; 3] {
        let event = PacketEvent {
            id: Id::new("packet").unwrap(),
            evaluation: Position::new(U64::new(5), U64::new(0), Phase::Reaction),
            completion: Position::new(U64::new(6), U64::new(0), Phase::Publication),
            payload: Some(Bytes::new(vec![1, 2, 3])),
        };
        [
            PacketConnectedSourceProgram::Producer {
                program: PacketProgramDefinition {
                    schema: "source-owned.packet-program.v1".into(),
                    events: vec![event],
                },
            },
            PacketConnectedSourceProgram::Reactive {
                program: reactive_definition().unwrap(),
            },
            PacketConnectedSourceProgram::Reactive {
                program: reactive_definition().unwrap(),
            },
        ]
    }

    fn producer_model(
        programmes: &[PacketConnectedSourceProgram; 3],
    ) -> Result<PacketProgram, Box<dyn std::error::Error>> {
        let PacketConnectedSourceProgram::Producer { program } = &programmes[0] else {
            panic!("selected producer fixture");
        };
        Ok(PacketProgram::new(
            program.events.clone(),
            UnixDatagram::unbound()?,
        )?)
    }

    fn reactive_definition() -> Result<PacketConnectedDefinition, Box<dyn std::error::Error>> {
        let endpoint = |node| -> Result<Endpoint, Box<dyn std::error::Error>> {
            Ok(Endpoint {
                node_id: Id::new(node)?,
                port_id: Id::new("port")?,
                lane_id: Id::new("lane")?,
            })
        };
        Ok(PacketConnectedDefinition {
            schema: "source-owned.packet-connected-program/4".into(),
            connections: vec![PacketInputConnection {
                id: Id::new("original-route")?,
                policy: canonical::content_ref(b"original-policy", "application/octet-stream")?,
                producer: endpoint("producer")?,
                consumer: endpoint("reactive")?,
                delay_ps: U64::new(1),
            }],
            output: None,
        })
    }

    fn reactive_model() -> Result<PacketConnectedProgram, Box<dyn std::error::Error>> {
        Ok(PacketConnectedProgram::new(
            reactive_definition()?,
            UnixDatagram::unbound()?,
        )?)
    }

    fn producer(model: &PacketProgram) -> PacketNativeRecord {
        PacketNativeRecord {
            schema: "source-owned.packet-native/2".into(),
            native_pid: U64::new(u64::from(std::process::id())),
            original: original(),
            inventory: model.inventory(),
            grant: None,
        }
    }

    fn reactive(
        model: &PacketConnectedProgram,
    ) -> Result<PacketConnectedNativeRecord, Box<dyn std::error::Error>> {
        Ok(PacketConnectedNativeRecord {
            schema: "source-owned.packet-native/4".into(),
            native_pid: U64::new(u64::from(std::process::id())),
            original: original(),
            inventory: model.inventory()?,
            grant: None,
        })
    }

    fn empty() -> Observed {
        Observed {
            seals: Vec::new(),
            effects: [Vec::new(), Vec::new(), Vec::new()],
            bytes: 0,
            failed: false,
        }
    }

    #[test]
    fn real_populated_producer_and_reactive_seals_count_exactly_and_refuse_one_short() -> TestResult
    {
        let programmes = programmes();
        let producer = producer(&producer_model(&programmes)?);
        let reactive = reactive(&reactive_model()?)?;
        let mut observed = empty();
        authenticate_initial_journal_data(&programmes, &observed)?;
        for (member, body) in [
            (0, NativeBody::Producer(producer)),
            (1, NativeBody::Reactive(reactive)),
        ] {
            let raw = match &body {
                NativeBody::Producer(record) => {
                    canonical::canonical_json(&serde_json::to_value(record)?)?
                }
                NativeBody::Reactive(record) => {
                    canonical::canonical_json(&serde_json::to_value(record)?)?
                }
                _ => unreachable!(),
            };
            let native_ref = canonical::content_ref(&raw, "application/json")?;
            let wrapper =
                canonical::canonical_json(&serde_json::json!({"native_record": native_ref}))?;
            let wrapper_ref = canonical::content_ref(&wrapper, "application/json")?;
            PacketCompleteNativeOracle::enroll_data(
                usize::MAX,
                &mut observed,
                member,
                &wrapper_ref,
                &wrapper,
                Some((&native_ref, &raw)),
                || body,
            )?;
        }
        authenticate_initial_journal_data(&programmes, &observed)?;
        let mut actual = Counter::new(usize::MAX);
        retained::charge_observed_storage_data(&mut actual, &observed)?;
        let requested = actual.bytes();
        assert!(requested > observed.seals.capacity() * size_of::<Seal>());
        let mut exact = Counter::new(requested);
        retained::charge_observed_storage_data(&mut exact, &observed)?;
        assert_eq!(exact.bytes(), requested);
        assert!(
            retained::charge_observed_storage_data(&mut Counter::new(requested - 1), &observed)
                .is_err()
        );

        let first = &observed.seals[0];
        let reference = first.reference.clone();
        let bytes = first.bytes.clone();
        let native = first.native.clone().unwrap();
        PacketCompleteNativeOracle::enroll_data(
            usize::MAX,
            &mut observed,
            0,
            &reference,
            &bytes,
            Some((&native.0, &native.1)),
            || panic!("already enrolled body must not be cloned"),
        )?;
        assert_eq!(observed.seals.len(), 2);
        let mut repeated = Counter::new(usize::MAX);
        retained::charge_observed_storage_data(&mut repeated, &observed)?;
        assert_eq!(repeated.bytes(), requested);
        assert!(
            PacketCompleteNativeOracle::enroll_data(
                usize::MAX,
                &mut observed,
                0,
                &reference,
                b"changed",
                Some((&native.0, &native.1)),
                || panic!("changed duplicate must refuse before clone"),
            )
            .is_err()
        );
        observed.failed = true;
        assert!(authenticate_initial_journal_data(&programmes, &observed).is_err());
        assert_eq!(observed.seals.len(), 2);
        Ok(())
    }

    #[test]
    fn initial_inventory_guard_refuses_progress_and_foreign_family() -> TestResult {
        let programmes = programmes();
        let mut producer = producer(&producer_model(&programmes)?);
        let mut reactive = reactive(&reactive_model()?)?;
        assert!(
            authenticate_initial_record_data(
                &programmes[0],
                PacketCompleteNativeRecord::Producer(&producer)
            )
            .is_ok()
        );
        assert!(
            authenticate_initial_record_data(
                &programmes[1],
                PacketCompleteNativeRecord::Reactive(&reactive)
            )
            .is_ok()
        );
        assert!(
            authenticate_initial_record_data(
                &programmes[1],
                PacketCompleteNativeRecord::Producer(&producer)
            )
            .is_err()
        );
        let pending = producer.inventory.pending.pop().unwrap();
        assert!(
            authenticate_initial_record_data(
                &programmes[0],
                PacketCompleteNativeRecord::Producer(&producer)
            )
            .is_err()
        );
        producer.inventory.pending.push(pending);
        producer.inventory.private_mutations = U64::new(1);
        assert!(
            authenticate_initial_record_data(
                &programmes[0],
                PacketCompleteNativeRecord::Producer(&producer)
            )
            .is_err()
        );
        reactive
            .inventory
            .stages
            .push(canonical::content_ref(b"stage", "application/json").unwrap());
        assert!(
            authenticate_initial_record_data(
                &programmes[1],
                PacketCompleteNativeRecord::Reactive(&reactive)
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn actual_unopened_models_pass_and_actual_open_gate_models_refuse() -> TestResult {
        let programmes = programmes();
        let mut producer_model = producer_model(&programmes)?;
        let mut reactive_model = reactive_model()?;
        let producer_before = producer(&producer_model);
        let reactive_before = reactive(&reactive_model)?;
        assert_eq!(producer_before.inventory.reached, start());
        assert_eq!(reactive_before.inventory.reached, start());
        assert!(producer_before.inventory.gate_closed);
        assert!(reactive_before.inventory.gate_closed);
        authenticate_initial_record_data(
            &programmes[0],
            PacketCompleteNativeRecord::Producer(&producer_before),
        )?;
        authenticate_initial_record_data(
            &programmes[1],
            PacketCompleteNativeRecord::Reactive(&reactive_before),
        )?;

        // Use the genuine model transitions rather than rewriting the proof's
        // gate flag. Even zero-progress opened owners are a later phase.
        producer_model.open_gate()?;
        reactive_model.open_gate()?;
        let producer_after = producer(&producer_model);
        let reactive_after = reactive(&reactive_model)?;
        assert!(!producer_after.inventory.gate_closed);
        assert!(!reactive_after.inventory.gate_closed);
        assert!(
            authenticate_initial_record_data(
                &programmes[0],
                PacketCompleteNativeRecord::Producer(&producer_after),
            )
            .is_err()
        );
        assert!(
            authenticate_initial_record_data(
                &programmes[1],
                PacketCompleteNativeRecord::Reactive(&reactive_after),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn unsupported_initial_datagram_stays_in_the_same_receiver() -> TestResult {
        let [(a, peer_a), (b, peer_b), (c, peer_c)] = [
            UnixDatagram::pair()?,
            UnixDatagram::pair()?,
            UnixDatagram::pair()?,
        ];
        let (group, reader) = PacketCompleteEffectReceiverGroup::from_original_receivers([a, b, c]);
        let mut observed = empty();
        authenticate_initial_queues_data(&group, &reader, &mut observed)?;
        peer_a.send(b"unexpected")?;
        assert!(authenticate_initial_queues_data(&group, &reader, &mut observed).is_err());
        assert!(observed.failed);
        assert!(authenticate_initial_queues_data(&group, &reader, &mut observed).is_err());
        let mut retained = [0; 16];
        assert_eq!(
            reader.receive(0, &mut retained).map_err(|e| e.reason)?,
            Some(10)
        );
        assert_eq!(&retained[..10], b"unexpected");
        assert!(group.authenticate_empty().is_ok());
        assert!(authenticate_initial_queues_data(&group, &reader, &mut observed).is_err());
        assert!(observed.failed);
        drop((peer_a, peer_b, peer_c));
        Ok(())
    }
}
