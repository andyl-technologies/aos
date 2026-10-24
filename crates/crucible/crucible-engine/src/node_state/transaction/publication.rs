//! Hands actual inactive restoration state to the complete durable publisher.
//!
//! This opt-in codec preserves source histories and the checked fresh rebinding,
//! rather than pretending a restored world has empty initial coordinator state.
//! Only the existing prepared owner can construct it. It contains public data;
//! actual native handles and grants remain in the original staging capsule.

use std::io::{self, Write};

use crucible_node_format::canonical;
use serde::Serialize;

use super::*;
use crate::node_scheduling::InputPayload;

fn encode(value: &impl Serialize, maximum: usize) -> Result<Vec<u8>, StateError> {
    struct Credit(usize);
    impl Write for Credit {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_sub(bytes.len())
                .ok_or_else(|| io::Error::other("restored coordinator byte ceiling"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(&mut Credit(maximum), value).map_err(super::super::schema)?;
    let value = serde_json::to_value(value).map_err(super::super::schema)?;
    let bytes = canonical::canonical_json(&value).map_err(super::super::schema)?;
    if bytes.len() > maximum {
        return Err(incomplete("restored coordinator", "canonical byte ceiling"));
    }
    Ok(bytes)
}

impl<'a> PreparedRestore<'a> {
    /// Retains the actual complete inactive coordinator before restored publication.
    ///
    /// This optional handoff is required by concrete publishers that must own
    /// their original complete coordinator bytes. It preserves the actual source
    /// artifact/manifest, complete runtime and scheduler histories, native
    /// continuation proof, fresh acknowledgements/epochs, exact target and all
    /// original validated ready records. It never installs a scheduler, polls a
    /// native owner, or mints a WorldActivation.
    ///
    /// The full first body remains in this prepared owner before the callback.
    /// Refusal or unwind leaves existing preparation/native quarantine behavior
    /// intact. Unrelated legacy publication entry points remain unchanged.
    ///
    /// # Errors
    /// Retains the complete original failure on duplicate handoff, absent actual
    /// preparation/continuation, changed source/target, exhausted bytes, publisher
    /// refusal or callback unwind. No failed owner or first body is discarded.
    pub fn retain_original_coordinator(
        mut self,
        publisher: &mut dyn ActivationPublisher,
        maximum_bytes: usize,
    ) -> Result<Self, RestoreFailure> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.retain_original_coordinator_data(publisher, maximum_bytes)
        }));
        match result {
            Ok(Ok(())) => Ok(self),
            Ok(Err(error)) => Err(self.fail(error)),
            Err(payload) => {
                let mut failure = self.fail(incomplete(
                    "restored coordinator",
                    "original handoff callback unwound",
                ));
                failure.panic_payload = Some(payload);
                Err(failure)
            }
        }
    }

    /// Publishes while retaining the same original failure on callback unwind.
    ///
    /// Unlike the legacy publication entry, this opt-in path catches callbacks
    /// while this actual prepared owner is still alive, including post-commit
    /// continuation installation. RecordingPublisher's
    /// original publication knowledge, first complete bank, opaque panic payload
    /// and native/runtime quarantine are kept together. It never claims rollback
    /// or interprets an unknown commit as absence of effects.
    pub fn publish_original_retained(
        self,
        publisher: &mut dyn ActivationPublisher,
    ) -> RestorePublication<'a> {
        self.publication_with_unwind_policy(publisher, false, true)
    }

    fn retain_original_coordinator_data(
        &mut self,
        publisher: &mut dyn ActivationPublisher,
        maximum_bytes: usize,
    ) -> Result<(), StateError> {
        if maximum_bytes == 0
            || maximum_bytes > crate::node_contract::MAXIMUM_ACTIVATION_COORDINATOR_BYTES
            || self.publication != PublicationKnowledge::NotAttempted
            || self.prepared_publication.is_some()
        {
            return Err(incomplete(
                "restored coordinator",
                "original handoff unavailable",
            ));
        }
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| incomplete("restored coordinator", "actual runtime absent"))?;
        let nodes = runtime
            .prepared_node_records()
            .map_err(|error| incomplete("restored coordinator", &error.to_string()))?;
        let continuation = self
            .continuation
            .as_ref()
            .ok_or_else(|| incomplete("restored coordinator", "actual continuation absent"))?;
        let scheduler = self
            .scheduler
            .as_ref()
            .ok_or_else(|| incomplete("restored coordinator", "actual scheduler absent"))?;
        if continuation.native_continuation().target_activation() != &self.activation
            || self.activation.world_binding_hash != *self.graph.world_binding_hash()
            || nodes.len() != self.graph.node_ids().count()
            || nodes.iter().any(|node| node.prepared_owners().is_none())
        {
            return Err(incompatible(
                "restored coordinator",
                "actual public target/roster differs",
            ));
        }
        let target = &self.activation;
        let bytes = encode(
            &(
                "crucible/coordinator-restoration-prepared/1",
                (
                    &target.generation,
                    &target.activation_id,
                    &target.world_binding_hash,
                    &target.owners,
                    &target.boundary,
                ),
                self.graph.world(),
                &self.capture.artifact,
                &self.capture.manifest,
                &self.capture.runtime,
                &self.capture.scheduler,
                self.capture.repeatability,
                continuation.original_publication_data(),
                scheduler.original_publication_data(),
                nodes,
            ),
            maximum_bytes,
        )?;
        let coordinator = InputPayload {
            reference: canonical::content_ref(&bytes, "application/json")
                .map_err(super::super::schema)?,
            bytes,
        };
        let mut owners = std::collections::BTreeMap::new();
        for node in nodes {
            for owner in node
                .prepared_owners()
                .ok_or_else(|| incomplete("restored coordinator", "owner mapping absent"))?
            {
                if owners
                    .insert(owner.owner_id.clone(), owner.clone())
                    .is_some_and(|old| old != *owner)
                {
                    return Err(incompatible(
                        "restored coordinator",
                        "inconsistent owner aliases",
                    ));
                }
            }
        }
        if owners.len() != self.activation.owners.len() {
            return Err(incomplete(
                "restored coordinator",
                "incomplete original owner roster",
            ));
        }
        self.prepared_publication = Some(Rc::new(PreparedWorldPublication {
            nodes: nodes.to_vec().into(),
            owners: owners.into_values().collect(),
            coordinator,
        }));
        let original = self
            .prepared_publication
            .as_ref()
            .ok_or_else(|| incomplete("restored coordinator", "first body custody absent"))?;
        publisher
            .retain_restored_coordinator(
                &self.activation,
                original.nodes().to_vec(),
                original.coordinator_snapshot().clone(),
            )
            .map_err(|error| incomplete("restored coordinator publisher", &error.to_string()))
    }
}

impl PendingRestorePublication<'_> {
    /// Retains the same uncertain generation as an owned quarantined failure.
    ///
    /// This consumes the pending owner without retry, reconciliation, native
    /// release or execution authority. Publication remains explicitly unknown;
    /// the exact prepared bank and native/runtime custody remain in the failure.
    pub fn retain_uncertain_failure(self) -> RestoreFailure {
        self.prepared.fail(incomplete(
            "restored publication",
            "original commit outcome remains unknown",
        ))
    }
}

#[cfg(test)]
mod tests {
    // These are explicit data and synthetic native-custody controls, never
    // realized Clock witnesses or normal acceptance inputs.
    // crucible-lint: allow panic-shortcut -- Model custody controls deliberately panic when an original failure owner is lost.

    use super::*;

    #[test]
    fn coordinator_handoff_preserves_nonempty_history_and_exact_one_short_budget()
    -> Result<(), StateError> {
        let actual = serde_json::json!({
            "source": {"operations":[{"operation":"original/1", "acknowledged":true}]},
            "target": {"generation":"9"},
            "control":"\n\u{0}",
        });
        let expected = canonical::canonical_json(&actual).map_err(super::super::super::schema)?;
        assert_eq!(encode(&actual, expected.len())?, expected);
        assert!(encode(&actual, expected.len() - 1).is_err());
        assert_eq!(encode(&actual, expected.len() + 73)?, expected);
        Ok(())
    }

    #[test]
    fn restored_coordinator_native_acknowledgement_changes_identity() -> Result<(), StateError> {
        let mut actual = serde_json::json!({"source":{"operations":["original/1"]}, "fresh_ack":{"generation":"9"}});
        let before = encode(&actual, 4096)?;
        actual["fresh_ack"]["generation"] = "10".into();
        let after = encode(&actual, 4096)?;
        assert_ne!(before, after);
        assert_ne!(
            canonical::content_ref(&before, "application/json")
                .map_err(super::super::super::schema)?,
            canonical::content_ref(&after, "application/json")
                .map_err(super::super::super::schema)?
        );
        Ok(())
    }
    fn retained_test_bank() -> Result<Rc<PreparedWorldPublication>, StateError> {
        let bytes = b"first complete prepared coordinator bank".to_vec();
        Ok(Rc::new(PreparedWorldPublication {
            nodes: Rc::from([]),
            owners: Vec::new(),
            coordinator: InputPayload {
                reference: canonical::content_ref(&bytes, "application/octet-stream")
                    .map_err(super::super::super::schema)?,
                bytes,
            },
        }))
    }

    #[test]
    fn duplicate_handoff_returns_same_bank_and_actual_quarantined_model_runtime()
    -> Result<(), StateError> {
        let (graph, blobs) = crate::node_admission::test_restore_fixture_with_content(false);
        let mut prepared = crate::node_state::tests::prepared_publication_fixture(&graph, blobs)
            .unwrap_or_else(|failure| panic!("model preparation refused: {}", failure.error));
        let original = retained_test_bank()?;
        prepared.prepared_publication = Some(Rc::clone(&original));
        struct NoCallback;
        impl ActivationPublisher for NoCallback {
            fn publish(&mut self, _: &ActivationRecord) -> PublicationStatus {
                panic!("unexpected publication")
            }
            fn reconcile(&mut self, _: &ActivationRecord) -> PublicationStatus {
                panic!("unexpected reconciliation")
            }
            fn retain_restored_coordinator(
                &mut self,
                _: &ActivationRecord,
                _: Vec<crate::node_contract::ValidatedNodePreparation>,
                _: InputPayload,
            ) -> Result<(), crate::node_contract::RuntimeError> {
                panic!("occupied handoff reached callback")
            }
        }
        let mut failure = match prepared.retain_original_coordinator(&mut NoCallback, 1024) {
            Ok(_) => panic!("duplicate handoff accepted"),
            Err(failure) => failure,
        };
        assert!(
            failure
                .prepared_publication
                .as_ref()
                .is_some_and(|retained| Rc::ptr_eq(retained, &original))
        );
        assert_eq!(
            failure.publication_knowledge(),
            PublicationKnowledge::NotAttempted
        );
        assert!(failure.quarantined_runtime().is_some());
        Ok(())
    }

    #[test]
    fn uncertain_model_publication_keeps_same_bank_and_unknown_generation() -> Result<(), StateError>
    {
        let (graph, blobs) = crate::node_admission::test_restore_fixture_with_content(false);
        let mut prepared = crate::node_state::tests::prepared_publication_fixture(&graph, blobs)
            .unwrap_or_else(|failure| panic!("model preparation refused: {}", failure.error));
        let target = prepared.proposed_activation().clone();
        let original = retained_test_bank()?;
        prepared.prepared_publication = Some(Rc::clone(&original));
        struct UnknownPublisher;
        impl ActivationPublisher for UnknownPublisher {
            fn publish(&mut self, _: &ActivationRecord) -> PublicationStatus {
                PublicationStatus::Unknown
            }
            fn reconcile(&mut self, _: &ActivationRecord) -> PublicationStatus {
                panic!("no retry is permitted")
            }
        }
        let pending = match prepared.publish(&mut UnknownPublisher) {
            RestorePublication::Uncertain(pending) => pending,
            _ => panic!("original unknown publication lost"),
        };
        let mut failure = (*pending).retain_uncertain_failure();
        assert_eq!(
            failure.publication_knowledge(),
            PublicationKnowledge::Unknown
        );
        assert_eq!(failure.original_activation(), Some(&target));
        assert!(
            failure
                .prepared_publication
                .as_ref()
                .is_some_and(|retained| Rc::ptr_eq(retained, &original))
        );
        assert!(failure.quarantined_runtime().is_some());
        Ok(())
    }
    #[test]
    fn publisher_unwind_keeps_original_payload_bank_unknown_and_runtime_owner()
    -> Result<(), StateError> {
        let (graph, blobs) = crate::node_admission::test_restore_fixture_with_content(false);
        let mut prepared = crate::node_state::tests::prepared_publication_fixture(&graph, blobs)
            .unwrap_or_else(|failure| panic!("model preparation refused: {}", failure.error));
        let original = retained_test_bank()?;
        prepared.prepared_publication = Some(Rc::clone(&original));
        struct PanickingPublisher;
        impl ActivationPublisher for PanickingPublisher {
            fn publish(&mut self, _: &ActivationRecord) -> PublicationStatus {
                std::panic::panic_any(String::from("original publisher payload"))
            }
            fn reconcile(&mut self, _: &ActivationRecord) -> PublicationStatus {
                panic!("no retry is permitted")
            }
        }
        let mut failure = match prepared.publish_original_retained(&mut PanickingPublisher) {
            RestorePublication::Failed(failure) => failure,
            _ => panic!("original callback unwind escaped owned failure"),
        };
        assert_eq!(
            failure.publication_knowledge(),
            PublicationKnowledge::Unknown
        );
        assert!(
            failure
                .prepared_publication
                .as_ref()
                .is_some_and(|retained| Rc::ptr_eq(retained, &original))
        );
        assert_eq!(
            failure
                .panic_payload
                .as_ref()
                .and_then(|payload| payload.downcast_ref::<String>())
                .map(String::as_str),
            Some("original publisher payload")
        );
        assert!(failure.has_retained_panic_payload_data());
        assert!(failure.quarantined_runtime().is_some());
        Ok(())
    }
    #[test]
    fn complete_publication_keeps_first_bank_and_refuses_changed_body_before_callback()
    -> Result<(), StateError> {
        let original = retained_test_bank()?;
        let mut retained = Some(Rc::clone(&original));
        let mut knowledge = PublicationKnowledge::NotAttempted;
        struct CompletePublisher(usize);
        impl ActivationPublisher for CompletePublisher {
            fn publish(&mut self, _: &ActivationRecord) -> PublicationStatus {
                panic!("complete control must not call the scalar surface")
            }
            fn reconcile(&mut self, _: &ActivationRecord) -> PublicationStatus {
                panic!("complete control must not reconcile")
            }
            fn publish_complete(
                &mut self,
                _: &ActivationRecord,
                _: &PreparedWorldPublication,
            ) -> PublicationStatus {
                self.0 += 1;
                PublicationStatus::NotCommitted
            }
        }
        let (graph, blobs) = crate::node_admission::test_restore_fixture_with_content(false);
        let prepared = crate::node_state::tests::prepared_publication_fixture(&graph, blobs)
            .unwrap_or_else(|failure| panic!("model preparation refused: {}", failure.error));
        let activation = prepared.proposed_activation();
        let mut concrete = CompletePublisher(0);
        {
            let mut recording = RecordingPublisher {
                publisher: &mut concrete,
                status: None,
                publication: &mut knowledge,
                prepared: &mut retained,
                retain_first: true,
            };
            assert_eq!(
                recording.publish_complete(activation, &original),
                PublicationStatus::NotCommitted
            );
        }
        assert_eq!(concrete.0, 1);
        assert!(
            retained
                .as_ref()
                .is_some_and(|bank| Rc::ptr_eq(bank, &original))
        );

        let mut changed = original.as_ref().clone();
        changed.coordinator.bytes.push(0);
        {
            let mut recording = RecordingPublisher {
                publisher: &mut concrete,
                status: None,
                publication: &mut knowledge,
                prepared: &mut retained,
                retain_first: true,
            };
            assert_eq!(
                recording.publish_complete(activation, &changed),
                PublicationStatus::Unknown
            );
        }
        assert_eq!(concrete.0, 1);
        assert_eq!(knowledge, PublicationKnowledge::Unknown);
        assert!(
            retained
                .as_ref()
                .is_some_and(|bank| Rc::ptr_eq(bank, &original))
        );
        Ok(())
    }
}
