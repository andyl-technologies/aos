//! Installed native allocation and complete-source authentication under retained Host custody.

use super::*;

impl HostWorldFactory for InstalledHostStateFactory {
    fn authenticate_condition_custody(
        &self,
        graph: &AdmittedGraph,
        runtime: &RuntimeSnapshot,
        scheduler: &SchedulingSnapshot,
        content: Option<&VerifiedStateContent>,
    ) -> Result<crucible::node_contract::SavedConditionStop, StateError> {
        self.authenticate_condition_scope(graph, runtime, scheduler, content)
    }

    fn authenticate_fault_custody(
        &self,
        graph: &AdmittedGraph,
        runtime: &RuntimeSnapshot,
        scheduler: &SchedulingSnapshot,
        content: Option<&VerifiedStateContent>,
    ) -> Result<(), StateError> {
        self.authenticate_fault_scope(graph, runtime, scheduler, content)
    }

    fn authenticate_terminal_custody(
        &self,
        graph: &AdmittedGraph,
        runtime: &RuntimeSnapshot,
        scheduler: &SchedulingSnapshot,
        _content: Option<&VerifiedStateContent>,
    ) -> Result<(), StateError> {
        self.check_graph(graph)?;
        let saved = runtime
            .terminal
            .as_ref()
            .ok_or_else(|| refusal("complete original terminal custody absent"))?;
        if runtime.schema_version != 3
            || !saved.submitted
            || saved.record.source.world_binding_hash != *graph.world_binding_hash()
            || saved.record.cut != runtime.capture_cut
            || scheduler.capture_cut != runtime.capture_cut
            || saved
                .record
                .native
                .iter()
                .any(|native| native.boundary != saved.record.cut)
            || runtime.inputs.iter().any(|input| {
                !input.deliveries.is_empty()
                    || !input.payloads.is_empty()
                    || input.provenance.is_some()
            })
            || !scheduler.pending_deliveries.is_empty()
            || !scheduler.reservations.is_empty()
        {
            return Err(refusal(
                "selected closed terminal codec lacks complete unchanged custody",
            ));
        }
        let mut semantic = 0;
        for selection in self.selections.values() {
            match &selection.kind {
                InstalledNodeKind::HostClock => {}
                InstalledNodeKind::HostSemantics { profile } => {
                    let program = &self
                        .objects
                        .get(&profile.program.hash.digest)
                        .filter(|(reference, _)| reference == &profile.program)
                        .ok_or_else(|| refusal("installed original semantic program absent"))?
                        .1;
                    let definition: crucible::node_adapters::HostSemanticDefinition =
                        serde_json::from_slice(program).map_err(state_error)?;
                    if definition.version != 2
                        || !definition.inputs.is_empty()
                        || saved.record.node != selection.node
                    {
                        return Err(refusal(
                            "selected terminal program has unqualified external semantics",
                        ));
                    }
                    semantic += 1;
                }
                _ => {
                    return Err(refusal(
                        "terminal native world codec is not installed for this family",
                    ));
                }
            }
        }
        if semantic != 1 || !runtime.operations.iter().any(|original| {
            original.operation == saved.record.operation
                && matches!(&original.result,
                    crucible::node_contract::SavedRuntimeResult::Complete(outcome)
                        | crucible::node_contract::SavedRuntimeResult::Acknowledged(outcome)
                    if matches!(outcome.progress, crucible::node_contract::ProgressEvidence::AssertionsFinalized { .. }))
        }) {
            return Err(refusal("original terminal outcome is not complete under selected native custody"));
        }
        Ok(())
    }

    fn reservation(
        &self,
        graph: &AdmittedGraph,
        node: &Id,
        native: &[u8],
        limits: HostModelResources,
    ) -> Result<RestoreReservations, StateError> {
        self.check_graph(graph)?;
        if graph.descriptor(node).is_none()
            || native.len() > limits.maximum_capture_bytes
            || limits.maximum_operations > 65_536
        {
            return Err(refusal(
                "installed clock source or operation reservation exceeds finite limits",
            ));
        }
        // This synchronous edition has no external handles. The peak allowance
        // covers parsed envelopes, immutable model inputs, native queue copies,
        // and original runtime receipt/input ledgers before any model allocation.
        let immutable_bytes = match &self.selection(node)?.kind {
            InstalledNodeKind::HostIo { profile } => profile.artifact().length.get(),
            InstalledNodeKind::HostRecordedBlockPreserving { profile } => profile
                .storage
                .artifact()
                .length
                .get()
                .checked_add(profile.source.length.get())
                .ok_or_else(|| refusal("recorded artifact credit overflow"))?,
            InstalledNodeKind::HostScripted { profile } => profile.script.length.get(),
            InstalledNodeKind::HostSeededLink { profile } => profile.program.length.get(),
            InstalledNodeKind::HostFaultedLink { profile } => profile.program.length.get(),
            InstalledNodeKind::HostControlledFaultLink { profile } => profile.program.length.get(),
            InstalledNodeKind::HostClock | InstalledNodeKind::HostPacketReceiver { .. } => 0,
            InstalledNodeKind::HostSemantics { profile } => profile.program.length.get(),
            InstalledNodeKind::HostConditionDebugPreserving { profile } => {
                profile.program.length.get()
            }
            _ => return Err(refusal("unsupported installed native reservation family")),
        };
        let memory_bytes = (native.len() as u64)
            .checked_add(immutable_bytes)
            .and_then(|bytes| bytes.checked_mul(32))
            .and_then(|bytes| bytes.checked_add(64 * 1024))
            .ok_or_else(|| refusal("installed native peak memory reservation exhausted"))?;
        Ok(RestoreReservations {
            memory_bytes,
            ..Default::default()
        })
    }

    fn state_schema(&self, graph: &AdmittedGraph, node: &Id) -> Result<SchemaRef, StateError> {
        self.check_graph(graph)?;
        let binding = graph
            .binding(node)
            .ok_or_else(|| refusal("installed clock binding absent"))?;
        binding
            .compatibility
            .implementation
            .formats
            .iter()
            .find(|schema| {
                ((schema.id.as_str() == "host/native-continuation-v1"
                    || schema.id.as_str() == "host/native-recorded-block-v1"
                    || schema.id.as_str() == "host/native-condition-continuation-v1"
                    || schema.id.as_str() == "host/native-seeded-link-v1"
                    || schema.id.as_str() == "host/native-faulted-link-v1"
                    || schema.id.as_str() == "host/native-controlled-fault-link-v1"
                    || schema.id.as_str() == "host/native-packet-receiver-v1")
                    && schema.version == 1)
                    || (schema.id.as_str() == "host/native-semantic-continuation-v2"
                        && schema.version == 2)
            })
            .cloned()
            .ok_or_else(|| refusal("installed complete native continuation edition absent"))
    }

    fn authenticate_coordinator(
        &self,
        graph: &AdmittedGraph,
        runtime: &RuntimeSnapshot,
        scheduler: &SchedulingSnapshot,
        content: &VerifiedStateContent,
    ) -> Result<(), StateError> {
        self.check_graph(graph)?;
        let policy = graph.ownership_policy();
        if !(matches!(runtime.schema_version, 1 | 3 | 4)
            || (runtime.schema_version == 2 && self.recorded_world())
            || (runtime.schema_version == 6 && self.condition_world()))
            || (self.recorded_world() && runtime.schema_version != 2)
            || !matches!(scheduler.schema_version, 1 | 3 | 4)
            || (scheduler.schema_version == 3 && runtime.schema_version != 4)
            || (scheduler.schema_version == 4) != (runtime.schema_version == 6)
            || (self.condition_world() && runtime.schema_version != 6)
            || runtime.source_activation.world_binding_hash != *graph.world_binding_hash()
            || scheduler.world_binding_hash != *graph.world_binding_hash()
            || runtime.capture_cut != scheduler.capture_cut
            || runtime.capture_ordinal != scheduler.capture_ordinal
            || policy.objects.len()
                != self.scenario.descriptors.len() + self.scenario.world.connections.len()
            || policy.domains.len()
                != self.scenario.descriptors.len() + self.scenario.world.connections.len()
            || policy.capture_owners.iter().any(|owner| {
                !owner.complete_model
                    || !owner.unchanged_cut
                    || !owner.exact_continuation
                    || !owner.dependencies.is_empty()
            })
            || (!scheduler.external_closed_prefixes.is_empty() && !self.recorded_world())
        {
            return Err(refusal(
                "installed coordinator inventory contains unsupported domains, fault or external state",
            ));
        }
        // The regenerated profile closes every native and ordinary public
        // transfer path. This validator checks original FIFO/payload/credit,
        // input staging/consumption and reservation state against that exact
        // immutable graph; native validators below check both endpoint ledgers.
        crucible::node_scheduling::validate_saved_source(graph, scheduler).map_err(state_error)?;
        if self.condition_world() {
            self.authenticate_condition_scope(graph, runtime, scheduler, Some(content))?;
        }
        if self.recorded_world() {
            self.authenticate_recorded_coordinator(graph, runtime, scheduler)?;
        }
        for delivery in &scheduler.pending_deliveries {
            if let InstalledNodeKind::HostRecordedBlockPreserving { .. } =
                &self.selection(&delivery.producer)?.kind
            {
                let descriptor = graph
                    .descriptor(&delivery.producer)
                    .ok_or_else(|| refusal("recorded producer absent"))?;
                let definition =
                    super::super::recorded_ingress::from_content(descriptor, &self.objects)
                        .map_err(state_error)?;
                let input = definition
                    .source()
                    .inputs
                    .iter()
                    .find(|original| original.event == delivery.publication_id)
                    .ok_or_else(|| refusal("recorded pending event unknown"))?;
                if delivery.external_root.as_ref() != Some(&definition.source().endpoint)
                    || delivery.producer_endpoint != definition.source().endpoint
                    || delivery.consumer_endpoint != definition.source().endpoint
                    || delivery.native_sequence != input.sequence
                    || delivery.publication != input.publication
                    || delivery.payload != input.payload.reference
                    || content.get(&input.payload.reference) != Some(input.payload.bytes.as_slice())
                    || delivery.provenance_ref != *definition.root()
                    || delivery.connection_id.is_some()
                    || delivery.connection_policy_ref.is_some()
                    || !delivery.causal_parents.is_empty()
                {
                    return Err(refusal(
                        "recorded pending FIFO or original source body differs",
                    ));
                }
                continue;
            }
            let producer_kind = &self.selection(&delivery.producer)?.kind;
            let link_consumer = match producer_kind {
                InstalledNodeKind::HostSeededLink { profile } => Some(&profile.consumer),
                InstalledNodeKind::HostFaultedLink { profile } => Some(&profile.consumer),
                InstalledNodeKind::HostControlledFaultLink { profile } => Some(&profile.consumer),
                _ => None,
            };
            if let Some(consumer) = link_consumer {
                let bytes = content
                    .get(&delivery.payload)
                    .ok_or_else(|| refusal("original seeded payload absent"))?;
                delivery.payload.verify(bytes).map_err(state_error)?;
                let original = runtime
                    .operations
                    .iter()
                    .filter(|operation| operation.route.node == delivery.producer)
                    .filter_map(|operation| match &operation.result {
                        crucible::node_contract::SavedRuntimeResult::Complete(outcome)
                        | crucible::node_contract::SavedRuntimeResult::Acknowledged(outcome) => {
                            outcome.scheduling.as_ref()
                        }
                        _ => None,
                    })
                    .flat_map(|observation| &observation.publications)
                    .find(|publication| publication.publication_id == delivery.publication_id);
                if &delivery.consumer != consumer
                    || original.is_none_or(|publication| {
                        publication.payload != delivery.payload
                            || publication.payload_bytes != bytes
                            || publication.native_sequence != delivery.native_sequence
                            || publication.publication != delivery.publication
                            || publication.evaluation != delivery.evaluation
                            || publication.causal_parents != delivery.causal_parents
                    })
                {
                    return Err(refusal(
                        "seeded transfer differs from authentic original native publication",
                    ));
                }
                continue;
            }
            let InstalledNodeKind::HostScripted { profile } =
                &self.selection(&delivery.producer)?.kind
            else {
                return Err(refusal(
                    "pending transfer has no installed immutable source",
                ));
            };
            let script = ScriptedSource::from_script_bytes(
                self.immutable_input(&delivery.producer, content)?
                    .ok_or_else(|| refusal("original pending transfer script absent"))?,
            )
            .map_err(|error| refusal(error.reason))?;
            let index = usize::try_from(delivery.native_sequence.get()).map_err(state_error)?;
            let original = script
                .requests()
                .get(index)
                .ok_or_else(|| refusal("pending transfer exceeds original immutable script"))?;
            let bytes = content
                .get(&delivery.payload)
                .ok_or_else(|| refusal("original pending request bytes absent"))?;
            delivery.payload.verify(bytes).map_err(state_error)?;
            if delivery.consumer != profile.consumer
                || bytes != original.payload.as_slice()
                || delivery.publication
                    != Position::new(original.time_ps.into(), 1.into(), Phase::Publication)
                || delivery.evaluation
                    != Some(Position::new(
                        original.time_ps.into(),
                        0.into(),
                        Phase::Reaction,
                    ))
                || !delivery.causal_parents.is_empty()
            {
                return Err(refusal(
                    "pending transfer changed original script event provenance",
                ));
            }
        }
        for expected in &self.scenario.content {
            // Scenario-owned objects include the complete selected fault-free
            // coordinator and native model definitions. All referenced objects
            // must remain in the authenticated immutable closure.
            if content.get(&expected.reference).is_none()
                && self.scenario.world.initialization_ref == expected.reference
            {
                return Err(refusal(
                    "installed clock initialization inventory is incomplete",
                ));
            }
        }
        Ok(())
    }

    fn authenticate_input_provenance(
        &self,
        graph: &AdmittedGraph,
        runtime: &RuntimeSnapshot,
        scheduler: &SchedulingSnapshot,
        content: &VerifiedStateContent,
    ) -> Result<(), StateError> {
        if self.condition_world() && runtime.schema_version == 6 {
            self.authenticate_condition_scope(graph, runtime, scheduler, Some(content))?;
            return self.authenticate_condition_inputs(graph, runtime, scheduler, content);
        }
        if !self.recorded_world() || runtime.schema_version != 2 {
            return Err(refusal(
                "installed original input provenance codec is unsupported",
            ));
        }
        self.authenticate_coordinator(graph, runtime, scheduler, content)?;
        self.authenticate_recorded_provenance(graph, runtime, content)
    }

    fn authenticate_source(
        &self,
        graph: &AdmittedGraph,
        node: &Id,
        native: &[u8],
        source: &RuntimeSnapshot,
        content: &VerifiedStateContent,
    ) -> Result<(), StateError> {
        self.check_graph(graph)?;
        let descriptor = graph
            .descriptor(node)
            .ok_or_else(|| refusal("installed clock descriptor absent"))?;
        let binding = graph
            .binding(node)
            .ok_or_else(|| refusal("installed clock binding absent"))?;
        let inventory = validate_host_continuation(
            native,
            source,
            descriptor,
            binding,
            HostModelResources {
                maximum_capture_bytes: 64 * 1024 * 1024,
                maximum_operations: 65_536,
            },
        )
        .map_err(|error| refusal(error.reason))?;
        let initial = self
            .objects
            .get(&descriptor.initialization_ref.hash.digest)
            .ok_or_else(|| refusal("installed native initialization absent"))?;
        if content.get(&descriptor.initialization_ref) != Some(initial.1.as_slice()) {
            return Err(refusal("complete installed native initialization differs"));
        }
        match &self.selection(node)?.kind {
            InstalledNodeKind::HostPacketReceiver { .. } => {
                // Full native restore and original envelope validator above already
                // authenticate the selected byte receiver and source runtime.
            }
            InstalledNodeKind::HostClock => {
                if inventory.native_model.bytes
                    != host_clock_initial_bytes(source.capture_cut.time_ps.get())
                    || source.inputs.iter().any(|input| &input.node == node)
                {
                    return Err(refusal(
                        "actual clock codec or closed input inventory differs",
                    ));
                }
            }
            InstalledNodeKind::HostSeededLink { .. } => {
                let definition: crucible::node_adapters::SeededLinkDefinition =
                    serde_json::from_slice(
                        self.immutable_input(node, content)?
                            .ok_or_else(|| refusal("complete seeded program absent"))?,
                    )
                    .map_err(state_error)?;
                definition
                    .restore(&inventory.native_model.bytes, 64 * 1024 * 1024)
                    .map_err(|error| refusal(error.reason))?;
            }
            InstalledNodeKind::HostFaultedLink { .. } => {
                let definition: crucible::node_adapters::FaultedLinkDefinition =
                    serde_json::from_slice(
                        self.immutable_input(node, content)?
                            .ok_or_else(|| refusal("complete seeded program absent"))?,
                    )
                    .map_err(state_error)?;
                definition
                    .restore(&inventory.native_model.bytes, 64 * 1024 * 1024)
                    .map_err(|error| refusal(error.reason))?;
            }
            InstalledNodeKind::HostControlledFaultLink { .. } => {
                let program = serde_json::from_slice(
                    self.immutable_input(node, content)?
                        .ok_or_else(|| refusal("complete controller program absent"))?,
                )
                .map_err(state_error)?;
                let controller = crucible::node_adapters::ControlledFaultLink::restore(
                    &program,
                    &inventory.native_model.bytes,
                    64 * 1024 * 1024,
                )
                .map_err(|error| refusal(error.reason))?;
                self.authenticate_fault_journal(node, &controller, source, content)?;
            }
            InstalledNodeKind::HostRecordedBlockPreserving { profile } => {
                let expected =
                    super::super::recorded_ingress::from_content(descriptor, &self.objects)
                        .map_err(state_error)?;
                if inventory
                    .recorded_input
                    .as_ref()
                    .is_none_or(|(definition, consumed)| {
                        definition != &expected
                            || self
                                .recorded_consumed(source, &expected)
                                .map_or(true, |cursor| cursor != consumed.get() as usize)
                    })
                {
                    return Err(refusal(
                        "recorded actual native cursor differs from original signed runtime consumption",
                    ));
                }
                for original in expected.objects() {
                    if content.get(&original.reference) != Some(original.bytes.as_slice()) {
                        return Err(refusal(
                            "recorded complete source closure differs from installed original",
                        ));
                    }
                }
                io::validate_native_storage(
                    self.selection(node)?,
                    &profile.storage,
                    self.immutable_input(node, content)?
                        .ok_or_else(|| refusal("recorded base absent"))?
                        .to_vec(),
                    &inventory.native_model.bytes,
                )
                .map_err(state_error)?;
            }
            InstalledNodeKind::HostIo { profile } => io::validate_native_storage(
                self.selection(node)?,
                profile,
                self.immutable_input(node, content)?
                    .ok_or_else(|| refusal("complete storage immutable input absent"))?
                    .to_vec(),
                &inventory.native_model.bytes,
            )
            .map_err(state_error)?,
            InstalledNodeKind::HostScripted { .. } => {
                ScriptedSource::from_continuation(
                    self.immutable_input(node, content)?
                        .ok_or_else(|| refusal("complete immutable request script absent"))?,
                    &inventory.native_model.bytes,
                )
                .map_err(|error| refusal(error.reason))?;
                if source.inputs.iter().any(|input| {
                    &input.node == node
                        && (!input.deliveries.is_empty() || !input.payloads.is_empty())
                }) {
                    return Err(refusal("output-only source has nonempty input custody"));
                }
            }
            InstalledNodeKind::HostSemantics { .. } => {
                let definition = serde_json::from_slice(
                    self.immutable_input(node, content)?
                        .ok_or_else(|| refusal("semantic original program absent"))?,
                )
                .map_err(state_error)?;
                let model = crucible::node_adapters::HostSemanticModel::restore(
                    definition,
                    &inventory.native_model.bytes,
                    super::super::semantics::MAXIMUM_SEMANTIC_STATE_BYTES,
                    super::super::semantics::MAXIMUM_SEMANTIC_EVENTS,
                )
                .map_err(|error| refusal(error.reason))?;
                if !model.definition().inputs.is_empty()
                    || source.inputs.iter().any(|input| {
                        &input.node == node
                            && (!input.deliveries.is_empty()
                                || !input.payloads.is_empty()
                                || input.provenance.is_some())
                    })
                {
                    return Err(refusal(
                        "semantic archive input provenance edition is unqualified",
                    ));
                }
                match &source.terminal {
                    Some(saved) if &saved.record.node == node => {
                        let report = model
                            .terminal_report()
                            .ok_or_else(|| refusal("original terminal marker absent"))?;
                        if model.terminal_context() != Some((&saved.record, &saved.reference))
                            || saved.report.as_ref().is_some_and(|saved| saved != report)
                            || !inventory.evidence.iter().any(|original| original == report)
                        {
                            return Err(refusal(
                                "original semantic terminal context/report changed",
                            ));
                        }
                    }
                    _ if model.terminal_report().is_some() => {
                        return Err(refusal(
                            "finalized semantic state omits original runtime custody",
                        ));
                    }
                    _ => {}
                }
            }
            InstalledNodeKind::HostConditionDebugPreserving { .. } => {
                let definition = serde_json::from_slice(
                    self.immutable_input(node, content)?
                        .ok_or_else(|| refusal("condition original program absent"))?,
                )
                .map_err(state_error)?;
                let model = crucible::node_adapters::ConditionDebugModel::restore(
                    definition,
                    &inventory.native_model.bytes,
                    super::super::condition_debug::MAXIMUM_STATE_BYTES,
                    super::super::condition_debug::MAXIMUM_EVENTS,
                )
                .map_err(|error| refusal(error.reason))?;
                if model.position() != source.capture_cut || !model.awaiting_control() {
                    return Err(refusal(
                        "condition original native model is not at its stopped cut",
                    ));
                }
            }
            _ => return Err(refusal("unsupported installed native source family")),
        }
        for definition in &binding.compatibility.implementation.model_definitions {
            if content.get(definition).is_none() {
                return Err(refusal(
                    "installed clock model definition absent from source",
                ));
            }
        }
        Ok(())
    }

    fn prepare_node(
        &self,
        graph: &AdmittedGraph,
        node: &Id,
        source: &AuthenticatedHostSource<'_>,
        target: &ActivationRecord,
        limits: HostModelResources,
    ) -> Result<(HostModelNode, NativeRuntimeContinuationEvidence), StateError> {
        if source.node() != node {
            return Err(refusal("authenticated original clock identity differs"));
        }
        self.authenticate_source(
            graph,
            node,
            source.native(),
            source.runtime(),
            source.content(),
        )?;
        let qualification = SourceQualification {
            installed: self,
            source,
            target,
        };
        let mut actual = HostModelNode::new(
            graph,
            node,
            self.model(node, source.content())?,
            &qualification,
            limits,
        )
        .map_err(|error| refusal(error.reason))?;
        if matches!(
            &self.selection(node)?.kind,
            InstalledNodeKind::HostRecordedBlockPreserving { .. }
        ) {
            let definition = super::super::recorded_ingress::from_content(
                graph
                    .descriptor(node)
                    .ok_or_else(|| refusal("recorded descriptor absent"))?,
                &self.objects,
            )
            .map_err(state_error)?;
            actual = actual
                .with_preservable_recorded_ingress(graph, definition, &qualification)
                .map_err(|error| refusal(error.reason))?;
        }
        if self.condition_world() {
            actual = actual
                .with_preservable_condition(&qualification)
                .map_err(|error| refusal(error.reason))?;
        }
        let proof = actual
            .prepare_continuation(source.native(), source.runtime(), target, &qualification)
            .map_err(|error| refusal(error.reason))?;
        Ok((actual, proof))
    }
}
